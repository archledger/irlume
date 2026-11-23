// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright the irlume contributors.

use crate::managed_pad::capture_with_timing;
use irlume_common::diagnostics::{
    DiagnosticSink, TraceEventKind, TraceStage, CURRENT_TRACE_SCHEMA_VERSION,
};
use std::sync::{mpsc, Mutex};
use std::time::Duration;

#[derive(Default)]
struct TimingSink(Mutex<Vec<TraceEventKind>>);

impl DiagnosticSink for TimingSink {
    fn emit_trace(&self, event: TraceEventKind) {
        self.0.lock().unwrap().push(event);
    }
}

impl TimingSink {
    fn events(&self) -> Vec<TraceEventKind> {
        self.0.lock().unwrap().clone()
    }
}

#[test]
fn managed_timing_is_emitted_inside_each_capture_callback_before_join_and_cancel() {
    // Native sessions are hardware-only. Pin this wiring alongside the
    // callback helper's runtime tests so moving it after the join cannot pass.
    let source = include_str!("../managed_pad.rs");
    let method = source
        .split("fn prepare_managed_concurrent_sample(")
        .nth(1)
        .expect("managed capture method");
    let pair = method
        .split_once("let (rgb_result, ir_result) = irlume_camera::capture_pair_with(")
        .expect("paired capture call")
        .1;
    let (capture, after) = pair
        .split_once("\n        );\n")
        .expect("paired capture end");
    assert_eq!(capture.matches("capture_with_timing(").count(), 2);
    let compact: String = capture.chars().filter(|c| !c.is_whitespace()).collect();
    for callback in [
        "|session|{let(frame,elapsed_ms)=capture_with_timing(diagnostics,irlume_common::diagnostics::TraceStage::RgbCapture,||{letframe=session.denoised();",
        "|session|{let(frame,elapsed_ms)=capture_with_timing(diagnostics,irlume_common::diagnostics::TraceStage::IrCapture,||{letframe=session.capture_with_stats();",
    ] {
        assert!(compact.contains(callback), "missing role-bound capture: {callback}");
    }
    assert_eq!(capture.matches("session.denoised()").count(), 1);
    assert_eq!(capture.matches("session.capture_with_stats()").count(), 1);
    assert!(!after.contains("TraceStage::RgbCapture"));
    assert!(!after.contains("TraceStage::IrCapture"));
}

struct WorkerRelease {
    peer: Option<mpsc::Sender<()>>,
    drain: Option<mpsc::Sender<()>>,
}

impl WorkerRelease {
    fn release_all(&mut self) {
        if let Some(peer) = self.peer.take() {
            let _ = peer.send(());
        }
        if let Some(drain) = self.drain.take() {
            let _ = drain.send(());
        }
    }
}

impl Drop for WorkerRelease {
    fn drop(&mut self) {
        self.release_all();
    }
}

fn assert_early_role_is_reported(early: TraceStage, late: TraceStage, late_panics: bool) {
    let sink = TimingSink::default();
    let (completed, completion) = mpsc::channel();
    let (release_peer, peer_released) = mpsc::channel();
    let (release_drain, drain_released) = mpsc::channel();
    let (peer_started, peer_start) = mpsc::channel();
    let (observed, peer_ready, before_release, early_result, late_result) =
        std::thread::scope(|scope| {
            // This guard must live inside the scope: it releases/disconnects both
            // receivers before thread::scope joins workers during unwinding.
            let mut release = WorkerRelease {
                peer: Some(release_peer),
                drain: Some(release_drain),
            };
            let sink = &sink;
            let early_worker = scope.spawn(move || {
                let result = capture_with_timing(sink, early, || "early frame");
                completed.send(()).unwrap();
                drain_released
                    .recv_timeout(Duration::from_secs(10))
                    .unwrap();
                result
            });
            let late_worker = scope.spawn(move || {
                if late_panics {
                    drop(peer_released);
                    peer_started.send(()).unwrap();
                    panic!("deliberate late-worker failure");
                }
                peer_started.send(()).unwrap();
                capture_with_timing(sink, late, || {
                    peer_released.recv_timeout(Duration::from_secs(10)).unwrap();
                    "late frame"
                })
            });
            let observed = completion.recv_timeout(Duration::from_secs(10));
            let peer_ready = peer_start.recv_timeout(Duration::from_secs(10));
            let before_release = sink.events();
            release.release_all();
            let early_result = early_worker.join();
            let late_result = late_worker.join();
            (
                observed,
                peer_ready,
                before_release,
                early_result,
                late_result,
            )
        });
    observed.unwrap();
    peer_ready.unwrap();
    assert_eq!(early_result.unwrap().0, "early frame");
    assert!(matches!(
        before_release.as_slice(),
        [TraceEventKind::StageTiming { stage, .. }] if *stage == early
    ));
    if late_panics {
        let panic = late_result.unwrap_err();
        assert_eq!(
            panic.downcast_ref::<&str>(),
            Some(&"deliberate late-worker failure")
        );
        assert_eq!(sink.events(), before_release);
    } else {
        assert_eq!(late_result.unwrap().0, "late frame");
        assert!(matches!(
            sink.events().as_slice(),
            [TraceEventKind::StageTiming { stage: first, .. }, TraceEventKind::StageTiming { stage: second, .. }]
                if *first == early && *second == late
        ));
    }
}

#[test]
fn managed_timing_reports_rgb_before_ir_and_tail_drain_finish() {
    assert_early_role_is_reported(TraceStage::RgbCapture, TraceStage::IrCapture, false);
}

#[test]
fn managed_timing_reports_ir_before_rgb_and_tail_drain_finish() {
    assert_early_role_is_reported(TraceStage::IrCapture, TraceStage::RgbCapture, false);
}

#[test]
fn managed_timing_late_worker_panic_still_releases_the_early_worker() {
    assert_early_role_is_reported(TraceStage::RgbCapture, TraceStage::IrCapture, true);
}

#[test]
fn managed_timing_fixture_unwind_releases_both_workers_before_join() {
    use std::sync::atomic::{AtomicUsize, Ordering};
    let released = AtomicUsize::new(0);
    let result = std::panic::catch_unwind(|| {
        std::thread::scope(|scope| {
            let (peer, peer_released) = mpsc::channel();
            let (drain, drain_released) = mpsc::channel();
            let _release = WorkerRelease {
                peer: Some(peer),
                drain: Some(drain),
            };
            for receiver in [peer_released, drain_released] {
                let released = &released;
                scope.spawn(move || {
                    if receiver.recv_timeout(Duration::from_secs(10)).is_ok() {
                        released.fetch_add(1, Ordering::SeqCst);
                    }
                });
            }
            panic!("deliberate coordinator failure");
        });
    });
    assert!(result.is_err());
    assert_eq!(released.load(Ordering::SeqCst), 2);
}

#[test]
fn managed_timing_keeps_cancel_deadline_and_error_results_without_payloads() {
    use irlume_common::Error;
    for error in [
        Error::Preempted("private cancellation".into()),
        Error::DeadlineExpired,
        Error::Hardware("private driver error".into()),
    ] {
        let sink = TimingSink::default();
        let kind = std::mem::discriminant(&error);
        let text = error.to_string();
        let (result, _) = capture_with_timing(&sink, TraceStage::IrCapture, || Err::<(), _>(error));
        let returned = result.unwrap_err();
        assert_eq!(std::mem::discriminant(&returned), kind);
        assert_eq!(returned.to_string(), text);
        assert!(matches!(
            sink.events().as_slice(),
            [TraceEventKind::StageTiming {
                stage: TraceStage::IrCapture,
                ..
            }]
        ));
        assert!(!serde_json::to_string(&sink.events())
            .unwrap()
            .contains("private"));
    }
}

#[test]
fn managed_timing_runs_once_preserves_value_and_uses_one_elapsed_interval() {
    let sink = TimingSink::default();
    let calls = std::cell::Cell::new(0);
    let value = Box::new(7_u8);
    let address = &*value as *const u8;
    let (returned, elapsed_ms) = capture_with_timing(&sink, TraceStage::RgbCapture, || {
        assert!(
            sink.events().is_empty(),
            "timing cannot precede capture completion"
        );
        calls.set(calls.get() + 1);
        value
    });
    assert_eq!(calls.get(), 1);
    assert_eq!(&*returned as *const u8, address);
    match sink.events().as_slice() {
        [TraceEventKind::StageTiming {
            stage: TraceStage::RgbCapture,
            elapsed_us,
        }] => {
            assert_eq!(u128::from(*elapsed_us / 1_000), elapsed_ms);
        }
        other => panic!("unexpected timing events: {other:?}"),
    }
}

#[test]
fn managed_timing_elapsed_includes_the_capture_callback_work() {
    let sink = TimingSink::default();
    let minimum = Duration::from_millis(2);
    let (_, elapsed_ms) = capture_with_timing(&sink, TraceStage::RgbCapture, || {
        let started = std::time::Instant::now();
        // Only a lower bound, with no scheduling-sensitive upper threshold.
        // This is a clock/measurement guard, not a performance benchmark.
        while started.elapsed() < minimum {
            std::thread::yield_now();
        }
    });
    assert!(elapsed_ms >= minimum.as_millis());
    assert!(matches!(
        sink.events().as_slice(),
        [TraceEventKind::StageTiming { elapsed_us, .. }]
            if u128::from(*elapsed_us) >= minimum.as_micros()
    ));
}

fn rate_evidence(
    role: irlume_common::diagnostics::CameraRoleLabel,
    decision: irlume_common::diagnostics::RateEvidenceDecision,
) -> TraceEventKind {
    TraceEventKind::RateEvidence {
        role,
        decision,
        deltas: 30,
        probe_deltas: None,
        offset_us: 0,
        elapsed_us: 7,
    }
}

/// Each stream's rate evidence reaches the trace once, RGB before IR, and
/// only for a stream whose fill established a window (ADR-0021). It is not
/// a stage timing, so it takes no part in a capture round or the envelope.
#[test]
fn rate_evidence_is_reported_once_per_established_stream_rgb_before_ir() {
    use irlume_common::diagnostics::{
        CameraRoleLabel, RateEvidenceDecision, V5_TRACE_SCHEMA_VERSION,
    };
    let rgb = rate_evidence(CameraRoleLabel::Rgb, RateEvidenceDecision::FullWindow);
    let ir = rate_evidence(CameraRoleLabel::Ir, RateEvidenceDecision::ProbeAdmitted);
    for (given, expected) in [
        (
            [Some(rgb.clone()), Some(ir.clone())],
            vec![rgb.clone(), ir.clone()],
        ),
        ([Some(rgb.clone()), None], vec![rgb.clone()]),
        ([None, Some(ir.clone())], vec![ir.clone()]),
        ([None, None], vec![]),
    ] {
        let sink = TimingSink::default();
        crate::emit_rate_evidence(&sink, given);
        assert_eq!(sink.events(), expected);
    }
    for event in [rgb, ir] {
        assert!(event.supports_schema(CURRENT_TRACE_SCHEMA_VERSION));
        assert!(!event.supports_schema(V5_TRACE_SCHEMA_VERSION));
        assert!(!matches!(event, TraceEventKind::StageTiming { .. }));
        let json = serde_json::to_string(&event).unwrap();
        assert!(json.starts_with("{\"event\":\"rate_evidence\""), "{json}");
        assert!(!json.contains("/dev"), "{json}");
    }
}

fn assert_rate_evidence_report(text: &str) {
    let emit = text
        .find("emit_rate_evidence(")
        .expect("the records are emitted");
    let rgb = text
        .find("rgb.diagnostic_rate_evidence()")
        .expect("the RGB record is read");
    let ir = text
        .find("ir.diagnostic_rate_evidence()")
        .expect("the IR record is read");
    assert!(
        emit < rgb && rgb < ir,
        "both records are read, RGB before IR, into one report: {text}"
    );
}

/// Native sessions exist only with a camera, so the two sites that time a
/// pair's rate establishment are pinned by shape: each reads both streams'
/// records right after the fill and before the fill's error handling, so a
/// stream whose window was established before its twin failed still reports.
#[test]
fn both_pair_fills_report_each_streams_rate_evidence_after_the_fill() {
    let lib = include_str!("../lib.rs");
    let eager = lib
        .split("\n    fn assess_with_fresh_pair_finish<T>(")
        .nth(1)
        .expect("the eager pair assessment");
    let after = eager
        .split_once("let rate = irlume_camera::establish_pair_rate(rgb, ir);")
        .expect("the eager pair fill")
        .1;
    let reported = after
        .split_once("rate.map_err(|error|")
        .expect("the fill's error handling")
        .0;
    // This route times the block itself, first, then decomposes it.
    assert!(
        reported
            .find("TraceStage::RateEstablishment")
            .zip(reported.find("emit_rate_evidence("))
            .is_some_and(|(block, evidence)| block < evidence),
        "the block's own timing is reported first: {reported}"
    );
    assert_rate_evidence_report(reported);

    let managed = include_str!("../managed_pad.rs");
    let (before, after) = managed
        .split_once("let established = irlume_camera::establish_pair_rate(rgb, ir);")
        .expect("the managed pair fill");
    let reported = after
        .split_once("established.map_err(|error|")
        .expect("the fill's error handling")
        .0;
    assert!(before.contains("with_managed_pair("));
    // Here the block's timer wraps this whole closure, so the records
    // precede the block's own timing record on this route.
    assert!(
        !reported.contains("TraceStage::"),
        "the managed block's timer closes after this closure: {reported}"
    );
    assert_rate_evidence_report(reported);
}

// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright the irlume contributors.

// The rate evidence each fill records (the schema 6 `RateEvidence` record):
// the decision, the delta counts and the stream's own timing, on the
// single-stream fill and on the paired concurrent fill. Every fixture here
// is software-only; no camera is opened.

use irlume_common::diagnostics::{CameraRoleLabel, RateEvidenceDecision, TraceEventKind};

/// The recorded `(decision, deltas, probe_deltas, offset_us, elapsed_us)`.
fn recorded_evidence<S>(stream: &TrackedStream<S>) -> (RateEvidenceDecision, u32, Option<u32>, u64, u64) {
    match stream.rate_evidence.clone() {
        Some(TraceEventKind::RateEvidence {
            decision,
            deltas,
            probe_deltas,
            offset_us,
            elapsed_us,
            ..
        }) => (decision, deltas, probe_deltas, offset_us, elapsed_us),
        other => panic!("no rate evidence recorded: {other:?}"),
    }
}

/// The window the record names: `(deltas, seed_frame, end_frame, span_us)`.
fn window_of<S>(stream: &TrackedStream<S>) -> (u32, u64, u64, u64) {
    match stream.rate_evidence.clone() {
        Some(TraceEventKind::RateEvidence {
            deltas,
            seed_frame,
            end_frame,
            span_us,
            ..
        }) => (deltas, seed_frame, end_frame, span_us),
        other => panic!("no rate evidence recorded: {other:?}"),
    }
}

/// The stream role a trace record's role label names.
fn role_of(role: CameraRoleLabel) -> contracts::StreamRole {
    match role {
        CameraRoleLabel::Rgb => contracts::StreamRole::Rgb,
        CameraRoleLabel::Ir => contracts::StreamRole::Ir,
    }
}

/// A frame queue delivering frames with exactly the given driver
/// timestamps, in microseconds.
fn timed_queue(timestamps_us: &[i64]) -> QueuedContinuityFixture {
    let metadata = timestamps_us
        .iter()
        .enumerate()
        .map(|(index, micros)| {
            let mut frame = continuity_metadata(
                u32::try_from(index).unwrap() + 1,
                micros.div_euclid(1_000_000),
                v4l::buffer::Flags::TIMESTAMP_MONOTONIC,
            );
            frame.timestamp = v4l::timestamp::Timestamp::new(
                micros.div_euclid(1_000_000),
                micros.rem_euclid(1_000_000),
            );
            frame
        })
        .collect();
    QueuedContinuityFixture {
        payload: [1],
        metadata,
    }
}

/// A frame queue whose first frame seeds and whose later frames arrive
/// after the given deltas, in microseconds.
fn delta_queue(deltas_us: &[i64]) -> QueuedContinuityFixture {
    let mut micros = 1_000_000_i64;
    let mut metadata = std::collections::VecDeque::new();
    metadata.push_back(continuity_metadata(
        1,
        1,
        v4l::buffer::Flags::TIMESTAMP_MONOTONIC,
    ));
    for (index, delta) in deltas_us.iter().enumerate() {
        micros += delta;
        let mut frame = continuity_metadata(
            index as u32 + 2,
            micros / 1_000_000,
            v4l::buffer::Flags::TIMESTAMP_MONOTONIC,
        );
        frame.timestamp = v4l::timestamp::Timestamp::new(micros / 1_000_000, micros % 1_000_000);
        metadata.push_back(frame);
    }
    QueuedContinuityFixture {
        payload: [1],
        metadata,
    }
}

fn role_config(role: contracts::StreamRole) -> rate_gate::StreamRateConfig {
    let interval = frame_interval::FrameInterval::new(1, 15).unwrap();
    rate_gate::StreamRateConfig::new(role, interval, interval)
}

fn stream_with_deltas(
    role: contracts::StreamRole,
    deltas_us: &[i64],
) -> TrackedStream<QueuedContinuityFixture> {
    TrackedStream::new(delta_queue(deltas_us), role_config(role))
}

/// `count` deltas at the 15 fps fleet floor.
fn floor_deltas(count: usize) -> Vec<i64> {
    vec![66_667; count]
}

/// A queue that delivers each frame after a real pause, so a test can read
/// the wall time a window's collection took.
struct PacedQueue {
    inner: QueuedContinuityFixture,
    interval: std::time::Duration,
}

impl ValidatedStream for PacedQueue {
    fn next_validated(
        &mut self,
    ) -> Result<(&[u8], frame_provenance::DequeuedBufferFacts), ValidatedDequeueError> {
        std::thread::sleep(self.interval);
        self.inner.next_validated()
    }
}

fn paced_stream(
    role: contracts::StreamRole,
    frames: usize,
    interval: std::time::Duration,
) -> TrackedStream<PacedQueue> {
    let interval_us = i64::try_from(interval.as_micros()).unwrap();
    let deltas = vec![interval_us; frames];
    TrackedStream::new(
        PacedQueue {
            inner: delta_queue(&deltas),
            interval,
        },
        role_config(role),
    )
}

#[test]
fn rate_evidence_a_cold_single_stream_reports_its_full_window() {
    let _lock = crate::testenv::env_lock();
    let _env = crate::testenv::EnvGuard::unset("IRLUME_RATE_AMORTIZATION");
    let node = "/dev/video-evidence-cold";
    let key = rate_amortization::Key::new(node, contracts::StreamRole::Rgb);
    rate_amortization::test_support::force_completion(key.clone(), None);
    let mut stream = TrackedStream::new(delta_queue(&floor_deltas(40)), role_config(contracts::StreamRole::Rgb))
        .with_rate_amortization(node);
    assert!(stream.rate_evidence.is_none(), "nothing is established yet");
    stream.fill_rate_evidence().expect("full fill");
    let recorded = stream.rate_evidence.clone();
    // RGB has no flush and keeps every delta: the window is the session's
    // first 31 frames, 30 deltas of 66,667 us.
    assert!(matches!(
        recorded,
        Some(TraceEventKind::RateEvidence {
            role: CameraRoleLabel::Rgb,
            decision: RateEvidenceDecision::FullWindow,
            deltas: 30,
            probe_deltas: None,
            seed_frame: 0,
            end_frame: 30,
            span_us: 2_000_010,
            persisted: false,
            offset_us: 0,
            elapsed_us: 0..=1_000_000,
        })
    ));
    assert_eq!(window_of(&stream), (30, 0, 30, 2_000_010));
    // A ready window is not established again, so its record stays as it was.
    stream.fill_rate_evidence().expect("ready window");
    assert_eq!(stream.rate_evidence, recorded);

    // A session created without an amortization key has nothing recorded.
    let mut unkeyed = TrackedStream::new(delta_queue(&floor_deltas(40)), role_config(contracts::StreamRole::Ir));
    unkeyed.fill_rate_evidence().expect("full fill");
    assert!(matches!(
        unkeyed.rate_evidence,
        Some(TraceEventKind::RateEvidence {
            role: CameraRoleLabel::Ir,
            decision: RateEvidenceDecision::FullWindow,
            deltas: 30,
            probe_deltas: None,
            offset_us: 0,
            ..
        })
    ));
    // IR's five-frame flush precedes the window: frames 5 through 35.
    assert_eq!(window_of(&unkeyed), (30, 5, 35, 2_000_010));
    rate_amortization::test_support::force_completion(key, None);
}

#[test]
fn rate_evidence_a_stale_completion_and_the_kill_switch_are_named() {
    let _lock = crate::testenv::env_lock();
    let node = "/dev/video-evidence-stale";
    let key = rate_amortization::Key::new(node, contracts::StreamRole::Rgb);
    let cold = || {
        TrackedStream::new(delta_queue(&floor_deltas(40)), role_config(contracts::StreamRole::Rgb))
            .with_rate_amortization(node)
    };
    {
        let _env = crate::testenv::EnvGuard::unset("IRLUME_RATE_AMORTIZATION");
        rate_amortization::test_support::force_completion(
            key.clone(),
            Some(
                std::time::Instant::now()
                    - rate_amortization::MAX_STALENESS
                    - std::time::Duration::from_secs(1),
            ),
        );
        // One second past the bound: the completion is older than 24 hours.
        let mut stale = cold();
        stale.fill_rate_evidence().expect("full fill");
        assert_eq!(recorded_evidence(&stale).0, RateEvidenceDecision::StaleFullWindow);
    }
    rate_amortization::test_support::force_completion(key.clone(), None);
    {
        let _off = crate::testenv::EnvGuard::set("IRLUME_RATE_AMORTIZATION", "0");
        rate_amortization::test_support::force_completion(key.clone(), Some(std::time::Instant::now()));
        let mut disabled = cold();
        disabled.fill_rate_evidence().expect("full fill");
        let (decision, deltas, probe_deltas, offset_us, _) = recorded_evidence(&disabled);
        assert_eq!(
            (decision, deltas, probe_deltas, offset_us),
            (RateEvidenceDecision::DisabledFullWindow, 30, None, 0)
        );
    }
    rate_amortization::test_support::force_completion(key, None);
}

#[test]
fn rate_evidence_a_probe_admission_reports_the_deltas_it_admitted_on() {
    let _lock = crate::testenv::env_lock();
    let _env = crate::testenv::EnvGuard::unset("IRLUME_RATE_AMORTIZATION");
    let (first_node, wide_node) = (
        "/dev/video-evidence-admitted",
        "/dev/video-evidence-escalated",
    );
    let first_key = rate_amortization::Key::new(first_node, contracts::StreamRole::Ir);
    let wide_key = rate_amortization::Key::new(wide_node, contracts::StreamRole::Rgb);
    for key in [&first_key, &wide_key] {
        rate_amortization::test_support::force_completion(key.clone(), Some(std::time::Instant::now()));
    }

    // A recent completion admits on seed + 5 deltas, after the IR flush.
    let mut first = TrackedStream::new(delta_queue(&floor_deltas(40)), role_config(contracts::StreamRole::Ir))
        .with_rate_amortization(first_node);
    first
        .fill_rate_evidence_with_startup(false)
        .expect("probe admission");
    let (decision, deltas, probe_deltas, offset_us, elapsed_us) = recorded_evidence(&first);
    assert_eq!(
        (decision, deltas, probe_deltas, offset_us),
        (RateEvidenceDecision::ProbeAdmitted, 5, None, 0)
    );
    assert!(elapsed_us < 1_000_000, "{elapsed_us} us");
    // The probe's window follows the five-frame flush: frames 5 through 10.
    assert_eq!(window_of(&first), (5, 5, 10, 333_335));
    assert!(first.health_admitted);

    // The measured N930W RGB startup shape: one ~616 ms queue-refill stall
    // inside the first deltas misses the 5-delta point sample and clears
    // the floor only once the window has widened past it.
    let widened_deltas: Vec<i64> = [616_000].into_iter().chain(floor_deltas(40)).collect();
    let mut widened = stream_with_deltas(contracts::StreamRole::Rgb, &widened_deltas)
        .with_rate_amortization(wide_node);
    widened.fill_rate_evidence().expect("escalated admission");
    let (decision, deltas, probe_deltas, _, _) = recorded_evidence(&widened);
    assert_eq!(decision, RateEvidenceDecision::ProbeAdmitted);
    assert!(
        deltas > rate_amortization::CONTINUITY_PROBE_DELTAS as u32
            && deltas <= rate_amortization::CONTINUITY_PROBE_ESCALATED_DELTAS as u32,
        "only the widened window admitted: {deltas} deltas"
    );
    assert_eq!(probe_deltas, None, "an admission is not a miss");
    // RGB keeps every frame: the stall is the first delta after a seed at
    // frame 0, and the window runs to the frame that cleared the floor.
    assert_eq!(
        window_of(&widened),
        (deltas, 0, u64::from(deltas), 616_000 + 7 * 66_667)
    );
    assert!(widened.health_admitted);

    for key in [first_key, wide_key] {
        rate_amortization::test_support::force_completion(key, None);
    }
}

#[test]
fn rate_evidence_a_missed_probe_reports_the_miss_and_the_full_window() {
    let _lock = crate::testenv::env_lock();
    let _env = crate::testenv::EnvGuard::unset("IRLUME_RATE_AMORTIZATION");
    let (slow_node, blind_node) = (
        "/dev/video-evidence-missed",
        "/dev/video-evidence-missed-blind",
    );
    let slow_key = rate_amortization::Key::new(slow_node, contracts::StreamRole::Ir);
    let blind_key = rate_amortization::Key::new(blind_node, contracts::StreamRole::Rgb);
    for key in [&slow_key, &blind_key] {
        rate_amortization::test_support::force_completion(key.clone(), Some(std::time::Instant::now()));
    }

    // IR at 10 fps: below the 14.55 fps floor, so the probe misses at the
    // escalated width and the full window is paid after it (#1034's rule
    // keeps the fill itself from judging the floor).
    let mut slow = stream_with_deltas(contracts::StreamRole::Ir, &vec![100_000; 80])
        .with_rate_amortization(slow_node);
    slow.fill_rate_evidence().expect("window fills regardless");
    let (decision, deltas, probe_deltas, offset_us, elapsed_us) = recorded_evidence(&slow);
    assert_eq!(
        (decision, deltas, probe_deltas, offset_us),
        (RateEvidenceDecision::ProbeMissed, 30, Some(15), 0)
    );
    assert!(elapsed_us < 1_000_000, "{elapsed_us} us");
    assert!(!slow.health_admitted);
    // The probe took frames 5 through 20 (15 deltas); the full window that
    // followed was seeded on the next frame and ran to frame 51.
    assert_eq!(window_of(&slow), (30, 21, 51, 3_000_000));
    assert!(
        !rate_amortization::amortizable(&slow_key),
        "the missed probe revoked the completion"
    );

    // A probe whose dequeues were all driver-marked errors collects no
    // delta and never admits: the miss reports the zero it collected.
    let mut blind = TrackedStream::new(delta_queue(&floor_deltas(MAX_PROBE_FILL_ATTEMPTS + 40)), role_config(contracts::StreamRole::Rgb))
        .with_rate_amortization(blind_node);
    for metadata in blind
        .stream_mut()
        .unwrap()
        .metadata
        .iter_mut()
        .skip(1)
        .take(MAX_PROBE_FILL_ATTEMPTS)
    {
        metadata.flags |= v4l::buffer::Flags::ERROR;
    }
    blind
        .fill_rate_evidence()
        .expect("full fill after the missed probe");
    let (decision, deltas, probe_deltas, _, _) = recorded_evidence(&blind);
    assert_eq!(
        (decision, deltas, probe_deltas),
        (RateEvidenceDecision::ProbeMissed, 30, Some(0))
    );
    assert!(!blind.health_admitted);

    for key in [slow_key, blind_key] {
        rate_amortization::test_support::force_completion(key, None);
    }
}

#[test]
fn rate_evidence_a_cold_pair_reports_each_streams_full_window_then_its_probes() {
    let _lock = crate::testenv::env_lock();
    let _env = crate::testenv::EnvGuard::unset("IRLUME_RATE_AMORTIZATION");
    let (rgb_node, ir_node) = (
        "/dev/video-evidence-pair-rgb",
        "/dev/video-evidence-pair-ir",
    );
    let (rgb_key, ir_key) = (
        rate_amortization::Key::new(rgb_node, contracts::StreamRole::Rgb),
        rate_amortization::Key::new(ir_node, contracts::StreamRole::Ir),
    );
    for key in [&rgb_key, &ir_key] {
        rate_amortization::test_support::force_completion(key.clone(), None);
    }
    // The stream that is ready first keeps dequeuing while its twin
    // finishes, within the fill budget; both queues hold more frames than
    // that budget plus a window, so the drain cannot run them dry.
    let rgb = || {
        TrackedStream::new(delta_queue(&floor_deltas(200)), role_config(contracts::StreamRole::Rgb))
            .with_rate_amortization(rgb_node)
    };
    let ir = || {
        TrackedStream::new(delta_queue(&floor_deltas(200)), role_config(contracts::StreamRole::Ir))
            .with_rate_amortization(ir_node)
    };

    let (mut cold_rgb, mut cold_ir) = (rgb(), ir());
    establish_concurrent_rate(&mut cold_rgb, &mut cold_ir).expect("cold pair fill");
    for (stream, role) in [(&cold_rgb, CameraRoleLabel::Rgb), (&cold_ir, CameraRoleLabel::Ir)] {
        let (decision, deltas, probe_deltas, offset_us, elapsed_us) = recorded_evidence(stream);
        assert_eq!((decision, deltas, probe_deltas), (RateEvidenceDecision::FullWindow, 30, None));
        // Each collection began with the pair fill and is measured to its
        // own window alone: the trailing drain while the twin finishes,
        // and IR's five-frame flush, are outside `elapsed_us`.
        assert!(offset_us < 1_000_000, "{role:?} offset {offset_us} us");
        assert!(elapsed_us < 1_000_000, "{role:?} elapsed {elapsed_us} us");
        assert!(matches!(
            stream.rate_evidence,
            Some(TraceEventKind::RateEvidence { role: recorded, .. }) if recorded == role
        ));
        // Each window begins right after its own flush: frame 0 for RGB,
        // frame 5 for IR.
        let seed = rate_gate::startup_flush(role_of(role)) as u64;
        assert_eq!(window_of(stream), (30, seed, seed + 30, 2_000_010), "{role:?}");
        assert!(!stream.health_admitted);
    }

    // The next pair on the same nodes and roles admits each stream on the
    // probe, so the record says so with the five deltas it admitted on.
    let (mut warm_rgb, mut warm_ir) = (rgb(), ir());
    establish_concurrent_rate(&mut warm_rgb, &mut warm_ir).expect("warm pair fill");
    for (stream, role) in [(&warm_rgb, CameraRoleLabel::Rgb), (&warm_ir, CameraRoleLabel::Ir)] {
        let (decision, deltas, probe_deltas, offset_us, _) = recorded_evidence(stream);
        assert_eq!((decision, deltas, probe_deltas), (RateEvidenceDecision::ProbeAdmitted, 5, None));
        assert!(offset_us < 1_000_000, "offset {offset_us} us");
        let seed = rate_gate::startup_flush(role_of(role)) as u64;
        assert_eq!(window_of(stream), (5, seed, seed + 5, 333_335), "{role:?}");
        assert!(stream.health_admitted);
    }

    for key in [rgb_key, ir_key] {
        rate_amortization::test_support::force_completion(key, None);
    }
}

#[test]
fn rate_evidence_a_pair_reports_a_probe_miss_on_the_stream_that_missed() {
    let _lock = crate::testenv::env_lock();
    let _env = crate::testenv::EnvGuard::unset("IRLUME_RATE_AMORTIZATION");
    let (rgb_node, ir_node) = (
        "/dev/video-evidence-pair-miss-rgb",
        "/dev/video-evidence-pair-miss-ir",
    );
    let (rgb_key, ir_key) = (
        rate_amortization::Key::new(rgb_node, contracts::StreamRole::Rgb),
        rate_amortization::Key::new(ir_node, contracts::StreamRole::Ir),
    );
    for key in [&rgb_key, &ir_key] {
        rate_amortization::test_support::force_completion(key.clone(), Some(std::time::Instant::now()));
    }
    // RGB, ready first, drains while IR pays its miss and a full window.
    let mut rgb = TrackedStream::new(
        delta_queue(&floor_deltas(200)),
        role_config(contracts::StreamRole::Rgb),
    )
    .with_rate_amortization(rgb_node);
    // IR at 10 fps misses its probe; its twin's probe still admits.
    let mut ir = TrackedStream::new(
        delta_queue(&vec![100_000; 200]),
        role_config(contracts::StreamRole::Ir),
    )
    .with_rate_amortization(ir_node);
    establish_concurrent_rate(&mut rgb, &mut ir).expect("pair fill completes on readiness");
    let (decision, deltas, probe_deltas, _, _) = recorded_evidence(&rgb);
    assert_eq!((decision, deltas, probe_deltas), (RateEvidenceDecision::ProbeAdmitted, 5, None));
    assert!(rgb.health_admitted);
    let (decision, deltas, probe_deltas, _, _) = recorded_evidence(&ir);
    assert_eq!(
        (decision, deltas, probe_deltas),
        (RateEvidenceDecision::ProbeMissed, 30, Some(15))
    );
    assert!(!ir.health_admitted);
    let rgb_cached = rate_amortization::amortizable(&rgb_key);
    let ir_cached = rate_amortization::amortizable(&ir_key);
    for key in [rgb_key, ir_key] {
        rate_amortization::test_support::force_completion(key, None);
    }
    assert!(rgb_cached, "the admitted stream's completion stays");
    assert!(!ir_cached, "the missed probe revoked only its own completion");
}

/// The record carries enough to tell a pair fill that collects both windows
/// at once from one that fills them one after the other: each stream's
/// collection start relative to the pair fill, and its own duration. A
/// sleep never returns early, so every lower bound holds on any host; no
/// assertion depends on how soon the scheduler runs a thread, and the
/// overlap is judged with a margin left for it.
#[test]
fn rate_evidence_shows_whether_a_pair_fill_collects_both_windows_at_once() {
    let _lock = crate::testenv::env_lock();
    let _env = crate::testenv::EnvGuard::unset("IRLUME_RATE_AMORTIZATION");
    // RGB: seed + 30 deltas at 40 ms, about 1.24 s. IR: a five-frame flush
    // then seed + 30 deltas at 10 ms, about 0.36 s in all. Once IR is ready
    // it keeps dequeuing while RGB finishes, so its queue carries enough
    // frames for the whole pair fill.
    let pair = || {
        (
            paced_stream(
                contracts::StreamRole::Rgb,
                34,
                std::time::Duration::from_millis(40),
            ),
            paced_stream(
                contracts::StreamRole::Ir,
                132,
                std::time::Duration::from_millis(10),
            ),
        )
    };

    // Concurrent: the faster stream has its window long before the slower
    // one has its, which cannot happen when the two are filled in turn.
    let (mut rgb, mut ir) = pair();
    establish_concurrent_rate(&mut rgb, &mut ir).expect("concurrent pair fill");
    let (_, _, _, rgb_offset, rgb_elapsed) = recorded_evidence(&rgb);
    let (_, _, _, ir_offset, ir_elapsed) = recorded_evidence(&ir);
    assert!(rgb_elapsed >= 30 * 40_000, "rgb elapsed {rgb_elapsed} us");
    assert!(ir_elapsed >= 30 * 10_000, "ir elapsed {ir_elapsed} us");
    // IR's collection starts after its flush, five frames of 10 ms.
    assert!(ir_offset >= 5 * 10_000, "ir offset {ir_offset} us");
    assert!(
        ir_offset + ir_elapsed + 300_000 < rgb_offset + rgb_elapsed,
        "the collections overlapped: ir was done {} us into the fill, rgb took {} us",
        ir_offset + ir_elapsed,
        rgb_elapsed
    );

    // Serial, for contrast: the same two streams filled one after the other
    // from one pair start read as the second collection beginning only
    // once the first is complete, so the inequality above cannot hold.
    let (mut rgb, mut ir) = pair();
    let started = std::time::Instant::now();
    rgb.pair_fill_started = Some(started);
    ir.pair_fill_started = Some(started);
    // Each call reports into a count that already holds the other stream.
    let alone = || std::sync::atomic::AtomicUsize::new(1);
    let cancelled = std::sync::atomic::AtomicBool::new(false);
    drain_until_both_ready(&mut rgb, &alone(), &cancelled, &mut 0).expect("first fill");
    drain_until_both_ready(&mut ir, &alone(), &cancelled, &mut 0).expect("second fill");
    let (_, _, _, rgb_offset, rgb_elapsed) = recorded_evidence(&rgb);
    let (_, _, _, ir_offset, ir_elapsed) = recorded_evidence(&ir);
    assert!(rgb_elapsed >= 30 * 40_000, "rgb elapsed {rgb_elapsed} us");
    assert!(ir_elapsed >= 30 * 10_000, "ir elapsed {ir_elapsed} us");
    assert!(
        ir_offset > rgb_offset + rgb_elapsed,
        "a serial fill starts the second window after the first: ir offset {} us, rgb done {} us",
        ir_offset,
        rgb_offset + rgb_elapsed
    );
}

/// A window that began on a camera's first frames after power-on is told
/// from a slow stream by the frames the record names. The profile here is
/// measured: the driver timestamps of the IR stream of a NexiGo N930W
/// (3443:c803) on 2026-11-22, metadata only. In the first session after the
/// camera was plugged in the intervals arriving at frame 1 and at frames 5
/// to 9 run long (432 ms, then 80, 84, 88, 96 and 80 ms against 68 ms) and
/// the cadence is normal from frame 10. The floor is 15 fps at 97 percent,
/// so 30 deltas may span at most 2,061,855 us. Neither path nor floor is
/// changed; the record shows where the first window began and how long it
/// ran, which is what tells this case from a stream that is slow throughout.
#[test]
fn rate_evidence_names_the_frames_of_a_first_window_on_a_measured_startup_profile() {
    let _lock = crate::testenv::env_lock();
    let _env = crate::testenv::EnvGuard::unset("IRLUME_RATE_AMORTIZATION");
    // Driver timestamps in microseconds of frames 0 through 40.
    const AFTER_POWER_ON: &[i64] = &[
        414152152796, 414152584806, 414152652809, 414152720796,
        414152788816, 414152868826, 414152952816, 414153040879,
        414153136824, 414153216827, 414153280849, 414153348723,
        414153416672, 414153484831, 414153552861, 414153620847,
        414153688843, 414153752868, 414153820870, 414153888868,
        414153956878, 414154024884, 414154092882, 414154164880,
        414154228891, 414154296882, 414154364891, 414154432778,
        414154500893, 414154568899, 414154636895, 414154700909,
        414154768908, 414154836919, 414154904917, 414154972916,
        414155040929, 414155109000, 414155172994, 414155240894,
        414155308935,
    ];
    const FIVE_SECONDS_LATER: &[i64] = &[
        414166109777, 414166273806, 414166341613, 414166409834,
        414166481801, 414166553889, 414166625698, 414166693816,
        414166761824, 414166829816, 414166897801, 414166965801,
        414167029846, 414167097839, 414167165828, 414167233824,
        414167301856, 414167369833, 414167437808, 414167501860,
        414167569853, 414167637751, 414167709866, 414167777854,
        414167845756, 414167913783, 414167977877, 414168045881,
        414168113751, 414168181892, 414168249888, 414168317959,
        414168385847, 414168449893, 414168517899, 414168585911,
        414168653793, 414168721914, 414168789904, 414168857811,
        414168921822,
    ];
    const FLOOR_LIMIT_US: u64 = 2_061_855;
    let late_frames = |timestamps: &[i64]| {
        (1..timestamps.len())
            .filter(|&index| timestamps[index] - timestamps[index - 1] > 72_500)
            .map(|index| index as u64)
            .collect::<Vec<_>>()
    };
    assert_eq!(late_frames(AFTER_POWER_ON), [1, 5, 6, 7, 8, 9]);
    assert_eq!(late_frames(FIVE_SECONDS_LATER), [1]);

    for (label, timestamps, fill, first_judged, refused) in [
        // Fixed startup: one warm-up frame, the flush of frames 1 to 5,
        // then a window seeded at frame 6. It holds the late intervals that
        // arrive at frames 7 to 9; the frame after it is refused.
        (
            "fixed startup, first session after power-on",
            AFTER_POWER_ON,
            (6, 36, 2_088_113_u64),
            2_068_121_u64,
            true,
        ),
        (
            "fixed startup, five seconds later",
            FIVE_SECONDS_LATER,
            (6, 36, 2_028_095),
            2_028_098,
            false,
        ),
        // Paired startup: the flush of frames 0 to 4, then a window seeded
        // at frame 5, which holds the late intervals of frames 6 to 9.
        (
            "paired startup, first session after power-on",
            AFTER_POWER_ON,
            (5, 35, 2_104_090),
            2_088_113,
            true,
        ),
        (
            "paired startup, five seconds later",
            FIVE_SECONDS_LATER,
            (5, 35, 2_032_022),
            2_028_095,
            false,
        ),
    ] {
        let mut stream =
            TrackedStream::new(timed_queue(timestamps), role_config(contracts::StreamRole::Ir));
        if label.starts_with("fixed") {
            IrSessionStartup::Fixed
                .warm_up("measured", &mut stream, &no_progress())
                .expect("one warm-up frame");
            IrSessionStartup::Fixed.fill(&mut stream).expect("the window fills on readiness");
        } else {
            drain_until_both_ready(
                &mut stream,
                &std::sync::atomic::AtomicUsize::new(1),
                &std::sync::atomic::AtomicBool::new(false),
                &mut 0,
            )
            .expect("the window fills on readiness");
        }
        assert_eq!(window_of(&stream), (30, fill.0, fill.1, fill.2), "{label}");
        assert!(
            matches!(
                stream.rate_evidence,
                Some(TraceEventKind::RateEvidence {
                    role: CameraRoleLabel::Ir,
                    decision: RateEvidenceDecision::FullWindow,
                    deltas: 30,
                    probe_deltas: None,
                    seed_frame,
                    end_frame,
                    span_us,
                    ..
                }) if (seed_frame, end_frame, span_us) == fill
            ),
            "{label}"
        );
        // The first frame the session delivers is judged on the window as
        // it stands then, seeded one frame later than the fill's own.
        let judged = stream.next().map_err(|error| match error {
            DeliveryError::BelowFloor(evidence) => *evidence,
            other => panic!("{label}: unexpected refusal: {other}"),
        });
        if refused {
            let evidence = judged.expect_err("{label}: below the floor");
            assert_eq!(evidence.window_count, 30);
            assert_eq!(evidence.window_span_us, first_judged, "{label}");
            assert!(evidence.window_span_us > FLOOR_LIMIT_US, "{label}");
            assert!(!evidence.meets_floor);
        } else {
            judged.unwrap_or_else(|error| panic!("{label}: at the floor: {error:?}"));
        }
    }
}

/// A stream that a standalone fill established keeps no record of that
/// window once the paired fill resets it: a paired fill that then fails at
/// its next dequeue reports nothing, not how a window that no longer
/// stands was established.
#[test]
fn rate_evidence_a_failed_paired_fill_leaves_no_record_of_an_earlier_window() {
    let _lock = crate::testenv::env_lock();
    let _env = crate::testenv::EnvGuard::unset("IRLUME_RATE_AMORTIZATION");
    for (role, flush) in [
        (contracts::StreamRole::Rgb, 0_usize),
        (
            contracts::StreamRole::Ir,
            rate_gate::startup_flush(contracts::StreamRole::Ir),
        ),
    ] {
        // One seed, then enough frames for the standalone fill and after
        // it for the paired fill's own flush alone.
        let frames = flush + rate_gate::RATE_WINDOW_CAPACITY + flush;
        let mut stream = stream_with_deltas(role, &floor_deltas(frames));
        stream.fill_rate_evidence().expect("standalone full fill");
        assert_eq!(recorded_evidence(&stream).0, RateEvidenceDecision::FullWindow);

        // A fill that fails sets its own cancel flag, so each stream gets
        // a fresh one: the second is not refused for the first's failure.
        let failed = drain_until_both_ready(
            &mut stream,
            &std::sync::atomic::AtomicUsize::new(1),
            &std::sync::atomic::AtomicBool::new(false),
            &mut 0,
        );
        assert!(failed.is_err(), "the paired fill runs out of frames");
        assert!(
            stream.rate_evidence.is_none(),
            "{role:?}: the record of the reset window is gone"
        );
        assert!(!stream.rate_window.ready() && !stream.health_admitted);
    }
}

#[test]
fn rate_evidence_is_cleared_when_the_established_window_is_revoked() {
    let _lock = crate::testenv::env_lock();
    let _env = crate::testenv::EnvGuard::unset("IRLUME_RATE_AMORTIZATION");
    let (ready, cancelled) = (
        std::sync::atomic::AtomicUsize::new(1),
        std::sync::atomic::AtomicBool::new(false),
    );
    let mut stream = TrackedStream::new(delta_queue(&floor_deltas(80)), role_config(contracts::StreamRole::Rgb));
    drain_until_both_ready(&mut stream, &ready, &cancelled, &mut 0).expect("fill");
    assert_eq!(recorded_evidence(&stream).0, RateEvidenceDecision::FullWindow);

    // The paired Parked handling revokes both admissions and their windows.
    invalidate_paired_rate_admission(&mut stream);
    assert!(
        stream.rate_evidence.is_none(),
        "a revoked window leaves no record behind"
    );
    ready.store(1, std::sync::atomic::Ordering::Release);
    drain_until_both_ready(&mut stream, &ready, &cancelled, &mut 0).expect("refill");
    assert!(stream.rate_evidence.is_some());

    // So does a recovery epoch: the recovered stream owes a new window.
    stream.take();
    let mut replacement = stream_with_deltas(contracts::StreamRole::Rgb, &floor_deltas(40)).take();
    stream.install_recovered(&mut replacement).expect("recovered stream");
    assert!(stream.rate_evidence.is_none());
}

#[test]
fn rate_evidence_full_window_decisions_and_the_record_are_typed() {
    use rate_amortization::Reuse;
    for (reuse, expected) in [
        (Reuse::Unrecorded, RateEvidenceDecision::FullWindow),
        (Reuse::Stale, RateEvidenceDecision::StaleFullWindow),
        (Reuse::Disabled, RateEvidenceDecision::DisabledFullWindow),
        (
            Reuse::Recent,
            RateEvidenceDecision::FullWindow,
        ),
    ] {
        assert_eq!(
            rate_amortization::full_window_decision(reuse, false),
            expected,
            "{reuse:?}"
        );
        assert_eq!(
            rate_amortization::full_window_decision(reuse, true),
            RateEvidenceDecision::ProbeMissed,
            "{reuse:?}: a missed probe is reported whatever it could reuse"
        );
    }
    assert_eq!(
        rate_amortization::rate_evidence(
            contracts::StreamRole::Ir,
            RateEvidenceDecision::ProbeMissed,
            rate_amortization::Window {
                deltas: 30,
                seed_frame: 21,
                end_frame: 51,
                span_us: 2_088_113,
            },
            Some(15),
            false,
            std::time::Duration::from_micros(333_555),
            std::time::Duration::from_micros(2_010_000),
        ),
        TraceEventKind::RateEvidence {
            role: CameraRoleLabel::Ir,
            decision: RateEvidenceDecision::ProbeMissed,
            deltas: 30,
            probe_deltas: Some(15),
            seed_frame: 21,
            end_frame: 51,
            span_us: 2_088_113,
            persisted: false,
            offset_us: 333_555,
            elapsed_us: 2_010_000,
        }
    );
    // A count, an ordinal or a duration that does not fit saturates; it
    // never panics on the capture path.
    assert_eq!(
        rate_amortization::rate_evidence(
            contracts::StreamRole::Rgb,
            RateEvidenceDecision::ProbeAdmitted,
            rate_amortization::Window {
                deltas: usize::MAX,
                seed_frame: u64::MAX,
                end_frame: u64::MAX,
                span_us: u64::MAX,
            },
            Some(usize::MAX),
            false,
            std::time::Duration::MAX,
            std::time::Duration::MAX,
        ),
        TraceEventKind::RateEvidence {
            role: CameraRoleLabel::Rgb,
            decision: RateEvidenceDecision::ProbeAdmitted,
            deltas: u32::MAX,
            probe_deltas: Some(u32::MAX),
            seed_frame: u64::MAX,
            end_frame: u64::MAX,
            span_us: u64::MAX,
            persisted: false,
            offset_us: u64::MAX,
            elapsed_us: u64::MAX,
        }
    );
}

/// `RgbSession` and `IrSession` exist only with a camera, so the accessors
/// that hand their stream's record to the trace are pinned by shape; the
/// record itself is exercised by the tests above.
#[test]
fn sessions_hand_their_streams_rate_evidence_to_the_trace() {
    let lib = include_str!("lib.rs");
    for owner in ["\nimpl<'a> RgbSession<'a> {", "\nimpl IrSession<'_> {"] {
        let body = source_body(lib, owner);
        let start = body
            .find("pub fn diagnostic_rate_evidence(")
            .unwrap_or_else(|| panic!("{owner} lost its rate evidence accessor"));
        // The method ends at column 4; the next such brace after its start.
        let end = body[start..]
            .find("\n    }")
            .expect("a method that ends at column 4");
        let accessor = &body[start..start + end];
        assert!(
            accessor.contains("self.stream.rate_evidence.clone()"),
            "{owner} must return its stream's record"
        );
        assert!(
            accessor.contains("-> Option<irlume_common::diagnostics::TraceEventKind>"),
            "{owner} must return the typed record"
        );
    }
}

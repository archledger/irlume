// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright the irlume contributors.

use super::*;
use crate::sequential_batch::{
    capture_rgb_batch_controlled_with, capture_rgb_batch_with, OverlapStop, RgbBatchRequest,
};
use std::cell::{Cell, RefCell};
use std::collections::VecDeque;
use std::time::{Duration, Instant};

struct Owner<'a> {
    role: &'static str,
    events: &'a RefCell<Vec<String>>,
    now: &'a Cell<Instant>,
    expire_on_drop: bool,
    deadline: Instant,
}

impl Drop for Owner<'_> {
    fn drop(&mut self) {
        self.events
            .borrow_mut()
            .push(format!("{} close", self.role));
        if self.expire_on_drop {
            self.now.set(self.deadline);
        }
    }
}

struct BatchFixture {
    request: SequentialBatchRequest,
    now: Cell<Instant>,
    events: RefCell<Vec<String>>,
    rgb: VecDeque<Frame>,
    ir: VecDeque<(Frame, IrCaptureStats)>,
}

impl BatchFixture {
    fn new(count: usize) -> Self {
        let base = Instant::now();
        let mut rgb = VecDeque::new();
        let mut ir = VecDeque::new();
        for n in 0..count {
            let mut r = runtime_gate_frame(
                contracts::StreamRole::Rgb,
                Spectrum::Rgb,
                contracts::IlluminationProvenance::Unknown,
                'a',
                1,
                *b"RGB3",
                true,
                false,
            );
            let mut i = runtime_gate_frame(
                contracts::StreamRole::Ir,
                Spectrum::Ir,
                contracts::IlluminationProvenance::ActiveIr,
                'a',
                1,
                *b"GREY",
                true,
                false,
            );
            // Script the public monotonic windows independently of wall time.
            r.captured = CaptureWindow::at(base + Duration::from_millis(n as u64 * 100));
            i.captured = CaptureWindow::at(base + Duration::from_millis(1000 + n as u64 * 100));
            r.data[0] = n as u8;
            i.data[0] = (10 + n) as u8;
            rgb.push_back(r);
            ir.push_back((i, stats((20 + n) as f32)));
        }
        Self {
            request: SequentialBatchRequest {
                pairs: count,
                pair_gap_limit: Duration::from_secs(8),
                deadline: base + Duration::from_secs(15),
            },
            now: Cell::new(base),
            events: RefCell::new(Vec::new()),
            rgb,
            ir,
        }
    }

    fn run(&mut self, fault: &str) -> irlume_common::Result<Vec<(Frame, Frame, IrCaptureStats)>> {
        self.run_with(fault, false)
    }

    /// [`Self::run`], logging each reported phase by name beside the owner
    /// events, so the log shows exactly which calls a phase covers.
    fn run_observed(
        &mut self,
        fault: &str,
    ) -> irlume_common::Result<Vec<(Frame, Frame, IrCaptureStats)>> {
        self.run_with(fault, true)
    }

    fn run_with(
        &mut self,
        fault: &str,
        observed: bool,
    ) -> irlume_common::Result<Vec<(Frame, Frame, IrCaptureStats)>> {
        self.run_overlapped(fault, observed, None::<fn(&[Frame], &OverlapStop<'_>)>, |_, _| {})
            .map(|(pairs, _)| pairs)
    }

    /// [`Self::run_with`] with an overlap worker; `on_ir_capture` runs on the
    /// calling thread at the start of each IR capture, given its index and
    /// the event log.
    fn run_overlapped<W: Send>(
        &mut self,
        fault: &str,
        observed: bool,
        overlap: Option<impl FnOnce(&[Frame], &OverlapStop<'_>) -> W + Send>,
        on_ir_capture: impl Fn(usize, &RefCell<Vec<String>>),
    ) -> irlume_common::Result<crate::sequential_batch::OverlappedBatch<W>> {
        let events = &self.events;
        let observe = |phase: SequentialBatchPhase, _elapsed: Duration| {
            if observed {
                events.borrow_mut().push(format!("{phase:?}"));
            }
        };
        let now = &self.now;
        let deadline = self.request.deadline;
        let open = |role| {
            events.borrow_mut().push(format!("{role} open"));
            if fault == format!("{role} open error") {
                return Err(Error::Hardware("scripted open failure".into()));
            }
            if fault == format!("{role} open deadline") {
                now.set(deadline);
            }
            Ok(Owner {
                role,
                events,
                now,
                deadline,
                expire_on_drop: fault == format!("{role} close deadline"),
            })
        };
        let validation_checkpoints = Cell::new(0);
        let ir_captures = Cell::new(0);
        crate::sequential_batch::capture_batch_overlapped_with(
            self.request,
            &runtime_gate_contract(),
            (
                || open("rgb"),
                |_: &mut Owner<'_>| {
                    events.borrow_mut().push("rgb capture".into());
                    if fault == "rgb capture error" && self.rgb.len() == 3 {
                        return Err(Error::Hardware("scripted capture failure".into()));
                    }
                    assert_ne!(fault, "rgb panic", "scripted panic");
                    if fault == "rgb capture deadline" {
                        now.set(deadline);
                    }
                    Ok(self.rgb.pop_front().expect("bounded RGB capture"))
                },
            ),
            (
                || open("ir"),
                |_: &mut Owner<'_>| {
                    on_ir_capture(ir_captures.get(), events);
                    ir_captures.set(ir_captures.get() + 1);
                    events.borrow_mut().push("ir capture".into());
                    if fault == "ir capture error" && self.ir.len() == 3 {
                        return Err(Error::Hardware("scripted capture failure".into()));
                    }
                    assert_ne!(fault, "ir panic", "scripted panic");
                    if fault == "ir capture deadline" {
                        now.set(deadline);
                    }
                    Ok(self.ir.pop_front().expect("bounded IR capture"))
                },
            ),
            || {
                // After IR closes, checkpoints cover phase completion, the
                // whole batch, then before and after each pair validation.
                if events.borrow().last().is_some_and(|e| e == "ir close") {
                    validation_checkpoints.set(validation_checkpoints.get() + 1);
                    if (fault == "validation deadline" && validation_checkpoints.get() == 3)
                        || (fault == "validation after deadline"
                            && validation_checkpoints.get() == 4)
                    {
                        now.set(deadline);
                    }
                }
                now.get()
            },
            &CaptureControl::with_progress(no_progress()),
            || {
                events.borrow_mut().push("lease check".into());
                if fault == "lease deadline" {
                    now.set(deadline);
                }
                if fault == "lease stale" {
                    Err(Error::Hardware("stale lease".into()))
                } else {
                    Ok(())
                }
            },
            &observe,
            overlap,
        )
    }
}

#[test]
fn batch_preserves_order_stats_and_releases_both_sessions_before_return() {
    for count in [1, 5] {
        let mut fixture = BatchFixture::new(count);
        let result = fixture.run("").expect("valid batch");
        assert_eq!(result.len(), count);
        for (n, (r, i, s)) in result.into_iter().enumerate() {
            assert_eq!(
                (r.data[0], i.data[0], s.lit_mean),
                (n as u8, (10 + n) as u8, (20 + n) as f32)
            );
            assert_eq!(s.burst_frames, 8);
        }
        let events = fixture.events.borrow();
        let rgb_close = events.iter().position(|e| e == "rgb close").unwrap();
        let ir_open = events.iter().position(|e| e == "ir open").unwrap();
        assert!(rgb_close < ir_open);
        assert_eq!(&events[events.len() - 2..], ["ir close", "lease check"]);
    }
}

/// How long a test waits for a signal from the other thread before failing
/// instead of hanging.
const OVERLAP_WAIT: Duration = Duration::from_secs(10);

/// The overlap worker reads the released RGB samples in capture order, runs
/// while the IR session captures (the IR phase waits for the worker's start
/// signal, and the worker waits for the second IR capture), finds the stop
/// still down there (the third IR capture waits for its reading), and its
/// result comes back with the unchanged batch.
#[test]
fn overlap_reads_the_released_rgb_samples_while_ir_captures() {
    use std::sync::{
        atomic::{AtomicUsize, Ordering},
        mpsc,
    };
    let mut fixture = BatchFixture::new(5);
    let (started_tx, started_rx) = mpsc::channel();
    let (stop_tx, stop_rx) = mpsc::channel();
    let ir_captures = AtomicUsize::new(0);
    let ir_captures_ref = &ir_captures;
    let overlap = move |rgb: &[Frame], stop: &OverlapStop<'_>| {
        started_tx.send(()).unwrap();
        let waited = Instant::now();
        while ir_captures_ref.load(Ordering::Acquire) < 2 {
            assert!(waited.elapsed() < OVERLAP_WAIT, "the IR phase never ran");
            std::thread::yield_now();
        }
        stop_tx.send(stop.requested()).unwrap();
        rgb.iter().map(|frame| frame.data[0]).collect::<Vec<_>>()
    };
    let (pairs, overlapped) = fixture
        .run_overlapped("", false, Some(overlap), |index, events| {
            if index == 0 {
                started_rx.recv_timeout(OVERLAP_WAIT).expect("the worker started");
                events.borrow_mut().push("overlap started".into());
            }
            if index == 2 {
                let raised = stop_rx.recv_timeout(OVERLAP_WAIT).expect("the worker read the stop");
                events.borrow_mut().push(format!("stop raised mid-phase: {raised}"));
            }
            ir_captures.fetch_add(1, Ordering::Release);
        })
        .expect("valid batch");
    assert_eq!(overlapped, Some(vec![0, 1, 2, 3, 4]));
    assert!(
        fixture.events.borrow().iter().any(|e| e == "stop raised mid-phase: false"),
        "the stop stays down while IR captures"
    );
    assert_eq!(pairs.len(), 5);
    for (n, (r, i, _)) in pairs.iter().enumerate() {
        assert_eq!((r.data[0], i.data[0]), (n as u8, (10 + n) as u8));
    }
    let events = fixture.events.borrow();
    let position = |name: &str| events.iter().position(|e| e == name).unwrap();
    assert!(position("rgb close") < position("ir open"));
    assert!(position("ir open") < position("overlap started"));
    assert!(position("overlap started") < position("ir close"));
}

/// A healthy IR phase also raises the stop flag when it ends, so the batch
/// waits only for the worker's unit in flight; what the worker returns comes
/// back with the batch.
#[test]
fn a_healthy_ir_phase_raises_the_stop_when_it_ends() {
    let mut fixture = BatchFixture::new(5);
    let overlap = |_: &[Frame], stop: &OverlapStop<'_>| {
        let waited = Instant::now();
        while !stop.requested() {
            assert!(waited.elapsed() < OVERLAP_WAIT, "the stop flag never rose");
            std::thread::yield_now();
        }
        "stopped"
    };
    let (pairs, overlapped) = fixture
        .run_overlapped("", false, Some(overlap), |_, _| {})
        .expect("valid batch");
    assert_eq!(pairs.len(), 5);
    assert_eq!(overlapped, Some("stopped"));
}

/// A failed IR phase raises the stop flag and still joins the worker before
/// the error returns; the worker's result is discarded with the batch.
#[test]
fn a_failed_ir_phase_stops_and_joins_the_overlap() {
    use std::sync::atomic::{AtomicBool, Ordering};
    let mut fixture = BatchFixture::new(5);
    let finished = AtomicBool::new(false);
    let finished_ref = &finished;
    let overlap = move |_: &[Frame], stop: &OverlapStop<'_>| {
        let waited = Instant::now();
        while !stop.requested() {
            assert!(waited.elapsed() < OVERLAP_WAIT, "the stop flag never rose");
            std::thread::yield_now();
        }
        finished_ref.store(true, Ordering::Release);
    };
    let result = fixture.run_overlapped("ir capture error", false, Some(overlap), |_, _| {});
    assert!(matches!(result, Err(Error::Hardware(_))));
    assert!(finished.load(Ordering::Acquire), "the worker joined before return");
    assert!(fixture.events.borrow().iter().any(|e| e == "ir close"));
}

/// A panicking worker resumes its panic only after the IR phase has run to
/// its end and reported its release, so no stream outlives the batch.
#[test]
fn an_overlap_panic_resumes_after_the_ir_session_is_released() {
    let mut fixture = BatchFixture::new(5);
    let overlap = |_: &[Frame], _: &OverlapStop<'_>| -> () { panic!("scripted overlap panic") };
    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        fixture.run_overlapped("", true, Some(overlap), |_, _| {})
    }));
    let Err(payload) = result else {
        panic!("the worker's panic resumes");
    };
    assert_eq!(
        payload.downcast_ref::<&str>().copied(),
        Some("scripted overlap panic")
    );
    let events = fixture.events.borrow();
    assert_eq!(events.iter().filter(|e| *e == "ir capture").count(), 5, "{events:?}");
    let position = |name: &str| events.iter().position(|e| e == name);
    let (closed, released) = (position("ir close"), position("IrRelease"));
    assert!(closed.is_some() && released.is_some(), "{events:?}");
    assert!(closed < released, "{events:?}");
    assert!(position("lease check").is_none(), "{events:?}");
}

/// An unwinding IR phase raises the stop flag, and the scope joins the
/// worker before the panic continues.
#[test]
fn an_unwinding_ir_phase_stops_and_joins_the_overlap() {
    use std::sync::atomic::{AtomicBool, Ordering};
    let mut fixture = BatchFixture::new(5);
    let finished = AtomicBool::new(false);
    let finished_ref = &finished;
    let overlap = move |_: &[Frame], stop: &OverlapStop<'_>| {
        let waited = Instant::now();
        while !stop.requested() {
            assert!(waited.elapsed() < OVERLAP_WAIT, "the stop flag never rose");
            std::thread::yield_now();
        }
        finished_ref.store(true, Ordering::Release);
    };
    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        fixture.run_overlapped("ir panic", false, Some(overlap), |_, _| {})
    }));
    assert!(result.is_err(), "the IR panic continues");
    assert!(finished.load(Ordering::Acquire), "the worker joined first");
}

/// Each phase covers exactly its own calls: the start ends when the opener
/// returns, a sample when its capture returns, and the release after the
/// owner is dropped and before the next session opens.
#[test]
fn batch_reports_every_phase_around_exactly_its_own_calls() {
    let mut fixture = BatchFixture::new(5);
    fixture.run_observed("").expect("valid batch");
    let mut expected = vec!["rgb open".to_owned(), "RgbStart".into()];
    for _ in 0..5 {
        expected.extend(["rgb capture".into(), "RgbSample".into()]);
    }
    expected.extend(["rgb close".into(), "RgbRelease".into()]);
    expected.extend(["ir open".into(), "IrStart".into()]);
    for _ in 0..5 {
        expected.extend(["ir capture".into(), "IrSample".into()]);
    }
    expected.extend(["ir close".into(), "IrRelease".into(), "lease check".into()]);
    assert_eq!(*fixture.events.borrow(), expected);
}

/// A failed phase still reports its time; every opened session reports its
/// release, and nothing is reported for a phase that never began. Only an
/// unwinding capture skips the release report; its owner still closes.
#[test]
fn batch_reports_failed_phases_and_the_release_of_every_opened_session() {
    let reported = |fixture: &BatchFixture| -> Vec<String> {
        fixture
            .events
            .borrow()
            .iter()
            .filter(|event| !event.contains(' '))
            .cloned()
            .collect()
    };
    let rgb = |samples: usize| {
        let mut phases = vec!["RgbStart".to_owned()];
        phases.extend(std::iter::repeat_n("RgbSample".to_owned(), samples));
        phases.push("RgbRelease".into());
        phases
    };
    let ir_after_rgb = |samples: usize| {
        let mut phases = rgb(5);
        phases.push("IrStart".into());
        phases.extend(std::iter::repeat_n("IrSample".to_owned(), samples));
        phases.push("IrRelease".into());
        phases
    };
    for (fault, expected) in [
        ("rgb open error", vec!["RgbStart".to_owned()]),
        ("rgb open deadline", rgb(0)),
        ("rgb capture error", rgb(3)),
        ("rgb capture deadline", rgb(1)),
        ("rgb close deadline", rgb(5)),
        ("ir open error", {
            let mut phases = rgb(5);
            phases.push("IrStart".into());
            phases
        }),
        ("ir capture error", ir_after_rgb(3)),
        ("ir close deadline", ir_after_rgb(5)),
        ("lease stale", ir_after_rgb(5)),
    ] {
        let mut fixture = BatchFixture::new(5);
        assert!(fixture.run_observed(fault).is_err(), "{fault}");
        assert_eq!(reported(&fixture), expected, "{fault}");
    }
    for (role, release) in [("rgb", "RgbRelease"), ("ir", "IrRelease")] {
        let mut fixture = BatchFixture::new(5);
        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            fixture.run_observed(&format!("{role} panic"))
        }));
        assert!(result.is_err());
        let events = fixture.events.borrow();
        assert_eq!(events.last().unwrap(), &format!("{role} close"));
        assert!(!events.iter().any(|event| event == release), "{events:?}");
    }
}

#[test]
fn batch_rejects_unbounded_count_before_open() {
    for count in [0, 6, usize::MAX] {
        let mut fixture = BatchFixture::new(0);
        fixture.request.pairs = count;
        assert!(fixture.run("").is_err());
        assert!(fixture.events.borrow().is_empty());
    }
}

#[test]
fn batch_deadline_equality_prevents_open() {
    let mut fixture = BatchFixture::new(5);
    fixture.now.set(fixture.request.deadline);
    assert!(fixture.run("").is_err());
    assert!(fixture.events.borrow().is_empty());
}

#[test]
fn batch_drops_owners_on_capture_errors_and_never_returns_partial_samples() {
    for role in ["rgb", "ir"] {
        let mut fixture = BatchFixture::new(5);
        assert!(fixture.run(&format!("{role} capture error")).is_err());
        assert_eq!(
            fixture.events.borrow().last().unwrap(),
            &format!("{role} close")
        );
        assert_eq!(
            fixture
                .events
                .borrow()
                .iter()
                .filter(|e| **e == format!("{role} capture"))
                .count(),
            3
        );
        assert!(!fixture.events.borrow().iter().any(|e| e == "lease check"));
    }
}

#[test]
fn batch_drops_owners_on_panic() {
    for role in ["rgb", "ir"] {
        let mut fixture = BatchFixture::new(5);
        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            fixture.run(&format!("{role} panic"))
        }));
        assert!(result.is_err());
        assert_eq!(
            fixture.events.borrow().last().unwrap(),
            &format!("{role} close")
        );
    }
}

#[test]
fn batch_checks_deadline_after_open_capture_close_validation_and_lease() {
    for fault in [
        "rgb open deadline",
        "ir open deadline",
        "rgb capture deadline",
        "ir capture deadline",
        "rgb close deadline",
        "ir close deadline",
        "validation deadline",
        "validation after deadline",
        "lease deadline",
    ] {
        let mut fixture = BatchFixture::new(5);
        assert!(fixture.run(fault).is_err(), "{fault}");
        let events = fixture.events.borrow();
        for role in ["rgb", "ir"] {
            if events.contains(&format!("{role} open")) {
                assert!(events.contains(&format!("{role} close")), "{fault}");
            }
        }
        if fault == "rgb open deadline" {
            assert!(!events.contains(&"rgb capture".into()));
        }
        if fault == "ir open deadline" {
            assert!(!events.contains(&"ir capture".into()));
        }
        if fault.starts_with("rgb") {
            assert!(!events.contains(&"ir open".into()));
        }
    }
}

#[test]
fn batch_open_failure_stops_without_recovery() {
    for role in ["rgb", "ir"] {
        let mut fixture = BatchFixture::new(5);
        assert!(fixture.run(&format!("{role} open error")).is_err());
        assert_eq!(
            fixture.events.borrow().last().unwrap(),
            &format!("{role} open")
        );
    }
}

#[test]
fn batch_rejects_lease_invalidation_after_successful_captures() {
    let mut fixture = BatchFixture::new(5);
    assert!(fixture.run("lease stale").is_err());
    assert_eq!(fixture.events.borrow().last().unwrap(), "lease check");
}

#[test]
fn batch_gap_limit_is_inclusive() {
    let mut fixture = BatchFixture::new(5);
    fixture.request.pair_gap_limit = Duration::from_secs(1);
    assert!(fixture.run("").is_ok());
    let mut fixture = BatchFixture::new(5);
    fixture.request.pair_gap_limit = Duration::from_secs(1) - Duration::from_nanos(1);
    assert!(fixture.run("").is_err());
}

#[test]
fn batch_refuses_repeated_reversed_and_overlapping_windows() {
    for role in ["rgb", "ir"] {
        for offset in [0, 2] {
            let mut fixture = BatchFixture::new(5);
            if role == "rgb" {
                fixture.rgb[3].captured = fixture.rgb[offset].captured;
            } else {
                fixture.ir[3].0.captured = fixture.ir[offset].0.captured;
            }
            assert!(fixture.run("").is_err());
        }
    }
}

#[test]
fn batch_refuses_overlapping_phases_and_malformed_windows() {
    let mut fixture = BatchFixture::new(5);
    fixture.ir[0].0.captured = fixture.rgb[4].captured;
    assert!(fixture.run("").is_err());
    for role in ["rgb", "ir"] {
        let mut fixture = BatchFixture::new(5);
        let window = if role == "rgb" {
            &mut fixture.rgb[2].captured
        } else {
            &mut fixture.ir[2].0.captured
        };
        window.start += Duration::from_nanos(1);
        assert!(fixture.run("").is_err());

        let mut fixture = BatchFixture::new(5);
        if role == "rgb" {
            fixture.rgb[2].captured.end = fixture.rgb[3].captured.start;
        } else {
            fixture.ir[2].0.captured.end = fixture.ir[3].0.captured.start;
        }
        assert!(fixture.run("").is_err());
    }
}

#[test]
fn batch_rejects_each_real_runtime_contract_failure() {
    for role in [Spectrum::Rgb, Spectrum::Ir] {
        for case in ["generation", "format", "rate", "continuity", "illumination"] {
            if role == Spectrum::Rgb && case == "illumination" {
                continue; // Active illumination is required only for IR.
            }
            let mut fixture = BatchFixture::new(5);
            let mut invalid = runtime_gate_frame(
                if role == Spectrum::Rgb {
                    contracts::StreamRole::Rgb
                } else {
                    contracts::StreamRole::Ir
                },
                role,
                if role == Spectrum::Rgb || case == "illumination" {
                    contracts::IlluminationProvenance::Unknown
                } else {
                    contracts::IlluminationProvenance::ActiveIr
                },
                'a',
                if case == "generation" { 2 } else { 1 },
                if case == "format" {
                    *b"Y16 "
                } else if role == Spectrum::Rgb {
                    *b"RGB3"
                } else {
                    *b"GREY"
                },
                case != "rate",
                case == "continuity",
            );
            if role == Spectrum::Rgb {
                invalid.captured = fixture.rgb[3].captured;
                fixture.rgb[3] = invalid;
            } else {
                invalid.captured = fixture.ir[3].0.captured;
                fixture.ir[3].0 = invalid;
            }
            assert!(fixture.run("").is_err(), "{role:?}: {case}");
        }
    }
}

#[test]
fn capture_cancellation_releases_rgb_and_never_opens_ir_batch() {
    use std::sync::{atomic::{AtomicBool, Ordering}, Arc};
    let mut fixture = BatchFixture::new(1);
    let cancelled = Arc::new(AtomicBool::new(false));
    let signal = cancelled.clone();
    let control = CaptureControl::new(no_progress(), Arc::new(move || signal.load(Ordering::SeqCst)));
    let events = &fixture.events;
    let now = &fixture.now;
    let deadline = fixture.request.deadline;
    let contract = runtime_gate_contract();
    let result = crate::sequential_batch::capture_batch_controlled_with(
        fixture.request,
        &contract,
        (|| {
            events.borrow_mut().push("rgb open".into());
            Ok(Owner { role: "rgb", events, now, expire_on_drop: false, deadline })
        }, |_owner| {
            cancelled.store(true, Ordering::SeqCst);
            Ok(fixture.rgb.pop_front().unwrap())
        }),
        (|| -> irlume_common::Result<()> { panic!("IR must not open after cancellation") },
         |_owner| -> irlume_common::Result<(Frame, IrCaptureStats)> { panic!("IR must not capture") }),
        || now.get(),
        &control,
        || panic!("cancelled partial batch must not be validated"),
        &|_, _| {},
    );
    assert!(matches!(result, Err(Error::Preempted(_))));
    assert_eq!(*events.borrow(), ["rgb open", "rgb close"]);
}

struct RgbBatchFixture {
    request: RgbBatchRequest,
    now: Cell<Instant>,
    events: RefCell<Vec<String>>,
    frames: VecDeque<Frame>,
}

impl RgbBatchFixture {
    fn new(count: usize) -> Self {
        let base = Instant::now();
        let mut frames = VecDeque::new();
        for n in 0..count {
            let mut f = runtime_gate_frame(
                contracts::StreamRole::Rgb,
                Spectrum::Rgb,
                contracts::IlluminationProvenance::Unknown,
                'a',
                1,
                *b"RGB3",
                true,
                false,
            );
            f.data[0] = n as u8;
            frames.push_back(f);
        }
        Self {
            request: RgbBatchRequest {
                samples: count,
                deadline: base + Duration::from_secs(15),
            },
            now: Cell::new(base),
            events: RefCell::new(Vec::new()),
            frames,
        }
    }

    fn run(&mut self, fault: &str) -> irlume_common::Result<Vec<Frame>> {
        let events = &self.events;
        let now = &self.now;
        let deadline = self.request.deadline;
        let open = || {
            events.borrow_mut().push("rgb open".into());
            if fault == "rgb open error" {
                return Err(Error::Hardware("scripted open failure".into()));
            }
            if fault == "rgb open deadline" {
                now.set(deadline);
            }
            Ok(Owner {
                role: "rgb",
                events,
                now,
                expire_on_drop: fault == "rgb close deadline",
                deadline,
            })
        };
        capture_rgb_batch_with(
            self.request,
            (
                open,
                |_: &mut Owner<'_>| {
                    events.borrow_mut().push("rgb capture".into());
                    if fault == "rgb capture error" && self.frames.len() == 3 {
                        return Err(Error::Hardware("scripted capture failure".into()));
                    }
                    assert_ne!(fault, "rgb panic", "scripted panic");
                    if fault == "rgb capture deadline" {
                        now.set(deadline);
                    }
                    Ok(self.frames.pop_front().expect("bounded RGB sample"))
                },
            ),
            || now.get(),
            || {
                events.borrow_mut().push("lease check".into());
                if fault == "lease deadline" {
                    now.set(deadline);
                }
                if fault == "lease stale" {
                    Err(Error::Hardware("stale lease".into()))
                } else {
                    Ok(())
                }
            },
        )
    }
}

#[test]
fn rgb_batch_collects_every_sample_from_one_session_in_order() {
    for count in [1, 5] {
        let mut fixture = RgbBatchFixture::new(count);
        let result = fixture.run("").expect("valid batch");
        assert_eq!(result.len(), count);
        for (n, frame) in result.into_iter().enumerate() {
            assert_eq!(frame.data[0], n as u8);
        }
        let events = fixture.events.borrow();
        assert_eq!(
            events.iter().filter(|e| **e == "rgb open").count(),
            1,
            "one session for the whole group"
        );
        assert_eq!(
            events.iter().filter(|e| **e == "rgb capture").count(),
            count
        );
        assert_eq!(&events[events.len() - 2..], ["rgb close", "lease check"]);
    }
}

#[test]
fn rgb_batch_rejects_unbounded_count_before_open() {
    for count in [0, 6, usize::MAX] {
        let mut fixture = RgbBatchFixture::new(0);
        fixture.request.samples = count;
        assert!(fixture.run("").is_err());
        assert!(fixture.events.borrow().is_empty());
    }
}

#[test]
fn rgb_batch_deadline_equality_prevents_open() {
    let mut fixture = RgbBatchFixture::new(5);
    fixture.now.set(fixture.request.deadline);
    assert!(fixture.run("").is_err());
    assert!(fixture.events.borrow().is_empty());
}

#[test]
fn rgb_batch_drops_owner_on_capture_error_and_never_returns_partial_samples() {
    let mut fixture = RgbBatchFixture::new(5);
    assert!(fixture.run("rgb capture error").is_err());
    let events = fixture.events.borrow();
    assert_eq!(events.last().unwrap(), "rgb close");
    assert_eq!(events.iter().filter(|e| **e == "rgb capture").count(), 3);
    assert!(!events.iter().any(|e| *e == "lease check"));
}

#[test]
fn rgb_batch_drops_owner_on_panic() {
    let mut fixture = RgbBatchFixture::new(5);
    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        fixture.run("rgb panic")
    }));
    assert!(result.is_err());
    assert_eq!(fixture.events.borrow().last().unwrap(), "rgb close");
}

#[test]
fn rgb_batch_checks_deadline_after_open_capture_close_and_lease() {
    for fault in [
        "rgb open deadline",
        "rgb capture deadline",
        "rgb close deadline",
        "lease deadline",
    ] {
        let mut fixture = RgbBatchFixture::new(5);
        assert!(fixture.run(fault).is_err(), "{fault}");
        let events = fixture.events.borrow();
        if events.contains(&"rgb open".to_string()) {
            assert!(events.contains(&"rgb close".to_string()), "{fault}");
        }
        if fault == "rgb open deadline" {
            assert!(!events.contains(&"rgb capture".to_string()), "{fault}");
        }
    }
}

#[test]
fn rgb_batch_open_failure_stops_without_recovery() {
    let mut fixture = RgbBatchFixture::new(5);
    assert!(fixture.run("rgb open error").is_err());
    assert_eq!(fixture.events.borrow().last().unwrap(), "rgb open");
}

#[test]
fn rgb_batch_rejects_lease_invalidation_after_successful_captures() {
    let mut fixture = RgbBatchFixture::new(5);
    assert!(fixture.run("lease stale").is_err());
    assert_eq!(fixture.events.borrow().last().unwrap(), "lease check");
}

#[test]
fn rgb_batch_cancellation_releases_session_and_returns_no_partial() {
    use std::sync::{
        atomic::{AtomicBool, Ordering},
        Arc,
    };
    let mut fixture = RgbBatchFixture::new(5);
    let cancelled = Arc::new(AtomicBool::new(false));
    let signal = cancelled.clone();
    let control = CaptureControl::new(no_progress(), Arc::new(move || signal.load(Ordering::SeqCst)));
    let events = &fixture.events;
    let now = &fixture.now;
    let deadline = fixture.request.deadline;
    let result = capture_rgb_batch_controlled_with(
        fixture.request,
        (
            || {
                events.borrow_mut().push("rgb open".into());
                Ok(Owner {
                    role: "rgb",
                    events,
                    now,
                    expire_on_drop: false,
                    deadline,
                })
            },
            |_owner| {
                cancelled.store(true, Ordering::SeqCst);
                Ok(fixture.frames.pop_front().unwrap())
            },
        ),
        || now.get(),
        &control,
        || panic!("cancelled partial batch must not be lease-checked"),
    );
    assert!(matches!(result, Err(Error::Preempted(_))));
    assert_eq!(*events.borrow(), ["rgb open", "rgb close"]);
}

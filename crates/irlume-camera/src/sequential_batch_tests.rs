use super::*;
use crate::sequential_batch::capture_batch_with;
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
        let events = &self.events;
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
        capture_batch_with(
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

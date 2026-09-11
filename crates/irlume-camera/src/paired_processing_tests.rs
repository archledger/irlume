// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright the irlume contributors.

use super::*;
use std::cell::Cell;
use std::rc::Rc;
use std::sync::{atomic::{AtomicBool, AtomicUsize, Ordering}, mpsc, Arc};
use std::time::Duration;

use crate::paired_processing::{drain_until_finished, finish_processing, process_with_pair_drains};

const WAIT: Duration = Duration::from_secs(2);

#[test]
fn processing_services_both_queues_independently_on_the_calling_thread() {
    let caller = std::thread::current().id();
    let local = Rc::new(Cell::new(0));
    let captured = local.clone();
    let (rgb_ready, wait_rgb) = mpsc::channel();
    let (ir_ready, wait_ir) = mpsc::channel();
    let (ready, waiting) = mpsc::channel();
    let rgb_done = ready.clone();
    let (mut first_rgb, mut first_ir) = (true, true);
    let output = process_with_pair_drains(
        || {
            waiting.recv_timeout(WAIT).expect("RGB and IR must service independently");
            waiting.recv_timeout(WAIT).expect("both queues must run during processing");
            assert_eq!(std::thread::current().id(), caller);
            captured.set(7);
            captured
        },
        move || {
            if std::mem::take(&mut first_rgb) {
                rgb_ready.send(()).unwrap();
                wait_ir.recv_timeout(WAIT).expect("IR cannot wait behind RGB");
                rgb_done.send(()).unwrap();
            }
            std::thread::sleep(Duration::from_millis(1));
            Ok(())
        },
        move || {
            if std::mem::take(&mut first_ir) {
                ir_ready.send(()).unwrap();
                wait_rgb.recv_timeout(WAIT).expect("RGB cannot wait behind IR");
                ready.send(()).unwrap();
            }
            std::thread::sleep(Duration::from_millis(1));
            Ok(())
        },
    ).unwrap();
    assert!(Rc::ptr_eq(&output, &local), "non-Send result stays on its caller");
    assert_eq!(local.get(), 7);
}

struct Dropped(Rc<Cell<bool>>);
impl Drop for Dropped {
    fn drop(&mut self) { self.0.set(true); }
}

#[test]
fn processing_rejects_success_after_either_in_flight_tail_failure() {
    for fail_rgb in [true, false] {
        let discarded = Rc::new(Cell::new(false));
        let result_drop = discarded.clone();
        let (started, waiting) = mpsc::channel();
        let (finish, release) = mpsc::channel();
        let fail = move || {
            started.send(()).unwrap();
            release.recv_timeout(WAIT).unwrap();
            Err(Error::DeadlineExpired)
        };
        let healthy = || {
            std::thread::sleep(Duration::from_millis(1));
            Ok(())
        };
        let process = || {
            waiting.recv_timeout(WAIT).expect("tail drain must be in flight");
            finish.send(()).unwrap();
            Dropped(result_drop)
        };
        let result = if fail_rgb {
            process_with_pair_drains(process, fail, healthy)
        } else {
            process_with_pair_drains(process, healthy, fail)
        };
        assert!(matches!(result, Err(Error::DeadlineExpired)));
        assert!(discarded.get(), "a successful prepared result must be discarded");
    }
}

#[test]
fn processing_keeps_inner_authentication_errors_separate() {
    let output = finish_processing(
        Ok(Err::<(), _>(Rc::new("inference failure"))),
        || Ok(()),
        || Ok(()),
    ).unwrap();
    assert_eq!(*output.unwrap_err(), "inference failure");
}

struct WorkerDropped(Arc<AtomicBool>);
impl Drop for WorkerDropped {
    fn drop(&mut self) { self.0.store(true, Ordering::SeqCst); }
}

#[test]
fn processing_panic_joins_both_workers_before_unwinding() {
    let (ready, waiting) = mpsc::channel();
    let rgb_dropped = Arc::new(AtomicBool::new(false));
    let ir_dropped = Arc::new(AtomicBool::new(false));
    let make_drain = |ready: mpsc::Sender<()>, dropped| {
        let owner = WorkerDropped(dropped);
        let mut first = true;
        move || {
            let _owner = &owner;
            if std::mem::take(&mut first) { ready.send(()).unwrap(); }
            std::thread::sleep(Duration::from_millis(1));
            Ok(())
        }
    };
    let rgb = make_drain(ready.clone(), rgb_dropped.clone());
    let ir = make_drain(ready, ir_dropped.clone());
    let panic = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        let _ = process_with_pair_drains(
            || {
                waiting.recv_timeout(WAIT).unwrap();
                waiting.recv_timeout(WAIT).unwrap();
                panic!("processing defect");
            }, rgb, ir,
        );
    }));
    assert_eq!(panic.unwrap_err().downcast_ref::<&str>(), Some(&"processing defect"));
    assert!(rgb_dropped.load(Ordering::SeqCst) && ir_dropped.load(Ordering::SeqCst));
}

#[test]
fn processing_drain_panic_is_not_a_camera_result() {
    for panic_rgb in [true, false] {
        let (started, waiting) = mpsc::channel();
        let companion_dropped = Arc::new(AtomicBool::new(false));
        let owner = WorkerDropped(companion_dropped.clone());
        let panicking = move || -> irlume_common::Result<()> {
            started.send(()).unwrap();
            panic!("drain defect");
        };
        let companion = move || {
            let _owner = &owner;
            std::thread::sleep(Duration::from_millis(1));
            Ok(())
        };
        let process = || { waiting.recv_timeout(WAIT).unwrap(); 7 };
        let panic = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            if panic_rgb {
                process_with_pair_drains(process, panicking, companion)
            } else {
                process_with_pair_drains(process, companion, panicking)
            }
        }));
        assert_eq!(panic.unwrap_err().downcast_ref::<&str>(), Some(&"drain defect"));
        assert!(companion_dropped.load(Ordering::SeqCst));
    }
}

#[test]
fn processing_bounds_discard_work_while_processing_continues() {
    let (at_limit, waiting) = mpsc::channel();
    struct NotifyOnDrop(mpsc::Sender<()>);
    impl Drop for NotifyOnDrop {
        fn drop(&mut self) { let _ = self.0.send(()); }
    }
    let finished_drain = NotifyOnDrop(at_limit);
    let calls = Arc::new(AtomicUsize::new(0));
    let count = calls.clone();
    let result = process_with_pair_drains(
        || { waiting.recv_timeout(WAIT).unwrap(); },
        move || {
            let _finished = &finished_drain;
            count.fetch_add(1, Ordering::SeqCst);
            Ok(())
        },
        || { std::thread::sleep(Duration::from_millis(1)); Ok(()) },
    );
    assert!(result.is_err(), "bounded transport work cannot become an accepted result");
    assert_eq!(calls.load(Ordering::SeqCst), 2 * MAX_RATE_FILL_ATTEMPTS);
}

#[test]
fn processing_preserves_the_real_drain_rate_and_continuity_refusals() {
    for gap in [false, true] {
        let mut stream = rate_fill_fixture(contracts::StreamRole::Ir, 100, if gap {66_667} else {200_000});
        if gap {
            stream.next().unwrap();
            stream.stream_mut().unwrap().metadata.front_mut().unwrap().sequence += 1;
        }
        let (started, waiting) = mpsc::channel();
        let output = process_with_pair_drains(
            || { waiting.recv_timeout(WAIT).unwrap(); true },
            move || {
                started.send(()).unwrap();
                drain_pair_frame(&mut stream, "fixture")
            },
            || { std::thread::sleep(Duration::from_millis(1)); Ok(()) },
        );
        if gap {
            assert!(matches!(output, Err(Error::Hardware(ref message)) if message.contains("continuity")));
        } else {
            assert!(matches!(output, Err(Error::DeliveredRate(_))));
        }
    }
}

#[test]
fn processing_preserves_cancellation_observed_by_the_tail_drain() {
    let cancelled = Arc::new(AtomicBool::new(false));
    let signal = cancelled.clone();
    let control = CaptureControl::new(no_progress(), Arc::new(move || signal.load(Ordering::SeqCst)));
    let (started, waiting) = mpsc::channel();
    let (release, released) = mpsc::channel();
    let output = process_with_pair_drains(
        || {
            waiting.recv_timeout(WAIT).unwrap();
            cancelled.store(true, Ordering::SeqCst);
            release.send(()).unwrap();
            true
        },
        move || { started.send(()).unwrap(); released.recv_timeout(WAIT).unwrap(); control.check() },
        || { std::thread::sleep(Duration::from_millis(1)); Ok(()) },
    );
    assert!(matches!(output, Err(Error::Preempted(_))));
}

#[test]
fn processing_prioritizes_cancellation_and_deadline_from_either_worker() {
    for rgb_error in 0..3 {
        for ir_error in 0..3 {
            let (started, waiting) = mpsc::channel();
            let (release_rgb, rgb_released) = mpsc::channel();
            let (release_ir, ir_released) = mpsc::channel();
            let make_drain = |started: mpsc::Sender<()>, released: mpsc::Receiver<()>, error| {
                move || {
                    started.send(()).unwrap();
                    released.recv_timeout(WAIT).unwrap();
                    match error {
                        2 => Err(Error::Preempted("cancelled".into())),
                        1 => Err(Error::DeadlineExpired),
                        _ => Err(Error::Hardware("transport failure".into())),
                    }
                }
            };
            let output = process_with_pair_drains(
                || {
                    waiting.recv_timeout(WAIT).unwrap();
                    waiting.recv_timeout(WAIT).unwrap();
                    release_rgb.send(()).unwrap();
                    release_ir.send(()).unwrap();
                    7
                },
                make_drain(started.clone(), rgb_released, rgb_error),
                make_drain(started, ir_released, ir_error),
            );
            match rgb_error.max(ir_error) {
                2 => assert!(matches!(output, Err(Error::Preempted(_)))),
                1 => assert!(matches!(output, Err(Error::DeadlineExpired))),
                _ => assert!(matches!(output, Err(Error::Hardware(_)))),
            }
        }
    }
}

#[test]
fn processing_rechecks_final_control_even_after_transport_failure() {
    let checked = Cell::new(false);
    let output = finish_processing::<()>(
        Err(Error::Hardware("tail transport failure".into())),
        || { checked.set(true); Err(Error::Preempted("cancelled".into())) },
        || panic!("a rejected result must not consult a stale lease"),
    );
    assert!(checked.get());
    assert!(matches!(output, Err(Error::Preempted(_))));
}

#[test]
fn processing_rejects_success_if_the_final_lease_is_stale() {
    let discarded = Rc::new(Cell::new(false));
    let output = finish_processing(
        Ok(Dropped(discarded.clone())),
        || Ok(()),
        || Err(Error::Hardware("stale lease".into())),
    );
    assert!(matches!(output, Err(Error::Hardware(ref message)) if message == "stale lease"));
    assert!(discarded.get());
}

#[test]
fn processing_preserves_the_transport_cause_instead_of_a_stale_lease() {
    let output = finish_processing::<()>(
        Err(Error::Hardware("IR privacy refused paired drain".into())),
        || Ok(()),
        || panic!("stale lease must not replace the existing privacy failure"),
    );
    assert!(matches!(output, Err(Error::Hardware(ref message)) if message == "IR privacy refused paired drain"));
}

#[test]
fn processing_accepts_completion_during_the_last_bounded_drain() {
    let finished = AtomicBool::new(false);
    let mut calls = 0;
    let output = drain_until_finished(&finished, || {
        calls += 1;
        if calls == 2 * MAX_RATE_FILL_ATTEMPTS { finished.store(true, Ordering::Release); }
        Ok(())
    });
    assert!(output.is_ok());
    assert_eq!(calls, 2 * MAX_RATE_FILL_ATTEMPTS);
}

#[test]
fn processing_preserves_prior_cancellation_over_a_final_deadline() {
    let output = finish_processing::<()>(
        Err(Error::Preempted("cancelled".into())),
        || Err(Error::DeadlineExpired),
        || panic!("a rejected result must not consult its lease"),
    );
    assert!(matches!(output, Err(Error::Preempted(_))));
}

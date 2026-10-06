// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright the irlume contributors.

//! Compose the real transport, camera-state boundary, tracker and warm-up policy.
//! Only device syscalls/state observations and retry sleeps are simulated.

use super::*;
use crate::frame_interval::{FrameInterval, FrameIntervalDomain, FrameIntervalQuery};
use crate::{CameraState, CameraStateStream, CaptureControl, TrackedStream};
use std::cell::RefCell;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::time::Instant;

#[test]
fn paired_startup_native_parked_then_clean_requires_full_window() {
    for errors in [1, 2] {
        let fake = Arc::new(Mutex::new(FakeIo::default()));
        fake.lock().unwrap().next_flags = vec![0x2040; errors].into();
        let dev = Device::with_path("/dev/null").unwrap();
        let control = CaptureControl::with_progress(crate::no_progress());
        let mut stream = open(State::new(&fake), &dev, &control);
        let ready = AtomicUsize::new(1); // companion's independently ready window
        let cancelled = AtomicBool::new(false);
        crate::drain_until_both_ready(&mut stream, &ready, &cancelled, &mut 0)
            .expect("paired admission must consume bounded native Parked before clean evidence");
        // Five sound IR flushes, a new seed and thirty clean deltas.
        assert_eq!(calls(&fake, "DQBUF"), errors + 36);
        assert_eq!(calls(&fake, "view"), 36);
        assert_eq!(calls(&fake, "QBUF"), 39);
        assert_eq!(stream.accounting(), (36, 36, 35));
        assert_eq!(stream.rate_window.count(), 30);
        assert_eq!(stream.rate_window.span_us(), 30_000);
        assert!(stream.rate_window.ready());
        assert!(!stream.health_admitted);
        assert!(!cancelled.load(Ordering::Acquire));
        assert_eq!(ready.load(Ordering::Acquire), 2);
        for index in 0..errors {
            assert!(!fake.lock().unwrap().queued[index]);
        }
        assert_eq!(calls(&fake, "REQBUFS"), 1);
        assert_eq!(calls(&fake, "STREAMON"), 1);
        drop(stream);
        assert_eq!(calls(&fake, "STREAMOFF"), 1);
        assert_eq!(calls(&fake, "REQBUFS(0)"), 1);
        assert_eq!(calls(&fake, "lease-stop"), 1);
        assert_eq!(fake.lock().unwrap().mapped, 0);
    }
}

#[test]
fn paired_startup_native_parked_cannot_admit_from_a_cached_probe() {
    let _guard = crate::testenv::env_lock();
    let _environment = crate::testenv::EnvGuard::unset("IRLUME_RATE_AMORTIZATION");
    let key = crate::rate_amortization::Key::new(
        "native-paired-park-cache",
        crate::contracts::StreamRole::Ir,
    );
    crate::rate_amortization::record_completion(key.clone());
    assert!(crate::rate_amortization::amortizable(&key));
    let fake = Arc::new(Mutex::new(FakeIo::default()));
    fake.lock().unwrap().next_flags = [0x2040].into();
    let dev = Device::with_path("/dev/null").unwrap();
    let control = CaptureControl::with_progress(crate::no_progress());
    let mut stream = open(State::new(&fake), &dev, &control);
    stream.amort_key = Some(key.clone());
    let ready = AtomicUsize::new(1);
    let cancelled = AtomicBool::new(false);
    let result = crate::drain_until_both_ready(&mut stream, &ready, &cancelled, &mut 0);
    crate::rate_amortization::invalidate(&key);
    result.expect("a parked native startup must re-owe the complete clean window");
    assert_eq!(stream.rate_window.count(), 30);
    assert_eq!(stream.rate_window.span_us(), 30_000);
    assert_eq!(calls(&fake, "DQBUF"), 37);
    assert_eq!(calls(&fake, "view"), 36);
    assert!(!stream.health_admitted);
    assert!(!fake.lock().unwrap().queued[0]);
}

#[test]
fn paired_startup_native_terminal_corruption_preserves_ring_retirement() {
    for (flags, granted, dequeues, views) in [
        (vec![0x2040; 3], 4, 3, 0),
        (vec![0x2040], 1, 1, 0),
        (vec![0x2000, 0x2040], 4, 2, 1),
    ] {
        let fake = Arc::new(Mutex::new(FakeIo::default()));
        {
            let mut io = fake.lock().unwrap();
            io.next_flags = flags.into();
            io.granted = granted;
        }
        let dev = Device::with_path("/dev/null").unwrap();
        let control = CaptureControl::with_progress(crate::no_progress());
        let mut stream = open(State::new(&fake), &dev, &control);
        let ready = AtomicUsize::new(1);
        let cancelled = AtomicBool::new(false);
        let error =
            crate::drain_until_both_ready(&mut stream, &ready, &cancelled, &mut 0).unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::InvalidData);
        assert!(!parked(&error));
        assert!(cancelled.load(Ordering::Acquire));
        assert_eq!(ready.load(Ordering::Acquire), 1);
        assert_eq!(calls(&fake, "DQBUF"), dequeues);
        assert_eq!(calls(&fake, "view"), views);
        // The prior SOUND held buffer is returned before the next DQBUF;
        // the ERROR buffer itself is never viewed or requeued.
        assert_eq!(calls(&fake, "QBUF"), granted as usize + views);
        assert!(!stream.rate_window.ready());
        let events = fake.lock().unwrap().events.clone();
        assert!(stream.next_discarded().is_err());
        assert_eq!(
            fake.lock().unwrap().events,
            events,
            "retired ring does no more io"
        );
        drop(stream);
        assert_eq!(calls(&fake, "STREAMOFF"), 1);
        assert_eq!(calls(&fake, "REQBUFS(0)"), 1);
        assert_eq!(fake.lock().unwrap().mapped, 0);
    }
}

#[test]
fn paired_startup_native_does_not_retry_uncertain_queue_start_or_dequeue() {
    for operation in ["QBUF", "STREAMON", "DQBUF"] {
        for errno in [libc::EIO, libc::EINTR, libc::ETIMEDOUT] {
            let fake = Arc::new(Mutex::new(FakeIo::default()));
            let dev = Device::with_path("/dev/null").unwrap();
            let control = CaptureControl::with_progress(crate::no_progress());
            let mut stream = open(State::new(&fake), &dev, &control);
            if operation == "DQBUF" {
                fake.lock().unwrap().dequeues.push_back(Err(errno));
            } else {
                let mut io = fake.lock().unwrap();
                io.fail = Some(operation);
                io.fail_errno = errno;
            }
            let ready = AtomicUsize::new(1);
            let cancelled = AtomicBool::new(false);
            let error =
                crate::drain_until_both_ready(&mut stream, &ready, &cancelled, &mut 0).unwrap_err();
            assert!(!parked(&error), "errno alone is not pending authority");
            assert!(cancelled.load(Ordering::Acquire));
            assert_eq!(calls(&fake, operation), 1);
            assert_eq!(calls(&fake, "view"), 0);
            assert_eq!(stream.accounting(), (0, 0, 0));
            drop(stream);
            assert_eq!(fake.lock().unwrap().mapped, 0);
        }
    }
}

#[test]
fn paired_startup_native_parked_still_checks_cancellation_endpoint_and_privacy() {
    for boundary in ["cancel", "endpoint", "privacy"] {
        let fake = Arc::new(Mutex::new(FakeIo::default()));
        fake.lock().unwrap().next_flags = [0x2040].into();
        let state = State::new(&fake);
        let valid = state.valid.clone();
        let private = state.private.clone();
        let observed = fake.clone();
        let control = CaptureControl::new(
            crate::no_progress(),
            Arc::new(move || {
                let after_park = calls(&observed, "DQBUF") >= 1;
                if after_park && boundary == "endpoint" {
                    valid.store(false, Ordering::SeqCst);
                }
                if after_park && boundary == "privacy" {
                    private.store(true, Ordering::SeqCst);
                }
                after_park && boundary == "cancel"
            }),
        );
        let dev = Device::with_path("/dev/null").unwrap();
        let mut stream = open(state, &dev, &control);
        let ready = AtomicUsize::new(1);
        let cancelled = AtomicBool::new(false);
        assert!(crate::drain_until_both_ready(&mut stream, &ready, &cancelled, &mut 0).is_err());
        assert!(cancelled.load(Ordering::Acquire));
        assert_eq!(
            calls(&fake, "DQBUF"),
            1,
            "{boundary}: no new io after refusal"
        );
        assert_eq!(calls(&fake, "view"), 0);
        assert_eq!(calls(&fake, "QBUF"), 4);
        assert_eq!(stream.accounting(), (0, 0, 0));
        drop(stream);
        assert_eq!(calls(&fake, "STREAMOFF"), 1);
        assert_eq!(calls(&fake, "REQBUFS(0)"), 1);
        assert_eq!(fake.lock().unwrap().mapped, 0);
    }
}

#[test]
fn paired_startup_native_expired_deadline_refuses_before_first_io() {
    let fake = Arc::new(Mutex::new(FakeIo::default()));
    fake.lock().unwrap().next_flags = [0x2040].into();
    let dev = Device::with_path("/dev/null").unwrap();
    let control =
        CaptureControl::with_progress(crate::no_progress()).with_deadline(Some(Instant::now()));
    let mut stream = open(
        State::new(&fake),
        &dev,
        &CaptureControl::with_progress(crate::no_progress()),
    );
    stream.control = control;
    let ready = AtomicUsize::new(1);
    let cancelled = AtomicBool::new(false);
    assert!(crate::drain_until_both_ready(&mut stream, &ready, &cancelled, &mut 0).is_err());
    assert_eq!(calls(&fake, "DQBUF"), 0);
    assert_eq!(calls(&fake, "STREAMON"), 0);
    assert!(cancelled.load(Ordering::Acquire));
    assert!(!stream.rate_window.ready());
}

struct PendingOnly {
    calls: Arc<AtomicUsize>,
}

impl crate::ValidatedStream for PendingOnly {
    fn next_validated(
        &mut self,
    ) -> Result<(&[u8], crate::frame_provenance::DequeuedBufferFacts), crate::ValidatedDequeueError>
    {
        self.calls.fetch_add(1, Ordering::SeqCst);
        Err(crate::ValidatedDequeueError::Io(parked_error_for_test()))
    }
    fn quiesce(&mut self) -> io::Result<()> {
        Ok(())
    }
}

#[test]
fn paired_startup_policy_budget_and_post_admission_pending_stay_terminal() {
    for state in ["new", "observed", "admitted", "recovering"] {
        let calls = Arc::new(AtomicUsize::new(0));
        let mut stream = TrackedStream::new(
            PendingOnly {
                calls: calls.clone(),
            },
            crate::rate_gate::StreamRateConfig::new(
                crate::contracts::StreamRole::Ir,
                interval(),
                interval(),
            ),
        );
        if state == "observed" {
            stream.observations = 1;
        }
        if state == "admitted" {
            stream.health_admitted = true;
        }
        if state == "recovering" {
            stream.recovery_epoch_pending = true;
        }
        let ready = AtomicUsize::new(1);
        let cancelled = AtomicBool::new(false);
        assert!(crate::drain_until_both_ready(&mut stream, &ready, &cancelled, &mut 0).is_err());
        assert_eq!(
            calls.load(Ordering::SeqCst),
            if state == "new" { 3 } else { 1 }
        );
        assert_eq!(ready.load(Ordering::Acquire), 1);
        assert!(cancelled.load(Ordering::Acquire));
        assert!(!stream.rate_window.ready());
    }
}

#[test]
fn paired_startup_native_rgb_first_fill_also_rejects_cached_probe_after_park() {
    let _guard = crate::testenv::env_lock();
    let _environment = crate::testenv::EnvGuard::unset("IRLUME_RATE_AMORTIZATION");
    let key = crate::rate_amortization::Key::new(
        "native-paired-rgb-park",
        crate::contracts::StreamRole::Rgb,
    );
    crate::rate_amortization::record_completion(key.clone());
    let fake = Arc::new(Mutex::new(FakeIo::default()));
    fake.lock().unwrap().next_flags = [0x2040].into();
    let dev = Device::with_path("/dev/null").unwrap();
    let control = CaptureControl::with_progress(crate::no_progress());
    let mut stream = open(State::new(&fake), &dev, &control);
    stream.rate_config = crate::rate_gate::StreamRateConfig::new(
        crate::contracts::StreamRole::Rgb,
        interval(),
        interval(),
    );
    stream.amort_key = Some(key.clone());
    let ready = AtomicUsize::new(1);
    let cancelled = AtomicBool::new(false);
    let result = crate::drain_until_both_ready(&mut stream, &ready, &cancelled, &mut 0);
    crate::rate_amortization::invalidate(&key);
    result.expect("a Parked during RGB's first probe still owes a fresh full window");
    assert_eq!(stream.rate_window.count(), 30);
    assert_eq!(stream.rate_window.span_us(), 30_000);
    assert!(!stream.health_admitted);
    assert!(calls(&fake, "view") >= 31);
    assert_eq!(calls(&fake, "DQBUF"), calls(&fake, "view") + 1);
    assert!(!fake.lock().unwrap().queued[0]);
}

struct PairedNativePaced<'a> {
    native: CameraStateStream<'a, State>,
    side: usize,
    gate: Arc<(Mutex<[usize; 2]>, std::sync::Condvar)>,
}

impl crate::ValidatedStream for PairedNativePaced<'_> {
    fn next_validated(
        &mut self,
    ) -> Result<(&[u8], crate::frame_provenance::DequeuedBufferFacts), crate::ValidatedDequeueError>
    {
        let (lock, wake) = &*self.gate;
        let mut counts = lock.lock().unwrap();
        while counts[self.side] > counts[1 - self.side] + 1 {
            let (next, timeout) = wake.wait_timeout(counts, Duration::from_millis(2)).unwrap();
            counts = next;
            if timeout.timed_out() {
                // A sensor still produces after its companion worker finishes.
                // Pace CPU-only arrivals without making peer liveness a fake
                // transport error; every dequeue still uses the native fixture.
                break;
            }
        }
        counts[self.side] += 1;
        wake.notify_all();
        drop(counts);
        self.native.next_validated()
    }
    fn quiesce(&mut self) -> io::Result<()> {
        self.native.quiesce()
    }
}

#[test]
fn paired_startup_native_parallel_fill_keeps_two_clean_original_windows() {
    for errors in [0, 1, 2] {
        let rgb_fake = Arc::new(Mutex::new(FakeIo::default()));
        let ir_fake = Arc::new(Mutex::new(FakeIo::default()));
        ir_fake.lock().unwrap().next_flags = vec![0x2040; errors].into();
        let rgb_dev = Device::with_path("/dev/null").unwrap();
        let ir_dev = Device::with_path("/dev/null").unwrap();
        let control = CaptureControl::with_progress(crate::no_progress());
        let mut rgb_native = open(State::new(&rgb_fake), &rgb_dev, &control);
        let mut ir_native = open(State::new(&ir_fake), &ir_dev, &control);
        let gate = Arc::new((Mutex::new([0, 0]), std::sync::Condvar::new()));
        let mut rgb = TrackedStream::new(
            PairedNativePaced {
                native: rgb_native.take().unwrap(),
                side: 0,
                gate: gate.clone(),
            },
            crate::rate_gate::StreamRateConfig::new(
                crate::contracts::StreamRole::Rgb,
                interval(),
                interval(),
            ),
        );
        let mut ir = TrackedStream::new(
            PairedNativePaced {
                native: ir_native.take().unwrap(),
                side: 1,
                gate,
            },
            crate::rate_gate::StreamRateConfig::new(
                crate::contracts::StreamRole::Ir,
                interval(),
                interval(),
            ),
        );
        crate::establish_concurrent_rate(&mut rgb, &mut ir).unwrap();
        for (stream, fake, parked_count) in [(&rgb, &rgb_fake, 0), (&ir, &ir_fake, errors)] {
            assert_eq!(stream.rate_window.count(), 30);
            assert_eq!(stream.rate_window.span_us(), 30_000);
            assert!(stream.rate_window.ready());
            assert!(!stream.health_admitted);
            assert_eq!(calls(fake, "DQBUF"), calls(fake, "view") + parked_count);
            assert_eq!(calls(fake, "view") as u64, stream.observations);
            assert_eq!(stream.discarded_observations, stream.observations);
            assert_eq!(calls(fake, "QBUF"), 4 + calls(fake, "view") - 1);
            assert_eq!(calls(fake, "STREAMON"), 1);
            assert_eq!(calls(fake, "REQBUFS"), 1);
        }
        for index in 0..errors {
            assert!(!ir_fake.lock().unwrap().queued[index]);
        }
        drop(rgb);
        drop(ir);
        for fake in [&rgb_fake, &ir_fake] {
            assert_eq!(calls(fake, "STREAMOFF"), 1);
            assert_eq!(calls(fake, "REQBUFS(0)"), 1);
            assert_eq!(calls(fake, "lease-stop"), 1);
            assert_eq!(fake.lock().unwrap().mapped, 0);
        }
    }
}

#[test]
fn paired_startup_native_park_revokes_both_cached_pair_admissions() {
    let _guard = crate::testenv::env_lock();
    let _environment = crate::testenv::EnvGuard::unset("IRLUME_RATE_AMORTIZATION");
    for (parked_side, errors) in [(0, 1), (1, 1), (1, 2)] {
        let rgb_fake = Arc::new(Mutex::new(FakeIo::default()));
        let ir_fake = Arc::new(Mutex::new(FakeIo::default()));
        let parked_fake = if parked_side == 0 {
            &rgb_fake
        } else {
            &ir_fake
        };
        parked_fake.lock().unwrap().next_flags = vec![0x2040; errors].into();
        let rgb_dev = Device::with_path("/dev/null").unwrap();
        let ir_dev = Device::with_path("/dev/null").unwrap();
        let control = CaptureControl::with_progress(crate::no_progress());
        let mut rgb_native = open(State::new(&rgb_fake), &rgb_dev, &control);
        let mut ir_native = open(State::new(&ir_fake), &ir_dev, &control);
        let gate = Arc::new((Mutex::new([0, 0]), std::sync::Condvar::new()));
        let mut rgb = TrackedStream::new(
            PairedNativePaced {
                native: rgb_native.take().unwrap(),
                side: 0,
                gate: gate.clone(),
            },
            crate::rate_gate::StreamRateConfig::new(
                crate::contracts::StreamRole::Rgb,
                interval(),
                interval(),
            ),
        );
        let mut ir = TrackedStream::new(
            PairedNativePaced {
                native: ir_native.take().unwrap(),
                side: 1,
                gate,
            },
            crate::rate_gate::StreamRateConfig::new(
                crate::contracts::StreamRole::Ir,
                interval(),
                interval(),
            ),
        );
        let rgb_key = crate::rate_amortization::Key::new(
            "native-pair-generation-rgb",
            crate::contracts::StreamRole::Rgb,
        );
        let ir_key = crate::rate_amortization::Key::new(
            "native-pair-generation-ir",
            crate::contracts::StreamRole::Ir,
        );
        for key in [&rgb_key, &ir_key] {
            crate::rate_amortization::record_completion(key.clone());
        }
        rgb.amort_key = Some(rgb_key.clone());
        ir.amort_key = Some(ir_key.clone());
        let result = crate::establish_concurrent_rate(&mut rgb, &mut ir);
        for key in [&rgb_key, &ir_key] {
            crate::rate_amortization::invalidate(key);
        }
        result.unwrap();
        for stream in [&rgb, &ir] {
            assert!(
                !stream.health_admitted,
                "a companion probe cannot survive paired startup invalidation"
            );
            assert_eq!(stream.rate_window.count(), 30);
            assert_eq!(stream.rate_window.span_us(), 30_000);
            // Both have collected a wholly fresh window AFTER an initial
            // preparation phase; old/partial readiness cannot finish this pair.
            assert!(
                stream.observations >= 62,
                "fresh phase must replace both prior windows"
            );
        }
        for index in 0..errors {
            assert!(!parked_fake.lock().unwrap().queued[index]);
        }
        drop(rgb);
        drop(ir);
        for fake in [&rgb_fake, &ir_fake] {
            assert_eq!(calls(fake, "STREAMON"), 1);
            assert_eq!(calls(fake, "REQBUFS"), 1);
            assert_eq!(calls(fake, "STREAMOFF"), 1);
            assert_eq!(calls(fake, "REQBUFS(0)"), 1);
            assert_eq!(fake.lock().unwrap().mapped, 0);
        }
    }
}

#[test]
fn paired_startup_native_failed_preparation_revokes_both_admissions() {
    let _guard = crate::testenv::env_lock();
    let _environment = crate::testenv::EnvGuard::unset("IRLUME_RATE_AMORTIZATION");
    for privacy in [false, true] {
        let rgb_fake = Arc::new(Mutex::new(FakeIo::default()));
        let ir_fake = Arc::new(Mutex::new(FakeIo::default()));
        let rgb_dev = Device::with_path("/dev/null").unwrap();
        let ir_dev = Device::with_path("/dev/null").unwrap();
        let control = CaptureControl::with_progress(crate::no_progress());
        let mut rgb = open(State::new(&rgb_fake), &rgb_dev, &control);
        rgb.rate_config = crate::rate_gate::StreamRateConfig::new(
            crate::contracts::StreamRole::Rgb,
            interval(),
            interval(),
        );
        let rgb_key = crate::rate_amortization::Key::new(
            "native-pair-failed-rgb",
            crate::contracts::StreamRole::Rgb,
        );
        let ir_key = crate::rate_amortization::Key::new(
            "native-pair-failed-ir",
            crate::contracts::StreamRole::Ir,
        );
        for key in [&rgb_key, &ir_key] {
            crate::rate_amortization::record_completion(key.clone());
        }
        rgb.amort_key = Some(rgb_key.clone());
        crate::drain_until_both_ready(
            &mut rgb,
            &AtomicUsize::new(1),
            &AtomicBool::new(false),
            &mut 0,
        )
        .unwrap();
        assert!(
            rgb.health_admitted,
            "real cached companion admission positive control"
        );
        assert_eq!(rgb.rate_window.count(), 5);
        let state = State::new(&ir_fake);
        let private = state.private.clone();
        let observed = ir_fake.clone();
        let ir_control = CaptureControl::new(
            crate::no_progress(),
            Arc::new(move || {
                if privacy && calls(&observed, "DQBUF") >= 1 {
                    private.store(true, Ordering::SeqCst);
                }
                false
            }),
        );
        let mut ir = open(state, &ir_dev, &ir_control);
        ir.amort_key = Some(ir_key.clone());
        {
            let mut fake = ir_fake.lock().unwrap();
            fake.next_flags = [0x2040].into();
            if !privacy {
                fake.dequeues = [Ok(0), Err(libc::EIO)].into();
            }
        }
        let result = crate::establish_concurrent_rate(&mut rgb, &mut ir);
        let rgb_cached = crate::rate_amortization::amortizable(&rgb_key);
        let ir_cached = crate::rate_amortization::amortizable(&ir_key);
        for key in [&rgb_key, &ir_key] {
            crate::rate_amortization::invalidate(key);
        }
        let error = result.unwrap_err();
        if privacy {
            assert!(crate::is_privacy_boundary_error(&error));
        } else {
            assert_eq!(
                crate::mmap_capture::source_io(&error).raw_os_error(),
                Some(libc::EIO)
            );
        }
        assert!(!rgb.health_admitted && !ir.health_admitted);
        assert!(!rgb.rate_window.ready() && !ir.rate_window.ready());
        assert_eq!(rgb.rate_window.count(), 0);
        assert_eq!(ir.rate_window.count(), 0);
        assert!(
            !rgb_cached && !ir_cached,
            "failed Parked preparation revokes both caches"
        );
        assert_eq!(calls(&ir_fake, "view"), 0);
        assert!(!ir_fake.lock().unwrap().queued[0]);
        drop(rgb);
        drop(ir);
        for fake in [&rgb_fake, &ir_fake] {
            assert_eq!(calls(fake, "STREAMON"), 1);
            assert_eq!(calls(fake, "STREAMOFF"), 1);
            assert_eq!(calls(fake, "REQBUFS(0)"), 1);
            assert_eq!(fake.lock().unwrap().mapped, 0);
        }
    }
}

#[test]
fn paired_startup_native_image_and_metadata_errors_compose_with_fresh_correlation() {
    let events = Arc::new(Mutex::new(Vec::new()));
    let (log, set_timestamp, check_metadata) =
        crate::ir_metadata::composed_startup_test_log(events.clone());
    let mut metadata = Some(log); // armed before either native image STREAMON
    let rgb_fake = Arc::new(Mutex::new(FakeIo::default()));
    let ir_fake = Arc::new(Mutex::new(FakeIo::default()));
    {
        let mut fake = ir_fake.lock().unwrap();
        fake.next_flags = [0x2040].into();
        fake.shared_events = Some(events.clone());
    }
    let rgb_dev = Device::with_path("/dev/null").unwrap();
    let ir_dev = Device::with_path("/dev/null").unwrap();
    let control = CaptureControl::with_progress(crate::no_progress());
    let mut rgb_native = open(State::new(&rgb_fake), &rgb_dev, &control);
    let mut ir_native = open(State::new(&ir_fake), &ir_dev, &control);
    let gate = Arc::new((Mutex::new([0, 0]), std::sync::Condvar::new()));
    let mut rgb = TrackedStream::new(
        PairedNativePaced {
            native: rgb_native.take().unwrap(),
            side: 0,
            gate: gate.clone(),
        },
        crate::rate_gate::StreamRateConfig::new(
            crate::contracts::StreamRole::Rgb,
            interval(),
            interval(),
        ),
    );
    let mut ir = TrackedStream::new(
        PairedNativePaced {
            native: ir_native.take().unwrap(),
            side: 1,
            gate,
        },
        crate::rate_gate::StreamRateConfig::new(
            crate::contracts::StreamRole::Ir,
            interval(),
            interval(),
        ),
    );
    crate::establish_concurrent_rate(&mut rgb, &mut ir).unwrap();
    for stream in [&rgb, &ir] {
        assert_eq!(stream.rate_window.count(), 30);
        assert_eq!(stream.rate_window.span_us(), 30_000);
        assert!(!stream.health_admitted);
    }
    let stamp = i64::from(ir_fake.lock().unwrap().sequence) * 1000;
    set_timestamp(stamp);
    // Compose the public held-pair fill's existing metadata-drain boundary.
    crate::finish_hidden_rate_fill(Ok::<(), io::Error>(()), false, || {
        metadata.as_mut().unwrap().drain()
    })
    .unwrap();
    let log = metadata.as_ref().unwrap();
    assert_eq!(
        log.illumination_at(1000),
        None,
        "ERROR metadata is never evidence"
    );
    assert_eq!(
        log.illumination_at(stamp),
        Some(crate::ir_metadata::Illumination::Lit)
    );
    assert_eq!(calls(&ir_fake, "DQBUF"), calls(&ir_fake, "view") + 1);
    assert!(!ir_fake.lock().unwrap().queued[0]);
    crate::close_ir_stream(&mut ir, &mut metadata).unwrap();
    assert!(metadata.is_none());
    drop(rgb);
    drop(ir);
    check_metadata();
    let recorded = events.lock().unwrap();
    let position = |event| recorded.iter().position(|value| *value == event).unwrap();
    assert!(position("image-stop") < position("metadata-stop"));
    assert!(position("metadata-stop") < position("metadata-release"));
    assert!(position("metadata-release") < position("image-release"));
    assert_eq!(ir_fake.lock().unwrap().mapped, 0);
    assert_eq!(rgb_fake.lock().unwrap().mapped, 0);
}

struct State {
    fake: Arc<Mutex<FakeIo>>,
    valid: Arc<AtomicBool>,
    private: Arc<AtomicBool>,
    reads: Arc<AtomicUsize>,
}

fn format() -> v4l::Format {
    let mut format = v4l::Format::new(4, 4, v4l::FourCC::new(b"GREY"));
    format.stride = 4;
    format.size = 16;
    format
}

fn interval() -> FrameInterval {
    FrameInterval::new(1, 30).unwrap()
}

impl State {
    fn new(fake: &Arc<Mutex<FakeIo>>) -> Self {
        Self {
            fake: fake.clone(),
            valid: Arc::new(AtomicBool::new(true)),
            private: Arc::new(AtomicBool::new(false)),
            reads: Arc::new(AtomicUsize::new(0)),
        }
    }
}

impl CameraState for State {
    type Device = Device;
    type Claim<'a> = MmapCapture;
    type EndpointError = crate::lease::CameraLeaseError;

    fn set_format(&self, _: &Device, _: &v4l::Format) -> io::Result<v4l::Format> {
        panic!("warm-up must not renegotiate")
    }
    fn interval_domain(
        &self,
        _: &Device,
        _: &v4l::Format,
    ) -> irlume_common::Result<FrameIntervalDomain> {
        panic!("warm-up must not renegotiate")
    }
    fn set_interval(
        &self,
        _: &Device,
        _: FrameIntervalQuery,
        _: FrameInterval,
        _: &'static str,
    ) -> irlume_common::Result<FrameInterval> {
        panic!("warm-up must not renegotiate")
    }
    fn require_endpoint(&self) -> Result<(), Self::EndpointError> {
        if self.valid.load(Ordering::SeqCst) {
            Ok(())
        } else {
            Err(crate::lease::CameraLeaseError::Stale)
        }
    }
    fn require_dequeue_boundary(&self, _: &Device) -> io::Result<()> {
        self.require_endpoint().map_err(io::Error::other)?;
        if self.private.load(Ordering::SeqCst) {
            Err(crate::privacy_boundary_error("test privacy refusal".into()))
        } else {
            Ok(())
        }
    }
    fn compare_format(&self, a: &v4l::Format, b: &v4l::Format) -> Option<String> {
        crate::format_moved(a, b)
    }
    fn claim_buffers(&self, dev: &Device) -> io::Result<MmapCapture> {
        let mut stream = MmapCapture::test_new(dev.handle(), 5000);
        stream.fake = Some(self.fake.clone());
        stream.allocate(4)?;
        Ok(stream)
    }
    fn accepted_interval(&self) -> Option<FrameInterval> {
        Some(interval())
    }
    fn current_format(&self, _: &Device) -> io::Result<v4l::Format> {
        self.reads.fetch_add(1, Ordering::SeqCst);
        Ok(format())
    }
    fn current_interval(
        &self,
        _: &Device,
        _: FrameIntervalQuery,
        _: &'static str,
    ) -> irlume_common::Result<FrameInterval> {
        Ok(interval())
    }
    fn start_stream(&self) -> irlume_common::Result<()> {
        self.fake.lock().unwrap().events.push("lease-start".into());
        Ok(())
    }
    fn stop_stream(&self) {
        self.fake.lock().unwrap().events.push("lease-stop".into());
    }
}

fn open<'a>(
    state: State,
    dev: &'a Device,
    control: &CaptureControl,
) -> TrackedStream<CameraStateStream<'a, State>> {
    let stream = CameraStateStream::open(state, "test-camera", dev, &format()).unwrap();
    TrackedStream::new(
        stream,
        crate::rate_gate::StreamRateConfig::new(
            crate::contracts::StreamRole::Ir,
            interval(),
            interval(),
        ),
    )
    .with_control(control)
}

fn resume_on_last_try(errno: i32, poll: bool, succeeds: bool) {
    let fake = Arc::new(Mutex::new(FakeIo::default()));
    let errors = if succeeds { 7 } else { 8 };
    if poll {
        fake.lock().unwrap().polls = vec![Err(errno); errors].into();
    } else {
        fake.lock().unwrap().dequeues = vec![Err(errno); errors].into();
    }
    let state = State::new(&fake);
    let reads = state.reads.clone();
    let dev = Device::with_path("/dev/null").unwrap();
    let heartbeats = Arc::new(AtomicUsize::new(0));
    let mark = heartbeats.clone();
    let control = CaptureControl::with_progress(Arc::new(move || {
        mark.fetch_add(1, Ordering::SeqCst);
    }));
    let mut stream = open(state, &dev, &control);
    let mut sleeps = 0;
    let result = crate::warm_up_with(
        "test-camera",
        || {
            assert_eq!(stream.accounting(), (0, 0, 0));
            assert_eq!(reads.load(Ordering::SeqCst), 2);
            stream.next_discarded()
        },
        |gap| {
            assert_eq!(gap, Duration::from_millis(120));
            sleeps += 1;
        },
        &control.progress,
    );
    assert_eq!(
        result.is_ok(),
        succeeds,
        "errno={errno}, poll={poll}: {result:?}"
    );
    assert_eq!(sleeps, 7, "errno={errno}, poll={poll}: {result:?}");
    assert_eq!(calls(&fake, "poll"), 8);
    assert_eq!(
        calls(&fake, "DQBUF"),
        if poll { usize::from(succeeds) } else { 8 }
    );
    assert_eq!(calls(&fake, "QBUF"), 4);
    assert_eq!(calls(&fake, "STREAMON"), 1);
    assert_eq!(calls(&fake, "REQBUFS"), 1);
    assert_eq!(
        stream.accounting(),
        if succeeds { (1, 1, 0) } else { (0, 0, 0) }
    );
    assert!(!stream.recovery_epoch_pending);
    assert_eq!(heartbeats.load(Ordering::SeqCst), 0);
    drop(stream);
    assert_eq!(calls(&fake, "STREAMOFF"), 1);
    assert_eq!(calls(&fake, "REQBUFS(0)"), 1);
    assert_eq!(calls(&fake, "lease-stop"), 1);
    assert_eq!(fake.lock().unwrap().mapped, 0);
}

#[test]
fn pending_eio_keeps_the_full_budget_without_restarting_the_queue() {
    for poll in [false, true] {
        for succeeds in [true, false] {
            resume_on_last_try(libc::EIO, poll, succeeds);
        }
    }
}

#[test]
fn pending_enodev_keeps_the_full_budget_while_the_endpoint_remains_valid() {
    for poll in [false, true] {
        for succeeds in [true, false] {
            resume_on_last_try(libc::ENODEV, poll, succeeds);
        }
    }
}

#[test]
fn uncertain_queue_or_start_errors_are_terminal_even_with_a_retryable_kind() {
    for operation in ["QBUF", "STREAMON"] {
        for errno in [
            libc::EIO,
            libc::ENODEV,
            libc::EPIPE,
            libc::ENOTCONN,
            libc::ETIMEDOUT,
        ] {
            for requeue in [false, true] {
                if requeue && operation == "STREAMON" {
                    continue;
                }
                let fake = Arc::new(Mutex::new(FakeIo::default()));
                let dev = Device::with_path("/dev/null").unwrap();
                let heartbeats = Arc::new(AtomicUsize::new(0));
                let mark = heartbeats.clone();
                let control = CaptureControl::with_progress(Arc::new(move || {
                    mark.fetch_add(1, Ordering::SeqCst);
                }));
                let mut stream = open(State::new(&fake), &dev, &control);
                if requeue {
                    stream.next_discarded().unwrap();
                }
                fake.lock().unwrap().fail = Some(operation);
                fake.lock().unwrap().fail_errno = errno;
                let mut sleeps = 0;
                let result = crate::warm_up_with(
                    "test-camera",
                    || stream.next_discarded(),
                    |_| sleeps += 1,
                    &control.progress,
                );
                assert!(result.is_err());
                assert_eq!(sleeps, 0, "{operation}, errno={errno}, requeue={requeue}");
                assert_eq!(heartbeats.load(Ordering::SeqCst), 0);
                assert_eq!(calls(&fake, "poll"), usize::from(requeue));
                let events = fake.lock().unwrap().events.clone();
                assert!(stream.next_discarded().is_err());
                assert_eq!(fake.lock().unwrap().events, events);
                assert!(crate::warm_up_with(
                    "test-camera",
                    || stream.next_discarded(),
                    |_| sleeps += 1,
                    &control.progress,
                )
                .is_err());
                assert_eq!(sleeps, 0, "a retired ring must also fail immediately");
            }
        }
    }
}

#[test]
fn endpoint_or_privacy_refusal_after_a_pending_error_stops_before_more_io() {
    for privacy in [false, true] {
        let fake = Arc::new(Mutex::new(FakeIo::default()));
        fake.lock().unwrap().dequeues.push_back(Err(libc::ENODEV));
        let state = State::new(&fake);
        let valid = state.valid.clone();
        let private = state.private.clone();
        let dev = Device::with_path("/dev/null").unwrap();
        let control = CaptureControl::with_progress(crate::no_progress());
        let mut stream = open(state, &dev, &control);
        let mut sleeps = 0;
        let result = crate::warm_up_with(
            "test-camera",
            || stream.next_discarded(),
            |_| {
                sleeps += 1;
                if privacy {
                    private.store(true, Ordering::SeqCst);
                } else {
                    valid.store(false, Ordering::SeqCst);
                }
            },
            &control.progress,
        );
        assert!(result.is_err());
        assert_eq!(sleeps, 1);
        assert_eq!(calls(&fake, "DQBUF"), 1);
        assert_eq!(calls(&fake, "QBUF"), 4);
        assert_eq!(stream.accounting(), (0, 0, 0));
        assert_eq!(stream.stream.as_ref().unwrap().privacy_refused(), privacy);
    }
}

#[test]
fn cancellation_or_deadline_during_a_pending_retry_remains_authoritative() {
    for expired in [false, true] {
        let fake = Arc::new(Mutex::new(FakeIo::default()));
        fake.lock().unwrap().dequeues.push_back(Err(libc::EIO));
        let cancelled = Arc::new(AtomicBool::new(false));
        let flag = cancelled.clone();
        let control = CaptureControl::new(
            crate::no_progress(),
            Arc::new(move || flag.load(Ordering::SeqCst)),
        );
        let dev = Device::with_path("/dev/null").unwrap();
        let stream = RefCell::new(open(State::new(&fake), &dev, &control));
        let mut sleeps = 0;
        let result = crate::warm_up_with(
            "test-camera",
            || stream.borrow_mut().next_discarded(),
            |_| {
                sleeps += 1;
                if expired {
                    stream.borrow_mut().control = control
                        .clone()
                        .with_deadline(Some(std::time::Instant::now()));
                } else {
                    cancelled.store(true, Ordering::SeqCst);
                }
            },
            &control.progress,
        );
        if expired {
            assert!(matches!(result, Err(irlume_common::Error::DeadlineExpired)));
        } else {
            assert!(matches!(result, Err(irlume_common::Error::Preempted(_))));
        }
        assert_eq!(sleeps, 1);
        assert_eq!(calls(&fake, "DQBUF"), 1);
        assert_eq!(calls(&fake, "QBUF"), 4);
        assert_eq!(stream.borrow().accounting(), (0, 0, 0));
    }
}

#[test]
fn retry_never_requeues_an_unidentified_buffer_consumed_by_eio() {
    let fake = Arc::new(Mutex::new(FakeIo::default()));
    fake.lock().unwrap().consume_on_error = true;
    fake.lock().unwrap().dequeues = [Err(libc::EIO), Ok(1)].into();
    let dev = Device::with_path("/dev/null").unwrap();
    let control = CaptureControl::with_progress(crate::no_progress());
    let mut stream = open(State::new(&fake), &dev, &control);
    crate::warm_up_with(
        "test-camera",
        || stream.next_discarded(),
        |_| {},
        &control.progress,
    )
    .unwrap();
    assert_eq!(calls(&fake, "QBUF"), 4);
    assert_eq!(calls(&fake, "DQBUF"), 2);
    assert!(!fake.lock().unwrap().queued[0]);
    assert_eq!(stream.accounting(), (1, 1, 0));
}

#[test]
fn unrelated_pending_errnos_do_not_spend_the_resume_budget() {
    // EINTR/EAGAIN remain caller-visible as before; raw EIO/ENODEV are the
    // only additions to the warm-up retry policy in this correction.
    for errno in [
        libc::EINVAL,
        libc::EACCES,
        libc::EPROTO,
        libc::ENOSPC,
        libc::EINTR,
        libc::EAGAIN,
    ] {
        for poll in [false, true] {
            let fake = Arc::new(Mutex::new(FakeIo::default()));
            if poll {
                fake.lock().unwrap().polls.push_back(Err(errno));
            } else {
                fake.lock().unwrap().dequeues.push_back(Err(errno));
            }
            let dev = Device::with_path("/dev/null").unwrap();
            let control = CaptureControl::with_progress(crate::no_progress());
            let mut stream = open(State::new(&fake), &dev, &control);
            let mut sleeps = 0;
            assert!(crate::warm_up_with(
                "test-camera",
                || stream.next_discarded(),
                |_| sleeps += 1,
                &control.progress,
            )
            .is_err());
            assert_eq!(sleeps, 0);
            assert_eq!(calls(&fake, "poll"), 1);
            assert_eq!(calls(&fake, "DQBUF"), usize::from(!poll));
            assert_eq!(stream.accounting(), (0, 0, 0));
        }
    }
}

#[test]
fn operation_context_preserves_original_errno_and_actionable_diagnostics() {
    for operation in ["QBUF", "STREAMON", "DQBUF"] {
        for errno in [
            libc::EIO,
            libc::EINVAL,
            libc::EACCES,
            libc::ENOSPC,
            libc::EBUSY,
        ] {
            let fake = Arc::new(Mutex::new(FakeIo::default()));
            fake.lock().unwrap().fail = Some(operation);
            fake.lock().unwrap().fail_errno = errno;
            let mut stream = stream(&fake);
            let error = dequeue_error(&mut stream);
            let source = error.get_ref().unwrap().source().unwrap();
            assert_eq!(
                source.downcast_ref::<io::Error>().unwrap().raw_os_error(),
                Some(errno)
            );
            let mapped = crate::map_io("/nonexistent-test-camera", error);
            if errno == libc::EBUSY {
                assert!(matches!(mapped, irlume_common::Error::CameraBusy(_)));
            } else {
                let message = mapped.to_string();
                let expected = match errno {
                    libc::EACCES => "permission denied",
                    libc::EINVAL => "driver rejected an argument",
                    libc::EIO | libc::ENOSPC => "matching kernel log",
                    _ => unreachable!(),
                };
                assert!(message.contains(expected), "{operation}: {message}");
            }
        }
    }
}

#[cfg(feature = "capture-timing")]
#[test]
fn operation_context_preserves_payload_free_rate_failure_categories() {
    use crate::capture_timing::{CaptureTimings, RateFillFailure};
    for (errno, expected) in [
        (libc::EIO, RateFillFailure::IoDevice),
        (libc::EINVAL, RateFillFailure::IoInvalidArgument),
        (libc::ENOSPC, RateFillFailure::IoNoSpace),
        (libc::EACCES, RateFillFailure::IoPermissionDenied),
        (libc::ETIMEDOUT, RateFillFailure::IoTimeout),
        (libc::ENODEV, RateFillFailure::IoOther),
    ] {
        let fake = Arc::new(Mutex::new(FakeIo::default()));
        fake.lock().unwrap().dequeues.push_back(Err(errno));
        let timings = CaptureTimings::default();
        let control = CaptureControl::with_progress(crate::no_progress())
            .with_capture_timings(Some(timings.clone()));
        let dev = Device::with_path("/dev/null").unwrap();
        let mut stream = open(State::new(&fake), &dev, &control);
        let error = stream.fill_rate_evidence().unwrap_err();
        control.record_rate_fill_failure(&error);
        assert_eq!(timings.rate_fill_failure(), Some(expected));
        assert_eq!(
            calls(&fake, "DQBUF"),
            1,
            "rate fill must not acquire warm-up retries"
        );
    }
}

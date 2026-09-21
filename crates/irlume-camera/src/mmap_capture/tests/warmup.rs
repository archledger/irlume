// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright the irlume contributors.

//! Compose the real transport, camera-state boundary, tracker and warm-up policy.
//! Only device syscalls/state observations and retry sleeps are simulated.

use super::*;
use crate::frame_interval::{FrameInterval, FrameIntervalDomain, FrameIntervalQuery};
use crate::{CameraState, CameraStateStream, CaptureControl, TrackedStream};
use std::cell::RefCell;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

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

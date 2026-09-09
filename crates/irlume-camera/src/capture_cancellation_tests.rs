use super::*;
use std::sync::{atomic::{AtomicBool, AtomicUsize, Ordering}, Arc};

struct CancellingFrames {
    frames: QueuedContinuityFixture,
    calls: Arc<AtomicUsize>,
    cancelled: Arc<AtomicBool>,
    cancel_on: usize,
}

impl ValidatedStream for CancellingFrames {
    fn next_validated(&mut self) -> Result<(&[u8], frame_provenance::DequeuedBufferFacts), ValidatedDequeueError> {
        let call = self.calls.fetch_add(1, Ordering::SeqCst) + 1;
        if call == self.cancel_on {
            self.cancelled.store(true, Ordering::SeqCst);
        }
        self.frames.next_validated()
    }
}

fn fixture(cancel_on: usize) -> (TrackedStream<CancellingFrames>, Arc<AtomicUsize>, Arc<AtomicBool>) {
    let original = rate_fill_fixture(contracts::StreamRole::Rgb, 100, 66_667);
    let cancelled = Arc::new(AtomicBool::new(false));
    let calls = Arc::new(AtomicUsize::new(0));
    let signal = cancelled.clone();
    let mut stream = TrackedStream::new(CancellingFrames {
        frames: original.stream.unwrap(), calls: calls.clone(), cancelled: cancelled.clone(), cancel_on,
    }, original.rate_config);
    stream.control = CaptureControl::new(no_progress(), Arc::new(move || signal.load(Ordering::SeqCst)));
    (stream, calls, cancelled)
}

#[test]
fn capture_cancellation_precedes_any_dequeue() {
    let (mut stream, calls, cancelled) = fixture(usize::MAX);
    cancelled.store(true, Ordering::SeqCst);
    let result = stream.next_discarded();
    assert!(result.as_ref().is_err_and(capture_control::is_cancelled), "cancelled request must not dequeue");
    assert_eq!(calls.load(Ordering::SeqCst), 0);
}

#[test]
fn capture_cancellation_stops_rate_fill_at_the_returned_frame() {
    let (mut stream, calls, _) = fixture(3);
    let result = stream.fill_rate_evidence();
    assert!(result.as_ref().is_err_and(capture_control::is_cancelled), "rate fill must stop after cancellation");
    assert_eq!(calls.load(Ordering::SeqCst), 3);
    assert!(!stream.rate_window.ready());
    assert_eq!(stream.accounting().0, 2, "late frame must not contribute evidence");
}

#[test]
fn capture_cancellation_discards_a_late_delivered_frame() {
    let (mut stream, calls, _) = fixture(usize::MAX);
    stream.fill_rate_evidence().unwrap();
    let before = stream.accounting();
    let cancel_on = calls.load(Ordering::SeqCst) + 1;
    stream.stream.as_mut().unwrap().cancel_on = cancel_on;
    let result = stream.next();
    assert!(matches!(result, Err(DeliveryError::Io(ref error)) if capture_control::is_cancelled(error)), "late delivered frame must be discarded");
    assert_eq!(stream.accounting(), before);
    assert_eq!(calls.load(Ordering::SeqCst), cancel_on);
}

#[test]
fn capture_cancellation_is_not_a_hardware_fault_or_driver_interrupt() {
    let control = CaptureControl::new(no_progress(), Arc::new(|| true));
    assert!(matches!(map_io("synthetic", control.check_io().unwrap_err()), Error::Preempted(_)));
    assert!(matches!(map_io("synthetic", std::io::Error::from_raw_os_error(libc::EINTR)), Error::Hardware(_)));
}

#[test]
fn capture_cancellation_does_not_poison_a_fresh_request() {
    let (mut cancelled_stream, _, signal) = fixture(usize::MAX);
    signal.store(true, Ordering::SeqCst);
    let _ = cancelled_stream.next_discarded();
    drop(cancelled_stream);
    let (mut fresh, _, _) = fixture(usize::MAX);
    assert!(fresh.next().is_ok(), "next request must establish and deliver normally");
}

#[test]
fn capture_cancellation_stops_warmup_after_a_completed_timeout_and_heartbeat() {
    struct SilentFrames(Arc<AtomicUsize>);
    impl ValidatedStream for SilentFrames {
        fn next_validated(&mut self) -> Result<(&[u8], frame_provenance::DequeuedBufferFacts), ValidatedDequeueError> {
            self.0.fetch_add(1, Ordering::SeqCst);
            Err(ValidatedDequeueError::Io(std::io::ErrorKind::TimedOut.into()))
        }
    }
    let calls = Arc::new(AtomicUsize::new(0));
    let reports = Arc::new(AtomicUsize::new(0));
    let cancelled = Arc::new(AtomicBool::new(false));
    let (mark, cancel) = (reports.clone(), cancelled.clone());
    let progress: Progress = Arc::new(move || {
        mark.fetch_add(1, Ordering::SeqCst);
        cancel.store(true, Ordering::SeqCst);
    });
    let control = CaptureControl::new(progress, Arc::new(move || cancelled.load(Ordering::SeqCst)));
    let mut stream = TrackedStream::new(SilentFrames(calls.clone()), test_rate_config(contracts::StreamRole::Rgb)).with_control(&control);
    let result = warm_up_with("synthetic", || stream.next_discarded(), |_| {}, &control.progress);
    assert!(matches!(result, Err(Error::Preempted(_))));
    assert_eq!(calls.load(Ordering::SeqCst), 1, "cancelled warmup must not spend another driver window");
    assert_eq!(reports.load(Ordering::SeqCst), 1, "completed timeout must still report watchdog progress");
}

#[test]
fn capture_deadline_precedes_dequeue_and_is_not_a_hardware_fault() {
    let (mut stream, calls, _) = fixture(usize::MAX);
    stream.control = stream.control.clone().with_deadline(Some(std::time::Instant::now()));
    let result = stream.next_discarded();
    assert!(result.is_err(), "expired capture must not dequeue");
    assert!(matches!(map_io("synthetic", result.unwrap_err()), Error::DeadlineExpired));
    assert_eq!(calls.load(Ordering::SeqCst), 0);
    assert!(matches!(map_io("synthetic", std::io::ErrorKind::TimedOut.into()), Error::Hardware(_)), "a real driver timeout must retain hardware handling");
}

#[test]
fn capture_deadline_precedes_device_open_and_cancellation_keeps_precedence() {
    let control = CaptureControl::with_progress(no_progress()).with_deadline(Some(std::time::Instant::now()));
    let result = capture_rgb_denoised_with_control("/nonexistent/irlume-deadline-fixture", &control);
    assert!(matches!(result, Err(Error::DeadlineExpired)));
    let cancelled = CaptureControl::new(no_progress(), Arc::new(|| true)).with_deadline(Some(std::time::Instant::now()));
    assert!(matches!(cancelled.check(), Err(Error::Preempted(_))));
}

#[test]
fn capture_deadline_is_not_retried_as_a_driver_warmup_timeout() {
    let control = CaptureControl::with_progress(no_progress()).with_deadline(Some(std::time::Instant::now()));
    let (mut calls, mut sleeps) = (0, 0);
    let result = warm_up_with("synthetic", || { calls += 1; control.check_io() }, |_| sleeps += 1, &control.progress);
    assert!(matches!(result, Err(Error::DeadlineExpired)));
    assert_eq!(calls, 1, "expired request must not be retried as a driver timeout");
    assert_eq!(sleeps, 0);
}

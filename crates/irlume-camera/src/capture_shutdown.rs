// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright the irlume contributors.

//! Producer quiescence, distinct from a best-effort teardown attempt.
//!
//! On an unconfirmed main-stream stop, keep kernel-facing owners alive rather
//! than freeing descriptors still reachable by UVC callbacks. The native domain
//! is process-lifetime storage and faults further capture admission. It is never
//! drained on a timer or on guessed fd-close/disconnect evidence. This contains
//! cooperative failure paths; it cannot repair a kernel or protect forced process
//! termination from driver bugs.

use std::{
    any::Any,
    io,
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc, Mutex, OnceLock,
    },
};

type Owner = Box<dyn Any + Send>;

#[derive(Default)]
struct Domain {
    faulted: AtomicBool,
    retained: Mutex<Vec<Owner>>,
}

fn native_domain() -> &'static Arc<Domain> {
    static DOMAIN: OnceLock<Arc<Domain>> = OnceLock::new();
    DOMAIN.get_or_init(|| Arc::new(Domain::default()))
}

#[derive(Debug)]
struct UnconfirmedShutdown;

impl std::fmt::Display for UnconfirmedShutdown {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("capture unavailable: a stream stop was not confirmed; kernel-facing resources are retained")
    }
}

impl std::error::Error for UnconfirmedShutdown {}

fn fault() -> io::Error {
    io::Error::other(UnconfirmedShutdown)
}

pub(crate) fn is_fault(error: &io::Error) -> bool {
    error
        .get_ref()
        .is_some_and(|inner| inner.is::<UnconfirmedShutdown>())
}

pub(crate) fn check_capture() -> io::Result<()> {
    native_domain().check()
}

impl Domain {
    fn check(&self) -> io::Result<()> {
        if self.faulted.load(Ordering::Acquire) {
            Err(fault())
        } else {
            Ok(())
        }
    }

    fn retain(&self, mut owners: Vec<Owner>) {
        let first_fault = !self.faulted.swap(true, Ordering::AcqRel);
        self.retained
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .append(&mut owners);
        // Logging must not unwind this transition: the caller may still need
        // to transfer its image mappings after retaining these dependents.
        if first_fault {
            irlume_common::jout_err!("irlume: main camera stream stop is unconfirmed; retaining resources and refusing further capture in this process");
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Phase {
    NeverStarted,
    Producing,
    Stopped,
    Unconfirmed,
}

struct State {
    phase: Phase,
    deferred: Vec<Owner>,
}

#[derive(Clone)]
pub(crate) struct Producer {
    state: Arc<Mutex<State>>,
    domain: Arc<Domain>,
}

impl Producer {
    pub(crate) fn new() -> Self {
        Self::in_domain(native_domain().clone())
    }

    fn in_domain(domain: Arc<Domain>) -> Self {
        Self {
            domain,
            state: Arc::new(Mutex::new(State {
                phase: Phase::NeverStarted,
                deferred: Vec::new(),
            })),
        }
    }

    #[cfg(test)]
    pub(crate) fn for_test() -> Self {
        Self::in_domain(Arc::new(Domain::default()))
    }

    pub(crate) fn check(&self) -> io::Result<()> {
        self.domain.check()
    }

    pub(crate) fn begin(&self) -> io::Result<()> {
        self.check()?;
        let mut state = self.state.lock().unwrap_or_else(|e| e.into_inner());
        if state.phase != Phase::NeverStarted {
            return Err(io::Error::other("capture producer cannot be started twice"));
        }
        state.phase = Phase::Producing;
        Ok(())
    }

    pub(crate) fn is_quiescent(&self) -> bool {
        matches!(
            self.state.lock().unwrap_or_else(|e| e.into_inner()).phase,
            Phase::NeverStarted | Phase::Stopped
        )
    }

    pub(crate) fn stopped(&self) {
        let deferred = {
            let mut state = self.state.lock().unwrap_or_else(|e| e.into_inner());
            // Once quarantined, no later guess may resurrect this owner.
            if state.phase == Phase::Unconfirmed {
                return;
            }
            state.phase = Phase::Stopped;
            std::mem::take(&mut state.deferred)
        };
        drop(deferred);
    }

    pub(crate) fn unconfirmed(&self) {
        let deferred = {
            let mut state = self.state.lock().unwrap_or_else(|e| e.into_inner());
            state.phase = Phase::Unconfirmed;
            std::mem::take(&mut state.deferred)
        };
        self.domain.retain(deferred);
    }

    /// The owner must have its Producer link removed before it is deferred.
    pub(crate) fn after_stop<T: Any + Send>(&self, owner: T) {
        let owner: Owner = Box::new(owner);
        let mut state = self.state.lock().unwrap_or_else(|e| e.into_inner());
        match state.phase {
            Phase::NeverStarted | Phase::Stopped => {
                drop(state);
                drop(owner);
            }
            Phase::Producing => state.deferred.push(owner),
            Phase::Unconfirmed => {
                drop(state);
                self.domain.retain(vec![owner]);
            }
        }
    }

    #[cfg(test)]
    fn retained(&self) -> usize {
        self.domain.retained.lock().unwrap().len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    struct Mark(Arc<Mutex<Vec<&'static str>>>, &'static str);
    impl Drop for Mark {
        fn drop(&mut self) {
            self.0.lock().unwrap().push(self.1);
        }
    }

    #[test]
    fn coupled_owners_wait_for_successful_producer_stop() {
        let producer = Producer::for_test();
        let events = Arc::new(Mutex::new(Vec::new()));
        producer.begin().unwrap();
        producer.after_stop(Mark(events.clone(), "metadata"));
        producer.after_stop(Mark(events.clone(), "emitter"));
        assert!(events.lock().unwrap().is_empty());
        producer.stopped();
        assert_eq!(*events.lock().unwrap(), ["metadata", "emitter"]);
        assert_eq!(producer.retained(), 0);
    }

    #[test]
    fn unknown_stop_keeps_existing_and_later_owners_and_faults_admission() {
        let producer = Producer::for_test();
        let events = Arc::new(Mutex::new(Vec::new()));
        producer.begin().unwrap();
        producer.after_stop(Mark(events.clone(), "metadata"));
        producer.unconfirmed();
        producer.after_stop(Mark(events.clone(), "image"));
        producer.after_stop(Mark(events.clone(), "emitter"));
        assert!(is_fault(&producer.check().unwrap_err()));
        assert_eq!(producer.retained(), 3);
        assert!(events.lock().unwrap().is_empty());
        producer.stopped(); // No revival from an unproven late notification.
        assert!(!producer.is_quiescent());
        assert!(events.lock().unwrap().is_empty());
        // This isolated test domain contains only markers; native storage has
        // process lifetime and is never drained by application recovery.
    }

    #[test]
    fn a_producer_that_never_started_needs_no_stop_to_release_a_dependent() {
        let producer = Producer::for_test();
        let events = Arc::new(Mutex::new(Vec::new()));
        producer.after_stop(Mark(events.clone(), "metadata"));
        assert_eq!(*events.lock().unwrap(), ["metadata"]);
        assert!(producer.check().is_ok());
    }

    #[test]
    fn process_fault_refuses_capture_without_overriding_cancel_or_deadline() {
        const CHILD: &str = "IRLUME_TEST_CAPTURE_SHUTDOWN_CHILD";
        if std::env::var_os(CHILD).is_some() {
            let producer = Producer::new();
            producer.begin().unwrap();
            producer.unconfirmed();
            let control = crate::CaptureControl::with_progress(crate::no_progress());
            assert!(matches!(
                control.check(),
                Err(irlume_common::Error::Hardware(_))
            ));
            let cancelled = crate::CaptureControl::new(crate::no_progress(), Arc::new(|| true));
            assert!(matches!(
                cancelled.check(),
                Err(irlume_common::Error::Preempted(_))
            ));
            let expired = control
                .clone()
                .with_deadline(Some(std::time::Instant::now()));
            assert!(matches!(
                expired.check(),
                Err(irlume_common::Error::DeadlineExpired)
            ));
            let mut sleeps = 0;
            assert!(crate::warm_up_with(
                "test",
                || control.check_io(),
                |_| sleeps += 1,
                &control.progress
            )
            .is_err());
            assert_eq!(sleeps, 0);
            let device = v4l::Device::with_path("/dev/null").unwrap();
            let error = crate::mmap_capture::MmapCapture::with_buffers(
                &device,
                4,
                std::time::Duration::from_secs(5),
            )
            .err()
            .expect("capture is refused before REQBUFS");
            assert!(is_fault(&error));
            return;
        }
        let _env = crate::testenv::env_lock();
        let output = std::process::Command::new(std::env::current_exe().unwrap())
            .args(["capture_shutdown::tests::process_fault_refuses_capture_without_overriding_cancel_or_deadline", "--exact", "--nocapture"])
            .env(CHILD, "1").output().unwrap();
        assert!(
            output.status.success(),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
    }
}

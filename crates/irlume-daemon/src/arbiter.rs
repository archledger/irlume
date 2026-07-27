// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright the irlume contributors.

//! Who gets the camera next.
//!
//! The daemon serves requests from one worker that owns the [`Engine`], because
//! two threads driving V4L2 and ONNX over one device is not something to attempt
//! on an authentication path. That single worker is also the problem: before
//! this module, a local account running a legitimate self-enrollment held it for
//! as long as the enrollment took, and a lock-screen unlock arriving meanwhile
//! waited in the kernel accept backlog where the daemon could not even see it.
//!
//! So connections are now read and parsed off the worker, and what they parse
//! into is queued here. Two rules do the work:
//!
//! * **Authentication goes first.** A queued or running authentication is what
//!   makes every other camera request wait.
//! * **Non-authentication camera work is refused, not queued,** while
//!   authentication is pending, and each unprivileged uid may hold at most one
//!   camera slot. Refusing beats queueing: a preview client that is told to come
//!   back has lost a frame, while one that is queued behind an enrollment holds
//!   a slot the login path may want.
//!
//! What this deliberately does not do is preempt. An operation already running
//! runs to completion, so an enrollment in flight still delays a login until it
//! finishes. Stopping one early means checking a signal between whole captures,
//! inside `irlume_auth`'s enrollment loop rather than here, and that is the
//! second half of issue #117.
//!
//! [`Engine`]: irlume_auth::Engine

use irlume_common::Request;
use std::collections::VecDeque;
use std::sync::{Condvar, Mutex};

/// What a request costs and how much it may delay a login.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Class {
    /// The login path: face authentication, and the credential release that
    /// follows it. Never refused, always served before other camera work.
    Auth,
    /// Opens the camera without being an authentication: the framing guide,
    /// 1:N identify, enrollment, emitter probes, self-tests.
    Camera,
    /// Touches no camera: listings, keyring metadata, settings. Cheap enough
    /// that arbitration would cost more than it saves.
    Plain,
}

/// Classify a request by what it does to the camera, not by who sent it.
///
/// `Authenticate` is the login path. The unseal operations are the credential
/// release that a successful authentication leads to, and delaying them behind a
/// preview would leave a user logged in with a locked keyring, so they share the
/// priority rather than competing with it.
pub fn classify(req: &Request) -> Class {
    use Request::*;
    match req {
        Authenticate { .. } | UnsealPassword { .. } | UnsealKeyring { .. } => Class::Auth,
        PositionSample { .. }
        | Identify
        | Enroll { .. }
        | AddScan { .. }
        | CaptureEarMedian { .. }
        | SetupIrEmitter { .. }
        | TuneCaptureMode { .. }
        | SelfTest { .. } => Class::Camera,
        _ => Class::Plain,
    }
}

/// Why a camera request was turned away, in words a client can show.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Refusal {
    /// An authentication is queued or running. The camera belongs to it.
    AuthenticationPending,
    /// This uid already has a camera operation queued or running.
    AlreadyHoldsSlot,
}

impl Refusal {
    pub fn message(self) -> &'static str {
        match self {
            Refusal::AuthenticationPending => {
                "camera busy: an authentication has priority; retry in a moment"
            }
            Refusal::AlreadyHoldsSlot => {
                "camera busy: this account already has a camera operation in flight"
            }
        }
    }
}

/// One queued unit of work: what to run, and who asked.
pub struct Job<T> {
    pub class: Class,
    pub uid: u32,
    pub payload: T,
}

struct Inner<T> {
    auth: VecDeque<Job<T>>,
    other: VecDeque<Job<T>>,
    /// Uids with a camera job queued or running. Root is never tracked: the
    /// greeter and PAM run as root, and holding them to one camera operation
    /// would be a denial of the login path rather than a fairness rule.
    camera_slots: Vec<u32>,
    /// An authentication is running (queue length alone would miss it).
    auth_running: bool,
    closed: bool,
}

impl<T> Inner<T> {
    fn auth_pending(&self) -> bool {
        self.auth_running || !self.auth.is_empty()
    }
}

/// The queue itself: submission decides admission, the worker takes what is next.
pub struct Arbiter<T> {
    inner: Mutex<Inner<T>>,
    ready: Condvar,
}

impl<T> Default for Arbiter<T> {
    fn default() -> Self {
        Self::new()
    }
}

impl<T> Arbiter<T> {
    pub fn new() -> Self {
        Arbiter {
            inner: Mutex::new(Inner {
                auth: VecDeque::new(),
                other: VecDeque::new(),
                camera_slots: Vec::new(),
                auth_running: false,
                closed: false,
            }),
            ready: Condvar::new(),
        }
    }

    /// Offer a request to the queue.
    ///
    /// `Err(refusal)` means the caller should answer the client immediately; the
    /// job was not queued and holds nothing.
    pub fn submit(&self, class: Class, uid: u32, payload: T) -> Result<(), Refusal> {
        let mut inner = self.lock();
        match class {
            // An authentication never waits behind preview work.
            Class::Auth => inner.auth.push_back(Job {
                class,
                uid,
                payload,
            }),
            Class::Camera => {
                if inner.auth_pending() {
                    return Err(Refusal::AuthenticationPending);
                }
                if uid != 0 && inner.camera_slots.contains(&uid) {
                    return Err(Refusal::AlreadyHoldsSlot);
                }
                if uid != 0 {
                    inner.camera_slots.push(uid);
                }
                inner.other.push_back(Job {
                    class,
                    uid,
                    payload,
                });
            }
            Class::Plain => inner.other.push_back(Job {
                class,
                uid,
                payload,
            }),
        }
        self.ready.notify_one();
        Ok(())
    }

    /// Block until there is work, and take the most urgent job.
    ///
    /// `None` once the arbiter is closed and drained, which is the worker's
    /// signal to exit.
    pub fn take(&self) -> Option<Job<T>> {
        let mut inner = self.lock();
        loop {
            if let Some(job) = inner.auth.pop_front() {
                inner.auth_running = true;
                return Some(job);
            }
            if let Some(job) = inner.other.pop_front() {
                return Some(job);
            }
            if inner.closed {
                return None;
            }
            inner = self
                .ready
                .wait(inner)
                .unwrap_or_else(|poisoned| poisoned.into_inner());
        }
    }

    /// Release what a finished job held. Always call this, including when the
    /// job panicked: a slot that is never released is a uid locked out of the
    /// camera until the daemon restarts.
    pub fn finish(&self, job_class: Class, uid: u32) {
        let mut inner = self.lock();
        if job_class == Class::Auth {
            inner.auth_running = false;
        }
        if let Some(i) = inner.camera_slots.iter().position(|&u| u == uid) {
            inner.camera_slots.swap_remove(i);
        }
        // A camera request refused while this one ran can now be retried, and a
        // waiting worker needs waking if the queue filled while it slept.
        self.ready.notify_one();
    }

    /// Stop accepting work and wake the worker so it can drain and exit.
    pub fn close(&self) {
        self.lock().closed = true;
        self.ready.notify_all();
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, Inner<T>> {
        // A poisoned queue is still a usable queue: the alternative is that one
        // panicking job takes down every future login.
        self.inner
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn arb() -> Arbiter<&'static str> {
        Arbiter::new()
    }

    #[test]
    fn authentication_is_taken_before_camera_work_that_arrived_first() {
        let a = arb();
        a.submit(Class::Camera, 1000, "preview").unwrap();
        a.submit(Class::Plain, 1000, "listing").unwrap();
        a.submit(Class::Auth, 0, "login").unwrap();
        // Queued last, served first: that is the whole point.
        assert_eq!(a.take().unwrap().payload, "login");
    }

    #[test]
    fn camera_work_is_refused_while_an_authentication_waits() {
        let a = arb();
        a.submit(Class::Auth, 0, "login").unwrap();
        assert_eq!(
            a.submit(Class::Camera, 1000, "preview"),
            Err(Refusal::AuthenticationPending)
        );
        // Refusing is not the same as blocking the machine: work that does not
        // touch the camera still goes through.
        assert!(a.submit(Class::Plain, 1000, "listing").is_ok());
    }

    #[test]
    fn camera_work_is_refused_while_an_authentication_runs() {
        let a = arb();
        a.submit(Class::Auth, 0, "login").unwrap();
        let job = a.take().unwrap();
        // The queue is empty now, so only `auth_running` can carry the refusal.
        assert_eq!(
            a.submit(Class::Camera, 1000, "preview"),
            Err(Refusal::AuthenticationPending)
        );
        a.finish(job.class, job.uid);
        assert!(a.submit(Class::Camera, 1000, "preview").is_ok());
    }

    #[test]
    fn one_camera_slot_per_unprivileged_uid_and_no_cap_on_root() {
        let a = arb();
        a.submit(Class::Camera, 1000, "first").unwrap();
        assert_eq!(
            a.submit(Class::Camera, 1000, "second"),
            Err(Refusal::AlreadyHoldsSlot)
        );
        // A different account is unaffected by this one's slot.
        assert!(a.submit(Class::Camera, 1001, "other user").is_ok());
        // Root is the greeter and PAM; capping it would deny the login path.
        assert!(a.submit(Class::Camera, 0, "greeter").is_ok());
        assert!(a.submit(Class::Camera, 0, "greeter again").is_ok());
    }

    #[test]
    fn a_finished_job_releases_its_slot() {
        let a = arb();
        a.submit(Class::Camera, 1000, "first").unwrap();
        let job = a.take().unwrap();
        a.finish(job.class, job.uid);
        assert!(a.submit(Class::Camera, 1000, "again").is_ok());
    }

    #[test]
    fn plain_work_keeps_its_order_behind_earlier_plain_work() {
        let a = arb();
        a.submit(Class::Plain, 1000, "first").unwrap();
        a.submit(Class::Plain, 1001, "second").unwrap();
        assert_eq!(a.take().unwrap().payload, "first");
        assert_eq!(a.take().unwrap().payload, "second");
    }

    #[test]
    fn a_closed_and_drained_arbiter_tells_the_worker_to_exit() {
        let a = arb();
        a.submit(Class::Plain, 0, "last").unwrap();
        a.close();
        assert_eq!(a.take().unwrap().payload, "last");
        assert!(a.take().is_none());
    }

    #[test]
    fn the_worker_wakes_when_work_arrives() {
        use std::sync::Arc;
        let a = Arc::new(arb());
        let worker = {
            let a = Arc::clone(&a);
            std::thread::spawn(move || a.take().map(|j| j.payload))
        };
        // The worker is parked on the condvar; submitting must wake it rather
        // than leave it asleep with work queued.
        std::thread::sleep(std::time::Duration::from_millis(50));
        a.submit(Class::Auth, 0, "login").unwrap();
        assert_eq!(worker.join().unwrap(), Some("login"));
    }

    #[test]
    fn classification_follows_what_touches_the_camera() {
        use irlume_common::SecretBytes;
        assert_eq!(
            classify(&Request::Authenticate {
                user: "u".into(),
                service: None,
            }),
            Class::Auth
        );
        assert_eq!(
            classify(&Request::UnsealKeyring {
                user: "u".into(),
                service: None,
            }),
            Class::Auth
        );
        assert_eq!(
            classify(&Request::PositionSample { user: None }),
            Class::Camera
        );
        assert_eq!(
            classify(&Request::ListProfiles {
                user: "u".into(),
                structured_errors: true
            }),
            Class::Plain
        );
        assert_eq!(classify(&Request::Ping), Class::Plain);
        // A secret-carrying management request is not camera work.
        assert_eq!(
            classify(&Request::SealPassword {
                user: "u".into(),
                password: SecretBytes::new(vec![1u8]),
            }),
            Class::Plain
        );
    }
}

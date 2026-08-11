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
//! What this deliberately does not do is preempt by force. An operation already
//! running is ASKED to stop, through [`CancelToken`], and it answers at its own
//! next safe boundary: between whole captures, where nothing is half-written.
//! Nothing here unwinds a thread, closes a device out from under a capture, or
//! interrupts an ONNX session.
//!
//! [`Engine`]: irlume_auth::Engine

use irlume_common::Request;
use std::collections::VecDeque;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Condvar, Mutex};

/// What a request costs and how much it may delay a login.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Class {
    /// The login path: face authentication, and the credential release that
    /// follows it. Never refused, always served before other camera work.
    Auth,
    /// Opens the camera without being an authentication: the framing guide,
    /// 1:N identify, enrollment, emitter setup, self-tests.
    Camera,
    /// Touches no camera: settings writes, seals, deletions, renames. These
    /// stay on the worker so every mutation of shared state stays serialized
    /// against captures and against each other.
    Plain,
    /// Status that can be answered on the CONNECTION THREAD without touching
    /// the camera, the engine, the TPM, or any shared mutable state: pure
    /// path checks, the published engine bits, and the worker-published
    /// enrollment summary. This class exists because `ListProfiles` is a TPM
    /// unseal that measured 10.8 seconds on a slow TPM, and queued behind
    /// the worker it made a concurrently arriving authentication wait that
    /// long (#212). Membership is strict on purpose: the physical TPM
    /// executes one command at a time (tpmrm queues, it does not
    /// parallelize), so ANY TPM-touching request serves from the worker,
    /// and a status answer that would need the TPM (an unpublished summary)
    /// falls through to the worker queue instead.
    Status,
}

/// Classify a request by what it does to the camera, not by who sent it.
///
/// `Authenticate` is the login path. The unseal operations are the credential
/// release that a successful authentication leads to, and delaying them behind a
/// preview would leave a user logged in with a locked keyring, so they share the
/// priority rather than competing with it.
///
/// Exhaustive with NO wildcard arm on purpose (#351). This is the same shape
/// the posture table took for #344, and it is kept separate from that table so
/// neither has to answer both "who may do this" and "what does this cost the
/// camera". The wildcard this replaced classified seventeen variants as
/// `Plain` without anyone deciding that, and a variant added tomorrow would
/// have joined them silently: a camera-touching one would not have been refused
/// while an authentication was pending nor charged the per-uid camera slot, so
/// it could hold the worker while a lock screen waited. That is availability on
/// the login path, and no test could have seen it, because both tests over this
/// function are hand-picked sample lists, not enumerations.
pub fn classify(req: &Request) -> Class {
    use Request::*;
    match req {
        Authenticate { .. } | UnsealPassword { .. } | UnsealKeyring { .. } => Class::Auth,
        // Answerable from memory and path checks alone. ListProfiles is
        // here because its ANSWER comes from the worker-published summary
        // cache; a cache miss falls through to the worker queue, where the
        // real load (a TPM unseal that may also re-seal the template key)
        // stays serialized. KeyringInfo is NOT here: its PCR diagnosis is a
        // TPM command, and the TPM executes one command at a time, so it
        // serves from the worker with the other TPM users.
        Ping | Health | HasSealedPassword { .. } | RecoveryStatus { .. } | ListProfiles { .. } => {
            Class::Status
        }
        PositionSample { .. }
        | Identify
        | Enroll { .. }
        | AddScan { .. }
        | CaptureEarMedian { .. }
        | SetupIrEmitter { .. }
        | TuneCaptureMode { .. }
        | SelfTest { .. }
        // Enumeration OPENS every node, so it belongs to the camera class
        // even though it captures nothing (#187).
        | ListCameras => Class::Camera,

        // ---- Plain from here down. Everything below reaches the worker and
        // nothing below opens a camera node; that was checked arm by arm when
        // this table replaced the wildcard, not assumed from the name.

        // Storage and settings writes. No camera and no TPM, but they mutate
        // shared state, so they stay on the worker where mutations serialize
        // against captures and against each other.
        //
        // SetCameras is the surprising member: it is named for the camera and
        // still opens nothing. It assigns two device strings and reads sysfs
        // identity plus a path existence check, which is why it is a write and
        // not a capture.
        SetCameras { .. }
        | DeleteProfile { .. }
        | DeleteScan { .. }
        | ForgetRecognizer { .. }
        | RenameProfile { .. }
        | RenameScan { .. }
        | SetRequireEyesOpen { .. }
        // Stores the numbers CaptureEarMedian already captured; the capture
        // was the camera work, and it is classified Camera above.
        | SetClosureCalibration { .. } => Class::Plain,

        // TPM work. These are Plain rather than Status for the reason
        // `Class::Status` gives: the TPM executes one command at a time, so
        // anything that issues one serves from the worker with the other TPM
        // users instead of racing them from a connection thread.
        SealPassword { .. }
        | KeyringInfo { .. }
        | ForgetPassword { .. }
        | ReleaseTokenForDisarm { .. }
        | RecoverySetup { .. }
        | RecoveryRestore { .. }
        | RecoveryForget { .. } => Class::Plain,

        // ResealPassword is the one row here that had a decision hiding in it,
        // and the wildcard is why nobody had to write the decision down.
        //
        // It is fired from the login SESSION phase, after authentication has
        // already succeeded, so an argument exists for giving it Auth priority:
        // as Plain it queues behind camera work that is already in flight, and
        // a session open can wait on an enrollment.
        //
        // It stays Plain anyway. Auth is not merely a priority, it is a
        // cancellation: submitting one asks the running capture loop to stop
        // and marks an authentication in flight, which refuses other camera
        // work. Opportunistic self-healing must not cancel a user's enrollment,
        // and the re-seal is exactly that: if it loses the race it is retried
        // on the next password login rather than lost.
        ResealPassword { .. } => Class::Plain,
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

/// A cooperative stop signal for long camera loops.
///
/// Enrolment captures many scans and may retry each one. The boundary between
/// two whole captures is where stopping is safe, and it is the only place this
/// is read. The token says "an authentication is waiting"; what it never does is
/// interrupt a capture already inside V4L2 or an inference session, or fire
/// while a profile is half-written.
#[derive(Clone, Default)]
pub struct CancelToken(Arc<AtomicBool>);

impl CancelToken {
    pub fn new() -> Self {
        Self::default()
    }

    /// Ask the running long operation to stop at its next safe boundary.
    pub fn request_stop(&self) {
        self.0.store(true, Ordering::SeqCst);
    }

    /// True once a stop has been asked for.
    pub fn stop_requested(&self) -> bool {
        self.0.load(Ordering::SeqCst)
    }

    /// Clear the signal before the worker starts its next operation, so the one
    /// that yielded does not hand its cancellation to the one that follows.
    pub fn reset(&self) {
        self.0.store(false, Ordering::SeqCst);
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
    cancel: CancelToken,
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
            cancel: CancelToken::new(),
        }
    }

    /// The signal long operations poll. Shared, so an authentication arriving on
    /// any connection reaches an enrolment already in flight.
    pub fn cancel_token(&self) -> CancelToken {
        self.cancel.clone()
    }

    /// Offer a request to the queue.
    ///
    /// `Err(refusal)` means the caller should answer the client immediately; the
    /// job was not queued and holds nothing.
    pub fn submit(&self, class: Class, uid: u32, payload: T) -> Result<(), Refusal> {
        let mut inner = self.lock();
        match class {
            Class::Auth => {
                // An authentication never waits behind preview work, and the
                // request to yield goes out NOW rather than when the worker next
                // looks: an enrolment should learn it is wanted elsewhere while
                // it still has boundaries left to stop at.
                self.cancel.request_stop();
                inner.auth.push_back(Job {
                    class,
                    uid,
                    payload,
                });
            }
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
            // Status is answered on the connection thread and never submitted;
            // if a future caller submits one anyway it queues like Plain, which
            // is correct (just slower) rather than lost.
            Class::Plain | Class::Status => inner.other.push_back(Job {
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
                // The stop that was asked for has been honoured by this
                // authentication reaching the front; clear it so the next long
                // operation does not start already cancelled.
                self.cancel.reset();
                return Some(job);
            }
            if let Some(job) = inner.other.pop_front() {
                self.cancel.reset();
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
    fn a_submitted_authentication_asks_a_running_loop_to_stop() {
        let a = arb();
        let token = a.cancel_token();
        a.submit(Class::Camera, 1000, "enrolment").unwrap();
        let job = a.take().unwrap();
        assert!(!token.stop_requested(), "nothing is waiting yet");
        a.submit(Class::Auth, 0, "login").unwrap();
        assert!(
            token.stop_requested(),
            "the enrolment must learn an authentication is waiting"
        );
        a.finish(job.class, job.uid);
        let next = a.take().unwrap();
        assert_eq!(next.payload, "login");
        assert!(
            !token.stop_requested(),
            "the next operation must not inherit the cancellation"
        );
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
                have_password: false,
            }),
            Class::Auth
        );
        assert_eq!(
            classify(&Request::PositionSample { user: None }),
            Class::Camera
        );
        // Read-only status answers on the connection thread (#212): a TPM-
        // bound listing must not make a login wait, and Ping must answer
        // while the worker grinds.
        assert_eq!(
            classify(&Request::ListProfiles {
                user: "u".into(),
                structured_errors: true
            }),
            Class::Status
        );
        assert_eq!(classify(&Request::Ping), Class::Status);
        // A secret-carrying management request is not camera work.
        assert_eq!(
            classify(&Request::SealPassword {
                kind: None,
                user: "u".into(),
                password: SecretBytes::new(vec![1u8]),
            }),
            Class::Plain
        );
    }

    /// The two rows whose class is a judgement rather than an observation.
    ///
    /// Exhaustiveness is the compiler's job now (#351), so this does not
    /// re-list the enum. It pins the two answers that a reader could
    /// reasonably expect to be the other way, so that changing either is a
    /// deliberate act with a failing test attached rather than a quiet edit.
    #[test]
    fn the_two_judged_classifications_stay_where_they_were_argued() {
        // Named for the camera, opens nothing: two string assignments, a sysfs
        // identity read and a path existence check.
        assert_eq!(
            classify(&Request::SetCameras {
                rgb: "/dev/video0".into(),
                ir: "/dev/video2".into(),
            }),
            Class::Plain
        );
        // Fired from the login session phase, so Auth priority is arguable.
        // Auth also CANCELS the running capture loop, and opportunistic
        // self-healing must not cancel a user's enrollment: a lost race is
        // retried on the next password login.
        assert_eq!(
            classify(&Request::ResealPassword {
                user: "u".into(),
                password: irlume_common::SecretBytes::new(vec![1u8]),
            }),
            Class::Plain
        );
    }
}

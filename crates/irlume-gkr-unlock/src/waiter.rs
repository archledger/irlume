// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright the irlume contributors.

//! Wait until gnome-keyring is initialized, then hand it the token.
//!
//! A `--login` gnome-keyring-daemon, the one `pam_gnome_keyring auto_start`
//! starts where no socket unit exists (Fedora 43 and 44), answers every
//! `UNLOCK` and `CHANGE` with DENIED until something sends it INITIALIZE
//! (`daemon/gkd-main.c`, `daemon/control/gkd-control-server.c`). On GNOME 49
//! and later only the first Secret Service client does that, through D-Bus
//! activation, seconds after the PAM session phase has returned. So a token
//! sent once from the session phase always arrives too early.
//!
//! gnome-keyring claims `org.gnome.keyring` on the user bus inside
//! INITIALIZE, after it has tried the typed password and before it claims
//! `org.freedesktop.secrets` (`gkd-main.c`, `daemon/dbus/gkd-dbus.c`). The
//! waiter watches for that name, checks that its owner is this user's own
//! daemon, and then sends `CHANGE(token, token)`: it unlocks the login keyring
//! and proves it is keyed to the token, and a refusal records nothing. Only
//! after that succeeds does it send `UNLOCK(token)`, which clears the failed
//! typed password gnome-keyring recorded. A client's `Prompt()` handled after
//! that finds the collection unlocked and shows nothing
//! (`daemon/dbus/gkd-secret-unlock.c`).
//!
//! The bus is only a trigger. The token goes to the control socket and
//! nowhere else. Every call on the bus goes to the bus itself or to the name's
//! current owner and carries `NO_AUTO_START`, so the waiter never starts
//! gnome-keyring, which matters in a Plasma session where ksecretd serves
//! `org.freedesktop.secrets`.
//!
//! Everything that touches the outside world goes through [`World`], so the
//! decisions here are tested step by step against a scripted one.

use std::time::{Duration, Instant};

use irlume_common::gkr_wire::{ControlResult, Op};

/// The longest the waiter waits for gnome-keyring to initialize: gnome-keyring's
/// own `LOGIN_TIMEOUT` (`daemon/gkd-main.c`), after which an uninitialized
/// `--login` daemon exits.
pub(crate) const WAITER_BOUND: Duration = Duration::from_secs(120);

/// How long the user bus may take to accept a connection before the waiter
/// falls back to polling the control socket.
pub(crate) const BUS_GRACE: Duration = Duration::from_secs(5);

/// Pause between two attempts to connect to the user bus.
pub(crate) const BUS_RETRY: Duration = Duration::from_millis(100);

/// With no `org.gnome.keyring` owner and no control socket after this long,
/// the session has no gnome-keyring at all (a Plasma session, or Fedora 45's
/// oo7).
pub(crate) const CONTROL_GRACE: Duration = Duration::from_secs(15);

/// Pause between two `CHANGE(token, token)` attempts when there is no bus.
pub(crate) const POLL_INTERVAL: Duration = Duration::from_millis(250);

/// Longest single wait for a bus message, so a stop request is seen promptly.
pub(crate) const WAIT_SLICE: Duration = Duration::from_millis(250);

/// Pause before the owner of `org.gnome.keyring` is asked for again after an
/// attempt that failed in a way the same daemon can recover from (a timeout,
/// a `FAILED` answer, an owner that could not be identified). Such a daemon
/// keeps its name, so no owner change would ever bring it back.
pub(crate) const RETRY_AFTER: Duration = Duration::from_millis(500);

/// What the waiter observed about the owner of `org.gnome.keyring`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum Identity {
    /// The owner reports this user's control directory, and its pid is known.
    Serves { owner_pid: u32 },
    /// The owner reports another control directory, or none.
    Mismatch { owner_pid: u32 },
    /// The owner left the bus, or its pid could not be read.
    Gone,
}

/// Which control-socket listener may receive the token.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Expect {
    /// The process that owns `org.gnome.keyring`, or this user's systemd
    /// manager when the socket is socket-activated (the manager listens on
    /// the daemon's behalf).
    OwnerOrManager { owner_pid: u32 },
    /// Exactly the listener an earlier request on this path reached.
    Peer(u32),
    /// Any listener running as this user: the fallback without a bus, where
    /// no owner can be named. It is the check the helper made before the
    /// waiter existed.
    AnyPeer,
}

impl Expect {
    /// Whether a listener with this pid and uid may receive the token.
    /// `is_manager` says whether a pid is the user's systemd manager.
    pub(crate) fn accepts(
        self,
        peer_pid: u32,
        peer_uid: u32,
        uid: u32,
        is_manager: impl Fn(u32) -> bool,
    ) -> bool {
        if peer_uid != uid || peer_pid == 0 {
            return false;
        }
        match self {
            Expect::OwnerOrManager { owner_pid } => peer_pid == owner_pid || is_manager(peer_pid),
            Expect::Peer(pid) => peer_pid == pid,
            Expect::AnyPeer => true,
        }
    }
}

/// The result of one control-socket request.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Sent {
    /// The listener was the expected one and answered.
    Answered {
        result: ControlResult,
        peer_pid: u32,
    },
    /// The listener was not the expected one; nothing was written.
    PeerMismatch { peer_pid: u32 },
    /// No listener, a refused or reset connection, a malformed reply, or the
    /// I/O deadline passed.
    Unreachable,
}

/// The user bus went away while the waiter was using it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct BusLost;

/// A progress report to the helper's parent, which leaves as soon as it
/// has one.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Status {
    Waiting,
    Delivered,
    Failed,
}

/// Everything the waiter needs from outside itself.
pub(crate) trait World {
    fn now(&self) -> Instant;
    /// SIGTERM, SIGHUP or SIGALRM arrived.
    fn stop_requested(&self) -> bool;
    /// `login.keyring` is still there: `UNLOCK` would create it otherwise.
    fn keyring_exists(&self) -> bool;
    /// Something is at `<runtime>/keyring/control`.
    fn control_socket_exists(&self) -> bool;
    fn sleep(&mut self, pause: Duration);
    fn log(&mut self, event: Event);
    fn report(&mut self, status: Status);
    /// One attempt to connect to the user bus and subscribe to owner
    /// changes of `org.gnome.keyring`.
    fn connect_bus(&mut self) -> Result<(), BusLost>;
    /// The current owner of `org.gnome.keyring`, as a unique name.
    fn owner(&mut self) -> Result<Option<String>, BusLost>;
    /// Wait up to `timeout` for the owner to change: `Some(Some(owner))` for
    /// a new owner, `Some(None)` when the name was released, `None` when
    /// nothing changed.
    fn next_owner_change(&mut self, timeout: Duration) -> Result<Option<Option<String>>, BusLost>;
    fn identify(&mut self, owner: &str) -> Identity;
    /// Connect to the control socket, check its listener against `expect`,
    /// and only then send `op` with `args`.
    fn send(&mut self, op: Op, args: &[&[u8]], expect: Expect) -> Sent;
}

/// Fixed inputs of one wait.
#[derive(Debug, Clone, Copy)]
pub(crate) struct Plan {
    /// When the helper started: the session line's moment.
    pub(crate) started: Instant,
    /// When to give up, counted from `started`.
    pub(crate) bound: Duration,
    /// The target user.
    pub(crate) uid: u32,
}

impl Plan {
    fn deadline(&self) -> Instant {
        self.started + self.bound
    }

    fn control_deadline(&self) -> Instant {
        self.started + CONTROL_GRACE.min(self.bound)
    }

    fn bus_deadline(&self) -> Instant {
        self.started + BUS_GRACE.min(self.bound)
    }

    fn bound_secs(&self) -> u64 {
        self.bound.as_secs()
    }
}

/// How one wait ended.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Outcome {
    /// `CHANGE(token, token)` succeeded, and `UNLOCK(token)` followed it.
    Delivered { after_ms: u64, daemon_pid: u32 },
    /// This user's gnome-keyring, identity checked, refused
    /// `CHANGE(token, token)`: the login keyring is keyed to something else.
    Stale { daemon_pid: u32 },
    /// gnome-keyring did not initialize within the bound.
    GaveUp { bound_secs: u64 },
    /// No gnome-keyring in this session.
    NoGnomeKeyring,
    /// `login.keyring` disappeared while waiting.
    KeyringMissing,
    /// SIGTERM, SIGHUP or SIGALRM stopped the wait.
    Stopped,
}

impl Outcome {
    /// The exit status in `--foreground` mode.
    pub(crate) fn exit_code(self) -> u8 {
        match self {
            Outcome::Delivered { .. } => 0,
            Outcome::KeyringMissing => 1,
            Outcome::GaveUp { .. } | Outcome::Stopped => 3,
            Outcome::Stale { .. } => 4,
            Outcome::NoGnomeKeyring => 5,
        }
    }

    fn status(self) -> Status {
        match self {
            Outcome::Delivered { .. } => Status::Delivered,
            _ => Status::Failed,
        }
    }

    fn event(self) -> Event {
        match self {
            Outcome::Delivered {
                after_ms,
                daemon_pid,
            } => Event::Delivered {
                after_ms,
                daemon_pid,
            },
            Outcome::Stale { daemon_pid } => Event::Stale { daemon_pid },
            Outcome::GaveUp { bound_secs } => Event::GaveUp { bound_secs },
            Outcome::NoGnomeKeyring => Event::NoGnomeKeyring,
            Outcome::KeyringMissing => Event::KeyringMissing,
            Outcome::Stopped => Event::Stopped,
        }
    }
}

/// Syslog priority of an [`Event`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Level {
    Info,
    Notice,
    Warning,
}

/// The journal catalog. Every field is a number; the text around them is
/// fixed. Neither the token, nor its length, nor any password ever appears
/// here (a test reads this enum's source to keep it that way).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Event {
    Waiting {
        bound_secs: u64,
        uid: u32,
    },
    Delivered {
        after_ms: u64,
        daemon_pid: u32,
    },
    Stale {
        daemon_pid: u32,
    },
    GaveUp {
        bound_secs: u64,
    },
    NoGnomeKeyring,
    IdentityMismatch {
        owner_pid: u32,
        peer_pid: Option<u32>,
    },
    NoBus,
    KeyringMissing,
    Stopped,
}

impl Event {
    pub(crate) fn level(self) -> Level {
        match self {
            Event::Waiting { .. } | Event::Delivered { .. } => Level::Info,
            Event::GaveUp { .. } | Event::NoGnomeKeyring | Event::NoBus | Event::Stopped => {
                Level::Notice
            }
            Event::Stale { .. } | Event::IdentityMismatch { .. } | Event::KeyringMissing => {
                Level::Warning
            }
        }
    }

    pub(crate) fn text(self) -> String {
        match self {
            Event::Waiting { bound_secs, uid } => format!(
                "waiting up to {bound_secs} s for gnome-keyring to initialize (uid {uid})"
            ),
            Event::Delivered {
                after_ms,
                daemon_pid,
            } => format!(
                "token delivered {after_ms} ms after the session line (gnome-keyring pid {daemon_pid})"
            ),
            Event::Stale { daemon_pid } => format!(
                "the login keyring is not keyed to irlume's token (gnome-keyring pid {daemon_pid}); \
                 nothing was sent that gnome-keyring would remember. Run `irlume keyring arm` as \
                 the user to put them back in step, or `irlume keyring forget`"
            ),
            Event::GaveUp { bound_secs } => format!(
                "gnome-keyring was not initialized within {bound_secs} s (not a GNOME session?); \
                 nothing was sent"
            ),
            Event::NoGnomeKeyring => "no gnome-keyring in this session; nothing was sent. On \
                 Fedora 45 (oo7) a token arm does not carry over: run `irlume keyring forget`"
                .to_string(),
            Event::IdentityMismatch {
                owner_pid,
                peer_pid: Some(peer_pid),
            } => format!(
                "the org.gnome.keyring owner (pid {owner_pid}) does not match this user's control \
                 socket (listener pid {peer_pid}); not sent"
            ),
            Event::IdentityMismatch {
                owner_pid,
                peer_pid: None,
            } => format!(
                "the org.gnome.keyring owner (pid {owner_pid}) does not serve this user's control \
                 directory; not sent"
            ),
            Event::NoBus => "no user bus; polling the control socket instead".to_string(),
            Event::KeyringMissing => {
                "the login keyring was removed while waiting; nothing was sent".to_string()
            }
            Event::Stopped => "stopped by a signal before delivery; nothing was sent".to_string(),
        }
    }
}

/// What to do after a `CHANGE(token, token)` sent to an owner whose control
/// directory matched.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum AfterChange {
    /// The keyring is unlocked and keyed to the token: follow with `UNLOCK`
    /// to the same listener.
    Unlock { peer_pid: u32 },
    /// A verified gnome-keyring refused the token. Send nothing more:
    /// an `UNLOCK` now would be recorded, and gnome-keyring would re-key the
    /// keyring to that stale token at the next prompted unlock.
    Stale { peer_pid: u32 },
    /// The listener is not the owner's: treat the name as unowned.
    Mismatch { peer_pid: u32 },
    /// No verdict (no listener, FAILED, a timeout): ask for the current
    /// owner again after [`RETRY_AFTER`] and try it.
    Retry,
}

/// The decision after one `CHANGE(token, token)`.
pub(crate) fn after_change(sent: Sent) -> AfterChange {
    match sent {
        Sent::Answered {
            result: ControlResult::Ok,
            peer_pid,
        } => AfterChange::Unlock { peer_pid },
        Sent::Answered {
            result: ControlResult::Denied,
            peer_pid,
        } => AfterChange::Stale { peer_pid },
        Sent::Answered {
            result: ControlResult::Failed | ControlResult::NoDaemon | ControlResult::Unknown(_),
            ..
        } => AfterChange::Retry,
        Sent::PeerMismatch { peer_pid } => AfterChange::Mismatch { peer_pid },
        Sent::Unreachable => AfterChange::Retry,
    }
}

/// One attempt at an owner.
enum Attempt {
    Done(Outcome),
    Mismatch {
        owner_pid: u32,
        peer_pid: Option<u32>,
    },
    Retry,
}

/// Wait, deliver, log the outcome and report it to the parent.
pub(crate) fn run(world: &mut impl World, token: &[u8], plan: &Plan) -> Outcome {
    let outcome = wait_and_deliver(world, token, plan);
    world.log(outcome.event());
    world.report(outcome.status());
    outcome
}

fn wait_and_deliver(world: &mut impl World, token: &[u8], plan: &Plan) -> Outcome {
    loop {
        if world.stop_requested() {
            return Outcome::Stopped;
        }
        if world.connect_bus().is_ok() {
            return on_bus(world, token, plan);
        }
        let now = world.now();
        if now >= plan.bus_deadline() {
            return poll_control(world, token, plan);
        }
        world.sleep(BUS_RETRY.min(plan.bus_deadline() - now));
    }
}

/// Wait for `org.gnome.keyring` to gain an owner that is this user's
/// gnome-keyring, then deliver.
fn on_bus(world: &mut impl World, token: &[u8], plan: &Plan) -> Outcome {
    // Subscribed in `connect_bus` first, then look: an owner that appears in
    // between is seen either here or as a queued signal.
    let mut owner = match world.owner() {
        Ok(owner) => owner,
        Err(BusLost) => return poll_control(world, token, plan),
    };
    let mut mismatch_logged = false;
    let mut waiting = false;
    // When to ask for the current owner again after a retryable failure. An
    // identity mismatch is not retried: only an owner change can end it.
    let mut retry_at: Option<Instant> = None;
    loop {
        if world.stop_requested() {
            return Outcome::Stopped;
        }
        if let Some(name) = owner.take() {
            match try_owner(world, token, &name, plan) {
                Attempt::Done(outcome) => return outcome,
                Attempt::Mismatch {
                    owner_pid,
                    peer_pid,
                } => {
                    if !mismatch_logged {
                        world.log(Event::IdentityMismatch {
                            owner_pid,
                            peer_pid,
                        });
                        mismatch_logged = true;
                    }
                }
                Attempt::Retry => retry_at = Some(world.now() + RETRY_AFTER),
            }
        }
        if !waiting {
            world.log(Event::Waiting {
                bound_secs: plan.bound_secs(),
                uid: plan.uid,
            });
            world.report(Status::Waiting);
            waiting = true;
        }
        let now = world.now();
        if now >= plan.control_deadline() && !world.control_socket_exists() {
            return Outcome::NoGnomeKeyring;
        }
        if now >= plan.deadline() {
            return Outcome::GaveUp {
                bound_secs: plan.bound_secs(),
            };
        }
        if retry_at.is_some_and(|at| now >= at) {
            retry_at = None;
            owner = match world.owner() {
                Ok(current) => current,
                Err(BusLost) => return poll_control(world, token, plan),
            };
            continue;
        }
        let mut slice = WAIT_SLICE.min(plan.deadline() - now);
        if let Some(at) = retry_at {
            slice = slice.min(at - now);
        }
        match world.next_owner_change(slice) {
            Ok(Some(change)) => {
                owner = change;
                retry_at = None;
            }
            Ok(None) => {}
            Err(BusLost) => return poll_control(world, token, plan),
        }
    }
}

fn try_owner(world: &mut impl World, token: &[u8], owner: &str, plan: &Plan) -> Attempt {
    let owner_pid = match world.identify(owner) {
        Identity::Serves { owner_pid } => owner_pid,
        Identity::Mismatch { owner_pid } => {
            return Attempt::Mismatch {
                owner_pid,
                peer_pid: None,
            }
        }
        Identity::Gone => return Attempt::Retry,
    };
    if !world.keyring_exists() {
        return Attempt::Done(Outcome::KeyringMissing);
    }
    let sent = world.send(
        Op::Change,
        &[token, token],
        Expect::OwnerOrManager { owner_pid },
    );
    match after_change(sent) {
        AfterChange::Unlock { peer_pid } => {
            // The CHANGE already unlocked the keyring; this UNLOCK only clears
            // the typed password gnome-keyring recorded as a failed login
            // secret, so its answer changes nothing here.
            let _ = world.send(Op::Unlock, &[token], Expect::Peer(peer_pid));
            Attempt::Done(delivered(world, plan, owner_pid))
        }
        AfterChange::Stale { .. } => Attempt::Done(Outcome::Stale {
            daemon_pid: owner_pid,
        }),
        AfterChange::Mismatch { peer_pid } => Attempt::Mismatch {
            owner_pid,
            peer_pid: Some(peer_pid),
        },
        AfterChange::Retry => Attempt::Retry,
    }
}

/// Without a bus nothing names the daemon or says when it is initialized, so
/// ask it directly: `CHANGE(token, token)` records nothing when it is refused,
/// so repeating it is harmless, and one `UNLOCK` follows its success. This
/// unlocks eventually, but a prompt a client already put on screen stays up.
fn poll_control(world: &mut impl World, token: &[u8], plan: &Plan) -> Outcome {
    world.log(Event::NoBus);
    let mut waiting = false;
    loop {
        if world.stop_requested() {
            return Outcome::Stopped;
        }
        if !world.keyring_exists() {
            return Outcome::KeyringMissing;
        }
        if let Sent::Answered {
            result: ControlResult::Ok,
            peer_pid,
        } = world.send(Op::Change, &[token, token], Expect::AnyPeer)
        {
            let _ = world.send(Op::Unlock, &[token], Expect::Peer(peer_pid));
            return delivered(world, plan, peer_pid);
        }
        if !waiting {
            world.report(Status::Waiting);
            waiting = true;
        }
        let now = world.now();
        if now >= plan.control_deadline() && !world.control_socket_exists() {
            return Outcome::NoGnomeKeyring;
        }
        if now >= plan.deadline() {
            return Outcome::GaveUp {
                bound_secs: plan.bound_secs(),
            };
        }
        world.sleep(POLL_INTERVAL.min(plan.deadline() - now));
    }
}

fn delivered(world: &impl World, plan: &Plan, daemon_pid: u32) -> Outcome {
    let after = world.now().saturating_duration_since(plan.started);
    Outcome::Delivered {
        after_ms: u64::try_from(after.as_millis()).unwrap_or(u64::MAX),
        daemon_pid,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::VecDeque;

    const TOKEN: &[u8] = b"fake-waiter-token-0000";
    const UID: u32 = 1234;
    const DAEMON: u32 = 4242;
    const OWNER: &str = ":1.7";

    /// A scripted world on a virtual clock that only moves when the waiter
    /// sleeps or waits.
    struct Script {
        start: Instant,
        now: Instant,
        /// Offset at which `connect_bus` starts to succeed; `None` for never.
        bus_from: Option<Duration>,
        /// Offset at which the bus breaks.
        bus_lost_at: Option<Duration>,
        owner_at_start: Option<String>,
        /// Owner changes, each at an offset.
        changes: VecDeque<(Duration, Option<String>)>,
        identities: Vec<(String, Identity)>,
        /// Replies to `send`, in order; `Unreachable` once they run out.
        replies: VecDeque<Sent>,
        control_socket: bool,
        keyring: bool,
        stop_at: Option<Duration>,
        sent: Vec<(Op, usize, Expect)>,
        logs: Vec<Event>,
        reports: Vec<Status>,
    }

    impl Script {
        fn new() -> Self {
            let start = Instant::now();
            Script {
                start,
                now: start,
                bus_from: Some(Duration::ZERO),
                bus_lost_at: None,
                owner_at_start: None,
                changes: VecDeque::new(),
                identities: Vec::new(),
                replies: VecDeque::new(),
                control_socket: true,
                keyring: true,
                stop_at: None,
                sent: Vec::new(),
                logs: Vec::new(),
                reports: Vec::new(),
            }
        }

        fn plan(&self) -> Plan {
            Plan {
                started: self.start,
                bound: WAITER_BOUND,
                uid: UID,
            }
        }

        fn elapsed(&self) -> Duration {
            self.now - self.start
        }

        fn serves(mut self, owner: &str, pid: u32) -> Self {
            self.identities
                .push((owner.into(), Identity::Serves { owner_pid: pid }));
            self
        }

        fn reply(mut self, sent: Sent) -> Self {
            self.replies.push_back(sent);
            self
        }

        fn change_at(mut self, secs: f64, owner: Option<&str>) -> Self {
            self.changes
                .push_back((Duration::from_secs_f64(secs), owner.map(str::to_string)));
            self
        }

        fn run(&mut self) -> Outcome {
            let plan = self.plan();
            run(self, TOKEN, &plan)
        }

        fn ops(&self) -> Vec<(Op, Expect)> {
            self.sent.iter().map(|(op, _, e)| (*op, *e)).collect()
        }
    }

    fn answered(result: ControlResult) -> Sent {
        Sent::Answered {
            result,
            peer_pid: DAEMON,
        }
    }

    impl World for Script {
        fn now(&self) -> Instant {
            self.now
        }
        fn stop_requested(&self) -> bool {
            self.stop_at.is_some_and(|at| self.elapsed() >= at)
        }
        fn keyring_exists(&self) -> bool {
            self.keyring
        }
        fn control_socket_exists(&self) -> bool {
            self.control_socket
        }
        fn sleep(&mut self, pause: Duration) {
            assert!(!pause.is_zero(), "a zero sleep would spin");
            self.now += pause;
        }
        fn log(&mut self, event: Event) {
            self.logs.push(event);
        }
        fn report(&mut self, status: Status) {
            self.reports.push(status);
        }
        fn connect_bus(&mut self) -> Result<(), BusLost> {
            match self.bus_from {
                Some(at) if self.elapsed() >= at => Ok(()),
                _ => Err(BusLost),
            }
        }
        fn owner(&mut self) -> Result<Option<String>, BusLost> {
            Ok(self.owner_at_start.clone())
        }
        fn next_owner_change(
            &mut self,
            timeout: Duration,
        ) -> Result<Option<Option<String>>, BusLost> {
            assert!(!timeout.is_zero(), "a zero wait would spin");
            let until = self.elapsed() + timeout;
            if let Some(lost) = self.bus_lost_at {
                if lost <= until {
                    self.now = self.start + lost.max(self.elapsed());
                    return Err(BusLost);
                }
            }
            match self.changes.front() {
                Some((at, _)) if *at <= until => {
                    let (at, owner) = self.changes.pop_front().unwrap();
                    self.now = self.start + at.max(self.elapsed());
                    // `owner()` answers with the current owner from now on.
                    self.owner_at_start.clone_from(&owner);
                    Ok(Some(owner))
                }
                _ => {
                    self.now = self.start + until;
                    Ok(None)
                }
            }
        }
        fn identify(&mut self, owner: &str) -> Identity {
            self.identities
                .iter()
                .find(|(name, _)| name == owner)
                .map(|(_, id)| id.clone())
                .unwrap_or(Identity::Gone)
        }
        fn send(&mut self, op: Op, args: &[&[u8]], expect: Expect) -> Sent {
            assert!(args.iter().all(|a| *a == TOKEN), "only the token is sent");
            self.sent.push((op, args.len(), expect));
            self.now += Duration::from_millis(5);
            self.replies.pop_front().unwrap_or(Sent::Unreachable)
        }
    }

    #[test]
    fn after_change_decides_each_reply() {
        use ControlResult as R;
        let cases = [
            (answered(R::Ok), AfterChange::Unlock { peer_pid: DAEMON }),
            (answered(R::Denied), AfterChange::Stale { peer_pid: DAEMON }),
            (answered(R::Failed), AfterChange::Retry),
            (answered(R::NoDaemon), AfterChange::Retry),
            (answered(R::Unknown(9)), AfterChange::Retry),
            (
                Sent::PeerMismatch { peer_pid: 77 },
                AfterChange::Mismatch { peer_pid: 77 },
            ),
            (Sent::Unreachable, AfterChange::Retry),
        ];
        for (sent, want) in cases {
            assert_eq!(after_change(sent), want, "{sent:?}");
        }
    }

    #[test]
    fn expect_admits_only_the_named_listener_of_this_user() {
        let manager = |pid| pid == 99;
        let owner = Expect::OwnerOrManager { owner_pid: DAEMON };
        assert!(owner.accepts(DAEMON, UID, UID, manager));
        assert!(
            owner.accepts(99, UID, UID, manager),
            "socket activation: the manager listens"
        );
        assert!(!owner.accepts(55, UID, UID, manager), "a third process");
        assert!(!owner.accepts(DAEMON, 0, UID, manager), "another uid");
        assert!(!owner.accepts(0, UID, UID, |_| true), "no pid at all");
        assert!(Expect::Peer(55).accepts(55, UID, UID, |_| false));
        assert!(!Expect::Peer(55).accepts(56, UID, UID, |_| true));
        assert!(Expect::AnyPeer.accepts(56, UID, UID, |_| false));
        assert!(!Expect::AnyPeer.accepts(56, UID + 1, UID, |_| true));
    }

    #[test]
    fn an_unowned_name_is_waited_for_until_the_bound() {
        let mut w = Script::new();
        let outcome = w.run();
        assert_eq!(
            outcome,
            Outcome::GaveUp {
                bound_secs: WAITER_BOUND.as_secs()
            }
        );
        assert!(w.sent.is_empty(), "nothing is sent without an owner");
        assert_eq!(w.elapsed(), WAITER_BOUND);
        assert_eq!(w.reports, [Status::Waiting, Status::Failed]);
        assert_eq!(
            w.logs,
            [
                Event::Waiting {
                    bound_secs: 120,
                    uid: UID
                },
                Event::GaveUp { bound_secs: 120 }
            ]
        );
        assert_eq!(outcome.exit_code(), 3);
    }

    #[test]
    fn a_verified_owner_gets_change_then_unlock() {
        let mut w = Script::new()
            .change_at(2.0, Some(OWNER))
            .serves(OWNER, DAEMON)
            .reply(answered(ControlResult::Ok))
            .reply(answered(ControlResult::Ok));
        let outcome = w.run();
        assert!(
            matches!(outcome, Outcome::Delivered { after_ms, daemon_pid: DAEMON } if (2000..2100).contains(&after_ms)),
            "{outcome:?}"
        );
        assert_eq!(
            w.ops(),
            [
                (Op::Change, Expect::OwnerOrManager { owner_pid: DAEMON }),
                (Op::Unlock, Expect::Peer(DAEMON)),
            ]
        );
        assert_eq!(w.sent[0].1, 2, "CHANGE carries the token twice");
        assert_eq!(w.sent[1].1, 1, "UNLOCK carries it once");
        assert_eq!(w.reports, [Status::Waiting, Status::Delivered]);
        assert_eq!(outcome.exit_code(), 0);
    }

    #[test]
    fn an_owner_present_at_start_is_delivered_to_before_any_waiting() {
        let mut w = Script::new()
            .serves(OWNER, DAEMON)
            .reply(answered(ControlResult::Ok))
            .reply(answered(ControlResult::Ok));
        w.owner_at_start = Some(OWNER.into());
        assert!(matches!(w.run(), Outcome::Delivered { .. }));
        assert_eq!(w.reports, [Status::Delivered], "no waiting report first");
        assert!(!w.logs.iter().any(|e| matches!(e, Event::Waiting { .. })));
    }

    #[test]
    fn a_denied_change_from_a_verified_owner_is_stale_and_ends_the_sending() {
        let mut w = Script::new()
            .change_at(1.0, Some(OWNER))
            .serves(OWNER, DAEMON)
            .reply(answered(ControlResult::Denied));
        let outcome = w.run();
        assert_eq!(outcome, Outcome::Stale { daemon_pid: DAEMON });
        assert_eq!(
            w.ops(),
            [(Op::Change, Expect::OwnerOrManager { owner_pid: DAEMON })],
            "no UNLOCK after a stale CHANGE"
        );
        assert_eq!(w.logs.last(), Some(&Event::Stale { daemon_pid: DAEMON }));
        assert_eq!(outcome.exit_code(), 4);
        assert_eq!(w.reports.last(), Some(&Status::Failed));
    }

    #[test]
    fn an_identity_mismatch_is_logged_once_and_nothing_is_sent() {
        let mut w = Script::new()
            .change_at(1.0, Some(":1.9"))
            .change_at(2.0, None)
            .change_at(3.0, Some(":1.10"))
            .change_at(4.0, Some(OWNER))
            .serves(OWNER, DAEMON)
            .reply(Sent::PeerMismatch { peer_pid: 31 })
            .reply(answered(ControlResult::Ok))
            .reply(answered(ControlResult::Ok));
        w.identities
            .push((":1.9".into(), Identity::Mismatch { owner_pid: 30 }));
        w.identities.push((
            ":1.10".into(),
            Identity::Serves {
                owner_pid: DAEMON + 1,
            },
        ));
        let outcome = w.run();
        assert!(matches!(outcome, Outcome::Delivered { .. }), "{outcome:?}");
        let mismatches: Vec<_> = w
            .logs
            .iter()
            .filter(|e| matches!(e, Event::IdentityMismatch { .. }))
            .collect();
        assert_eq!(
            mismatches,
            [&Event::IdentityMismatch {
                owner_pid: 30,
                peer_pid: None
            }],
            "logged once, for the first mismatch"
        );
        // The directory mismatch sends nothing. The listener mismatch is
        // refused inside `send`, before anything is written.
        assert_eq!(
            w.ops(),
            [
                (
                    Op::Change,
                    Expect::OwnerOrManager {
                        owner_pid: DAEMON + 1
                    }
                ),
                (Op::Change, Expect::OwnerOrManager { owner_pid: DAEMON }),
                (Op::Unlock, Expect::Peer(DAEMON)),
            ]
        );
    }

    /// A daemon that times out or answers FAILED keeps its name, so no owner
    /// change would bring it back: the same owner is asked for and tried
    /// again after a pause.
    #[test]
    fn an_unreachable_or_failed_daemon_is_tried_again_while_it_keeps_the_name() {
        for first in [
            Sent::Unreachable,
            answered(ControlResult::Failed),
            answered(ControlResult::NoDaemon),
        ] {
            let mut w = Script::new()
                .change_at(1.0, Some(OWNER))
                .serves(OWNER, DAEMON)
                .reply(first)
                .reply(answered(ControlResult::Ok))
                .reply(answered(ControlResult::Ok));
            let outcome = w.run();
            let pause = u64::try_from(RETRY_AFTER.as_millis()).unwrap();
            assert!(
                matches!(outcome, Outcome::Delivered { after_ms, .. }
                    if (1000 + pause..2000).contains(&after_ms)),
                "{first:?}: tried again after the pause, with no owner change: {outcome:?}"
            );
            assert_eq!(
                w.ops(),
                [
                    (Op::Change, Expect::OwnerOrManager { owner_pid: DAEMON }),
                    (Op::Change, Expect::OwnerOrManager { owner_pid: DAEMON }),
                    (Op::Unlock, Expect::Peer(DAEMON)),
                ],
                "{first:?}"
            );
        }
    }

    /// A retry asks the bus for the owner now: one that released the name
    /// meanwhile is not tried again, and a new owner is tried at once.
    #[test]
    fn a_retry_follows_the_current_owner() {
        let mut w = Script::new()
            .change_at(1.0, Some(OWNER))
            .change_at(1.2, None)
            .change_at(3.0, Some(":1.20"))
            .serves(OWNER, DAEMON)
            .reply(answered(ControlResult::Failed))
            .reply(Sent::Answered {
                result: ControlResult::Ok,
                peer_pid: DAEMON + 2,
            })
            .reply(answered(ControlResult::Ok));
        w.identities.push((
            ":1.20".into(),
            Identity::Serves {
                owner_pid: DAEMON + 2,
            },
        ));
        let outcome = w.run();
        assert!(
            matches!(outcome, Outcome::Delivered { daemon_pid, after_ms } if daemon_pid == DAEMON + 2 && after_ms >= 3000),
            "{outcome:?}"
        );
        assert_eq!(
            w.ops(),
            [
                (Op::Change, Expect::OwnerOrManager { owner_pid: DAEMON }),
                (
                    Op::Change,
                    Expect::OwnerOrManager {
                        owner_pid: DAEMON + 2
                    }
                ),
                (Op::Unlock, Expect::Peer(DAEMON + 2)),
            ]
        );
    }

    #[test]
    fn an_owner_that_is_gone_before_the_check_is_skipped() {
        let mut w = Script::new().change_at(1.0, Some(":1.99"));
        w.bus_lost_at = None;
        let outcome = w.run();
        assert!(matches!(outcome, Outcome::GaveUp { .. }));
        assert!(w.sent.is_empty());
        assert!(!w
            .logs
            .iter()
            .any(|e| matches!(e, Event::IdentityMismatch { .. })));
    }

    #[test]
    fn no_bus_after_the_grace_falls_back_to_the_control_socket() {
        let mut w = Script::new()
            .reply(answered(ControlResult::Denied))
            .reply(Sent::Unreachable)
            .reply(answered(ControlResult::Ok))
            .reply(answered(ControlResult::Ok));
        w.bus_from = None;
        let outcome = w.run();
        assert!(
            matches!(outcome, Outcome::Delivered { daemon_pid: DAEMON, after_ms } if after_ms >= 5000),
            "{outcome:?}"
        );
        assert_eq!(w.logs.first(), Some(&Event::NoBus));
        assert_eq!(
            w.ops(),
            [
                (Op::Change, Expect::AnyPeer),
                (Op::Change, Expect::AnyPeer),
                (Op::Change, Expect::AnyPeer),
                (Op::Unlock, Expect::Peer(DAEMON)),
            ]
        );
        assert_eq!(w.reports, [Status::Waiting, Status::Delivered]);
    }

    #[test]
    fn the_control_socket_loop_never_follows_a_refusal_with_unlock() {
        let mut w = Script::new();
        w.bus_from = None;
        for _ in 0..1000 {
            w.replies.push_back(answered(ControlResult::Denied));
        }
        let outcome = w.run();
        assert!(matches!(outcome, Outcome::GaveUp { .. }), "{outcome:?}");
        assert!(w.ops().iter().all(|(op, _)| *op == Op::Change));
    }

    #[test]
    fn a_bus_that_appears_within_the_grace_is_used() {
        let mut w = Script::new()
            .change_at(4.0, Some(OWNER))
            .serves(OWNER, DAEMON)
            .reply(answered(ControlResult::Ok))
            .reply(answered(ControlResult::Ok));
        w.bus_from = Some(Duration::from_millis(1500));
        assert!(matches!(w.run(), Outcome::Delivered { .. }));
        assert!(!w.logs.contains(&Event::NoBus));
    }

    #[test]
    fn a_lost_bus_falls_back_to_the_control_socket() {
        let mut w = Script::new()
            .reply(answered(ControlResult::Ok))
            .reply(answered(ControlResult::Ok));
        w.bus_lost_at = Some(Duration::from_secs(2));
        assert!(matches!(w.run(), Outcome::Delivered { .. }));
        assert!(w.logs.contains(&Event::NoBus));
        assert_eq!(w.ops()[0], (Op::Change, Expect::AnyPeer));
    }

    #[test]
    fn no_owner_and_no_control_socket_is_no_gnome_keyring() {
        for bus in [Some(Duration::ZERO), None] {
            let mut w = Script::new();
            w.bus_from = bus;
            w.control_socket = false;
            let outcome = w.run();
            assert_eq!(outcome, Outcome::NoGnomeKeyring, "bus {bus:?}");
            let late = w.elapsed() - CONTROL_GRACE;
            assert!(late < POLL_INTERVAL, "bus {bus:?}: {late:?} past the grace");
            assert_eq!(outcome.exit_code(), 5);
            assert_eq!(w.logs.last(), Some(&Event::NoGnomeKeyring));
        }
    }

    #[test]
    fn a_control_socket_without_an_owner_keeps_waiting_past_the_grace() {
        let mut w = Script::new()
            .change_at(60.0, Some(OWNER))
            .serves(OWNER, DAEMON);
        w.replies.push_back(answered(ControlResult::Ok));
        w.replies.push_back(answered(ControlResult::Ok));
        assert!(matches!(w.run(), Outcome::Delivered { after_ms, .. } if after_ms >= 60_000));
    }

    #[test]
    fn a_stop_request_ends_the_wait_without_sending() {
        let mut w = Script::new();
        w.stop_at = Some(Duration::from_secs(3));
        let outcome = w.run();
        assert_eq!(outcome, Outcome::Stopped);
        assert!(w.sent.is_empty());
        assert!(w.elapsed() < Duration::from_secs(4));
        assert_eq!(outcome.exit_code(), 3);
        assert_eq!(w.logs.last(), Some(&Event::Stopped));

        let mut w = Script::new();
        w.bus_from = None;
        w.stop_at = Some(Duration::from_secs(1));
        assert_eq!(w.run(), Outcome::Stopped);
    }

    #[test]
    fn a_removed_login_keyring_is_never_sent_to() {
        let mut w = Script::new()
            .change_at(1.0, Some(OWNER))
            .serves(OWNER, DAEMON);
        w.keyring = false;
        let outcome = w.run();
        assert_eq!(outcome, Outcome::KeyringMissing);
        assert!(w.sent.is_empty(), "UNLOCK or CHANGE would create one");
        assert_eq!(outcome.exit_code(), 1);

        let mut w = Script::new();
        w.bus_from = None;
        w.keyring = false;
        assert_eq!(w.run(), Outcome::KeyringMissing);
        assert!(w.sent.is_empty());
    }

    #[test]
    fn a_shorter_bound_shortens_every_grace() {
        let mut w = Script::new();
        w.bus_from = None;
        w.control_socket = false;
        let plan = Plan {
            started: w.start,
            bound: Duration::from_secs(3),
            uid: UID,
        };
        assert_eq!(run(&mut w, TOKEN, &plan), Outcome::NoGnomeKeyring);
        assert!(w.elapsed() - Duration::from_secs(3) < POLL_INTERVAL);

        let mut w = Script::new();
        let plan = Plan {
            started: w.start,
            bound: Duration::from_secs(3),
            uid: UID,
        };
        assert_eq!(run(&mut w, TOKEN, &plan), Outcome::GaveUp { bound_secs: 3 });
        assert_eq!(w.elapsed(), Duration::from_secs(3));
    }

    /// The catalog carries numbers only. Reading this file's own source is
    /// the check: a field of another type in [`Event`] fails it.
    #[test]
    fn the_log_catalog_carries_numbers_only() {
        let src = include_str!("waiter.rs");
        let start = src.find("pub(crate) enum Event {").expect("the Event enum");
        let body = &src[start..start + src[start..].find("\n}").expect("its end")];
        let mut fields = 0;
        for field in body.split(['{', ',', '}']).filter(|f| f.contains(':')) {
            let ty = field.split(':').nth(1).unwrap().trim();
            assert!(
                matches!(ty, "u32" | "u64" | "Option<u32>"),
                "Event field `{}` is not a number",
                field.trim()
            );
            fields += 1;
        }
        assert!(fields >= 8, "the scan found the fields: {fields}");
        for event in [
            Event::Waiting {
                bound_secs: 1,
                uid: 2,
            },
            Event::Delivered {
                after_ms: 1,
                daemon_pid: 2,
            },
            Event::Stale { daemon_pid: 1 },
            Event::GaveUp { bound_secs: 1 },
            Event::NoGnomeKeyring,
            Event::IdentityMismatch {
                owner_pid: 1,
                peer_pid: Some(2),
            },
            Event::IdentityMismatch {
                owner_pid: 1,
                peer_pid: None,
            },
            Event::NoBus,
            Event::KeyringMissing,
            Event::Stopped,
        ] {
            let text = event.text();
            assert!(
                text.is_ascii() && !text.contains('\n') && !text.contains('%'),
                "{text}"
            );
        }
    }
}

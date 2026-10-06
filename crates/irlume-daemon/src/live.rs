// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright the irlume contributors.

//! Bounded copied worker observations. Guards never own cameras or requests.

use crate::{
    arbiter::CancelToken,
    diagnostics::{Clock, Owner},
};
use irlume_common::{
    diagnostics::OperationId, live::*, live_camera::CameraInventorySnapshot, Request,
};
use std::collections::BTreeMap;
use std::sync::{
    atomic::{AtomicU8, Ordering},
    Arc, Mutex, OnceLock,
};

#[derive(Clone)]
pub(crate) struct LiveState(Arc<Shared>);
struct Shared {
    clock: Arc<dyn Clock>,
    instance: OperationId,
    inner: Mutex<Inner>,
    cancel: OnceLock<CancelToken>,
}
struct Inner {
    stage: LiveStage,
    /// Every completed state change: root's revision.
    revision: u64,
    /// Completed changes every reader can observe: camera setup and
    /// qualification, which change what every account reads, and other
    /// daemon-wide work ([`change_readers`]).
    shared_revision: u64,
    /// Completed changes to each account's own state, for at most
    /// [`MAX_REVISION_ACCOUNTS`] accounts. A reader other than root reads
    /// `shared_revision` plus its own account's count, so its revision does
    /// not move for another account's work ([`Inner::revision_for`]).
    account_revisions: BTreeMap<u32, AccountRevision>,
    /// Waiting counts by kind and by whose operation it is, so a reader's
    /// view can relabel another account's without miscounting.
    waiting: BTreeMap<(LiveOperationKind, Owner), u64>,
    worker: Option<Worker>,
    background: Vec<Worker>,
    available: bool,
}
struct Worker {
    id: OperationId,
    kind: LiveOperationKind,
    owner: Owner,
    started_ms: u64,
    cancelled: bool,
}
/// Accounts whose state changes keep a count of their own. Each count is
/// two words; past the bound, the account whose latest change is oldest
/// gives up its count to the shared one (see [`Inner::note_change`]).
const MAX_REVISION_ACCOUNTS: usize = 1024;
#[derive(Clone, Copy)]
struct AccountRevision {
    changes: u64,
    /// `Inner::revision` after this account's latest change.
    latest: u64,
}
/// Whose revision a completed change moves besides root's.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum ChangeReaders {
    Every,
    Account(u32),
    RootOnly,
}
/// Camera setup and qualification change what every account reads (the
/// cameras, the capture schedule), whoever asked for them, so they move
/// every reader's revision; so does daemon-wide work, and root's work for
/// a name that did not resolve, which is no account's history and may
/// still have changed an account's records. Other changes are the
/// account's own: its enrollment, profiles, keyring and recovery. Root's
/// own account's are root's alone, since root reads every change.
fn change_readers(kind: LiveOperationKind, owner: Owner) -> ChangeReaders {
    match (kind, owner) {
        (LiveOperationKind::CameraSetup | LiveOperationKind::CaptureQualification, _)
        | (_, Owner::Daemon | Owner::Unresolved) => ChangeReaders::Every,
        (_, Owner::Account(0)) => ChangeReaders::RootOnly,
        (_, Owner::Account(uid)) => ChangeReaders::Account(uid),
    }
}
impl Inner {
    /// Count one completed state change of `kind` for `owner`.
    fn note_change(&mut self, kind: LiveOperationKind, owner: Owner) {
        let Some(revision) = self.revision.checked_add(1) else {
            self.available = false;
            return;
        };
        self.revision = revision;
        // Every count below adds up to at most `revision`, so none overflows.
        match change_readers(kind, owner) {
            ChangeReaders::Every => self.shared_revision += 1,
            ChangeReaders::Account(uid) => {
                if !self.account_revisions.contains_key(&uid)
                    && self.account_revisions.len() == MAX_REVISION_ACCOUNTS
                {
                    // Moving the evicted count into the shared one keeps that
                    // account's revision where it was and every other
                    // reader's from going back: each only grows.
                    if let Some((&evicted, _)) = self
                        .account_revisions
                        .iter()
                        .min_by_key(|(_, account)| account.latest)
                    {
                        if let Some(account) = self.account_revisions.remove(&evicted) {
                            self.shared_revision += account.changes;
                        }
                    }
                }
                let account = self
                    .account_revisions
                    .entry(uid)
                    .or_insert(AccountRevision {
                        changes: 0,
                        latest: 0,
                    });
                account.changes += 1;
                account.latest = revision;
            }
            ChangeReaders::RootOnly => {}
        }
    }
    /// The revision the peer with uid `peer_uid` reads: root's counts every
    /// change; another reader's counts the changes it can observe.
    fn revision_for(&self, peer_uid: u32) -> u64 {
        if peer_uid == 0 {
            return self.revision;
        }
        let own = self
            .account_revisions
            .get(&peer_uid)
            .map_or(0, |account| account.changes);
        self.shared_revision + own
    }
    /// Whether the view of the peer with uid `peer_uid` shows work it may
    /// not see, as `Unknown`, running or waiting.
    fn shows_unknown_work(&self, peer_uid: u32) -> bool {
        let hidden = |owner: Owner| !owner.visible_to(peer_uid);
        self.worker
            .as_ref()
            .is_some_and(|worker| hidden(worker.owner))
            || self.background.iter().any(|task| hidden(task.owner))
            || self.waiting.keys().any(|&(_, owner)| hidden(owner))
    }
}
const CREATED: u8 = 0;
const WAITING: u8 = 1;
const RUNNING: u8 = 2;
const FINISHED: u8 = 3;
const UNTRACKED: u8 = 4;
#[derive(Clone, Copy, PartialEq, Eq)]
enum Lane {
    Worker,
    Background,
}

pub(crate) struct WorkerLifetime(LiveState);
impl Drop for WorkerLifetime {
    fn drop(&mut self) {
        self.0.set_stage(LiveStage::Stopping);
    }
}

#[derive(Clone)]
pub(crate) struct LiveGuard(Arc<Registration>);
struct Registration {
    state: LiveState,
    id: OperationId,
    kind: LiveOperationKind,
    /// Whose operation it is (`OperationScope::owner`).
    owner: Owner,
    changes_state: bool,
    lane: Lane,
    // Only accessed under state.inner; Atomic supplies interior mutability for
    // shared guards without introducing an opposite lock order.
    phase: AtomicU8,
}

impl LiveState {
    pub(crate) fn new(instance: OperationId, clock: Arc<dyn Clock>) -> Self {
        Self(Arc::new(Shared {
            clock,
            instance,
            cancel: OnceLock::new(),
            inner: Mutex::new(Inner {
                stage: LiveStage::Starting,
                revision: 0,
                shared_revision: 0,
                account_revisions: BTreeMap::new(),
                waiting: BTreeMap::new(),
                worker: None,
                background: Vec::new(),
                available: true,
            }),
        }))
    }
    pub(crate) fn worker_lifetime(&self) -> WorkerLifetime {
        WorkerLifetime(self.clone())
    }
    pub(crate) fn set_cancel_token(&self, token: CancelToken) {
        let _ = self.0.cancel.set(token);
    }
    fn lock(&self) -> std::sync::MutexGuard<'_, Inner> {
        self.0.inner.lock().unwrap_or_else(|error| {
            let mut inner = error.into_inner();
            inner.available = false;
            inner
        })
    }
    pub(crate) fn set_stage(&self, stage: LiveStage) {
        let mut inner = self.lock();
        // Shutdown wins over a concurrent startup/rebuild publication.
        if inner.stage != LiveStage::Stopping {
            inner.stage = stage;
        }
    }
    /// `owner` is whose operation it is, as its diagnostic scope records it;
    /// see [`LiveState::snapshot_for`].
    pub(crate) fn register(
        &self,
        id: OperationId,
        kind: LiveOperationKind,
        changes_state: bool,
        owner: Owner,
    ) -> LiveGuard {
        self.register_in_lane(id, kind, changes_state, owner, Lane::Worker)
    }
    fn register_in_lane(
        &self,
        id: OperationId,
        kind: LiveOperationKind,
        changes_state: bool,
        owner: Owner,
        lane: Lane,
    ) -> LiveGuard {
        LiveGuard(Arc::new(Registration {
            state: self.clone(),
            id,
            kind,
            owner,
            changes_state,
            lane,
            phase: AtomicU8::new(CREATED),
        }))
    }
    pub(crate) fn register_background(&self, id: OperationId) -> LiveGuard {
        self.register_in_lane(
            id,
            LiveOperationKind::CaptureQualification,
            true,
            Owner::Daemon,
            Lane::Background,
        )
    }
    /// Root's view: every operation under the kind it registered with.
    #[cfg(test)]
    pub(crate) fn snapshot(&self, cameras: CameraInventorySnapshot) -> LiveStatusSnapshot {
        self.snapshot_for(cameras, 0)
    }
    /// The view of the peer with uid `peer_uid`. For a reader other than
    /// root, every operation of another account, or of one that did not
    /// resolve, reads as [`LiveOperationKind::Unknown`] whatever its kind:
    /// it keeps its place and elapsed time, so the worker still reads busy
    /// and a client does not queue camera work behind it, but the kind does
    /// not say what another account is doing, and an authentication reads
    /// the same as that account's enrollment, profile or wallet work
    /// (ADR-0030 §5). Its stop request follows the kind the reader reads
    /// ([`stop_requested`]). Daemon-wide work keeps its kind
    /// ([`Owner::visible_to`]). Its `state_revision` moves only for changes
    /// the reader can observe ([`change_readers`]).
    pub(crate) fn snapshot_for(
        &self,
        cameras: CameraInventorySnapshot,
        peer_uid: u32,
    ) -> LiveStatusSnapshot {
        let inner = self.lock();
        // Capture once: elapsed must never exceed the same snapshot's uptime.
        let now_ms = self.0.clock.now_ms();
        let worker = inner.worker.as_ref().map(|worker| {
            let kind = visible_kind(worker.kind, worker.owner, peer_uid);
            // Read the shared stop bit under the tracker lock. The previous
            // worker is removed before the next arbiter.take resets that bit.
            let requested = self
                .0
                .cancel
                .get()
                .is_some_and(|token| stop_requested(token, kind, worker.owner, peer_uid));
            LiveWorkerOperation {
                operation_id: worker.id,
                kind,
                elapsed_ms: now_ms.saturating_sub(worker.started_ms),
                cancellation_requested: worker.cancelled || requested,
            }
        });
        let mut waiting = BTreeMap::<LiveOperationKind, u64>::new();
        for (&(kind, owner), &count) in &inner.waiting {
            let row = waiting
                .entry(visible_kind(kind, owner, peer_uid))
                .or_default();
            *row = row.saturating_add(count);
        }
        LiveStatusSnapshot {
            live_schema: LIVE_SCHEMA_VERSION,
            daemon_instance: self.0.instance,
            daemon_uptime_ms: now_ms,
            state_revision: inner.revision_for(peer_uid),
            stage: inner.stage,
            worker,
            background: inner
                .background
                .iter()
                .map(|task| LiveWorkerOperation {
                    operation_id: task.id,
                    kind: visible_kind(task.kind, task.owner, peer_uid),
                    elapsed_ms: now_ms.saturating_sub(task.started_ms),
                    cancellation_requested: task.cancelled,
                })
                .collect(),
            waiting: waiting
                .into_iter()
                .map(|(kind, count)| LiveWaitingCount { kind, count })
                .collect(),
            cameras,
            tracking_available: inner.available,
        }
    }
    /// A change every reader can observe that an operation made beside its
    /// own records: the capture schedule every account reads changed while
    /// it ran (a stored qualification, a runtime trip). Moves every reader's
    /// revision, as daemon-wide work does.
    pub(crate) fn note_shared_change(&self) {
        self.lock()
            .note_change(LiveOperationKind::CaptureQualification, Owner::Daemon);
    }
    /// Whether the peer with uid `peer_uid` reads work in live status as
    /// `Unknown`: another account's, or one that did not resolve, running or
    /// waiting. The daemon refuses such a peer's camera work then, as it does
    /// while an authentication is pending, so the refusal tells it nothing
    /// its live status does not ([`crate::arbiter::Refusal::Busy`]).
    pub(crate) fn shows_unknown_work(&self, peer_uid: u32) -> bool {
        self.lock().shows_unknown_work(peer_uid)
    }
}
/// The kind the peer with uid `peer_uid` reads for an operation: its own
/// unless the reader may not see that operation ([`Owner::visible_to`]),
/// else `Unknown`.
fn visible_kind(kind: LiveOperationKind, owner: Owner, peer_uid: u32) -> LiveOperationKind {
    if owner.visible_to(peer_uid) {
        kind
    } else {
        LiveOperationKind::Unknown
    }
}
/// Whether the shared token asks the running worker, of `kind` as the
/// peer with uid `peer_uid` reads it and owned by `owner`, to stop.
/// Authentications and credential releases stop only when their client
/// leaves; other work also yields to a queued authentication. An operation
/// the reader may not see reads as `Unknown` and shows only the request
/// every kind honours, its client leaving: showing the yield would tell an
/// authentication, which never yields, from any other kind. A reader other
/// than root sees the yield only on its own work, whose client is told it
/// yielded anyway: on daemon-wide work it would say that the unknown work
/// waiting is an authentication.
fn stop_requested(
    token: &CancelToken,
    kind: LiveOperationKind,
    owner: Owner,
    peer_uid: u32,
) -> bool {
    let yield_shown = peer_uid == 0 || owner == Owner::Account(peer_uid);
    match kind {
        LiveOperationKind::Authentication
        | LiveOperationKind::WalletAuthentication
        | LiveOperationKind::Unknown => token.cancel_requested(),
        _ if yield_shown => token.stop_requested(),
        _ => token.cancel_requested(),
    }
}
impl LiveGuard {
    pub(crate) fn waiting(&self) {
        let mut inner = self.0.state.lock();
        // A fast worker may have claimed/completed before submit returns.
        if self.0.phase.load(Ordering::Relaxed) != CREATED {
            return;
        }
        if self.0.lane != Lane::Worker {
            inner.available = false;
            return;
        }
        let count = inner
            .waiting
            .entry((self.0.kind, self.0.owner))
            .or_default();
        if let Some(next) = count.checked_add(1) {
            *count = next;
        } else {
            inner.available = false;
        }
        self.0.phase.store(WAITING, Ordering::Relaxed);
    }
    pub(crate) fn running(&self) {
        let mut inner = self.0.state.lock();
        match self.0.phase.load(Ordering::Relaxed) {
            WAITING => remove_waiter(&mut inner, self.0.kind, self.0.owner),
            CREATED => {}
            _ => return,
        }
        self.0.phase.store(RUNNING, Ordering::Relaxed);
        let duplicate_id = inner
            .worker
            .as_ref()
            .is_some_and(|worker| worker.id == self.0.id)
            || inner.background.iter().any(|task| task.id == self.0.id);
        let full = match self.0.lane {
            Lane::Worker => inner.worker.is_some(),
            Lane::Background => inner.background.len() == MAX_BACKGROUND_OPERATIONS,
        };
        if duplicate_id || full {
            // Keep existing owners intact. This registration did run, so its
            // eventual completion still invalidates potentially changed state.
            inner.available = false;
            self.0.phase.store(UNTRACKED, Ordering::Relaxed);
            return;
        }
        let worker = Worker {
            id: self.0.id,
            kind: self.0.kind,
            owner: self.0.owner,
            started_ms: self.0.state.0.clock.now_ms(),
            cancelled: false,
        };
        match self.0.lane {
            Lane::Worker => inner.worker = Some(worker),
            Lane::Background => inner.background.push(worker),
        }
    }
    pub(crate) fn cancel(&self) {
        let mut inner = self.0.state.lock();
        if self.0.phase.load(Ordering::Relaxed) == RUNNING {
            let task = match self.0.lane {
                Lane::Worker => inner
                    .worker
                    .as_mut()
                    .filter(|worker| worker.id == self.0.id),
                Lane::Background => inner
                    .background
                    .iter_mut()
                    .find(|worker| worker.id == self.0.id),
            };
            if let Some(task) = task {
                task.cancelled = true;
            }
        }
    }
    pub(crate) fn finish(&self) {
        self.0.finish();
    }
}
fn remove_waiter(inner: &mut Inner, kind: LiveOperationKind, owner: Owner) {
    match inner.waiting.get_mut(&(kind, owner)) {
        Some(count) if *count > 1 => *count -= 1,
        Some(_) => {
            inner.waiting.remove(&(kind, owner));
        }
        None => inner.available = false,
    }
}
impl Registration {
    fn finish(&self) {
        let mut inner = self.state.lock();
        match self.phase.swap(FINISHED, Ordering::Relaxed) {
            WAITING => remove_waiter(&mut inner, self.kind, self.owner),
            phase @ (RUNNING | UNTRACKED) => {
                if phase == RUNNING {
                    match self.lane {
                        Lane::Worker => {
                            if inner
                                .worker
                                .as_ref()
                                .is_some_and(|worker| worker.id == self.id)
                            {
                                inner.worker = None;
                            } else {
                                inner.available = false;
                            }
                        }
                        Lane::Background => {
                            if let Some(index) = inner
                                .background
                                .iter()
                                .position(|worker| worker.id == self.id)
                            {
                                inner.background.swap_remove(index);
                            } else {
                                inner.available = false;
                            }
                        }
                    }
                }
                // Completion invalidates even after an error or unwind: writes
                // may have happened before the final response became unknown.
                if self.changes_state {
                    inner.note_change(self.kind, self.owner);
                }
            }
            _ => {}
        }
    }
}
impl Drop for Registration {
    fn drop(&mut self) {
        self.finish();
    }
}

/// Observer reads never register or advance invalidation. Exhaustive on purpose.
pub(crate) fn request_kind(req: &Request) -> Option<(LiveOperationKind, bool)> {
    use LiveOperationKind as K;
    use Request::*;
    Some(match req {
        Authenticate { .. } => (K::Authentication, false),
        // A disarm's token release checks the account's password and hands
        // the token out: a credential release, shown to root and its account
        // only (`LiveState::snapshot_for`).
        UnsealPassword { .. } | UnsealKeyring { .. } | ReleaseTokenForDisarm { .. } => {
            (K::WalletAuthentication, false)
        }
        Enroll { .. }
        | EnrollOn { .. }
        | EnrollSplitOn { .. }
        | EnrollmentSession { .. }
        | AddScan { .. }
        | AddCameraGroup { .. }
        | AddCameraGroupOn { .. }
        | AddSplitCameraGroupOn { .. } => (K::Enrollment, true),
        PositionSample { .. } | PositionSession { .. } => (K::Framing, false),
        // A recognition test changes no state: advancing the revision
        // would make every client drop all of its daemon observations.
        Identify | IdentifyFor { .. } => (K::Identification, false),
        ListCameras => (K::CameraEnumeration, false),
        SetCameras { .. }
        | SetCamerasIfCurrent { .. }
        | AddSplitAuthorization { .. }
        | RemoveSplitAuthorization { .. }
        | SelectSplitPair { .. } => (K::CameraSetup, true),
        ListSplitAuthorizations | SplitStatus => return None,
        SetupIrEmitter { dry_run } => (K::CameraSetup, !dry_run),
        TuneCaptureMode { .. } => (K::CaptureQualification, true),
        CaptureModeStatus | CameraDiagnostics | SelfTest { .. } | SupportProbe { .. } => {
            (K::CameraDiagnostics, false)
        }
        ListProfiles { .. } => (K::ProfileRead, false),
        DeleteProfile { .. }
        | DeleteScan { .. }
        | ForgetRecognizer { .. }
        | RenameProfile { .. }
        | RemoveCameraGroup { .. }
        | RenameScan { .. }
        | SetRequireEyesOpen { .. } => (K::ProfileUpdate, true),
        FaceSensorStatus { user: Some(_) } => (K::SensorReadiness, false),
        KeyringInfo { .. } => (K::WalletRead, false),
        SealPassword { .. } | ResealPassword { .. } | ForgetPassword { .. } => {
            (K::WalletUpdate, true)
        }
        RecoverySetup { .. } | RecoveryRestore { .. } | RecoveryForget { .. } => {
            (K::RecoveryUpdate, true)
        }
        CaptureEarMedian { .. } | SetClosureCalibration { .. } => (K::Compatibility, false),
        LiveStatus
        | SupportSnapshot { .. }
        | TraceSubscribe { .. }
        | Ping
        | Health
        | PreferencesStatus
        | SealedStorage
        | LastAttempts { .. }
        | FaceSensorStatus { user: None }
        | HasSealedPassword { .. }
        | KeyringMetadata { .. }
        | RecoveryStatus { .. }
        | RetryStatus { .. }
        | RetryReset { .. } => return None,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::AtomicU64;
    #[derive(Default)]
    struct TestClock(AtomicU64);
    impl Clock for TestClock {
        fn now_ms(&self) -> u64 {
            self.0.load(Ordering::Relaxed)
        }
    }
    fn setup() -> (LiveState, Arc<TestClock>) {
        let clock = Arc::new(TestClock::default());
        (
            LiveState::new(OperationId::from_bytes([1; 16]), clock.clone()),
            clock,
        )
    }
    fn snapshot(state: &LiveState) -> LiveStatusSnapshot {
        state.snapshot(CameraInventorySnapshot::default())
    }
    fn guard(state: &LiveState, id: u8, mutation: bool) -> LiveGuard {
        state.register(
            OperationId::from_bytes([id; 16]),
            LiveOperationKind::Enrollment,
            mutation,
            Owner::Daemon,
        )
    }
    #[test]
    fn live_tracker_distinguishes_waiting_running_and_completion() {
        let (state, clock) = setup();
        let task = guard(&state, 2, true);
        task.waiting();
        assert_eq!(snapshot(&state).waiting[0].count, 1);
        assert!(snapshot(&state).worker.is_none());
        clock.0.store(25, Ordering::Relaxed);
        task.running();
        clock.0.store(75, Ordering::Relaxed);
        assert_eq!(snapshot(&state).worker.unwrap().elapsed_ms, 50);
        assert!(snapshot(&state).waiting.is_empty());
        task.finish();
        let done = snapshot(&state);
        assert!(done.worker.is_none());
        assert_eq!(done.state_revision, 1);
    }
    #[test]
    fn live_tracker_late_admission_cannot_downgrade_running_or_finished() {
        let (state, _) = setup();
        let task = guard(&state, 2, true);
        task.running();
        task.waiting();
        assert!(snapshot(&state).worker.is_some());
        assert!(snapshot(&state).waiting.is_empty());
        task.finish();
        task.waiting();
        task.running();
        assert!(snapshot(&state).worker.is_none());
        assert_eq!(snapshot(&state).state_revision, 1);
    }
    #[test]
    fn live_tracker_clone_drop_does_not_release_worker_but_last_drop_does() {
        let (state, _) = setup();
        let task = guard(&state, 2, true);
        let other = task.clone();
        task.running();
        drop(task);
        assert!(snapshot(&state).worker.is_some());
        drop(other);
        assert!(snapshot(&state).worker.is_none());
        assert_eq!(snapshot(&state).state_revision, 1);
    }
    #[test]
    fn live_tracker_old_cancel_and_finish_cannot_touch_next_worker() {
        let (state, _) = setup();
        let old = guard(&state, 2, true);
        old.running();
        old.finish();
        let next = guard(&state, 3, true);
        next.running();
        old.cancel();
        old.finish();
        let current = snapshot(&state).worker.unwrap();
        assert_eq!(current.operation_id, OperationId::from_bytes([3; 16]));
        assert!(!current.cancellation_requested);
        next.cancel();
        assert!(snapshot(&state).worker.unwrap().cancellation_requested);
    }
    #[test]
    fn live_tracker_waiting_drop_and_refusal_do_not_invalidate_state() {
        let (state, _) = setup();
        let never_admitted = guard(&state, 2, true);
        drop(never_admitted);
        let waiting = guard(&state, 3, true);
        waiting.waiting();
        drop(waiting);
        assert!(snapshot(&state).waiting.is_empty());
        assert_eq!(snapshot(&state).state_revision, 0);
    }
    #[test]
    fn live_tracker_observers_and_failed_mutations_have_distinct_revision_semantics() {
        let (state, _) = setup();
        assert!(request_kind(&Request::LiveStatus).is_none());
        assert!(request_kind(&Request::SupportSnapshot { since_ms: 60_000 }).is_none());
        // A recognition test is activity but never a state change: a
        // revision bump would make clients drop every observation.
        for identify in [Request::Identify, Request::IdentifyFor { user: "u".into() }] {
            assert_eq!(
                request_kind(&identify),
                Some((LiveOperationKind::Identification, false))
            );
        }
        for _ in 0..100 {
            assert_eq!(snapshot(&state).state_revision, 0);
        }
        let failed_or_unknown = guard(&state, 2, true);
        failed_or_unknown.running();
        failed_or_unknown.finish();
        assert_eq!(snapshot(&state).state_revision, 1);
        let read = guard(&state, 3, false);
        read.running();
        read.finish();
        assert_eq!(snapshot(&state).state_revision, 1);
    }
    #[test]
    fn live_tracker_stages_and_large_waiting_sets_are_bounded() {
        let (state, _) = setup();
        state.set_stage(LiveStage::Rebuilding);
        assert_eq!(snapshot(&state).stage, LiveStage::Rebuilding);
        let tasks: Vec<_> = (0..1000)
            .map(|_| {
                let g = guard(&state, 2, false);
                g.waiting();
                g
            })
            .collect();
        assert_eq!(snapshot(&state).waiting.len(), 1);
        assert_eq!(snapshot(&state).waiting[0].count, 1000);
        drop(tasks);
        assert!(snapshot(&state).waiting.is_empty());
    }
    #[test]
    fn live_tracker_unwind_cleans_running_metadata() {
        let (state, _) = setup();
        let copy = state.clone();
        let _ = std::panic::catch_unwind(std::panic::AssertUnwindSafe(move || {
            let g = guard(&copy, 2, true);
            g.running();
            panic!("synthetic unwind");
        }));
        assert!(snapshot(&state).worker.is_none());
        assert_eq!(snapshot(&state).state_revision, 1);
    }
    #[test]
    fn live_tracker_worker_unwind_stops_stage_and_cannot_be_republished_ready() {
        let (state, _) = setup();
        let _ = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let _lifetime = state.worker_lifetime();
            state.set_stage(LiveStage::Ready);
            panic!("synthetic worker panic");
        }));
        state.set_stage(LiveStage::Ready);
        assert_eq!(snapshot(&state).stage, LiveStage::Stopping);
    }
    #[test]
    fn live_tracker_shared_stop_distinguishes_authentication_preemption() {
        let (state, _) = setup();
        let token = CancelToken::new();
        state.set_cancel_token(token.clone());
        let auth = state.register(
            OperationId::from_bytes([2; 16]),
            LiveOperationKind::Authentication,
            false,
            Owner::Daemon,
        );
        auth.running();
        token.request_stop();
        assert!(!snapshot(&state).worker.unwrap().cancellation_requested);
        token.request_cancel();
        assert!(snapshot(&state).worker.unwrap().cancellation_requested);
        auth.finish();
        token.reset();
        let enrollment = guard(&state, 3, true);
        enrollment.running();
        assert!(!snapshot(&state).worker.unwrap().cancellation_requested);
        token.request_stop();
        assert!(snapshot(&state).worker.unwrap().cancellation_requested);
    }
    /// A reader other than root sees every operation of another account, or
    /// of an unresolved one, as unknown work whatever its kind, with its
    /// place, elapsed time and a departed client's stop request intact; its
    /// own operations and daemon-wide work under the kind they registered.
    /// Root sees every kind. Relabelled waiting rows merge into one valid
    /// row per kind.
    #[test]
    fn live_status_shows_other_accounts_operations_of_every_kind_as_unknown_work() {
        use LiveOperationKind as K;
        let (state, clock) = setup();
        let register = |id: u8, kind, owner| {
            state.register(OperationId::from_bytes([id; 16]), kind, false, owner)
        };
        let running = register(2, K::Enrollment, Owner::Account(1_000));
        running.running();
        let own_waiting = register(3, K::Authentication, Owner::Account(1_000));
        own_waiting.waiting();
        let other_release = register(4, K::WalletAuthentication, Owner::Account(2_000));
        other_release.waiting();
        let other_update = register(5, K::WalletUpdate, Owner::Account(2_000));
        other_update.waiting();
        let unresolved = register(6, K::Authentication, Owner::Unresolved);
        unresolved.waiting();
        let daemon = register(7, K::CameraSetup, Owner::Daemon);
        daemon.waiting();
        let background = state.register_background(OperationId::from_bytes([8; 16]));
        background.running();
        clock.0.store(40, Ordering::Relaxed);
        running.cancel();
        let view = |peer_uid| {
            let live = state.snapshot_for(CameraInventorySnapshot::default(), peer_uid);
            let encoded =
                serde_json::to_string(&irlume_common::Response::LiveStatus(Box::new(live.clone())))
                    .unwrap();
            assert!(
                serde_json::from_str::<irlume_common::Response>(&encoded).is_ok(),
                "{peer_uid}'s view must decode"
            );
            let worker = live.worker.expect("the worker stays busy for every reader");
            assert_eq!(worker.operation_id, OperationId::from_bytes([2; 16]));
            assert_eq!(worker.elapsed_ms, 40);
            assert!(worker.cancellation_requested, "the stop request stays");
            assert_eq!(
                live.background
                    .iter()
                    .map(|task| (task.operation_id, task.kind))
                    .collect::<Vec<_>>(),
                [(OperationId::from_bytes([8; 16]), K::CaptureQualification)],
                "daemon-wide work keeps its kind"
            );
            let waiting = live
                .waiting
                .iter()
                .map(|row| (row.kind, row.count))
                .collect::<Vec<_>>();
            (worker.kind, waiting)
        };
        assert_eq!(
            snapshot(&state),
            state.snapshot_for(CameraInventorySnapshot::default(), 0)
        );
        assert_eq!(
            view(0),
            (
                K::Enrollment,
                vec![
                    (K::Authentication, 2),
                    (K::WalletAuthentication, 1),
                    (K::CameraSetup, 1),
                    (K::WalletUpdate, 1),
                ]
            )
        );
        assert_eq!(
            view(1_000),
            (
                K::Enrollment,
                vec![(K::Authentication, 1), (K::CameraSetup, 1), (K::Unknown, 3)]
            )
        );
        assert_eq!(
            view(2_000),
            (
                K::Unknown,
                vec![
                    (K::WalletAuthentication, 1),
                    (K::CameraSetup, 1),
                    (K::WalletUpdate, 1),
                    (K::Unknown, 2)
                ]
            )
        );
        assert_eq!(
            view(3_000),
            (K::Unknown, vec![(K::CameraSetup, 1), (K::Unknown, 4)])
        );
        drop((own_waiting, other_release, other_update, unresolved, daemon));
        assert!(state
            .snapshot_for(CameraInventorySnapshot::default(), 3_000)
            .waiting
            .is_empty());
    }
    /// A reader other than root reads the same stop request for another
    /// account's running operation, an unresolved one's or daemon-wide
    /// work, whatever its kind: a queued authentication's yield, which only
    /// some kinds honour, does not show, and a departed client's cancel,
    /// which every kind honours, does. Root reads the kind's own request,
    /// and so does the account for its own work.
    #[test]
    fn live_status_shows_one_stop_request_for_hidden_operations_of_every_kind() {
        use LiveOperationKind as K;
        let (state, _) = setup();
        let token = CancelToken::new();
        state.set_cancel_token(token.clone());
        let flag = |peer_uid| {
            state
                .snapshot_for(CameraInventorySnapshot::default(), peer_uid)
                .worker
                .expect("the worker stays busy for every reader")
                .cancellation_requested
        };
        let kinds = [
            K::Authentication,
            K::WalletAuthentication,
            K::Enrollment,
            K::Framing,
            K::Identification,
            K::CameraEnumeration,
            K::CameraSetup,
            K::CaptureQualification,
            K::CameraDiagnostics,
            K::ProfileRead,
            K::ProfileUpdate,
            K::SensorReadiness,
            K::WalletRead,
            K::WalletUpdate,
            K::RecoveryUpdate,
            K::Compatibility,
            K::Status,
        ];
        for owner in [Owner::Account(1_000), Owner::Unresolved, Owner::Daemon] {
            for kind in kinds {
                let worker = state.register(OperationId::from_bytes([2; 16]), kind, false, owner);
                worker.running();
                let yields = !matches!(kind, K::Authentication | K::WalletAuthentication);
                for peer_uid in [0, 1_000, 2_000] {
                    assert!(!flag(peer_uid), "{owner:?} {kind:?}: nothing asked yet");
                }
                token.request_stop();
                assert_eq!(flag(0), yields, "{owner:?} {kind:?}: root reads the kind's");
                let owners_view = owner == Owner::Account(1_000) && yields;
                assert_eq!(
                    flag(1_000),
                    owners_view,
                    "{owner:?} {kind:?}: uid 1000 reads the kind's for its own work only"
                );
                assert!(
                    !flag(2_000),
                    "{owner:?} {kind:?}: another account reads no yield"
                );
                token.request_cancel();
                for peer_uid in [0, 1_000, 2_000] {
                    assert!(
                        flag(peer_uid),
                        "{owner:?} {kind:?}: a departed client reads for {peer_uid}"
                    );
                }
                worker.finish();
                token.reset();
            }
        }
    }
    #[test]
    fn live_tracker_revision_overflow_and_poison_report_unavailable() {
        let (state, _) = setup();
        state.lock().revision = u64::MAX;
        let operation = guard(&state, 2, true);
        operation.running();
        operation.finish();
        assert_eq!(snapshot(&state).state_revision, u64::MAX);
        assert!(!snapshot(&state).tracking_available);
        let (poisoned, _) = setup();
        let _ = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let _lock = poisoned.0.inner.lock().unwrap();
            panic!("synthetic poison");
        }));
        assert!(!snapshot(&poisoned).tracking_available);
    }
    #[test]
    fn live_background_is_separate_from_worker_and_shared_cancellation() {
        let (state, clock) = setup();
        let token = CancelToken::new();
        state.set_cancel_token(token.clone());
        let worker = guard(&state, 2, false);
        worker.running();
        clock.0.store(10, Ordering::Relaxed);
        let background = state.register_background(OperationId::from_bytes([3; 16]));
        background.running();
        clock.0.store(50, Ordering::Relaxed);
        token.request_cancel();
        let live = snapshot(&state);
        assert!(live.tracking_available);
        assert_eq!(
            live.worker.unwrap().operation_id,
            OperationId::from_bytes([2; 16])
        );
        assert_eq!(live.background.len(), 1);
        assert_eq!(live.background[0].elapsed_ms, 40);
        assert!(!live.background[0].cancellation_requested);
        background.finish();
        let done = snapshot(&state);
        assert!(done.background.is_empty());
        assert!(done.worker.is_some());
        assert_eq!(done.state_revision, 1);
    }
    #[test]
    fn live_background_unwind_releases_only_background_and_invalidates() {
        let (state, _) = setup();
        let worker = guard(&state, 2, false);
        worker.running();
        let _ = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let background = state.register_background(OperationId::from_bytes([3; 16]));
            background.running();
            assert_eq!(snapshot(&state).background.len(), 1);
            panic!("synthetic background unwind");
        }));
        let live = snapshot(&state);
        assert!(live.tracking_available);
        assert!(live.worker.is_some());
        assert!(live.background.is_empty());
        assert_eq!(live.state_revision, 1);
    }
    #[test]
    fn live_background_overflow_is_unavailable_and_never_grows_the_wire() {
        let (state, _) = setup();
        let tasks: Vec<_> = (2..=6)
            .map(|id| {
                let background = state.register_background(OperationId::from_bytes([id; 16]));
                background.running();
                background
            })
            .collect();
        let live = snapshot(&state);
        assert!(!live.tracking_available);
        assert_eq!(live.background.len(), MAX_BACKGROUND_OPERATIONS);
        drop(tasks);
        assert!(snapshot(&state).background.is_empty());
    }
    #[test]
    fn live_background_clone_drop_retains_owner_until_last_copy() {
        let (state, _) = setup();
        let worker = guard(&state, 2, false);
        worker.running();
        let background = state.register_background(OperationId::from_bytes([3; 16]));
        let other = background.clone();
        background.running();
        drop(background);
        assert_eq!(snapshot(&state).background.len(), 1);
        drop(other);
        let done = snapshot(&state);
        assert!(done.background.is_empty());
        assert!(done.worker.is_some());
        assert_eq!(done.state_revision, 1);
    }
    #[test]
    fn live_background_duplicate_registration_cannot_release_existing_owner() {
        let (state, _) = setup();
        let owner = state.register_background(OperationId::from_bytes([2; 16]));
        owner.running();
        let duplicate = state.register_background(OperationId::from_bytes([2; 16]));
        duplicate.running();
        duplicate.finish();
        let live = snapshot(&state);
        assert!(!live.tracking_available);
        assert_eq!(live.background.len(), 1);
        assert_eq!(
            live.background[0].operation_id,
            OperationId::from_bytes([2; 16])
        );
        owner.finish();
        assert!(snapshot(&state).background.is_empty());
    }
    /// A reader other than root reads a revision that moves for its own
    /// changes and for those every reader can observe, never for another
    /// account's or an unresolved one's; root's moves for every change.
    #[test]
    fn a_readers_state_revision_moves_only_for_changes_it_can_see() {
        use LiveOperationKind as K;
        let (state, _) = setup();
        let mut next_id = 1u8;
        let mut change = |kind, owner| {
            next_id += 1;
            let operation =
                state.register(OperationId::from_bytes([next_id; 16]), kind, true, owner);
            operation.running();
            operation.finish();
        };
        let revisions = || {
            [0, 1_000, 2_000, 3_000].map(|uid| {
                state
                    .snapshot_for(CameraInventorySnapshot::default(), uid)
                    .state_revision
            })
        };
        assert_eq!(revisions(), [0, 0, 0, 0]);
        // The account's own work, whether it or root asked for it.
        change(K::Enrollment, Owner::Account(1_000));
        change(K::WalletUpdate, Owner::Account(1_000));
        assert_eq!(revisions(), [2, 2, 0, 0]);
        change(K::ProfileUpdate, Owner::Account(2_000));
        change(K::RecoveryUpdate, Owner::Account(2_000));
        assert_eq!(revisions(), [4, 2, 2, 0]);
        // Root's own account's work is root's alone.
        change(K::WalletUpdate, Owner::Account(0));
        assert_eq!(revisions(), [5, 2, 2, 0]);
        assert!(!state.lock().account_revisions.contains_key(&0));
        // Daemon-wide work, root's work for a name that did not resolve, and
        // camera setup and qualification whoever asked for them, move every
        // reader's.
        change(K::WalletUpdate, Owner::Unresolved);
        change(K::CameraSetup, Owner::Daemon);
        change(K::CameraSetup, Owner::Account(2_000));
        change(K::CaptureQualification, Owner::Account(3_000));
        assert_eq!(revisions(), [9, 6, 6, 4]);
        let background = state.register_background(OperationId::from_bytes([200; 16]));
        background.running();
        background.finish();
        assert_eq!(revisions(), [10, 7, 7, 5]);
        // Work that changes nothing moves no one's revision.
        let read = state.register(
            OperationId::from_bytes([201; 16]),
            K::ProfileRead,
            false,
            Owner::Account(1_000),
        );
        read.running();
        read.finish();
        assert_eq!(revisions(), [10, 7, 7, 5]);
        // An operation of any account that changed the capture schedule
        // every account reads.
        state.note_shared_change();
        assert_eq!(revisions(), [11, 8, 8, 6]);
    }
    /// Past the bound of accounts with a count of their own, the account
    /// whose latest change is oldest gives its count to the shared one: its
    /// revision stays where it was and no reader's goes back.
    #[test]
    fn a_readers_state_revision_never_goes_back_when_its_count_is_evicted() {
        let (state, _) = setup();
        let change = |id: u64, uid: u32| {
            let mut bytes = [0u8; 16];
            bytes[..8].copy_from_slice(&id.to_le_bytes());
            let operation = state.register(
                OperationId::from_bytes(bytes),
                LiveOperationKind::ProfileUpdate,
                true,
                Owner::Account(uid),
            );
            operation.running();
            operation.finish();
        };
        let revision = |uid: u32| {
            state
                .snapshot_for(CameraInventorySnapshot::default(), uid)
                .state_revision
        };
        let first = 10_000u32;
        change(1, first);
        change(2, first);
        let mut id = 3u64;
        for uid in first + 1..first + MAX_REVISION_ACCOUNTS as u32 {
            change(id, uid);
            id += 1;
        }
        assert_eq!(state.lock().account_revisions.len(), MAX_REVISION_ACCOUNTS);
        assert_eq!(revision(first), 2);
        assert_eq!(revision(first + 1), 1);
        assert_eq!(revision(5), 0, "an account with no changes");
        // One more account: `first` changed longest ago and is evicted.
        let newcomer = first + MAX_REVISION_ACCOUNTS as u32;
        change(id, newcomer);
        assert_eq!(state.lock().account_revisions.len(), MAX_REVISION_ACCOUNTS);
        assert!(!state.lock().account_revisions.contains_key(&first));
        assert_eq!(revision(first), 2, "the evicted account's stays put");
        assert_eq!(revision(first + 1), 3, "another account's only grows");
        assert_eq!(revision(newcomer), 3);
        assert_eq!(revision(5), 2);
        assert_eq!(revision(0), MAX_REVISION_ACCOUNTS as u64 + 2);
        // The evicted account's next change counts on from there; coming
        // back, it evicts `first + 1`, whose one change also becomes shared.
        change(id + 1, first);
        assert_eq!(revision(first), 4);
        assert_eq!(revision(first + 1), 3);
    }
    /// A reader other than root is shown another account's work, or an
    /// unresolved one's, as unknown, running or waiting; that is when the
    /// daemon refuses its camera work. Its own and daemon-wide work are not.
    #[test]
    fn unknown_work_is_what_the_reader_cannot_see_running_or_waiting() {
        use LiveOperationKind as K;
        let (state, _) = setup();
        let readers = || [0, 1_000, 2_000].map(|uid| state.shows_unknown_work(uid));
        assert_eq!(readers(), [false, false, false]);
        let register = |id: u8, owner| {
            state.register(
                OperationId::from_bytes([id; 16]),
                K::ProfileRead,
                false,
                owner,
            )
        };
        let daemon = register(2, Owner::Daemon);
        daemon.running();
        let background = state.register_background(OperationId::from_bytes([3; 16]));
        background.running();
        assert_eq!(readers(), [false, false, false], "daemon-wide work");
        let own = register(4, Owner::Account(1_000));
        own.waiting();
        assert_eq!(readers(), [false, false, true]);
        own.finish();
        let unresolved = register(5, Owner::Unresolved);
        unresolved.waiting();
        assert_eq!(readers(), [false, true, true]);
        unresolved.finish();
        daemon.finish();
        let running = register(6, Owner::Account(2_000));
        running.running();
        assert_eq!(readers(), [false, true, false]);
        running.finish();
        assert_eq!(readers(), [false, false, false]);
    }
}

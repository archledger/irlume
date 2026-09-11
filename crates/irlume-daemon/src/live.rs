// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright the irlume contributors.

//! Bounded copied worker observations. Guards never own cameras or requests.

use crate::{arbiter::CancelToken, diagnostics::Clock};
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
    revision: u64,
    waiting: BTreeMap<LiveOperationKind, u64>,
    worker: Option<Worker>,
    background: Vec<Worker>,
    available: bool,
}
struct Worker {
    id: OperationId,
    kind: LiveOperationKind,
    started_ms: u64,
    cancelled: bool,
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
    pub(crate) fn register(
        &self,
        id: OperationId,
        kind: LiveOperationKind,
        changes_state: bool,
    ) -> LiveGuard {
        self.register_in_lane(id, kind, changes_state, Lane::Worker)
    }
    fn register_in_lane(
        &self,
        id: OperationId,
        kind: LiveOperationKind,
        changes_state: bool,
        lane: Lane,
    ) -> LiveGuard {
        LiveGuard(Arc::new(Registration {
            state: self.clone(),
            id,
            kind,
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
            Lane::Background,
        )
    }
    pub(crate) fn snapshot(&self, cameras: CameraInventorySnapshot) -> LiveStatusSnapshot {
        let inner = self.lock();
        // Capture once: elapsed must never exceed the same snapshot's uptime.
        let now_ms = self.0.clock.now_ms();
        let worker = inner.worker.as_ref().map(|worker| {
            // Read the shared stop bit under the tracker lock. The previous
            // worker is removed before the next arbiter.take resets that bit.
            let requested = self.0.cancel.get().is_some_and(|token| {
                if matches!(
                    worker.kind,
                    LiveOperationKind::Authentication | LiveOperationKind::WalletAuthentication
                ) {
                    token.cancel_requested()
                } else {
                    token.stop_requested()
                }
            });
            LiveWorkerOperation {
                operation_id: worker.id,
                kind: worker.kind,
                elapsed_ms: now_ms.saturating_sub(worker.started_ms),
                cancellation_requested: worker.cancelled || requested,
            }
        });
        LiveStatusSnapshot {
            live_schema: LIVE_SCHEMA_VERSION,
            daemon_instance: self.0.instance,
            daemon_uptime_ms: now_ms,
            state_revision: inner.revision,
            stage: inner.stage,
            worker,
            background: inner
                .background
                .iter()
                .map(|task| LiveWorkerOperation {
                    operation_id: task.id,
                    kind: task.kind,
                    elapsed_ms: now_ms.saturating_sub(task.started_ms),
                    cancellation_requested: task.cancelled,
                })
                .collect(),
            waiting: inner
                .waiting
                .iter()
                .map(|(&kind, &count)| LiveWaitingCount { kind, count })
                .collect(),
            cameras,
            tracking_available: inner.available,
        }
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
        let count = inner.waiting.entry(self.0.kind).or_default();
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
            WAITING => remove_waiter(&mut inner, self.0.kind),
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
    pub(crate) fn finish_waiting(&self) {
        let mut inner = self.0.state.lock();
        match self.0.phase.load(Ordering::Relaxed) {
            WAITING => remove_waiter(&mut inner, self.0.kind),
            CREATED => {}
            _ => return,
        }
        self.0.phase.store(FINISHED, Ordering::Relaxed);
    }
    pub(crate) fn finish(&self) {
        self.0.finish();
    }
}
fn remove_waiter(inner: &mut Inner, kind: LiveOperationKind) {
    match inner.waiting.get_mut(&kind) {
        Some(count) if *count > 1 => *count -= 1,
        Some(_) => {
            inner.waiting.remove(&kind);
        }
        None => inner.available = false,
    }
}
impl Registration {
    fn finish(&self) {
        let mut inner = self.state.lock();
        match self.phase.swap(FINISHED, Ordering::Relaxed) {
            WAITING => remove_waiter(&mut inner, self.kind),
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
                    if let Some(next) = inner.revision.checked_add(1) {
                        inner.revision = next;
                    } else {
                        inner.available = false;
                    }
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
        UnsealPassword { .. } | UnsealKeyring { .. } => (K::WalletAuthentication, false),
        Enroll { .. } | EnrollmentSession { .. } | AddScan { .. } => (K::Enrollment, true),
        PositionSample { .. } | PositionSession { .. } => (K::Framing, false),
        Identify => (K::Identification, false),
        ListCameras => (K::CameraEnumeration, false),
        SetCameras { .. } | SetCamerasIfCurrent { .. } => (K::CameraSetup, true),
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
        | RenameScan { .. }
        | SetRequireEyesOpen { .. } => (K::ProfileUpdate, true),
        FaceSensorStatus { user: Some(_) } => (K::SensorReadiness, false),
        KeyringInfo { .. } => (K::WalletRead, false),
        SealPassword { .. } | ResealPassword { .. } | ForgetPassword { .. } => {
            (K::WalletUpdate, true)
        }
        ReleaseTokenForDisarm { .. } => (K::WalletRead, false),
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
    fn live_tracker_waiting_cancellation_cannot_finish_a_running_worker() {
        let (state, _) = setup();
        let queued = guard(&state, 2, true);
        queued.waiting();
        queued.finish_waiting();
        queued.running();
        assert!(snapshot(&state).worker.is_none());
        let running = guard(&state, 3, true);
        running.running();
        running.finish_waiting();
        assert!(snapshot(&state).worker.is_some());
        assert_eq!(snapshot(&state).state_revision, 0);
        running.finish();
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
}

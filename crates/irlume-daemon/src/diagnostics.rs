// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright the irlume contributors.

//! Process-local ownership for bounded, share-safe diagnostic history.

use irlume_common::diagnostics::{
    CaptureStatus, CategoricalOutcome, DiagnosticSink, OperationClass, OperationId,
    SanitizedCameraContext, ShareSafeEvent, ShareSafeEventKind, SupportSnapshot, TraceEventKind,
    TraceLimits, TraceRecord, TraceWarning, MAX_HISTORY_MS, MAX_SHARE_SAFE_EVENTS,
    MAX_TRACE_LINE_BYTES, TRACE_SCHEMA_VERSION,
};
use sha2::{Digest as _, Sha256};
use std::collections::VecDeque;
use std::io::Read as _;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::mpsc::{Receiver, RecvTimeoutError, SyncSender, TrySendError};
use std::sync::{Arc, Mutex, Weak};
use std::time::{Duration, Instant};

pub(crate) trait Clock: Send + Sync {
    fn now_ms(&self) -> u64;
}

struct MonotonicClock(Instant);

impl Default for MonotonicClock {
    fn default() -> Self {
        Self(Instant::now())
    }
}

impl Clock for MonotonicClock {
    fn now_ms(&self) -> u64 {
        u64::try_from(self.0.elapsed().as_millis()).unwrap_or(u64::MAX)
    }
}

#[derive(Clone)]
pub(crate) struct DiagnosticState {
    shared: Arc<Shared>,
}

struct Shared {
    clock: Arc<dyn Clock>,
    inner: Mutex<Inner>,
    entropy: Mutex<Option<std::fs::File>>,
    fallback_sequence: AtomicU64,
    trace: Mutex<Option<Weak<TraceSubscriber>>>,
}

const TRACE_CHANNEL_CAPACITY: usize = 1_024;

struct TraceSubscriber {
    sender: SyncSender<TraceRecord>,
    inner: Mutex<TraceInner>,
    limits: TraceLimits,
    started_ms: u64,
}

struct TraceInner {
    next_sequence: u64,
    pending_dropped: u64,
    emitted_bytes: u64,
    finished: bool,
}

pub(crate) struct TraceSubscription {
    subscriber: Arc<TraceSubscriber>,
    receiver: Receiver<TraceRecord>,
    operation_id: OperationId,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum TraceSubscribeError {
    NotRoot,
    Busy,
}

#[derive(Default)]
struct Inner {
    events: VecDeque<TimedShareSafeEvent>,
    next_sequence: u64,
    capture: Option<CaptureStatus>,
    cameras: Vec<SanitizedCameraContext>,
    inference: Option<irlume_common::InferenceResolutionReport>,
}

struct TimedShareSafeEvent {
    recorded_ms: u64,
    sequence: u64,
    operation_id: OperationId,
    operation: OperationClass,
    kind: ShareSafeEventKind,
}

impl Default for DiagnosticState {
    fn default() -> Self {
        Self::with_clock(Arc::new(MonotonicClock::default()))
    }
}

impl DiagnosticState {
    pub(crate) fn with_clock<C>(clock: Arc<C>) -> Self
    where
        C: Clock + 'static,
    {
        Self {
            shared: Arc::new(Shared {
                clock,
                inner: Mutex::new(Inner {
                    next_sequence: 1,
                    ..Inner::default()
                }),
                entropy: Mutex::new(std::fs::File::open("/dev/urandom").ok()),
                fallback_sequence: AtomicU64::new(0),
                trace: Mutex::new(None),
            }),
        }
    }

    pub(crate) fn begin(&self, operation: OperationClass) -> OperationScope {
        OperationScope {
            state: self.clone(),
            operation_id: self.next_operation_id(),
            operation,
            finished: Arc::new(AtomicBool::new(false)),
        }
    }

    pub(crate) fn snapshot(&self, since: Duration) -> SupportSnapshot {
        let now_ms = self.shared.clock.now_ms();
        let since_ms = u64::try_from(since.as_millis())
            .unwrap_or(u64::MAX)
            .min(MAX_HISTORY_MS);
        let mut inner = self
            .shared
            .inner
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        prune_expired(&mut inner.events, now_ms);
        let events = inner
            .events
            .iter()
            .filter_map(|event| {
                let age_ms = now_ms.saturating_sub(event.recorded_ms);
                (age_ms <= since_ms).then(|| ShareSafeEvent {
                    sequence: event.sequence,
                    age_ms,
                    operation_id: event.operation_id,
                    operation: event.operation,
                    kind: event.kind.clone(),
                })
            })
            .collect();
        let capture = inner.capture.clone();
        let cameras = inner.cameras.clone();
        let inference = inner.inference.clone();
        drop(inner);
        SupportSnapshot::bounded(
            now_ms,
            MAX_HISTORY_MS,
            capture,
            cameras,
            events,
            Vec::new(),
            inference,
        )
    }

    pub(crate) fn publish_inference_report(
        &self,
        report: irlume_common::InferenceResolutionReport,
    ) {
        self.shared
            .inner
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .inference = Some(irlume_common::diagnostics::bounded_inference_report(report));
    }

    fn publish_support_context(
        &self,
        capture: CaptureStatus,
        cameras: Vec<SanitizedCameraContext>,
    ) {
        let mut inner = self
            .shared
            .inner
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        inner.capture = Some(capture);
        inner.cameras = cameras;
    }

    pub(crate) fn subscribe_trace(
        &self,
        peer_uid: u32,
        duration_ms: u64,
    ) -> Result<TraceSubscription, TraceSubscribeError> {
        self.subscribe_trace_with_capacity(peer_uid, duration_ms, TRACE_CHANNEL_CAPACITY)
    }

    fn subscribe_trace_with_capacity(
        &self,
        peer_uid: u32,
        duration_ms: u64,
        capacity: usize,
    ) -> Result<TraceSubscription, TraceSubscribeError> {
        if peer_uid != 0 {
            return Err(TraceSubscribeError::NotRoot);
        }
        let mut active = self
            .shared
            .trace
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        if active.as_ref().and_then(Weak::upgrade).is_some() {
            return Err(TraceSubscribeError::Busy);
        }

        let limits = TraceLimits::bounded(duration_ms);
        let (sender, receiver) = std::sync::mpsc::sync_channel(capacity);
        let subscriber = Arc::new(TraceSubscriber {
            sender,
            inner: Mutex::new(TraceInner {
                next_sequence: 0,
                pending_dropped: 0,
                emitted_bytes: 0,
                finished: false,
            }),
            limits,
            started_ms: monotonic_ms(),
        });
        *active = Some(Arc::downgrade(&subscriber));
        drop(active);

        let operation_id = self.next_operation_id();
        subscriber.emit(
            operation_id,
            OperationClass::Status,
            TraceEventKind::TraceStarted {
                limits,
                warning: TraceWarning::PrivilegedDiagnosticOracle,
            },
        );
        Ok(TraceSubscription {
            subscriber,
            receiver,
            operation_id,
        })
    }

    fn emit_trace(
        &self,
        operation_id: OperationId,
        operation: OperationClass,
        kind: TraceEventKind,
    ) {
        let subscriber = self
            .shared
            .trace
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .as_ref()
            .and_then(Weak::upgrade);
        if let Some(subscriber) = subscriber {
            subscriber.emit(operation_id, operation, kind);
        }
    }

    fn record(
        &self,
        operation_id: OperationId,
        operation: OperationClass,
        kind: ShareSafeEventKind,
    ) {
        let now_ms = self.shared.clock.now_ms();
        let mut inner = self
            .shared
            .inner
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        record_locked(&mut inner, now_ms, operation_id, operation, kind);
    }

    fn record_if_unfinished(
        &self,
        operation_id: OperationId,
        operation: OperationClass,
        kind: ShareSafeEventKind,
        finished: &AtomicBool,
    ) -> bool {
        let now_ms = self.shared.clock.now_ms();
        let mut inner = self
            .shared
            .inner
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        // Checked while holding the same ring lock terminal insertion takes.
        // Either this event lands first, or finish flips the bit and no later
        // event can cross the terminal boundary.
        if finished.load(Ordering::Acquire) {
            return false;
        }
        record_locked(&mut inner, now_ms, operation_id, operation, kind);
        true
    }

    fn next_operation_id(&self) -> OperationId {
        let mut bytes = [0_u8; 16];
        let mut entropy = self
            .shared
            .entropy
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        if entropy
            .as_mut()
            .is_some_and(|source| source.read_exact(&mut bytes).is_ok())
            && bytes != [0; 16]
        {
            return OperationId::from_bytes(bytes);
        }
        *entropy = None;
        drop(entropy);

        let sequence = self
            .shared
            .fallback_sequence
            .fetch_add(1, Ordering::Relaxed);
        let mut hash = Sha256::new();
        hash.update(b"irlume-operation-id-fallback-v1");
        hash.update(std::process::id().to_le_bytes());
        hash.update(self.shared.clock.now_ms().to_le_bytes());
        hash.update(sequence.to_le_bytes());
        let digest = hash.finalize();
        bytes.copy_from_slice(&digest[..16]);
        OperationId::from_bytes(bytes)
    }
}

impl TraceSubscriber {
    fn emit(&self, operation_id: OperationId, operation: OperationClass, kind: TraceEventKind) {
        let mut inner = self
            .inner
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        if inner.finished {
            return;
        }
        if inner.pending_dropped > 0 {
            let dropped = inner.pending_dropped;
            if !self.try_send_locked(
                &mut inner,
                operation_id,
                operation,
                TraceEventKind::EventsDropped { count: dropped },
                false,
            ) {
                inner.pending_dropped = inner.pending_dropped.saturating_add(1);
                return;
            }
            inner.pending_dropped = 0;
        }
        if !self.try_send_locked(&mut inner, operation_id, operation, kind, false) {
            inner.pending_dropped = inner.pending_dropped.saturating_add(1);
        }
    }

    fn try_send_locked(
        &self,
        inner: &mut TraceInner,
        operation_id: OperationId,
        operation: OperationClass,
        event: TraceEventKind,
        terminal: bool,
    ) -> bool {
        // Reserve a drop marker plus terminal marker, both written by the
        // owning connection after it has stopped accepting producer events.
        if !terminal && inner.next_sequence >= self.limits.max_events.saturating_sub(2) {
            return false;
        }
        let record = self.record(
            inner.next_sequence,
            operation_id,
            operation,
            event,
            terminal,
        );
        let Ok(serialized) = serde_json::to_vec(&record) else {
            return false;
        };
        let bytes = u64::try_from(serialized.len().saturating_add(1)).unwrap_or(u64::MAX);
        let terminal_reserve = u64::try_from(MAX_TRACE_LINE_BYTES)
            .unwrap_or(u64::MAX)
            .saturating_mul(2);
        if serialized.len() > MAX_TRACE_LINE_BYTES
            || (!terminal
                && inner.emitted_bytes.saturating_add(bytes)
                    > self.limits.max_bytes.saturating_sub(terminal_reserve))
        {
            return false;
        }
        match self.sender.try_send(record) {
            Ok(()) => {
                inner.next_sequence = inner.next_sequence.saturating_add(1);
                inner.emitted_bytes = inner.emitted_bytes.saturating_add(bytes);
                true
            }
            Err(TrySendError::Full(_)) => false,
            Err(TrySendError::Disconnected(_)) => {
                inner.finished = true;
                false
            }
        }
    }

    fn record(
        &self,
        sequence: u64,
        operation_id: OperationId,
        operation: OperationClass,
        event: TraceEventKind,
        terminal: bool,
    ) -> TraceRecord {
        let monotonic_ms = monotonic_ms();
        TraceRecord {
            trace_schema: TRACE_SCHEMA_VERSION,
            sequence,
            monotonic_us: monotonic_ms
                .saturating_sub(self.started_ms)
                .saturating_mul(1_000),
            utc_unix_ms: utc_unix_ms(),
            operation_id,
            operation,
            event,
            terminal,
        }
    }
}

impl TraceSubscription {
    pub(crate) fn limits(&self) -> TraceLimits {
        self.subscriber.limits
    }

    pub(crate) fn recv_timeout(&self, timeout: Duration) -> Result<TraceRecord, RecvTimeoutError> {
        self.receiver.recv_timeout(timeout)
    }

    pub(crate) fn finish(&self, outcome: CategoricalOutcome) -> Vec<TraceRecord> {
        let mut inner = self
            .subscriber
            .inner
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        if inner.finished {
            return Vec::new();
        }
        inner.finished = true;
        let mut records = Vec::with_capacity(2);
        if inner.pending_dropped > 0
            && inner.next_sequence < self.subscriber.limits.max_events.saturating_sub(1)
        {
            records.push(self.subscriber.record(
                inner.next_sequence,
                self.operation_id,
                OperationClass::Status,
                TraceEventKind::EventsDropped {
                    count: inner.pending_dropped,
                },
                false,
            ));
            inner.next_sequence = inner.next_sequence.saturating_add(1);
            inner.pending_dropped = 0;
        }
        records.push(self.subscriber.record(
            inner.next_sequence,
            self.operation_id,
            OperationClass::Status,
            TraceEventKind::Finished { outcome },
            true,
        ));
        inner.next_sequence = inner.next_sequence.saturating_add(1);
        records
    }
}

fn monotonic_ms() -> u64 {
    static START: std::sync::OnceLock<Instant> = std::sync::OnceLock::new();
    u64::try_from(START.get_or_init(Instant::now).elapsed().as_millis()).unwrap_or(u64::MAX)
}

fn utc_unix_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .ok()
        .and_then(|duration| u64::try_from(duration.as_millis()).ok())
        .unwrap_or(0)
}

fn record_locked(
    inner: &mut Inner,
    now_ms: u64,
    operation_id: OperationId,
    operation: OperationClass,
    kind: ShareSafeEventKind,
) {
    prune_expired(&mut inner.events, now_ms);
    while inner.events.len() >= MAX_SHARE_SAFE_EVENTS {
        inner.events.pop_front();
    }
    let sequence = inner.next_sequence;
    inner.next_sequence = inner.next_sequence.saturating_add(1);
    inner.events.push_back(TimedShareSafeEvent {
        recorded_ms: now_ms,
        sequence,
        operation_id,
        operation,
        kind,
    });
}

#[derive(Clone)]
pub(crate) struct OperationScope {
    state: DiagnosticState,
    operation_id: OperationId,
    operation: OperationClass,
    finished: Arc<AtomicBool>,
}

impl OperationScope {
    #[cfg(test)]
    pub(crate) const fn operation_id(&self) -> OperationId {
        self.operation_id
    }

    #[cfg(test)]
    pub(crate) const fn operation_class(&self) -> OperationClass {
        self.operation
    }

    pub(crate) fn emit(&self, kind: ShareSafeEventKind) {
        if self.state.record_if_unfinished(
            self.operation_id,
            self.operation,
            kind.clone(),
            &self.finished,
        ) {
            self.state.emit_trace(
                self.operation_id,
                self.operation,
                TraceEventKind::Shared { transition: kind },
            );
        }
    }

    pub(crate) fn finish(&self, outcome: CategoricalOutcome) {
        if self.finished.swap(true, Ordering::AcqRel) {
            return;
        }
        let kind = ShareSafeEventKind::OperationFinished { outcome };
        self.state
            .record(self.operation_id, self.operation, kind.clone());
        self.state.emit_trace(
            self.operation_id,
            self.operation,
            TraceEventKind::Shared { transition: kind },
        );
    }

    pub(crate) fn snapshot(&self, since: Duration) -> SupportSnapshot {
        self.state.snapshot(since)
    }
}

impl DiagnosticSink for OperationScope {
    fn emit_share_safe(&self, kind: ShareSafeEventKind) {
        self.emit(kind);
    }

    fn emit_trace(&self, kind: TraceEventKind) {
        if !self.finished.load(Ordering::Acquire) {
            self.state
                .emit_trace(self.operation_id, self.operation, kind);
        }
    }

    fn publish_support_context(
        &self,
        capture: CaptureStatus,
        cameras: Vec<SanitizedCameraContext>,
    ) {
        if !self.finished.load(Ordering::Acquire) {
            self.state.publish_support_context(capture, cameras);
        }
    }
}

fn prune_expired(events: &mut VecDeque<TimedShareSafeEvent>, now_ms: u64) {
    let cutoff = now_ms.saturating_sub(MAX_HISTORY_MS);
    while events
        .front()
        .is_some_and(|event| event.recorded_ms < cutoff)
    {
        events.pop_front();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use irlume_common::diagnostics::{
        CameraRoleLabel, CaptureSchedule, CaptureScheduleSource, CategoricalOutcome, DigestToken,
        ExactFraction, ExactStreamContract, FourCc, QualificationState, SafeLabel,
        ShareSafeEventKind,
    };
    use std::sync::atomic::{AtomicU64, Ordering};

    #[derive(Default)]
    struct FakeClock(AtomicU64);

    impl Clock for FakeClock {
        fn now_ms(&self) -> u64 {
            self.0.load(Ordering::Relaxed)
        }
    }

    impl FakeClock {
        fn advance(&self, duration: std::time::Duration) {
            self.0.fetch_add(
                u64::try_from(duration.as_millis()).unwrap(),
                Ordering::Relaxed,
            );
        }
    }

    fn selected() -> ShareSafeEventKind {
        ShareSafeEventKind::CaptureScheduleSelected {
            schedule: CaptureSchedule::Sequential,
            source: CaptureScheduleSource::SequentialDefault,
        }
    }

    fn camera() -> SanitizedCameraContext {
        let stream = ExactStreamContract {
            width: 640,
            height: 480,
            fourcc: FourCc::new(*b"YUYV").unwrap(),
            interval: ExactFraction::new(1, 30).unwrap(),
        };
        SanitizedCameraContext {
            vid: 0x046d,
            pid: 0x085e,
            role: CameraRoleLabel::Rgb,
            interface_number: 0,
            driver: SafeLabel::new("uvcvideo").unwrap(),
            backend: SafeLabel::new("uvc-v4l2").unwrap(),
            speed_millimbps: 5_000_000,
            controller: SafeLabel::new("0000:0d:00.3").unwrap(),
            usb_bus: 4,
            usb_port_chain: vec![2],
            lifecycle_generation: 3,
            serial_present: true,
            descriptor_token: DigestToken::from_bytes([1; 8]),
            qualification_token: Some(DigestToken::from_bytes([2; 8])),
            requested: stream.clone(),
            accepted: stream,
        }
    }

    #[test]
    fn latest_support_context_is_retained_without_reopening_a_camera() {
        let state = DiagnosticState::default();
        let operation = state.begin(OperationClass::SupportProbe);
        let capture = CaptureStatus {
            schedule: CaptureSchedule::Sequential,
            source: CaptureScheduleSource::StoredQualification,
            runtime_context: Some(DigestToken::from_bytes([3; 8])),
            qualification_state: QualificationState::MeasuredSequential,
            qualification_reason: None,
            qualification_context: Some(DigestToken::from_bytes([2; 8])),
            runtime_degradation: None,
            authoritative_rate_shortfalls: None,
            latest_attempt_rate_shortfalls: None,
        };

        operation.publish_support_context(capture.clone(), vec![camera()]);
        let snapshot = operation.snapshot(Duration::from_secs(60));

        assert_eq!(snapshot.capture(), Some(&capture));
        assert_eq!(snapshot.cameras(), &[camera()]);
    }

    #[test]
    fn latest_inference_resolution_is_retained_in_support_snapshots() {
        let state = DiagnosticState::default();
        let report = irlume_common::InferenceResolutionReport::new(
            irlume_common::ExecutionDevicePolicy::Auto,
            irlume_common::ExecutionDevicePolicySource::Environment,
            irlume_common::ResolvedExecutionDevice::Npu,
            irlume_common::InferenceBackend::OpenVino,
        );

        state.publish_inference_report(report.clone());

        assert_eq!(
            state.snapshot(Duration::from_secs(60)).inference,
            Some(report)
        );
    }

    #[test]
    fn history_keeps_at_most_256_events_and_30_minutes() {
        let clock = std::sync::Arc::new(FakeClock::default());
        let state = DiagnosticState::with_clock(clock.clone());
        for _ in 0..300 {
            let operation = state.begin(OperationClass::Authentication);
            operation.emit(selected());
        }
        assert_eq!(
            state
                .snapshot(std::time::Duration::from_secs(1_800))
                .events()
                .len(),
            256
        );
        clock.advance(std::time::Duration::from_secs(1_801));
        assert!(state
            .snapshot(std::time::Duration::from_secs(1_800))
            .events()
            .is_empty());
    }

    #[test]
    fn daemon_generates_one_opaque_id_for_all_events_in_a_request() {
        let state = DiagnosticState::default();
        let operation = state.begin(OperationClass::Authentication);
        operation.emit(selected());
        operation.finish(CategoricalOutcome::Denied);
        let events = state
            .snapshot(std::time::Duration::from_secs(60))
            .events()
            .to_vec();
        assert_eq!(events.len(), 2);
        assert_eq!(events[0].operation_id, events[1].operation_id);
        assert_ne!(events[0].operation_id.as_bytes(), &[0; 16]);
    }

    #[test]
    fn finishing_cloned_scopes_records_exactly_one_terminal_event() {
        let state = DiagnosticState::default();
        let operation = state.begin(OperationClass::Enrollment);
        operation.clone().finish(CategoricalOutcome::Completed);
        operation.finish(CategoricalOutcome::Failed);
        operation.emit(selected());
        let events = state
            .snapshot(std::time::Duration::from_secs(60))
            .events()
            .to_vec();
        assert_eq!(events.len(), 1);
        assert!(matches!(
            events[0].kind,
            ShareSafeEventKind::OperationFinished {
                outcome: CategoricalOutcome::Completed
            }
        ));
    }

    #[test]
    fn trace_subscription_is_root_only_and_single_owner() {
        let state = DiagnosticState::default();
        assert!(matches!(
            state.subscribe_trace(1_000, 60_000),
            Err(TraceSubscribeError::NotRoot)
        ));
        let subscription = state.subscribe_trace(0, 60_000).unwrap();
        assert!(matches!(
            state.subscribe_trace(0, 60_000),
            Err(TraceSubscribeError::Busy)
        ));
        drop(subscription);
        assert!(state.subscribe_trace(0, 60_000).is_ok());
    }

    #[test]
    fn slow_trace_reader_never_blocks_producers_and_gets_an_explicit_drop_marker() {
        let state = DiagnosticState::default();
        let subscription = state.subscribe_trace_with_capacity(0, 60_000, 2).unwrap();
        let operation = state.begin(OperationClass::Authentication);
        let started = std::time::Instant::now();
        for _ in 0..10_000 {
            operation.emit(selected());
        }
        assert!(started.elapsed() < Duration::from_secs(2));

        let mut records: Vec<_> = subscription.receiver.try_iter().collect();
        operation.emit(selected());
        records.extend(subscription.receiver.try_iter());
        records.extend(subscription.finish(CategoricalOutcome::Completed));

        assert!(records.iter().any(
            |record| matches!(record.event, TraceEventKind::EventsDropped { count } if count > 0)
        ));
        assert!(records
            .iter()
            .enumerate()
            .all(|(index, record)| record.sequence == index as u64));
        assert!(matches!(
            records.last(),
            Some(TraceRecord {
                event: TraceEventKind::Finished { .. },
                terminal: true,
                ..
            })
        ));
    }

    #[test]
    fn trace_projects_share_safe_events_with_the_originating_operation_id() {
        let state = DiagnosticState::default();
        let subscription = state.subscribe_trace(0, 60_000).unwrap();
        let operation = state.begin(OperationClass::Enrollment);
        operation.emit(selected());
        operation.finish(CategoricalOutcome::Completed);
        let records: Vec<_> = subscription.receiver.try_iter().collect();
        assert_eq!(records.len(), 3);
        assert!(matches!(records[1].event, TraceEventKind::Shared { .. }));
        assert_eq!(records[1].operation_id, operation.operation_id);
        assert_eq!(records[1].operation, OperationClass::Enrollment);
        assert!(matches!(
            records[2].event,
            TraceEventKind::Shared {
                transition: ShareSafeEventKind::OperationFinished {
                    outcome: CategoricalOutcome::Completed
                }
            }
        ));
        assert_eq!(records[2].operation_id, operation.operation_id);
    }
}

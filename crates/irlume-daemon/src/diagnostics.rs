// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright the irlume contributors.

//! Process-local ownership for bounded, share-safe diagnostic history.

use irlume_common::diagnostics::{
    CategoricalOutcome, DiagnosticSink, OperationClass, OperationId, ShareSafeEvent,
    ShareSafeEventKind, SupportSnapshot, MAX_HISTORY_MS, MAX_SHARE_SAFE_EVENTS,
};
use sha2::{Digest as _, Sha256};
use std::collections::VecDeque;
use std::io::Read as _;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
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
}

#[derive(Default)]
struct Inner {
    events: VecDeque<TimedShareSafeEvent>,
    next_sequence: u64,
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
        drop(inner);
        SupportSnapshot::bounded(now_ms, MAX_HISTORY_MS, None, Vec::new(), events, Vec::new())
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
    ) {
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
            return;
        }
        record_locked(&mut inner, now_ms, operation_id, operation, kind);
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
    pub(crate) fn emit(&self, kind: ShareSafeEventKind) {
        self.state
            .record_if_unfinished(self.operation_id, self.operation, kind, &self.finished);
    }

    pub(crate) fn finish(&self, outcome: CategoricalOutcome) {
        if self.finished.swap(true, Ordering::AcqRel) {
            return;
        }
        self.state.record(
            self.operation_id,
            self.operation,
            ShareSafeEventKind::OperationFinished { outcome },
        );
    }
}

impl DiagnosticSink for OperationScope {
    fn emit_share_safe(&self, kind: ShareSafeEventKind) {
        self.emit(kind);
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
        CaptureSchedule, CaptureScheduleSource, CategoricalOutcome, ShareSafeEventKind,
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
}

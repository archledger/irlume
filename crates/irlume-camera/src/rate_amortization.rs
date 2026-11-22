// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright the irlume contributors.

//! Bounded cross-session reuse of completed delivered-rate evidence
//! (ADR-0021). A sequential pair re-pays open, flush and a 30-delta
//! observation window per stream per attempt; when the same node and role
//! completed a full window recently in this process and nothing invalidating
//! happened since, a 5-delta continuity probe through the same exact
//! `meets_floor` arithmetic may admit the session instead. The per-frame
//! sliding judgment keeps running for the whole burst either way. Every
//! fill records which of the two happened and why ([`rate_evidence`]).

use crate::contracts::StreamRole;
use std::collections::HashMap;
use std::sync::{Mutex, OnceLock};
use std::time::{Duration, Instant};

/// Positive deltas in the continuity probe. Five deltas at the 15 fps floor
/// is ~0.33 s. Judged only as confirmation of a prior full window, never as
/// sole evidence (ADR-0021; the slice-8 measurement invalidated that).
pub(crate) const CONTINUITY_PROBE_DELTAS: usize = 5;

/// The escalated probe width. A first-stage miss collects up to this many
/// deltas before the cached evidence is invalidated: live-measured startup
/// shapes that a 5-delta point sample cannot carry are (a) one ~616 ms
/// queue-refill stall inside the first concurrent-window frames (the RGB
/// side of the N930W pair) and (b) a ~1.2% early-delivery slope that settles
/// within a handful of frames (its IR side). A 15-delta window meets the
/// same exact floor arithmetic over both measured shapes, while a genuinely
/// slow stream still escalates to miss, invalidate, and re-establish from
/// scratch - the probe never passes anything the full fill would not.
pub(crate) const CONTINUITY_PROBE_ESCALATED_DELTAS: usize = 15;

/// How long a completed full window stays reusable. ADR-0021's bound,
/// raised from 5 minutes to 24 hours by its 2026-09-22 amendment: the
/// evidence that admits a session is the probe on THIS session (5 deltas,
/// escalating to 15) plus the per-frame judgment, so the bound only says
/// how long ago the stream's full shape was last seen. Five minutes made
/// almost every real unlock (after more than five minutes away) re-pay the
/// full 30-delta fill, measured at +1.5 s on a NexiGo N930W pair.
pub(crate) const MAX_STALENESS: Duration = Duration::from_secs(24 * 60 * 60);

/// Rollback valve, house style: `IRLUME_RATE_AMORTIZATION=0` disables reuse.
fn enabled() -> bool {
    // Deliberately not cached: this is read once per capture session start,
    // and caching would freeze a debug toggle for the process lifetime.
    !matches!(std::env::var("IRLUME_RATE_AMORTIZATION"), Ok(v) if v == "0")
}

/// Identity of one physical capture stream role on one node, within this
/// process. The node path plus role is sufficient here because camera
/// identity is re-pinned by `verify_pinned` at every open; a swapped device
/// on the same node fails the open before any cache question arises.
#[derive(Clone, Debug, Hash, PartialEq, Eq)]
pub(crate) struct Key {
    node: String,
    role: StreamRole,
}

impl Key {
    pub(crate) fn new(node: &str, role: StreamRole) -> Self {
        Self {
            node: node.to_owned(),
            role,
        }
    }
}

fn cache() -> &'static Mutex<HashMap<Key, Instant>> {
    static CACHE: OnceLock<Mutex<HashMap<Key, Instant>>> = OnceLock::new();
    CACHE.get_or_init(|| Mutex::new(HashMap::new()))
}

/// Whether a session for this key may try the continuity probe, and when
/// not, why. [`amortizable`] asks whether it is `Recent`.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum Reuse {
    /// Reuse is switched off by `IRLUME_RATE_AMORTIZATION=0`.
    Disabled,
    /// No completion is recorded for this key: the first session for this
    /// node and role in the process, a changed node, or an earlier
    /// invalidating event removed it.
    Unrecorded,
    /// A completion is recorded but older than [`MAX_STALENESS`].
    Stale,
    /// A completion within the staleness bound.
    Recent,
}

impl Reuse {
    /// Why a session for `key` may or may not try the continuity probe. A
    /// session created without an amortization key has nothing recorded.
    pub(crate) fn for_key(key: Option<&Key>) -> Self {
        let Some(key) = key else {
            return Self::Unrecorded;
        };
        if !enabled() {
            return Self::Disabled;
        }
        match cache()
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .get(key)
            .copied()
        {
            Some(completed_at) if completed_at.elapsed() <= MAX_STALENESS => Self::Recent,
            Some(_) => Self::Stale,
            None => Self::Unrecorded,
        }
    }
}

/// Whether a session for this key may admit on a continuity probe: enabled,
/// and a full window completed within the staleness bound.
pub(crate) fn amortizable(key: &Key) -> bool {
    Reuse::for_key(Some(key)) == Reuse::Recent
}

/// Record that a full 30-delta window completed for this key now.
pub(crate) fn record_completion(key: Key) {
    cache()
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .insert(key, Instant::now());
}

/// Remove any cached evidence for this key. Called on every invalidating
/// event: stream recovery, dequeue I/O errors, and a failed probe.
pub(crate) fn invalidate(key: &Key) {
    cache()
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .remove(key);
}

/// The decision under which a session paid its full window, given what its
/// probe could have reused and whether a probe missed first.
pub(crate) fn full_window_decision(
    reuse: Reuse,
    probe_missed: bool,
) -> irlume_common::diagnostics::RateEvidenceDecision {
    use irlume_common::diagnostics::RateEvidenceDecision as Decision;
    if probe_missed {
        return Decision::ProbeMissed;
    }
    match reuse {
        Reuse::Disabled => Decision::DisabledFullWindow,
        Reuse::Stale => Decision::StaleFullWindow,
        // A recent completion without an admission: the paired fill skipped
        // the probe for a stream that parked a startup buffer (which revoked
        // the entry as well), or the entry lapsed between a fill's two
        // checks. Either way a full window established the session.
        Reuse::Unrecorded | Reuse::Recent => Decision::FullWindow,
    }
}

/// The schema 6 trace record for one stream's established rate window.
pub(crate) fn rate_evidence(
    role: StreamRole,
    decision: irlume_common::diagnostics::RateEvidenceDecision,
    deltas: usize,
    probe_deltas: Option<usize>,
    offset: Duration,
    elapsed: Duration,
) -> irlume_common::diagnostics::TraceEventKind {
    let micros = |duration: Duration| u64::try_from(duration.as_micros()).unwrap_or(u64::MAX);
    irlume_common::diagnostics::TraceEventKind::RateEvidence {
        role: match role {
            StreamRole::Rgb => irlume_common::diagnostics::CameraRoleLabel::Rgb,
            StreamRole::Ir => irlume_common::diagnostics::CameraRoleLabel::Ir,
        },
        decision,
        deltas: u32::try_from(deltas).unwrap_or(u32::MAX),
        probe_deltas: probe_deltas.map(|deltas| u32::try_from(deltas).unwrap_or(u32::MAX)),
        offset_us: micros(offset),
        elapsed_us: micros(elapsed),
    }
}

#[cfg(test)]
pub(crate) mod test_support {
    use super::*;

    /// Install an entry with an arbitrary completion instant, or remove it.
    pub(crate) fn force_completion(key: Key, completed_at: Option<Instant>) {
        let mut guard = cache().lock().unwrap_or_else(|e| e.into_inner());
        match completed_at {
            Some(at) => {
                guard.insert(key, at);
            }
            None => {
                guard.remove(&key);
            }
        }
    }

    /// The stored completion instant for a key, so a test can show an entry
    /// was (not) renewed by an exact instant comparison instead of sleeping
    /// out the staleness bound.
    pub(crate) fn completion_instant(key: &Key) -> Option<Instant> {
        cache()
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .get(key)
            .copied()
    }
}

#[cfg(test)]
mod tests {
    use super::test_support::force_completion;
    use super::*;
    // The kill switch reads the process environment, so every test that
    // touches `IRLUME_RATE_AMORTIZATION` (here and the stream-level tests in
    // `lib.rs`) serializes on the ONE crate-wide lock; a module-local mutex
    // would leave them racing each other across modules.
    use crate::testenv::{env_lock, EnvGuard};

    fn key() -> Key {
        Key::new("/dev/video-probe", StreamRole::Rgb)
    }

    #[test]
    fn a_recent_completion_is_amortizable_and_invalidation_removes_it() {
        let _g = env_lock();
        let _env = EnvGuard::unset("IRLUME_RATE_AMORTIZATION");
        force_completion(key(), Some(Instant::now()));
        assert!(amortizable(&key()));
        invalidate(&key());
        assert!(!amortizable(&key()));
    }

    #[test]
    fn a_stale_completion_is_not_amortizable() {
        let _g = env_lock();
        let _env = EnvGuard::unset("IRLUME_RATE_AMORTIZATION");
        force_completion(
            key(),
            Some(Instant::now() - MAX_STALENESS - Duration::from_secs(1)),
        );
        assert!(!amortizable(&key()));
        force_completion(key(), None);
    }

    /// The bound covers a working day of unlocks: a window completed hours
    /// ago still admits the probe, which is the evidence that matters
    /// (ADR-0021 amendment of 2026-09-22).
    #[test]
    fn a_completion_from_earlier_the_same_day_is_still_amortizable() {
        let _g = env_lock();
        let _env = EnvGuard::unset("IRLUME_RATE_AMORTIZATION");
        force_completion(
            key(),
            Some(Instant::now() - Duration::from_secs(8 * 60 * 60)),
        );
        assert!(amortizable(&key()));
        force_completion(key(), None);
    }

    #[test]
    fn the_kill_switch_disables_reuse_even_with_a_fresh_completion() {
        let _g = env_lock();
        force_completion(key(), Some(Instant::now()));
        {
            let _off = EnvGuard::set("IRLUME_RATE_AMORTIZATION", "0");
            assert!(!amortizable(&key()));
        }
        let _on = EnvGuard::unset("IRLUME_RATE_AMORTIZATION");
        assert!(amortizable(&key()));
        force_completion(key(), None);
    }
}

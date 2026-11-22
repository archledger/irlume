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

/// The stream identity the completion record is keyed by (ADR-0021 amendment
/// 2026-11-22): a digest of the USB endpoint facts collected from the open
/// descriptor (vendor and product id, serial where present, interface number,
/// bus and port, the configuration-bound descriptor digest, controller and
/// link speed), of the negotiated stream contract and of the rate policy the
/// window is judged by (role floor, tolerance, window width, startup flush).
/// A renumbered video node keeps its identity; another port, link speed,
/// descriptor, stream or policy is another. Only the digest is kept on disk,
/// never the serial: a unit without a serial is known by its port, just as
/// the emitter journal and the qualifications know it.
#[derive(Clone, Copy, Debug, Hash, PartialEq, Eq)]
pub(crate) struct Identity([u8; 32]);

impl Identity {
    /// Compute the identity for one fd-collected endpoint and its negotiated
    /// stream contract. `None` when either cannot be serialized, which cannot
    /// happen for a validated endpoint or contract.
    pub(crate) fn for_stream(
        endpoint: &crate::capture_qualification::CameraEndpoint,
        stream: &crate::capture_qualification::StreamContract,
    ) -> Option<Self> {
        let mut material = b"rate-evidence-identity-v1\n".to_vec();
        // Serialize, not display: both types expose every collected field to
        // `serde` in declaration order, so the digest is stable across calls.
        material.extend_from_slice(&serde_json::to_vec(endpoint).ok()?);
        material.extend_from_slice(&serde_json::to_vec(stream).ok()?);
        let (floor_num, floor_den) = stream.minimum_rate().parts();
        let flush = if (floor_num, floor_den)
            == (
                crate::rate_gate::IR_FLOOR_NUM,
                crate::rate_gate::IR_FLOOR_DEN,
            ) {
            crate::rate_gate::startup_flush(StreamRole::Ir)
        } else {
            crate::rate_gate::startup_flush(StreamRole::Rgb)
        };
        let policy = format!(
            "floor:{floor_num}/{floor_den}|tolerance:{}|window:{}|flush:{flush}",
            crate::rate_gate::DEFAULT_TOLERANCE_PERCENT,
            crate::rate_gate::RATE_WINDOW_CAPACITY,
        );
        material.extend_from_slice(policy.as_bytes());
        let digest = irlume_common::sha256_hex(&material);
        Self::from_hex(&digest)
    }

    /// Parse a 64-character lowercase hex digest, and nothing else. A wrong
    /// length, uppercase or a non-hex character is no identity.
    pub(crate) fn from_hex(text: &str) -> Option<Self> {
        if text.len() != 64 {
            return None;
        }
        let mut digest = [0_u8; 32];
        for (index, slot) in digest.iter_mut().enumerate() {
            let byte = text.as_bytes().get(index * 2..index * 2 + 2)?;
            if !byte
                .iter()
                .all(|c| c.is_ascii_hexdigit() && !c.is_ascii_uppercase())
            {
                return None;
            }
            let text = std::str::from_utf8(byte).ok()?;
            *slot = u8::from_str_radix(text, 16).ok()?;
        }
        Some(Self(digest))
    }

    /// The digest as 64 lowercase hex characters, which is also the record's
    /// filename.
    pub(crate) fn hex(&self) -> String {
        self.0.iter().map(|byte| format!("{byte:02x}")).collect()
    }
}

/// Identity of one physical capture stream role on one node, within this
/// process. The node path plus role is sufficient here because camera
/// identity is re-pinned by `verify_pinned` at every open; a swapped device
/// on the same node fails the open before any cache question arises.
#[derive(Clone, Debug, Hash, PartialEq, Eq)]
pub(crate) struct Key {
    node: String,
    role: StreamRole,
    identity: Option<Identity>,
}

impl Key {
    pub(crate) fn new(node: &str, role: StreamRole) -> Self {
        Self {
            node: node.to_owned(),
            role,
            identity: None,
        }
    }

    /// Attach the persistent USB identity the completion record lives under.
    /// `None` means stream-level evidence only: nothing is read from or
    /// written to disk for this key (diagnostic readers keep process-local
    /// evidence).
    pub(crate) fn with_identity(mut self, identity: Option<Identity>) -> Self {
        self.identity = identity;
        self
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
    // `IRLUME_RATE_AMORTIZATION=0`: restores nothing, records nothing,
    // removes nothing (ADR-0021 amendment 2026-11-22, item 4).
    if !enabled() {
        return;
    }
    cache()
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .insert(key.clone(), Instant::now());
    // An entry this process observed is by definition not a restore. The
    // completion is kept under the stream's USB identity as well: small,
    // root-only records that hold no secret and no serial.
    restored_flags()
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .remove(&key);
    if let Some(identity) = key.identity {
        let _ = crate::rate_evidence_store::Store::system()
            .record(&identity, std::time::SystemTime::now());
    }
}

/// Remove any cached evidence for this key. Called on every invalidating
/// event: stream recovery, dequeue I/O errors, and a failed probe. The
/// on-disk record goes with it, which is the conservative direction: an
/// invalidated stream re-proves itself with a full window. With
/// `IRLUME_RATE_AMORTIZATION=0` this removes nothing at all.
pub(crate) fn invalidate(key: &Key) {
    if !enabled() {
        return;
    }
    cache()
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .remove(key);
    restored_flags()
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .remove(key);
    if let Some(identity) = key.identity {
        let _ = crate::rate_evidence_store::Store::system().remove(&identity);
    }
}

/// Consult the on-disk completion at session start, exactly as the in-memory
/// cache is consulted after it (ADR-0021 amendment 2026-11-22, item 3). Only
/// an empty cache slot is filled: a completion this process already observed
/// is observed state, and another writer cannot replace it.
pub(crate) fn restore(key: &Key) {
    if !enabled() {
        return;
    }
    if cache()
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .contains_key(key)
    {
        return;
    }
    let Some(identity) = key.identity else {
        return;
    };
    if let Some(age) =
        crate::rate_evidence_store::Store::system().load(&identity, std::time::SystemTime::now())
    {
        // The staleness bound stays at 24 hours and now spans restarts. On a
        // freshly booted host the monotonic clock may be younger than the
        // record; clamp it, never reject a completion that is still inside
        // the bound.
        let completed = std::time::Instant::now()
            .checked_sub(age)
            .unwrap_or_else(std::time::Instant::now);
        cache()
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .insert(key.clone(), completed);
        restored_flags()
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .insert(key.clone());
    }
}

/// Whether this key's in-memory completion was restored from the record
/// rather than observed by this process. The trace's `persisted` field reads
/// exactly this, so a probe admission says the completion predates the
/// daemon start rather than being misreported as fresh work.
pub(crate) fn restored(key: &Key) -> bool {
    restored_flags()
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .contains(key)
}

fn restored_flags() -> &'static Mutex<std::collections::HashSet<Key>> {
    static FLAGS: OnceLock<Mutex<std::collections::HashSet<Key>>> = OnceLock::new();
    FLAGS.get_or_init(|| Mutex::new(std::collections::HashSet::new()))
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

/// The window that established a session, as its trace record names it.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct Window {
    /// Deltas the window held.
    pub(crate) deltas: usize,
    /// Ordinal, from zero, of its seed frame among the frames the session
    /// dequeued.
    pub(crate) seed_frame: u64,
    /// Ordinal of its last frame.
    pub(crate) end_frame: u64,
    /// Microseconds its deltas sum to.
    pub(crate) span_us: u64,
}

/// The schema 6 trace record for one stream's established rate window.
/// `persisted` says the decision rested on a completion from an earlier
/// daemon run, not on work this process measured.
pub(crate) fn rate_evidence(
    role: StreamRole,
    decision: irlume_common::diagnostics::RateEvidenceDecision,
    window: Window,
    probe_deltas: Option<usize>,
    persisted: bool,
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
        deltas: u32::try_from(window.deltas).unwrap_or(u32::MAX),
        probe_deltas: probe_deltas.map(|deltas| u32::try_from(deltas).unwrap_or(u32::MAX)),
        seed_frame: window.seed_frame,
        end_frame: window.end_frame,
        span_us: window.span_us,
        persisted,
        offset_us: micros(offset),
        elapsed_us: micros(elapsed),
    }
}

#[cfg(test)]
pub(crate) mod test_support {
    pub(crate) use super::restored;
    use super::*;

    /// Forget everything held in memory, without touching the record on disk.
    /// Tests that model a daemon restart call this between two sessions.
    pub(crate) fn restart() {
        cache().lock().unwrap_or_else(|e| e.into_inner()).clear();
        restored_flags()
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .clear();
    }

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

# ADR-0014: Schedule-aware cross-spectrum pairing budget

**Status:** Accepted
**Date:** 2026-08-22
**Implementation:** With this PR. `MAX_CROSS_SPECTRUM_SKEW` (3 s) continues to
govern pairs captured under the CONCURRENT schedule; pairs captured as
sequential one-shots (the qualified sequential schedule, or a concurrent
attempt that degraded to the sequential retry) are governed by
`SEQUENTIAL_MAX_CROSS_SPECTRUM_SKEW` (8 s).

## Context

The cross-spectrum cues (same face co-located in RGB and IR, RGB pose judged
against the IR face, and — since ADR-0013 — the ViT RGB PAD and FLIR IR PAD
wired into the cross-spectrum path) treat the RGB and IR frames of one
decision as a single scene. `MAX_CROSS_SPECTRUM_SKEW` (3 s) bounds how far
apart the two capture windows may be. Its rationale was written when the
capture path had no rate-evidence machinery between the bursts: concurrent
captures overlap (gap zero) and sequential bursts ran back to back.

Two things changed:

1. The delivered-rate gate (slices 6-8) made each one-shot capture pay
   open/negotiate + startup flush + a 30-delta measurement window before its
   burst. In a sequential schedule that machinery sits BETWEEN the two
   bursts: the measured inter-window gap is 3050 ms on the ASUS (post
   role-aware flush, PR #518) — over the 3 s ceiling on every attempt, by
   construction, on hardware that passes every one of its gates.
2. ADR-0013 wired the ViT RGB PAD into the cross-spectrum path. Because
   paired RGB is skew-discarded on every sequential attempt, the ViT cue is
   structurally unreachable in production lit authentication on BOTH
   IR-capable fleet hosts (both qualified `sequential_required`). The
   flagship PAD shipped in #516 runs only on the RGB-only hosts.

## Decision

The pairing budget becomes schedule-aware:

- **Concurrent: 3 s, unchanged.** Concurrent captures overlap; a 3 s gap
  still means retry/self-heal stacking — the pathological case the constant
  was calibrated against (measured worst single capture: the NexiGo N930W at
  ~3.6 s for a full sequential pair).
- **Sequential: 8 s**, applied whenever the two frames were actually
  captured as sequential one-shots (the qualified sequential schedule, or a
  concurrent pair that degraded to its sequential retry — `pair_sequential_retried`).

The 8 s figure is derived, not chosen:

- The rate gate guarantees a delivered IR floor (14.55-15 fps across the
  fleet's IR nodes), so the normal machinery gap (open ~0.3 s + flush 10 +
  window 30 dequeues) is bounded by construction at ~3.1 s. Measured:
  3050 ms (ASUS, post-#518).
- A hard retry or self-heal recapture replaces ONE window and re-pays one
  open+fill (~3.1 s); both can occur in one decision, giving a worst
  stacking case of ~6.2 s.
- 8 s bounds that with margin while staying under the login grace window
  (15 s) — a decision this stale still completes inside the window the user
  already waits.

## Security posture

The load-bearing fact: **the alternative to accepting the pair is not a
stricter check — the IR-only path GRANTS.** When the pair is stale, the RGB
evidence is discarded and authentication proceeds through the independently
gated IR-only path, which has no RGB co-location, no RGB recognition, and no
ViT PAD at all. The 3 s-under-sequential behavior therefore REMOVED cues
from an already-granting decision on every authentication:

- Both paths (paired and IR-only) hinge on the same IR liveness and IR match
  evidence; stale RGB cannot manufacture a grant.
- Accepting the pair only ADDS deny-capable cues (RGB co-location, RGB
  recognition, ViT print-species PAD).
- The cost of accepting is the same false-denial risk the retry loop already
  carries: a genuine user who moves between the two captures. An 8 s bound
  keeps that within one login window.

This is a loosening in name only for the sequential schedule; for concurrent
captures nothing changes.

## What this does NOT change

- The IR-only dark path (no RGB at all) is unaffected.
- Enrollment and identify remain RGB-primary.
- A stale pair with no IR face is still `Uncertain`, never Spoof (stale
  frames say nothing about the person).
- Concurrent-mode hosts and the concurrent capture path keep the 3 s
  ceiling exactly as before.

## Consequences

- Sequential-schedule hosts regain paired RGB evidence and the ViT RGB PAD
  in production lit authentication; the pairing decision itself (not the
  machinery) again decides whether RGB participates.
- The grace-window retry bound (remaining-time vs last-attempt cost) becomes
  more important: an 8 s stale pair finishing inside a 5 s sudo window is
  still possible mid-capture, and the retry-bound fix addresses that
  separately.
- If a future capture-path change shrinks the machinery gap (pre-arm,
  persistent sessions), this budget can be re-derived from the new measured
  gap; the derivation formula is recorded on
  `SEQUENTIAL_MAX_CROSS_SPECTRUM_SKEW`.
- Windows Hello, for comparison, never captures RGB during authentication
  at all (Microsoft Learn, face-authentication camera bring-up); irlume's
  joint-PAD architecture is a deliberate superset, and this ADR is what
  makes it reachable on sequential hardware.

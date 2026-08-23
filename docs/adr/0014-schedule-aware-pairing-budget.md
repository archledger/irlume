# ADR-0014: Schedule-aware cross-spectrum pairing budget

**Status:** Accepted
**Date:** 2026-08-22
**Implementation:** With this PR. `MAX_CROSS_SPECTRUM_SKEW` (3 s) continues to
govern pairs captured under the CONCURRENT schedule; pairs captured as
sequential one-shots (the qualified sequential schedule, or a concurrent
attempt that degraded to the sequential retry) are governed by
`SEQUENTIAL_MAX_CROSS_SPECTRUM_SKEW` (8 s). Pairs admitted only under the
sequential budget DEFER the lit path's RGB-primary grant to the
IR-identity-verified arms (see Security posture).

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

- The rate gate enforces a delivered IR floor of 14.55 fps (fleet IR nodes
  deliver 14.73-15), so the normal machinery gap (open ~0.3 s + flush 10 +
  window 30 dequeues) is bounded by construction at ~3.1 s. Measured:
  3050 ms (ASUS, post-#518).
- A hard retry or self-heal recapture replaces ONE window and re-pays one
  open+fill (~3.1 s); both can occur in one decision, giving a worst
  stacking case of ~6.2 s.
- 8 s bounds that with margin while staying under the login grace window
  (15 s) — a decision this stale still completes inside the window the user
  already waits. Since the RGB-primary deferral above no longer rides on
  the budget, this margin is a pairing-evidence bound, not a grant bound.

## Security posture

The load-bearing fact: **the alternative to accepting the pair is not a
stricter check — the IR-only path GRANTS.** When the pair is stale, the RGB
evidence is discarded and authentication proceeds through the independently
gated IR-only path, which has no RGB co-location, no RGB recognition, and no
ViT PAD at all. The 3 s-under-sequential behavior therefore REMOVED cues
from an already-granting decision on every authentication.

But accepting the pair also OPENS an arm the stale-discard behavior had
structurally closed on sequential-schedule hosts: the lit path's RGB-primary
grant, which decides on RGB recognition + cross-spectrum liveness ALONE —
IR contributes presence and liveness there (co-location, FLIR IR PAD, the
per-user IR center/edge floor), NOT an IR identity match. On a sequential
schedule the two bursts are separated by the capture machinery gap
(~3.05 s measured), which is a physical swap window: an attacker can hold
the enrolled user's image in front of the RGB burst, then present their OWN
live face for the IR burst. Every IR-side gate passes for the attacker's
live face; the remaining control would be the ViT RGB PAD, whose measured
species coverage is print/banner (100% catch, ADR-0013 fleet validation)
while the phone/screen species is explicitly NOT covered by any
single-frame RGB cue on this camera class
(docs/research/2026-08-22-screen-attack-pad-survey.md) — that species is IR
identity's job. Letting a >3 s pair carry the RGB-primary grant would trade
"must defeat IR identity" for "must defeat one RGB PAD model" on exactly
the hosts that carry dual cameras.

### Decision

Pairs admitted only under the sequential budget (skew above
`MAX_CROSS_SPECTRUM_SKEW`, i.e. captured as separated one-shot bursts)
carry that fact on the `Assessment` (`sequential_pair`). The lit path then
DEFERS its RGB-primary grant: such pairs authenticate only through the arms
that also require an IR identity match — quality-weighted fusion, the IR
fallback (+`IR_FALLBACK_MARGIN`), or the calibrated centroid (ADR-0004).
Concurrent pairs (skew ≤ 3 s) interleave the two spectra and keep the
RGB-primary arm unchanged.

This preserves the pre-ADR-0014 posture on sequential-schedule hosts (the
stale discard forced the IR-only path, which requires IR identity) while
restoring paired evidence, the ViT print-species PAD, and identify on that
hardware. Genuine users keep the latency win: a genuine face passes
fusion/IR-fallback with its usual margin (live IR scores 0.78-0.82
fleet-measured against a ~0.63 fallback bar).

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
  machinery) again decides whether RGB participates. Grants on those pairs
  route through the IR-identity arms (Security posture above).
- The grace-window retry bound (remaining-time vs costliest-attempt) also
  gates the sequential fallback's FIRST attempt: after a held-pair failure
  the fallback is skipped when the costliest observed attempt cannot finish
  before the deadline, releasing the camera for the password fallback
  inside the window instead of overrunning the lease mid-capture.
- Evidence bound, recorded honestly: the concurrent-mode
  `drain_until_both_ready` flush reduction rests on single-stream startup
  probes; no fleet host currently qualified for concurrent dual capture
  exercises it. Its failure mode is fail-closed — a startup transient
  longer than the role's flush misses the floor and the capture degrades
  to the sequential schedule.
- If a future capture-path change shrinks the machinery gap (pre-arm,
  persistent sessions), this budget can be re-derived from the new measured
  gap; the derivation formula is recorded on
  `SEQUENTIAL_MAX_CROSS_SPECTRUM_SKEW`.
- Windows Hello, for comparison, never captures RGB during authentication
  at all (Microsoft Learn, face-authentication camera bring-up); irlume's
  joint-PAD architecture is a deliberate superset, and this ADR is what
  makes it reachable on sequential hardware.

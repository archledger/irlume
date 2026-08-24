# ADR-0017: No adaptive enrollment; templates change only by explicit re-enrollment

**Status:** Accepted
**Date:** 2026-08-24
**Implementation:** Current behavior; no code change required.

## Context

Howdy issue #342 ("[Feature Request] Continuous retraining", +5 reactions)
asks for the recognizer to update the enrolled model from successful
authentication frames, so glasses, beard growth, aging, and lighting drift
are absorbed without the user doing anything. Users of face-unlock tools
ask for this regularly, and at least one Howdy fork experimented with it.

The request is legitimate: enrollment is a chore, faces change, and a
stale template produces false rejections that push users back to
passwords. The question is whether silent template updates are
compatible with irlume's security posture (ADR-0001, ADR-0013,
ADR-0016), in which every grant rests on evidence that was measured
before the fact and on thresholds whose calibration assumptions are
recorded.

## Decision

Irlume does not adapt enrolled templates from authentication traffic.
A template changes in exactly one way: the user runs an explicit
enrollment (`irlume enroll`, or the TUI flow), which records new scans
under the same consent and validation rules as the first enrollment
(face present, quality-gated, PAD does not downgrade the capture, the
TPM-sealed storage transaction commits atomically). Aging and
appearance changes are handled by re-enrolling, which takes under a
minute and can add scans to an existing profile.

What ships instead of silent adaptation:

1. **Best-of-N scoring already absorbs ordinary variation.** Every
   authentication scores the live probe against all enrolled scans and
   takes the best cosine, so a profile holding scans from several
   sittings (glasses on, glasses off, summer, winter) matches any of
   them. The measured distributions behind the thresholds (CBSR, Tufts,
   and the live dark sessions) were all computed in this shape.
2. **Thresholds carry provenance.** The operating points (0.635-scaled
   dark bar, per-user IR center/edge floors, fusion ladders) were
   measured against fixed templates. Silently mutating the templates
   moves every one of those distributions without any measurement.
3. **Guided re-enroll is the supported path** for real appearance
   change, and the TUI offers it without deleting the old profile.

## Why silent adaptation is rejected on security grounds

An adaptive system updates the model from frames that were *accepted*.
That has a specific failure shape: whatever gets in, trains the model.
Concretely:

- **A borderline impostor hardens into a permanent grant.** A sibling,
  a printed photo that scraped past a PAD cue, or an averaging attack
  (presenting many near-miss probes) each leave template residue. With
  continuous retraining, a sequence of individually-rejected probes can
  still drag the template toward the attacker, because the update rule
  sees only "this frame was close enough to consider". This is the
  classic adaptive-biometric attack class (the template-update
  literature's poisoning and averaging attacks); every published
  defense adds gating that amounts to re-imposing the
  explicit-enrollment discipline we already have.
- **The audit trail breaks.** Enrollment is a consented, attributable
  event (who enrolled, when, how many scans, on which hardware).
  Background updates would scatter template provenance across the
  auth log with no consent record, which conflicts with the
  enrollment-transaction integrity the storage layer guarantees.
- **Measured constants stop meaning what they say.** Our thresholds are
  not tunables; each one cites the corpus and shape it was measured in
  (CHANGELOG, ADR-0016). Templates that drift invalidate the
  FAR/FRR claims retroactively and silently.

Howdy's tracker also shows the operational cost: retraining issues
appear as "it stopped recognizing me after X" with no way to reproduce
what the model became. Explicit enrollment keeps the system
debuggable: the template equals the scans, always.

## Consequences

- Users with large appearance changes re-enroll (under a minute,
  additive scans, no data loss).
- The reject-then-re-enroll path must stay cheap and obvious; the TUI
  already funnels a "not recognizing you" diagnosis toward enrollment.
- If demand for lower-friction updates grows, the acceptable loosening
  is an *explicitly confirmed* refresh (the user types `yes` to a
  "update your face model from this scan?" prompt inside `irlume tui`),
  which preserves consent and provenance. That is a future ADR, not a
  default.
- This position is user-facing copy: the FAQ answers "does it learn my
  face over time?" with "no, and here is why that is the safe choice".

## Sources

- Howdy #342 (continuous retraining request, +5).
- The adaptive-biometric attack class as summarized in the
  2026-08-24 competitor survey
  (docs/research/2026-08-24-face-unlock-competitor-pain-survey.md).
- irlume's own threshold provenance: CHANGELOG 0.11.0 (SecureDark
  stage 1/2 measured operating points), ADR-0013 (PAD default-on),
  ADR-0016 (dark-path bar and its live-session validation).

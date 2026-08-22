# ADR-0016: SecureDark — hardening the pure-dark IR authentication path

**Status:** Accepted
**Date:** 2026-08-22
**Implementation:** Stage 1 with this PR (scene gate + dark threshold). Later
stages are evidence-gated and listed under Open Measurements.

## Context

The pure-dark path (no RGB face, IR face present → IR-only liveness + IR
recognition) is the only authentication modality that works in darkness. Its
own threshold documentation said it plainly: **"DARK MODE IS CONVENIENCE-
GRADE."** Three specific gaps made that true:

1. **A presentation-controllable entry trigger.** The path activated on
   "RGB found no face" — a condition the PRESENTATION can create in a fully
   lit room (an artifact that reflects 850nm while absorbing visible light;
   a black visor over the presented material). That routes a lit-room attack
   onto the path with the least evidence: no RGB co-location, no RGB
   recognition, no RGB PAD.
2. **A threshold inversion.** The dim-light IR fallback — which at least
   VERIFIED an RGB face existed before the RGB match missed — demanded
   base 0.55 + 0.05 = 0.60, while the pure-dark path granted at 0.55 with
   strictly less evidence. Less evidence, looser bar.
3. **Convenience-grade statistics at a Secure-tier decision.** A pure-dark
   grant satisfies biopolicy's Secure tier (credential release: login,
   keyring unseal) on IR hardware. At 0.55, the repo's own CBSR benchmark
   puts the impostor bar at FAR 1.3e-3 — a ~1-in-750 bar guarding
   credential release.

What already exists and is kept unchanged: the per-user IR calibration
(ADR-0004: local, ridge-regularized, space-bound, no threshold relaxation),
the native IR physics gates, the per-user center/edge floor, FLIR PAD
(ADR-0003/0013, deny-only, consulted on the dark path), the camera binding
(anti-swap), emitter privacy-bounded control with journaling, lit-phase
selection, and blown-frame quality skips.

## Decision

### Stage 1 (this PR)

**Objective scene gate.** The dark path now requires the scene to actually
be dark: `rgb_frame_mean >= CONCLUSIVE_SCENE_BRIGHTNESS (100.0)` refuses the
IR-only path (Uncertain — retryable; a genuine user walking up gets found by
RGB, an artifact gets the password). The constant is the camera crate's
existing measured lit/dark boundary (pitch dark ≈17, dark room ≈62, lit arm
117-143; 100.0 anchored between) — no new number was invented. The RGB
capture attempt remains REQUIRED upstream (a hard RGB capture failure errors
the whole authentication to the password; the darkness measurement needs the
frame).

**Dark operating point 0.60.** `IR_DARK_MATCH_THRESHOLD = 0.60` for the
pure-dark best-of-N and calibrated-centroid arms: FAR 2.7e-4 / FRR 3.0% on
the CBSR NIR benchmark — a ~5x impostor-bar tightening over 0.55 for +1.3%
false rejects — and the end of the fallback inversion (both IR grant bars
now stand at 0.60). The user-supplied-adapter arm keeps its own validated
0.40 (already FAR ~1e-4 on its benchmark).

**What the threshold deliberately does NOT claim:** stopping the life-size
print species. ADR-0002 measured the enrolled user's vinyl banner at IR
cosine 0.650 — above 0.60 and above the 0.635 FAR≤1e-4 point. Prints are
FLIR PAD + IR physics + the per-user center/edge floor's job. The threshold
is the statistical bar against unseen impostors, and the scene gate is the
routing bar against lit-room IR-only attacks; the species defenses are the
PAD stack.

### Evidence-gated later stages (NOT shipped here)

- **0.635 (FAR ≤1e-4, FRR 4.6% CBSR):** blocked on the live dark-session
  genuine distribution — the threshold documentation's standing observation
  is that live genuine IR sits in the CBSR overlap zone, and no honest bar
  can be set above the live genuine floor without measuring it.
- **Multi-frame temporal consistency** (embed ≥2 lit burst frames, require
  agreement): the burst already exists; the agreement constant has no
  measured value in-repo and will not be invented. Measured in the same
  dark-session protocol.
- **Per-action-class thresholds** (Unseal-class surfaces stricter than
  Verify-class): plumbed after the live distribution is known.
- **IR quality-filter deepening** (sharpness/pose floors beyond the existing
  blown-skip and brightness gates): only if the dark-session FRR analysis
  shows rejections clustering on a filterable quality axis.

## Threat analysis

- **Lit-room NIR-only presentation:** closed by the scene gate (the artifact
  can no longer choose the IR-only path in a lit room). Residual: an
  attacker who can darken the victim's room physically — outside the
  attacker model for a presentation attack (and the same attack then faces
  the full dark stack: FLIR + physics + 0.60).
- **Life-size print (vinyl banner species):** unchanged posture — FLIR PAD
  (measured catching it at p_fake 0.99+), IR physics, per-user floor. The
  0.650 banner score clears 0.60; the threshold was never this species'
  defense.
- **Statistical impostor (photo of another person / lookalike in a dark
  room):** bar tightened 1.3e-3 → 2.7e-4.
- **Genuine-user cost:** dim-dark-room users whose genuine IR cosine lands
  in [0.55, 0.60) now fall to password (+1.3% FRR on CBSR; live cost to be
  quantified by the open measurement). Security takes priority over
  convenience per the product's stated rule.

## Consequences

- A pure-dark grant is defensible as Secure-tier evidence at the 0.60 bar
  with the scene gate closing the lit-room routing hole; the "convenience
  grade" caveat in the threshold documentation is retired for the dark path.
- Lit rooms where RGB genuinely cannot find a face (harsh backlight) lose
  IR-only fallback: retry, then password. Disclosed trade.
- The scene gate constant is shared with the capture-contention logic
  (`CONCLUSIVE_SCENE_BRIGHTNESS`); both semantics are "conclusively lit",
  and the coupling is pinned by a unit test.
- This PR touches the same dark-path block as PR #518's pairing-budget
  change; whichever merges second rebases.

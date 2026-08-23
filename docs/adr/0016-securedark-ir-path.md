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

**Dark operating point 0.635 (stage 2, live-measured).**
`IR_DARK_MATCH_THRESHOLD = 0.635` for the pure-dark best-of-N and
calibrated-centroid arms. Stage 1 shipped 0.60 (FAR 2.7e-4 / FRR 3.0%
pairwise); stage 2's pre-written rule — raise to 0.635 only if the live
genuine 1st-percentile clears the effective bar by >= 0.02 — was executed
against the 2026-08-23 live dark session (minihost NexiGo, 30 auths, true
dark: genuine min 0.884 vs 0.685 effective, margin 0.199, 10x the rule)
plus the deployment-shaped CBSR OR-arm (0.635 -> FAR 1.24e-4 / FRR 0.69%)
and the Tufts calibrated arm (~4.9e-5). The stage-1 inversion fix stands:
the dim-light fallback (RGB-verified, more evidence) keeps its
0.60-effective bar while the pure-dark bar sits above it, so the arm with
less evidence is never the looser one. The user-supplied-adapter arm keeps
its own validated 0.40 (already FAR ~1e-4 on its benchmark).

**What the threshold deliberately does NOT claim:** stopping the life-size
print species. ADR-0002 measured the enrolled user's vinyl banner at IR
cosine 0.650 — above 0.635. Prints are FLIR PAD + IR physics + the
per-user center/edge floor's job. The threshold is the statistical bar
against unseen impostors, and the scene gate is the routing bar against
lit-room IR-only attacks; the species defenses are the PAD stack.

### Evidence-gated later stages

- ~~0.635~~ **SHIPPED (stage 2)** per the live dark session above.
- **Multi-frame temporal consistency** (embed >=2 lit burst frames, require
  agreement): the burst already exists; CBSR's adjacent-frame cosine
  distribution is recorded as the loose bound (genuine p1 0.520 / p50
  0.944); same-burst AND-of-2 buys only 1.5x FAR (correlated). The
  agreement constant needs the LIVE in-burst distribution (next dark
  session, same protocol).
- **Per-action-class thresholds** (Unseal-class surfaces stricter than
  Verify-class): plumbed after the multi-frame stage.
- **IR quality-filter deepening** (sharpness/pose floors beyond the existing
  blown-skip and brightness gates): only if the dark-session FRR analysis
  shows rejections clustering on a filterable quality axis.

## Threat analysis

- **Lit-room NIR-only presentation:** the scene gate closes the ROUTING, not
  the species. Two disclosed residuals keep it partial:
  - **Frame-fraction bound.** `rgb_frame_mean` is a whole-frame statistic: a
    large visibly-dark 850nm-reflective presentation (the ADR-0002 banner
    species, held at login distance) can fill enough of the RGB FOV to drag
    the mean below 100 in a lit room. The gate's protection is bounded by
    the artifact's frame fraction; what stands behind it is unchanged (FLIR
    PAD, IR physics, the per-user floor, 0.635).
  - **Blinded RGB sensor (MEASURED, 2026-08-23).** A finger over the RGB
    lens in a fully lit room reads rgb_frame_mean ≈ 18 (translucency glow)
    and passes the gate — the session's lit-room control GRANTED through
    the dark path this way, twice. A true-dark room is indistinguishable
    from a covered lens (dark reads 0-17), so no in-stream discriminator
    exists. Tape/shutter/black-frame faults also read ≈0 and pass
    (deliberately, so a sensor fault degrades to the liveness/match gates
    rather than a lit-scene refusal). Blinding the RGB sensor is physical
    device access — outside the presentation-attacker model — and the IR
    node's own privacy state remains fail-closed upstream. The occluded
    attacker still faces the full IR stack (0.635-effective identity,
    FLIR, per-user floor). Note FLIR's margin thins in this regime: the
    same control measured genuine-face p_fake 0.799 in a lit room via IR
    (vs <= 0.005 true dark) — out of FLIR's training domain, under but
    near the 0.9 bar. Disclosed as the cheapest physical route onto the
    dark path; a fix needs an independent sensor or a per-frame
    illumination-metadata trust chain (Windows-Hello-style), not an RGB
    statistic.
  - **Stale brightness on a skew-discarded pair.** When the concurrent pair
    exceeds the skew limit, the stale RGB frame's mean still feeds the gate
    (a >3s-old reading). Exploiting the gap requires lighting changes on
    that timescale — room control, already residual.
- **An attacker who can darken the victim's room physically** faces the full
  dark stack (FLIR + physics + 0.635) — same posture as before, tighter bar.
- **Life-size print (vinyl banner species):** unchanged posture — FLIR PAD
  (measured catching it at p_fake 0.99+), IR physics, per-user floor. The
  0.650 banner score clears 0.635; the threshold was never this species'
  defense.
- **Statistical impostor (photo of another person / lookalike in a dark
  room):** bar tightened 1.3e-3 → 2.7e-4 (stage 1) → 1.24e-4 deployment-shaped (stage 2).
- **Genuine-user cost:** dim-dark-room users whose genuine IR cosine lands
  in [0.55, 0.635) fall to password (offline FRR cost 0.7% at the OR-arm;
  the live session measured zero dark-path score rejections — every grant
  cleared 0.884+). Security takes priority over convenience per the
  product's stated rule.

## Consequences

- A pure-dark grant is defensible as Secure-tier evidence at the 0.635 bar
  with the scene gate closing the lit-room routing hole; the "convenience
  grade" caveat in the threshold documentation is retired for the dark path.
- Lit rooms where RGB genuinely cannot find a face (harsh backlight) lose
  IR-only fallback: retry, then password. Disclosed trade.
- The scene gate constant is shared with the capture-contention logic
  (`CONCLUSIVE_SCENE_BRIGHTNESS`); both semantics are "conclusively lit",
  and the coupling is pinned by a unit test. Lit-room verification
  (frame_mean_probe, 2026-08-22, current ambient): ASUS 128.2-129.2,
  NexiGo 138.3-138.4, Brio 125.4-128.2 — three sensors clear the boundary
  in lit rooms. The DARK-room side (<100) per host, and thinkpad entirely,
  are part of the user-present measurement before release.
- This PR touches the same dark-path block as PR #518's pairing-budget
  change; whichever merges second rebases.

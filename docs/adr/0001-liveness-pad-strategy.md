# ADR-0001: Single-frame IR-physics PAD; no multi-frame biological liveness

**Status:** Accepted (V1.0)
**Date:** 2026-06-28

## Context

Presentation Attack Detection (PAD) can be approached two ways: single-frame
**IR physics** (cross-spectrum co-location, shape-from-shading depth gradient,
corneal glint) or multi-frame **biological liveness** (remote photoplethysmography
[rPPG], respiratory/parallax motion, learned PAD CNNs). A proposal was raised to
add a low-latency (<500 ms, ~5-frame) biological-liveness layer using rPPG and a
distilled model such as MiniFASNet, to harden against 3D masks and active spoofs.

## Decision

irlume V1.0 relies **strictly on single-frame IR physics** for PAD and does **not**
add multi-frame biological liveness. The existing hard gate (face present in RGB
*and* IR, co-located; IR skin-reflectance; `ir_center_edge_ratio ≥ 1.03`; glint)
stands as the PAD mechanism.

## Reasoning

1. **The physics/latency paradox.** Reliable rPPG (heart rate ~1 Hz) or
   respiratory parallax (~0.3 Hz) requires observing multiple physiological
   cycles. The literature minimum for rPPG heart-rate is ~10 s, with ~60 s for
   reliability. A low-latency window (<500 ms) captures a small fraction of a
   single cycle and yields **no measurable biological signal**; it degrades to
   plain motion detection, which the IR depth gradient already subsumes for 2D
   attacks. "Low-latency rPPG" is self-contradictory.

2. **The clean-BOM block.** Bypassing the latency paradox with a learned PAD CNN
   runs into licensing: the state-of-the-art models (MiniFASNet / Silent-Face)
   are trained on **non-commercial datasets (CelebA-Spoof)**. Integrating them
   reintroduces exactly the license taint the project removed elsewhere (see
   `FAIRNESS.md` and the model-licensing notes). No commercially-clean PAD
   dataset/model currently exists.

## Consequences: accepted residual risk

Without a temporal or learned PAD layer, irlume is vulnerable to **3D physical
replicas** (silicone masks with IR-approximating reflectance) and **active
IR-emitting spoofs** that satisfy the single-frame physics gate. These are
explicitly **out of scope for the V1.0 threat model**.

**This residual risk is *not* covered by the PAM fallback.** Face is configured
`auth sufficient` (single-factor) in every path (sudo, lockscreen, login), so the
non-biometric fallback engages only on biometric *failure* (a convenience path).
A spoof that *passes* the gate yields a full unlock with no fallback in the way.
Genuine mitigation of a successful spoof would require either (a) making the
biometric a non-sufficient factor combined with a second factor, (b) cryptographic
camera attestation, or (c) a clean-licensed PAD model, none of which are V1.0.
The accepted posture for V1.0 is: the IR-physics gate defeats 2D screen/print
(validated) and userspace injection (device pinning); 3D-mask and active-IR
spoofs are documented, accepted gaps for a future release.

## Revisit when

- A commercially-clean PAD dataset/model becomes available, **or**
- own-IR-rig data is collected to train a license-clean PAD model (the path noted
  in `THREAT_MODEL.md`), **or**
- the deployment moves to a higher-assurance posture requiring iBeta L2, at which
  point biometric-as-sole-factor should be reconsidered.

## Validation update (2026-06-30): residual risk demonstrated

The ISO/IEC 30107-3 self-test ([`../PAD_SELFTEST.md`](../PAD_SELFTEST.md)) was run
against this gate (results:
[`../pad-results/2026-06-30-ir-liveness-selftest.md`](../pad-results/2026-06-30-ir-liveness-selftest.md)).
Phone/laptop screen replays and a **matte paper** print were all rejected 0% APCER
(caught at `face_in_ir`). A **life-size glossy vinyl print** (a graduation banner)
**breached the gate at 98.6% APCER** (69/70 accepted as live).

Two consequences for this ADR:

1. **The residual risk is now demonstrated, not theoretical**, and the instrument
   is a cheap large-format **glossy print**, not an exotic 3D mask. Vinyl reflects
   850 nm (defeating `face_in_ir`), and on a **2D-IR camera** the brightness-ratio
   "depth" cue is mimicked by a large flat surface's illumination falloff (banner
   depth ranged 1.02–1.58, *overlapping and exceeding* the genuine 1.37–1.40 range,
   so **no depth threshold separates them**; threshold tuning is not a fix).
2. **The reasoning's premise that "the IR depth gradient subsumes 2D attacks" is
   falsified** for IR-reflective large-format prints.

**Direction (for a follow-up ADR):** the durable mitigation is **challenge-response /
temporal liveness**: a static print cannot blink or turn on command, so lightweight
motion/blink verification defeats this class without rPPG. The `require-eyes-open` +
IR-glint eyes scaffolding is the starting point. Reason (1) of this ADR (the rPPG
latency paradox) still stands; reason (2) does not, so temporal liveness should be
reconsidered, not for heart-rate rPPG, but for **static-artifact motion challenge**.

## Update (2026-07-16): acceptance bar for a learned PAD model

Issue #4 asked whether algorithmic-only PAD is permanent policy. It is not. The
bar is the clean-BOM standard the rest of the model stack already meets (YuNet,
BlazeFace, FaceMesh, and AuraFace are all learned models). A learned PAD model
is acceptable when all four criteria hold:

1. **Permissive license** on weights and inference code, compatible with
   GPL-3.0 redistribution.
2. **Training-data provenance:** licensed or consented data, not scraped. This
   is the criterion CelebA-Spoof-trained models (MiniFASNet / Silent-Face)
   fail.
3. **Reproducible training:** the pipeline from dataset to weights can be
   re-run, so the shipped weights are auditable rather than opaque.
4. **Inversion-risk assessment:** a model trained on real face/IR data can leak
   that data through model inversion, which conflicts with the
   raw-frames-never-leave-the-daemon stance. A spoof/live texture classifier
   trained on consented captures carries less identity information than a
   recognition model, but a candidate still owes an explicit assessment.

Criterion 4 was contributed by issue #4.

## Update (2026-08-04): the model is offered during setup, and still not shipped

Measurement changed the balance. The algorithmic gate contributes nothing
against the demonstrated print: it returned `Live` for all 24 presentations in
#235, and again for all six presentations of an enhanced attack on 2026-08-04, a
black cotton sock over the print's chin that carries the centre/edge ratio from
1.06 into 1.32-1.44 and so inside the genuine population (1.26-1.49). The same
enhancement defeats a floor-style implementation of the landmark-relief
candidate (#25) by making an absorbed chin return an unbounded ratio.

The opt-in `flir` cue refused every one of those presentations: p_fake
0.988-1.000 bare and 0.998-0.999 occluded, against a 0.9 threshold. Across
2026-07-17, 2026-07-27 and 2026-08-04 it has not failed to deny this attack.

So the default posture, where a printed photograph of an enrolled user passes,
is no longer defensible when a cue that stops it is one command away and most
users will never run that command.

**Decision.** `irlume setup` offers the model as a numbered step, with the
license and provenance on screen and the answer defaulting to yes. Declining is
one keystroke and the consequence is stated.

**What deliberately did not change:**

- The weights are **not** shipped in irlume's packages. Distributing weights
  whose training data the publisher does not document is the criterion-2 problem
  restated as a redistribution problem, and it is the same thing that blocks
  commercial use of the model stack.
- Nothing is fetched without consent. The daemon does not download on first
  start; setup asks, and `models enable` keeps its stricter type-the-name gate
  for anyone reaching that command without context.
- The cue stays **deny-only**. It can refuse a presentation the built-in gate
  accepted; it can never approve one the built-in gate rejected.
- `flir` still fails criteria 2 and 3, and irlume still does not warrant it.
  Offering a model is not certifying it, and the four criteria remain the bar
  for anything irlume would ship rather than fetch.

**The cost, stated plainly.** The operating window is narrow and thinly
measured: the highest genuine score recorded is 0.702 and the lowest attack
score 0.941, both from one subject on one camera, with the threshold at 0.9.
Genuine-side failures are mapped rather than absent, in dim strobe frames and
direct sun, and a blown frame drops p_fake into an abstain band (#237). More
users now inherit that false-rejection risk; every such failure falls back to
the password, which is why the trade is acceptable, and widening the evidence
beyond one subject remains the thing that would justify shipping rather than
offering.

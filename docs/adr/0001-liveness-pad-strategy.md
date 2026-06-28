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
   single cycle and yields **no measurable biological signal** — it degrades to
   plain motion detection, which the IR depth gradient already subsumes for 2D
   attacks. "Low-latency rPPG" is self-contradictory.

2. **The clean-BOM block.** Bypassing the latency paradox with a learned PAD CNN
   runs into licensing: the state-of-the-art models (MiniFASNet / Silent-Face)
   are trained on **non-commercial datasets (CelebA-Spoof)**. Integrating them
   reintroduces exactly the license taint the project removed elsewhere (see
   `FAIRNESS.md` and the model-licensing notes). No commercially-clean PAD
   dataset/model currently exists.

## Consequences — accepted residual risk

Without a temporal or learned PAD layer, irlume is vulnerable to **3D physical
replicas** (silicone masks with IR-approximating reflectance) and **active
IR-emitting spoofs** that satisfy the single-frame physics gate. These are
explicitly **out of scope for the V1.0 threat model**.

**This residual risk is *not* covered by the PAM fallback.** Face is configured
`auth sufficient` (single-factor) in every path (sudo, lockscreen, login), so the
non-biometric fallback engages only on biometric *failure* (a convenience path) —
a spoof that *passes* the gate yields a full unlock with no fallback in the way.
Genuine mitigation of a successful spoof would require either (a) making the
biometric a non-sufficient factor combined with a second factor, (b) cryptographic
camera attestation, or (c) a clean-licensed PAD model — none of which are V1.0.
The accepted posture for V1.0 is: the IR-physics gate defeats 2D screen/print
(validated) and userspace injection (device pinning); 3D-mask and active-IR
spoofs are documented, accepted gaps for a future release.

## Revisit when

- A commercially-clean PAD dataset/model becomes available, **or**
- own-IR-rig data is collected to train a license-clean PAD model (the path noted
  in `THREAT_MODEL.md`), **or**
- the deployment moves to a higher-assurance posture requiring iBeta L2, at which
  point biometric-as-sole-factor should be reconsidered.

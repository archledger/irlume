# ADR-0002: Challenge-response temporal liveness for IR-reflective print attacks

**Status:** Accepted — implemented & live-validated 2026-07-01 (opt-in). Revises the
reasoning of [ADR-0001](0001-liveness-pad-strategy.md); does not supersede its rPPG
rejection.
**Date:** 2026-06-30 (implemented 2026-07-01)

## Context

The ISO/IEC 30107-3 self-test
([`../pad-results/2026-06-30-ir-liveness-selftest.md`](../pad-results/2026-06-30-ir-liveness-selftest.md))
demonstrated a real breach: a **life-size glossy vinyl print** (graduation banner)
defeated the single-frame IR gate at **98.6% APCER**. Vinyl reflects 850 nm (so it
renders a real IR face, defeating `face_in_ir`), and on a **2D-IR camera** (not a
structured-light depth sensor) the brightness-ratio "depth" cue is mimicked by a
large flat surface's illumination falloff — banner depth (1.02–1.58) *overlaps and
exceeds* the genuine range (1.37–1.40), so **no threshold separates them.**

Two prior options are now closed:

1. **Threshold tuning** — proven not to work (overlap; ADR-0001 validation update).
2. **A clean-licensed trained PAD model** — still unavailable. Re-verified
   2026-06-30: **Silent-Face / MiniFASNet** is Apache-2.0 *for its code*, but the
   **weights carry no explicit license and no documented training data** (the HF
   ONNX re-export assumes inheritance, disclaims training, gives no warranty). That
   fails irlume's clean-BOM bar (weights ≠ code; provenance must be warrantable for
   downstream commercial freedom under GPLv3). No permissive/GPL-compatible
   anti-spoof dataset or model exists as of this date. See
   [`../../models/README.md`](../../models/README.md) and ADR-0001 §"clean-BOM block".

ADR-0001 rejected multi-frame liveness for two reasons: **(1)** the rPPG latency
paradox (heart-rate liveness needs ~10 s), and **(2)** that low-latency motion
"degrades to plain motion detection, which the IR depth gradient already subsumes
for 2D attacks." The breach **falsifies reason (2)**: against an IR-reflective
large-format print, the depth gradient does *not* subsume the attack. Reason (1)
still stands and is not challenged here.

## Decision

Add an **optional challenge-response temporal-liveness stage** to the
credential-releasing path, as **defense-in-depth on top of** (never replacing) the
single-frame IR gate. The insight: **a static print cannot blink or move on
command.** This is not rPPG (no physiological-signal recovery, no ~10 s window) —
it is a sub-second **motion challenge** that specifically defeats static artefacts.

The primary mechanism reuses signals irlume already computes:

- **Blink via glint *transition*.** The corneal glint (`eye_glint`) was the one cue
  that still separated genuine (224–254) from the banner (≤193) in the self-test —
  but its *absolute* level is fragile (the banner reached 193; glasses/dry-eyes drop
  a live user's glint). The **temporal transition** is the robust signal: over a
  short multi-frame capture, a live user blinking shows glint **high → low → high**
  (eyes open → closed → open); a static print holds glint constant and **cannot
  produce the transition**, regardless of its absolute glint level. This reuses the
  existing `require-eyes-open` scaffolding and `eye_glint`.

## Design (to be implemented)

1. **Flow position.** After the single-frame IR gate returns `Live` on a
   credential-release request (login / sudo / unseal), and before the match releases
   a secret, run the challenge stage. The cheap IR gate still kills screens/paper
   first; the challenge only runs when something already looks live.
2. **Capture.** A short burst (~1.0–1.5 s, ~10–15 IR frames). Per frame compute
   `eye_glint` (and eyes-open state). Detect the **open → closed → open** transition
   with hysteresis to reject flicker. Latency budget ≪ the ~10 s rPPG floor
   ADR-0001 ruled out.
3. **Verdict.** Transition seen within the window → `Live`. No transition within
   the timeout → `Uncertain` (not `Spoof`): re-prompt once, then **fall through to
   the non-biometric fallback (password).** A challenge failure must **never lock
   the user out** — it degrades to the existing fallback, same as any biometric miss.
4. **Blink-detection robustness / clean upgrade path.** YuNet's 5 landmarks give
   two eye points — enough to place the glint ROI, not enough for eye-aspect-ratio
   (EAR). If glint-transition proves unreliable (glasses, low light, fast blinks),
   the clean upgrade is a richer landmarker for EAR-based blink: **MediaPipe Face
   Mesh (Apache-2.0)** or **dlib-68 (Boost Software License)** — both GPLv3-clean
   *landmark* models (general face geometry, not NC-trained spoof classifiers, so
   they do **not** hit the Silent-Face weights problem). Add only if needed.
5. **Alternative challenge.** A **head-turn / nod** (small yaw or pitch change on
   command) as a fallback for users whose blink is hard to detect (glasses). irlume
   already computes `head_pose` (yaw_asym / pitch_frac), so the motion signal exists.
6. **Configuration.** Ship **opt-in** first, extending the per-user
   `require-eyes-open` mechanism (a `require-challenge` flag), so BPCER can be
   measured on real users before considering default-on for high-value paths
   (sudo / login). Re-run `irlume padreport` (bona-fide set) to confirm BPCER stays
   low with the challenge active.
7. **Anti-replay scope.** Randomized prompts (blink *N* times / turn a random
   direction) are **deferred**. On this hardware, screen video-replay already dies
   at `face_in_ir` (no IR face), so the *only* class the challenge must beat is
   **static IR-reflective prints**, which *any* motion challenge defeats without
   randomization. Randomization is future hardening against exotic IR-video replay
   (which is already near the accepted active-IR-spoof line).

## Consequences

- **Closes the demonstrated vinyl-print class** — a static print cannot satisfy the
  motion challenge.
- **Costs** ~1–1.5 s added latency and a small user action on the challenge path;
  mitigated by shipping opt-in and keeping the fast IR gate as the first filter.
- **Does not** address **active IR-emitting spoofs** or a **video replay that
  reproduces an 850 nm face and responds to prompts** — still out of scope
  (ADR-0001 residual risk), and the reason to keep randomized challenge on the
  roadmap.
- **The trained-PAD track stays blocked** (no clean weights). Challenge-response +
  IR physics is the "better-than-Hello" bar without a trained model.

## Implementation & validation (2026-07-01)

Built and live-validated on the Zenbook S14. Two findings changed the design during
bring-up (both via a new `irlume blinkprobe` diagnostic that plots the per-frame
signal):

1. **Metric: specular *contrast*, not raw glint peak.** Raw eye-glint barely drops
   on a blink — a closed lid still reflects 850 nm, so peak stays ~140–190 and the
   blink is lost in noise. **Specular contrast** (peak − local-mean at the eye)
   collapses on closure (a real cornea makes a sharp spike; a lid/print is diffuse)
   and separates cleanly. Implemented as `irlume_auth::eye_glint_contrast`; the
   detector (`irlume_liveness::detect_blink`) requires an open-eye contrast floor
   **and** a *sustained* closure (≥3 consecutive closed samples) to reject noise.
2. **De-strobing.** The IR emitter strobes (~15 fps node), so raw frames alternate
   lit/dark. `irlume_camera::capture_ir_sequence(device, samples, burst=2)` keeps
   the brightest of each mini-burst → a clean per-sample trace.

**Live results** (contrast peak; challenge verdict):

| presentation | contrast peak | verdict |
|---|---|---|
| genuine held blink | ~129 | **Blinked** (accept) |
| static vinyl banner | ~46 | **NoEyes** (reject) |
| live face, no blink | ~143 | **NoBlink** (re-prompt) |
| banner + hand cover/uncover (adversarial) | ~45 | **NoEyes** (reject) |

**End-to-end** through `authenticate` with `require_challenge` on: a genuine held
blink **granted** (recognition 0.861 + Blinked); the banner — *recognized* as the
user (0.650) so it would otherwise grant — was **denied** by the challenge
("no live eyes (looks like a print)"). The 98.6%-APCER banner breach is closed.

Shipped **opt-in** (`irlume profiles challenge on|off`, per-user `require_challenge`
in storage; daemon `SetRequireChallenge`). The open-eye contrast floor (banner ≤46
vs genuine ≥120) is itself a strong guard: a diffuse print can't reach it, so hand
cover/uncover can't fake a blink. Residual: gluing specular dots on a print's eyes
to fake the corneal spike + coordinated cover — defeated by deferred randomized
prompts.

**Known follow-up:** no greeter/lock-screen "blink to confirm" prompt is wired yet,
so the challenge relies on the user knowing to blink during the ~4 s window — hence
opt-in only for now. A UI prompt is the prerequisite for considering default-on.

## Revisit / follow-ups

- Implement the blink-via-glint-transition stage behind `require-challenge`;
  measure BPCER on the bona-fide self-test set; re-run the banner attack to confirm
  APCER → 0 with the challenge on.
- Reconsider default-on for sudo/login once BPCER is measured.
- Randomized multi-prompt challenge if IR-video replay becomes a considered threat.
- Own-IR-rig data collection for a clean-licensed passive PAD model remains the
  durable, still-deferred alternative.

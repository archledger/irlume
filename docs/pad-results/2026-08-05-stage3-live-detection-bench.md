# Stage-3 live detection/landmarks bench, 2026-08-05

The live half of the #276 stage-3 measurement: the shipped YuNet, the shipped
BlazeFace short-range (the only converted third-party detection candidate),
and the shipped 478-point Face Landmarker mesh, over fresh captures of the
enrolled user on both of this project's cameras. Decides whether any
detection/landmarks catalog entry is justified, and live-validates the #293
geometry gates on genuine input.

- **Hardware:** Zenbook S14 Windows-Hello RGB+IR module (IR 640x400,
  self-strobing emitter) and archhost NexiGo RGB+IR (IR 640x360). Absolute
  lit-frame means vary widely by segment and ambient light (see the
  per-frame means in the CSVs); lit/ambient classification everywhere below
  uses each burst's own min/max midpoint, never an absolute level.
- **Subject:** the enrolled user, one session per camera, five segments each:
  frontal (~50cm), close (~30cm), far (~1m), a continuous pose sweep
  (yaw then pitch), and a glasses contrast (ON for the Zenbook set, whose
  baseline was glasses-on already; OFF baseline + ON contrast for the
  NexiGo set). A dim segment was planned and NOT exercised (the room could
  not be darkened); nothing here speaks to low-light detection floors.
- **Instrument:** `scripts/capture-stage3-segment.sh` (8 RGB PPM + 24 IR PGM
  per segment) and `examples/detect_bench.rs` (one CSV row per frame:
  detection count/score/box, mesh EAR/central-span, Blaze score/box, frame
  mean). Raw CSVs: `2026-08-05-stage3-bench-{zenbook,nexigo}.csv`, one row
  per captured frame (320: 80 RGB + 240 IR); the tables below aggregate RGB
  frames and lit IR frames only, where lit means above the burst's own
  min/max midpoint (IR ambient-phase frames carry no emitter light and the
  pipeline never detects on them).
- **Model identity:** the bench refuses to run on anything but the shipped
  artifacts and prints their digests; this run measured
  `face_detection_yunet_2023mar.onnx`
  (`8f2383e4dd3cfbb4553ea8718107fc0423210dc964f9f4280604804ed2552fa4`),
  `blaze_face_short_range.onnx`
  (`c5453678015f6289c1d77bda88a8ba9c87574f01de1a05ba1909b9a7e08b237b`) and
  `face_landmark.onnx`
  (`821683be088447839638f79d64268bd501bdb72e5d9e262ec981c7e252956caf`),
  matching `models/SHA256SUMS`.
- **Inference errors are not misses:** detector execution errors abort the
  run, and mesh errors are logged per frame. The final run produced ZERO
  inference errors and its CSVs are byte-identical to the corrected first
  run, so no error hides in the rates below.
- **Instrument defects found and fixed during the run**, recorded because
  the first numbers were wrong: a strict UTF-8 parse of the PPM header
  prefix silently dropped most RGB frames (bright first-row pixels are not
  valid UTF-8; dark IR corners parsed by luck), a fixed lit-frame floor
  mislabeled bright-ambient bursts as lit, halving two segments' apparent
  detection rate, and the first cut collapsed inference errors into misses.
  All fixes are in the committed instrument; the tables below are from the
  corrected, error-free run.

## Results (lit IR frames and RGB frames, per segment)

Zenbook:

| segment | kind | n | YuNet det | YuNet score | mesh ok | span_x px | EAR sd | Blaze det |
|---|---|---:|---:|---:|---:|---:|---:|---:|
| frontal | rgb | 8 | 100% | 0.945 | 100% | 118.6 | 0.010 | 100% |
| frontal | ir-lit | 10 | 100% | 0.939 | 100% | 100.2 | 0.010 | 100% |
| close | rgb | 8 | 100% | 0.925 | 100% | 206.2 | 0.071 | 100% |
| close | ir-lit | 8 | 75% | 0.890 | 75% | 175.5 | 0.027 | 100% |
| far | rgb | 8 | 100% | 0.934 | 100% | 58.3 | 0.012 | 100% |
| far | ir-lit | 8 | 100% | 0.922 | 100% | 52.2 | 0.026 | 100% |
| sweep | rgb | 8 | 100% | 0.936 | 100% | 81.8 | 0.036 | 100% |
| sweep | ir-lit | 12 | 100% | 0.931 | 100% | 83.5 | 0.039 | 100% |
| glasses-on | rgb | 8 | 100% | 0.926 | 100% | 102.3 | 0.013 | 100% |
| glasses-on | ir-lit | 12 | 100% | 0.923 | 100% | 88.0 | 0.026 | 100% |

NexiGo:

| segment | kind | n | YuNet det | YuNet score | mesh ok | span_x px | EAR sd | Blaze det |
|---|---|---:|---:|---:|---:|---:|---:|---:|
| frontal | rgb | 8 | 100% | 0.943 | 100% | 96.3 | 0.007 | 100% |
| frontal | ir-lit | 12 | 100% | 0.936 | 100% | 88.1 | 0.014 | 100% |
| close | rgb | 8 | 100% | 0.942 | 100% | 166.3 | 0.020 | 100% |
| close | ir-lit | 12 | 92% | 0.764 | 92% | 149.3 | 0.027 | 100% |
| far | rgb | 8 | 100% | 0.907 | 100% | 54.6 | 0.007 | 75% |
| **far** | **ir-lit** | **9** | **100%** | 0.931 | 100% | 50.5 | 0.011 | **0%** |
| sweep | rgb | 8 | 100% | 0.937 | 100% | 87.6 | 0.016 | 100% |
| sweep | ir-lit | 8 | 88% | 0.805 | 88% | 65.8 | 0.040 | 75% |
| glasses-on | rgb | 8 | 100% | 0.935 | 100% | 97.2 | 0.006 | 100% |
| glasses-on | ir-lit | 12 | 100% | 0.921 | 100% | 91.0 | 0.026 | 100% |

## Findings

1. **YuNet holds the login envelope.** 100% on RGB in every segment on both
   cameras; on lit IR it misses only at 30cm (75-92%, a face too large for
   the frame, the regime the framing guide already steers away from) and at
   sweep extremes (88% NexiGo). Scores 0.76-0.95.
2. **BlazeFace short-range fails outright at 1m on NexiGo IR: 0 of 9 lit
   frames.** On RGB at the same distance irlume's wiring reads 75% at score
   0.55 (the official runtime reads lower still; see the cross-runtime note
   below), far below its close-range 0.94-0.96. This is the same shape as
   the 2026-07-15 sunlight bench (rescue, never a primary), now confirmed
   at distance on live IR: promoted to the primary detector it would break
   far-distance dark login on this camera. Within ~50cm it is 100%
   everywhere, which is exactly its rescue niche.
3. **The #293 geometry gates cost nothing on genuine input.** 196 frames
   produced a detection; the mesh ran on every one and was refused on none.
   Central spans measured 50-206px against the 2px validity floor, a 25x
   margin at the worst (the far segments).
4. **The 478-point mesh is stable across conditions.** Per-segment EAR
   standard deviation 0.006-0.040 on held poses (0.071 only on the 30cm RGB
   partial-face), glasses on or off.

## Full-range BlazeFace, measured through Google's own runtime

The first draft of this document dismissed the full-range variant on a
range claim its unread model card does not support; the #294 review caught
that, and the measurement below replaced it. To keep hand-rolled decode out
of the answer, both BlazeFace variants ran over the same stored corpus
through the official `mediapipe` Python runtime (version 1.0.0, Tasks
`FaceDetector`, `min_detection_confidence=0.5`, the same floor as irlume's
`BLAZE_SCORE_THRESHOLD`): `scripts/mp-face-detector-bench.py`, raw rows in
`2026-08-05-stage3-bench-official-runtime.csv`. Artifacts: the pinned
`/float16/1/` downloads, short-range sha256
`b4578f35940bf5a1a655214a1cce5cab13eba73c1297cd78e1a04c2380b0152f`
(matching the #276 research pin), full-range sha256
`3698b18f063835bc609069ef052228fbe86d9c9a6dc8dcb7c7c2d69aed2b181b`. The
full-range model card WAS read this time: Apache-2.0 weights, the same
consented first-party training-data statement as short-range, input
160x192, in-scope out to 5 meters, out-of-scope for faces looking away,
strong inclines, and crowds beyond its detection cap.

| camera | segment | kind | n | short-range | full-range | full score |
|---|---|---|---:|---:|---:|---:|
| nexigo | far | ir-lit | 9 | **0%** | **100%** | 0.965 |
| nexigo | far | rgb | 8 | 12% | 100% | 0.884 |
| zenbook | far | ir-lit | 8 | 0% | 100% | 0.813 |
| all other segment/kind cells | | | 154 | 88-100% | **100%** | 0.71-0.96 |

Full-range detected every frame of the corpus, on both cameras, in every
segment, including all the far-IR frames short-range misses. It is a real
detection-stage candidate, not a dismissed one.

**Cross-runtime disagreement, recorded rather than reconciled:** irlume's
own BlazeRescue wiring (parity-tested against the official runtime in the
2026-07-15 bench at 0.94 IoU) reports HIGHER short-range far rates than the
official runtime does on this corpus (Zenbook far-IR: 100% at mean score
0.57 vs the official 0%; NexiGo far-RGB: 75% vs 12%), with the same 0.5
score floor on both sides. The difference is preprocessing (letterbox and
resampling), not thresholds, and it does not change any conclusion here:
short-range fails the NexiGo far-IR segment in both instruments and
full-range clears everything in the official one. It does mean the Rust
bench's Blaze columns measure irlume's wiring, not the model's ceiling.

## Decision

- **The detection stage stays closed today, and the remaining #276
  detection work is now concrete instead of open-ended:** full-range
  BlazeFace is the candidate. What opening requires, per the catalog rules:
  a tf2onnx conversion with the converter version pinned beside the model
  hash, a full-range decoder in irlume-vision parity-tested against the
  official runtime the way the short-range one was (160x192 input and a
  different anchor layout: the shipped decoder cannot load it), and the
  operating threshold measured through irlume's OWN pipeline, since the
  cross-runtime gap above shows wiring changes the numbers.
- **BlazeFace short-range is settled as rescue-only** by both instruments:
  0 of 9 lit IR frames at 1m on the NexiGo against YuNet's 100%, within its
  card's stated short-range design point.
- **The landmarks stage has no distinct candidate to open for.** The
  measured Face Landmarker mesh IS the shipped artifact (same bytes,
  #276 candidate research), and the only alternative mesh (Holistic's
  192px) failed the clean-BOM bar. Nothing to list.

## What this does not establish

- No low-light or no-light captures (the dim segment was skipped), so
  detection floors in the dark path's regime are not measured here.
- One subject, one session per camera; no occlusions beyond glasses, no
  extreme backlight or sunlight (the 2026-07-15 bursts cover saturation).
- Landmark ACCURACY is not measured against ground truth; what is measured
  is stability (EAR spread on held poses) and geometric plausibility. The
  478-point mesh's accuracy claims remain the model card's.
- The Rust bench's short-range far numbers disagree with the official
  runtime's (see the cross-runtime note); treat the Rust Blaze columns as
  irlume-wiring figures and the official-runtime CSV as the model's
  capability.
- Full-range is measured at the RUNTIME level only: nothing here measures
  it through irlume's pipeline, which the cross-runtime gap shows can move
  the numbers. That measurement is the remaining #276 detection work.

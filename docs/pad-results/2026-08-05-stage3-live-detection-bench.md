# Stage-3 live detection/landmarks bench, 2026-08-05

The live half of the #276 stage-3 measurement: the shipped YuNet, the shipped
BlazeFace short-range (the only converted third-party detection candidate),
and the shipped 478-point Face Landmarker mesh, over fresh captures of the
enrolled user on both of this project's cameras. Decides whether any
detection/landmarks catalog entry is justified, and live-validates the #293
geometry gates on genuine input.

- **Hardware:** Zenbook S14 Windows-Hello RGB+IR module (IR 640x400,
  self-strobing emitter, lit frames mean 33-47 this session); archhost NexiGo
  RGB+IR (IR 640x360, strobe lit 55-67).
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
- **Instrument defects found and fixed during the run**, recorded because
  the first numbers were wrong: a strict UTF-8 parse of the PPM header
  prefix silently dropped most RGB frames (bright first-row pixels are not
  valid UTF-8; dark IR corners parsed by luck), and a fixed lit-frame floor
  mislabeled bright-ambient bursts as lit, halving two segments' apparent
  detection rate. Both fixes are in the committed instrument; the tables
  below are from the corrected run.

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
   frames.** On RGB at the same distance it manages 75% at score 0.55, far
   below its close-range 0.94-0.96. This is the same shape as the 2026-07-15
   sunlight bench (rescue, never a primary), now confirmed at distance on
   live IR: promoted to the primary detector it would break far-distance
   dark login on this camera. Within ~50cm it is 100% everywhere, which is
   exactly its rescue niche.
3. **The #293 geometry gates cost nothing on genuine input.** 196 frames
   produced a detection; the mesh ran on every one and was refused on none.
   Central spans measured 50-206px against the 2px validity floor, a 25x
   margin at the worst (the far segments).
4. **The 478-point mesh is stable across conditions.** Per-segment EAR
   standard deviation 0.006-0.040 on held poses (0.071 only on the 30cm RGB
   partial-face), glasses on or off.

## Decision

- **The detection stage stays closed, now on measurement rather than on the
  absence of one.** The only converted candidate (BlazeFace short-range)
  loses to YuNet at distance by 0% to 100% on IR, and #276 allowed
  "declining to open" as an outcome. The full-range BlazeFace variant is
  unmeasured here; its design range (several meters) is outside the login
  envelope, its model card was not read, and nothing in this data shows a
  gap it would fill, so no conversion was spent on it.
- **The landmarks stage has no distinct candidate to open for.** The
  measured Face Landmarker mesh IS the shipped artifact (same bytes,
  #276 candidate research), and the only alternative mesh (Holistic's
  192px) failed the clean-BOM bar. Nothing to list.
- **BlazeFace short-range keeps its shipped rescue role unchanged**, and
  this data adds a live IR distance boundary to its documented envelope.

## What this does not establish

- No low-light or no-light captures (the dim segment was skipped), so
  detection floors in the dark path's regime are not measured here.
- One subject, one session per camera; no occlusions beyond glasses, no
  extreme backlight or sunlight (the 2026-07-15 bursts cover saturation).
- Landmark ACCURACY is not measured against ground truth; what is measured
  is stability (EAR spread on held poses) and geometric plausibility. The
  478-point mesh's accuracy claims remain the model card's.
- The Blaze far-IR failure is measured on the NexiGo only; the Zenbook far
  segment sat closer (its chair-limited ~1m kept a larger face) and Blaze
  held 100% there.

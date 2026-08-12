# SCRFD-10G against the shipped YuNet, stage-3 corpus

Date: 2026-08-12, offline against committed frames; no camera, no subject
present. Instrument:
`benchmarks/pad-candidates/scrfd_vs_yunet_bench.py`; per-frame output
`2026-08-12-scrfd-vs-yunet-frames.csv` beside this file.

- SCRFD-10G: `det_10g.onnx` from the official InsightFace buffalo_l pack,
  sha256 `5838f7fe053675b1c7a08b633df49e7af5495cee0493c7dcf6697200b85b5b91`.
- YuNet (shipped): sha256
  `8f2383e4dd3cfbb4553ea8718107fc0423210dc964f9f4280604804ed2552fa4`.
- Corpus: `2026-08-05` stage-3, two cameras, eight segments each, 512
  frames, all verified against the committed manifest
  `2026-08-05-stage3-corpus.sha256`.

**Scope, stated before any number.** This measures detection availability
and box agreement. It measures nothing about false grants. A detector
hands a box to alignment, recognition and the liveness cues, and a box on
a print feeds that path exactly as a live face does. The detection stage
is closed for that reason and nothing here changes it.

## Instrument verification

The YuNet side is a port of irlume's own `Detector::detect` (letterbox,
stride decode, NMS) rather than a re-implementation, validated against
the committed `bench-nexigo.csv` and `bench-zenbook.csv` on all 320
overlapping rows: max score delta 0.000000, max face-size delta 0.0001,
zero disagreements on detection count. Every frame here is 640 wide, so
irlume's letterbox scale is exactly 1.0 and no resampling occurs on
either side.

The SCRFD boxes were checked visually as well as numerically: on a
frontal RGB frame YuNet gives (261,162)-(400,355) and SCRFD (262,157)-
(400,348), IoU 0.935, 8.6% of frame area, sitting on the face rather
than the frame or a corner. Same on a close IR frame (IoU 0.887) and a
far RGB frame (IoU 0.907). Both return nothing on an empty room.

One anomaly chased rather than stepped over: this harness's `mean`
column differs from the committed bench CSVs by up to 0.3, because
`detect_bench.rs` accumulates brightness with `sum::<f32>()` over 921,600
samples where the f32 ulp is 16. Sequential f32 accumulation reproduces
the committed values exactly. It is a rounding artefact of the bench's
own mean column, touches no detection decision, and is recorded because
it is real.

## Populations

| population | n | YuNet | SCRFD @0.5 | SCRFD @0.6 |
|---|--:|--:|--:|--:|
| genuine, all | 384 | 223 (58.1%) | 231 (60.2%), 4 FALSE | 224 (58.3%), 0 false |
| genuine, RGB | 96 | 90 (93.8%) | 90 (93.8%) | 88 (91.7%) |
| genuine, IR, exposure-usable | 195 | 131 (67.2%) | 139 (71.3%), 4 false | 134 (68.7%) |
| empty scene (any box is false) | 128 | 0 | 0 | 0 |

Where both detect (n=223): IoU median 0.904, min 0.610, p05 0.789, 218 of
223 at or above 0.7. Neither detector returned more than one box on any
of the 512 frames.

## The eight disagreements, inspected rather than counted

At SCRFD's own default 0.5 threshold, SCRFD fires on eight frames YuNet
misses. They split exactly in half:

- **Four true recoveries**: saturated lit-strobe IR frames (means
  106-147) where the blown face defeats YuNet and SCRFD boxes it
  correctly.
- **Four false positives**: a dark pose-sweep burst (means about 18,
  scores 0.51-0.59) where the subject is a silhouette at frame right and
  SCRFD boxes a bright background object at the left edge. Uncorrected,
  these made one segment read 66.7% for SCRFD against YuNet's 50%. That
  reading is wrong.

Raising SCRFD to 0.6, the number irlume happens to use for YuNet: both
detect 221, YuNet-only 2, SCRFD-only 3, background false positives 0. The
two YuNet-only frames are dim RGB where SCRFD scores 0.58 and 0.60 and
falls under the bar.

That 0.6 is a reference point, NOT a matched operating point. The two
scores come from different models with different preprocessing and no
shared calibration, so an equal number does not equalise false-positive
rate, false-negative rate, or anything else. It is also not independently
chosen: the only evidence that SCRFD's background boxes fall below 0.6 is
the same corpus the comparison is reported on, which contains 128
empty-room frames and no attacks. A background box at 0.65 in another
room would remove the property without contradicting anything measured
here (the review round on this PR named this; the earlier draft called it
a matched threshold).

## Deviations from irlume's own invocation

The YuNet side has none (validated above). The SCRFD side runs at the
publisher's reference operating point and differs in five disclosed ways:
score threshold 0.5 against irlume's 0.6 (load-bearing: every false
positive sits between 0.51 and 0.59); NMS 0.4 with the Faster-RCNN area
convention against irlume's 0.3 plain IoU (changed no outcome, since no
frame produced two boxes); normalisation `(x-127.5)/128` against YuNet's
raw 0-255; RGB channel order against BGR; and pad value, SCRFD padding
before normalising so the pad reaches the net at -0.996. IR grey is
replicated to three channels for both, which is identical under either
channel order.

Not tested: latency, landmark quality, any camera or subject outside this
corpus, and everything downstream of the box.

## Reading

The two detectors are a wash on availability and differ in how they
fail. SCRFD recovers saturated lit-strobe IR frames YuNet loses; YuNet
holds two dim RGB frames SCRFD drops at a matched threshold; SCRFD's own
default threshold produces background false positives that YuNet's
operating point does not. Neither hallucinates on an empty room. Where
both fire they agree closely, median IoU 0.904.

Nothing here is evidence toward opening the detection stage. This corpus
has one subject, one room, one session and no attack presentations at
all. The question the stage is closed over, whether a box from this
detector on a print or a screen reaches a grant, is untouched, and it is
the question #440 exists to answer.

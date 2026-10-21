# ViT RGB PAD cue: dim-room sensitivity (#1155)

Harness and scores behind
[`docs/research/2026-10-21-vit-dim-room-cue-evaluation.md`](../../../docs/research/2026-10-21-vit-dim-room-cue-evaluation.md).
Inputs are the original, non-aligned LFW images (genuine faces only), the
corpus behind the recorded 2026-08-21 LFW scores; no camera capture is
involved and no image is committed, only per-frame scores.

## Files

- `dim_room_score.py {grain,photon} <lfw-root> <out.csv>`: scores an evenly
  spaced LFW sample through the shipped cue's scorer contract (m96 crop,
  `INTER_LINEAR` to 224, `(px/255 - 0.5)/0.5`, softmax index 1) with one
  transform per arm on the crop. `grain` (200 images): base, Gaussian grain
  sigma 3/6/10/15/20 code units, code values scaled by 0.32/0.14 (arm
  `exposure`), JPEG quality 20. `photon` (300 images): base, photon-count
  noise with linear-light exposure 0.10/0.04/0.02 (arm `noise`), Gaussian
  blur sigma 1.5 px, contrast x0.5. Verifies the model and detector
  sha256 against the pins before scoring; noise is seeded per image.
- `summarize.py <csv>... [--recorded <vit-lfw-scores.csv>]`: the tables in
  the research note, including the "5-median refused" i.i.d. bootstrap
  (20,000 draws, seed 1155) of the shipped decision (median of 5 at or above
  0.55); `--recorded` adds the recorded LFW distribution and the uniform-shift
  table (i.i.d. and per-identity groups of five).
- `validate_harness.py <lfw-root>`: rescores 300 rows of
  [`docs/research/2026-08-21-vit-lfw-scores.csv`](../../../docs/research/2026-08-21-vit-lfw-scores.csv)
  and reports the per-frame deltas and both distributions, then counts the
  sampled faces whose crop bounds differ from the shipped arithmetic (width
  and height rebuilt from float32 corners); it exits non-zero unless every
  sampled score reproduces, every sampled face is detected and no bound
  differs.
- `grain.csv`, `photon.csv`: the committed output on original LFW (`frame,
  arm, param, luma, p_spoof, noise_std`; `noise_std` is the measured
  code-unit standard deviation of the noisy crop minus the clean one).
- `deepfunneled/grain.csv`, `deepfunneled/photon.csv`: the same passes on the
  deep-funneled LFW release, the first pass of this harness. That corpus
  already has 5 to 8% of baseline frames at or above 0.55 (1 to 2% on the
  original images), so its refusal rates are not comparable with the recorded
  operating point. Kept because figures from it were posted on #1155; those
  came from the same scores with a different bootstrap draw, so `summarize.py`
  reproduces them to within 0.8 points.

## Reproduce

```sh
cd benchmarks/pad-candidates/dim-room
python3 summarize.py grain.csv photon.csv --recorded ../../../docs/research/2026-08-21-vit-lfw-scores.csv
python3 validate_harness.py <lfw-root>
python3 dim_room_score.py grain  <lfw-root> /tmp/grain.csv  && cmp /tmp/grain.csv grain.csv
python3 dim_room_score.py photon <lfw-root> /tmp/photon.csv && cmp /tmp/photon.csv photon.csv
```

The first line needs only the committed files. A rerun writes byte-identical
CSVs on the recorded environment (Python 3.14.8, NumPy 2.5.2, OpenCV 5.0.0,
ONNX Runtime 1.29.0); other versions may differ in the last digits.

`<lfw-root>` is any directory holding the 13,233 original LFW `.jpg` files
(the sample is chosen by file name, so the folder layout does not matter; the
committed run used `https://huggingface.co/datasets/marcelohaps/lfw` at
`12a61458`). On that corpus `validate_harness.py` reproduces all 300 sampled
recorded scores to four decimals. The models come from
`scripts/fetch-models.sh` (`--models-dir` overrides `models/`).
Python deps: `numpy>=2.0,<3` (as in `benchmarks/requirements-bench.txt`; NumPy
1.x widens the float32 crop arithmetic to float64, which moves some crop bounds
by a pixel, and the scripts refuse it), `opencv-python` (>= 4.6 for
`FaceDetectorYN`), `onnxruntime`.

# Third-party PAD candidate evaluations

Scripts and score summaries behind
[`docs/pad-results/2026-07-17-third-party-pad-candidates.md`](../../docs/pad-results/2026-07-17-third-party-pad-candidates.md).
Raw captures contain the operator's face and are never committed; these scripts
regenerate scores from your own captures.

## Model artifacts (download from the publisher, verify the hash)

| Model | URL | sha256 |
|---|---|---|
| FLIR (MIT) | `https://modelscope.cn/api/v1/models/damo/cv_manual_face-liveness_flir/repo?FilePath=model.onnx&Revision=master` | `df80cea7228b92562692e56aac965d35766c77399159798c552fb3c77b410c72` |
| anti-spoof-mn3 (Apache-2.0) | `https://storage.openvinotoolkit.org/repositories/open_model_zoo/public/2022.1/anti-spoof-mn3/anti-spoof-mn3.onnx` | `c4c99af04603b62d7e44f6f4daeb33e0daeccc696008c0b1d62f6f5cebbb3262` |

## Scripts

- `flir_eval.py <model.onnx> <out.json>`: scores a directory tree of IR PGM
  bursts with the FLIR model; replicates ModelScope's `FaceLivenessIrPipeline`
  preprocessing (bbox + 16/112 padding, square 127-fill, 128 resize, center-112
  crop, (x-127.5)/128). FLIR outputs raw logits; softmax applied once here.
- `mn3_eval.py <model.onnx> <out.json>` / `mn3_eval2.py`: mn3 scoring per
  Intel's OMZ README (mean/scale normalization, author-demo bbox crop).
  `mn3_eval2.py` adds the crop-margin sweep and uses the corrected scoring:
  mn3's ONNX already outputs probabilities; do NOT softmax again (a ~0.731
  median is the double-softmax fingerprint).
- `live-flir-test.sh <name> [ir-device]`: one-shot live capture + score:
  a 36-frame IR strobe burst via the `landmark_dump` example, each lit frame
  scored immediately. Needs `ORT_DYLIB_PATH` and the shipped YuNet model.

Python deps: `numpy`, `opencv-python` (>= 4.6 for `FaceDetectorYN`),
`onnxruntime`. Detection uses irlume's shipped YuNet file.

- `flir-live-session-scores.txt` / `mn3-session-scores.txt`: the recorded score
  summaries from the 2026-07-17 sessions, verbatim.

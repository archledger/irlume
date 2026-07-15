# Models

irlume bundles a **permissive, GPLv3-compatible** model stack. All weights are
committed to this repo via **Git LFS** (see `../.gitattributes`) and loaded from
`/usr/share/irlume/models/` (packages) or this dir (dev); a clone or package is
self-contained, no runtime download or fetch step. After cloning, run
`git lfs pull` if your client didn't fetch LFS objects automatically.

`SHA256SUMS` holds the release checksums; the daemon embeds it at build time
and warns at startup when a loaded model doesn't match (see ../SECURITY.md).
After changing any shipped model, regenerate it and commit both:
`cd models && sha256sum face_detection_yunet_2023mar.onnx face_landmark.onnx glintr100.onnx ir_adapter.onnx > SHA256SUMS`.

| File | Stage | Source | License | Notes |
|---|---|---|---|---|
| `face_detection_yunet_2023mar.onnx` | detection | [OpenCV Zoo](https://github.com/opencv/opencv_zoo) | **MIT** | bbox + 5 landmarks; int8 variant also fine |
| `glintr100.onnx` | recognition | [fal/AuraFace-v1](https://huggingface.co/fal/AuraFace-v1) | **Apache-2.0** | 512-D ArcFace; use ONLY this file from the repo |
| `face_landmark.onnx` | liveness (EAR) + rescue alignment | Google MediaPipe FaceLandmarker mesh (`face_landmarks_detector.tflite` from `face_landmarker.task`) | **Apache-2.0** | 478 landmarks (468 + iris); input `[1,256,256,3]` RGB → `1434` + face flag. Replaced the legacy 192px/468pt FaceMesh 2026-07-15 (12% better eye accuracy on CBSR, NME 0.0345 vs 0.0392); the loader auto-detects either generation, legacy banked as `.legacy-192`. |
| `blaze_face_short_range.onnx` | detection rescue | Google MediaPipe BlazeFace short-range (`blaze_face_short_range.tflite`) | **Apache-2.0** | Cascade stage 2: runs only when YuNet finds no face. 2026-07-15 bench: 96.9% vs YuNet's 76.9% on saturated outdoor frames, but 40% on shaded faces where YuNet holds 99% — never a YuNet replacement. Box refined by FaceMesh before alignment. |
| `ir_adapter.onnx` | recognition (IR domain) | self-trained residual adapter (512→512), trained on the CBSR NIR (OTCBVS dataset 07) and Oulu-CASIA NIR academic datasets | **research-only taint — see note below** | boosts IR-frame match scores toward the RGB enrollment |

### ir_adapter.onnx: training-data correction (2026-07-14)

Earlier revisions of this file claimed the IR adapter was trained on the
author's own captures with no third-party training data. That was wrong.
Both shipped adapter versions (`ir_adapter.onnx` and the banked
`ir_adapter.onnx.v1-256`) were trained on AuraFace embeddings of two
academic NIR datasets: CBSR NIR (OTCBVS benchmark dataset 07, education
and research use only) and Oulu-CASIA NIR (academic release). By the same
standard this project applies to third-party weights (see the Silent-Face
note below), that restricts the adapter to non-commercial research use,
even though the code that trained it is ours. The rest of the model table
is unaffected.

Resolution decided 2026-07-15, see
[ADR-0004](../docs/adr/0004-per-enrollment-ir-adapter.md): the adapter will
be removed from packaging (raw IR matching against the enrolled IR
templates costs at most 0.07 EER points on unseen data) and replaced by
per-enrollment on-device calibration fitted from each user's own scans.
Until the removal release, commercial redistribution should either omit
`ir_adapter.onnx` or contact the dataset providers for licensing.

### MediaPipe FaceMesh: license-verified (unlike Silent-Face)

Cleared the clean-BOM gate 2026-07-01 against Google's **official model card**
(`storage.googleapis.com/mediapipe-assets/…FaceMesh…`). Unlike Silent-Face, the
model card **itself states "LICENSED UNDER Apache License, Version 2.0"** (weights,
not just code; authored by Google) and documents **first-party training data**
(Google-collected smartphone/AR images, no MS-Celeb-1M / CelebA-Spoof taint). →
warrantable, GPLv3-compatible. **Sourced 2026-07-01** by converting Google's
canonical Apache-2.0 `face_landmark.tflite`
(`storage.googleapis.com/mediapipe-assets/`) with `tf2onnx --opset 13` on archhost
(TF needs Python ≤3.12 via a `uv` venv; neither box ships one by default). The
`face_landmark_with_attention.tflite` (478 + iris) does **not** convert to a runnable
ONNX: tf2onnx leaves a MediaPipe custom op (`TFL_Landmarks2TransformMatrix`) that
onnxruntime rejects, so we use the basic 468-landmark model, whose eye-contour
points suffice for EAR. Non-license
caveats to document at use: the card's out-of-scope notes ("not for
facial recognition/identification", "not for life-critical decisions") are
**advisory**: irlume uses it for LIVENESS only (EAR/blink, not recognition) with a
mandatory password fallback; and it is RGB/selfie-trained, so IR-grey performance
must be validated (see ADR-0002).

## Do NOT use

- **AuraFace's bundled `scrfd_10g_bnkps.onnx`** (and `1k3d68`, `2d106det`,
  `genderage`): those are InsightFace detection/aux models with **non-commercial**
  weights. Take only `glintr100.onnx` from that repo; use YuNet for detection.
- **InsightFace buffalo_l / antelopev2** (`w600k_r50`, `det_10g`): non-commercial
  weights, **incompatible with GPL** (which guarantees downstream commercial use).
- **Silent-Face / MiniFASNet anti-spoofing weights** (minivision-ai, incl. HF ONNX
  re-exports): the *code* is Apache-2.0 but the **weights carry no explicit license
  and no documented training data** (verified 2026-06-30; the re-export disclaims
  training and gives no warranty). Weights ≠ code: an Apache `LICENSE` on the source
  does not license weights whose provenance is unwarrantable. **Fails the clean-BOM
  bar**; do not bundle. Anti-spoofing stays algorithmic (IR physics + challenge-
  response, [`../docs/adr/0002-challenge-response-liveness.md`](../docs/adr/0002-challenge-response-liveness.md))
  until a clean-licensed PAD model or own-IR-rig data exists.

## Verification

Record SHA-256 sums in `SHA256SUMS` and check them in CI before bundling.

## Open due-diligence item

fal's model card + blog state AuraFace was trained on a commercial dataset and
is for commercial use; the lower-than-ArcFace accuracy confirms independent
training (not a re-upload of antelopev2). For belt-and-braces, an issue asking
fal to confirm `glintr100.onnx`'s provenance in writing is worthwhile.

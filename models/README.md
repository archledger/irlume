# Models

irlume bundles a **permissive, GPLv3-compatible** model stack. All weights are
committed to this repo via **Git LFS** (see `../.gitattributes`) and loaded from
`/usr/share/irlume/models/` (packages) or this dir (dev); a clone or package is
self-contained, no runtime download or fetch step. After cloning, run
`git lfs pull` if your client didn't fetch LFS objects automatically.

`SHA256SUMS` holds the release checksums; the daemon embeds it at build time
and warns at startup when a loaded model doesn't match (see ../SECURITY.md).
After changing any shipped model, regenerate it and commit both:
`cd models && sha256sum face_detection_yunet_2023mar.onnx face_landmark.onnx glintr100.onnx blaze_face_short_range.onnx > SHA256SUMS`.

| File | Stage | Source | License | Notes |
|---|---|---|---|---|
| `face_detection_yunet_2023mar.onnx` | detection | [OpenCV Zoo](https://github.com/opencv/opencv_zoo) | **MIT** | bbox + 5 landmarks; int8 variant also fine |
| `glintr100.onnx` | recognition | [fal/AuraFace-v1](https://huggingface.co/fal/AuraFace-v1) | **Apache-2.0** | 512-D ArcFace; use ONLY this file from the repo |
| `face_landmark.onnx` | liveness (EAR) + rescue alignment | Google MediaPipe FaceLandmarker mesh (`face_landmarks_detector.tflite` from `face_landmarker.task`) | **Apache-2.0** | 478 landmarks (468 + iris); input `[1,256,256,3]` RGB → `1434` + face flag. Replaced the legacy 192px/468pt FaceMesh 2026-07-15 (measured 28% better eye accuracy on CBSR ground truth, NME 0.0378 → 0.0273 through the YuNet-crop pipeline); the loader auto-detects either generation, legacy banked as `.legacy-192`. |
| `blaze_face_short_range.onnx` | detection rescue | Google MediaPipe BlazeFace short-range (`blaze_face_short_range.tflite`) | **Apache-2.0** | Cascade stage 2: runs only when YuNet finds no face. 2026-07-15 bench: on saturated outdoor-walking frames the cascade (YuNet→BlazeFace) detects 98.5% vs YuNet-alone's 76.9%; BlazeFace-alone weakens to 40% on shaded faces where YuNet holds 99%, so it is a rescue, never a YuNet replacement. Box refined by FaceMesh before alignment. |

Every file above is MIT or Apache-2.0 with first-party or commercially
warrantable training data, so the shipped stack carries no non-commercial or
research-only restriction.

### ir_adapter.onnx: removed (2026-07-15)

A former `ir_adapter.onnx` (a 512→512 residual MLP over IR embeddings) was
**retired and removed from the repo and every package** on 2026-07-15. Both
versions that ever shipped were trained on AuraFace embeddings of two academic
NIR datasets, CBSR NIR (OTCBVS benchmark dataset 07) and Oulu-CASIA NIR, whose
grants cover education and research only. By the same standard this project
applies to third-party weights (see the Silent-Face note below), that
restricted the adapter to non-commercial research use, which conflicts with the
commercial freedom GPLv3 promises downstream.

Its replacement is per-enrollment on-device calibration fitted from each user's
own scans (`../crates/irlume-core/src/calib.rs`), which carries no third-party
data. See [ADR-0004](../docs/adr/0004-per-enrollment-ir-adapter.md) for the
decision and the measurement: the global adapter improved recognition for the
handful of identities it was trained on but slightly *worsened* every unseen
face (Tufts NIR-NIR 1.43% → 1.53% EER), so raw AuraFace plus per-enrollment
calibration is the better default as well as the clean one. Existing
enrollments made against the old adapter are tagged with its embedding space
and must be re-enrolled after upgrading; the daemon refuses a space mismatch
rather than matching across it.

### MediaPipe FaceMesh: license-verified (unlike Silent-Face)

Cleared the clean-BOM gate 2026-07-01 against Google's **official model card**
(`storage.googleapis.com/mediapipe-assets/…FaceMesh…`). Unlike Silent-Face, the
model card **itself states "LICENSED UNDER Apache License, Version 2.0"** (weights,
not just code; authored by Google) and documents **first-party training data**
(Google-collected smartphone/AR images, no MS-Celeb-1M / CelebA-Spoof taint). →
warrantable, GPLv3-compatible. **Currently shipped (2026-07-15):** the
478-point/256px FaceLandmarker mesh, converted with `tf2onnx --opset 17` from
the Apache-2.0 `face_landmarks_detector.tflite` inside Google's
`face_landmarker.task` bundle (TF needs Python ≤3.12 via a `uv` venv; neither
box ships one by default). The loader reads the input side from the model and
accepts either landmark generation (468 or 478), so the legacy 192px/468pt
`face_landmark.tflite` still loads if swapped back in (banked as `.legacy-192`).
Historical note: the older `face_landmark_with_attention.tflite` (478 + iris)
would not convert cleanly (tf2onnx left a `TFL_Landmarks2TransformMatrix`
custom op onnxruntime rejected), which is why the 468-point model shipped
first; the `face_landmarker.task` mesh converts without that op. Non-license
caveats to document at use: the card's out-of-scope notes ("not for
facial recognition/identification", "not for life-critical decisions") are
**advisory**: irlume uses it for LIVENESS (EAR/blink) plus rescue-path
alignment, never recognition, with a mandatory password fallback; and it is
RGB/selfie-trained, so IR-grey performance must be validated (see ADR-0002).

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

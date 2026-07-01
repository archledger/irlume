# Models

irlume bundles a **permissive, GPLv3-compatible** model stack. Once you add the
weights here they are compiled into `irlumed` via `include_bytes!` — no runtime
download, no `fetch-models` step.

| File | Stage | Source | License | Notes |
|---|---|---|---|---|
| `face_detection_yunet_2023mar.onnx` | detection | [OpenCV Zoo](https://github.com/opencv/opencv_zoo) | **MIT** | bbox + 5 landmarks; int8 variant also fine |
| `glintr100.onnx` | recognition | [fal/AuraFace-v1](https://huggingface.co/fal/AuraFace-v1) | **Apache-2.0** | 512-D ArcFace; use ONLY this file from the repo |
| `face_mesh.onnx` (planned) | liveness (EAR) | Google MediaPipe FaceMesh V2 | **Apache-2.0** | 478 + 10 iris landmarks; eye-contour EAR for passive blink liveness. See note below. |

### MediaPipe FaceMesh — license-verified (unlike Silent-Face)

Cleared the clean-BOM gate 2026-07-01 against Google's **official model card**
(`storage.googleapis.com/mediapipe-assets/…FaceMesh…`). Unlike Silent-Face, the
model card **itself states "LICENSED UNDER Apache License, Version 2.0"** (weights,
not just code; authored by Google) and documents **first-party training data**
(Google-collected smartphone/AR images — no MS-Celeb-1M / CelebA-Spoof taint). →
warrantable, GPLv3-compatible. Use the canonical Google Apache-2.0 `.tflite`
converted to ONNX (preserve the NOTICE), not an unprovenanced re-upload. Honest,
non-license caveats to document at use: the card's out-of-scope notes ("not for
facial recognition/identification", "not for life-critical decisions") are
**advisory** — irlume uses it for LIVENESS only (EAR/blink, not recognition) with a
mandatory password fallback; and it is RGB/selfie-trained, so IR-grey performance
must be validated (see ADR-0002).

## Do NOT use

- **AuraFace's bundled `scrfd_10g_bnkps.onnx`** (and `1k3d68`, `2d106det`,
  `genderage`) — those are InsightFace detection/aux models with **non-commercial**
  weights. Take only `glintr100.onnx` from that repo; use YuNet for detection.
- **InsightFace buffalo_l / antelopev2** (`w600k_r50`, `det_10g`) — non-commercial
  weights, **incompatible with GPL** (which guarantees downstream commercial use).
- **Silent-Face / MiniFASNet anti-spoofing weights** (minivision-ai, incl. HF ONNX
  re-exports) — the *code* is Apache-2.0 but the **weights carry no explicit license
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

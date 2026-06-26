# Models

lumen bundles a **permissive, GPLv3-compatible** model stack. Once you add the
weights here they are compiled into `lumend` via `include_bytes!` — no runtime
download, no `fetch-models` step.

| File | Stage | Source | License | Notes |
|---|---|---|---|---|
| `face_detection_yunet_2023mar.onnx` | detection | [OpenCV Zoo](https://github.com/opencv/opencv_zoo) | **MIT** | bbox + 5 landmarks; int8 variant also fine |
| `glintr100.onnx` | recognition | [fal/AuraFace-v1](https://huggingface.co/fal/AuraFace-v1) | **Apache-2.0** | 512-D ArcFace; use ONLY this file from the repo |

## Do NOT use

- **AuraFace's bundled `scrfd_10g_bnkps.onnx`** (and `1k3d68`, `2d106det`,
  `genderage`) — those are InsightFace detection/aux models with **non-commercial**
  weights. Take only `glintr100.onnx` from that repo; use YuNet for detection.
- **InsightFace buffalo_l / antelopev2** (`w600k_r50`, `det_10g`) — non-commercial
  weights, **incompatible with GPL** (which guarantees downstream commercial use).

## Verification

Record SHA-256 sums in `SHA256SUMS` and check them in CI before bundling.

## Open due-diligence item

fal's model card + blog state AuraFace was trained on a commercial dataset and
is for commercial use; the lower-than-ArcFace accuracy confirms independent
training (not a re-upload of antelopev2). For belt-and-braces, an issue asking
fal to confirm `glintr100.onnx`'s provenance in writing is worthwhile.

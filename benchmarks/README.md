# Benchmarks — how the accuracy numbers were measured

Every model-accuracy figure in the README, `models/README.md`, the CHANGELOG,
and the release notes is produced by the scripts in this directory, on public
datasets, with the exact protocols documented below. The raw result files are
committed here as `results-*.json` / `results-*.log` so the numbers can be read
without re-running anything, and reproduced from scratch if you don't trust them.

Nothing here runs inside the daemon or ships in a package — these are offline
measurement scripts. They open ONNX models directly (the same weights irlume
ships) and score them against face datasets.

## Environment

The committed results were produced with:

- ONNX Runtime 1.27.0, CUDA execution provider (an NVIDIA RTX 3060)
- OpenCV (`cv2`) 5.0.0 for image I/O and the YuNet detector wrapper
- Python 3 in a venv with `opencv-python`, `onnxruntime-gpu`, `numpy`

`"ort"` and `"cuda"` fields in each result JSON record the runtime that produced
it. CPU runs give the same accuracy (only latency differs).

## Datasets (all public; obtain them yourself)

| Name | What | Source | Terms |
|---|---|---|---|
| LFW | 13k in-the-wild RGB faces, standard 6000-pair verification protocol | [vis-www.cs.umass.edu/lfw](http://vis-www.cs.umass.edu/lfw/) (also on Kaggle) | research use, free download |
| CBSR NIR | CASIA near-infrared faces (OTCBVS benchmark dataset 07) | [OTCBVS](http://vcipl-okstate.org/pbvs/bench/) | research/education only |
| Oulu-CASIA NIR | near-infrared faces, multiple illuminations | Oulu-CASIA NIR-VIS academic release | research only |
| Tufts Face | paired RGB + NIR (thermal/near-IR), many subjects | [tdface.ece.tufts.edu](http://tdface.ece.tufts.edu/) | research use |

CBSR and Oulu are the datasets the removed IR adapter was trained on — that is
exactly why an adapter result on them (e.g. CBSR) is an in-training-set number,
not a generalization claim. Tufts is never used for training, so it is the clean
"unseen faces" test. These license terms are also why irlume does not ship any
weights derived from these sets (see `models/README.md` and ADR-0004).

## Scripts and what they measure

| Script | Produces | Protocol |
|---|---|---|
| `bench_faceid.py` | `results-lfw.json` | LFW 6000-pair verification, 10-fold accuracy + EER + TAR@FAR; AuraFace vs InsightFace buffalo; latency |
| `bench_lfw_cascade.py` | `results-lfw-cascade.json` | Same LFW protocol with the YuNet→BlazeFace detection cascade active; records rescue count |
| `bench_nir_ext.py` | `results-nir_results.json` | CBSR + Tufts NIR verification (6000 pairs each) and rank-1 identification; AuraFace vs buffalo vs AuraFace+adapter |
| `bench_cascade.py` | `results-cascade.json`, `results-cascade.log` | Per-environment detection rate (YuNet vs BlazeFace vs cascade) and the 468-vs-478 mesh eye-NME |
| `bench_mp_results` (via `bench_cascade.py`/mediapipe harness) | `results-mp_results.json` | Detector eye-NME and standalone 468-vs-478 landmarker NME |
| `bench_insightface.py` | — | Full AuraFace-vs-InsightFace comparison across all sets |
| `blaze_parity.py` | — | BlazeFace ONNX decode parity vs the official MediaPipe runtime (IoU, keypoint px error) |

## The headline numbers and where to read them

- **LFW recognition — AuraFace 99.03% 10-fold accuracy** (`results-lfw-cascade.json`,
  `auraface.acc10fold`), EER 1.37%. The cascade fired 0 rescues on LFW
  (`blaze_rescues: 0` over 7701 detections), so easy detection is unchanged.
  InsightFace buffalo scores 99.4% (`results-lfw.json`) — higher, but its weights
  are non-commercial, which is why irlume ships AuraFace instead. This is a
  deliberate license-over-peak-accuracy tradeoff, stated plainly.
- **IR adapter overfit — Tufts NIR→NIR EER 1.43% (raw) vs 1.53% (+v3 adapter)**
  (`results-nir_results.json`, `tufts.nir_nir`). On CBSR, the adapter's own
  training data, it instead improved (0.77% → 0.37%, `cbsr_nir`). Helping the
  training set while hurting unseen faces is why the global adapter was removed.
- **Detection cascade — outdoor-walking frames 76.9% (YuNet) → 98.5% (cascade)**
  (`results-cascade.json`, `outdoor-walking`, n=65). On shade-frontal, BlazeFace
  alone collapses to 40.3% where YuNet holds 99.2%, so BlazeFace is a rescue on a
  YuNet miss, never a replacement. The outdoor-walking sample is small (65 frames
  from one field session); treat it as directional, not a population estimate.
- **Mesh landmarks — eye NME 0.0378 → 0.0273 (~28% lower)** for the 478-point
  256px FaceLandmarker vs the legacy 468-point 192px mesh, measured through
  irlume's own YuNet→crop pipeline on CBSR (`results-cascade.log`, `[mesh]` lines,
  n=985). The standalone MediaPipe-crop harness shows a smaller 0.0392 → 0.0345
  (`results-mp_results.json`, `landmarkers`); the pipeline number is the relevant
  one because that is how irlume feeds the mesh.

## Reproduce

```sh
# in a venv with opencv-python, onnxruntime(-gpu), numpy
python3 bench_lfw_cascade.py --lfw /path/to/lfw --models-dir /path/to/models --out lfw.json
python3 bench_nir_ext.py     --cbsr /path/to/cbsr_nir --tufts /path/to/tufts --models-dir /path/to/models --out nir.json
python3 bench_cascade.py     --datasets /path/to/... --models-dir /path/to/models --out cascade.json
```

`--models-dir` holds the shipped `glintr100.onnx`, `face_detection_yunet_2023mar.onnx`,
`face_landmark.onnx`, and `blaze_face_short_range.onnx` (from `../models/`).
Run each script with `--help` for its full flag set. Numbers should land within
run-to-run seeding noise of the committed `results-*.json`.

# Model Calibration Campaign: Design

Status: approved design, pending implementation plan
Date: 2026-08-30
Agent: opencode
Scope: benchmarks/ + docs/research/ only. No daemon, CLI, or model-file changes in this campaign.

## Goal

Calibrate and validate every shipped irlume model against large public datasets,
and evaluate license-clean replacement candidates under identical protocols, so
that threshold constants, cascade behavior, and shipped-model choices rest on
measured evidence instead of small-sample anecdotes.

Compute target: archhost (NVIDIA RTX 3060, the same box that produced the
committed benchmark numbers). Scale: massive, roughly 60 to 90 GB of extracted
data. Shape: extend the existing benchmarks/ script convention (approach A),
not a standalone harness.

## What "improve" means here (binding)

1. Calibration and validation of shipped weights: threshold sweeps, failure
   regime maps, per-species and per-modality breakdowns. Improvements land as
   evidence-backed constant or preprocessing changes in normal PRs.
2. Evaluation of clean-licensed replacement candidates. A replacement ships
   only if it wins its track comparison AND clears the clean-BOM bar.
3. No retraining of weights on Kaggle or academic face datasets. Research-only
   dataset terms forbid shipping derived weights; this is exactly why
   ir_adapter.onnx was removed (ADR-0004). Datasets here are for measurement
   only.

## Model inventory (the six shipped files)

| File | Stage | Wired operating point today |
|---|---|---|
| face_detection_yunet_2023mar.onnx | detection | score threshold, 320x240 input, stage 1 |
| blaze_face_short_range.onnx | detection rescue | runs only on YuNet miss, stage 2 |
| face_landmark.onnx | dense landmarks (478) + rescue alignment | YuNet-crop pipeline |
| glintr100.onnx | recognition, 512-D ArcFace | grant/deny cosine thresholds per modality |
| liveness_vit.onnx | RGB PAD, deny-only | deny line 0.55, 5-frame-median vote (ADR-0013) |
| flir.onnx | IR PAD, deny-only | deny line 0.9, lit-phase frames (ADR-0013) |

face_landmarks_detector.tflite is the parity reference for the mesh, not a
seventh model.

## Validation matrix

| Track | Shipped model(s) | Datasets | Protocol | Metrics, calibration decision |
|---|---|---|---|---|
| Detection | YuNet + BlazeFace | WIDER FACE (train+val, official splits); full-frame IR sets (CBSR, Oulu) for IR-grey behavior | Official WIDER AP eval at irlume operating scale; cascade rescue measurement at scale | AP Easy/Med/Hard; recall at operating FPPI; rescue rate. Decides: cascade switch point, score threshold, input resolution |
| Landmarks | face_landmark.onnx | WFLW (10k), 300W, AFLW2000-3D | Through irlume's YuNet-crop pipeline AND standalone, mirroring bench_cascade.py | NME eye-normalized overall + per-region (eyes, brows, nose, mouth, contour, iris). Decides: rescue-alignment reliability, iris fitness |
| Recognition | glintr100.onnx | LFW, CFP-FP, AgeDB-30, CALFW, CPLFW (RGB); CBSR, Oulu-CASIA, Tufts (NIR) | Full irlume pipeline (detect, align, 112 crop, embed); standard pair protocol per set | 10-fold acc, EER, TAR at FAR 1e-3 to 1e-1, threshold-to-FAR table. Decides: grant/deny cosine thresholds per modality |
| RGB PAD | liveness_vit.onnx | Full CelebA-Spoof (~625k images, 10 attack species), CASIA-FASD, OULU-NPU (video) | m96 crop matching irlume feed; 5-frame-median voting emulated on video | APCER/BPCER at the wired 0.55 line; ROC/AUC; per-species breakdown. Decides: deny threshold, coverage-gap map (phone-at-distance is an explicit measured row) |
| IR PAD | flir.onnx | CBSR NIR and Oulu-CASIA NIR over all subjects, superseding the earlier 197-identity sample | Lit-phase frames per ADR-0013 | TPR at the wired 0.9 line; ROC; genuine-failure regimes (dim, sun). Decides: threshold, phase gating |

Cross-cutting rule: replacement candidates (license-clean only, for example
OpenCV Zoo detector variants) run the same protocol in the same table. Nothing
measured on research-only datasets produces shipped weights.

## Infrastructure (archhost)

- Data root: ~/datasets/<name>/ per dataset, each with MANIFEST.sha256 and
  PROVENANCE.md (source URL, license terms, download date, mirror identity).
  Mirror identity is recorded because the benchmarks README documents that
  mirror-vs-canonical differences change numbers.
- Storage: archives deleted after extraction. Budget 60 to 90 GB landed against
  148 GB free. CelebA-Spoof (~40 to 60 GB extracted) is the largest item.
- Python: uv-managed CPython 3.12 venv at ~/venvs/bench (system Python 3.14 is
  too new for onnxruntime wheels). Packages: onnxruntime-gpu (CUDA provider,
  RTX 3060), opencv-python, numpy, huggingface_hub, requests, tqdm.
- Fetcher: benchmarks/fetch_data.py, resumable (HTTP Range) downloads from
  Kaggle REST (Bearer auth) and HuggingFace hub, sha256-verified against
  manifests, driven by a per-dataset spec table.
- Credentials (installed and verified 2026-08-30, chmod 600, on archhost and
  the ASUS workstation): Kaggle new-style API token at ~/.kaggle/api_token
  (verified HTTP 200 via Bearer on api/v1), HuggingFace token at
  ~/.cache/huggingface/token (user archledger, fine-grained). No secret values
  are recorded anywhere in the repo or shared memory.
- Repo flow: all scripts and results land through the normal PR convention
  (worktree branch, GPG + DCO sign-off reading exactly Signed-off-by:
  Wisbendji Fimerlus <archledger236@gmail.com>, zero em dashes, CI green).

## Deliverables

- New scripts in benchmarks/: fetch_data.py, bench_detection_wider.py,
  bench_landmarks_wflw.py, bench_recog_suite.py, bench_pad_rgb_celeba.py,
  bench_pad_oulu.py, bench_pad_ir_scaled.py.
- Shared evaluation utilities (crop, pair construction, threshold parsing) get
  unit tests per the repo quality bar; the bench scripts stay
  measurement-only, like the existing ones.
- Committed results-*.json and results-*.log per track.
- docs/research/2026-08-30-model-calibration-campaign.md master report plus
  per-track narratives. Every headline number traces to a committed result
  file.

## Phases (each ends with committed results before the next starts)

1. Phase 0: venv, fetcher, WIDER FACE download, smoke run.
2. Phase 1: detection + landmarks tracks.
3. Phase 2: recognition suite.
4. Phase 3: PAD tracks, CelebA-Spoof last.
5. Phase 4: calibration synthesis. Threshold-sweep tables become
   evidence-backed PRs. Threshold constants change only through normal PR
   review. Any replacement model additionally requires the models-vN release
   flow (new release, SHA256SUMS regeneration, four pinned hash locations) and
   explicit user approval.

## User gates

- Dataset bandwidth spend (per-dataset download start, especially CelebA-Spoof).
- Any threshold change PR.
- Any shipped-model swap.

## Risks and mitigations

- Dataset availability: some sets live only as community mirrors of variable
  fidelity, and Tufts is request-form gated (reuse the earlier copy if it
  survives, otherwise re-request before Phase 2). Mitigation: per-set
  PROVENANCE.md, sha256 manifests, mirror identity recorded next to every
  result, preference for the exact Kaggle mirrors the committed numbers used.
- Kaggle/HF rate limits on 100+ GB pulls. Mitigation: resumable downloads,
  off-peak bulk runs, per-dataset user gate before the whale sets.
- onnxruntime wheel availability: pinned to Python 3.12 via uv, CUDA optional
  (CPU gives identical accuracy).
- PAD model training data is undocumented by their publishers; measurements on
  attack datasets are for calibration of deny-only thresholds under ADR-0013,
  not claims of certified anti-spoofing strength.
- Storage pressure on archhost: archives deleted post-extract; dataset
  directories can be pruned phase by phase since later phases do not re-read
  earlier sets (results are committed).

## Success criteria

- Every track produces committed machine-readable results on its datasets with
  a documented protocol a reviewer can reproduce.
- At least one concrete calibration recommendation per model, accepted or
  declined with evidence, tracked as PRs or explicit declines in the master
  report.
- A replacement-candidate table per track with a clear ship-or-not verdict
  honoring the clean-BOM bar.
- The known RGB PAD coverage gap (phone at login distance) has a measured row.

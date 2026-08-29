# Model Calibration Phase 1 Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Produce the detection and landmarks calibration evidence: official WIDER FACE AP at irlume's operating point plus threshold and resolution sweeps and the cascade rescue measurement, IR-grey detection behavior on CBSR and Oulu NIR, and landmark accuracy (eye NME, anchor NME, alignment quality) on WFLW, 300W, and AFLW2000.

**Architecture:** Extends the Phase 0 layout. New registry entries ride the existing fetcher. AP evaluation and landmark scoring live in testable pure modules (`wider_ap.py`, `landmark_score.py`); the bench scripts stay thin measurement drivers. All execution on archhost (venv `~/venvs/bench`, code `~/irlume-bench/`, datasets `~/datasets/`).

**Tech Stack:** Same as Phase 0 (Python 3.12, onnxruntime-gpu 1.27.0 CUDA, OpenCV, requests, pytest).

**Spec:** `docs/superpowers/specs/2026-08-30-model-calibration-campaign-design.md` (Detection and Landmarks rows of the validation matrix).

## Global Constraints

- Zero em dashes (U+2014) in every file and commit message.
- DCO trailer exactly: `Signed-off-by: Wisbendji Fimerlus <archledger236@gmail.com>`. Repo enforces GPG; on pinentry timeout report BLOCKED, never `--no-gpg-sign`.
- Never print token values; auth failures report HTTP status only.
- The user gates every dataset download start. This phase's sets: WFLW ~0.76 GB (Kaggle), 300W ~2.1 GB (HF), AFLW2000 ~87 MB (Kaggle), CBSR NIR ~1.2 GB (Kaggle), Oulu-CASIA NIR ~1.2 GB (Kaggle). Ask once per dataset with exact size before fetching.
- irlume's real YuNet operating point is INPUT_SIZE 640 square letterbox, SCORE_THRESHOLD 0.6 (crates/irlume-vision/src/detect.rs:19-20). All "operating point" measurements use these values; sweeps bracket them.
- Research-only datasets are measurement-only; nothing derived ships.
- Work on branch `calib/phase1` (stacked on `docs/calibration-campaign` @ 9007b190), worktree `/home/wisbfime/irlume/.worktrees/calib-spec`.
- Kaggle-sourced specs define exactly ONE archive file (v1 REST downloads the whole dataset per call); the fetcher enforces this (Task 2).
- archhost venv python: `/home/archledger/venvs/bench/bin/python` (absolute path; uv not on non-interactive PATH).

---

### Task 1: Registry additions (5 datasets)

**Files:**
- Modify: `benchmarks/datasets.py`
- Test: `benchmarks/tests/test_datasets.py`

**Interfaces:**
- Consumes: Phase 0 `datasets.py` (DatasetSpec, DatasetFile, _DATASETS dict)
- Produces: `get_dataset` names `wflw`, `300w`, `aflw2000`, `cbsr_nir`, `oulu_casia_nir`, each kaggle-sourced one being a single-file spec with `path="kaggle-archive.zip"`, `extract=True`.

- [ ] **Step 1: Write the failing tests** (append to `benchmarks/tests/test_datasets.py`)

```python
def test_kaggle_specs_are_single_archive():
    for name in list_datasets():
        spec = get_dataset(name)
        if spec.source == "kaggle":
            assert len(spec.files) == 1, f"{name} must be a single kaggle archive"
            assert spec.files[0].path == "kaggle-archive.zip"
            assert spec.files[0].extract


def test_new_landmark_and_ir_entries():
    wflw = get_dataset("wflw")
    assert wflw.source == "kaggle"
    assert wflw.repo == "mrriandmstique/wflw-wider-facial-landmarks-in-the-wild"
    three = get_dataset("300w")
    assert three.source == "hf"
    assert three.repo == "quoctai219/300W"
    assert three.files[0].path == "300w_dataset.zip"
    aflw = get_dataset("aflw2000")
    assert aflw.repo == "mohamedadlyi/aflw2000-3d"
    cbsr = get_dataset("cbsr_nir")
    assert cbsr.repo == "gpreda/cbsr-nir-face-dataset"
    oulu = get_dataset("oulu_casia_nir")
    assert oulu.repo == "aryanbaibaswata/oulu-casia"
    for spec in (wflw, three, aflw, cbsr, oulu):
        assert spec.provenance_url
        assert spec.license_note
        assert spec.notes
```

- [ ] **Step 2: Run to verify RED**: `.venv-bench/bin/pytest benchmarks/tests/test_datasets.py -q` expect FAIL (KeyError wflw).

- [ ] **Step 3: Add the five entries** to `_DATASETS` (exact refs above; each kaggle entry one DatasetFile `kaggle-archive.zip` with size_hint: wflw 760_000_000, aflw2000 87_000_000, cbsr_nir 1_200_000_000, oulu_casia_nir 1_200_000_000; 300w one DatasetFile `300w_dataset.zip` size 2_140_000_000). license_note for the NIR sets must state research-only terms per benchmarks/README.md (CBSR and Oulu: research/education only; Tufts request-form precedent noted). provenance_url = the kaggle dataset page or HF page. notes must record: mirror identity matters (benchmarks/README.md), Oulu layout `Oulu_CASIA_NIR_VIS/NI/<lighting>/<subject>/`, CBSR bmp images, WFLW test split 2500 images with 98-pt txts, 300W zip is the full canonical set, AFLW2000 ships 2000 jpgs + .mat annotations.

- [ ] **Step 4: Run to verify GREEN** (7 tests in file) then commit `bench: registry entries for landmark and nir sets`.

---

### Task 2: Fetcher kaggle single-archive enforcement

**Files:**
- Modify: `benchmarks/fetch_data.py`
- Test: `benchmarks/tests/test_fetch_data_guard.py`

**Interfaces:**
- Consumes: datasets.get_dataset
- Produces: `validate_spec(spec)` raising SystemExit when a kaggle spec has more than one file; called at the top of download_dataset.

- [ ] **Step 1: Failing test**

```python
import pytest

from datasets import DatasetFile, DatasetSpec, get_dataset
from fetch_data import validate_spec


def _spec(source, files):
    return DatasetSpec(
        name="x", source=source, repo="o/d", files=tuple(files),
        license_note="l", provenance_url="https://example.com", notes="n",
    )


def test_kaggle_multi_file_rejected():
    with pytest.raises(SystemExit):
        validate_spec(_spec("kaggle", [
            DatasetFile(path="a.zip"), DatasetFile(path="b.zip"),
        ]))


def test_kaggle_single_file_ok():
    validate_spec(_spec("kaggle", [DatasetFile(path="kaggle-archive.zip")]))


def test_real_kaggle_specs_pass():
    for name in ["wflw", "aflw2000", "cbsr_nir", "oulu_casia_nir"]:
        validate_spec(get_dataset(name))


def test_hf_multi_file_ok():
    validate_spec(get_dataset("wider_face"))
```

- [ ] **Step 2: RED** (ImportError validate_spec), **Step 3: implement** `validate_spec` (2-line rule + clear message), call it first thing inside `download_dataset`. **Step 4: GREEN** all 4 + suite. **Step 5: commit** `bench: enforce kaggle single-archive spec rule`.

---

### Task 3: Official WIDER AP evaluator (`wider_ap.py`)

**Files:**
- Create: `benchmarks/wider_ap.py`
- Test: `benchmarks/tests/test_wider_ap.py`

**Interfaces:**
- Produces (Task 4 consumes):
  - `parse_val_gt(path: Path) -> dict[str, list[dict]]` keyed by the GT's relative image path; each box dict: `box` (x1,y1,x2,y2 floats), `invalid` (bool from the GT invalid column)
  - `iou(a, b) -> float`
  - `evaluate_image(preds: list[tuple[float, list[float]]], gt: list[dict], iou_thr: float = 0.5) -> tuple[int, int, int]` returns (tp, fp, n_gt_valid): greedily match highest-score preds to non-invalid GT by IoU >= thr, one GT once; unmatched pred = fp; invalid GT never matched and not counted
  - `voc_ap(scores: list[float], tps: list[int], total_gt: int) -> float` all-point interpolated AP (PASCAL 2010 style), preds given sorted descending by score
  - `evaluate(preds_by_image, gt_by_image) -> dict` returns {"ap": float, "tp": int, "fp": int, "n_gt": int}; caller aggregates per split

- [ ] **Step 1: Failing tests** covering: parse_val_gt on a 3-line synthetic GT snippet (image line then box lines, blank separator, invalid flag honored); iou identity/overlap/disjoint; evaluate_image perfect match = (n, 0, n); duplicate detection on same GT = second is fp; invalid GT excluded from both tp and n_gt; voc_ap perfect ranking = 1.0, reversed ranking < 0.5, all-fp = 0.0.
- [ ] **Step 2: RED. Step 3: implement. Step 4: GREEN** (new tests + full suite). **Step 5: commit** `bench: official-protocol WIDER AP evaluator`.

---

### Task 4: Letterbox + full detection bench (`bench_detection_wider.py` extension)

**Files:**
- Modify: `benchmarks/bench_detection_wider.py` (add modes; keep --smoke behavior identical)
- Modify: `benchmarks/wider_ap.py` only if a defect surfaces (no behavior drift)
- Create: `benchmarks/results-detection-wider.json` (committed output)

**Interfaces:**
- Consumes: wider_ap (Task 3), models dir (yunet + blaze_face_short_range.onnx), `~/datasets/wider_face`
- Produces: results-detection-wider.json schema:
  `{"runtime": {...}, "operating_point": {"input": 640, "score_threshold": 0.6}, "ap": {"easy": f, "medium": f, "hard": f, "tp": i, "fp": i, "n_gt": i, "images": 3226}, "sweep": [{"input": i, "score_threshold": s, "ap_hard": f, "recall_at_op_fppi": f}...], "cascade": {"val": {"yunet_recall": f, "cascade_recall": f, "rescues": i}, "train_sample": {...}}, "notes": [...]}`

- [ ] **Step 1: Failing tests for the letterbox math** (append to `benchmarks/tests/test_wider_ap.py` or a new test_letterbox.py):

```python
from letterbox import letterbox_params, restore_boxes


def test_letterbox_square_input_scales_long_side():
    sx, sy, pad_x, pad_y = letterbox_params(1280, 960, 640)
    assert sx == 0.5 and sy == 0.5
    assert pad_x == 0 and pad_y > 0


def test_restore_boxes_roundtrip():
    p = letterbox_params(1280, 960, 640)
    boxes = [[10.0, 10.0, 100.0, 100.0]]
    out = restore_boxes(boxes, p, orig_w=1280, orig_h=960)
    assert out[0][0] <= out[0][2] and out[0][1] <= out[0][3]
```

(Exact letterbox convention: square 640 canvas, uniform scale by the longer side, centered padding on the short side; letterbox_params returns (scale_x, scale_y, pad_x, pad_y) with restore undoing both.)

- [ ] **Step 2: RED for letterbox tests, implement `benchmarks/letterbox.py`, GREEN.**
- [ ] **Step 3: Extend the bench script** with modes `--ap`, `--sweep`, `--cascade` (all read/write the schema above; sweep runs a stratified 2000-image val sample: every k-th image of the sorted list; cascade measures recall with and without the BlazeFace rescue on YuNet misses, full val plus a 4000-image train sample). Detection at the operating point uses the 640 letterbox and 0.6 threshold. Per-image results print progress every 200 images.
- [ ] **Step 4: Deploy to archhost, run AP at operating point** (full 3,226-image val; expect minutes on the 3060), then sweep, then cascade. Fetch results back, sanity-check: easy AP >= hard AP (standard WIDER ordering), cascade recall >= yunet recall, rescue count > 0.
- [ ] **Step 5: commit** `bench: wider ap at operating point with sweep and cascade`.

---

### Task 5: IR-grey detection bench (`bench_detection_ir.py`)

**Files:**
- Create: `benchmarks/bench_detection_ir.py`
- Create: `benchmarks/results-detection-ir.json` (committed output)

**Interfaces:**
- Consumes: letterbox.py, cbsr_nir + oulu_casia_nir datasets, yunet
- Produces: schema `{"runtime": {...}, "cbsr": {"frames": i, "detected": i, "rate": f, "score_p50": f, "score_p10": f}, "oulu": {"per_lighting": [{"lighting": str, "frames": i, "rate": f}...], "overall": {...}}, "notes": [...]}`

- [ ] **Step 1: Write the script** (structure mirrors bench_detection_wider: YuNet at operating point over full frames, no GT exists so the output is detection rate + score distribution; Oulu grouped by its lighting directory names; CBSR flat over its subject dirs; cap at 4000 frames per dataset, stride-sampled, recorded in the notes).
- [ ] **Step 2: Local parse check** (`ast.parse`), deploy, **run on archhost** after the two NIR datasets are downloaded (see Task 7 ordering note).
- [ ] **Step 3: Sanity-check** (CBSR rate high, active-NIR; Oulu per-lighting rates must show dark-vs-strong spread or flat-high, either is informative; zero-rate datasets mean a path bug, stop and investigate).
- [ ] **Step 4: commit** `bench: ir-grey detection rates on cbsr and oulu nir`.

---

### Task 6: Landmark bench (`bench_landmarks.py`)

**Files:**
- Create: `benchmarks/landmark_score.py`
- Create: `benchmarks/bench_landmarks.py`
- Test: `benchmarks/tests/test_landmark_score.py`
- Create: `benchmarks/results-landmarks.json` (committed output)

**Interfaces:**
- Consumes: yunet + face_landmark.onnx (478-point mesh: output float32 [1,1434] reshaped 478x3 + faceflag), letterbox.py, wflw/300w/aflw2000 datasets
- Produces:
  - `landmark_score.py`: `nme(pred_pts, gt_eye_center_a, gt_eye_center_b, anchors_pred, anchors_gt) -> float` (mean anchor L2 error / inter-ocular distance); `mesh_eye_centers(mesh478) -> tuple[tuple[float,float], tuple[float,float]]` (iris centers: left mean of indices 468-472, right 473-477; fall back to eye-corner midpoints (33,133) and (362,263) if iris block degenerate); `ANCHOR_MESH_IDX = [33, 133, 362, 263, 61, 291, 1, 152]` with docstring naming them (left eye outer/inner, right eye inner/outer, mouth corners, nose tip, chin)
  - bench schema: `{"runtime": {...}, "per_dataset": {"wflw_test": {"images": i, "mesh_ok": i, "eye_nme_mean": f, "eye_nme_p90": f, "eye_nme_standalone_mean": f, "anchor_nme_mean": f, "align_iou_gain_mean": f, "n_fail_yunet": i, "n_fail_mesh": i}, "300w_test": {...}, "aflw2000": {...}}, "notes": [...]}`
- Protocol: YuNet (operating point) -> crop with 1.25x margin -> mesh; GT eye index sets are VERIFIED IN A TASK STEP before scoring (Step 2), then hard-coded as constants with a comment naming the source annotation file that pinned them. BOTH pipeline crops AND standalone GT-box crops are scored (the spec requires the comparison; standalone = mesh fed the GT box crop directly).

- [ ] **Step 1: Failing tests** for nme (identical points = 0; known synthetic = expected ratio), mesh_eye_centers (synthetic 478x3 array with iris block placed off-center; degenerate iris block falls back to corner midpoints), ANCHOR index bounds.
- [ ] **Step 2: GT eye-index verification step (executes once, on archhost or locally with a downloaded sample):** for each dataset, take the first 20 annotation files, compute per-index mean positions for candidate eye-index sets, and print the cluster geometry; pin the sets that satisfy: two tight clusters, one clearly left and one clearly right of the face midline, both above the mouth candidates. Record the pinned indices + the evidence line in the report. (68-pt schemes: standard left eye 36-41, right 42-47, eye center = corner mean; WFLW 98: derive per this step.)
- [ ] **Step 3: Implement + GREEN + run on archhost** (full WFLW test 2500, 300W test set as shipped, AFLW2000 2000), fetch results back, sanity: eye NME through the pipeline should land in the same decade as the committed 0.0273 CBSR number; n_fail_yunet/n_fail_mesh recorded per dataset.
- [ ] **Step 4: commit** `bench: landmark track with eye and anchor nme`.

Scope note (spec conflict resolution, ruled by the controller): the spec matrix lists per-region NME over eyes, brows, nose, mouth, contour, and iris. Cross-scheme correspondence (478-point mesh vs 98/68-point GT) is unambiguous only for the pinned anchors (eye corners, mouth corners, nose tip, chin) plus iris-informed eye centers. Brows, contour, and iris region rows are therefore DEFERRED to the Phase 4 synthesis, where the correspondence question can be settled against measured need; this plan does not silently drop them, it reports the achievable anchor set now.

---

### Task 7: Downloads (USER GATE, interleaved before Tasks 4-6 runs)

**Files:** none (host state only)

- [ ] **Step 1:** Ask the user per dataset (exact sizes above), then fetch+verify each on archhost with the fetcher (`download <name> --root ~/datasets`), verifying: WFLW test annotation txt count + image count match (2500 expected), 300W zip extracts with its shipped test set, AFLW2000 has 2000 jpgs + .mat files, CBSR bmps present, Oulu has the NI/<lighting> layout. Record every verification in the phase report.
- [ ] **Step 2:** Register MANIFEST/PROVENANCE existence per dataset (fetcher writes them; spot-check).

---

### Task 8: Phase 1 report + calibration table

**Files:**
- Create: `docs/research/2026-08-30-detection-landmarks-phase1.md`
- Modify: `docs/superpowers/plans/2026-08-30-model-calibration-phase0.md` only if a Phase 0 claim needs correction (none expected)

- [ ] **Step 1:** Write the report: per-track results with exact numbers traceable to the committed results files, the calibration recommendation table (YuNet score threshold, input resolution, cascade switch behavior, IR-grey detection posture, landmark alignment fitness), and the replacement-candidate note (none evaluated this phase; candidates join Phase 4 synthesis).
- [ ] **Step 2:** Zero em dashes check, commit `docs: phase 1 detection and landmarks calibration report`.

---

## Phase 1 exit criteria

- results-detection-wider.json, results-detection-ir.json, results-landmarks.json committed; report written.
- Every recommendation in the report traces to a committed number.
- All downloads user-gated and PROVENANCE'd.
- Suite green (`pytest benchmarks/tests -q`), zero new em dashes, every commit GPG + DCO.

## Out of scope for Phase 1

- Recognition suite (Phase 2), PAD tracks (Phase 3), threshold-change PRs and replacement candidates (Phase 4).

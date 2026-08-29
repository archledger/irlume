# Model Calibration Phase 2 Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Produce the recognition calibration evidence: AuraFace (glintr100.onnx) verification accuracy, EER, TAR@FAR, and threshold-to-FAR calibration tables per modality on LFW, CFP(FW), AgeDB-30, CALFW, CPLFW (RGB) and CBSR + Oulu-CASIA NIR, through irlume's own embedding path.

**Architecture:** New pure metrics module (`verification_metrics.py`) under TDD; one bench script (`bench_recog_suite.py`) with lanes per modality; registry + fetcher reuse from Phases 0-1. Execution on archhost in the established layout.

**Tech Stack:** Same as Phases 0-1.

**Spec:** `docs/superpowers/specs/2026-08-30-model-calibration-campaign-design.md` (Recognition row).

## Global Constraints

- Zero em dashes (U+2014) everywhere; DCO trailer exactly `Signed-off-by: Wisbendji Fimerlus <archledger236@gmail.com>`; GPG-signed commits (BLOCKED on pinentry timeout); no `--no-gpg-sign`.
- Never print token values.
- User gates every download. New sets: aligned-112 bundle (AgeDB-30 + CALFW + CPLFW + LFW aligned) ~1.4 GB Kaggle, CFPW ~86 MB Kaggle, LFW ~112 MB Kaggle. CBSR + Oulu NIR reuse the Phase 1 downloads.
- The alignment/embedding path MUST reproduce what the committed benchmark numbers used: read `benchmarks/bench_faceid.py` and `benchmarks/bench_nir_ext.py` FIRST and reuse their pipeline (they produced results-lfw.json 99.03% and results-nir_results.json). If the old scripts' approach conflicts with irlume's current Rust pipeline, note the divergence in the report and follow the old scripts (continuity of the committed numbers).
- Work on branch `calib/phase2` stacked on `calib/phase1`; after #599 merges, rebase `--onto origin/main <phase1-head>` (the Phase 1 pattern, clean skip expected).
- archhost venv python: `/home/archledger/venvs/bench/bin/python`.

## Dataset decisions (controller rulings, execute as written)

- Aligned bundle: kaggle `yakhyokhuja/agedb-30-calfw-cplfw-lfw-aligned-112x112`, single ~1.4 GB archive containing AgeDB-30, CALFW, CPLFW, LFW in aligned 112x112 form WITH their standard pair lists. This lane gives published-comparable numbers (the standard protocol for these sets).
- CFPW: kaggle `chinafax/cfpw-dataset` (~86 MB). VERIFY at extraction: 500 identities, frontal/profile structure, protocol folds. If the mirror is short of the official CFP protocol (7000 pairs, 10 folds), record the shortfall and score what exists, labeled honestly (reviewer precedent: mirror reality is recorded, never papered over).
- LFW: kaggle `jessicali9530/lfw-dataset` (the benchmarks README's documented source). VERIFY it contains the deepfunneled alignment (the committed 99.03% is lfw-deepfunneled; the README warns alignment variants are not comparable). The archhost `~/datasets-recog/lfw` copy is an HF-style restructure (train/ + metadata.csv), NOT deepfunneled: do not reuse it. If the Kaggle mirror lacks deepfunneled, fetch the deepfunneled tarball from its canonical public source and record provenance accordingly.
- Tufts NIR: the archhost copy is GONE (verified 2026-08-30) and Tufts is request-form gated. NIR cross-domain coverage rides on CBSR + Oulu this phase; Tufts returns only if the user re-requests it. Record this in the report.
- NIR pairs: CBSR ships gallery/probe ground truth (verified in the Phase 1 download); Oulu has no canonical pair list, so build a seeded deterministic protocol (10,000 pairs: 5,000 genuine, 5,000 impostor, subject-disjoint folds) pinned in the report and reproducible from the seed.

---

### Task 1: Registry entries (3 datasets)

**Files:**
- Modify: `benchmarks/datasets.py`
- Test: `benchmarks/tests/test_datasets.py`

**Interfaces:**
- Produces: `get_dataset` names `lfw`, `cfpw`, `aligned_fr_bundle`, all kaggle single-archive specs (`kaggle-archive.zip`).

- [ ] **Step 1: Failing tests** (append): `test_new_recognition_entries` asserting the three refs above + required fields; `test_kaggle_specs_are_single_archive` already covers the invariant.
- [ ] **Step 2: RED. Step 3: implement** (size hints: lfw 112_000_000, cfpw 86_000_000, aligned_fr_bundle 1_400_000_000; notes record: LFW must contain deepfunneled (verify at download), CFPW official protocol counts to verify, aligned bundle = published-comparable lane). **Step 4: GREEN** (suite + new). **Step 5: commit** `bench: recognition registry entries`.

---

### Task 2: Verification metrics (`verification_metrics.py`)

**Files:**
- Create: `benchmarks/verification_metrics.py`
- Test: `benchmarks/tests/test_verification_metrics.py`

**Interfaces:**
- Produces (Task 3-5 consume):
  - `eer(scores_genuine: list[float], scores_impostor: list[float]) -> float` (equal error rate over the pooled similarity distributions, cosine scores in [-1,1])
  - `tar_at_far(scores_genuine, scores_impostor, far: float) -> float` (threshold = impostor quantile at FAR, TAR = genuine fraction above it)
  - `far_threshold_table(scores_genuine, scores_impostor, fars: list[float]) -> list[dict]` rows {"far": f, "threshold": t, "tar": v}
  - `fold_accuracy(pairs: list[tuple[float, int]], threshold: float) -> float` (accuracy of cosine > threshold vs label)
  - `ten_fold(scores: list[float], labels: list[int], folds: list[int]) -> dict` (per-fold accuracy at the per-fold optimal threshold, mean and sd; the LFW-style protocol)
- [ ] **Step 1: Failing tests** with hand-computed synthetic cases (separable distributions -> EER 0; identical distributions -> EER ~0.5; known quantile -> exact TAR; fold accuracy exact fractions).
- [ ] **Step 2: RED. Step 3: implement. Step 4: GREEN** + full suite. **Step 5: commit** `bench: verification metrics module`.

---

### Task 3: RGB lane (`bench_recog_suite.py`)

**Files:**
- Create: `benchmarks/bench_recog_suite.py`
- Create: `benchmarks/results-recognition.json` (committed output)

**Interfaces:**
- Consumes: verification_metrics.py, models dir (glintr100.onnx), the embedding/alignment approach from bench_faceid.py (READ IT FIRST, reuse its functions or copy its exact preprocessing)
- Produces: schema `{"runtime": {...}, "rgb": {"lfw": {"acc10fold": f, "eer": f, "tar_table": [...], "pairs": 6000}, "agedb30": {...}, "calfw": {...}, "cplfw": {...}}, "threshold_calibration": {"rgb": {"grant_recommendation": f, "far_at_grant": f, "table": [...]}, "nir": {...}}, "notes": [...]}`

- [ ] **Step 1: Write the lane**: load pairs from each set's shipped pair list (LFW pairs.txt 10-fold 6000; AgeDB-30/CALFW/CPLFW pair lists inside the aligned bundle), embed via the bench_faceid.py path, score cosine, run ten_fold + eer + far_threshold_table.
- [ ] **Step 2: Local parse check, deploy, run on archhost** (the aligned bundle serves AgeDB-30/CALFW/CPLFW + the aligned-LFW cross-check; lfw deepfunneled serves the continuity number vs the committed 99.03%; expect the continuity number to land within run-to-run noise of 99.03 or EXPLAIN the delta in notes).
- [ ] **Step 3: Sanity + commit** `bench: rgb recognition lane`.

---

### Task 4: CFP lane (frontal-profile)

**Files:**
- Modify: `benchmarks/bench_recog_suite.py` (add `--cfp` lane)

**Interfaces:**
- Produces: `rgb.cfpw` row (frontal-profile verification, 10 folds per the shipped protocol; accuracy + EER + TAR table; pose-gap analysis = error rate on frontal-profile vs frontal-frontal pairs)

- [ ] **Step 1: Implement the CFPW protocol reader** (verify 500 IDs / folds at extraction; if short, score what exists with honest labeling). **Step 2: Run + merge into results JSON. Step 3: commit** `bench: cfp frontal-profile lane`.

---

### Task 5: NIR lane (CBSR + Oulu)

**Files:**
- Modify: `benchmarks/bench_recog_suite.py` (add `--nir` lane)
- Modify: `benchmarks/results-recognition.json` (merge)

**Interfaces:**
- Produces: `nir.cbsr` row (gallery/probe per the shipped ground truth), `nir.oulu` row (seeded 10k-pair protocol), `threshold_calibration.nir` (grant/deny cosine thresholds per modality)

- [ ] **Step 1: Implement**: CBSR gallery/probe per its ground-truth files; Oulu seeded protocol (document the seed + construction in JSON notes); NIR embedding path from bench_nir_ext.py. **Step 2: Run + merge. Step 3: commit** `bench: nir recognition lane with calibration tables`.

---

### Task 6: Downloads (USER GATE, before Task 3 runs)

- [ ] **Step 1:** Ask per dataset: aligned bundle ~1.4 GB, CFPW ~86 MB, LFW ~112 MB (~1.6 GB total).
- [ ] **Step 2:** Fetch + verify each on archhost (LFW deepfunneled present; CFPW protocol counts; aligned bundle pair lists present); MANIFEST + PROVENANCE per set.

---

### Task 7: Phase 2 report + calibration table

**Files:**
- Create: `docs/research/2026-08-30-recognition-phase2.md`

- [ ] **Step 1:** Report: per-set table (acc/EER/TAR@1e-3/1e-2/1e-1), the threshold-to-FAR calibration tables per modality with grant/deny recommendations, continuity vs committed numbers (LFW 99.03, CBSR EER 0.77, Tufts-absent note), alignment-lane comparison note (deepfunneled vs aligned-112 vs irlume-pipeline), limitations (mirror provenance per set, seeded Oulu protocol).
- [ ] **Step 2:** Zero em dashes, commit `docs: phase 2 recognition calibration report`.

## Phase 2 exit criteria

- results-recognition.json committed with rgb + cfpw + nir + threshold_calibration sections; report written; suite green; downloads gated + PROVENANCE'd; every recommendation traceable.

## Out of scope for Phase 2

- PAD tracks (Phase 3), threshold-change PRs and replacement candidates (Phase 4), Tufts re-acquisition (user decision).

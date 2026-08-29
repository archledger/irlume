# Model Calibration Phase 3 Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Produce the PAD calibration evidence: RGB PAD (liveness_vit.onnx) APCER/BPCER at the wired deny line with full ROC and per-species breakdown on full CelebA-Spoof plus CASIA-FASD and OULU-NPU, and IR PAD (flir.onnx) at the 0.9 wired line on CBSR + Oulu NIR over all subjects with genuine-failure regimes.

**Architecture:** New pure scoring module (`pad_score.py`) under TDD; two bench scripts (`bench_pad_rgb.py`, `bench_pad_ir.py`); the CelebA-Spoof whale arrives as HF parquet shards read directly by the bench (no zip extraction, per-file streaming fits the disk).

**Tech Stack:** Same as Phases 0-2 plus pyarrow (Apache-2.0) and huggingface_hub (Apache-2.0), controller-approved for the measurement venv only.

**Spec:** `docs/superpowers/specs/2026-08-30-model-calibration-campaign-design.md` (RGB PAD and IR PAD rows).

## Global Constraints

- Zero em dashes (U+2014); DCO trailer exactly `Signed-off-by: Wisbendji Fimerlus <archledger236@gmail.com>`; GPG-signed commits (BLOCKED on pinentry timeout); never `--no-gpg-sign`.
- Never print token values.
- User gates every download. This phase: CASIA-FASD ~2.2 GB (Kaggle immada/casia-fasd), OULU-NPU ~0.5-2.8 GB (Kaggle, decision rule in Task 1), CelebA-Spoof HF parquet ~60-75 GB (the whale).
- READ THE RUST CONSTANTS FIRST (the Phase 1 lesson): the wired RGB PAD line is `VIT_PAD_THRESHOLD = 0.55` with a 5-frame-median vote (crates/irlume-vision/src/lib.rs:350-354); the ViT feed is the m96 convention (bbox expanded by 96/112 of w/h per side, CLAMPED no fill, bilinear 224, RGB, (px/255-0.5)/0.5, CHW; P(spoof) = softmax index 1, lib.rs:1316-1370). Find and read the PadIr preprocessing (lib.rs:1516+) before writing the IR lane. Grep for any threshold changes in irlume-auth before trusting 0.55/0.9 as the wired lines.
- Metrics semantics (ISO-style, pinned): with s = P(spoof): APCER = fraction of ATTACK (spoof) samples with s < threshold (missed attacks); BPCER = fraction of GENUINE samples with s >= threshold (false rejections). At a wired line T, attacks caught = s >= T.
- Work on branch `calib/phase3` stacked on `calib/phase2`; after #599 merges, rebase the whole stacked series onto main (the established pattern).
- archhost venv python: `/home/archledger/venvs/bench/bin/python`. Disk check before the whale: `df -h /` must show >= 80G free; if not, prune per the Task 5 ruling.

---

### Task 1: Registry entries + snapshot fetch mode

**Files:**
- Modify: `benchmarks/datasets.py`
- Modify: `benchmarks/fetch_data.py`
- Modify: `benchmarks/requirements-bench.txt` (append pyarrow>=14, huggingface_hub>=0.30)
- Test: `benchmarks/tests/test_datasets.py`

**Interfaces:**
- Produces: registry names `casia_fasd` (kaggle immada/casia-fasd, single archive, 2_200_000_000 hint), `oulu_npu` (kaggle mizaku/oulu-npu-test, 500_000_000 hint; notes carry the decision rule: if extraction shows test-split-only content and the bench needs sessions breadth, fetch minhtranv/oulu-npu-w-depth 2_760_000_000 as the fallback and record which was used), and `celeba_spoof_hf` (hf repo Ar4ikov/celebA_spoof, `source="hf"`, files = empty tuple, notes: parquet shard snapshot lane, read via snapshot_download allow_patterns data/*).
- `fetch_data.py` gains `download <name> --snapshot`: when the spec has zero files and source hf, use huggingface_hub snapshot_download(repo_id, repo_type="dataset", local_dir=root/name, allow_patterns="data/*", token=load_token(...)) then write PROVENANCE.md + MANIFEST.sha256 over the downloaded shard files.

- [ ] **Step 1: Failing tests** (registry assertions for the three names; a fetch_data guard test that --snapshot rejects specs with files, and non-hf specs).
- [ ] **Step 2: RED. Step 3: implement. Step 4: GREEN** (suite + new). **Step 5: commit** `bench: pad registry entries and hf snapshot fetch mode`.

---

### Task 2: PAD scoring module (`pad_score.py`)

**Files:**
- Create: `benchmarks/pad_score.py`
- Test: `benchmarks/tests/test_pad_score.py`

**Interfaces:**
- Produces (Tasks 3-4 consume):
  - `apcer_bpcer(scores_attack: list[float], scores_genuine: list[float], threshold: float) -> dict` {"apcer": f, "bpcer": f} per the pinned ISO semantics in Global Constraints
  - `roc_auc(scores_attack, scores_genuine) -> float` (rank-based, tie-handled)
  - `species_breakdown(per_sample: list[tuple[str, float]], threshold: float) -> list[dict]` rows {"species": s, "n": i, "caught": i, "tpr": f} (TPR = fraction with s >= threshold)
  - `median_vote(scores: list[float]) -> float` (the 5-frame-median emulation: statistics.median)
  - `vote_video(frames: list[list[float]]) -> list[float]` (per-time-step rolling median of the last N=5 scores, matching the ADR-0013 vote semantics; window shorter than 5 uses what exists)
- [ ] **Step 1: Failing tests** with hand-computed cases (perfect separation -> APCER 0/BPCER 0 at sane thresholds; known small mixes -> exact fractions; tie handling in AUC; rolling median on a synthetic 7-frame sequence).
- [ ] **Step 2: RED. Step 3: implement. Step 4: GREEN** + suite. **Step 5: commit** `bench: pad scoring module`.

---

### Task 3: RGB PAD lane (`bench_pad_rgb.py`)

**Files:**
- Create: `benchmarks/bench_pad_rgb.py`
- Create: `benchmarks/results-pad-rgb.json` (committed output)

**Interfaces:**
- Consumes: pad_score.py, letterbox.py, yunet + liveness_vit.onnx, the three datasets
- Produces schema: `{"runtime": {...}, "wired": {"vit_threshold": 0.55, "vote_window": 5}, "celeba_spoof": {"images": i, "scored": i, "detected": i, "apcer": f, "bpcer": f, "auc": f, "per_species": [...], "threshold_sweep": [...]}, "casia_fasd": {...}, "oulu_npu": {"clips": i, "voted": {...}, "per_session": [...]}, "notes": [...]}`
- Protocol: YuNet at the 640 letterbox operating point -> best detection -> m96 crop convention -> P(spoof); CelebA-Spoof labels give live vs 10 attack species (discover the parquet schema first with a one-off print step, pin the column names in a code comment); CASIA-FASD real/attack from its directory protocol; OULU-NPU per-video 5-frame-median voting (sample frames at a fixed stride recorded in notes).

- [ ] **Step 1: Write the lane** (parquet read via pyarrow streaming batches; decode bytes to BGR; resumable progress file every 5000 rows so a killed run resumes). 
- [ ] **Step 2: Local parse check, deploy, run** on archhost: CASIA-FASD first (smallest, validates the chain), OULU-NPU next, CelebA-Spoof LAST via nohup with polling (ViT-base at 224 on a 3060 over ~600k images is a multi-hour run; the resumable progress file makes interruption safe). Record wall time.
- [ ] **Step 3: Sanity**: CelebA-Spoof AUC should sit well above 0.5; the known-uncovered phone-at-distance class is NOT separately labeled in CelebA-Spoof (record that the per-species table covers the labeled species only); CASIA/OULU numbers plausible vs the deny-only design (documented banner measurements caught 100% at 0.55 on the fleet; academic-set numbers will differ and that is the finding).
- [ ] **Step 4: commit** `bench: rgb pad lane on celeba spoof casia and oulu`.

---

### Task 4: IR PAD lane (`bench_pad_ir.py`)

**Files:**
- Create: `benchmarks/bench_pad_ir.py`
- Create: `benchmarks/results-pad-ir.json` (committed output)

**Interfaces:**
- Consumes: pad_score.py, letterbox.py, yunet + flir.onnx (READ PadIr preprocessing in lib.rs first), cbsr_nir + oulu_casia_nir datasets (already on archhost)
- Produces schema: `{"runtime": {...}, "wired": {"flir_threshold": 0.9}, "cbsr": {"frames": i, "scored": i, "tpr_at_wired": f, "roc_auc": f, "threshold_sweep": [...]}, "oulu": {"per_lighting": [{"lighting": str, "tpr_at_wired": f, "score_p50": f}...], "overall": {...}}, "genuine_regimes": "cross-reference: no genuine-attack pairs exist in these sets; genuine-side behavior rides on the Phase 1 detection ceiling and the fleet measurements", "notes": [...]}`

- [ ] **Step 1: Write the lane** (both sets are BONA FIDE only: no IR attack data exists on disk, so this lane measures the false-rejection side (BPCER-analog: genuine frames flagged as spoof at 0.9) and score distributions, NOT attack TPR. The schema above is corrected accordingly: replace tpr_at_wired with "flagged_rate_at_wired" = fraction of genuine frames at/above the deny line; keep the sweep + per-lighting rows. State in notes that attack-side IR evidence remains the fleet/banner measurements, a spec-honest limitation).
- [ ] **Step 2: Run on archhost** (all subjects, superseding the 197-identity sample; Oulu grouped by lighting incl. Dark, where the dim-strobe genuine failure regime lives).
- [ ] **Step 3: Sanity**: flagged_rate near 0 on lit CBSR frames (the committed measurement was 1/3,940 above the line); Oulu Dark flagged_rate expected higher (the dim genuine failure regime) and that number is the finding.
- [ ] **Step 4: commit** `bench: ir pad lane on cbsr and oulu all subjects`.

---

### Task 5: Downloads (USER GATE, ordering: small -> whale)

**Files:** none (host state)

- [ ] **Step 1:** Ask per dataset: CASIA-FASD ~2.2 GB, OULU-NPU ~0.5-2.8 GB, CelebA-Spoof parquet ~60-75 GB. Whale gate includes the disk check (>= 80G free; prune ruling if needed: the Phase 1/2 raw sets wider_face, 300w, aligned_fr_bundle, cfpw, lfw may be deleted on archhost to free ~5.7G since their results are committed; CBSR + Oulu NIR MUST STAY, they feed Task 4).
- [ ] **Step 2:** Fetch + verify: CASIA-FASD real/attack dirs present; OULU-NPU decision rule applied (test-split-only vs fallback); CelebA-Spoof shards land via the snapshot lane, shard count + total bytes + parquet schema printout recorded; MANIFEST/PROVENANCE per set.

---

### Task 6: Phase 3 report + calibration table

**Files:**
- Create: `docs/research/2026-08-30-pad-phase3.md`

- [ ] **Step 1:** Report: RGB PAD table (per set: APCER/BPCER at the wired 0.55 line, AUC, per-species TPR table incl. which labeled species miss the line, sweep summary), the vote effect (OULU voted vs single-frame), IR PAD table (flagged rates at 0.9 per set per lighting, the Dark regime finding), the coverage statement (phone-at-distance not labeled in any public set; IR attack-side evidence remains fleet-only), and the calibration recommendations (keep/adjust the wired lines, all evidence-backed, changes only via Phase 4 PRs).
- [ ] **Step 2:** Zero em dashes, commit `docs: phase 3 pad calibration report`.

## Phase 3 exit criteria

- results-pad-rgb.json + results-pad-ir.json committed; report written; suite green; whale run resumable and completed or explicitly partial with committed partials labeled; downloads gated + PROVENANCE'd.

## Out of scope for Phase 3

- Threshold-change PRs, replacement candidates, cross-track synthesis (Phase 4).

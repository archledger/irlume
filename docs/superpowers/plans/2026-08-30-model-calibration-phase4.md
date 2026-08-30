# Model Calibration Phase 4 Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Close the calibration campaign: turn the Phase 1 to 3 evidence into (a) a runtime mechanism inventory that maps every wired constant to the evidence that does or does not cover it, (b) a threshold-synthesis decision document with one recommendation per decision, (c) replacement-candidate tables with ship-or-not verdicts per track (one new measurement: anti-spoof-mn3 on the committed PAD mirrors), and (d) the user-gate list of concrete PRs awaiting approval. No runtime code, no threshold change, and no shipped-model swap happens in this phase.

**Spec:** `docs/superpowers/specs/2026-08-30-model-calibration-campaign-design.md` (Phase 4 section): threshold tables become evidence-backed PRs only through normal review; any replacement model additionally needs the models-vN release flow and explicit user approval.

**Architecture:** Same as Phases 0 to 3: scripts under `benchmarks/`, execution on archhost (RTX 3060, ORT 1.27.0, cv2 5.0.0) via ssh + rsync, results committed as JSON, reports under `docs/research/`. The only new measurement reuses `bench_pad_rgb.py`'s protocol with a candidate model, so the comparison table shares detection, sweeps, and scoring semantics with the committed ViT numbers.

## Global Constraints

- Zero em dashes (U+2014) and en dashes (U+2013) in every deliverable. Grep before committing.
- DCO trailer exactly `Signed-off-by: Wisbendji Fimerlus <archledger236@gmail.com>` on every commit; GPG-signed.
- No runtime (crates/) changes, no threshold edits, no model swaps in this phase. Those are user-gated PRs listed by this phase, not executed by it.
- The mn3 artifact must match the recorded sha256 `c4c99af04603b62d7e44f6f4daeb33e0daeccc696008c0b1d62f6f5cebbb3262` before any run; a mismatch aborts the candidate row.
- Every number in the synthesis documents is copied from committed JSON or from committed docs (pad-results, models/README); where a figure is host-side-only it is labeled fleet-measurement, not public-set.
- Evidence-over-wording: where a claim can be committed as data (JSON field) it is; documents point at data.

---

### Task 1: Runtime mechanism inventory

**Files:**
- Create: `benchmarks/results-synthesis-phase4.json` (seeded in Task 2; this task produces its `mechanisms` section)

**Steps:**
- [ ] Read `crates/irlume-auth/src/lib.rs` + `crates/irlume-vision/src/lib.rs` and record, as a table: every decision constant that gates a grant or deny (rgb match threshold, ViT PAD 0.55 + vote 5, FLIR 0.9, IR centroid/center-edge floors, sequential skew budget if evidence-relevant), its consumer arm (RGB-primary, fusion, IR fallback, centroid), which spectrum feeds it, and which phase's evidence (if any) measured that consumption shape. Mark uncovered combinations explicitly (`no public-set evidence covers this path`).
- [ ] Verify by grep that the table names every comparison site of each constant (no aspiration entries).

### Task 2: Threshold synthesis decision document

**Files:**
- Create: `docs/research/2026-08-30-calibration-synthesis-phase4.md`
- Create: `benchmarks/results-synthesis-phase4.json` (`decisions` array)

**Steps:**
- [ ] One decision per row, each with: the wired value, the phase evidence (file + field), the recommended action (`keep` / `change via gated PR` + exact constant + value), the trade stated in FAR/TAR or flag-rate terms, and the risk of the change. Minimum set: RGB recognizer 0.45 (vs Phase 2's 0.35 row and the 0.6 NIR non-viability finding mapped onto the actual IR arms from Task 1), ViT 0.55 (Phase 3 decline), FLIR 0.9 (Phase 3 decline), YuNet 0.6 / 640 / cascade posture (Phase 1 declines), landmarks alignment (Phase 1 decline + the WFLW loose-box flag resolved by source answer in Task 5).
- [ ] The `decisions` array in the JSON mirrors the document rows so the ledger is machine-readable.

### Task 3: mn3 on the committed PAD mirrors (the one new measurement)

**Files:**
- Create: `benchmarks/bench_pad_rgb_candidate.py` (thin variant of `bench_pad_rgb.py`: same detection, same walks, same sweeps; the candidate model + its publisher preprocessing instead of the ViT chip; softmax-already-applied output handling per the 2026-07-17 pitfall note)
- Create: `benchmarks/results-pad-rgb-mn3.json` (+ `.log`)

**Steps:**
- [ ] Locate or fetch the mn3 ONNX (Intel OMZ, Apache-2.0, 12 MB); verify sha256 against the recorded value before running; abort on mismatch.
- [ ] Run celeba, casia, oulu with identical walks/thresholds as the committed ViT results; commit results + log.
- [ ] Verdict row for the candidate table: public-set side from this run, deployment side cross-referenced from `docs/pad-results/2026-07-17-third-party-pad-candidates.md` (not-listed verdict stands; this run quantifies the public-domain strength the July study did not measure).

### Task 4: Replacement-candidate tables, all tracks

**Files:**
- Extend: `docs/research/2026-08-30-calibration-synthesis-phase4.md`

**Steps:**
- [ ] Per track (detection, landmarks, recognition, RGB PAD, IR PAD): publisher/license of the shipped artifact, the clean-BOM bar status, candidates considered with one-line disposition (evaluated: pointer; declined-with-evidence: pointer; not-motivated: the phase evidence that keeps the incumbent), and a ship-or-not verdict. Recognition must record why the license-clean incumbent stands (buffalo non-commercial; published-delta analysis), IR PAD must record that the shipped cue IS the July qualified candidate.

### Task 5: Campaign success-criteria closure

**Files:**
- Extend: `docs/research/2026-08-30-calibration-synthesis-phase4.md`

**Steps:**
- [ ] Walk the spec's success criteria one by one, each met / met-by-cross-reference (with pointer) / declined with evidence and reason. Includes the WFLW loose-box flag (source answer: which paths feed boxes to the mesh), and the phone-at-login-distance RGB PAD row (cross-reference the committed pad-results rows; if the ViT has no measured row at login distance, decline with the fleet-session proposal, do not improvise).

### Task 6: User-gate list + final review

**Steps:**
- [ ] The synthesis document ends with the gate table: every decision that requires user approval to become a PR (threshold changes, any swap), each with the exact PR shape and the evidence pointer.
- [ ] Final whole-branch review (fresh read-only agent) against this plan; fix round; PR.

## Phase 4 exit criteria

- Mechanism inventory verified against source; decisions ledger committed as JSON; mn3 row measured or aborted with the mismatch recorded; candidate tables complete with verdicts; success-criteria walk done; user-gate list explicit; suite green; zero em dashes.

## Out of scope

- Any threshold change PR, any models-vN release work, any crates/ edit, recognizer/detector candidate evaluation (declined-with-evidence path covers them), new dataset downloads beyond the 12 MB mn3 artifact.

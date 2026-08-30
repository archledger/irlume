# Calibration synthesis, Phase 4

- **What:** the closing phase of the model calibration campaign: a runtime
  mechanism inventory mapping every wired decision constant to its consumer
  arm and evidence, a decisions ledger with one disposition per decision,
  replacement-candidate tables with ship-or-not verdicts per track, the
  campaign success-criteria walk, and the user-gate list. No runtime code,
  threshold, or shipped model changes in this phase.
- **Where:** source-read of `crates/irlume-core/src/lib.rs` and
  `crates/irlume-auth/src/lib.rs` at base 1146e473; the one new measurement
  (the mn3 candidate row) ran on archhost (RTX 3060, ORT 1.27.0 CUDA,
  cv2 5.0.0) through `benchmarks/bench_pad_rgb_candidate.py` over the same
  committed mirrors and walks as the ViT lane.
- **Sources (committed):** `benchmarks/results-synthesis-phase4.json` (the
  machine-readable mechanisms + decisions ledger; every row below mirrors
  it), `benchmarks/results-pad-rgb-mn3.json`, and the phase 1 to 3 results
  files and reports cited inline.

## 1. Mechanism inventory (Task 1)

The runtime is already modality-aware: RGB and IR bars are separate
constants, each carrying its own deployment-shaped evidence. The full table
with source lines, consumer arms, and coverage verdicts is
`results-synthesis-phase4.json` (`mechanisms`). Summary:

| constant | value | arm | phase coverage |
|---|---|---|---|
| `RGB_MATCH_THRESHOLD` (core:91) | 0.55 | RGB-primary (concurrent pairs) | NOT covered: phase 2's pooled sweep stops at 0.50 |
| `IR_MATCH_THRESHOLD` + margin (core:104,151) | 0.55 + 0.05 | dim-light IR fallback | cross-check only (in-source full-CBSR bench) |
| `IR_DARK_MATCH_THRESHOLD` (core:133) | 0.635 | pure-dark IR-only (ADR-0016) | not swept by phases; OR-arm + live-session evidence in-source |
| `VIT_PAD_THRESHOLD` / `VIT_PAD_VOTE_N` (auth:350,356) | 0.55 / 5 | RGB PAD deny | measured (phase 3): transfer failure, decline |
| `IR_PAD_THRESHOLD` (auth:364) | 0.9 | FLIR IR PAD deny | measured (phase 3): keep |
| skew budgets (auth:426,479) | 3s / 8s | schedule gates, not scores | out of scope |
| `ir_center_edge_ratio` (auth:142,290) | per-enrollment | per-user IR print floor | fleet-calibrated; no public labels |

Two inventory findings matter more than any threshold row:

1. **Phase 2's runtime claim was wrong and is corrected in its report
   (decision D2):** 0.45 was the aligned-set evaluation convention, not the
   wired line. The wired RGB line is 0.55, which no phase swept on the
   mirrors. The correction is committed with this phase.
2. **Phase 2's cross-modality finding describes the runtime's existing
   design**, not a gap: a single cosine line indeed cannot serve both
   spectra, and the runtime already carries separate per-spectrum bars with
   deployment-shaped evidence (OR-arm protocols, live dark sessions,
   FAIRNESS.md per-group analysis) that the campaign's seeded mirror
   protocols do not displace.

## 2. Decisions ledger (Task 2)

Every row is D-numbered in `results-synthesis-phase4.json` (`decisions`),
with evidence pointers and gate status. Dispositions: **keep** for D1 (RGB
0.55; phase 2's 0.35 row is monitoring material: it trades roughly 20x FAR
for +0.20 TAR on a weaker protocol), D3 (IR 0.55+0.05 fallback and 0.635
dark), D4 (ViT 0.55, phase 3 decline), D5 (FLIR 0.9, phase 3 decline), D6
(all phase 1 detection/landmarks declines, including the WFLW loose-box
flag: the mesh consumes YuNet-primary or BlazeFace-rescue boxes in-pipeline,
never standalone loose crops, so the standalone deficit maps to no runtime
path). D2 is the phase 2 report correction committed here. D7 and D8 below.

## 3. RGB PAD replacement candidate: anti-spoof-mn3 (Task 3)

The one motivated replacement evaluation. Artifact: Intel OMZ
`anti-spoof-mn3`, Apache-2.0, trained on CelebA-Spoof, 12 MB, sha256
`c4c99af04603b62d7e44f6f4daeb33e0daeccc696008c0b1d62f6f5cebbb3262`
(enforced at load by the lane, which aborts on any digest mismatch; for
the committed run the digest was also verified on both hosts before
launch). Publisher preprocessing (raw bbox crop, 128x128,
per-channel mean/scale, softmax baked in) through the identical walks,
detection convention, thresholds, and metrics as the ViT lane. Comparison at
each model's own operating line (mn3 at the author 0.4, ViT at the wired
0.55), identical denominators:

| protocol | mn3 APCER/BPCER/AUC | ViT APCER/BPCER/AUC |
|---|---|---|
| celeba test (mn3 training domain) | 0.0694 / 0.0123 / 0.9961 | 0.6437 / 0.0528 / 0.6765 |
| casia test | 0.1670 / 0.6528 / 0.7024 | 0.4701 / 0.1413 / 0.6100 |
| oulu voted (mirror-limited) | 0.3389 / 0.0496 / 0.9011 | 0.8417 / 0.0 / 0.9311 |

The two sides of one pathology: mn3 dominates inside its training domain and
then flags 65.28% of genuine CASIA frames as spoof at its own author line,
the same genuine-saturation failure the 2026-07-17 hardware study caught in
the lit-indoor login condition (15/15 genuine flagged, median P(spoof)
0.9975). Verdict (D7): **do not ship.**

## 4. Replacement-candidate tables, all tracks (Task 4)

| track | shipped artifact | license | candidates considered | verdict |
|---|---|---|---|---|
| detection | `face_detection_yunet_2023mar.onnx` | Apache-2.0 | none motivated; phase 1 sweeps keep 0.6/640 with BlazeFace rescue-only | **keep** |
| landmarks | `face_landmarks_detector.tflite` | Apache-2.0 | none motivated; mesh-refinement IoU gains measured in phase 1 | **keep** |
| recognition | `glintr100.onnx` (fal AuraFace-v1) | Apache-2.0 | InsightFace buffalo (non-commercial, fails the clean-BOM bar; declined by license); published-delta analysis (1.5-2.6pt under ArcFace-class retrain figures) accepted as the license-over-accuracy tradeoff already committed in models/README.md | **keep** |
| RGB PAD | `liveness_vit.onnx` | MIT | anti-spoof-mn3: evaluated this phase on the public mirrors (see results-pad-rgb-mn3.json); deployment veto stands from the 2026-07-17 hardware study | **keep incumbent; mn3 not shipped (D7)** |
| IR PAD | `flir.onnx` (Alibaba DAMO) | MIT | the shipped cue IS the July study's qualified candidate (banner 122/123), shipped default-on with its measured 0.9 deny line | **keep** |

The mn3-vs-ViT comparison rows on the shared protocols are recorded in
`results-pad-rgb-mn3.json` with the same denominators as the phase 3 tables;
the document you are reading states only the disposition, so the JSON stays
the single numeric source.

## 5. Campaign success-criteria walk (Task 5)

- Committed machine-readable results per track with reproducible protocols:
  **met** (phases 1 to 3 results files + this phase's JSON).
- At least one concrete calibration recommendation per model, accepted or
  declined with evidence: **met** (phase 1 section 4; phase 2 section 4 with
  the D2 correction; phase 3 section 4; D1 to D7 here).
- Replacement-candidate table per track with ship-or-not verdict honoring
  the clean-BOM bar: **met** (section 4).
- The known RGB PAD phone-at-login-distance gap has a measured row (D8):
  **declined with evidence.** What is measured and committed: the IR-path
  phone rows (2026-06-30 selftest: phone_replay 20 attempts, APCER 0.0%,
  every catch by `face_in_ir`; a phone emits nothing at 850 nm, so the
  species never reaches an IR model) and the ViT banner-at-login-distance
  rows (0.594 to 0.656, caught). What does not exist is a ViT-specific
  phone-at-login-distance row, no public set labels the species (binary
  CelebA mirror, species-less CASIA/Oulu mirrors), and models/README.md:32
  already discloses the gap. Closing it needs one in-person fleet session:
  20 `phone_replay` attempts against the ViT alarm path per PAD_SELFTEST.md;
  listed in the gate table for the user to schedule.

## 6. User-gate list (Task 6)

| gate | item | evidence |
|---|---|---|
| none | all keep dispositions D1, D3 to D6 (no change proposed, nothing to approve) | sections 1 to 2 |
| none | D7 mn3 not shipped (verdict is no-swap) | section 3 |
| docs only | D2 phase 2 report correction rides in this PR | section 1 |
| user session | D8: the ViT phone-at-login-distance fleet row (20 attempts, in-person) | section 5 |
| would-be future PRs (none opened) | any future threshold change would require: the operating point actually measured on a protocol at least as strong as the wired evidence, a normal PR, and per the campaign spec explicit user approval; any model swap additionally requires the models-vN release flow | campaign spec |

## 7. Limitations

- The mechanism inventory is a source read at one commit (1146e473); line
  numbers drift, constants do not (pinned by name).
- The mn3 run measures public-domain strength on mirrors whose protocols
  carry the phase 3 caveats (binary labels, re-encoded frames, dead fallback
  source); its deployment-side verdict is single-session single-operator
  fleet evidence, per PAD_SELFTEST.md caveats.
- No phase 4 row re-runs the recognizer lanes; D1/D3 rest on the wired
  evidence plus the coverage gap stated plainly.

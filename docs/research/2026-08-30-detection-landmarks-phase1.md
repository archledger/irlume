# Detection and landmarks calibration, Phase 1

- **What:** Phase 1 of the model calibration campaign: measurement of the shipped
  detection stack (YuNet, plus the BlazeFace rescue stage) and the landmark
  alignment stack (478-point mesh behind YuNet crops) on WIDER FACE (RGB, wild),
  CBSR NIR and Oulu-CASIA NIR (IR-grey), and WFLW / 300W / AFLW2000 (landmark
  annotation sets).
- **Where:** archhost, NVIDIA RTX 3060, ONNX Runtime 1.27.0 with the CUDA
  execution provider (providers: Tensorrt, CUDA, CPU), OpenCV 5.0.0. Per
  `benchmarks/README.md`, CPU runs give the same accuracy; only latency differs.
- **When:** 2026-08-30 (Phase 1 report; dataset fetch provenance 2026-08-29 UTC
  per the PROVENANCE.md entries on the measurement host).
- **Sources (committed):** `benchmarks/results-detection-wider.json`,
  `benchmarks/results-detection-ir.json`, `benchmarks/results-landmarks.json`.
  Every number below is copied from those files (or from the committed README
  headlines referenced inline); values are rounded to 4 decimals.

## 1. Detection track (WIDER FACE val)

Operating point: input 640, score threshold 0.6.

Tiered AP at the operating point (3226 val images):

| tier | AP |
|---|---|
| easy | 0.8574 |
| medium | 0.7932 |
| hard | 0.4733 |

Hard-tier totals per the JSON: tp 15825, fp 2345, n_gt 32764, images 3226.

Protocol note: tiers use the official-approximation cuts (easy h > 50, medium
h > 30, hard h >= 10). Predictions whose best-overlap valid GT box lies outside
the tier are discarded entirely (neither tp nor fp); zero-overlap predictions
stay fp candidates; invalid-flag GT boxes are excluded everywhere. An earlier
height-band approximation (h >= 50 / h >= 20 / all valid) is superseded; its
numbers are preserved in the JSON notes: easy 0.6859 / medium 0.6866 /
hard 0.3964 (tp 15826, fp 2366, n_gt 39123).

### Input and threshold sweep

1613 of 3226 val images (stride 2, the nearest stride-integer approximation of
the 2000-image target). Decoders run at the 0.3 floor and rows post-filter
scores. ap_hard over all valid val GT faces on the sample:

| input | thr 0.3 | thr 0.45 | thr 0.6 | thr 0.7 |
|---|---|---|---|---|
| 320 | 0.2438 | 0.2283 | 0.2049 | 0.1779 |
| 448 | 0.3521 | 0.3325 | 0.2992 | 0.2620 |
| 640 | 0.4729 | 0.4504 | 0.4124 | 0.3669 |

Findings, exactly as the JSON shows them:

- Input 640 dominates 320 and 448 at every threshold: each 640 row exceeds the
  same-threshold 448 and 320 rows.
- Threshold 0.3 lifts sample ap_hard to 0.4729 from 0.4124 at the 0.6 row (same
  1613-image sample, same tiered scoring): recall is bought at FP cost, with
  the sweep's operating-point FPPI reference recorded at 0.7564 (the 640/0.6
  row) for the recall_at_op_fppi column.

### Cascade (YuNet + BlazeFace rescue)

BlazeFace short-range fires only on YuNet-empty images (rescue score 0.5,
shipped anchor decode). Recall = valid-GT faces matched at IoU 0.5.

| split | images | n_gt | yunet_recall | cascade_recall | rescues |
|---|---|---|---|---|---|
| val | 3226 | 39123 | 0.4045 | 0.4048 | 10 |
| train sample (stride 4) | 3220 | 40224 | 0.4093 | 0.4094 | 5 |

Findings:

- Cascade recall is >= YuNet recall on both splits (0.4048 >= 0.4045 val;
  0.4094 >= 0.4093 train sample).
- The rescue fired on all 182 YuNet-empty images per split and produced 27
  boxes (val) and 22 boxes (train), rescuing 10 and 5 GT faces respectively:
  on WIDER the rescue gain is tiny and never negative.
- BlazeFace stays a rescue, never a replacement, consistent with
  `models/README.md` and the outdoor-walking measurement in
  `benchmarks/README.md`.

## 2. IR-grey detection (CBSR NIR + Oulu-CASIA NIR)

YuNet at the operating point (640, 0.6). Detection rate = frames with at least
one face above threshold; no GT exists for either set, so nothing beyond rate
and score percentiles is claimed.

| set | frames | detected | rate |
|---|---|---|---|
| CBSR NIR | 3940 | 3940 | 1.0 |
| Oulu Dark | 1348 | 1348 | 1.0 |
| Oulu Strong | 1298 | 1298 | 1.0 |
| Oulu Weak | 1354 | 1354 | 1.0 |
| Oulu overall | 4000 | 4000 | 1.0 |

Score percentiles of detected faces: CBSR p50 0.9321 / p10 0.9213; Oulu
overall p50 0.9333 / p10 0.9249.

Headline: YuNet saturates NIR-grey detection on these sets, rate 1.0 on every
CBSR frame and every Oulu lighting at the operating point, with the score
floor (p10 0.9213 / 0.9249) far above the 0.6 threshold. Detection is not the
bottleneck on CBSR/Oulu-class NIR. The bench discriminates nothing below the
current operating point at threshold 0.6 (ceiling effect, recorded in the
task-5 report).

## 3. Landmarks track (WFLW / 300W / AFLW2000)

Pipeline: YuNet at the operating point; best detection matched to the GT face
box at IoU >= 0.3; matched and standalone paths crop a 1.25x-side square
centered on the box, edge-replicated at frame borders, resized to 256; mesh
output is gated by the runtime plausibility rule before scoring. GT face box =
tight bounds of the GT landmarks (WFLW's shipped rect is a loose region,
unusable for IoU-0.3 matching; 300W ships no box).

| dataset | images | mesh_ok | eye NME pipeline | eye NME standalone | anchor NME | align IoU gain | fail YuNet | fail mesh |
|---|---|---|---|---|---|---|---|---|
| wflw_test | 2500 | 2441 | 0.0950 | 0.1232 | 0.1148 | 0.0867 | 59 | 0 |
| 300w_test | 600 | 595 | 0.0813 | 0.0841 | 0.0857 | 0.1002 | 5 | 0 |
| aflw2000 | 2000 | 1974 | 0.1990 | 0.2795 | 0.2112 | 0.1007 | 26 | 0 |

Eye NME p90: 0.1701 (WFLW), 0.1208 (300W), 0.4370 (AFLW2000).

Findings:

- The pipeline beats GT-box (tight landmark bounds) standalone crops
  everywhere: 0.0950 vs 0.1232 (WFLW), 0.0813 vs 0.0841 (300W), 0.1990 vs
  0.2795 (AFLW2000).
- Mesh refinement of YuNet boxes adds a consistent positive alignment gain:
  align_iou_gain_mean 0.0867 / 0.1002 / 0.1007. Zero meshes were rejected as
  implausible on all 5,100 rows (n_fail_mesh 0 everywhere).
- AFLW2000 sits a decade above the other two sets (0.1990 pipeline vs
  0.0950 / 0.0813): the set spans yaw to +/- 90 degrees, where the
  frontal-biased mesh degrades (profile tail: eye NME p90 0.4370), and its GT
  is the 3DMM fit's x/y projection (mat pt3d_68), adding fit-error bias on
  extreme pose.
- Comparison anchor: the committed CBSR pipeline eye NME is 0.0273
  (`benchmarks/README.md`, n=985). WFLW and 300W land in the same 10^-2 decade
  at 0.0950 / 0.0813. Recorded differences: wild-set pose, occlusion,
  expression, and small faces vs CBSR's constrained high-res NIR bench, plus a
  convention offset that does not exist in the same-source CBSR comparison
  (predicted centers are mesh iris-block means; GT centers here are
  eyelid-corner means).

## 4. Calibration recommendations

| Decision | Recommendation | Evidence |
|---|---|---|
| YuNet score threshold | Keep 0.6 as the grant-path default; revisit only with a downstream consumer | The 0.3 sweep row buys sample ap_hard (0.4729 vs 0.4124 at the 0.6 row) at FP cost; relevant only if irlume ever needs a high-recall sweep mode, which it does not have today |
| Input resolution | Keep 640 | 640 dominates 320 and 448 at every sweep threshold |
| Cascade switch behavior | Keep BlazeFace as rescue-only (fires only on YuNet-empty images) | Rescue counts are tiny (10 val / 5 train) and cascade recall never drops below YuNet recall on either split (0.4048 >= 0.4045; 0.4094 >= 0.4093) |
| IR-grey detection posture | No detection-side action on CBSR/Oulu-class NIR | Rate 1.0 on 3940/3940 CBSR frames and on every Oulu lighting sample at the operating point |
| Landmark alignment fitness | Keep the current alignment (YuNet box refined by the mesh) | Mesh refinement adds a consistent IoU gain (0.0867 / 0.1002 / 0.1007) and the pipeline beats standalone crops on all three sets. WFLW's standalone deficit (0.1232 vs 0.0950) is flagged for Phase 4: if no irlume path feeds GT-like loose boxes, no action |

## 5. Replacement candidates

None evaluated this phase (per plan). Detector and mesh replacement candidates
join the Phase 4 synthesis.

## 6. Limitations

- The sweep sample is 1613 of 3226 val images (stride 2), the nearest
  stride-integer approximation of the 2000-image target; sweep rows are sample
  numbers, not full-val numbers.
- The tier scorer is an official-protocol approximation: height cuts with
  off-tier prediction discarding, not the official XOR against evaluation
  mats; hard n_gt 32764 sits about 2.5% above the official-mat decode. The
  superseded height-band numbers remain in the JSON notes.
- Each dataset was measured from a single mirror; provenance (originator,
  obtained-from, archive SHA-256) is recorded per dataset in PROVENANCE.md and
  MANIFEST.sha256 on the measurement host. Mirror variance is real: the 300W
  mirror ships the 600-image common test subset only, and WFLW annotation
  lists split by face, not by image.
- CBSR and Oulu produce detection rates only; no GT exists for either set, so
  no AP or recall is claimed there.
- The landmark sets use tight-landmark-bounds GT boxes and corner-mean eye
  centers; comparison against the CBSR 0.0273 anchor carries the convention
  offsets noted in section 3.

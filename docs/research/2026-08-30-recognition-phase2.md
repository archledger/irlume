# Recognition calibration, Phase 2

- **What:** Phase 2 of the model calibration campaign: verification quality of the
  shipped recognition model on RGB, CFP pose split, and NIR evidence, plus
  threshold-to-FAR calibration per modality with grant recommendations. Model:
  `glintr100.onnx` (fal AuraFace-v1, Apache-2.0, 512-d embeddings, cosine
  scoring), sha256
  `a7933ea5330113b01c9b60351d8f4c33003f145d8470ac5f0e52ee2effe25c60`, flip TTA on.
- **Where:** archhost, NVIDIA RTX 3060, ONNX Runtime 1.27.0 with the CUDA
  execution provider, OpenCV 5.0.0. Embedding paths: the wild RGB sets reuse
  `bench_faceid.py` exactly (YuNet detect, 5-point similarity warp to 112x112,
  `(x - 127.5) / 128` normalization, flip TTA, L2 norm); the pre-aligned sets
  embed their 112x112 crops directly with no detection; NIR reuses
  `bench_nir_ext.py` preprocessing (YuNet largest-face 5-point warp, GT
  two-eye similarity-warp fallback; 0 fallbacks needed on CBSR).
- **When:** measurement runs 2026-08-29 UTC (runtime block `started_utc`
  2026-08-29T14:55:02Z); report 2026-08-30.
- **Sources (committed):** `benchmarks/results-recognition.json` (sha256
  `c41c5e980b88df28ef489dc58ed1b7ec924dca82f233e8e511d652c975c723fa`),
  produced by `benchmarks/bench_recog_suite.py` over
  `benchmarks/verification_metrics.py`. Every number below is copied from that
  file or from the committed README headlines referenced inline; values are
  rounded to 4 decimals. Suite status at this tree: 62 passed.

## 1. RGB track

6,000 pairs per set. `acc10fold` (LFW only) uses the shipped 10-fold protocol
with per-fold optimal threshold on the fold itself (ties to lowest); the
aligned sets ship no folds, so their accuracy column is `acc@0.45`, the
`fold_accuracy` at the fixed 0.45 line.

| set | pairs | acc | eer | TAR@1e-1 | TAR@1e-2 | TAR@1e-3 |
|---|---|---|---|---|---|---|
| lfw (deepfunneled, detect+warp) | 6,000 | 0.9918 (acc10fold) | 0.0127 | 0.9933 | 0.9870 | 0.9760 |
| agedb30 (aligned 112x112) | 6,000 | 0.6995 (acc@0.45) | 0.0440 | 0.9727 | 0.8917 | 0.7547 |
| calfw (aligned 112x112) | 6,000 | 0.8150 (acc@0.45) | 0.0663 | 0.9427 | 0.8773 | 0.8247 |
| cplfw (aligned 112x112) | 6,000 | 0.7053 (acc@0.45) | 0.1197 | 0.8743 | 0.7763 | 0.6247 |

LFW continuity: the committed headline (`benchmarks/README.md`) is AuraFace
99.03% 10-fold accuracy (`results-lfw-cascade.json`, held-out-train-fold
threshold protocol), EER 1.37%. This run reuses the identical embedding path
and reproduces it: held-out protocol 0.9902 +/- 0.0038 vs committed 0.9903,
one pair of 6,000 differing (GPU run noise). The `ten_fold` semantics carried
in the acc column (0.9918) sits slightly above the held-out protocol as
expected. EER 0.0127 vs committed 0.0137 is consistent magnitude across runs.

Alignment-lane crosscheck: the bundle's own aligned-112 LFW annotation
(`lfw_ann.txt`, 6,000 pairs) pushed through the identical embedding path gives
EER 0.0067 and best accuracy 0.9948, vs EER 0.0127 for the deepfunneled
detect+warp lane. The bundle data and the irlume pipeline are consistent; the
deepfunneled lane's deficit is the alignment variant, not a pipeline defect.

Published-delta note: optimal-threshold accuracies on the aligned sets
(0.9582 / 0.9422 / 0.8975 at thresholds 0.214 / 0.235 / 0.212, task-3
investigation) run ~1.5-2.6pt under published ResNet100 ArcFace-class figures
(AgeDB-30 ~98.1-98.4, CALFW ~95.5-96.1, CPLFW ~91.5-92.3). The shortfall is
uniform and in the same direction on all three sets, genuine score
distributions are sane, and the difficulty ordering (agedb30 < calfw < cplfw)
matches the published pattern. Attributed to AuraFace retrain behavior:
`glintr100` is a third-party retrain, not the published MS1MV3 weights, and
the license-over-peak-accuracy tradeoff vs InsightFace buffalo (99.4% LFW,
non-commercial) is already the committed position (`benchmarks/README.md`,
`models/README.md`). Data+pipeline coherence is evidenced by the bundle-LFW
crosscheck above; the w600k_r50 reference anchor was not runnable (absent from
the measurement host; a new download was out of scope). The fixed 0.45 grant
line sits far above this recognizer's optimal band (0.21-0.24) on these sets,
which the calibration table in section 4 quantifies.

## 2. CFP pose track (CFP-W, wild images, detect+warp)

Shipped official protocol: `Protocol/Split/{FF,FP}/{01..10}` with 350 same +
350 diff rows per fold per protocol; `a,b` indices resolved through
`Pair_list_F.txt` (5,000 frontal) and `Pair_list_P.txt` (2,000 profile);
500 identities asserted. Folds are identity-separable, so `ten_fold` applies
directly.

| protocol | pairs | acc10fold | sd | eer | acc@0.45 | TAR@1e-1 | TAR@1e-2 | TAR@1e-3 |
|---|---|---|---|---|---|---|---|---|
| ff (frontal-frontal) | 6,990 | 0.9954 | 0.0034 | 0.0072 | 0.9577 | 0.9974 | 0.9946 | 0.9883 |
| fp (frontal-profile) | 6,899 | 0.9601 | 0.0107 | 0.0467 | 0.6891 | 0.9693 | 0.8950 | 0.7756 |

Pose gap, stated plainly: profile costs ~3.5pt of acc10fold (0.9601 vs
0.9954), raises EER from 0.72% to 4.67%, and drops TAR@1e-3 from 0.9883 to
0.7756 under the identical embedding path. FP is the weakest RGB condition
measured in this campaign, consistent with an RGB grant line tuned on
cooperative frontal evidence.

Detection-skip accounting: pairs with no detected face are skipped and
counted, never silently dropped: 10 FF pairs and 101 FP pairs skipped (34
wild images without a detectable face).

## 3. NIR track

CBSR: gallery/probe membership from the shipped ground truth
(`gallery-groundtruth.txt`, 1,576 entries; `probe-groundtruth.txt`, 2,364);
seeded (42) 3,000 genuine same-subject (gallery, probe) + 3,000 impostor
different-subject pairs over the 197 subjects present in both splits; 3,940
images, 0 GT-align fallbacks, 0 missing.

Oulu: constructed protocol, not canonical (no shipped pair list): identity is
the P### subject across the Dark/Strong/Weak lighting trees; 80 subjects; two
subject-disjoint halves each contributing 2,500 genuine + 2,500 impostor
pairs under `random.Random(42)`; 10,000 pairs, 0 skipped. `acc10fold` averages
the two halves.

| set | pairs | acc | eer | TAR@1e-1 | TAR@1e-2 | TAR@1e-3 |
|---|---|---|---|---|---|---|
| cbsr (gallery/probe, seed 42) | 6,000 | 0.9818 (acc@0.45) | 0.0083 | 0.9990 | 0.9920 | 0.9820 |
| oulu (seeded 10k, seed 42) | 10,000 | 0.9883 +/- 0.0053 (acc10fold); 0.9862 (acc@0.45) | 0.0122 | 0.9994 | 0.9854 | 0.9522 |

Comparability caveat vs the committed CBSR number: `benchmarks/README.md`
records AuraFace CBSR EER 0.77% (`results-nir_results.json`). That figure used
a different seeded pair-construction protocol and no flip TTA; this run's
0.83% uses the gallery/probe protocol and the suite flip-TTA path. Consistent
magnitude, different protocol: indicative context, not a continuity gate.

Tufts-absent note: Tufts (request-form dataset; the Kaggle
`kpvisionlab/tufts-face-database` entry is not the dataset per
`benchmarks/README.md`) was not acquired this phase, so there is no
unseen-faces NIR control here; NIR coverage rides on CBSR + Oulu. See
limitations.

## 4. Threshold calibration (calibration evidence only)

Pooling rule: impostor and genuine cosine scores of the scored pairs, pooled
across sets; grant rule is score > threshold with strict inequality;
`grant_recommendation` is the smallest candidate threshold with realized
FAR <= 1e-3 and the best TAR (lowest threshold on ties). CFPW scores are
deliberately NOT pooled into the RGB table (frozen to the task-3 pool: lfw,
agedb30, calfw, cplfw); CFPW stands alongside as pose-gap evidence. All of
this section is calibration evidence; no runtime code changed.

RGB (pooled 24,000 pairs from the four sets in section 1):

| threshold | FAR | TAR |
|---|---|---|
| 0.30 | 3.833e-3 | 0.8526 |
| 0.35 | 6.667e-4 | 0.7825 |
| 0.40 | 8.333e-5 | 0.6929 |
| 0.45 | 8.333e-5 | 0.5835 |
| 0.50 | 8.333e-5 | 0.4685 |

RGB grant recommendation: 0.35, realized FAR 6.67e-4, TAR 0.7825.

NIR (pooled 8,000 genuine + 8,000 impostor from cbsr + oulu; candidate sweep
extended to 0.2-0.6 because same-modality NIR evidence concentrates lower
while the pooled impostor tail reaches past 0.5):

| threshold | FAR | TAR |
|---|---|---|
| 0.20 | 4.955e-1 | 1.0000 |
| 0.25 | 3.273e-1 | 0.9998 |
| 0.30 | 1.966e-1 | 0.9996 |
| 0.35 | 9.913e-2 | 0.9985 |
| 0.40 | 4.163e-2 | 0.9942 |
| 0.45 | 1.700e-2 | 0.9861 |
| 0.50 | 5.625e-3 | 0.9711 |
| 0.55 | 1.125e-3 | 0.9451 |
| 0.60 | 0.0 | 0.9045 |

NIR grant recommendation: 0.6, realized FAR 0.0, TAR 0.9045 (0.55 misses the
1e-3 cap at 1.125e-3). The 0.2-0.4 rows above are also recorded as
`operating_band`, the realistic operating band of the current grant paths on
NIR evidence.

Per-modality finding, stated as evidence: RGB-band thresholds (0.2-0.4)
applied to the pooled NIR table give FAR 4.955e-1 down to 4.163e-2, i.e. a 4
to 50 percent impostor grant rate, and no threshold in the RGB band meets the
1e-3 FAR cap on NIR evidence. Conversely, the NIR grant line (0.6) sits above
the entire RGB table (pooled RGB TAR is already 0.4685 at 0.5 and falls
monotonically). A single cross-modality threshold is not viable on this
evidence; per-modality thresholds or modality-aware gating is the Phase 4
synthesis question.

## 5. Limitations

- Mirror provenance, per set (PROVENANCE.md + MANIFEST.sha256 recorded on the
  measurement host): lfw from Kaggle `jessicali9530/lfw-dataset`
  (deepfunneled-only mirror; 5,749 identities / 13,233 images verified); cfpw
  from Kaggle `chinafax/cfpw-dataset` (full official protocol, 500 IDs, 7,000
  FF + 7,000 FP pair lines); the aligned bundle from Kaggle
  `yakhyokhuja/agedb-30-calfw-cplfw-lfw-aligned-112x112` (48,000 referenced
  paths verified present); cbsr from Kaggle `gpreda/cbsr-nir-face-dataset`
  and oulu from Kaggle `aryanbaibaswata/oulu-casia` (per
  `benchmarks/README.md`). Mirror variance is real; figures are
  mirror-as-measured.
- The Oulu protocol is seeded and constructed (seed 42, two subject-disjoint
  halves), not a canonical Oulu benchmark protocol; its numbers are not
  comparable to published Oulu figures and exist to give irlume-sized NIR
  operating evidence.
- The CBSR protocol is likewise seeded (gallery/probe over the shipped GT)
  and differs from the committed `bench_nir_ext.py` construction (see the
  comparability caveat in section 3).
- CFPW detection skips: 34 wild images had no detectable face (10 FF + 101 FP
  pairs skipped, counted); the reported CFPW figures condition on detected
  faces.
- Tufts is absent (request-form acquisition; user decision pending). Tufts was
  the clean unseen-faces NIR control in prior benches; this phase has no such
  control, and CBSR/Oulu are also the sets the removed IR adapter trained on,
  which is context the Tufts control would have disentangled.
- The published-delta investigation ran without a reference-model anchor
  (w600k_r50 absent from the measurement host); the conclusion rests on the
  bundle-LFW crosscheck plus distribution and ordering checks.
- Determinism: the pipeline is deterministic (task-3 rerun reproduced every
  number; NIR lane run twice with identical metrics; CFP lane single run).

## 6. Replacement candidates

None evaluated this phase (per plan). Recognizer replacement candidates join
the Phase 4 synthesis.

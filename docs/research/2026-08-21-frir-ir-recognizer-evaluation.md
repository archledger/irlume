# FRIR (iic/cv_manual_face-recognition_frir) evaluation — rejected as the IR recognizer

Date: 2026-08-21 · Agent: opencode · Host: archhost (Ryzen 7 5700G, CPU, ORT 1.27.0)

## Question

`IR_MATCH_THRESHOLD`'s docblock (`crates/irlume-core/src/lib.rs`) records that
dark-mode IR matching is convenience-grade because AuraFace is an RGB-trained
recognizer applied to IR, and that high-assurance dark needs "a dedicated
IR-trained recognizer (proven, not speculation)". ModelScope's FRIR
(`iic/cv_manual_face-recognition_frir`, DAMO academy, MIT) is marketed as
exactly that: a residual network trained for IR face features for "low-cost IR
camera access control". This evaluation asks whether FRIR should replace
AuraFace-on-IR, retiring the RGB-model-on-IR workaround.

## Model facts (primary source: the download itself + modelscope 1.39.1 pipeline code)

- `modelscope download --model iic/cv_manual_face-recognition_frir` works
  (modelscope-hub 0.2.0); 6 files, 12.6 MB total, `model.onnx` is the weights.
- ONNX: opset 11, dynamic batch, input `3×112×112` float, output `1×512`
  float. Raw FC+BN head, **no baked preprocessing or L2 norm** (same shape
  convention as glintr100). 3.16M float parameters (AuraFace glintr100: ~65M).
- Vendor preprocessing (`face_recognition_onnx_ir_pipeline.py`): aligned
  112×112 BGR chip → RGB → `(px/255 - 0.5)/0.5` → external L2 norm. That is
  `(px-127.5)/127.5` on RGB, i.e. the standard ArcFace convention.
- License: MIT (README front-matter).
- Vendor claim: "私有数据集下，100人底库，1e-5的误识率下，通过率97%" — 97% TAR at
  1e-5 FAR on a private 100-person gallery, vendor pipeline.

## Method

Repo bench harness (`benchmarks/bench_faceid.py` + `bench_nir_ext.py`
protocols) run unmodified on archhost, both recognizers under irlume's
production pipeline: YuNet detection → ArcFace 5-point similarity warp to
112×112 → embed (std 127.5 for FRIR, matching the vendor formula). CBSR
active-NIR 850 nm (197 ids, 3940 faces) is the fleet IR cameras' physics
class; Tufts td-a paired RGB/NIR (110 ids, 3234+3234) adds passive NIR and
clean RGB controls.

Faithfulness control: the vendor README's own same-person demo pair
(`ir_face_recognition_1/2.png`) scores **0.7166 cosine** through this
embedding path — a healthy genuine score, proving the irlume-side
preprocessing matches the vendor's intent. The bench measures model quality,
not an integration bug.

## Results (archhost, CPU, 6000 seeded pairs per cell)

| protocol | AuraFace EER / TAR@1e-3 | FRIR EER / TAR@1e-3 | verdict |
|---|---|---|---|
| CBSR active-NIR verify | **0.77% / 98.3%** | 1.50% / 97.4% | FRIR 2× worse EER |
| CBSR rank-1 (197 ids) | **100.0%** | 99.79% | FRIR worse |
| Tufts NIR↔NIR | **1.43% / 93.6%** | 15.10% / 30.4% | FRIR 10× worse |
| Tufts RGB↔RGB (control) | **0.40% / 98.4%** | 15.20% / 34.0% | FRIR 38× worse |
| Tufts RGB-enroll→NIR-verify | **0.90% / 97.4%** | 10.25% / 44.6% | FRIR 11× worse |
| embed latency | 37.98 ms | **1.93 ms** | FRIR 20× faster |

Full numbers: `benchmarks/results-frir.json`, run log
`benchmarks/results-frir.log`.

## Verdict

**Reject FRIR; keep AuraFace-on-IR.** FRIR loses to the shipped RGB recognizer
on FRIR's own home domain (active NIR) and collapses everywhere else. The
RGB↔RGB control is decisive: a generalizable recognizer does not degrade to
15% EER on clean studio RGB under a faithful pipeline, so this is model
quality, not alignment mismatch. The vendor's private 100-person claim does
not transfer to public data under irlume's pipeline. The 20× latency win is
irrelevant while accuracy gates authentication, and the IR embed is not the
dark-path bottleneck (detection dominates).

"AuraFace-on-IR retirement" stays open as a goal with no candidate: the bar
remains a dedicated IR recognizer that measurably beats AuraFace-on-IR on
public NIR corpora under irlume's pipeline before any live-camera trial.

## Scope notes

- No fleet camera testing was run: a single-user live trial cannot overturn a
  2–10× EER deficit measured over 197+110 identities, and nothing was shipped
  for the daemon to load. Per the hardware rule, tests that cannot change the
  decision are not run.
- The vendor's integrated RetinaFace+landmark pipeline was not run to
  completion (mmcv dependency chain unavailable for py3.14); the demo-pair
  faithfulness control bounds that gap: both pipelines use InsightFace-family
  5-point similarity warps, and FRIR's chips are the same geometry family.
- archhost `~/ort-venv` gained `modelscope`, CPU torch, `datasets`,
  `scikit-image`, `pillow` for the vendor-pipeline attempt; `/tmp/frir-bench`
  staging was removed after the run (results pulled to this repo).

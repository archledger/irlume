# ViT liveness (Adedev-W/LivenessModels-ONNX) — offline evaluation: operating window found; live qualification DECLINED it

> **Outcome (see [`2026-08-22-vit-live-qualification.md`](2026-08-22-vit-live-qualification.md)):
> NOT QUALIFIED.** The live session found a scale-dependent phone hole —
> phone at login distance scores 0.455 (REAL-side) on the deployment
> camera, inside the genuine range. This offline note is retained as the
> record of the offline window and its honest constraints.

Date: 2026-08-21 · Agent: opencode · Scoring: archhost (Ryzen 7 5700G, CPU,
ort-venv); latency probe on minihost (N100) · Corpus: the unchanged
2026-08-12 flrgb live session + LFW

## Question

Third candidate for the RGB PAD slot (flrgb declined: low-light genuine
collapse; flxc declined: no separation). Source:
`https://github.com/Adedev-W/LivenessModels-ONNX`, artifact
`liveness_vit_with_meta.onnx` (Google Drive distribution), sha256
`c7f8a6f3054b11f9719f5e24d37ec227721608fff8b90373c6c3e7659864161c`,
MIT LICENSE in repo. **Status: promising offline; NOT wired — a live
qualification session on deployment cameras is required before any wiring
decision (the FLIR precedent).**

## Model facts (artifact + repo `Example/ONNX-python.py`)

- ViT-base layout (google/vit style), opset 14, 343 MB FP32 (~86M params),
  input `pixel_values` `1×3×224×224`, output `logits` `[1,2]`, embedded
  metadata `id2label {"0": "real", "1": "spoof"}`.
- Preprocessing per the repo example: (face) image resized to 224 — **no
  bbox convention documented** — RGB, `/255`, mean 0.5 std 0.5, CHW. Raw
  logits out; softmax applied by the consumer. Score = P(spoof).
- Training data: **undocumented** (no dataset, no metrics anywhere in the
  repo). Same disclosure regime as FLIR: opt-in with disclosure if ever
  wired, never shipped-by-default (ADR-0001 criteria 2–3).

## Method

`benchmarks/pad-candidates/vit_liveness_score.py` (committed, pinned
hashes): YuNet largest-face bbox (standing deviation), three crop margins
because the repo documents none — tight, +25%/side, +96/112/side (the DAMO
family convention) — plain resize 224 (the example's convention, no warp).
Corpora: the 2026-08-12 live session (75 genuine desk-light / 18 detectable
genuine low-light / 100 vinyl-print attack frames, five presentations,
Zenbook camera, frames unchanged) and all 13,233 LFW crops (5,749 ids) as
the at-scale genuine control (mn3/flxc precedent).

## Results (P(spoof), per frame)

Live corpus, per margin:

| condition | tight min/med/max | m96 min/med/max |
|---|---|---|
| genuine desk | 0.347 / 0.391 / 0.438 | 0.422 / 0.474 / 0.551 |
| genuine low-light | 0.392 / 0.440 / 0.532 | 0.378 / 0.469 / 0.519 |
| attack (5 presentations) | 0.390 / 0.557 / 0.715 | 0.604 / 0.707 / 0.773 |

The m25 margin sits between; m96 is the clean one (tight overlaps at the
tails). Threshold table (m96, denied = P ≥ thr):

| thr | genuine-desk | genuine-lowlight | attack |
|---|---|---|---|
| 0.55 | 1/75 | 0/18 | 100/100 |
| 0.60 | 0/75 | 0/18 | 100/100 |
| 0.65 | 0/75 | 0/18 | 94/100 |

Attack per-presentation (m96): flat login-distance 20/20 ≥ 0.6 (median
0.720 — the presentation that killed flrgb), close 20/20, tilt-left 20/20,
tilt-right 20/20, shallow-angle 20/20. Uniform coverage; min attack frame
0.604.

**Low-light genuine does not collapse** (median 0.469 vs flrgb's 0.785) —
the exact flaw that declined flrgb is absent.

LFW at scale (all genuine, m96): median 0.452, q75 0.487, q90 0.513, q99
0.565; **zero frames ≥ 0.9**. Frame-level ≥ 0.60: 38/13,233 (0.29%).
Identity-median ≥ 0.60: 7/2,280. **5-frame-median presentation simulation:
0/531 presentations ≥ 0.60** — multi-frame voting fully suppresses the
genuine tail. Contrast mn3 (99.75% spoof-saturated on lit indoor live) and
flxc (35% of LFW ≥ 0.5): this model reads ordinary imagery as genuinely
real with a thin, votable tail.

Latency (FP32, CPU): archhost 5700G **59 ms**/infer; minihost N100
(the fleet floor, dual-cam login box) **268 ms**/infer (probe script,
n=30, warm). FLIR is 1.2 ms — this is 50–200× heavier.

## Reading

The operating window at m96 is **[0.56, 0.604]**: genuine q99 0.565 below,
attack floor 0.604 above, with 5-frame voting collapsing the genuine side
to 0/531 sampled presentations. This is the first RGB candidate to hold
both lit and low-light genuine under the attack floor on this corpus. Three
honest constraints:

1. **The window is ~0.04 wide** (FLIR's measured window is 0.24). It exists
   but has little headroom; a different print or camera could land inside
   it. That is a question only a live session on the deployment cameras can
   answer.
2. **Latency is a wiring cost**: 268 ms/frame on the N100 means a 5-frame
   voting cue adds ~1.3 s worst-host unless pipelined with capture;
   FP16/int8 export may halve or quarter it (untested).
3. **Provenance is weak**: 2-star repo, Google Drive artifact, zero
   training documentation, no published metrics. Same opt-in-with-
   disclosure regime as FLIR if it ever ships; the 343 MB size also doubles
   irlume's current model payload.

## Next step (not taken this session)

A live qualification session per the FLIR precedent, with the user present:
both deployment cameras (Zenbook module, NexiGo), the vinyl banner and
phone/screen species live, glasses on/off, sun regimes — through the m96
crop at a 0.60 threshold with 5-frame voting. Only that can move this
candidate to "qualified for the opt-in menu."

Per-frame scores: [`2026-08-21-vit-scores.csv`](2026-08-21-vit-scores.csv)
(live corpus), [`2026-08-21-vit-lfw-scores.csv`](2026-08-21-vit-lfw-scores.csv)
(LFW). Scorers: [`vit_liveness_score.py`](../../benchmarks/pad-candidates/),
[`vit_lfw_score.py`](../../benchmarks/pad-candidates/).

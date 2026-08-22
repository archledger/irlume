# FLXC (cv_manual_face-liveness_flxc) evaluation — rejected as the RGB PAD candidate

Date: 2026-08-21 · Agent: opencode · Scoring host: archhost (Ryzen 7 5700G,
CPU, ort-venv) · Corpus: the 2026-08-12 flrgb live session, unchanged

## Question

The RGB PAD slot has been empty since
[`2026-08-12-flrgb-live-first-contact.md`](2026-08-12-flrgb-live-first-contact.md)
declined FLRGB ("a candidate that fixes the low-light genuine collapse — a
different model — could be re-evaluated against this same corpus shape").
ModelScope's FLXC (`iic/cv_manual_face-liveness_flxc`, DAMO, MIT) is that
shape of candidate: an RGB anti-spoofing model marketed for "low-cost IR
camera access control"-class devices, 99.8% spoof interception / 92.1% live
pass on the vendor's private set.

## Model facts (primary source: the download + modelscope 1.39.1 pipeline code)

- `modelscope download --model iic/cv_manual_face-liveness_flxc` works; 5
  files, `model.onnx` 334 KB (sha256
  `2efcdfeec34a474eaf94b425410635ae9b6b0ba7183dfdcdbd4c573daabbac2e`),
  opset 11, ResNet-family, `antispoofing_head` → Softmax, 2 classes.
- **Input is 12-channel** `1×12×112×112`. The vendor pipeline
  (`face_liveness_xc_pipeline.py`) builds it by
  `np.concatenate([img, img, img, img], axis=3)`: four RGB **color-flash
  frames**. FLXC is a 炫彩 (colorful-flash) protocol model — the device
  screen flashes colors at the face, the camera captures 4 synchronized
  frames, and the discriminative signal is the reflection differences.
- The demo "single image" mode replicates one ordinary frame 4× — a
  degenerate input. The model card itself states this mode is 不太鲁棒 ("not
  robust") and recommends sequence input with voting.
- Score: `out[0]` of the softmax pair = P(fake) (README: higher = spoof);
  no extra softmax (same convention pitfall as FLRGB/mn3).
- Preprocessing, shipped route: DamoFD detect + 5 landmarks →
  `align_face` similarity warp to the InsightFace 96/112 reference (+8
  slide) → `(px-127.5)*0.0078125` on the **BGR** chip → ×4 replicate → CHW.
  Card route: bbox + 96/112 expansion, 127-fill square, 128 resize,
  center-crop 112. Both scored, as in the FLRGB session.

## Method

Same corpus as the FLRGB first contact: 75 genuine desk-light frames, 75
genuine low-light frames (18 detectable in RGB — the rest is why dark login
runs on IR), 100 vinyl-print attack frames across five presentations,
Zenbook camera, frames unchanged in the local research store. Detection by
irlume's shipped YuNet (the standing deviation: DamoFD not fetched);
scoring by `benchmarks/pad-candidates/flxc_live_score.py`, committed with
pinned hashes.

Faithfulness control: the vendor docstring's own demo image (a genuine
flash-session capture, OSS-stored copy decodes via PIL despite server-side
truncation at exactly 3 MB) scores **P(fake) 0.008** through the warp route
(vendor's published example: 0.038) — both deep in genuine territory, so the
integration path is faithful and the corpus results below measure the model.

## Results (degenerate single-image mode, per-frame P(fake))

| condition | n | warp min/med/max | pad96 min/med/max |
|---|---|---|---|
| genuine, desk light | 75 | 0.875 / **0.965** / 0.985 | 0.957 / 0.985 / 0.990 |
| genuine, low light (detected) | 18 | 0.049 / 0.603 / 0.912 | 0.538 / 0.615 / 0.957 |
| attack, vinyl print (all presentations) | 100 | 0.759 / 0.962 / 0.995 | 0.221 / 0.434 / 0.736 |

Threshold table (warp route, denied = P(fake) ≥ thr):

| thr | genuine-desk denied | genuine-lowlight denied | attack denied |
|---|---|---|---|
| 0.50 | 75/75 | 17/18 | 100/100 |
| 0.70 | 75/75 | 1/18 | 100/100 |
| 0.90 | 74/75 | 1/18 | 79/100 |
| 0.95 | 70/75 | 0/18 | 58/100 |
| 0.99 | 0/75 | 0/18 | 13/100 |

**The genuine desk-light user scores as a spoof at near-saturation, OVERLAPPING
the attack.** At every threshold up to 0.95 the genuine denial rate is greater
than or equal to the attack denial rate; at 0.99 both collapse. There is no
operating point, and this is not a tuning problem.

Mechanism, consistent with the vendor's own architecture: with four
replicated non-flash frames the model has no flash-reflection differences to
read, and what remains reads ordinary camera imagery as out-of-distribution
→ spoof. (The demo image passes because it is a genuine flash-session
capture.) The pad96 route is no better: it merely moves the attack median
down (0.434) while genuine stays pinned at 0.985 — inverted separation.

## Why no as-designed (color-flash) live test was attempted

Even a perfect flash-mode score would not wire into irlume: capturing four
screen-color-flash frames requires the authenticating surface to drive the
display — KDE locker, GDM/SDDM greeters, polkit agents own the screen during
exactly the moments irlume authenticates, and irlume's daemon deliberately
has no display integration (the same boundary that keeps it
greeter-agnostic). A flash protocol would also be a visible, disruptive
light show at every login. And the vendor documents no flash sequence
(colors, order, timings), so an improvised sequence could not be claimed to
replicate the training distribution: a failure would be inconclusive and a
success unwireable. A test that cannot change the decision is not run.

## Verdict

**Reject FLXC.** In the only mode irlume could ever feed it (single-frame,
degenerate), it denies the genuine user at ≈100% at exactly the thresholds
that deny the print attack — negative value as a deny-only cue, strictly
worse than FLRGB's already-declined profile (FLRGB at least separated the
lit-condition user). The as-designed mode is architecturally unreachable for
a PAM daemon. The RGB PAD slot stays empty on the evidence; FLIR remains the
only qualified third-party PAD artifact (IR side).

Per-frame scores: [`2026-08-21-flxc-scores.csv`](2026-08-21-flxc-scores.csv).
Scorer: [`benchmarks/pad-candidates/flxc_live_score.py`](../../benchmarks/pad-candidates/).
Corpus: the unchanged 2026-08-12 live session (biometric, local research
store, never committed).

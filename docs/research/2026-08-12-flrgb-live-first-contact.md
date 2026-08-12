# flrgb live first contact, RGB genuine + vinyl-print attack

Date: 2026-08-12, Zenbook /dev/video0 (RGB), enrolled user, glasses on.
Model `cv_manual_face-liveness_flrgb` `model.onnx` sha256
`e13b5543520b7770cd844266a939aedeaeab57811e26c0e57754c654f8bb7419`,
detection by irlume's shipped YuNet sha256
`8f2383e4dd3cfbb4553ea8718107fc0423210dc964f9f4280604804ed2552fa4`.

Scores were produced by `benchmarks/pad-candidates/flrgb_live_score.py`
using `benchmarks/pad-candidates/flrgb_eval.py` for detection, cropping
and inference; both are committed with the hashes above pinned in the
scorer's header, and re-running the scorer reproduces
`2026-08-12-flrgb-live-scores.csv` byte for byte (verified after
deleting it). The weights are not committed and are resolved through
`FLRGB_MODEL` / `IRLUME_YUNET`. The captured frames are biometric and
stay in the local research store, per the recognition-results precedent.

`p_fake` is element zero of the model's own probability pair, without the
extra softmax the ModelScope pipeline applies. Both preprocessing
variants were scored: pad96, the model card's 96/112 expansion, and
pad16, the configured pipeline's 16/112 route.

## Captures

- Genuine: 75 frames, three poses (straight, leaned back, turned), 0
  non-detections.
- Attack: 100 frames, the #235/#237 vinyl graduation banner across five
  presentations (flat at login distance, close, tilted left, tilted right,
  shallow angle), 0 non-detections.
- Genuine, low light: 75 frames in a closet with the door ajar (frame mean
  luma 16-18, drift sd 0.5, no auto-exposure hunting). The RGB detector
  found a face in only 18 of the 75; near-dark RGB detection is itself
  marginal, which is why dark login runs on IR.

## pad96 is the variant; pad16 is not

| variant | genuine p_fake (min/median/max) | attack p_fake (min/median/max) |
|---|---|---|
| pad96 | 0.001 / 0.010 / 0.079 | 0.179 / 0.917 / 0.999 |
| pad16 | 0.036 / 0.212 / 0.778 | 0.029 / 0.616 / 0.990 |

pad16 spreads genuine to 0.778, which a deny-only cue would turn into
false denials, and its attack median is lower; pad96 holds genuine under
0.08 and separates. pad96 is the only defensible variant on this corpus,
which agrees with the offline finding that pad16 fails far/small faces
while pad96's weakness was low-light genuine (not tested today).

## The verdict: decline the candidate

pad96 per condition (frames where a face was detected):

| condition | n | p_fake min / median / max |
|---|---|---|
| genuine, desk light | 75 | 0.001 / 0.010 / 0.079 |
| genuine, low light | 18 | 0.166 / 0.785 / 0.977 |
| attack, flat login-distance | 20 | 0.179 / 0.390 / 0.867 |
| attack, all presentations | 100 | 0.179 / 0.917 / 0.999 |

The two populations a PAD threshold must separate are the genuine user
and the realistic (flat, head-on, login-distance) attack. In low light
they OVERLAP completely: genuine-low-light detected frames span
[0.166, 0.977], the head-on attack spans [0.179, 0.867], the shared band
is [0.179, 0.867]. No threshold does both jobs:

| threshold | genuine low-light denied (false denials) | head-on attack denied |
|---|---|---|
| 0.15 | 18 of 18 | 20 of 20 |
| 0.40 | 16 of 18 | 9 of 20 |
| 0.50 | 15 of 18 | 7 of 20 |
| 0.80 | 9 of 18 | 1 of 20 |

Any threshold low enough to deny the head-on print denies the genuine
user in low light almost always; any threshold high enough to pass the
low-light user passes the head-on print. flrgb is a deny-only cue, so
its false denials cost the password rather than a grant, but the whole
reason to add it is to cover the RGB attack the IR gate might miss, and
on the baseline square-on presentation it covers that attack only by
denying the legitimate user in the dark. That is negative value in the
exact regime it was added for.

This reproduces and hardens the offline finding (pad96 fails low-light
genuine, 9 of 9 there), now with the live head-on-attack overlap that
makes it a decline rather than a tuning problem. The double-softmax and
preprocessing-fork suspicions were real: pad16 is dead on overlap
alone, and pad96 collapses on the condition that decides a PAD cue.

## What would reopen this

Not more sessions of the same instrument: two independent measurements
agree. A candidate that fixes the low-light genuine collapse (a
different model, or a preprocessing route that does not read a dark
genuine face as fake) could be re-evaluated against this same corpus
shape. flir remains the only clean PAD artifact that survives its
measurements, and it covers IR where flrgb was meant to cover RGB; the
RGB PAD slot stays empty on the evidence, not on the absence of a
candidate.

## Per-presentation attack detail (pad96), for the record

| presentation | min | median | max | frames < 0.9 |
|---|---|---|---|---|
| flat, login distance | 0.179 | 0.390 | 0.867 | 20 of 20 |
| close | 0.491 | 0.909 | 0.981 | 8 |
| tilt left | 0.824 | 0.968 | 0.998 | 6 |
| tilt right | 0.841 | 0.975 | 0.996 | 1 |
| shallow angle | 0.366 | 0.948 | 0.999 | 7 |

flrgb scores the flat, square-on, login-distance presentation lowest and
the tilted presentations highest, on this print and this session. The
square-on presentation is the one this project's own threat model treats
as the baseline print attack (#235, #237), and it is the presentation a
camera-facing attacker can hold most easily; that makes the ordering the
unfavourable one, whatever an individual attacker would in fact choose.
Kin to the #239 lesson: an attack corpus that varies only the defender's
favourite axis measures the instrument, not the attacker.

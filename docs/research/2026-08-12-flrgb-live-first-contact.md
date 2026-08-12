# flrgb live first contact, RGB genuine + vinyl-print attack

Date: 2026-08-12, Zenbook /dev/video0 (RGB), enrolled user, glasses on,
normal desk light. Model `cv_manual_face-liveness_flrgb` model.onnx
sha256 e13b5543520b7770..., scored through the 2026-08-07 harness's
detect/align/infer unchanged (score.py imports its definitions). `p_fake`
is out[0] of the model's own softmax pair, avoiding the ModelScope
double-softmax. Both preprocessing variants scored: pad96 (the card's
96/112 expansion) and pad16 (the config's 16/112 route). Raw per-frame
scores in `2026-08-12-flrgb-live-scores.csv` beside this file; the frames
themselves are biometric and stay out of the repository, per the
recognition-results precedent.

## Captures

- Genuine: 75 frames, three poses (straight, leaned back, turned), 0
  non-detections.
- Attack: 100 frames, the #235/#237 vinyl graduation banner across five
  presentations (flat at login distance, close, tilted left, tilted right,
  shallow angle), 0 non-detections.

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

## The finding that shapes the entry: the login-shaped attack is the weak point

pad96 per attack presentation:

| presentation | min | median | max | frames < 0.9 |
|---|---|---|---|---|
| flat, login distance | 0.179 | 0.390 | 0.867 | 20 of 20 |
| close | 0.491 | 0.909 | 0.981 | 8 |
| tilt left | 0.824 | 0.968 | 0.998 | 6 |
| tilt right | 0.841 | 0.975 | 0.996 | 1 |
| shallow angle | 0.366 | 0.948 | 0.999 | 7 |

The flat, square-on, login-distance presentation, the one an attacker
actually uses, is the presentation flrgb scores LOWEST (median 0.390,
every frame under 0.9). The tilted and angled presentations, which no
attacker would choose, are the ones it catches hardest. This is the #239
lesson exactly: the attack's easiest case for the defender is the one the
attacker never presents.

Two thresholds bound the reading, and they disagree:

- A per-frame separator exists on THIS corpus: genuine tops out at 0.079,
  the flat attack bottoms at 0.179, so a threshold near 0.13 denies every
  attack frame and passes every genuine frame here.
- But that margin is one session, one print, one subject, one light, and a
  0.13 threshold has almost no genuine headroom; the offline low-light
  genuine regime (untested today) is where pad96 was already weakest, and
  a light that pushes a genuine frame from 0.08 toward 0.13 starts
  false-denying. At the safe-margin threshold the buffalo work used for its
  own operating points (0.5), pad96 denies 0/75 genuine and 85/100 attack,
  but only 0 of 20 flat-attack frames clear 0.5 by median, so the realistic
  attack mostly slips the deny.

## Disposition for #441

- Variant: pad96, settled.
- The attack question is answered in shape, not in a shippable threshold:
  flrgb catches the print strongly off-axis and weakly head-on, and the
  head-on case is the one that matters. As a deny-only cue a slipped attack
  frame is not a grant (the built-in IR gate still runs), but adding flrgb
  is meant to cover the RGB attack the IR gate might miss, and on the
  login-shaped presentation it covers it least.
- Not enough to ship a catalog entry: one print, one subject, glasses, one
  light, and the low-light genuine regime that decides the false-deny cost
  is untested. The threshold cannot be fixed from margin this thin.
- Next: repeat with the low-light genuine leg (screen-glow, side-lamp) and
  at least a second attack medium (screen), and only then decide the
  threshold and whether a deny-only `flrgb-rgb` entry ships at all.

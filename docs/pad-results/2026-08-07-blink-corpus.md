# Blink corpus: the blendshape closure margin, measured (#316)

Date: 2026-08-07. Machine: ASUS Zenbook S 14, internal ASUS FHD camera
(640x480 RGB, 640x400 IR at 13.7 fps delivered during the strobe burst).
Capture: `scripts/research/capture-blink-corpus.sh`, six segments of
24 RGB + 24 IR frames each, one subject. The frames live outside the
repository; `2026-08-07-blink-corpus.sha256` pins their contents, and the
probe verifies every frame against it before reading a pixel. Per-frame
output in `2026-08-07-blendshapes-blink.csv`.

The stage-3 corpus held no closed-eye frames, so #316's open question was
the margin between a genuine closure and the 0.37 open-eye ceiling
(segment mean, `2026-08-06-mediapipe-native-benchmark.md`). This corpus
closes that gap for one camera: held closures (guaranteed closed frames at
burst frame rates), natural blinks, and same-day open-eye controls, each
with glasses off and on.

Probe: `blendshapes_probe` in external-corpus mode, same pins as the
first-contact run (YuNet `8f2383e4`, landmarker mesh `c7d54204`,
blendshapes `4f36dded`). 288 frames emitted, 216 compared. The 72
uncompared frames are exactly the unlit strobe-phase IR frames: every one
has mean pixel value 0.0 in its burst's `means.txt` while detected IR
frames average 65 to 69, so the detector never saw a face to reject.

## Per-segment results

`blink` = per-frame max(eyeBlinkLeft, eyeBlinkRight). 12 IR frames per
segment (the lit ones), 24 RGB.

| segment | kind | blink min | blink median | blink max | segment mean | EAR median |
|---|---|---|---|---|---|---|
| held-closure | rgb | 0.565 | 0.643 | 0.711 | 0.641 | 0.061 |
| held-closure | ir | 0.623 | 0.664 | 0.710 | 0.664 | 0.048 |
| held-closure-glasses | rgb | 0.058 | 0.107 | 0.194 | 0.115 | 0.276 |
| held-closure-glasses | ir | 0.578 | 0.628 | 0.645 | 0.620 | 0.090 |
| natural-blink | rgb | 0.057 | 0.125 | 0.557 | 0.193 | 0.264 |
| natural-blink | ir | 0.175 | 0.477 | 0.741 | 0.420 | 0.136 |
| natural-blink-glasses | rgb | 0.059 | 0.090 | 0.139 | 0.091 | 0.278 |
| natural-blink-glasses | ir | 0.196 | 0.427 | 0.681 | 0.417 | 0.167 |
| open-frontal | rgb | 0.083 | 0.105 | 0.156 | 0.110 | 0.263 |
| open-frontal | ir | 0.188 | 0.212 | 0.240 | 0.213 | 0.250 |
| open-frontal-glasses | rgb | 0.035 | 0.068 | 0.105 | 0.069 | 0.288 |
| open-frontal-glasses | ir | 0.204 | 0.251 | 0.406 | 0.266 | 0.218 |

## The margin exists on IR

Held-closure IR segment means are 0.664 (no glasses) and 0.620 (glasses),
against open-eye segment means of 0.213 and 0.266 on the same day and the
0.37 historical ceiling. Per frame: the lowest closed-eye IR reading is
0.578; the highest open-eye reading in this corpus is 0.406 (glasses-on
IR). A per-frame threshold of 0.5 separates every labeled frame here.
Natural blinks are catchable at the strobe's 13.7 fps: the natural-blink
IR segments reach 0.741 and 0.681 mid-blink, with segment means of 0.420
and 0.417, elevated over all four open-eye baselines.

The pooled EAR correlation is r -0.9928 over the 216 compared frames.
The first-contact figure (r -0.938) was measured on open eyes only and
could not distinguish blink signal from a shared image-condition artifact;
this corpus has both states, so the correlation now spans the event it is
supposed to track.

## Glasses glare blinds RGB, and it blinds both cues at once

Held-closure-glasses RGB reads open (blink mean 0.115, EAR median 0.276,
both open-typical) while the same pose on IR reads closed (0.620). The
frames explain it: the monitor's reflection fills both lenses in every RGB
frame of that segment, hiding the eyes completely, while the IR frames
show the closed eyes through the lenses with only small specular dots from
the emitter (verified visually on rgb02/10/18 and ir frame10). The
glasses-on RGB frames carry no eye-state information at all, so the
blendshape cue and the production EAR cue fail together on them. The same
mechanism explains natural-blink-glasses RGB, where no blink ever
registered (max 0.139).

## What this means for the #316 design question

- Blendshape blink and EAR are near-duplicate readings of the same
  geometry (r -0.9928 with closed frames included). Fusing them buys
  little independence: under lens glare both went blind on the same
  frames. The channel split is what carries independence on this
  evidence: IR kept the full closure margin in every condition measured,
  including the one where RGB carried nothing.
- Any closure gate built on this cue should read the IR mesh, and a
  consent watch sampling at the strobe rate has enough temporal
  resolution to catch a natural blink, not only a held closure.

## Not measured here

One subject, one camera, one lighting condition. The NexiGo N930W half of
the protocol still needs capture on the mini PC test bed. No dark-room
segments, no spoof presentations (a printed closed-eye face against this
cue is untested), and no measurement of how the 0.5 separation behaves on
other faces or other glasses.

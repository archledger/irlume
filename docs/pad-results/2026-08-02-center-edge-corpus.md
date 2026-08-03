# Centre/edge ratio corpus, 2026-08-02: the overlap, measured again

Captured with `irlume padcapture` (the real `LivenessGate`) on the ASUS FHD IR pin,
GREY8 640x400, dark room, one subject. Raw records in the `.jsonl` beside this file.

This corpus was gathered to see whether `MIN_CENTER_EDGE_RATIO` could be raised from
1.03 to separate a flat print from a live face. **It cannot**, and the run is kept
because it reproduces the 2026-06-30 conclusion with a second data set.

| kind | species | n | ratio min | ratio max | called Live |
|---|---|---:|---:|---:|---:|
| attack | print_banner_varied_angle | 20 | 0.00 | 1.51 | 4 |
| attack | print_vinyl_close | 12 | 1.12 | 1.21 | 12 |
| attack | print_vinyl_normal | 12 | 1.02 | 1.16 | 10 |
| bonafide | live_close | 12 | 1.26 | 1.37 | 10 |
| bonafide | live_far | 12 | 1.36 | 1.41 | 12 |
| bonafide | live_normal_glasses | 12 | 1.40 | 1.47 | 12 |
| bonafide | live_normal_noglasses | 12 | 1.40 | 1.43 | 12 |
| bonafide | live_offangle | 12 | 1.43 | 1.49 | 12 |

## What the two attack species mean

`print_vinyl_normal` and `print_vinyl_close` held the banner SQUARE to the camera at two
fixed distances. Read alone they suggest a clean separation: the print tops out at 1.21
while the lowest genuine capture that passes liveness reads 1.31, so a floor near 1.25
looks like it would reject every print and accept every face. A change doing exactly that
was written, tested, hardware-validated, and then closed unmerged (PR #239).

`print_banner_varied_angle` is the same banner, tilted and angled while capturing. It
reaches **1.51**, and four of its twenty presentations were accepted as Live even against
the proposed 1.25 floor. A floor high enough to block them would have to exceed 1.51,
which rejects all 58 genuine captures here.

The populations overlap. This is the same finding as
[`2026-06-30-ir-liveness-selftest.md`](2026-06-30-ir-liveness-selftest.md), which measured
the banner at 1.02 to 1.58 over 70 varied presentations and wrote that "a naive 1.03 to
1.30 tightening would have been false confidence". It was right, and an attack sample that
holds the instrument still is what makes the tightening look safe.

## For anyone tuning this cue later

Vary the presentation. An attack corpus captured at one angle measures how the instrument
behaves at one angle, not how an attacker behaves. The 1.03 floor is not defensible either;
what the numbers say is that a brightness ratio on a 2D IR sensor cannot carry this gate,
which is what ADR 0001 already lists as residual risk.


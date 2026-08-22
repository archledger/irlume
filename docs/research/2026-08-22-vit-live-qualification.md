# ViT liveness — live qualification session, 2026-08-22 — NOT QUALIFIED

Agent: opencode · Host: local Zenbook (UX5406S) `/dev/video0`, MJPG
640×480 (matching the 2026-08-12 corpus convention), user present as
operator + subject. Harness: `vit_live_session.py` + `cap.sh` (session
scorer committed; per-frame scores in
[`2026-08-22-vit-live-session-scores.csv`](2026-08-22-vit-live-session-scores.csv)).
Scoring identical to the offline evaluation: YuNet largest-face bbox, m96
crop margin, resize 224, P(spoof) = softmax(logits)[1], 5-frame-median
voting, threshold 0.60.

## Protocol

Genuine: desk light without/with glasses; dim-marginal (screen-lit);
close-up. Attacks: vinyl banner (flat login-distance, close); phone
displaying the user's face photo (far, login-distance ×2 runs, close ×2,
tilt). 48-frame captures, 12+ frames auto-exposure settling dropped, first
session attempt frames verified by luma trace. Instruments on hand: vinyl
banner, phone, glasses.

## Results

| # | condition | box w (px) | P(spoof) med | 5-med vote | outcome |
|---|---|---|---|---|---|
| G1 | genuine desk, no glasses | — | 0.447 | REAL 0/32 | pass |
| G2 | genuine desk, glasses | — | 0.373 | REAL 0/32 | pass |
| G3 | genuine dim-marginal (luma ≈38) | — | 0.465 | REAL 0/35 | pass — no flrgb-style collapse |
| G4 | genuine close | 296 | 0.368 | REAL 0/44 | pass |
| A1 | banner flat, login distance | — | 0.656 | SPOOF 38/44 | caught |
| A2 | banner close | — | 0.594 | split 18/44 | marginal |
| A3 | phone far | ~75 | 0.624 | SPOOF 43/44 | caught |
| A4 | phone login distance | ~226 | **0.455** | **REAL** | **MISS** |
| A5 | phone close | ~316 | 0.566 | split 17/44 | marginal |
| A6 | phone tilt / close (varied run) | ~283 | 0.455 / 0.700 | mixed | partial |

Sub-detection dark regimes (luma 1–9) produced no detectable face —
correct abstention; dark login is the IR path where FLIR covers it.

## The decisive finding: scale-dependent phone hole

The phone species is score-ordered by presented face size: far ≈0.62
(caught), login-distance ≈0.455 (**missed, REAL-side**), close ≈0.57
(split). The missed presentation is the realistic one — a phone held where
a face would be during login. The G4 control (genuine close, box 296 px,
same scale band as A5) scored 0.368: the model still separates at matched
scale, but the phone-at-login-distance band (0.455) sits INSIDE the
genuine range (0.34–0.55). A3's first run caught the same presentation
(0.671), so the species is also inconsistent run-to-run at mid scale —
bistable, not a stable margin.

No threshold recovers this: 0.55 catches A2/A5 but not A4 (0.455) and
begins flagging genuine (offline corpus genuine max 0.551); 0.60 misses
A2/A4/A5. Voting cannot repair a wrong median.

## Verdict

**Not qualified.** Genuine-side behavior is excellent (0 false-fires
across 180 frames including dim and close regimes, and the flrgb
low-light collapse is absent), and the banner is caught at every
presentation. But the phone at login distance — the cheapest, most common
RGB attack — reads as REAL, inconsistently with distance and between runs.
As a deny-only cue it would add banner protection and zero reliable phone
protection on this camera; the offline window [0.56, 0.604] (~0.04 wide)
did not survive a second session and a second instrument. Per the FLIR
precedent's bar, this is a decline.

The RGB PAD slot stays empty on the evidence. flir remains the only
qualified third-party PAD artifact (IR side, where screens and phones
present no face at all — the physics the RGB side cannot replicate).

## What would reopen

A candidate that holds the phone-at-login-distance species above its
genuine maximum on THIS camera, or a genuinely cross-scale-stable margin.
The session corpus (10 conditions, 480 frames) is retained in the local
research store as the replay baseline for the next candidate.

Raw captures are biometric and stay local per the standing rule.

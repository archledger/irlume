# FaceID (milansinghal2004) review — checked, not a candidate

Date: 2026-08-21 · Agent: opencode · Source:
`https://github.com/milansinghal2004/FaceID` (1 commit, MIT, ~500 lines
Python, no tests, no measurements)

## What it is

An RGB-only Python *application* — not a model, no artifact to download or
benchmark. MediaPipe Face Mesh + a three-layer pipeline: passive liveness
(Laplacian variance + FFT high-frequency energy), active challenge-response
(blink/pose, EAR threshold 0.18), identity by geometric landmark signature
(normalized 3-D landmark positions, Euclidean distance), users stored in
`data/users.json`.

## Check against irlume, component by component

| FaceID component | irlume status |
|---|---|
| FFT moire / screen-artifact cue | **Already shipped** (`irlume-vision` moire module, N=128 FFT plan, measured across `docs/pad-results/` since June) |
| Laplacian/sharpness cue | Already shipped (quality/starvation cues; the sun/ambient regimes in the pad-results series are exactly these measured properly) |
| Active blink/pose challenges | **Deliberately retired** (PR #502: eye challenges removed, keyboard-confirmed face intent instead — the recorded design decision supersedes this approach) |
| Geometric-landmark identity matching | Strictly weaker than the shipped AuraFace 512-D embeddings; landmark geometry is also the identity signal a mask reproduces best |

Nothing adoptable: every layer is either already present, retired on
evidence, or weaker than what ships.

## Findings worth recording

1. **The README misdocuments security**: it claims `users.json` holds
   "Encrypted face signatures"; `database.py` writes plain `json.dump`
   output — no encryption anywhere in the codebase.
2. **The FFT thresholds are tuned to the author's own camera**, by the
   code's own comments ("Based on your camera: RAW-F of 102.6 is a real
   face … Screens typically jump to 200-400"): `texture_analysis.py`
   hardcodes 130/100. A cue calibrated to one camera is the trap the whole
   `docs/pad-results/` series exists to avoid.
3. The README's threat table (e.g. "3D Mask … frequency analysis detects
   unnatural skin texture") is unevidenced — no measurement backs any row.

No further action; recorded so the candidate is not re-investigated.

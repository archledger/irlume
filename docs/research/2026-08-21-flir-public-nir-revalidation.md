# FLIR public-NIR revalidation at scale — 2026-07-17 qualification holds on physics-matched NIR

Date: 2026-08-21 · Agent: opencode · Scoring host: archhost (Ryzen 7 5700G,
CPU, ort-venv) · Model: the exact qualified artifact, sha256-verified

## Question

FLIR (`iic/cv_manual_face-liveness_flir`, the only qualified third-party PAD
cue, wired deny-only per
[`2026-07-17-third-party-pad-candidates.md`](../pad-results/2026-07-17-third-party-pad-candidates.md))
was qualified on a single-subject field corpus. Does its genuine-side
behavior survive a large multi-identity NIR population, and does the attack
side extend to the stored local attack bursts?

`modelscope download --model iic/cv_manual_face-liveness_flir` was re-run:
the artifact hashes exactly to the pinned qualified sha256
`df80cea7228b92562692e56aac965d35766c77399159798c552fb3c77b410c72` — the
same weights, so the 2026-07-17 wiring and threshold (0.9, lit-phase-only,
deny-only) remain bound to this measurement.

## Method

`benchmarks/pad-candidates/flir_public_nir_score.py` (committed): identical
preprocessing to the qualified `flir_eval.py` (gray→BGR replicate, YuNet
largest-face bbox, `align_face_padding` 16/112, `(px-127.5)/128`, softmax
once). Corpora:

- **CBSR active-NIR 850 nm** — 3,940 faces, 197 identities. This is the
  deployment physics class (active 850 nm illumination, as on the Zenbook /
  NexiGo IR nodes).
- **Tufts td NIR-a** — 3,215 detected frames, 110 identities. Passive-style
  NIR stills at a different wavelength, tight 224×224 crops; included as the
  domain-mismatch arm, not as a deployment claim.
- **Local attack bursts** — `irlume-suncal/spoof-01..07` (paper ×4, screen,
  phone, video replay; 36-frame NexiGo IR strobe bursts), dark strobe frames
  (mean luma < 10) skipped per the qualified convention.

## Results (per-frame P(fake))

| corpus | n | median | p90 | p99 | max | ≥0.5 | ≥0.9 |
|---|---|---|---|---|---|---|---|
| CBSR 850 nm genuine | 3,940 | **0.0000** | 0.0001 | 0.0085 | 0.8645 | **2** | 0 |
| Tufts NIR genuine (mismatch arm) | 3,215 | 0.3298 | 0.9209 | 0.9924 | 0.9994 | 1,279 | 388 |
| attack bursts (all 7 species) | 0 | — | — | — | — | — | — |

Attack bursts: **no face is detectable in IR in any of the 252 frames** —
paper prints present a dark/blank surface to 850 nm and screens/phones emit
nothing there. Presentations never reach the PAD cue; this is the same
non-response class the 2026-07-17 phone finding recorded. The attack-side
evidence therefore remains the 2026-07-17 vinyl-banner session (122/123
frames flagged); nothing here weakens it.

## Reading

- **The qualification survives contact with 197 new identities at the
  deployment physics**: on 850 nm active-NIR imagery the false-fire rate is
  2/3,940 at the conventional 0.5 line and 0/3,940 at the wired 0.9
  threshold. Genuine medians sit at 0.0000, matching the single-subject
  field measurement (0.001–0.13).
- **The Tufts arm bounds the domain**: on 1122 nm-style tight-crop stills the
  false-fire rate rises to ~40% at 0.5. Deployment cameras are CBSR-class,
  so this is a recorded generalization caveat, not a deployment defect — but
  it predicts FLIR will misfire if ever fed stills/transcoded NIR rather
  than live 850 nm frames, which is worth knowing before anyone reuses the
  cue off-device.
- No change to the wiring: deny-only, 0.9, lit-phase frames only.

Per-corpus JSON: [`2026-08-21-flir-public-nir.json`](2026-08-21-flir-public-nir.json).

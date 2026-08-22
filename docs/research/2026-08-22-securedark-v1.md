# SecureDark v1 — evidence base and the open measurement protocol

Date: 2026-08-22
Branch: feat/securedark (ADR-0016 stage 1)

## What shipped (stage 1)

1. **Scene gate**: `scene_conclusively_lit(rgb_frame_mean) >=
   CONCLUSIVE_SCENE_BRIGHTNESS (100.0)` refuses the pure-dark path (retryable
   Uncertain). Closes the lit-room IR-only routing hole.
2. **`IR_DARK_MATCH_THRESHOLD = 0.60`** for pure-dark best-of-N and centroid
   arms; adapter arm unchanged (0.40, its own validated bar).

## Evidence relied on (all pre-existing, cited in the constant docs)

- CBSR NIR full-dataset benchmark (197 ids / 3,940 faces / 7.72M impostor
  pairs; `benchmarks/results-nir_results.json`): AuraFace EER 0.77% @0.495;
  FAR/FRR 0.55 → 1.3e-3/1.7%; 0.60 → 2.7e-4/3.0%; FAR≤1e-4 @0.635 (FRR 4.6%).
- Genuine/impostor OVERLAP (impostor MAX 0.900 vs genuine mean 0.855): no
  threshold separates the classes on CBSR; PAD carries the species defense.
- ADR-0002 live vinyl-banner measurement: the enrolled user's life-size
  print scored IR cosine 0.650 (would clear 0.60 AND 0.635); stopped by the
  then-challenge, today by FLIR PAD + physics + the per-user floor.
- Scene-brightness landscape (`irlume-camera::CONCLUSIVE_SCENE_BRIGHTNESS`
  provenance): pitch-dark RGB mean ≈17, dark room ≈62 (NexiGo 2026-07-25),
  dim ≈83, lit arm 117-143; boundary 100.0.
- Threshold inversion being fixed: dim-light fallback demanded 0.60 with an
  RGB face verified; pure dark granted at 0.55 with none.
- Per-user calibration (ADR-0004): FRR 33%→15% at 0.55 in hard conditions
  with zero measured FAR inflation (1,600+ strangers); ridge λ fixed;
  unchanged by this work.

## The open measurement (user-present session; blocks stages 2-4)

**Live dark-session genuine distribution** — needed before any bar above
0.60 and before a multi-frame agreement constant:

1. Per dual-capable host (ASUS + minihost; archhost pending its Brio dual
   investigation), lights OFF, evening: N ≥ 30 dark-path auths of the
   enrolled user (vary distance 30-70cm, glasses on/off, angle).
2. Record per-auth: ir/dark best cosine, centroid cosine, rgb_frame_mean,
   liveness verdict + signals (center/edge, ambient), FLIR p_fake,
   frame-pair cosines for the temporal-constant design (embed the two best
   non-blown lit frames of each burst and record their pairwise cosine —
   the same-person-across-frames distribution is the constant FLIR never
   needed and we must not guess).
3. Decision rules, written before the data: raise the bar to 0.635 only if
   the live genuine 1st-percentile clears it with ≥0.02 margin; otherwise
   0.60 stands and the SecureDark answer to FAR is multi-frame AND-scoring
   (two frames each ≥ 0.60 — correlated frames, so treat as hardening, not
   a squared FAR) plus the scene gate.
4. Same session, one lit-room control: confirm the scene gate refuses
   IR-only in a lit room on every host (present a face, cover nothing).

## Residuals (disclosed, not fixed by stage 1)

- An attacker who can physically darken the room faces the full dark stack
  (FLIR + physics + 0.60) — same posture as before, now with a tighter bar.
- The banner species (0.650) clears any plausible threshold; FLIR is the
  defense; its kill switch (`IRLUME_PAD_IR=0`) disables it knowingly.
- Dim rooms (mean < 100) with genuinely undetectable RGB faces still take
  the dark path at 0.60 — the gate is deliberately "conclusively lit", not
  "any light", so it never false-refuses a legitimate dark user.

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

## Offline sweep results (2026-08-22 night, benchmarks/securedark_sweep.py,
CBSR 197 ids / 347,508 impostor pairs deployment-shaped best-of-11; Tufts
109 ids, victim-calibrated impostors, the exact ir_match_in shape):

- **CBSR best-of-N with PRODUCTION scaling** (+0.015*log2(11) = +0.052):
  0.60 base -> effective 0.652: **FAR 1.38e-4 / FRR 0.62%** (better than the
  flat-threshold 2.7e-4 the historical pairwise figure implied — best-of-N
  inflates FAR ~2.7x over pairwise, and the shipped scaling more than pays
  it back at N=11). 0.635 base -> 0.687: FAR 5.2e-5 / FRR 0.79%.
- **Tufts cross-spectral, per-user calibration (λ=0.5, k=5, best-of-N)**:
  FAR@0.60 = 1.0e-4, FRR 4.32% vs no-calibration FAR 4.9e-5 / FRR 6.64%.
  The calibration costs ~2x FAR at equal threshold (impostor max 0.617 ->
  0.737) while cutting FRR a third — the first quantification of that
  trade, both arms ~1e-4-class at 0.60. k=5 fit pairs beat k=3 on FRR at
  every λ (4.3% vs 5.3% at λ=0.5): enrollment should keep >=5 IR/RGB pairs.
  λ=1.0 trades slightly better FAR / slightly worse FRR than λ=0.5; the
  shipped 0.5 stays (midpoint of the measured-safe band, ADR-0004).
- Within-session-split caveat (labeled in the script): CBSR genuine tails
  are optimistic vs cross-session; the LIVE dark-session measurement
  remains the gate for anything above 0.60.

Net: the shipped 0.60 + scaling is STRONGER than the ADR's flat-number
claim; no constant changes tonight. The 0.635 rung now has deployment-
shaped support on both corpora (5.2e-5 / 4.9e-5 FAR) and stays live-gated.

## Offline sweep v2 (2026-08-23, OR-arm + multi-frame design numbers)

The committed sweep measured each grant arm separately; production's dark
path grants on best-of-N OR calibrated-centroid. cbsr_v2 (same corpus,
same split, `--cache` npz):

- **OR operating point (the number that matters)**: base 0.60 -> single
  frame **FAR 4.03e-4 / FRR 0.56%**; 0.615 -> 2.62e-4 / 0.64%; 0.625 ->
  1.90e-4 / 0.67%; 0.635 -> 1.24e-4 / 0.69%; 0.65 -> 7.2e-5 / 0.89%.
  The OR costs ~2.9x the best-of-N arm's FAR at 0.60 — the centroid arm
  is the contributor (its own FAR 4.0e-4 at 0.60 flat).
- **AND-of-2 consecutive frames** (correlated, same burst — the honest
  upper bound for same-burst multi-frame): 0.60 -> FAR 2.65e-4 / FRR
  0.76%; only a 1.5x FAR improvement over single-frame. Confirms the
  design note: correlated frames are hardening, NOT a squared FAR; a
  meaningful multi-frame win needs the temporal constant or cross-burst
  frames, not a second frame from the same burst.
- **Frame-pair cosines (the temporal-constant input, CBSR arm)**:
  genuine adjacent same-id frames p1 = 0.520, p5 = 0.666, p50 = 0.944,
  mean 0.894, min 0.334; impostor first-probe pairs p50 = 0.255. The
  same-person-across-frames distribution is wide — a temporal agreement
  constant near ~0.52 would carry ~1% intra-person rejection; near 0.67
  ~5%. Any multi-frame agreement gate must be designed against the LIVE
  in-burst distribution (which will be tighter than CBSR stills), with
  these numbers as the loose-bound anchor.

## ASUS (Shinetech module) auto-shutter finding — live session blocked

The 2026-08-23 live dark session on the ASUS could not complete; the
camera module's own firmware defeats it. All observations controlled,
sampled at 2 Hz via the read-only `privacy` UVC control:

- Idle in complete darkness: privacy stays 0 (135/135 samples over 70 s).
- Actively streaming in complete darkness: privacy engages =1 on BOTH
  nodes mid-capture within seconds (caught live, 20:57).
- Streaming in a lit room: never engages (all historical sessions).
- Release: within seconds of the stream stopping or light returning.
- **Decisive control: RGB lens taped + fully lit room -> still engages**
  during streaming. The firmware judges darkness from its own RGB
  stream's content, not the room's actual illumination.
- Consequence: sustained dark-room streaming on this host is firmware-
  impossible; the band between "RGB still finds a face" (mean ~50) and
  the engage threshold (~40s, one good grant at mean 41 exists) has
  hysteresis and flaps mid-capture (~50 loop failures observed, all
  failing CLOSED: irlume refuses capture and any emitter write when
  privacy reads 1 — correct behavior, no unsafe fallback taken).
- The module's HID descriptor exposes a Windows `Sensors.
  BiometricHumanPresence` sensor stack (Shinetech 3277:0059): the
  presence/darkness policy is firmware-owned and not configurable from
  Linux (the ASUS Windows "Camera Extension" installer is a Realtek
  package for a different module; irrelevant here).
- No ambient-light sensor exists on this laptop (IIO exposes two `prox`
  presence sensors only, no `in_illuminance*`), so the engage threshold
  cannot be cross-read from lux.
- The live >=30-auth dark session moves to minihost (NexiGo N930W, no
  such firmware behavior). ASUS dark-room support = fail-closed denial
  + password fallback, recorded as a host quirk.

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

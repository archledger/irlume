# V-shape (velocity) blink detector: design traces + validation, 2026-07-01

Follow-up to [2026-07-01-passive-ear-realworld-nonresponse.md](2026-07-01-passive-ear-realworld-nonresponse.md).
Same-day rework of `irlume_liveness::detect_blink` from a depth threshold to a
strobe-aware sharp-V detector, designed against raw 15 fps traces and validated
live (meshprobe + real `sudo` through the daemon).

## What the raw traces showed (meshprobe `--burst 1 --trace`)

1. **The emitter strobes exactly 1-of-2**: frames alternate emitter-lit
   (bri ≈50–90) and ambient-only (bri ≈0–12). In lit rooms the ambient frames
   still yield EAR, but systematically ~0.03 *lower* than lit frames, so a
   single shared median baseline is polluted. Detection must baseline each
   brightness class separately.
2. **Real blinks are sharp Vs**, not deep dips: e.g. lit-class
   `0.212 → 0.173 → 0.205` (one frame at 0.82× baseline) and dark-room
   `0.176 → 0.129 → 0.142 → 0.174` (two frames at 0.73×/0.81×). The old
   0.72×-depth rule missed most of these.
3. **Dark rooms produce a clean lit-class-only series** (ambient frames have no
   face); blink dips are visible when the capture survives.
4. **Camera-layer bugs in darkness** (separate follow-up): ~1 s of auto-exposure
   blowout at stream start (bri 255.7 saturated, no face), and a **stream-death
   mode** where frames freeze at exactly bri 144.0 for the rest of the window
   (dominates in a pitch-dark closet; fail-safe holds: no face → never grant).
5. **AE-settle risk**: EAR sags in sync with brightness slewing; with only a
   handful of samples such a dip once scored Live (genuine subject, but a
   plausible artifact vector) → countered with a minimum-samples floor and a
   brightness-band check on the V's reference samples.

## Detector (see constants in `irlume-liveness`)

Per-class median baseline (classes = emitter-lit vs ambient, split by local
brightness midpoint when the strobe is visible) → ratio timeline → blink =
deep dip (≤0.72×, unchanged) OR sharp V: a same-class run of ≤6 samples at
≤0.88×, deep enough for its length (single sample ≤0.82×, multi ≤0.85×), with
near-open (≥0.93×) samples at comparable exposure (±25% brightness) within 4
frames before and 6 after. Classes need ≥8 face samples and a ≥0.15 median EAR.
Auth window: 75 raw frames at burst=1 (~5 s, full 15 fps).

## Validation (same day)

meshprobe, 12 reps per condition:

| Condition | Blinked/Live | Notes |
|---|---|---|
| Genuine, kitchen sun | 9/12 | was ~1/12 with the depth rule |
| **Banner (attack)** | **0/12** | flat, min ratio ≈0.89–0.92; APCER 0% |
| Genuine, glasses | 6/12 | was 0/12; rest NoEyes (median < 0.15 floor) → password |
| Pitch-dark closet | n/a | stream-death bug dominates (camera follow-up) |

End-to-end (real `sudo` → pam_irlume → daemon, challenge ON): **8/10 grants**:
couch 2/2, desk 2/2, glasses 2/3, lying on couch 2/3; misses fell back to
password. Same test was 0/11 in the morning.

## Remaining follow-ups

- Camera stream-death recovery + saturation skip SHIPPED same day (see
  `capture_ir_sequence`): bit-identical mid-grey frames → stream re-arm (≤4,
  after 2 consecutive), blown frames (≥245) skipped, attempt budget 2×+30.
  Validated: the infinite constant-144 lock is gone (recoveries observed,
  one dark meshprobe rep went n=0 → n=11/Live). **Residual dark-room gap:**
  in near-total darkness auto-exposure pumps blown↔grey-fault and each re-arm
  resets the settle; real daemon path (exposure pre-warmed by the match scan)
  granted 3/8 sudo attempts in a dark room (was 0). The full fix is a
  warm-stream refactor: hold ONE IR stream across match scan + passive window
  so exposure never resets mid-auth (also shaves the reopen latency).
- Glasses UX: half the reps read NoEyes because the glasses baseline (~0.13–0.14)
  sits under `BLINK_MIN_OPEN_EAR` (0.15). Lowering toward 0.12 would likely
  raise the glasses catch rate; needs a spoof-side check first.
- The banner margin on the run threshold is modest (banner min ratio 0.89 vs
  0.88 cutoff); the depth-for-length and pre/post requirements provide the real
  margin. Re-run the banner if any constant is loosened.

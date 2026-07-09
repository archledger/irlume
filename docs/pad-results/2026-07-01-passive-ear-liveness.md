# Passive EAR blink liveness, validation 2026-07-01

Validation of the passive natural-blink liveness gate (MediaPipe FaceMesh → EAR →
`detect_blink`, ADR-0002) that replaced both the defeated single-frame IR gate and
the bad-UX deliberate-blink challenge. Same ISO/IEC 30107-3 tooling as the PAD
self-test (`irlume meshprobe --reps … --out` → `irlume padreport`).

- **Hardware:** Zenbook S14 IR module. **Gate:** commit `a8d839d`, passive path
  (`run_passive_liveness`): ~5 s IR window (40 samples, de-strobe burst 2), per-frame
  min-eye EAR, `BLINK_EAR_DIP_RATIO=0.72` of the median-EAR baseline.
- **Subject:** enrolled user (attacks = the life-size vinyl graduation banner).

## Results

| presentation | n | verdict spread | APCER / BPCER |
|---|---:|---|---|
| **bonafide** (natural blink, no prompt) | 10 | 9 Live · 1 non-response · 0 reject | BPCER **0%** [0, 30.8%] |
| **banner** (attack, varied angle/distance) | 10 | 0 Live · 10 non-response | APCER **0%** [0, 30.8%] |

**Worst-case APCER 0% · BPCER 0% · non-response 10% (bonafide).** The 98.6%-APCER
vinyl-print breach is **closed passively**, with no user action.

## Why the detector separates live from banner

The detector is **relative to each presentation's own median EAR**, so it needs no
per-user calibration and is scale-invariant:

- **Live:** open EAR ~0.20–0.27; a natural blink dips to **~0.11–0.14** = **0.55–0.65×**
  the median → below the 0.72 threshold → blink detected.
- **Banner:** median ~0.22; even across angles its min only reached **0.166–0.20** =
  **0.75–0.90×** the median → no proportional dip → rejected.

A diffuse printed eye can't produce the proportional collapse a real eyelid does, and
being static it never dips at all.

## Limitations before trusting as a default gate

1. **Small n:** CI upper bounds ~30.8% at n=10 each; capture more to tighten.
2. **10% non-response:** a genuine user whose blink is shallow, or who doesn't blink
   in the ~5 s window, gets `Uncertain` (re-present / password fallback, never a hard
   reject). Natural blink rate (~15–20/min) makes a blink likely but not certain per
   window; a longer window or a slightly looser ratio would reduce this, but only
   after re-checking the banner stays at APCER 0.
3. **One session, good light, no glasses, frontal.** NOT yet validated across
   **glasses** (IR reflections / occluded lid), **dark**, **distance**, or **extreme
   angle** for FRR, nor a **moving/tilted** banner across many more specular angles
   for FAR. That broader campaign is the remaining work.
4. **Ships opt-in / OFF** (`require_challenge` flag, `irlume profiles challenge on`);
   default-on waits on the broader-condition validation above.

## Glasses limitation: 80% non-response (2026-07-01)

Ran the genuine FRR test again **with glasses on** (10 presentations, same gate):

| condition | Live | non-response | hard-reject (BPCER) |
|---|---:|---:|---:|
| no glasses | 9/10 | 10% | 0 |
| **glasses** | **2/10** | **80%** | 0 |

**Safe but not usable.** Every glasses miss was `Uncertain` → password fallback: no
false accept, no hard reject; security is intact. But an 80% non-response rate makes
the gate unusable for glasses-wearers as shipped.

**Confirmed across distances (not a distance/tuning issue):**

| glasses condition | Live | non-response | blink dip |
|---|---:|---:|---|
| arm's length (run 1) | 2/10 | 80% | 0.11–0.20 |
| close to camera | 1/10 | 90% | 0.11–0.17 |
| arm's length (run 2) | 0/10 | 100% | 0.166–0.186 (barely dips) |

**Root cause: the separation collapses.** On IR grey the RGB-trained mesh can't
resolve the eyelid closing through the glasses (lens IR-reflections / frame confuse
the eye-contour landmarks), so EAR barely dips: glasses blinks reached only
**0.70–0.90×** the baseline, which **overlaps the banner's jitter (0.75–0.90×)**. No
single relative-dip ratio passes glasses-genuine *and* rejects the banner; loosening
0.72→0.78 would admit the banner's 0.75× jitter (a breach). **EAR alone is
insufficient with glasses, at any distance.**

**Options (none a quick tweak; a future session):**
1. **Temporal shape:** detect a blink as a fast V (drop-then-recover *velocity*), not
   just depth. A real blink is a sharp transient; glasses/banner jitter is not. May
   recover the separation where a static depth threshold can't.
2. **Two-cue OR:** pass on (EAR blink) OR (corneal-specular contrast floor), so a
   glasses-wearer whose blink is shallow still passes on the specular cue while the
   diffuse banner fails both. Needs testing whether glasses pass the contrast floor
   and the banner still fails it.
3. **Refined eye/iris landmarks:** the `face_landmark_with_attention` model has
   better eye/iris points but doesn't ONNX-convert (custom op); would need a different
   conversion route.
4. **Accept with a caveat:** ship opt-in, documented "works best without glasses";
   glasses-wearers fall to password (safe, poor UX for a large population).

Until one of these is validated, passive liveness stays **opt-in/OFF** and is NOT
suitable for default-on where glasses-wearers are common.

### Two-cue OR: tested and REFUTED (2026-07-01)

Measured the corneal-specular **contrast** cue (peak over the window) for glasses-
genuine vs the banner, to test the two-cue "EAR blink OR contrast floor" idea:

| group | contrast_max | EAR verdict |
|---|---|---|
| glasses-genuine (10) | **143–181** | all Uncertain (EAR fails, as before) |
| banner (10) | 38–72 for 9/10, **125** for 1/10 | **1/10 false-EAR-blinked (breach)** |

Glasses eyes *do* clear a contrast floor (143+ ≫ ~90). But the idea fails on security:

1. **OR increases FAR.** One banner presentation both false-EAR-blinked *and* spiked
   contrast to 125 (a glossy specular hotspot). OR accepts if *either* cue fires, so
   it breaches; OR-combining cues makes the gate *more* permissive, the wrong way.
2. **Contrast can't separate cleanly.** The banner's specular tail (**125**) *exceeds*
   no-glasses genuine (~120), so no single contrast floor passes both genuine types
   (no-glasses ~120, glasses 143+) *and* rejects the banner's 125.
3. **The banner beats EAR too, occasionally.** 1/10 here + 0/10 earlier ≈ **APCER ~5%
   (1/20)** for EAR-alone: a determined glossy print false-blinks at some angle.

**Conclusion.** On this 2D-IR camera, no combination of EAR + specular contrast
reliably separates *all* genuine conditions (esp. glasses) from a determined
life-size glossy print. This is the passive-cue ceiling ADR-0001 named:
the durable fix is a **trained PAD model** (Track B, license-blocked) or **true depth
hardware**. Passive EAR remains a useful *deterrent* (closes casual/typical print
attacks, works well without glasses) but is **not a guarantee** against a determined
glossy print and **does not cover glasses-wearers**; ship opt-in with those limits.

## Reproduce

```sh
export ORT_DYLIB_PATH=/usr/lib64/libonnxruntime.so   # stop irlumed first
DET=models/face_detection_yunet_2023mar.onnx; MESH=models/face_landmark.onnx; LOG=ear.jsonl
irlume meshprobe --det $DET --mesh $MESH --reps 10 --species bonafide --kind bonafide --out $LOG
irlume meshprobe --det $DET --mesh $MESH --reps 10 --species banner   --kind attack   --out $LOG
irlume padreport --in $LOG
```

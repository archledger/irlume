# Passive EAR blink liveness — validation 2026-07-01

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
vinyl-print breach is **closed passively** — no user action.

## Why it separates (the key finding)

The detector is **relative to each presentation's own median EAR**, so it needs no
per-user calibration and is scale-invariant:

- **Live:** open EAR ~0.20–0.27; a natural blink dips to **~0.11–0.14** = **0.55–0.65×**
  the median → below the 0.72 threshold → blink detected.
- **Banner:** median ~0.22; even across angles its min only reached **0.166–0.20** =
  **0.75–0.90×** the median → no proportional dip → rejected.

A diffuse printed eye can't produce the proportional collapse a real eyelid does, and
being static it never dips at all.

## Honest limitations (before trusting as a default gate)

1. **Small n** — CI upper bounds ~30.8% at n=10 each; capture more to tighten.
2. **10% non-response** — a genuine user whose blink is shallow, or who doesn't blink
   in the ~5 s window, gets `Uncertain` (re-present / password fallback, never a hard
   reject). Natural blink rate (~15–20/min) makes a blink likely but not certain per
   window; a longer window or a slightly looser ratio would reduce this — but only
   after re-checking the banner stays at APCER 0.
3. **One session, good light, no glasses, frontal.** NOT yet validated across
   **glasses** (IR reflections / occluded lid), **dark**, **distance**, or **extreme
   angle** for FRR, nor a **moving/tilted** banner across many more specular angles
   for FAR. That broader campaign is the remaining work.
4. **Ships opt-in / OFF** (`require_challenge` flag, `irlume profiles challenge on`);
   default-on waits on the broader-condition validation above.

## GLASSES — a real limitation found (2026-07-01)

Ran the genuine FRR test again **with glasses on** (10 presentations, same gate):

| condition | Live | non-response | hard-reject (BPCER) |
|---|---:|---:|---:|
| no glasses | 9/10 | 10% | 0 |
| **glasses** | **2/10** | **80%** | 0 |

**Safe but not usable.** Every glasses miss was `Uncertain` → password fallback — no
false accept, no hard reject; security is intact. But an 80% non-response rate makes
the gate unusable for glasses-wearers as shipped.

**Root cause — the separation collapses.** Glasses lower the open-EAR baseline and
make blink dips shallower *relative* to it: glasses blinks reached only **0.70–0.85×**
the median, which **overlaps the banner's jitter range (0.75–0.90×)**. So no single
relative-dip ratio passes glasses-genuine *and* rejects the banner — loosening 0.72→
0.78 to catch glasses blinks would also admit the banner's 0.75× jitter (a breach).
The single-metric relative-dip detector is insufficient with glasses.

**Options (none a quick tweak; a future session):**
1. **Temporal shape** — detect a blink as a fast V (drop-then-recover *velocity*), not
   just depth. A real blink is a sharp transient; glasses/banner jitter is not. May
   recover the separation where a static depth threshold can't.
2. **Two-cue OR** — pass on (EAR blink) OR (corneal-specular contrast floor), so a
   glasses-wearer whose blink is shallow still passes on the specular cue while the
   diffuse banner fails both. Needs testing whether glasses pass the contrast floor
   and the banner still fails it.
3. **Refined eye/iris landmarks** — the `face_landmark_with_attention` model has
   better eye/iris points but doesn't ONNX-convert (custom op); would need a different
   conversion route.
4. **Accept with a caveat** — ship opt-in, documented "works best without glasses";
   glasses-wearers fall to password (safe, poor UX for a large population).

Until one of these is validated, passive liveness stays **opt-in/OFF** and is NOT
suitable for default-on where glasses-wearers are common.

## Reproduce

```sh
export ORT_DYLIB_PATH=/usr/lib64/libonnxruntime.so   # stop irlumed first
DET=models/face_detection_yunet_2023mar.onnx; MESH=models/face_landmark.onnx; LOG=ear.jsonl
irlume meshprobe --det $DET --mesh $MESH --reps 10 --species bonafide --kind bonafide --out $LOG
irlume meshprobe --det $DET --mesh $MESH --reps 10 --species banner   --kind attack   --out $LOG
irlume padreport --in $LOG
```

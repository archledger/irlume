# IR liveness PAD self-test, 2026-06-30

First run of the ISO/IEC 30107-3 self-test (`irlume padcapture` / `padreport`, see
[`../PAD_SELFTEST.md`](../PAD_SELFTEST.md)) against the credential-releasing IR gate.

- **Hardware:** Zenbook S14 (UX5406S) Windows-Hello RGB + 2D-IR module, 850 nm emitter.
- **Gate commit:** `5cd24e0` · path: `full` (RGB+IR) · fixed thresholds
  (`IR_FACE_MIN_BRIGHTNESS=35`, `DEPTH_MIN_RATIO=1.03`, `GLINT_MIN=180`).
- **Subject:** the enrolled user (attacks used photos of that same identity).

## Results

| PAI species | n | APCER | 95% CI | non-resp | caught-by |
|---|---:|---:|---|---:|---|
| phone_replay | 20 | 0.0% | [0.0%, 16.8%] | 0% | `face_in_ir`×20 |
| laptop_replay | 20 | 0.0% | [0.0%, 16.8%] | 5% | `face_in_ir`×19 |
| print_matte (regular paper) | 20 | 0.0% | [0.0%, 16.8%] | 10% | `face_in_ir`×18 |
| **print_banner (life-size vinyl)** | **70** | **98.6%** | **[92.3%, 100%]** | 0% | `depth`×1 |
| bona-fide baseline | 10 | n/a (BPCER 0/10) | [0%, 30.8%] | 0% | n/a |

**Worst-case APCER 98.6% · BPCER 0%.** The self-test is not lab-accredited (small
n, single session, one operator); see PAD_SELFTEST.md §7.

## Finding: a life-size glossy vinyl print defeats the gate

Emissive screens (phone/laptop) and a **matte paper** print were all rejected at the
**first** cue, `face_in_ir`, because they render no detectable face under 850 nm on
this sensor. The **vinyl graduation banner** did not:

1. **Vinyl reflects 850 nm** → it produces a real, detectable IR face, defeating
   `face_in_ir` (the cue that stopped everything else).
2. **`depth` (the 2D backup) is defeated too.** Our "depth" is a brightness
   center/edge *ratio*, not a real depth measurement (this is a **2D IR camera, not
   a structured-light depth sensor**). A large flat print's IR illumination-falloff
   mimics facial depth.

### Threshold tuning cannot fix it: overlap is proven

| cue | genuine (10) | banner (70, worked at varied angle/distance) | separable? |
|---|---|---|---|
| depth ratio | 1.37 – 1.40 | **1.02 – 1.58** | **No**; banner max 1.58 exceeds genuine max 1.40 |
| glint peak | 224 – 254 | 76 – 193 | gap holds here, but fragile (see below) |

Because the worked banner's depth ratio (up to **1.58**) rises *above* the entire
genuine range, **no `DEPTH_MIN_RATIO` value accepts the live user and rejects the
banner.** A naive 1.03→1.30 tightening would have been false confidence. `glint`
still separated on this data (0/70 banner frames cleared *both* genuine floors), but
it is not a reliable fix: it false-rejects glasses / dry-eyes / off-angle users
(unmeasured BPCER) and is defeatable by gluing specular dots on the print's eyes.

## Interpretation

This **empirically confirms** the residual risk documented in
[`../adr/0001-liveness-pad-strategy.md`](../adr/0001-liveness-pad-strategy.md)
("3D physical replicas / IR-approximating spoofs"), with a concrete, cheaply-sourced
instrument: a large **glossy vinyl print**, not an exotic 3D mask. It also
**falsifies** that ADR's premise that "the IR depth gradient subsumes 2D attacks":
against an IR-reflective large-format print, it does not.

Single-frame IR physics, on a 2D-IR (non-depth) camera, cannot reliably separate a
live face from a life-size IR-reflective flat print by threshold alone.

## Recommended direction, not applied here

- **Do not** ship a depth/glint threshold change as a "fix"; it is not one.
- **Challenge-response / temporal liveness** is the fix that holds: a static print
  cannot blink or turn on command, so lightweight motion/blink verification defeats
  this whole class. Existing `require-eyes-open` + IR-glint eyes scaffolding is the
  starting point. This warrants a follow-up ADR revising 0001.
- **Trained PAD model** is the durable answer but needs a clean-licensed dataset,
  tracked with the anti-spoof BOM work.

## Reproduce

```sh
export ORT_DYLIB_PATH=/usr/lib64/libonnxruntime.so   # stop irlumed first
DET=models/face_detection_yunet_2023mar.onnx; LOG=pad-$(git rev-parse --short HEAD).jsonl
irlume padcapture --species bonafide     --kind bonafide --det $DET --out $LOG --n 10
irlume padcapture --species print_banner --kind attack   --det $DET --out $LOG --n 50   # a life-size glossy/vinyl print
irlume padreport  --in $LOG
```

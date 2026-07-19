# IR liveness PAD self-test (ISO/IEC 30107-3)

**Status:** V1.0 methodology · **Applies to:** the credential-releasing IR liveness
gate (`irlume_liveness::LivenessGate`)

This document defines how irlume's presentation-attack-detection (PAD) gate is
self-tested against the methodology of **ISO/IEC 30107-3** (*Biometric presentation
attack detection, Part 3: Testing and reporting*). It is the reference the
`CONTRIBUTING.md` mandate points at ("Liveness/PAD changes should come with a
self-test against the relevant ISO/IEC 30107-3 attack class") and the concrete
form of the "self-test against ISO/IEC 30107-3 attack classes" milestone named in
[`THREAT_MODEL.md`](THREAT_MODEL.md).

> **This is a self-administered engineering test, not a certification.** It follows
> the ISO metrics and an iBeta-shaped protocol so results are comparable to the
> literature, but it is **not** a lab-accredited evaluation and confers no iBeta /
> FIDO certificate. Its purpose is to *measure* the gate and to *drive
> threshold hardening* from real attack data instead of guesses.

---

## 1. What is under test

The **credential-releasing IR gate**: the hard, single-frame IR-physics gate that
must pass before any match releases a secret. Two code paths are in scope:

| Path (`--path`) | Gate function | When it runs |
|---|---|---|
| `full` (default) | `LivenessGate::evaluate` | RGB + IR present (normal, lit use) |
| `ir-only` | `LivenessGate::evaluate_ir_only` | dark operation (no visible-light face) |

**Deliberately out of scope.** The **RGB-only** convenience tier
(`evaluate_rgb_only`) is deterrent-grade only: it is limited to lock-screen unlock
and **never releases credentials, logs in, or elevates**. Measuring its APCER would
overstate what it is trusted to do, so it is excluded from the PAD claim. Its
screen/glare/moiré cues are documented in the source, not certified here.

The gate is a **hard AND of physically-grounded cues** (any single failure
rejects); there is no learned model and no score fusion in the liveness decision.
See [`adr/0001-liveness-pad-strategy.md`](adr/0001-liveness-pad-strategy.md) for why
(clean-BOM constraint + the rPPG latency paradox).

---

## 2. Cue → ISO/IEC 30107-3 mapping

Each cue is the gate's defence against one or more **PAI species** (Presentation
Attack Instrument categories, ISO term). Constants are the current values in
`crates/irlume-liveness/src/lib.rs`.

| Cue (code) | Physical basis | Defeats (PAI species) | Threshold |
|---|---|---|---|
| `face_in_ir` | skin reflects 850 nm; emissive screens / prints do not render an IR face | phone / tablet / laptop **screen replay**, printed photo | detector score ≥ `MIN_FACE_SCORE` (0.6) |
| `cross_spectrum_aligned` | the same face must appear co-located in RGB **and** IR | RGB-only deepfake + IR blocker, USB IR **injection** (CVE-2021-34466) | center distance ≤ `CROSS_SPECTRUM_TOLERANCE` (0.30) |
| `ir_reflectance_ok` | active-emitter skin remission floor (melanin-independent > 1.2 µm → skin-tone fair) | dark / low-reflectance flat media | IR face mean ≥ `IR_FACE_MIN_BRIGHTNESS` (35) |
| `depth_ok` | shape-from-shading: a 3D face is brighter center→edge under a near-coaxial emitter; flat media are uniform | **printed photo**, flat screen, paper **cutout** | center/edge ratio ≥ `DEPTH_MIN_RATIO` (1.03) |
| `frontal_ok` | Windows-Hello-style ±15° pose gate (quality, not spoof → `Uncertain`) | off-angle / partial captures | yaw ≤ 0.40, pitch ∈ [0.20, 0.80] |
| `glint_present` | corneal retro-reflection of the emitter | *supporting only*, never decisive (standalone-glint liveness is refuted) | eye peak ≥ `GLINT_MIN` (180) |

The **per-user calibrated IR floor** (a depth-only floor stored at enrollment by
`irlume-core`, enforced in `Engine::authenticate`) tightens the depth gate for a
specific user without depending on ambient brightness. `padcapture` exercises
the **global** gate only; the per-user floor applies at real authentication,
not in this self-test.

---

## 3. PAI species set

### In scope for V1.0 (2D artefacts, the iBeta Level 1 family)

| Species (`--species`) | Instrument |
|---|---|
| `print_matte` | matte-paper printed photo of the enrolled user |
| `print_glossy` | glossy-paper printed photo (worst case for the specular/depth cues) |
| `phone_replay` | photo/video shown on a phone screen, held at varying distance |
| `tablet_replay` | photo/video on a larger tablet screen |
| `laptop_replay` | photo/video on a laptop display |
| `cutout` | printed photo with the eyes cut out / bent for pseudo-depth |

Use a **high-quality image of the genuine enrolled user** for every instrument;
the attack must target *that identity*, or it tests nothing (a stranger's photo is
rejected by recognition, not PAD). Vary distance, angle, and (for prints) curvature
across the presentations of a species.

### Out of scope for V1.0 (documented, accepted gaps)

- **3D masks** (silicone / resin / wrapped-paper, the iBeta Level 2 family) and
- **active IR-emitting spoofs**

are **accepted residual risk** per [ADR-0001](adr/0001-liveness-pad-strategy.md) §
"Consequences". They are not sourced or tested here; a clean-licensed PAD model or
own-IR-rig data is the revisit path. Do **not** report a "pass" as covering these.

---

## 4. Metrics (as computed by `irlume padreport`)

Definitions follow ISO/IEC 30107-3. Implementation and unit tests live in
`crates/irlume-core/src/pad.rs`.

- **APCER** (Attack Presentation Classification Error Rate): fraction of *attack*
  presentations of a PAI species classified as **bona fide** (the gate returned
  `Live`). Computed **per species**; the report headline is the **worst-case (max)
  across species**, never an average; one weak species is the system's true
  exposure.
- **BPCER** (Bona-fide Presentation Classification Error Rate): fraction of
  *bona-fide* presentations classified as an attack (a genuine user returned
  `Spoof`). The false-reject cost.
- **Non-response**: presentations that returned `Uncertain` ("re-present / face the
  camera"). Reported **separately** per ISO. An `Uncertain` attack did **not**
  succeed (it is not counted in APCER's numerator), but a species whose attacks
  merely *stall* is flagged, because an attacker can retry; treat a high attack
  non-response rate as unresolved, not as a defence.
- **ACER** = (worst-case APCER + BPCER) / 2. Deprecated by newer ISO revisions but
  still the legacy iBeta single headline; reported for continuity only.
- **95% confidence intervals**: every rate carries a **Clopper-Pearson exact
  binomial** interval. This is essential at self-test sample sizes: *0 of 20 attacks
  accepted means "APCER ≤ 16.8% with 95% confidence", not "0% APCER".* Read the
  upper bound, not the point estimate.
- **Per-cue attribution**: for each species, which hard cue caught the rejected
  attacks (`face_in_ir`, `ir_reflectance`, `depth`). This points hardening at the
  cue that is (or isn't) doing the work.

### Decision policy

Fixed thresholds (§2), single hard-gate decision, no per-attempt adaptation. The
same thresholds are used at enrollment and authentication. Report the exact commit
and threshold values alongside any results, because a result is only meaningful for
one gate configuration.

---

## 5. Protocol

### Reference tier (iBeta-shaped, for comparability)

iBeta's ISO/IEC 30107-3 protocol runs, **per PAI species**, **150 attack
presentations interleaved with ~50 bona-fide presentations** (Level 1 ≤ 8 h /
species, Level 2 ≤ 24 h / species), and caps the error rates (historically ≤ 20%,
tightened to ≤ 15%). FIDO's overlay wants **IAPAR ≤ 7%**. These numbers are the
target to *approach*; matching them at home is impractical (time + instrument
sourcing), hence the runnable tier below.

### Home tier (runnable, the default for this repo)

Per in-scope species: **≥ 20 attack presentations**, plus a shared **≥ 10 bona-fide
baseline**. Vary distance / angle / lighting across presentations. This is enough to
*catch a broken cue* and to bound APCER with an exact-binomial CI; it is **not** enough to
claim a low APCER with tight confidence (20 clean trials only proves APCER ≤ ~17%).
Scale up any species that shows a non-zero APCER or a wide interval.

### Self-imposed pass targets: the better-than-Windows-Hello bar

| Metric | Target |
|---|---|
| Worst-case APCER (2D species) | **0 accepted** attacks; upper CI as low as sample size allows |
| BPCER | ≤ 5% (genuine users rarely re-tried) |
| Attack non-response | low, and never masking an unresolved species |

A single accepted 2D attack is a **release-blocker**: investigate the species and
tighten the responsible cue before shipping.

---

## 6. How to run

Requires a real camera + IR emitter (this is a live physical test) and the YuNet
detector model. `irlumed` needs the camera, so **stop the daemon first** or point
`--rgb`/`--ir` at free device nodes.

```sh
export IRLUME_DEV=1        # pad tools are dev-gated
export ORT_DYLIB_PATH=/usr/lib64/libonnxruntime.so
DET=models/face_detection_yunet_2023mar.onnx
LOG=pad-$(git rev-parse --short HEAD).jsonl     # tie the log to the gate commit

# 1) Bona-fide baseline, the live enrolled user (≥10):
irlume padcapture --species bonafide --kind bonafide --det $DET --out $LOG --n 10

# 2) Each attack species (≥20 each). Prompts before every presentation so you can
#    reposition the instrument; the gate should reject every one:
irlume padcapture --species print_matte   --kind attack --det $DET --out $LOG --n 20
irlume padcapture --species print_glossy  --kind attack --det $DET --out $LOG --n 20
irlume padcapture --species phone_replay  --kind attack --det $DET --out $LOG --n 20
irlume padcapture --species tablet_replay --kind attack --det $DET --out $LOG --n 20
irlume padcapture --species laptop_replay --kind attack --det $DET --out $LOG --n 20
irlume padcapture --species cutout        --kind attack --det $DET --out $LOG --n 20

# Dark path (optional): repeat attacks with lights off and --path ir-only.

# 3) Report (prints a table; --md emits a paste-ready block):
irlume padreport --in $LOG --md pad-results.md
```

`padcapture` **appends**, so one log accumulates every species. During capture an
accepted attack prints `‼ ACCEPTED (breach!)` immediately so you don't have to wait
for the report to notice a hole.

Each JSONL record carries the ground-truth label (`species`, `kind`), the gate
`verdict`, the catching cue (`caught`), and the raw signals (`ir_brightness`,
`ir_depth`, `ir_glint`, `cross_dist`, pose), so a marginal near-threshold attack
can be inspected to tune the exact constant responsible.

---

## 7. Limitations (read before quoting any number)

1. **Not a certification.** Self-administered; no accredited lab, no chain of
   custody, no adversarial red-team beyond the operator's own instruments.
2. **Small samples → wide intervals.** Always quote the CI upper bound.
3. **2D only.** 3D masks and active-IR spoofs are untested and are accepted V1.0
   gaps ([ADR-0001](adr/0001-liveness-pad-strategy.md)).
4. **Instrument quality bounds the result.** A weak print/screen makes the gate look
   better than it is. Use the best instruments you can build.
5. **Hardware-specific.** Thresholds are calibrated to the Zenbook S14 IR module;
   results and constants do not transfer across cameras without re-calibration.
6. **A passing spoof yields full unlock.** Face is `auth sufficient`, so the
   password fallback does not gate a spoof that *passes*, which is why
   APCER, not BPCER, is the number that matters here.

---

## 8. References

- ISO/IEC 30107-3:2023, *Biometric presentation attack detection, Part 3: Testing
  and reporting* (APCER / BPCER / non-response definitions).
- iBeta / ISO 30107-3 PAD test methodology (protocol shape: 150 PA + ~50 BF per PAI
  species; Level 1 = 2D, Level 2 = 3D).
- FIDO Biometric Requirements: IAPAR ≤ 0.07 overlay.
- [`adr/0001-liveness-pad-strategy.md`](adr/0001-liveness-pad-strategy.md): why
  single-frame IR physics, and the accepted 3D/active-IR residual risk.
- [`THREAT_MODEL.md`](THREAT_MODEL.md): liveness cues and the certification caveat.

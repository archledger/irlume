# Third-party PAD candidate evaluation, 2026-07-17

Measurement session behind the opt-in third-party-models lane discussed in
[issue #4](https://github.com/archledger/irlume/issues/4): before any
externally-trained PAD model is offered in irlume's menu, it gets measured on
real deployment hardware against the published attack species. Two candidates
had actual licenses on their weights (the bar Silent-Face fails, see
`models/README.md`); both were evaluated the same day. One qualified.

- **Hardware:** Zenbook S14 (UX5406S) built-in RGB + IR (850 nm strobe) module,
  and a NexiGo HelloCam N930W USB Windows-Hello camera (RGB + IR).
- **Subject/operator:** the enrolled user, single subject, home + car field
  conditions. Attacks target that identity per the
  [PAD self-test protocol](../PAD_SELFTEST.md).
- **Numbers are frame-level** (each scored frame counted separately), not
  presentation-level like the June self-test; conservative for comparing
  attack coverage, and stated per condition.

## Candidates

| Model | Publisher / license | Modality | Artifact |
|---|---|---|---|
| `cv_manual_face-liveness_flir` | Alibaba DAMO (ModelScope), **MIT** | IR | ONNX 1.3 MB, sha256 `df80cea7228b92562692e56aac965d35766c77399159798c552fb3c77b410c72` |
| `anti-spoof-mn3` | Intel OpenVINO OMZ, **Apache-2.0**, trained on CelebA-Spoof | RGB | ONNX 12 MB, sha256 `c4c99af04603b62d7e44f6f4daeb33e0daeccc696008c0b1d62f6f5cebbb3262` |

Preprocessing replicated from each publisher's own pipeline code (ModelScope
`FaceLivenessIrPipeline` incl. `align_face_padding`; Intel OMZ README mean/scale
with the author-demo bbox crop), detection by irlume's shipped YuNet.

**Scoring pitfall worth recording:** mn3's ONNX has softmax baked in (outputs
sum to 1); FLIR's outputs raw logits. The first mn3 pass applied softmax twice,
compressing every score into [0.269, 0.731]; a near-constant 0.731 median is
the fingerprint of that mistake. Check output normalization before applying
softmax.

## FLIR (IR): qualified

**Genuine, offline corpus** (1,175 frames, 38 field bursts, Zenbook camera):
near-zero false-fires indoors and in-car (median P(fake) 0.001–0.13);
false-fires concentrate in two mapped regimes: strobe dim-phase frames
(rejected frames clustered at ambient ≈82 vs accepted ≈121) and direct sun
above ambient ≈150 (the same envelope where irlume's own depth cue is starved;
the model card admits strong-light degradation). Inference ~1.2 ms/frame CPU.

**Genuine, live** (same day): Zenbook, 4 runs, 144 frames: 2 flagged, both at
ambient 80, i.e. the dim-phase regime again. NexiGo, 2 runs, dim living room:
0/35 flagged, median P(fake) 0.0000. First Zenbook run was clean at ambient up
to 180, above irlume's `IR_AMBIENT_FLOOD` line.

**Attack: the life-size glossy vinyl print**, the species that defeated the
algorithmic gate at [98.6% APCER on 2026-06-30](2026-06-30-ir-liveness-selftest.md):

| Camera | Runs (varied angle/distance) | Flagged |
|---|---|---|
| NexiGo | 4 | 68/69 frames (one accept: burst-start frame during auto-exposure settling) |
| Zenbook (the June-breach camera) | 3 | 54/54 frames |

Cross-camera aggregate: **122/123 banner frames flagged, ≈0.8% frame-level
APCER** (medians 0.998–1.0000), against 98.6% for the physics gate on the same
species. Same-camera separation on the NexiGo: genuine median 0.0000 vs banner
median ≈0.9997.

**Attack: phone screen (IR path):** 36/36 frames, no face detectable in IR; a
phone emits nothing at 850 nm, so this species never reaches an IR model.
Non-response, not a detection win.

**Verdict: first entry for the opt-in menu.** Wiring implications measured, not
assumed: deny-only (may reject, never approve what the physics gate rejected)
and lit-phase-frames-only (the daemon tracks strobe phase; that single
restriction removes the only genuine-side failure outside harsh sun).

## anti-spoof-mn3 (RGB): not listed

Sanity control: 13,233 LFW genuine web photos through the identical code path,
median P(spoof) 0.0018, 4.7% flagged at the author-demo 0.4 threshold, i.e.
plausible in its own domain. On the deployment cameras the condition map came
out:

| Condition (all genuine unless noted) | Result |
|---|---|
| Car, harsh morning light | 15/15 flagged (median 0.96); margin sweep 1.0–2.0× and resolution sweep 1080p→320×180 both worsen it (confounds ruled out) |
| Car, benign afternoon light | mostly live (run medians 0.007–0.20, one run 0/15); phone-photo attacks simultaneously 37/37 flagged at 0.997+ |
| **Home living room, lights on** (the dominant real login condition) | **15/15 flagged, median 0.9975** |
| Home, dim room | no face detectable in RGB at all (frame mean ≈40) |

There is a window (benign outdoor daylight) where mn3 separates genuine from
phone-replay perfectly. Everywhere that matters for a login tool it either
saturates at "spoof" for the genuine user (lit indoor, harsh sun) or has no
input (dark). A deny-only cue that false-fires near 100% in the primary lit
indoor condition adds retries for everyone and protection for no one.
CelebA-Spoof is phone-camera imagery; whatever the exact variable (it is not
gross brightness or global color cast; both matched between failing and passing
sets), the domain does not transfer to this hardware.

## Limitations

1. Frame-level rates, single subject, single operator, uncertified; the
   [PAD self-test caveats](../PAD_SELFTEST.md#7-limitations-read-before-quoting-any-number)
   apply unchanged.
2. Attack instruments: one vinyl banner, one phone (static photo). No 3D masks,
   no print-cutout variants this session.
3. FLIR's training data is undocumented by its publisher; that is exactly why
   it is opt-in with disclosure rather than shipped (ADR-0001 criteria 2–3).
4. The banner accept was a camera auto-exposure artifact; multi-frame voting
   makes a single settling frame inert, but it is counted honestly above.

## Reproduce

Eval scripts and score summaries are committed in
[`benchmarks/pad-candidates/`](../../benchmarks/pad-candidates/). Raw captures
contain the operator's face and are not committed. Model artifacts download
from their publishers (URLs in the scripts); verify the sha256 values above.
The live capture harness is `landmark_dump`
([DEVELOPMENT.md walkthrough](../DEVELOPMENT.md)) plus ffmpeg for RGB.

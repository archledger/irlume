# ViT RGB PAD cue in a dim room: exposure and capture-quality sensitivity

Date: 2026-10-21 · Baseline: `main` 0208dc72 · Issue: #1155 · No camera was
opened and no threshold was changed.

## Question

A T480 split pair (`5986:1141` IR, `5986:2113` RGB) refused an ordinary
attempt in a dim room on build `b720af0`
([@maurerr's report](https://github.com/archledger/irlume/issues/887#issuecomment-6252453400)).
Cross-spectrum liveness passed on every frame, while the shipped ViT RGB PAD
cue (`liveness_vit.onnx`) scored 0.641, 0.578, 0.582, 0.575 and 0.549
(median 0.578) with `ir_bright` 86 to 89. With the room light on, the same
setup granted at 0.428 to 0.507 with `ir_bright` 98 to 102. An earlier attempt
in the same report, lighting not stated, granted at 0.421 to 0.453 through the
IR-fallback match (its "dim light" text is the fixed label of that match path,
not a light reading). Is the cause the dark frame itself, or something else
about how the frame was captured?

## The cue and its recorded operating point

`VIT_PAD_THRESHOLD = 0.55` and `VIT_PAD_VOTE_N = 5`
(`crates/irlume-auth/src/lib.rs`): `vit_vote_denies` sorts the last five
scores and denies when the middle one is at or above 0.55; fewer than five
scores abstain, and the window slides. The cue is scored only on a Live
verdict, so it can turn Live into Spoof and nothing else. The score is
`PadVit::p_spoof` (`crates/irlume-vision/src/lib.rs`): m96 bbox expansion with
truncated bounds clamped to the frame, a bilinear resize to 224 that follows
OpenCV `INTER_LINEAR`, RGB, `(px/255 - 0.5)/0.5`, softmax index 1. There is no
illumination normalization and no per-frame quality gate in the cue. The
fixture test `onnx::pad_vit_input_tests::fixture_tensors_match_the_recorded_scorer_contract`
pins the input tensor against an OpenCV oracle.

Recomputed from the committed CSVs of
[`2026-08-21-vit-liveness-pad-evaluation.md`](2026-08-21-vit-liveness-pad-evaluation.md),
m96 crop:

| condition | frames | P(spoof) min / median / max |
|---|---|---|
| genuine desk light | 75 | 0.422 / 0.474 / 0.551 |
| genuine low light | 18 detectable of 75 | 0.378 / 0.469 / 0.519 |
| vinyl print, one print, five presentations | 100 | 0.604 / 0.705 / 0.773 |

The live corpus was captured on 2026-08-12 on the Zenbook module and scored on
2026-08-21. LFW (13,233 original images): median 0.452, q90 0.513, q99 0.565,
and 1.86% of frames at or above 0.55. Single genuine frames therefore already
reach the deny line, and the five-frame median suppresses most of that tail:
taking each LFW identity's images in fives, in file order, leaves 4 of 1,072
groups with a median at or above 0.55 (0 at 0.60). ADR-0013 §4 states its
genuine margin (0.085) on presentation medians: 0.27 to 0.465 for genuine
presentations on two cameras, 0.594 to 0.656 for login-distance banner
attacks. ADR-0013 §4 and the `VIT_PAD_THRESHOLD` comment, both from #516, also
say 0 of 531 sampled LFW presentations fire at 0.55; the only committed record
of that sample, the 2026-08-21 evaluation, reports 0/531 at or above 0.60 (as
the `VIT_PAD_VOTE_N` comment does), and the sample itself is not in the
committed CSV.

How fast refusals grow when something raises every frame's score, measured by
adding a uniform shift to the recorded LFW scores. Five-frame groups are
formed three ways: frames drawn independently from all 13,233 (the i.i.d.
bootstrap, see Method); each identity's images taken in fives in file order,
which are different photos of one person and so are correlated, closer to the
frames of one presentation though not the same thing (1,072 groups using 5,360
of the 5,985 images of the 423 identities with five or more); and, for a fair
comparison with those groups, frames drawn independently from the same 5,360
images:

| shift per frame | frames >= 0.55 | i.i.d., all frames | i.i.d., grouped frames | per-identity groups |
|---|---|---|---|---|
| 0 | 1.9% | 0.0% | 0.0% | 0.4% (4/1,072) |
| +0.02 | 4.5% | 0.1% | 0.1% | 0.9% |
| +0.03 | 7.4% | 0.3% | 0.4% | 2.2% |
| +0.05 | 16.7% | 3.4% | 5.0% | 12.2% |
| +0.08 | 37.6% | 28.1% | 36.9% | 39.6% |
| +0.10 | 51.7% | 53.7% | 67.0% | 64.4% |

Correlation within an identity matters at small shifts (+0.05: 12.2% against
5.0% on the same images) and little at large ones.

The reported dim attempt's median (0.578) is 0.071 to 0.150 above the
per-frame range of the light-on attempt (0.428 to 0.507). The earlier grant
(0.421 to 0.453) is left out of that comparison because its lighting was not
stated.

The 2026-08-22 live qualification
([`2026-08-22-vit-live-qualification.md`](2026-08-22-vit-live-qualification.md))
measured a screen-lit, dim-marginal genuine face (luma about 38, Zenbook,
MJPG) at median 0.465 and maximum 0.492 over 39 scored frames.

## Method

Inputs: the original, non-aligned LFW images (Hugging Face `marcelohaps/lfw`
at commit `12a61458`, 13,233 images), the same corpus as the recorded
2026-08-21 LFW scores. The harness takes an evenly spaced sample by file name
(200 images for the grain pass, 300 for the photon pass; 400 distinct faces),
detects with the pinned YuNet on the unmodified image, applies one transform
per arm to the m96 crop, and scores it with the recorded scorer contract.
Model and detector hashes are checked against the pins at startup. Rescoring
an evenly spaced 300 of the rows in `2026-08-21-vit-lfw-scores.csv` with the
harness reproduces all 300 recorded scores to four decimals. Like the
2026-08-21 scorer, the harness detects with OpenCV's `FaceDetectorYN` and
expands YuNet's width and height; the shipped path decodes YuNet itself
(`crates/irlume-vision/src/detect.rs`) and rebuilds width and height from
float32 corners, which can move a crop bound by one pixel.
`validate_harness.py` computes both on the 400 sampled faces and finds
identical bounds for all of them; the two detectors' boxes are not compared
here.

Each arm is reported two ways, because no burst-level dependence was measured
here. "Frames >= 0.55" is the refusal rate if a presentation's five frames all
scored alike. "5-median refused" is an i.i.d. bootstrap of the shipped
decision, 20,000 draws of five frames with replacement from the arm, refused
when their median is at or above 0.55 (seed 1155): the refusal rate if the
frames were independent. They are two reference cases. A real presentation's
refusal rate depends on how its frames covary and need not fall between them,
and neither is a prediction for one person.

"Paired shift" is the median over images of the arm's score minus the same
image's baseline score. "Noise std" is the measured standard deviation, in
0-255 code units, of the noisy crop minus the clean crop, and "luma" the
median mean luma of the transformed crop.

The harness, its validation script and the per-frame output are committed
under [`benchmarks/pad-candidates/dim-room/`](../../benchmarks/pad-candidates/dim-room/).

A first pass of this harness scored the deep-funneled LFW release instead:
resampled, aligned copies of the same photos. That corpus has a similar
baseline median (0.434 against 0.442) but a heavier upper tail (8.0% and 5.3%
of baseline frames at or above 0.55 in the 200- and 300-image samples, against
1.0% and 2.0% here), and its faces respond more strongly to the degrading
transforms: about twice the paired shift for grain, blur, JPEG and photon
noise (grain sigma 10: +0.088 against +0.047; photon exposure 0.02: +0.166
against +0.103), a rise under halved contrast (+0.045) where the original
images stay put (-0.005), and a smaller drop under darkening (-0.052 and
-0.023 against -0.064 and -0.053). Every arm's refusal rate came out higher
there (grain sigma 10: 19.4% against 0.6% for independent frames; halved
contrast: 13.1% against 0.1%). Those figures were posted on #1155 before this
check and are superseded for the comparison with the recorded operating point;
their CSVs are kept in `benchmarks/pad-candidates/dim-room/deepfunneled/`.

## Uniform darkening

The crop's 8-bit code values multiplied by a scale (the `exposure` rows of
`grain.csv`; 0.32 in code values is about 0.08 in linear light), 200 images.

| scale | luma | frame median | paired shift | frames >= 0.55 | 5-median refused |
|---|---|---|---|---|---|
| 1.0 | 98.1 | 0.442 | 0 | 1.0% | 0.0% |
| 0.32 | 31.0 | 0.364 | -0.064 | 1.0% | 0.0% |
| 0.14 | 13.3 | 0.383 | -0.053 | 1.0% | 0.0% |

Scaling the crop's code values lowers the score. This is not optical
underexposure: real darkness acts before the ISP and also changes
quantisation, shot and read noise, colour processing, denoising and encoding,
which are the effects probed next.

## Capture-quality shifts

| arm | images | noise std | luma | frame median | paired shift | frames >= 0.55 | 5-median refused |
|---|---|---|---|---|---|---|---|
| baseline (grain pass) | 200 | 0 | 98.1 | 0.442 | 0 | 1.0% | 0.0% |
| Gaussian grain sigma 3 | 200 | 3.0 | 97.8 | 0.461 | +0.021 | 4.0% | 0.1% |
| Gaussian grain sigma 6 | 200 | 5.9 | 97.9 | 0.478 | +0.039 | 8.0% | 0.5% |
| Gaussian grain sigma 10 | 200 | 9.8 | 98.0 | 0.487 | +0.047 | 9.0% | 0.6% |
| Gaussian grain sigma 15 | 200 | 14.5 | 98.2 | 0.488 | +0.041 | 9.0% | 0.6% |
| Gaussian grain sigma 20 | 200 | 19.1 | 98.4 | 0.490 | +0.046 | 9.0% | 0.6% |
| JPEG quality 20 | 200 | 0 | 98.3 | 0.456 | +0.011 | 2.0% | 0.0% |
| baseline (photon pass) | 300 | 0 | 97.7 | 0.446 | 0 | 2.0% | 0.0% |
| Gaussian blur 1.5 px | 300 | 0 | 97.7 | 0.461 | +0.014 | 2.3% | 0.0% |
| contrast x0.5 | 300 | 0 | 112.6 | 0.444 | -0.005 | 5.3% | 0.1% |
| photon noise, exposure 0.10 | 300 | 29.7 | 90.7 | 0.507 | +0.054 | 15.3% | 2.9% |
| photon noise, exposure 0.04 | 300 | 45.2 | 82.5 | 0.531 | +0.085 | 35.7% | 25.2% |
| photon noise, exposure 0.02 | 300 | 60.0 | 72.7 | 0.551 | +0.103 | 51.0% | 51.3% |

The photon arms model Poisson shot noise in linear light plus Gaussian read
noise and then sRGB encoding (their `exposure` parameter scales linear-light
photon counts), so their noise depends on the signal rather than
being uniform like the Gaussian grain. They also darken the crop (median luma
97.7 at baseline, 90.7, 82.5 and 72.7 in the three arms) through clipping,
integer truncation and the sRGB curve, and darkening alone lowers the score, so
their shift mixes both effects. The read noise is a fixed linear-light
standard deviation (2/255 of full scale) added after the exposure scaling, so
it does not grow with gain, and the sRGB curve makes its code-unit size depend
on the signal level. The JPEG probe is a general quality shift, not this
camera's path: the T480 RGB module advertises MJPG and YUYV, and
`choose_rgb_format` selects YUYV when both are offered.

For scale only, since the processing differs: RENOIR's real low-light captures,
converted from RAW by linear scaling and not denoised, average a noise
standard deviation of 11.7 to 19.2 in 8-bit units across its three cameras.

## Reading

On the reference corpus, darkening the code values lowers the score (paired
shift about -0.05 to -0.06). Gaussian grain raises it for about 90% of faces,
by a paired median of +0.02 at 3 code units and +0.04 to +0.05 from 6 to 19
code units, and unevenly: at 6 to 19 code units, 47 to 61 of the 200 faces
shift by 0.07 or more and 3 to 8 by 0.15 or more. Blur and JPEG quality 20
move the median by about +0.01; halved contrast leaves it in place (-0.005)
but widens the spread (frames at or above 0.55 from 2.0% to 5.3%). With 6 to
19 code units of grain, refusals go from 0.0% to 0.5 to 0.6% if a
presentation's frames were independent and from 1.0% to 8 to 9% if they scored
alike. The photon arms shift the median by +0.05 to +0.10 and refuse 3% to 51%
(independent) or 15% to 51% (alike).

The reported dim attempt sits 0.07 to 0.15 above the same unit's light-on
range. On this corpus the median grain shift is smaller (+0.04 to +0.05) and
only the two heavier photon arms (45 and 60 code units, +0.085 and +0.103)
reach 0.07, but 47 to 61 of 200 faces shift by 0.07 or more under moderate
grain, and on the deep-funneled copies of the same photos the median grain
shift is +0.074 to +0.102. How strongly a face responds to grain therefore
depends on the face and on the image's processing history, and capture noise
can produce a shift of the reported size; the measurement does not establish
that it did on that unit. Not measured here: that module's exposure and gain
control, colour processing and denoising, a screen-lit face, and a different
face box (when YuNet finds no face in a dim RGB frame, a BlazeFace rescue box
feeds the m96 crop, and the cue depends on the crop: on the 2026-08-21
desk-light frames the median is 0.391 with the tight box and 0.474 with m96).

## Next evidence

On current main, one dim-room attempt and one with the light on, with
`IRLUME_LOG=debug`. These debug lines carry it:

- each failed attempt writes
  `attempt: <situation>; face_frac=... yaw=... glint=... ir_bright=... rgb_bright=... score=...`.
  The situation reads `too dark` when an RGB face is present with
  `rgb_bright` below 55 and no earlier situation (`timed out`, `unavailable`,
  `no face`, `too far`, `off-center`, `looking away`, `IR source`) applies;
  otherwise it names the outcome (`spoof`, `glint below`, `below score` or
  `other`). An RGB
  PAD vote still incomplete when the window closes reads `timed out`. A
  granted attempt writes no such line;
- each sample writes `pad-vit: p_spoof <value>`;
- when the RGB match alone does not grant and the IR arms are scored (the
  earlier grant in the report took this path), the line
  `match(fusion): p=... grant=... (rgb ... bright N / ir ... bright N)` carries
  the RGB face brightness, granted or not;
- each RGB assessment writes `assess: rgb WxH ..., faces=N top-det=S`, and a
  frame where YuNet found nothing and BlazeFace did writes
  `detect(rgb): blaze rescue fired (score S)`.

A bounded trace (`sudo irlume trace`, docs/DEBUGGING.md) carries the same
brightness as the `RgbBrightness` measurement of each liveness assessment.
Whether the room was lit mainly by a screen and whether the RGB image looked
grainy separates the capture classes above. Public reports on #1155 carry only
the brightness values, the `pad-vit` scores, the situation label and the
detection lines, not match scores (`score=`, `p=`, the `rgb` and `ir` match
values).

## Decision

No threshold, cue or capture change follows. The refusal fails closed, the
password works, and the practical remedy is light on the face. irlume has no
fill-light step: Windows Hello's optional low-light sign-in brightens the
screen when the IR camera sees the face but the color camera lacks light, and
Microsoft has removed that setting for now and schedules its return from
November 2026. Any input or threshold change would need the retained attack
corpus re-run (2026-08-21 vinyl-print minimum 0.604 on one print and one
camera; login-distance banner presentation medians 0.594 to 0.656 in
ADR-0013 §4).

## Sources

All fetched 2026-10-21.

- Upstream model, `https://github.com/Adedev-W/LivenessModels-ONNX` (last
  commit 2025-09-04): architecture, preprocessing example and label metadata;
  no training data, accuracy metrics or illumination domain are documented.
- Microsoft Support, "Low light sign-in for Windows Hello facial recognition",
  `https://support.microsoft.com/en-us/windows/security/low-light-sign-in-for-windows-hello-facial-recognition`
  (page dated 2026-09-30): off by default, removed "for a short while" and
  "scheduled to reappear starting November 2026"; brightness rises "when the
  IR camera can see your face but there isn't enough light for the color
  camera".
- Microsoft Learn, "Windows Hello face authentication",
  `https://learn.microsoft.com/en-us/windows-hardware/design/device-experiences/windows-hello-face-authentication`,
  "Benefits of near infrared": color systems "rely on turning up the
  brightness, exposure, or other settings to create a useable image", which
  "expose artifacts that impact the robustness of the system".
- Feng et al., "Benchmarking Vision Foundation Models for
  Domain-Generalizable Face Anti-Spoofing", CVPRW 2026, arXiv 2604.19196v2:
  "achieving true domain invariance against real-world shifts (e.g., unseen
  capture devices, lighting conditions, and novel spoof materials) remains a
  highly challenging and open problem".
- "A MobileFaceNet-Based Face Anti-Spoofing Algorithm for Low-Quality Images",
  Electronics 13(14):2801 (2024), `https://www.mdpi.com/2079-9292/13/14/2801`:
  generalization under varying image quality, in long-distance surveillance
  capture, remains challenging for FAS.
- Anaya and Barbu, "RENOIR - A Dataset for Real Low-Light Image Noise
  Reduction", Journal of Visual Communication and Image Representation,
  arXiv 1409.8230v9, Table 2.
- LFW: `https://vis-www.cs.umass.edu/lfw/`; local copy from
  `https://huggingface.co/datasets/marcelohaps/lfw` at `12a61458`.

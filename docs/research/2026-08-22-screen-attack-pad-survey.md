# Screen-Attack / Replay-Attack PAD for the RGB-Only Path: State-of-the-Art Survey

- date: 2026-08-22
- agent: opencode (research task, read-only except this file)
- scope: software-only face PAD against phone-screen and print presentation attacks in ordinary RGB video, for irlume's RGB-only convenience path (IR path already defeats screens at 850nm and is out of scope)
- camera context: 640x480 MJPG 30fps, 480 labeled frames, 2026-08-22 session

Claim tags used throughout:

- [MEAS] measured on our corpus, 2026-08-22 session (640x480 MJPG webcam, 480 labeled frames; FFT and ViT numbers below)
- [PUB] published claim, primary source cited inline
- [INF] our inference or calculation, reasoning stated

## 1. Executive Summary: Top-5 Most Promising Approaches

Our measured failures define what a candidate must fix: the shipped FFT moiré peakiness cue has complete genuine/phone overlap (genuine 8-17, phone 11-23, banner 13-19, shipped threshold 28 catches nothing) [MEAS], and a 343MB CelebA-Spoof-family ViT misses phone-at-login-distance (P(spoof) 0.455 inside the genuine range 0.34-0.55) because its features are scale-dependent [MEAS]. The winning cues must therefore be (a) scale-invariant or temporal, (b) alive at VGA resolution after MJPG, (c) cheap enough for the daemon.

| Rank | Approach | Why it fits our measured gaps | Compute | Main risk |
|------|----------|-------------------------------|---------|-----------|
| 1 | Row-profile flicker-banding detector (temporal + spatial row analysis of screen refresh/PWM vs rolling shutter) | Physics is guaranteed for emissive displays; it is a property of the instrument, not the face texture, so it cannot be scale- or skin-dependent like our ViT and FFT cues. Published screen-capture literature calls banding "frequent and severe" when filming displays [PUB: arXiv:2509.24644]. | Negligible: row means O(H*W) adds + 1D FFT, cheaper than the shipped 2D FFT cue | Phones with DC dimming / PWM off; MJPG survival must be measured on our corpus first |
| 2 | Attack-instrument rectangle geometry (detect the phone/print boundary around the face box) | Detects the attack medium's geometry, not face texture. Our ViT data shows genuine vs phone faces ARE separable at matched scale (genuine close 0.368 vs phone close 0.566) [MEAS], so texture exists but current features miss it at distance; geometry does not degrade with face scale. | Small: Sobel/Hough on an annulus outside the face box, no NN | Partial occlusion, cropped screens, cut-out masks; needs multi-frame stability logic |
| 3 | Classical rPPG gate (POS/CHROM) against static photo-on-screen | A screen showing a STATIC photo has no pulse and no 0.7-4 Hz periodicity; published rPPG-PAD work confirms rPPG discriminates photo attacks (replay of *video* carries pulse, photo does not) [PUB: 10.1145/3345336.3345345, PMC9024982]. Catches exactly the cheap, most likely attack on the convenience path. | Low: ROI mean time series + bandpass + FFT over 8-10 s | Motion artifacts; deep rPPG models hallucinate pulses on non-live video, so classical methods only [PUB: arXiv:2303.06452] |
| 4 | Retrain/fine-tune a small screen-attack-native model (MiniFASNet-class 80x80 or CDCN 64x64) on Replay-Attack-style low-res screen data plus our own captures | Our ViT failure is a training-distribution failure (CelebA-Spoof is print-dominated and our prior mn3 transfer saturated) [MEAS]; Replay-Attack is 320x240 MJPG with iPhone/iPad screen attacks, nearly our exact domain [PUB: Idiap Replay-Attack page] | Small model 0.4M params, 0.081 GFLOPs [PUB: Silent-Face repo] | Any learned cue re-introduces transfer risk; must be deny-augmenting, not the sole gate |
| 5 | Reflection/specular glint tracking (diffuse face vs specular glass plane) | Published as effective only with active illumination (flash) or as auxiliary supervision today [PUB: arXiv:1907.12400, arXiv:2202.10187]; passive use is our design work | Low once motion tracking exists | Weakest evidence base of the five; do after 1-3 |

Ranks 1-3 are additive physics/geometry cues our stack lacks entirely; all three are deny-only signals that compose with the existing fail-closed gates. Rank 4 fixes the model-side gap. Rank 5 is exploratory.

## 2. Physical Cues in Ordinary Compressed RGB Video

### 2.1 (1a) Screen refresh / rolling-shutter banding

**Physics (PUBLISHED).** Flicker-banding is alternating bright-dark horizontal stripes "that arise from temporal aliasing between a camera's rolling-shutter readout and the display's brightness modulation" [PUB: arXiv:2509.24644 (RIFLE), same wording in arXiv:2605.21079 (VDFP/DeViD) and arXiv:2606.29845 (Bricker)]. The screen-capture restoration literature treats it as frequent and severe when photographing/filming emissive displays, and shows band morphology varies strongly with exposure settings [PUB: arXiv:2606.29845]. Row-wise flicker frequency classification from rolling-shutter imagery is an established technique (Tajbakhsh & Grigat, "Illumination flicker frequency classification in rolling shutter camera systems", SIP 2007, ACM DL 10.5555/1659892.1659948). Rolling-shutter sensitivity to modulated light is also a known security surface (laser injection through CMOS rolling shutter) [PUB: arXiv:2101.10011].

**Band geometry at our sensor (INFERRED calculation from published physics).** 480 rows read out in ~1/30 s give a row period t_row ~= 69 us (ignoring blanking). A display brightness modulation at f_m produces a vertical beat pattern with period (1/f_m)/t_row rows:

- f_m = 120 Hz (60Hz x2, PWM): ~120 rows per band pair (4 bands over the frame)
- f_m = 240 Hz (typical OLED PWM dimming): ~60 rows
- f_m = 1-2 kHz (high-frequency PWM): 7-14 rows, near the row-Nyquist; may alias into near-uniform row noise

So expected detectable structure is broad luminance bands, period roughly 20-120 rows, i.e. vertical spatial frequencies 0.04-0.25 cycles/row, well below JPEG's aggressive high-frequency cutoff. This is a different frequency regime from moire (which needs pixel-grid interference), which is why our shipped FFT peakiness cue in the high-frequency band is blind to it [INF, consistent with MEAS overlap].

**Temporal signature (INF).** At 30 fps sampling, a 120/240 Hz modulation aliases near DC per-pixel, but the rolling shutter assigns each row a different sampling phase, so the band pattern's phase drifts frame-to-frame unless f_m and the frame rate are commutatively locked. Candidate features: (i) per-frame row-profile FFT peakiness in the 20-120 row period band, (ii) inter-frame cross-correlation displacement of the row profile (band drift), (iii) row-time 2D FFT ridge. None is published as a PAD feature; no published PAD system keyed on banding was found in any query. This is our design grounded in published physics [INF].

**MJPG survival (INF, must measure).** Banding is a luminance phenomenon at low vertical spatial frequency; MJPG 4:2:0 subsampling damages chroma, not luma rows, and JPEG quantization attenuates high frequencies where the bands are not. The deflicker datasets are themselves compressed smartphone video, proving banding survives real capture pipelines [PUB: arXiv:2605.21079]. Verdict on our specific MJPG path: measure on the existing 480-frame corpus before building further.

**Known failure modes (PUB/INF).** Phones with DC dimming or PWM disabled at high brightness produce no modulation [INF, consistent with the exposure-dependent morphology in arXiv:2606.29845]; attack brightness setting is attacker-controlled, so banding is a deny-only cue, never a pass cue.

### 2.2 (1b) rPPG (remote photoplethysmography)

**Canonical methods (PUBLISHED).** CHROM: de Haan & Jeanne, "Robust Pulse Rate From Chrominance-Based rPPG", IEEE TBME 2013, DOI 10.1109/TBME.2013.2266196 (chrominance projection, motion-robust). POS: Wang et al., "Algorithmic Principles of Remote PPG", IEEE TBME 2017, DOI 10.1109/TBME.2016.2609282 (plane-orthogonal-to-skin projection; the standard distortion-robust classical method). DeepPhys: Chen & McDuff, "DeepPhys: Video-Based Physiological Measurement Using Convolutional Attention Networks", ECCV 2018. Windows are on the order of several seconds of frames (methods operate on time series of ROI means; PAD studies use multi-second windows) [PUB, method papers].

**For PAD specifically (PUBLISHED).** Liu et al., "Face Liveness Detection by rPPG Features and Contextual Patch Features", ACM ICIMCS 2019, DOI 10.1145/3345336.3345345: "rPPG feature is discriminant for photo attack and mask attack, while texture feature is effective for detecting replay attacks", i.e. rPPG separates photo and mask, but video replay carries the pulse and defeats pure rPPG. A Sensors 2022 study likewise motivates its method by rPPG "vulnerab[ility] to replay attacks" [PUB: PMC9024982]. Additional primary PAD-rPPG work: "Pulse-based Features for Face Presentation Attack Detection", IEEE BTAS 2018, DOI 10.1109/BTAS.2018.8698579; PAD-Phys [PUB: arXiv:2310.02140]; the JOINT benchmark combines visual + physiological cues across 2D/3D mask and replay attacks [PUB: arXiv:2208.05401].

**Critical limitations (PUBLISHED).** (a) Deep rPPG models trained only on live subjects hallucinate genuine-shaped pulses on anomalous or non-live videos; classical POS/CHROM with explicit signal-quality checks are the safer basis for a security gate [PUB: arXiv:2303.06452 "Hallucinated Heartbeats"]. (b) rPPG itself is attackable: imperceptible periodic noise (digital) or imperceptible visible-spectrum LED modulation (physical) can synthesize a fake pulse [PUB: arXiv:2110.11525]. (c) Video replay inherits the source recording's pulse [PUB: 10.1145/3345336.3345345]. (d) Motion and compression degrade accuracy [PUB: method papers; robustness is POS's core claim].

**Fit at 640x480 MJPG, login distance (INF).** rPPG needs a stable forehead/cheek ROI; Replay-Attack-class datasets are 320x240 compressed webcam video and rPPG-PAD work exists at that scale [PUB: above; INF for our exact distance: ROI shrinks with distance; a 10 s x 30 fps = 300-frame window on a >=20x20 px forehead ROI is the practical floor. Must measure pulse SNR on genuine corpus frames first).

**Verdict.** Use POS (classical, has published derivation) as a *static-photo* denial gate, never as a pass signal. For our threat model it covers the phone-showing-photo and printed-banner cases (both pulse-free) and complements banding, which covers video-on-screen.

### 2.3 (1c) Reflection physics: diffuse face vs emitter + specular glass

**Published state.** The strongest published passive results use either active illumination or supervision, not passive single-camera glint tracking: SpecDiff takes one flash + one no-flash photo and separates specular vs diffuse reflection on a monocular RGB camera for mobile PAD [PUB: arXiv:1907.12400]. Aurora Guard (Alipay, deployed) extracts surface normal cues from light-reflection analysis plus a screen-flash CAPTCHA, serving millions of users [PUB: arXiv:1902.10311, extended arXiv:2102.00713]. Reflection-map supervision improves generalization as an auxiliary task [PUB: arXiv:2202.10187]; physics-guided spoof-trace disentanglement uses a reflection model plus 3D geometry priors [PUB: arXiv:2012.05185]. For pure digital forgeries, specular-inconsistency under physical illumination laws is a discriminant [PUB: arXiv:2602.06452], and reflectance physical-correctness analysis has been applied to morphing attack detection [PUB: arXiv:1807.02030].

**Passive single-camera gap (INF).** A real face is a mostly diffuse (Lambertian + weak specular) reflector of ambient light; phone glass is a planar specular reflector in front of an emitter. Under our passive webcam, the observable difference is glint behavior during natural head motion: a room-light specular blob on glass translates rigidly with the instrument and stays sharp, while diffuse facial shading deforms smoothly. No published passive single-camera PAD system built on this was found; this is our design risk [INF]. Expected strength at 640x480: glints are a few pixels; usable only in a multi-frame, motion-triggered analysis [INF]. Rank 5 for a reason.

### 2.4 (1d) Color / gamut discriminants

**Published state.** Color-texture analysis is the classic result: joint color LBP in multiple color spaces detects print and replay attacks at low resolution with strong results on Replay-Attack/CASIA-FASD, explicitly at 320x240-scale imagery [PUB: arXiv:1511.06316, Boulkenafet et al., cited 589+]. Screens cannot reproduce all surface colors, and color distortion appears as a spoof-trace cue in the disentanglement literature [PUB: arXiv:2007.09273].

**Fit for us (INF + MEAS constraint).** MJPG 4:2:0 halves chroma resolution before we ever see it, weakening color statistics at exactly our resolution; and our ViT (color-capable, CelebA-Spoof-family) already failed on phones at distance [MEAS]. Color statistics are worth keeping as a feature input to a retrained small model (rank 4), not as a standalone gate [INF]. Multi-illuminant metamerism approaches need hardware; excluded per task statement.

### 2.5 (1e) Instrument-boundary (rectangle) detection

**Published state.** The FAS literature locates attack evidence, but always as *face-region texture/mask* estimation rather than as classical rectangle geometry: pixel-wise binary supervision localizes the attack region itself (DeepPixBiS) [PUB: arXiv:1907.04047, ICB 2019, DOI 10.1109/ICB45273.2019.8987370]; "spoof trace" explicitly names "color distortion, 3D mask edge, moire pattern" as the discriminative patterns and estimates them for generalization [PUB: arXiv:2007.09273, ECCV 2020; physics-guided variant arXiv:2012.05185]; SAM-based fine-grained annotation produces per-pixel live/spoof masks for better supervision [PUB: arXiv:2310.08142]; shuffled patch-wise supervision targets frame-level generalization [PUB: arXiv:2109.03484]. MToFNet notes moire patterns differ per screen type, motivating attack-region reasoning [PUB: arXiv:2110.04066].

**The classical-geometry detector (INF, our design).** No published work was found that detects the *rectangular boundary of the attack instrument* (phone/print edge structure) as the primary cue. Our measured evidence supports trying it: the attack instrument is a rigid rectangle surrounding the face box, stable across frames while the hand micro-moves; a genuine face presentation has no persistent right-angled high-gradient surround. It is scale-invariant in the sense that rectangle detection does not depend on face-texture detail, attacking exactly the distance failure of our ViT [INF grounded in MEAS scale-dependence]. Concrete parameters in section 7, design B.

### 2.6 (1f) Moire beyond FFT peakiness

**Published state.** Moire is real but instrument- and settings-dependent: moire patterns in screen recapture "differ by the screens" and cause overfitting rather than generalizing [PUB: arXiv:2110.04066]; systematic screen-recapture benchmarks show moire artifacts are common but vary across screens, phones, lighting, and camera distance [PUB: arXiv:2510.23225, arXiv:2407.10399]. The de-moire restoration literature establishes the pixel-grid-interference origin (sensor grid vs display subpixel grid) [PUB: restoration literature above].

**When moire is reliable (PUB+INF).** Moire needs the display's pixel grid to be resolved (or near-resolved) by the sensor grid. At 640x480 with a phone at 1-2 m, a 1080p-class phone screen spans roughly 100-250 sensor columns, ~5-13 sensor pixels per display pixel-width scale; the beat pattern lands at high spatial frequencies where the lens MTF and MJPG quantization suppress it [INF]. This exactly matches our measurement: complete overlap of genuine and phone peakiness at the shipped high-frequency FFT cue, threshold 28 catching nothing, while the banner (large, close, low-res print) is caught [MEAS]. Published orientation-histogram or line-profile moire features exist in the de-moire literature rather than as PAD features; at our resolution/distance regime the honest conclusion is: moire is a deny-only bonus cue for close/large screens, not a distance detector [INF]. Line-profile/orientation features would not change the physics (no resolvable grid, no stable beat).

### 2.7 (1g) Temporal cues for video replay (vs photo-on-screen)

**Published state.** Photo-on-screen is trivially separable temporally: zero content motion in screen coordinates. For video replay: GAIN distinguishes normal vs abnormal geometric motion of live vs spoof presentations via dense landmark dynamics [PUB: arXiv:2306.14313]. EulerNet (industry, 30k mobile-collected samples) amplifies "abnormal clues" from consecutive frames for FAS [PUB: arXiv:2208.04076]. Event-camera work states replay "cannot faithfully reproduce [temporal micro-dynamics] due to temporal resampling and display artifacts" [PUB: arXiv:2604.26285]; the same principle at standard frame rates is our inference. Forgery-detection work treats flicker/discontinuity as one of two temporal artifact families [PUB: arXiv:2307.08317]. For source-attribution of replay: PRNU sensor fingerprints are the established video/image source-identification trace [PUB: arXiv:2309.03353], with known fragility under heavy processing and non-uniqueness concerns on modern computational-photography pipelines [PUB: arXiv:2009.04878].

**Frame-rate mismatch/judder (INF).** A 24/25 fps source video played on a 60 Hz phone and captured at 30 fps produces periodic frame duplication (cadence); an autocorrelation of consecutive-frame differences would show a peak at the source period (e.g. ~5-frame cadence for 24-in-60). A 30 fps source on a 60 Hz phone captured at 30 fps produces clean 1:1, so absence of judder is not a pass signal [INF]. Deny-only, same as banding.

**Sensor-noise correlation (INF).** PRNU of the *attack source camera* can survive inside replayed content while our own camera's PRNU is absent from the face region; both require PRNU estimation infra and are fragile at VGA/MJPG. Not recommended for v1 [INF, based on PUB fragility above].

## 3. Deep Features Claiming Cross-Attack Robustness

| Method | What it does | Input/params | Cross-attack claim | Code/weights |
|---|---|---|---|---|
| CDCN [PUB: arXiv:2003.04092, CVPR 2020] | Central-difference convolution captures detailed intrinsic gradient/texture detail; frame-level, quick response | 64x64 RGB input (paper's low-res regime); designed for efficiency | Strong OULU-NPU intra-dataset results incl. unseen-attack protocol (Protocol 3) | github.com/ZitongYu/CDCN; license classified "Other" (custom) by GitHub API as of 2026-08-22; treat as research-only until reviewed |
| CDCN++ / Dual-Cross [PUB: arXiv:2105.01290, TPAMI 2021] | Sparse-directional CDC, multi-scale, attention; the "triplet" version optimizes for generalization | moderate; multi-scale | Improved cross-type/cross-domain vs CDCN | same group's repos |
| Multi-modal CDCN [PUB: arXiv:2004.08388] | CDC for RGB+depth+IR (CASIA-SURF) | needs depth/IR | n/a for our RGB-only path |  |
| NAS-FAS [PUB: arXiv:2011.02062] | NAS over static-dynamic CDC search space for cheap deployment | searched, small | DG-oriented |  |
| DeepPixBiS [PUB: arXiv:1907.04047, ICB 2019] | Pixel-wise binary supervision; localizes attack region | small CNN, grayscale-friendly | Strong cross-dataset (OULU->MSU etc.) for its size, driven by region localization | Idiap bob ecosystem |
| Spoof-trace DG-VAE [PUB: arXiv:2007.09273, ECCV 2020] | Disentangles spoof traces (color distortion, mask edge, moire) hierarchically | moderate | Explicitly targets cross-type generalization |  |
| Physics-guided spoof trace [PUB: arXiv:2012.05185] | Adds reflection + 3D-geometry priors to trace disentanglement | moderate | cross-type |  |
| Multi-cue explainable [PUB: arXiv:2202.10187] | Multiple auxiliary cues (depth, reflection map, others) | moderate | cross-dataset gains |  |
| Material perception [PUB: arXiv:2007.02157] | Human-material-perception-inspired descriptors |  | cross-attack (O, C, M, S: OULU, CASIA, MSU, replay) |  |
| Domain-generalization family: single-side DG [arXiv:2004.14043], D2AM [arXiv:2105.02453], IADG [arXiv:2304.05640], semi-supervised [arXiv:2206.06510], test-time [arXiv:2403.19334], CViT [arXiv:2307.12459] | meta-learning/alignment tricks for unseen domains | various | measured on O/C/M/I cross-dataset protocols | some public |
| Foundation models FS-VFM [arXiv:2510.10663], FSFM [arXiv:2412.12032] | self-supervised pretraining on real faces unifying spoof/deepfake detection | large backbones | broad but heavyweight; not <50MB | code released (2024-25) |
| Face X-Ray [PUB: arXiv:1912.13458, CVPR 2020, 1740+ citations] | Detects *blending boundary of two composited images* |  | **Confirmed: it only assumes a digital blending step; it does not target physical display replay. Not applicable to our phone-screen problem** [PUB abstract] | code available |

Requested items that could NOT be verified in any primary source (DBLP, arXiv, Crossref, survey tables checked 2026-08-22): a method named "LTAM" (no FAS paper with that acronym exists in DBLP) and "IDEAL (implicit domain alignment)" (no such paper on arXiv or DBLP). The nearest verified DG line is the family above; if a specific paper was meant, re-check the acronym. A "Single central difference network" corresponds to the CDCN line above.

**ONNX availability:** no official ONNX weights for the CDCN family or DeepPixBiS were found; MiniFASNet has a community ONNX export (section 5).

## 4. Datasets with Phone-Screen Attacks (and Fit to VGA)

| Dataset | Resolution / format | Subjects, attacks | Access | Fit |
|---|---|---|---|---|
| Replay-Attack (Idiap) [PUB: Idiap dataset page; Chingovska et al., BIOSIG 2012] | **320x240 MJPG .mov, 25 Hz, laptop webcam** | 50 clients, 1300 clips; print (matte/glossy) + phone (iPhone 3GS 480x320) + tablet (iPad 1024x768) photo & video attacks, fixed and hand-held, controlled/adverse light | EULA, research purposes, Idiap request | **Best match: near-identical resolution, codec (Motion JPEG!), and attack geometry to our path** |
| Replay-Mobile (Idiap) [PUB: Idiap page; DOI 10.1109/BIOSIG.2016.7736936] | 720x1280, 25 Hz, phone/tablet front cameras | 40 clients, 1190 clips; matte/glossy print + phone/tablet video replay | EULA, research | Higher-res; complementary |
| MSU-MFSD [PUB: DOI 10.1109/TIP.2015.2466088; cvlab.cse.msu.edu] | webcam + phone camera (VGA-class laptop) | 35 subjects; print + phone video replay | research request | Second-best fit; VGA laptop camera |
| CASIA-FASD [PUB: DOI 10.1109/ICB.2012.6199754] | low/normal/high quality | 50 subjects; warped/curved/cut print + phone screen replay | request | the classic C in O/C/M/I |
| OULU-NPU [PUB: DOI 10.1109/FG.2017.77] | 1920x1080 mobile front cam | 55 subjects; print + two different electronic displays | request | protocol gold standard: unseen-environment, unseen-attack, unseen-camera protocols are the domain-shift tests |
| SiW [PUB: MSU CVL project page] | HD | 165 subjects; live, print, phone replay, mask | research request | large intra-dataset variety |
| SiW-M [PUB: name only verified; 13 attack types incl. masks, transparent masks, replay] | HD |  | research request | cross-type stress |
| WMCA (Idiap) [PUB: Idiap page; DOI 10.1109/TIFS.2019.2916652] | color+depth+IR+thermal | 72 identities, 1941 clips; print, replay, 3D mask, glasses, transparent mask | EULA | RGB channel usable; multi-channel protocols beyond our path |
| CeFA [PUB: DOI 10.1109/WACV48630.2021.00122; arXiv:1912.02340] | RGB+depth+IR | 1607 subjects, 3 ethnicities; cross-ethnicity + cross-modality protocols |  | best *protocol-level* domain-shift robustness test (cross-ethnicity) |
| CASIA-SURF [PUB: arXiv:1812.00408] | RGB+D+IR | 1000 subjects | competition/EULA | multi-modal; out of scope for RGB-only |
| CelebA-Spoof [PUB: arXiv:2007.12342, ECCV 2020; Challenge arXiv:2102.12642] | web-quality stills, 10 sensors | 625,537 images, 10,177 subjects, 10 spoof types (print-dominated) | public, research | **our MEASURED result: models from this family (ViT 343MB; earlier mn3 saturated) do not transfer to our camera/distance; use only as pretraining, never as the shipped gate** |

**Per-frame availability:** Replay-Attack/Replay-Mobile/MSU-MFSD/OULU-NPU are videos (per-frame extractable). CelebA-Spoof is stills. Licenses above are research-oriented; commercial use of Idiap/MSU data requires separate agreement; none of this data may ship inside irlume, it is for training/eval only.

**Domain-shift-robust protocols (PUB):** OULU-NPU Protocols 3 (unseen attack) and 4 (unseen camera+lighting); cross-dataset O/C/M/I testing [arXiv:2004.14043 and the DG family]; CeFA cross-ethnicity; cross-dataset degradation is consistently reported as severe [PUB: arXiv:2206.06510, arXiv:2406.12258]. Video-wise aggregation of frame scores is recommended over single-frame decisions [PUB: arXiv:2406.12258].

## 5. Same-Day Testable Open Models

| Model | License | Input / size | Claimed screen-attack performance | Where |
|---|---|---|---|---|
| MiniFASNetV1/V2 (Silent-Face-Anti-Spoofing) | **Apache-2.0 (repo LICENSE file, verified 2026-08-22)**, covering code and the shipped weights | 80x80 BGR crop; 0.414M/0.435M params, 0.081 GFLOPs | APK model (2.7_80x80, open): FPR 1e-5, TPR 97.8% on their internal test; high-accuracy model NOT open-sourced. Vendor's own caveat: "RGB silent liveness robustness is limited by camera model and scenario" | github.com/minivision-ai/Silent-Face-Anti-Spoofing |
| MiniFASNetV2 ONNX community export | provenance-documented export of the Apache-2.0 weights | same 80x80 | inherits above | huggingface.co/garciafido/minifasnet-v2-anti-spoofing-onnx |
| CDCN (if license acceptable) | custom "Other" license, research-use expectation | 64x64 RGB | OULU-NPU protocols incl. unseen display attacks | github.com/ZitongYu/CDCN |
| DeepPixBiS | Idiap bob (BSD-style ecosystem); training code, weights need checking | small grayscale | strong cross-dataset for size | Idiap bob paper package |

OpenVINO OMZ: no face-PAD model in the public zoo (checked 2026-08-22; OMZ covers detection/recognition, not PAD). ONNX model zoo: none. Given our measured non-transfer of CelebA-Spoof-family models [MEAS], MiniFASNet should be tested as a *candidate*, expected to inherit some of the same distribution risk (it is silent-RGB, mobile-trained), and any adoption stays behind our own measured ROC on the 480-frame corpus plus fleet captures [INF].

## 6. Industry Practice (RGB-Only Screen-Attack Defense)

- **Microsoft Windows Hello**: face authentication "utilizes a camera specially configured for near infrared (IR) imaging"; Enhanced Sign-in Security further restricts to certified sensors. There is no RGB-only face path; the OS vendor's implicit position is that RGB-only passive liveness is not shippable as a primary authenticator [PUB: learn.microsoft.com, "Windows Hello face authentication" and "Windows Hello Enhanced Sign-in Security" pages, retrieved 2026-08-22].
- **Apple Face ID**: depth (projected IR dot pattern) + IR camera + "sophisticated anti-spoofing neural networks" + attention awareness. Again no RGB-only fallback; the anti-spoofing networks run on IR/depth-derived input, not passive RGB [PUB: Apple Support 102381, retrieved 2026-08-22].
- **Alipay/Ant (Aurora Guard)**: RGB path defended with ACTIVE screen-flash/light CAPTCHA plus reflection-based normal-cue CNN; deployed at millions of users. Passive RGB texture alone was not trusted; a challenge-response illumination sequence is the published mechanism [PUB: arXiv:1902.10311, arXiv:2102.00713].
- **Face Flashing (MSRA)**: protocol analysis of active light-projection liveness, arguing passive cues lack time-bounded security guarantees [PUB: arXiv:1801.01949].
- **Multi-frame voting / threshold placement**: published as necessary to bridge frame-wise accuracy and real-world stability [PUB: arXiv:2406.12258]; industry corpora train explicitly on mobile captures at scale [PUB: arXiv:2208.04076].

**Pattern (INF):** no first-party system was found that defends an RGB-only path against screen replay purely passively; published deployable systems either add active illumination (challenge) or require IR/depth hardware. Irlume's IR path matches the industry answer; the RGB convenience path should adopt the same shape: passive physics/geometry deny-cues (banding, rectangle, rPPG) plus conservative multi-frame voting, fail-closed to password.

## 7. Three Concrete Detector Designs for the Phone-at-Login-Distance Hole

### Design A: Row-profile flicker-banding detector (deny-only)

- **Signal:** per frame, compute row-mean luma y(r) from the decoded MJPG frame (any region containing the screen; face box dilated by 1.5x is fine). Detrend (subtract 31-row median filter). Compute (i) 1D FFT magnitude over r, peak energy in the period band 20-120 rows vs total; (ii) inter-frame: cross-correlate consecutive detrended row profiles, track peak displacement variance (band drift = emissive modulation alive).
- **Why our corpus says it should work:** the phone is an emissive display with refresh/PWM brightness modulation; our sensor is rolling-shutter [PUB physics, section 2.1]. Every phone presentation in our corpus should carry band structure *independent of face scale*, which is precisely the axis (scale/distance) where both our FFT cue and the ViT failed [MEAS]. The cue lives in luminance at low row-frequencies, below where MJPG quantization bites [INF, section 2.1].
- **Compute:** O(H*W) adds + two 1D FFTs of length 480 per frame; cheaper than the shipped 128x128 2D FFT cue [INF].
- **Validation plan:** run on the 480-frame corpus; report band-energy distributions for genuine vs phone vs banner; then fleet capture on ASUS/archhost/minihost/thinkpad phones (OLED PWM vs LCD backlit) before any threshold ships.
- **Failure mode:** DC-dimmed/high-brightness phones; acceptable because deny-only.

### Design B: Attack-instrument rectangle detector (deny-only)

- **Signal:** around the YuNet face box, take the annulus from 1.2x to 2.5x box size. Sobel gradients + Hough line segments; require >= 3 segments each >= 0.7 * face width, pairwise near-orthogonal or parallel, forming a closed right-angled quadrilateral whose aspect is in phone/print range (0.4-2.5), stable (IoU of the fitted rect > 0.8) across >= 5 consecutive frames while the face box itself jitters.
- **Why our corpus says it should work:** every phone/print attack in our corpus is a rigid rectangle physically surrounding the face; genuine presentations have hands/shoulders/background instead. The ViT evidence (genuine close 0.368 vs phone close 0.566; overlap growing with distance [MEAS]) shows texture features lose separability at distance, while rectangle geometry degrades only with occlusion, not scale [INF]. Published pixel-wise attack-region supervision proves attack-region evidence is learnable/locatable [PUB: arXiv:1907.04047, arXiv:2007.09273]; the classical closed-form rectangle check is our cheap, non-learned version [INF].
- **Compute:** one Sobel + Hough on a small ROI every N frames; trivially budget-compatible [INF].
- **Failure mode:** attacker masks the bezel (cutout), crops screen edges out of frame; then the face occupies the full frame at distance, which itself is a detectable prior violation (face-box-to-frame ratio) [INF].

### Design C: POS static-photo gate (deny-only) + fusion policy

- **Signal:** 8-10 s, forehead+cheek ROI means -> POS projection (published closed form) -> bandpass 0.7-4 Hz -> pulse-presence test (spectral peak SNR >= measured threshold in genuine corpus). Absent pulse with a present face => deny as static photo/print (phone showing photo, printed banner; both pulse-free by physics) [PUB: 10.1109/TBME.2016.2609282; photo/mask discriminability 10.1145/3345336.3345345].
- **Fusion (all deny-only, fail-closed to password):** banding present -> deny (screen, any content). No pulse -> deny (static photo). Neither fired -> existing texture ViT + recognition proceed; video replay on a DC-dimmed screen remains covered only by the ViT, which is why fleet-scale phone capture (OLED + LCD, multiple brightness levels) must be added to the eval corpus before enabling the RGB path in any default config [INF, MEAS gap].
- **Why our corpus supports it:** the banner and phone-photo classes are exactly the classes where our ViT is strongest (banner clean, phone split) and the FFT is blind [MEAS]; pulse-free physics gives an independent, texture-uncorrelated second vote for the same classes [INF].

## 8. Source Index (primary sources only)

Physical cues: arXiv:2509.24644 (RIFLE), arXiv:2605.21079 (VDFP/DeViD), arXiv:2606.29845 (Bricker/BRACE), arXiv:2101.10011 (rolling-shutter attack), Tajbakhsh & Grigat SIP 2007 (ACM DL 10.5555/1659892.1659948). rPPG: 10.1109/TBME.2013.2266196 (CHROM), 10.1109/TBME.2016.2609282 (POS), DeepPhys ECCV 2018, 10.1145/3345336.3345345 (rPPG-PAD photo/mask vs replay), PMC9024982 (replay vulnerability), 10.1109/BTAS.2018.8698579, arXiv:2303.06452 (hallucinated pulses), arXiv:2110.11525 (rPPG attacks), arXiv:2208.05401 (JOINT), arXiv:2310.02140 (PAD-Phys), arXiv:2104.07419 (TransRPPG). Reflection: arXiv:1907.12400 (SpecDiff), arXiv:1902.10311 + arXiv:2102.00713 (Aurora Guard), arXiv:2202.10187, arXiv:2012.05185, arXiv:2602.06452, arXiv:1807.02030. Color: arXiv:1511.06316. Spoof trace / region: arXiv:2007.09273, arXiv:1907.04047 (DeepPixBiS, DOI 10.1109/ICB45273.2019.8987370), arXiv:2310.08142, arXiv:2109.03484, arXiv:2110.04066 (MToFNet). Moire: arXiv:2510.23225, arXiv:2407.10399. Temporal: arXiv:2306.14313 (GAIN), arXiv:2208.04076 (EulerNet), arXiv:2604.26285 (event ocular), arXiv:2307.08317 (AltFreezing), arXiv:2309.03353 + arXiv:2009.04878 (PRNU). Deep FAS: arXiv:2003.04092 (CDCN), arXiv:2105.01290 (CDCN++), arXiv:2004.08388, arXiv:2011.02062 (NAS-FAS), arXiv:1912.13458 (Face X-Ray), arXiv:2007.02157, arXiv:2004.14043, arXiv:2105.02453, arXiv:2304.05640, arXiv:2206.06510, arXiv:2403.19334, arXiv:2307.12459, arXiv:2510.10663, arXiv:2412.12032. Datasets: Idiap pages (Replay-Attack, Replay-Mobile, WMCA), BIOSIG 2012 (Chingovska), 10.1109/BIOSIG.2016.7736936, 10.1109/TIFS.2019.2916652, 10.1109/TIP.2015.2466088, 10.1109/ICB.2012.6199754, 10.1109/FG.2017.77, MSU CVL pages (SiW), 10.1109/WACV48630.2021.00122, arXiv:1912.02340, arXiv:1812.00408, arXiv:2007.12342, arXiv:2102.12642. Models: github.com/minivision-ai/Silent-Face-Anti-Spoofing (Apache-2.0), huggingface.co/garciafido/minifasnet-v2-anti-spoofing-onnx, github.com/ZitongYu/CDCN (custom license). Industry: learn.microsoft.com (Windows Hello face, ESS), support.apple.com/102381 (Face ID), arXiv:1801.01949 (Face Flashing), arXiv:1902.10311/2102.00713 (Aurora Guard).

Unverified/does-not-exist (checked 2026-08-22): FAS method "LTAM"; FAS method "IDEAL (implicit domain alignment)". Face X-Ray confirmed inapplicable to physical replay.

---

# Part 2 — Measured probe validation, 2026-08-22 night session (opencode)

All seven candidate cues from Part 1 were implemented and measured against
the 2026-08-22 qualification corpus (11 conditions, ~1,000 labeled frames
incl. two 300-frame 10 s captures, single deployment camera, user-operated).
Probe scripts: local research store `/tmp` (session); key numbers below.

| # | cue | genuine range | attack range | verdict |
|---|---|---|---|---|
| 1 | moiré peakiness (SHIPPED `moire_score`, 128² nearest) | 8–23 | 11–40 (banner 10–19) | **DEAD** — full overlap at threshold 28; the docblock's own warning holds |
| 2 | 1D row-profile banding FFT | genuine-close 60 | phones 48–71 | **DEAD** — confounded by face structure (eyes/mouth rows are periodic) |
| 3 | 2D horizontal-cone anisotropy | coneFrac 0.026–0.055; genuine faces carry MORE horizontal energy than vertical | same range | **DEAD** — signal absent (DC-dimmed display or readout too fast) |
| 4 | MiniFASNet-V2 (Apache-2.0, 0.4M, HF `garciafido/…`, sha256 `d7b3cd9b…`) | P(replay) ≈ 0.97–0.99 | ≈ 0.97–0.99 | **DEAD** — total non-transfer; genuine saturates spoof (CelebA-family camera overfit, as measured for mn3) |
| 5 | instrument rectangle (Canny + axis-aligned side support, expansion sweep) | fires 61–100% at tight expansion | 0–96% inconsistent | **DEAD, inverted** — face/hair outline reads as rectangle; bezel below Canny contrast at distance |
| 6 | rPPG POS pulse-SNR (256-frame windows, central-face ROI) | no pulse peak (0.10 Hz drift; SNR 1.3–1.5); G lag-1 corr 0.94 | 0.2 Hz drift; SNR 1.7 | **DEAD on this hardware** — auto-exposure + MJPG crush the pulse modulation; also 8–10 s per attempt is unacceptable login UX |
| 7 | landmark micro-motion (relative, global-removed, IOD-normalized) | 5–35 mIOD | 11–89 mIOD (hand-held shakes MORE) | **DEAD, inverted** — hand-held instruments move more than a seated head; a tripod would move less than anything |

Corpus detail for cue 1 (the shipped moiré), per condition median: genuine
desk 11.5/11.9, dim 17.2, close 10.5; banner 14.6/15.6; phone 12.0–23.0.
The 28.0 ceiling catches only the far-phone run (23.0 median, 7/48 frames) —
the presentation the ViT already catches.

## The phone-at-login-distance species: closed by NOTHING measurable

Seven cues, three learned models (mn3 prior, ViT, MiniFASNet), one shipped
physics cue: none separates a phone displaying the enrolled face at login
distance from a genuine face on this camera class. Each failure has a
physics reason now measured, not speculated: moiré needs a resolvable panel
grid (VGA + distance + MJPG kills it); banding needs PWM/refresh modulation
that survives the readout (absent here); rPPG needs stable exposure (AGC
kills it); geometry needs bezel contrast (distance kills it); learned
features don't transfer across cameras (measured twice); motion cues invert
(hand-held > head micro-motion).

This matches Part 1's industry finding: nobody ships passive RGB-only
screen defense. Windows Hello requires IR; Apple uses depth+IR; Alipay adds
an ACTIVE screen-flash CAPTCHA. Irlume's architecture is already on the
right side of this evidence: IR face-presence defeats screens by physics
(screens emit nothing at 850 nm), and the RGB-only tier is gated to
convenience use that never releases credentials.

## What measurably improves the RGB path: the ViT as a PRINT/BANNER deny-only cue

The one positive result across all probes: the Adedev-W ViT (343 MB, m96
crop, 0.60 threshold, 5-frame-median voting) catches the vinyl banner —
the species that historically breached the physics gate at 98.6% APCER
(2026-06-30) — at **100% (all presentations, both sessions)** with **0
false-fire frames in 180 genuine frames** including dim and close regimes.
It honestly does NOT close the phone species; as a deny-only opt-in cue in
the FLIR pattern (may reject, never approve what other cues passed) it adds
banner/print protection the native stack measurably lacks, and its phone
miss changes nothing (deny-only cues cannot cause accepts).

Wiring decision (not taken in this session): opt-in third-party cue
`vit-pad`, m96 crop, 0.60, 5-frame voting, deny-only, print/banner species
disclosed; latency 59 ms (5700G) / 268 ms (N100) makes it consent-watch-
pipelined, not blocking. The phone species remains IR's job.

## Reproduce

Corpus: `~/irlume-research/2026-08-22-vit-live` (biometric, local only).
Scores: PR #515 session CSV (ViT + native), this file (cues 1–7 tables).
MiniFASNet artifact: HF `garciafido/minifasnet-v2-anti-spoofing-onnx`
(sha256 `d7b3cd9ba8a7ceb13baa8c4720902e27ca3112eff52f926c08804af6b6eecc7b`,
Apache-2.0, upstream .pth hash documented on the model card).

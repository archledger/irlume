//! Algorithmic IR presentation-attack detection (PAD) — NO trained weights.
//!
//! Why no model: every public anti-spoof dataset is non-commercial, so a trained
//! PAD model is license-tainted. We gate on documented physics instead, which is
//! license-clean and (for the NIR cue) demographically fair.
//!
//! The gate is HARD: any failing cue rejects. The signals are computed upstream
//! (camera + detector); this crate applies the decision thresholds.

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Verdict {
    Live,
    Spoof,
    Uncertain,
}

/// A detected face reduced to normalized center (0..1) + detector score.
#[derive(Debug, Clone, Copy)]
pub struct FaceBox {
    pub cx: f32,
    pub cy: f32,
    pub score: f32,
}

/// The physical signals the gate decides on (computed from RGB + IR captures).
#[derive(Debug, Clone)]
pub struct Signals {
    /// Top face in the RGB frame, if any.
    pub rgb_face: Option<FaceBox>,
    /// Top face in the IR frame, if any (a screen/print won't reflect 850nm IR
    /// like skin, so it usually yields no IR face).
    pub ir_face: Option<FaceBox>,
    /// Mean brightness (0..255) inside the IR face region — skin reflects the
    /// active emitter strongly; a screen/print does not.
    pub ir_face_brightness: f32,
    /// Center-to-edge IR brightness ratio in the face region. A real 3D face lit
    /// by a near-coaxial emitter is brighter at the center/nose and falls off at
    /// the edges (ratio > 1); a flat photo/screen is more uniform (~1). Anti-flat.
    pub ir_center_edge_ratio: f32,
    /// Peak IR brightness (0..255) at the eyes — the emitter's specular corneal
    /// glint. Supporting cue only (glint alone is not decisive).
    pub ir_eye_glint: f32,
    /// Head-orientation yaw asymmetry from the RGB face landmarks (0 frontal,
    /// →1 turned). Defaults to 0 (frontal) when not computed.
    pub head_yaw_asym: f32,
    /// Head-orientation pitch fraction (0.5 frontal; lower = chin down, higher =
    /// chin up). Defaults to 0.5 (frontal) when not computed.
    pub head_pitch_frac: f32,
    /// Mean RGB-face luma (0–255) — RGB-only path: the face must be lit enough to
    /// recognize. Unused on the IR path.
    pub rgb_face_brightness: f32,
    /// Fraction (0–1) of near-white pixels in the RGB face region — RGB-only
    /// screen/glare deterrent cue. Unused on the IR path.
    pub rgb_specular_frac: f32,
    /// High-frequency spectral peakiness of the RGB face region (2D-FFT moiré /
    /// pixel-grid cue) — RGB-only screen-replay deterrent. Unused on the IR path.
    pub rgb_moire_score: f32,
}

impl Default for Signals {
    fn default() -> Self {
        Self {
            rgb_face: None,
            ir_face: None,
            ir_face_brightness: 0.0,
            ir_center_edge_ratio: 0.0,
            ir_eye_glint: 0.0,
            head_yaw_asym: 0.0,   // frontal
            head_pitch_frac: 0.5, // frontal
            rgb_face_brightness: 0.0,
            rgb_specular_frac: 0.0,
            rgb_moire_score: 0.0,
        }
    }
}

/// RGB-only convenience path: the face must be at least this bright to recognize.
pub const RGB_FACE_MIN_BRIGHTNESS: f32 = 60.0;
/// And not blown out (sunlight/overexposure makes recognition unreliable too).
pub const RGB_FACE_MAX_BRIGHTNESS: f32 = 245.0;
/// Above this near-white fraction in the face region, treat it as a screen/glare
/// spoof (deterrent-grade — emissive displays & glossy prints blow out).
pub const RGB_SPECULAR_MAX: f32 = 0.18;
/// Above this high-frequency spectral peakiness, treat the face region as a
/// display (periodic pixel-grid / moiré). DETERRENT-grade and hardware-specific.
/// Calibrated on the Shinetech RGB cam: a real lit face read ~9–13; a high-PPI
/// phone held VERY CLOSE (the best case for moiré) read only ~15–38 — and moiré
/// weakens with distance, so at arm's length a replay would overlap real faces
/// entirely. This is NOT a robust PAD — the real mitigation for RGB-only is the
/// convenience-tier policy (lock-screen unlock only, never credential release).
///
/// PER-CAMERA SPREAD IS REAL (cross-distro survey 2026-07-01): a live face reads
/// 9–13 on the Zenbook's Shinetech but 18–27 on a ThinkPad Chicony — the old 18
/// hard-rejected a real user on the latter, and the two cameras' live/replay
/// ranges overlap so no universal threshold exists. 28 clears every observed
/// live face and still catches the top of the close-replay band (~30–38);
/// override per camera with IRLUME_RGB_MOIRE_MAX until enrollment-time
/// per-camera baselining lands.
pub const RGB_MOIRE_MAX: f32 = 28.0;

/// The effective moiré ceiling: `IRLUME_RGB_MOIRE_MAX` env override (per-camera
/// tuning, set on the daemon unit) or the built-in default.
pub fn rgb_moire_max() -> f32 {
    std::env::var("IRLUME_RGB_MOIRE_MAX")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(RGB_MOIRE_MAX)
}

/// Per-cue evidence, surfaced for logging/self-test (never raw image data).
#[derive(Debug, Default, Clone)]
pub struct Cues {
    pub face_in_rgb: bool,
    /// Face present in IR — defeats screen/print attacks (the core cue).
    pub face_in_ir: bool,
    /// RGB and IR face roughly co-located — defeats RGB-deepfake + IR-blocker.
    pub cross_spectrum_aligned: bool,
    /// IR face region is brightly lit by the emitter (skin reflectance).
    pub ir_reflectance_ok: bool,
    /// 3D structure present (center brighter than edges) — anti-flat-spoof.
    pub depth_ok: bool,
    /// Corneal glint present (supporting; logged, not decisive).
    pub glint_present: bool,
    /// Face is frontal enough (≈±15°) to make a decision — Windows-Hello-style
    /// head-orientation gate.
    pub frontal_ok: bool,
}

/// IR face region must be at least this bright (0..255). A lit live face ran ~83
/// mean overall on the Shinetech module; the face region is brighter still. A
/// screen reflects far less 850nm.
pub const IR_FACE_MIN_BRIGHTNESS: f32 = 35.0;
/// Max normalized center distance between the RGB and IR face.
pub const CROSS_SPECTRUM_TOLERANCE: f32 = 0.30;
/// Minimum detector score to trust a face.
pub const MIN_FACE_SCORE: f32 = 0.6;
/// Center/edge IR ratio above this indicates 3D structure (anti-flat). Calibrated
/// 2026-06-26: a real lit face measured 1.36; a flat spoof is ~1.0. Kept lenient
/// at 1.03 to avoid false-rejects across poses; tighten with flat-IR-spoof data.
pub const DEPTH_MIN_RATIO: f32 = 1.03;
/// Eye IR peak above this counts as a corneal glint (supporting cue).
pub const GLINT_MIN: f32 = 180.0;
/// Head-orientation gate (Windows-Hello-style ±15° frontality), approximated
/// from 2D landmarks. Deliberately PERMISSIVE — rejects only clearly off-angle
/// faces, to avoid false-rejects; a non-frontal face yields `Uncertain` ("face
/// the camera"), never `Spoof`. Also gates enrollment, keeping templates frontal.
/// PITCH is intentionally wide: a top-bezel camera sees the user pitched ~15-17°
/// DOWN when they look at the screen, so a tight pitch gate would reject normal
/// use. Tune per-camera with real pose data; calibrating to the user's enrolled
/// pose is a follow-up.
pub const YAW_ASYM_MAX: f32 = 0.40;
pub const PITCH_FRAC_MIN: f32 = 0.20;
pub const PITCH_FRAC_MAX: f32 = 0.80;

/// The hard liveness gate. Stateless for now (per-user IR calibration is a P2
/// follow-up).
#[derive(Default)]
pub struct LivenessGate;

impl LivenessGate {
    pub fn new() -> Self {
        Self
    }

    /// Decide live / spoof / uncertain from the captured signals. Any hard
    /// failure rejects (no weighted fusion).
    pub fn evaluate(&self, s: &Signals) -> (Verdict, Cues, String) {
        let mut cues = Cues::default();

        let Some(rgb) = s.rgb_face.filter(|f| f.score >= MIN_FACE_SCORE) else {
            return (
                Verdict::Uncertain,
                cues,
                "no face in RGB — present your face".into(),
            );
        };
        cues.face_in_rgb = true;

        // Core anti-screen cue: a real face reflects the IR emitter and is
        // detectable in IR; a phone/print does not.
        let Some(ir) = s.ir_face.filter(|f| f.score >= MIN_FACE_SCORE) else {
            return (
                Verdict::Spoof,
                cues,
                "no face in IR — a real face reflects 850nm; a screen/print does not".into(),
            );
        };
        cues.face_in_ir = true;

        // Cross-spectrum co-location: the same face in both spectra.
        let dist = ((rgb.cx - ir.cx).powi(2) + (rgb.cy - ir.cy).powi(2)).sqrt();
        cues.cross_spectrum_aligned = dist <= CROSS_SPECTRUM_TOLERANCE;
        if !cues.cross_spectrum_aligned {
            return (
                Verdict::Uncertain,
                cues,
                format!("RGB/IR face mismatch (dist {dist:.2}) — re-center"),
            );
        }

        // Head-orientation gate (Windows-Hello-style ±15° frontality): a face
        // turned away or tilted yields a poor representation. Quality issue, not
        // a spoof -> Uncertain ("face the camera"). Also rejects off-angle frames
        // at enrollment, keeping templates frontal.
        cues.frontal_ok = s.head_yaw_asym <= YAW_ASYM_MAX
            && (PITCH_FRAC_MIN..=PITCH_FRAC_MAX).contains(&s.head_pitch_frac);
        if !cues.frontal_ok {
            return (
                Verdict::Uncertain,
                cues,
                format!(
                    "not facing the camera (yaw {:.2}, pitch {:.2}) — look directly at it",
                    s.head_yaw_asym, s.head_pitch_frac
                ),
            );
        }

        // IR skin reflectance: the face region must be brightly lit.
        cues.ir_reflectance_ok = s.ir_face_brightness >= IR_FACE_MIN_BRIGHTNESS;
        if !cues.ir_reflectance_ok {
            return (
                Verdict::Spoof,
                cues,
                format!(
                    "IR face too dark ({:.0}) — not reflecting IR like skin",
                    s.ir_face_brightness
                ),
            );
        }

        // Anti-flat: a real 3D face shows center-vs-edge IR falloff.
        cues.depth_ok = s.ir_center_edge_ratio >= DEPTH_MIN_RATIO;
        if !cues.depth_ok {
            return (
                Verdict::Spoof,
                cues,
                format!(
                    "IR too flat (center/edge {:.2}) — looks 2D, not a 3D face",
                    s.ir_center_edge_ratio
                ),
            );
        }

        // Corneal glint — supporting only; logged, never decisive on its own.
        cues.glint_present = s.ir_eye_glint >= GLINT_MIN;

        (
            Verdict::Live,
            cues,
            "live: face in RGB+IR, co-located, frontal, IR-reflective, 3D".into(),
        )
    }

    /// RGB-only convenience gate (no IR hardware). DETERRENT-grade anti-spoof:
    /// requires a present, frontal, well-lit face and rejects obvious screen/glare
    /// (blown-out highlights). It CANNOT match IR's defeat of photo/screen replay,
    /// which is exactly why this tier is limited to lock-screen unlock and never
    /// releases credentials / logs in / elevates. The user must have light on
    /// their face for the RGB camera to see them.
    pub fn evaluate_rgb_only(&self, s: &Signals) -> (Verdict, Cues, String) {
        let mut cues = Cues::default();
        let Some(_rgb) = s.rgb_face.filter(|f| f.score >= MIN_FACE_SCORE) else {
            return (
                Verdict::Uncertain,
                cues,
                "no face — present your face to the camera".into(),
            );
        };
        cues.face_in_rgb = true;
        cues.frontal_ok = s.head_yaw_asym <= YAW_ASYM_MAX
            && (PITCH_FRAC_MIN..=PITCH_FRAC_MAX).contains(&s.head_pitch_frac);
        if !cues.frontal_ok {
            return (
                Verdict::Uncertain,
                cues,
                "not facing the camera — look directly at it".into(),
            );
        }
        if s.rgb_face_brightness < RGB_FACE_MIN_BRIGHTNESS {
            return (
                Verdict::Uncertain,
                cues,
                "too dark — add light on your face (RGB-only mode needs a lit face)".into(),
            );
        }
        if s.rgb_face_brightness > RGB_FACE_MAX_BRIGHTNESS {
            return (
                Verdict::Uncertain,
                cues,
                "overexposed — reduce the light/backlight".into(),
            );
        }
        if s.rgb_specular_frac > RGB_SPECULAR_MAX {
            return (
                Verdict::Spoof,
                cues,
                "screen/glare detected (blown-out highlights) — RGB-only anti-spoof".into(),
            );
        }
        if s.rgb_moire_score > rgb_moire_max() {
            return (Verdict::Spoof, cues,
                format!("screen pixel-grid/moiré pattern detected (peakiness {:.0}) — RGB-only anti-spoof", s.rgb_moire_score));
        }
        (
            Verdict::Live,
            cues,
            format!(
                "live (rgb convenience; bright {:.0} specular {:.2} moire {:.0})",
                s.rgb_face_brightness, s.rgb_specular_frac, s.rgb_moire_score
            ),
        )
    }

    /// Dark-operation gate: IR only (no RGB to cross-check). Used when there's no
    /// visible-light face. Weaker than the full gate (no cross-spectrum anti-
    /// injection) but keeps IR reflectance + 3D depth + glint — same basis
    /// Windows Hello uses in the dark.
    pub fn evaluate_ir_only(&self, s: &Signals) -> (Verdict, Cues, String) {
        let mut cues = Cues::default();
        let Some(ir) = s.ir_face.filter(|f| f.score >= MIN_FACE_SCORE) else {
            return (Verdict::Uncertain, cues, "no face in IR".into());
        };
        cues.face_in_ir = true;
        let _ = ir;
        cues.ir_reflectance_ok = s.ir_face_brightness >= IR_FACE_MIN_BRIGHTNESS;
        if !cues.ir_reflectance_ok {
            return (
                Verdict::Spoof,
                cues,
                format!("IR face too dark ({:.0})", s.ir_face_brightness),
            );
        }
        cues.depth_ok = s.ir_center_edge_ratio >= DEPTH_MIN_RATIO;
        if !cues.depth_ok {
            return (
                Verdict::Spoof,
                cues,
                format!("IR too flat (center/edge {:.2})", s.ir_center_edge_ratio),
            );
        }
        cues.glint_present = s.ir_eye_glint >= GLINT_MIN;
        (
            Verdict::Live,
            cues,
            "live (dark/IR-only): IR-reflective, 3D".into(),
        )
    }
}

// --- Passive blink liveness (opt-in, ADR-0002) ------------------------------
//
// Defeats the demonstrated static IR-reflective print attack (a life-size glossy
// vinyl banner passed the single-frame gate at 98.6% APCER, 2026-06-30): a static
// print cannot blink. Given a per-frame eye-aspect-ratio (EAR) sequence
// (`irlume_vision::eye_ear` over MediaPipe FaceMesh landmarks, in capture order),
// we PASSIVELY look for a natural blink — an EAR dip well below the user's open
// baseline. No prompt, no deliberate action: the user just looks at the camera and
// blinks naturally within the window; the print holds EAR flat and never dips.
//
// Why EAR (and not the earlier IR-glint metric): live-validated 2026-07-01, EAR is
// the clean signal — open eye ≈0.24 (rock-stable), a natural blink dips to ≈0.15,
// while a static vinyl banner sits flat 0.21–0.24 (min ≈0.206, spread ≈0.034, no
// dips). The deliberate-blink glint challenge that preceded this was replaced for
// bad UX (natural blinks too fast for the glint metric; a timed held blink is not
// ergonomic). EAR is scale-invariant (a ratio), so the threshold is relative to the
// user's own open baseline and needs no per-user calibration.

/// An EAR at/below this fraction of the open baseline is a blink outright (the
/// original depth rule, kept: live blinks hit ≈0.64×, banner jitter stays ≥0.75×).
pub const BLINK_EAR_DIP_RATIO: f32 = 0.72;
/// The open baseline (per-class median EAR) must be at least this to trust a
/// plausibly-open eye was seen — guards against the mesh failing / a squint spoof.
/// Lowered 0.15 → 0.12 (2026-07-01): glasses depress the open baseline to
/// 0.13–0.14 on IR, which read NoEyes and cost half the glasses catch rate; the
/// banner sits at 0.20–0.24 so this floor was never its rejector (re-validated
/// against the banner after the change).
pub const BLINK_MIN_OPEN_EAR: f32 = 0.12;
// -- V-shape (velocity) rule, added 2026-07-01 after real-world traces showed
// natural blinks at 15 fps dip only to 0.78–0.85× baseline (mid-closure sampled,
// full closure missed) — above the depth cutoff but with a sharp drop-and-recover
// transient a static print's slow jitter does not produce.
/// Samples at/below this ratio are candidates for a blink "run".
pub const BLINK_V_RUN_RATIO: f32 = 0.88;
/// A single-sample run must dip at least this deep (one 66 ms frame at full
/// closure) — deeper than the multi-sample floor to resist one-frame mesh noise.
pub const BLINK_V_MIN_SINGLE: f32 = 0.82;
/// A multi-sample run's deepest sample must reach this.
pub const BLINK_V_MIN_MULTI: f32 = 0.85;
/// Runs longer than this many samples are a squint / pose change, not a blink.
pub const BLINK_V_MAX_RUN: usize = 6;
/// The eye must be near-open (≥ this ratio) shortly before AND after the run —
/// the sharp V. Slow drifts (auto-exposure settling, gaze shifts) fail this.
pub const BLINK_V_OPEN_RATIO: f32 = 0.93;
/// How many frames before the run start the near-open pre-sample may be.
pub const BLINK_V_PRE_WIN: usize = 4;
/// How many frames after the run end the near-open recovery may be (~400 ms).
pub const BLINK_V_POST_WIN: usize = 6;
/// A brightness class needs at least this many face samples to be trusted —
/// tiny windows (camera stream died / exposure never settled) read NoEyes.
pub const BLINK_MIN_CLASS_SAMPLES: usize = 8;
/// The V's pre/post near-open samples must have frame brightness within this
/// factor of the dip's — EAR shifts with exposure, so a dip during auto-exposure
/// slewing (measured live 2026-07-01) must not pass as a blink.
pub const BLINK_V_BRI_BAND: f32 = 0.25;

/// One observation from an IR capture sequence: frame index in the sequence, the
/// min-eye EAR when a face was detected in that frame, and the frame's mean
/// brightness. The IR emitter STROBES (alternate frames are emitter-lit vs
/// ambient-only), and ambient-only frames read systematically lower EAR — so the
/// detector baselines each brightness class separately instead of one median.
#[derive(Clone, Copy, Debug)]
pub struct EarSample {
    pub idx: usize,
    pub ear: Option<f32>,
    pub bri: f32,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BlinkResult {
    /// A natural blink was observed (a clear EAR dip below the open baseline) → live.
    Blinked,
    /// A plausibly-open eye was seen but no blink in the window (a static artefact —
    /// or the user simply didn't blink; caller re-captures / falls back to password).
    NoBlink,
    /// No plausibly-open eye anywhere in the window (mesh failed, or a non-eye/print):
    /// the median EAR never reached the open floor.
    NoEyes,
}

fn median(xs: &mut [f32]) -> Option<f32> {
    if xs.is_empty() {
        return None;
    }
    xs.sort_by(|a, b| a.partial_cmp(b).unwrap_or(std::cmp::Ordering::Equal));
    Some(xs[xs.len() / 2])
}

/// Detect a natural blink PASSIVELY from a raw-frame-rate EAR sequence.
///
/// Steps: (1) split frames into emitter-lit vs ambient-only classes when the
/// strobe is visible (a frame is "lit" if brighter than the midpoint of its
/// neighbours); (2) baseline each class by its own median EAR and convert to
/// ratios; (3) a blink is either a deep dip (≤ `BLINK_EAR_DIP_RATIO`) or a sharp
/// V: a short run of samples ≤ `BLINK_V_RUN_RATIO` that is deep enough for its
/// length and has near-open samples just before and after it. A static print's
/// jitter is neither deep nor a coherent drop-and-recover; slow drifts (AE
/// settling, squints) fail the pre/post near-open check or the run-length cap.
pub fn detect_blink(samples: &[EarSample]) -> BlinkResult {
    if samples.is_empty() {
        return BlinkResult::NoEyes;
    }
    // Strobe visible? Compare typical adjacent brightness jump to typical level.
    let mut bris: Vec<f32> = samples.iter().map(|s| s.bri).collect();
    let mut deltas: Vec<f32> = samples
        .windows(2)
        .map(|w| (w[0].bri - w[1].bri).abs())
        .collect();
    let med_bri = median(&mut bris).unwrap_or(0.0).max(1.0);
    let strobing = median(&mut deltas).unwrap_or(0.0) > 0.30 * med_bri;
    let lit = |i: usize| -> bool {
        if !strobing {
            return true;
        }
        let prev = if i > 0 {
            samples[i - 1].bri
        } else {
            samples[i + 1].bri
        };
        let next = if i + 1 < samples.len() {
            samples[i + 1].bri
        } else {
            samples[i - 1].bri
        };
        samples[i].bri > (prev + next) / 2.0
    };
    // Per-class open baseline; classes too small or never-open don't count as eyes.
    let mut baseline = [None::<f32>; 2];
    for (class, slot) in baseline.iter_mut().enumerate() {
        let mut ears: Vec<f32> = samples
            .iter()
            .enumerate()
            .filter(|(i, s)| (lit(*i) == (class == 0)) && s.ear.is_some_and(|e| e.is_finite()))
            .map(|(_, s)| s.ear.unwrap())
            .collect();
        if ears.len() >= BLINK_MIN_CLASS_SAMPLES {
            *slot = median(&mut ears).filter(|m| *m >= BLINK_MIN_OPEN_EAR);
        }
    }
    // Merged ratio timeline (frame order, each sample against its class baseline).
    struct Obs {
        idx: usize,
        ratio: f32,
        bri: f32,
        lit: bool,
    }
    let ratios: Vec<Obs> = samples
        .iter()
        .enumerate()
        .filter_map(|(i, s)| {
            let base = baseline[if lit(i) { 0 } else { 1 }]?;
            let e = s.ear.filter(|e| e.is_finite())?;
            Some(Obs {
                idx: s.idx,
                ratio: e / base,
                bri: s.bri,
                lit: lit(i),
            })
        })
        .collect();
    if ratios.is_empty() {
        return BlinkResult::NoEyes;
    }
    if ratios.iter().any(|o| o.ratio <= BLINK_EAR_DIP_RATIO) {
        return BlinkResult::Blinked;
    }
    // Sharp-V scan: maximal same-class runs of near-consecutive samples (frame
    // gap ≤ 3) at/below the run ratio. A blink spanning both classes appears as
    // one run per class, each judged on its own.
    let mut start = 0;
    while start < ratios.len() {
        if ratios[start].ratio > BLINK_V_RUN_RATIO {
            start += 1;
            continue;
        }
        let mut end = start;
        while end + 1 < ratios.len()
            && ratios[end + 1].ratio <= BLINK_V_RUN_RATIO
            && ratios[end + 1].lit == ratios[start].lit
            && ratios[end + 1].idx - ratios[end].idx <= 3
        {
            end += 1;
        }
        let run = &ratios[start..=end];
        let len = run.len();
        let deepest = run.iter().map(|o| o.ratio).fold(f32::INFINITY, f32::min);
        let deep_enough = deepest
            <= if len == 1 {
                BLINK_V_MIN_SINGLE
            } else {
                BLINK_V_MIN_MULTI
            };
        if len <= BLINK_V_MAX_RUN && deep_enough {
            let (first_idx, last_idx) = (run[0].idx, run[len - 1].idx);
            let run_bri = run.iter().map(|o| o.bri).sum::<f32>() / len as f32;
            let bri_ok = |b: f32| {
                b >= (1.0 - BLINK_V_BRI_BAND) * run_bri && b <= (1.0 + BLINK_V_BRI_BAND) * run_bri
            };
            let pre = ratios[..start].iter().rev().any(|o| {
                first_idx - o.idx <= BLINK_V_PRE_WIN
                    && o.ratio >= BLINK_V_OPEN_RATIO
                    && bri_ok(o.bri)
            });
            let post = ratios[end + 1..].iter().any(|o| {
                o.idx - last_idx <= BLINK_V_POST_WIN
                    && o.ratio >= BLINK_V_OPEN_RATIO
                    && bri_ok(o.bri)
            });
            if pre && post {
                return BlinkResult::Blinked;
            }
        }
        start = end + 1;
    }
    BlinkResult::NoBlink
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fb(cx: f32, cy: f32) -> FaceBox {
        FaceBox { cx, cy, score: 0.9 }
    }

    fn live_signals() -> Signals {
        Signals {
            rgb_face: Some(fb(0.5, 0.5)),
            ir_face: Some(fb(0.52, 0.49)),
            ir_face_brightness: 90.0,
            ir_center_edge_ratio: 1.2,
            ir_eye_glint: 220.0,
            ..Default::default() // frontal pose
        }
    }

    #[test]
    fn live_face_passes() {
        assert_eq!(
            LivenessGate::new().evaluate(&live_signals()).0,
            Verdict::Live
        );
    }

    #[test]
    fn off_angle_face_is_uncertain() {
        // A real, co-located, IR-lit 3D face that is turned away -> Uncertain
        // (positioning), never Spoof or Live.
        let mut yaw = live_signals();
        yaw.head_yaw_asym = 0.5; // turned
        assert_eq!(LivenessGate::new().evaluate(&yaw).0, Verdict::Uncertain);
        let mut down = live_signals();
        down.head_pitch_frac = 0.15; // chin down
        assert_eq!(LivenessGate::new().evaluate(&down).0, Verdict::Uncertain);
    }

    #[test]
    fn flat_ir_is_spoof() {
        let mut s = live_signals();
        s.ir_center_edge_ratio = 1.0; // uniform => flat
        assert_eq!(LivenessGate::new().evaluate(&s).0, Verdict::Spoof);
    }

    #[test]
    fn screen_with_no_ir_face_is_spoof() {
        let s = Signals {
            rgb_face: Some(fb(0.5, 0.5)),
            ir_face: None,
            ir_face_brightness: 5.0,
            ..Default::default()
        };
        assert_eq!(LivenessGate::new().evaluate(&s).0, Verdict::Spoof);
    }

    #[test]
    fn dark_ir_face_is_spoof() {
        let s = Signals {
            rgb_face: Some(fb(0.5, 0.5)),
            ir_face: Some(fb(0.5, 0.5)),
            ir_face_brightness: 12.0,
            ..Default::default()
        };
        assert_eq!(LivenessGate::new().evaluate(&s).0, Verdict::Spoof);
    }

    #[test]
    fn no_subject_is_uncertain() {
        let s = Signals::default();
        assert_eq!(LivenessGate::new().evaluate(&s).0, Verdict::Uncertain);
    }

    /// Uniform lighting (no strobe): every frame same brightness, all with a face.
    fn flat(ears: &[f32]) -> Vec<EarSample> {
        ears.iter()
            .enumerate()
            .map(|(i, &e)| EarSample {
                idx: i,
                ear: Some(e),
                bri: 60.0,
            })
            .collect()
    }

    /// Emitter strobe: even frames lit (bri 60) with `lit` EARs, odd frames
    /// ambient-only (bri 9) with `dark` EARs (None = face not detected).
    fn strobed(lit: &[f32], dark: &[Option<f32>]) -> Vec<EarSample> {
        let mut out = Vec::new();
        for i in 0..lit.len().max(dark.len()) {
            if i < lit.len() {
                out.push(EarSample {
                    idx: 2 * i,
                    ear: Some(lit[i]),
                    bri: 60.0,
                });
            }
            if i < dark.len() {
                out.push(EarSample {
                    idx: 2 * i + 1,
                    ear: dark[i],
                    bri: 9.0,
                });
            }
        }
        out
    }

    #[test]
    fn deep_natural_blink_is_detected() {
        // Night-validation shape: open ≈0.24, blink to ≈0.15 (0.63× → deep rule).
        let seq = flat(&[0.24, 0.24, 0.23, 0.15, 0.16, 0.24, 0.24, 0.23, 0.24]);
        assert_eq!(detect_blink(&seq), BlinkResult::Blinked);
    }

    #[test]
    fn shallow_single_frame_v_is_detected() {
        // Real kitchen trace 2026-07-01 (the old depth rule MISSED this): lit-class
        // blink sampled mid-closure, one frame at 0.173 (0.82× the lit median 0.212),
        // sharp drop from 0.212 and recovery to 0.205. Ambient-class frames read
        // systematically lower (~0.185) and must not drag the baseline down.
        let lit = [
            0.209, 0.224, 0.257, 0.240, 0.236, 0.204, 0.208, 0.212, 0.173, 0.205, 0.226, 0.206,
        ];
        let dark: Vec<Option<f32>> = [
            0.192, 0.191, 0.180, 0.184, 0.189, 0.193, 0.194, 0.189, 0.181, 0.175, 0.184, 0.185,
        ]
        .iter()
        .map(|&e| Some(e))
        .collect();
        assert_eq!(detect_blink(&strobed(&lit, &dark)), BlinkResult::Blinked);
    }

    #[test]
    fn dark_room_two_sample_v_is_detected() {
        // Real dark-living-room trace 2026-07-01: ambient frames have NO face (only
        // the emitter lights you), blink = two lit samples 0.129/0.142 (0.73×/0.81×
        // of the 0.176 lit median) with clean pre/post open samples.
        let lit = [
            0.176, 0.185, 0.176, 0.129, 0.142, 0.174, 0.174, 0.188, 0.180, 0.176,
        ];
        let dark = vec![None; 10];
        assert_eq!(detect_blink(&strobed(&lit, &dark)), BlinkResult::Blinked);
    }

    #[test]
    fn static_banner_flat_ear_is_not_a_blink() {
        // Real banner trace: flat 0.21–0.24, min 0.206 (≈0.91× median) — too shallow
        // for a run sample, no V, no deep dip.
        let banner = flat(&[
            0.221, 0.236, 0.227, 0.229, 0.206, 0.232, 0.226, 0.224, 0.223,
        ]);
        assert_eq!(detect_blink(&banner), BlinkResult::NoBlink);
    }

    #[test]
    fn slow_drift_is_not_a_blink() {
        // Slow U-drift (gaze shift / AE settling, ~1s down and back): the bottom
        // sample only reaches 0.87× of median — a lone sample must reach the
        // single-frame depth (0.82×) to count, so no blink.
        let seq = flat(&[
            0.240, 0.236, 0.230, 0.224, 0.216, 0.208, 0.200, 0.193, 0.187, 0.193, 0.200, 0.208,
            0.216, 0.224, 0.230, 0.236,
        ]);
        assert_eq!(detect_blink(&seq), BlinkResult::NoBlink);
    }

    #[test]
    fn long_depression_is_not_a_blink() {
        // Real AE-settle trace (dark room 2026-07-01): EAR depressed for ~7
        // consecutive samples while exposure stabilises — longer than any real
        // blink; the run-length cap rejects it even though it is deep.
        let lit = [
            0.190, 0.168, 0.182, 0.159, 0.155, 0.159, 0.154, 0.158, 0.144, 0.137, 0.164, 0.185,
            0.189, 0.201, 0.200, 0.201, 0.203, 0.205, 0.194, 0.195,
        ];
        let dark = vec![None; 20];
        assert_eq!(detect_blink(&strobed(&lit, &dark)), BlinkResult::NoBlink);
    }

    #[test]
    fn tiny_window_is_no_eyes() {
        // Real closet trace 2026-07-01: the stream froze after 5 face frames whose
        // EAR dipped in sync with auto-exposure slewing (bri 182→57) — previously
        // scored Live. Too few samples to trust: NoEyes.
        let mut seq: Vec<EarSample> = [
            (0usize, 0.236f32, 182.4f32),
            (2, 0.226, 202.8),
            (4, 0.177, 145.6),
            (6, 0.181, 126.4),
            (8, 0.217, 57.0),
        ]
        .iter()
        .map(|&(idx, e, b)| EarSample {
            idx,
            ear: Some(e),
            bri: b,
        })
        .collect();
        for i in 5..30 {
            seq.push(EarSample {
                idx: 2 * i,
                ear: None,
                bri: 144.0,
            });
        }
        assert_eq!(detect_blink(&seq), BlinkResult::NoEyes);
    }

    #[test]
    fn exposure_slew_dip_is_not_a_blink() {
        // EAR sags while auto-exposure is still slewing (brightness falling 200→90):
        // the dip's only near-open neighbours sit at a very different exposure, so
        // the brightness-band check refuses to treat it as a V.
        let seq: Vec<EarSample> = [
            (0usize, 0.230f32, 210.0f32),
            (1, 0.231, 200.0),
            (2, 0.229, 185.0),
            (3, 0.185, 150.0),
            (4, 0.188, 132.0),
            (5, 0.219, 96.0),
            (6, 0.221, 92.0),
            (7, 0.222, 91.0),
            (8, 0.222, 90.0),
            (9, 0.221, 90.0),
            (10, 0.222, 90.0),
            (11, 0.221, 90.0),
        ]
        .iter()
        .map(|&(idx, e, b)| EarSample {
            idx,
            ear: Some(e),
            bri: b,
        })
        .collect();
        assert_eq!(detect_blink(&seq), BlinkResult::NoBlink);
    }

    #[test]
    fn no_plausible_open_eye_reads_no_eyes() {
        // Median below the open floor (mesh failing / non-eye) → NoEyes, not a blink.
        assert_eq!(
            detect_blink(&flat(&[0.05, 0.06, 0.04, 0.05, 0.05])),
            BlinkResult::NoEyes
        );
        assert_eq!(detect_blink(&[]), BlinkResult::NoEyes);
        // Dark closet: frames captured but no face anywhere → NoEyes.
        let none = strobed(&[], &[None; 20]);
        assert_eq!(detect_blink(&none), BlinkResult::NoEyes);
    }
}

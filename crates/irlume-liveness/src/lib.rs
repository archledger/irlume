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
            head_yaw_asym: 0.0,    // frontal
            head_pitch_frac: 0.5,  // frontal
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
/// entirely. 18 never false-rejects an observed real face (max 13) and catches
/// close-range replays (~23–38); marginal/distant screens slip. This is NOT a
/// robust PAD — the real mitigation for RGB-only is the convenience-tier policy
/// (lock-screen unlock only, never credential release). Re-tune per camera.
pub const RGB_MOIRE_MAX: f32 = 18.0;

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
            return (Verdict::Uncertain, cues, "no face in RGB — present your face".into());
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
            return (Verdict::Uncertain, cues, format!("RGB/IR face mismatch (dist {dist:.2}) — re-center"));
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
                format!("IR face too dark ({:.0}) — not reflecting IR like skin", s.ir_face_brightness),
            );
        }

        // Anti-flat: a real 3D face shows center-vs-edge IR falloff.
        cues.depth_ok = s.ir_center_edge_ratio >= DEPTH_MIN_RATIO;
        if !cues.depth_ok {
            return (
                Verdict::Spoof,
                cues,
                format!("IR too flat (center/edge {:.2}) — looks 2D, not a 3D face", s.ir_center_edge_ratio),
            );
        }

        // Corneal glint — supporting only; logged, never decisive on its own.
        cues.glint_present = s.ir_eye_glint >= GLINT_MIN;

        (Verdict::Live, cues, "live: face in RGB+IR, co-located, frontal, IR-reflective, 3D".into())
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
            return (Verdict::Uncertain, cues, "no face — present your face to the camera".into());
        };
        cues.face_in_rgb = true;
        cues.frontal_ok = s.head_yaw_asym <= YAW_ASYM_MAX
            && (PITCH_FRAC_MIN..=PITCH_FRAC_MAX).contains(&s.head_pitch_frac);
        if !cues.frontal_ok {
            return (Verdict::Uncertain, cues, "not facing the camera — look directly at it".into());
        }
        if s.rgb_face_brightness < RGB_FACE_MIN_BRIGHTNESS {
            return (Verdict::Uncertain, cues,
                "too dark — add light on your face (RGB-only mode needs a lit face)".into());
        }
        if s.rgb_face_brightness > RGB_FACE_MAX_BRIGHTNESS {
            return (Verdict::Uncertain, cues, "overexposed — reduce the light/backlight".into());
        }
        if s.rgb_specular_frac > RGB_SPECULAR_MAX {
            return (Verdict::Spoof, cues,
                "screen/glare detected (blown-out highlights) — RGB-only anti-spoof".into());
        }
        if s.rgb_moire_score > RGB_MOIRE_MAX {
            return (Verdict::Spoof, cues,
                format!("screen pixel-grid/moiré pattern detected (peakiness {:.0}) — RGB-only anti-spoof", s.rgb_moire_score));
        }
        (Verdict::Live, cues,
            format!("live (rgb convenience; bright {:.0} specular {:.2} moire {:.0})",
                s.rgb_face_brightness, s.rgb_specular_frac, s.rgb_moire_score))
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
            return (Verdict::Spoof, cues, format!("IR face too dark ({:.0})", s.ir_face_brightness));
        }
        cues.depth_ok = s.ir_center_edge_ratio >= DEPTH_MIN_RATIO;
        if !cues.depth_ok {
            return (Verdict::Spoof, cues, format!("IR too flat (center/edge {:.2})", s.ir_center_edge_ratio));
        }
        cues.glint_present = s.ir_eye_glint >= GLINT_MIN;
        (Verdict::Live, cues, "live (dark/IR-only): IR-reflective, 3D".into())
    }
}

// --- Blink challenge (opt-in temporal liveness, ADR-0002) -------------------
//
// Defeats the demonstrated static IR-reflective print attack (a life-size glossy
// vinyl banner passed the single-frame gate at 98.6% APCER, 2026-06-30): a static
// print cannot blink. Given a sequence of per-frame eye SPECULAR-CONTRAST samples
// (`irlume_auth::eye_glint_contrast`, in capture order), we look for an eyes
// open→closed→open transition with a SUSTAINED closure.
//
// Why specular contrast, not raw glint: live-validated 2026-06-30, a closed lid
// still reflects 850nm, so peak glint barely drops on a blink and is lost in noise;
// but the corneal specular SPIKE (peak-above-surround) collapses on closure. A
// static/printed eye is diffuse — its contrast is low (banner ≈70) and never
// reaches a real open eye's (≈120), and being static it can never produce the
// transition. Two independent guards therefore reject a print: it fails the
// absolute open-eye floor, AND it can't sustain a closed dip. Requiring the closure
// to persist for several consecutive samples rejects single-frame noise.

/// A sample is "closed" when its contrast falls to/below this fraction of the peak.
pub const BLINK_CLOSE_RATIO: f32 = 0.70;
/// A sample is "open" when its contrast is at/above this fraction of the peak.
pub const BLINK_REOPEN_RATIO: f32 = 0.82;
/// Peak eye contrast must reach at least this to trust a real corneal specular was
/// seen — a static/printed eye stays diffuse and low (banner ≈70) and fails here.
/// Set below the genuine open-eye level (≈120) with margin. Tune from real traces.
pub const BLINK_MIN_OPEN_CONTRAST: f32 = 90.0;
/// The closure must persist for at least this many consecutive samples (a
/// deliberate held blink), so single-sample noise dips don't count. At the ~15 fps
/// IR rate (de-strobed ≈133 ms/sample) this is ≈0.4 s.
pub const BLINK_MIN_CLOSED_RUN: usize = 3;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BlinkResult {
    /// A sustained eyes open→closed→open transition was observed (live).
    Blinked,
    /// A confident open eye was seen but no sustained blink (a static artefact — or
    /// the user didn't blink in the window; caller re-prompts / falls back).
    NoBlink,
    /// No confident open eye anywhere in the window (a diffuse/printed eye, or a
    /// poor capture): peak contrast never reached the open-eye floor.
    NoEyes,
}

/// Detect a sustained blink (eyes open→closed→open) in a per-frame eye-contrast
/// sequence. See the module comment for the rationale and why it defeats static
/// prints (absolute open-eye floor + a closure a static image cannot produce).
pub fn detect_blink(contrasts: &[f32]) -> BlinkResult {
    let peak = contrasts.iter().copied().fold(0.0f32, f32::max);
    if peak < BLINK_MIN_OPEN_CONTRAST {
        return BlinkResult::NoEyes;
    }
    let open_th = BLINK_REOPEN_RATIO * peak;
    let close_th = BLINK_CLOSE_RATIO * peak;
    // 0 = need first open · 1 = counting a consecutive closed run · 2 = need reopen.
    let mut phase = 0u8;
    let mut run = 0usize;
    for &c in contrasts {
        match phase {
            0 => {
                if c >= open_th {
                    phase = 1;
                }
            }
            1 => {
                if c <= close_th {
                    run += 1;
                    if run >= BLINK_MIN_CLOSED_RUN {
                        phase = 2;
                    }
                } else {
                    run = 0; // any non-closed sample breaks the consecutive run
                }
            }
            2 => {
                if c >= open_th {
                    return BlinkResult::Blinked;
                }
            }
            _ => {}
        }
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
        assert_eq!(LivenessGate::new().evaluate(&live_signals()).0, Verdict::Live);
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
        let s = Signals { rgb_face: Some(fb(0.5, 0.5)), ir_face: None, ir_face_brightness: 5.0, ..Default::default() };
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

    #[test]
    fn genuine_held_blink_is_detected() {
        // Contrast scale (real trace): open ≈120 → sustained closed ≈75 (≥3
        // samples) → reopen ≈110.
        let seq = [120.0, 124.0, 75.0, 73.0, 74.0, 76.0, 110.0, 112.0];
        assert_eq!(detect_blink(&seq), BlinkResult::Blinked);
    }

    #[test]
    fn static_banner_reads_no_eyes() {
        // A static/printed eye is diffuse: contrast flat and low (real banner
        // trace ≈55–70), never reaching the open-eye floor.
        assert_eq!(detect_blink(&[63.0, 63.0, 61.0, 57.0, 64.0, 70.0, 58.0]), BlinkResult::NoEyes);
    }

    #[test]
    fn steady_open_eye_is_not_a_blink() {
        // A real open eye held steady (no closure) — high contrast, no dip.
        assert_eq!(detect_blink(&[120.0, 124.0, 122.0, 121.0, 123.0]), BlinkResult::NoBlink);
    }

    #[test]
    fn single_sample_dip_is_noise_not_a_blink() {
        // One isolated low sample (< the sustained run) must not count as a blink.
        assert_eq!(detect_blink(&[120.0, 124.0, 70.0, 122.0, 124.0]), BlinkResult::NoBlink);
    }

    #[test]
    fn close_without_reopen_is_not_a_blink() {
        // Sustained closure but the window ends before the eyes reopen.
        assert_eq!(detect_blink(&[120.0, 124.0, 75.0, 73.0, 74.0, 76.0]), BlinkResult::NoBlink);
    }

    #[test]
    fn empty_reads_no_eyes() {
        assert_eq!(detect_blink(&[]), BlinkResult::NoEyes);
    }
}

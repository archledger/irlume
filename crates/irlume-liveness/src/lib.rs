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
#[derive(Debug, Clone, Default)]
pub struct Signals {
    /// Top face in the RGB frame, if any.
    pub rgb_face: Option<FaceBox>,
    /// Top face in the IR frame, if any (a screen/print won't reflect 850nm IR
    /// like skin, so it usually yields no IR face).
    pub ir_face: Option<FaceBox>,
    /// Mean brightness (0..255) inside the IR face region — skin reflects the
    /// active emitter strongly; a screen/print does not.
    pub ir_face_brightness: f32,
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
}

/// IR face region must be at least this bright (0..255). A lit live face ran ~83
/// mean overall on the Shinetech module; the face region is brighter still. A
/// screen reflects far less 850nm.
pub const IR_FACE_MIN_BRIGHTNESS: f32 = 35.0;
/// Max normalized center distance between the RGB and IR face.
pub const CROSS_SPECTRUM_TOLERANCE: f32 = 0.30;
/// Minimum detector score to trust a face.
pub const MIN_FACE_SCORE: f32 = 0.6;

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

        // IR skin reflectance: the face region must be brightly lit.
        cues.ir_reflectance_ok = s.ir_face_brightness >= IR_FACE_MIN_BRIGHTNESS;
        if !cues.ir_reflectance_ok {
            return (
                Verdict::Spoof,
                cues,
                format!("IR face too dark ({:.0}) — not reflecting IR like skin", s.ir_face_brightness),
            );
        }

        (Verdict::Live, cues, "live: face in RGB+IR, co-located, IR-reflective".into())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fb(cx: f32, cy: f32) -> FaceBox {
        FaceBox { cx, cy, score: 0.9 }
    }

    #[test]
    fn live_face_passes() {
        let s = Signals {
            rgb_face: Some(fb(0.5, 0.5)),
            ir_face: Some(fb(0.52, 0.49)),
            ir_face_brightness: 90.0,
        };
        assert_eq!(LivenessGate::new().evaluate(&s).0, Verdict::Live);
    }

    #[test]
    fn screen_with_no_ir_face_is_spoof() {
        let s = Signals { rgb_face: Some(fb(0.5, 0.5)), ir_face: None, ir_face_brightness: 5.0 };
        assert_eq!(LivenessGate::new().evaluate(&s).0, Verdict::Spoof);
    }

    #[test]
    fn dark_ir_face_is_spoof() {
        let s = Signals {
            rgb_face: Some(fb(0.5, 0.5)),
            ir_face: Some(fb(0.5, 0.5)),
            ir_face_brightness: 12.0,
        };
        assert_eq!(LivenessGate::new().evaluate(&s).0, Verdict::Spoof);
    }

    #[test]
    fn no_subject_is_uncertain() {
        let s = Signals::default();
        assert_eq!(LivenessGate::new().evaluate(&s).0, Verdict::Uncertain);
    }
}

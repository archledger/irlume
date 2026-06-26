//! Algorithmic IR presentation-attack detection (PAD) — NO trained weights.
//!
//! Why no model: every public anti-spoof dataset (CelebA-Spoof, CASIA-SURF,
//! OULU-NPU, SiW, even synthetic SynthASpoof) is non-commercial, so any trained
//! PAD model is license-tainted. We instead gate on documented physics, which is
//! both license-clean and (for the NIR skin test) demographically fair by design.
//!
//! Gate is HARD: any failing cue rejects (no weighted fusion). Honest caveat —
//! a pure hand-crafted gate is unproven at certification-grade error rates, so
//! every cue must be self-tested against ISO/IEC 30107-3 attacks; a self-trained
//! model on OWN IR-rig data is the fallback if cues can't reach iBeta Level 2.

use irlume_camera::Frame;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Verdict {
    Live,
    Spoof,
    Uncertain,
}

/// Per-cue evidence, surfaced for logging/self-test (never raw image data).
#[derive(Debug, Default, Clone)]
pub struct Cues {
    /// NIR skin reflectance test. Above ~1.2um, skin remission is melanin-
    /// independent (water-driven) => a simple threshold separates live skin
    /// from paper/screen/latex, fairly across skin tones.
    pub nir_skin: Option<bool>,
    /// Bright-pupil retro-reflection (~90% @850nm, coaxial emitter). Absent in
    /// prints/replays. Strong single-frame cue.
    pub bright_pupil: Option<bool>,
    /// Cross-spectrum RGB<->IR spatial overlap: the face must align in BOTH
    /// streams. Defeats "real IR + fake RGB" injection (CVE-2021-34466).
    pub cross_spectrum_overlap: Option<bool>,
    /// Active IR-strobe response: emitter on/off must change the scene as a
    /// real reflective surface would.
    pub strobe_response: Option<bool>,
    /// Corneal specular glint — SUPPORTING ONLY (standalone-glint liveness was
    /// refuted in research). Never decisive on its own.
    pub corneal_glint: Option<bool>,
}

/// The hard liveness gate.
pub struct LivenessGate { /* TODO: per-user calibration envelope, thresholds */ }

impl LivenessGate {
    pub fn new() -> Self {
        Self {}
    }

    /// Evaluate live-ness from paired captures. `rgb`/`ir` are the same instant.
    pub fn evaluate(&self, _rgb: &Frame, _ir: &Frame) -> (Verdict, Cues) {
        // TODO: compute each cue; reject on ANY hard failure; glint supporting.
        todo!()
    }
}

impl Default for LivenessGate {
    fn default() -> Self {
        Self::new()
    }
}

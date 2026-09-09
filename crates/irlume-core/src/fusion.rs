// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright the irlume contributors.

//! Stage-2 brightness-weighted RGB+IR score fusion.
//!
//! Fixed sigmoid mappings turn each modality's cosine into a score in `[0, 1]`.
//! The caller weights these scores by capture brightness and takes an arithmetic
//! mean. The legacy `prob` names do not establish calibrated genuine probabilities
//! for the current pipeline, a joint posterior, or a false-match-rate bound.
//!
//! Historical comments attribute the RGB coefficients to LFW and the IR
//! coefficients to CBSR+Oulu in the former v3 IR-adapter space. The fitting script
//! and a reproducible fit report are not present in this repository. ADR-0004
//! retired that shipped adapter; current raw/per-enrollment-calibrated IR scores
//! have a different provenance. Retaining these constants does not validate them
//! for that path or for a user-supplied adapter.
//!
//! Fusion can accept scores below the standalone identity thresholds. It expands
//! the acceptance rule even though those thresholds are unchanged. Assessing its
//! false-match rate requires evaluating the full rule, including template/profile
//! selection and other acceptance arms; neither modality independence nor an
//! overall error bound follows from this arithmetic. The caller separately
//! enforces liveness/PAD and disallows fusion grants for sequential pairs.

/// Legacy RGB sigmoid coefficient, historically attributed to an offline LFW fit.
pub const RGB_PLATT_A: f32 = 24.4708;
pub const RGB_PLATT_B: f32 = -8.1873;
/// Legacy IR sigmoid coefficient from the retired adapter space.
/// Its calibration for the current raw/per-enrollment path is unverified.
pub const IR_PLATT_A: f32 = 40.0120;
pub const IR_PLATT_B: f32 = -16.2221;

/// Minimum weighted score for the fusion arm, not a measured false-match bound.
pub const FUSION_PROB_THRESHOLD: f32 = 0.50;

/// Per-modality sigmoid-score floor. This is not a standalone identity threshold
/// or proof that both modalities independently verified the claimed identity.
pub const FUSION_MIN_PER_MODALITY_PROB: f32 = 0.10;

#[inline]
pub fn sigmoid(x: f32) -> f32 {
    1.0 / (1.0 + (-x).exp())
}

/// Legacy sigmoid score for an RGB cosine; current probability calibration is unverified.
pub fn rgb_genuine_prob(cos: f32) -> f32 {
    sigmoid(RGB_PLATT_A * cos + RGB_PLATT_B)
}
/// Legacy sigmoid score for an IR cosine; see the module-level calibration limits.
pub fn ir_genuine_prob(cos: f32) -> f32 {
    sigmoid(IR_PLATT_A * cos + IR_PLATT_B)
}

/// Quality-ramp knees, mean face luma on the 0-255 scale; knee values from the
/// real-ASUS calibration capture campaign.
const RGB_QUALITY_LO: f32 = 60.0;
const RGB_QUALITY_HI: f32 = 130.0;
const IR_QUALITY_LO: f32 = 35.0;
const IR_QUALITY_HI: f32 = 110.0;
/// Weight at or below the low knee; keeps a captured modality contributing a
/// little even at poor quality (never a hard 0 unless absent).
const QUALITY_FLOOR: f32 = 0.2;

/// A linear quality ramp on `[lo, hi]` mapped to `[QUALITY_FLOOR, 1.0]`.
fn ramp(x: f32, lo: f32, hi: f32, floor: f32) -> f32 {
    let t = ((x - lo) / (hi - lo)).clamp(0.0, 1.0);
    floor + (1.0 - floor) * t
}

/// RGB capture-quality weight from mean face brightness. Bright → 1.0, dim → 0.2.
pub fn rgb_quality_weight(face_brightness: f32) -> f32 {
    ramp(
        face_brightness,
        RGB_QUALITY_LO,
        RGB_QUALITY_HI,
        QUALITY_FLOOR,
    )
}
/// IR capture-quality weight from IR face brightness. 0.0 if no IR face was captured.
pub fn ir_quality_weight(ir_present: bool, ir_brightness: f32) -> f32 {
    if !ir_present {
        return 0.0;
    }
    ramp(ir_brightness, IR_QUALITY_LO, IR_QUALITY_HI, QUALITY_FLOOR)
}

/// Outcome of a fusion attempt.
#[derive(Debug, Clone, Copy)]
pub struct Fusion {
    /// Brightness-weighted score; the legacy field name does not imply calibration.
    pub prob: f32,
    pub p_rgb: f32,
    pub p_ir: f32,
    /// True iff the weighted score and both floors pass with positive IR weight.
    pub grant: bool,
}

/// Brightness-weighted arithmetic mean of the supplied sigmoid scores. Grants only
/// if the score clears [`FUSION_PROB_THRESHOLD`], each modality clears
/// [`FUSION_MIN_PER_MODALITY_PROB`], and `w_ir > 0`. The caller is responsible for
/// mapping absent IR to zero weight and enforcing capture/liveness policy.
pub fn fuse(p_rgb: f32, w_rgb: f32, p_ir: f32, w_ir: f32) -> Fusion {
    let wsum = (w_rgb + w_ir).max(1e-6);
    let prob = (w_rgb * p_rgb + w_ir * p_ir) / wsum;
    let grant = prob >= FUSION_PROB_THRESHOLD
        && p_rgb >= FUSION_MIN_PER_MODALITY_PROB
        && p_ir >= FUSION_MIN_PER_MODALITY_PROB
        && w_ir > 0.0;
    Fusion {
        prob,
        p_rgb,
        p_ir,
        grant,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn platt_is_monotonic_and_bounded() {
        assert!(rgb_genuine_prob(0.9) > rgb_genuine_prob(0.3));
        assert!(ir_genuine_prob(0.9) > ir_genuine_prob(0.3));
        for p in [
            rgb_genuine_prob(1.0),
            ir_genuine_prob(1.0),
            rgb_genuine_prob(-1.0),
        ] {
            assert!((0.0..=1.0).contains(&p));
        }
        // Synthetic high-cosine examples approach the top of the sigmoid.
        assert!(rgb_genuine_prob(0.80) > 0.99);
        assert!(ir_genuine_prob(0.75) > 0.99);
    }

    #[test]
    fn genuine_both_modalities_grants() {
        // Synthetic high-score pair with high brightness weights.
        let f = fuse(
            rgb_genuine_prob(0.78),
            rgb_quality_weight(120.0),
            ir_genuine_prob(0.72),
            ir_quality_weight(true, 100.0),
        );
        assert!(f.grant, "genuine multimodal should grant: {f:?}");
    }

    #[test]
    fn genuine_dim_light_ir_rescues() {
        // Synthetic low-brightness RGB and high-score IR exercise weighting.
        let f = fuse(
            rgb_genuine_prob(0.42),
            rgb_quality_weight(55.0),
            ir_genuine_prob(0.70),
            ir_quality_weight(true, 95.0),
        );
        assert!(f.grant, "dim-light genuine should be rescued by IR: {f:?}");
    }

    #[test]
    fn impostor_both_marginal_rejected() {
        // A synthetic low-score pair must not pass the configured fusion gate.
        let f = fuse(
            rgb_genuine_prob(0.29),
            rgb_quality_weight(120.0),
            ir_genuine_prob(0.28),
            ir_quality_weight(true, 100.0),
        );
        assert!(!f.grant, "impostor pair must be rejected: {f:?}");
    }

    #[test]
    fn one_strong_one_noise_rejected() {
        // Synthetic high RGB and zero IR cosine: the IR score floor blocks fusion.
        let f = fuse(
            rgb_genuine_prob(0.85),
            rgb_quality_weight(120.0),
            ir_genuine_prob(0.0),
            ir_quality_weight(true, 100.0),
        );
        assert!(
            !f.grant,
            "single-modality + noise must not grant via fusion: {f:?}"
        );
    }

    #[test]
    fn no_ir_capture_no_fusion() {
        let f = fuse(
            rgb_genuine_prob(0.50),
            rgb_quality_weight(120.0),
            ir_genuine_prob(0.0),
            ir_quality_weight(false, 0.0),
        );
        assert!(!f.grant, "fusion requires a real IR capture: {f:?}");
    }
}

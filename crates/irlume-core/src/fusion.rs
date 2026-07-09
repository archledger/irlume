//! Stage-2 lighting-adaptive RGB+IR score fusion.
//!
//! Each modality's cosine is mapped to a *calibrated* genuine-probability (Platt
//! scaling), weighted by capture quality, then fused. This lets a marginal-RGB +
//! marginal-IR capture JOINTLY grant in mixed light, while keeping the false-match
//! rate bounded, because an impostor must fool BOTH modalities at once (the two
//! score distributions are near-independent). Fusion only ADDS dim-light rescues on
//! top of the existing single-modality thresholds; it never relaxes them.
//!
//! Constants fit offline (scripts/calibrate.py): RGB Platt on LFW genuine/impostor
//! cosines; IR Platt on CBSR+Oulu NIR run through the DEPLOYED v3 residZero adapter.
//! Re-fit when the recognizer or IR adapter changes, and ideally refine on real captures.

/// RGB Platt: `p = sigmoid(a*cos + b)`. Fit on LFW (genuine cos μ0.565 / impostor μ0.062).
pub const RGB_PLATT_A: f32 = 24.4708;
pub const RGB_PLATT_B: f32 = -8.1873;
/// IR Platt (adapted-IR space). Fit on CBSR+Oulu via v3 residZero adapter (genuine μ0.783 / impostor μ0.033).
pub const IR_PLATT_A: f32 = 40.0120;
pub const IR_PLATT_B: f32 = -16.2221;

/// Fused genuine-probability required to grant via fusion. CONSERVATIVE: the
/// equal-weight independence model puts fused FAR≤1e-4 at ~0.31; 0.50 adds margin
/// and is trivially cleared by a true user (deployment fused-prob ≈1.0). Raising
/// this only tightens security.
pub const FUSION_PROB_THRESHOLD: f32 = 0.50;

/// Each modality must independently clear this genuine-probability for fusion to
/// fire; blocks "one strong modality + pure noise" from granting (anti
/// single-modality-spoof). Set just above chance.
pub const FUSION_MIN_PER_MODALITY_PROB: f32 = 0.10;

#[inline]
pub fn sigmoid(x: f32) -> f32 {
    1.0 / (1.0 + (-x).exp())
}

/// Calibrated genuine-probability for an RGB cosine.
pub fn rgb_genuine_prob(cos: f32) -> f32 {
    sigmoid(RGB_PLATT_A * cos + RGB_PLATT_B)
}
/// Calibrated genuine-probability for an (adapted) IR cosine.
pub fn ir_genuine_prob(cos: f32) -> f32 {
    sigmoid(IR_PLATT_A * cos + IR_PLATT_B)
}

/// A linear quality ramp on `[lo, hi]` mapped to `[floor, 1.0]`. `floor` keeps a
/// modality contributing a little even at poor quality (never a hard 0 unless absent).
fn ramp(x: f32, lo: f32, hi: f32, floor: f32) -> f32 {
    let t = ((x - lo) / (hi - lo)).clamp(0.0, 1.0);
    floor + (1.0 - floor) * t
}

/// RGB capture-quality weight from mean face brightness. Bright → 1.0, dim → 0.2.
pub fn rgb_quality_weight(face_brightness: f32) -> f32 {
    ramp(face_brightness, 60.0, 130.0, 0.2)
}
/// IR capture-quality weight from IR face brightness. 0.0 if no IR face was captured.
pub fn ir_quality_weight(ir_present: bool, ir_brightness: f32) -> f32 {
    if !ir_present {
        return 0.0;
    }
    ramp(ir_brightness, 35.0, 110.0, 0.2)
}

/// Outcome of a fusion attempt.
#[derive(Debug, Clone, Copy)]
pub struct Fusion {
    /// Quality-weighted fused genuine-probability.
    pub prob: f32,
    pub p_rgb: f32,
    pub p_ir: f32,
    /// True iff the fused probability clears the bar AND each modality shows floor evidence.
    pub grant: bool,
}

/// Quality-weighted fusion of the two calibrated genuine-probabilities. Grants only
/// if the fused probability clears [`FUSION_PROB_THRESHOLD`], each modality clears
/// [`FUSION_MIN_PER_MODALITY_PROB`], and a real IR capture was present (`w_ir > 0`).
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
        // Deployment genuine cosines map to near-certain.
        assert!(rgb_genuine_prob(0.80) > 0.99);
        assert!(ir_genuine_prob(0.75) > 0.99);
    }

    #[test]
    fn genuine_both_modalities_grants() {
        // True user, good light: both strong.
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
        // Dim RGB (marginal) + good IR -> fusion rescues.
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
        // Impostor near each modality's FAR-1e-3 cosine: must NOT grant.
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
        // Strong RGB but IR is pure noise (cos ~0) -> per-modality floor blocks fusion.
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

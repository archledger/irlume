//! Matching, template storage, and TPM-bound secret release.
//!
//! Decision rule (NIST SP 800-63B-4 aligned): grant only if the liveness gate
//! says Live AND the best cosine >= a FIXED threshold (0.55). That threshold
//! clears FMR <= 1e-4 per demographic group on FairFace, but unconstrained
//! real-world FAR is higher (2.0e-3 @ 0.55 on LFW); the mandatory password
//! fallback bounds the residual. See the `RGB` threshold constant below for the
//! measured numbers. Threshold is NOT ported from linhello (0.60): AuraFace's
//! score scale differs; derive it from a genuine/impostor ROC on real data.
//!
//! Storage: never store a raw recoverable face image. Store L2-normalized
//! embeddings (zeroized after use). The unlock SECRET (e.g. the login password
//! or a random release token) is SEALED IN THE TPM, gated by PCR policy, and
//! released only on a successful live+match, not the template itself.

pub mod biopolicy;
pub mod calib;
pub mod crypto;
pub mod envelope;
pub mod fusion;
pub mod keyring;
pub mod pad;
pub mod pcrsig;
pub mod policy;
pub mod recovery;
pub mod storage;
pub mod template_key;
pub mod tpm;
pub mod tpm_pcrlock;

/// RGB (visible-light) match threshold. Measured FAR: real faces (LFW, 13,233
/// images, 87M impostor pairs, same pipeline as production) give FAR 2.3e-3 @
/// 0.50 and 2.0e-3 @ 0.55; synthetic (SFHQ, 112M pairs) 9.8e-5 @ 0.50 (cleaner
/// than unconstrained real photos). **Set to 0.55** for demographic headroom:
/// FairFace per-group analysis showed 0.50 only clears FMR≤1e-4 for the best
/// group; ~0.55+ tightens every group (see docs/FAIRNESS.md), and because live
/// genuine sits at min 0.71 / mean 0.85, so 0.55 keeps a wide accept margin (no
/// added false-rejects). Unconstrained real-world FAR stays well above Windows
/// Hello's stated 1e-5 bar; the mandatory password fallback bounds the residual.
/// Do NOT assume buffalo_l's 0.60; AuraFace scale differs.
pub const RGB_MATCH_THRESHOLD: f32 = 0.55;

/// IR-mode (dark) match threshold, HIGHER than RGB because AuraFace-on-IR is
/// less discriminative. Benchmarked on the FULL CBSR NIR dataset (real 850nm,
/// 197 people, 3940 faces, 7.72M impostor pairs): genuine mean 0.855, impostor
/// MAX 0.900 (genuine/impostor OVERLAP), EER ≈0.8% @0.495. FAR/FRR: 0.55→
/// 1.3e-3/1.7%, 0.60→2.7e-4/3.0%, NIST FAR≤1e-4 only @0.635 (FRR 4.6%).
/// 0.55 is the CONVENIENCE balance (~1-in-750 FAR). DARK MODE IS CONVENIENCE-
/// GRADE: high-assurance dark needs a dedicated IR-trained recognizer (proven,
/// not speculation). Live genuine IR ~0.65 sits in the overlap zone.
pub const IR_MATCH_THRESHOLD: f32 = 0.55;

/// Match threshold for ADAPTED IR embeddings (when the IR adapter is loaded).
/// The adapter (models/ir_adapter.onnx) is the v3 residZero CLIP-adapter (512→512,
/// out = x + 0.6·A(x)) trained on CBSR+Oulu COMBINED. Validated on the real ASUS
/// sensor (irlume-caldata) against v1: no regression (EER 0.36%=0.36%, FAR@.40=0,
/// FRR@.40 1.09%) and strictly better on the hard conditions (backlight/dark/motion)
/// plus FRR@FAR1e-3 halved. Academic CBSR+Oulu puts FAR≈1e-3 at 0.354 and FAR≈1e-4
/// at 0.410, so 0.40 remains the deployment default (FAR ~1e-4). MUST be re-validated
/// on the live camera at re-enroll (re-enroll required when the adapter changes:
/// v3 is a different, 512-D cosine space from v1's 256-D).
pub const IR_ADAPTED_MATCH_THRESHOLD: f32 = 0.40;

/// Extra margin added to the IR threshold when IR is used as a DIM-LIGHT FALLBACK
/// after the RGB match already missed (Secure tier). The fallback grants a second
/// chance via the IR-emitter-lit face when ambient light is too low for RGB
/// recognition, but a second modality adds false-accept risk, so demand a
/// clearer IR match than the pure-dark path. Cross-spectral adaptive-fusion knob;
/// re-tune against live genuine IR-fallback margins.
pub const IR_FALLBACK_MARGIN: f32 = 0.05;

/// Threshold scaling per doubling of the template count. Matching takes the
/// MAX cosine over a profile's N templates, which inflates the false-accept rate
/// roughly linearly in N (union bound: P(any of N exceeds) ≈ N·p). Windows Hello
/// raises its threshold as more *users* enroll for the same reason; irlume is
/// 1:1 (PAM supplies the claimed user), so the equivalent compensation scales
/// with the number of *templates compared against*. Calibration (LFW): ~+0.05
/// cosine halves the impostor tail, so full compensation would be 0.05·log2(N),
/// but that approaches the genuine floor (~0.71) and would add false-rejects, so
/// this PARTIAL step (0.015·log2(N)) gently raises the bar while preserving the
/// accept margin. A heuristic; tune with a per-N impostor ROC.
pub const TEMPLATE_SCALE_STEP: f32 = 0.015;
/// Max upward adjustment (cosine), a safety cap kept well below the genuine
/// floor so scaling can never lock out a legitimate user.
pub const TEMPLATE_SCALE_MAX_BUMP: f32 = 0.10;

/// Effective match threshold for a profile holding `n_templates`, raised from
/// `base` to hold the false-accept rate roughly constant as templates accumulate
/// (max-over-N inflates FAR ~linearly). Monotonic in `n_templates`, capped at
/// `base + TEMPLATE_SCALE_MAX_BUMP`. `n_templates ≤ 1` returns `base` unchanged.
pub fn scaled_threshold(base: f32, n_templates: usize) -> f32 {
    if n_templates <= 1 {
        return base;
    }
    let bump = (TEMPLATE_SCALE_STEP * (n_templates as f32).log2()).min(TEMPLATE_SCALE_MAX_BUMP);
    base + bump
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn threshold_scales_monotonically_and_caps() {
        // One template (or none): unchanged.
        assert_eq!(scaled_threshold(0.55, 1), 0.55);
        assert_eq!(scaled_threshold(0.55, 0), 0.55);
        // Rises with template count.
        let t2 = scaled_threshold(0.55, 2);
        let t5 = scaled_threshold(0.55, 5);
        let t10 = scaled_threshold(0.55, 10);
        assert!(t2 > 0.55 && t5 > t2 && t10 > t5, "{t2} {t5} {t10}");
        // Stays below the genuine floor (~0.71) for realistic counts.
        assert!(t10 < 0.65, "10-template thr {t10} too high");
        // Capped: even an absurd count can't exceed base + MAX_BUMP.
        assert!(scaled_threshold(0.55, 100_000) <= 0.55 + TEMPLATE_SCALE_MAX_BUMP + 1e-6);
    }
}

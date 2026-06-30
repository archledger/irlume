//! Matching, template storage, and TPM-bound secret release.
//!
//! Decision rule (NIST SP 800-63B-4 aligned): grant only if the liveness gate
//! says Live AND the best cosine >= a FIXED threshold tuned for FMR <= 1e-4
//! across demographics. Threshold is NOT ported from linhello (0.60) — AuraFace's
//! score scale differs; derive it from a genuine/impostor ROC on real data.
//!
//! Storage: never store a raw recoverable face image. Store L2-normalized
//! embeddings (zeroized after use). The unlock SECRET (e.g. the login password
//! or a random release token) is SEALED IN THE TPM, gated by PCR policy, and
//! released only on a successful live+match — not the template itself.

pub mod biopolicy;
pub mod crypto;
pub mod envelope;
pub mod keyring;
pub mod matcher;
pub mod pcrsig;
pub mod policy;
pub mod recovery;
pub mod storage;
pub mod template_key;
pub mod tpm;
pub mod tpm_pcrlock;

/// RGB (visible-light) match threshold. Evidence-based across two large FAR
/// runs: real faces (LFW, 87M impostor pairs) give FAR 3e-5 @ 0.50 and 2e-5 @
/// 0.55; synthetic (SFHQ, 112M pairs) 9.8e-5 @ 0.50. **Set to 0.55** to meet
/// Windows Hello's stated bar (FAR < 1e-5) more closely AND for demographic
/// headroom — FairFace per-group analysis showed 0.50 only clears FMR≤1e-4 for
/// the best group; ~0.55+ tightens every group (see docs/FAIRNESS.md). Live
/// genuine sits at min 0.71 / mean 0.85, so 0.55 keeps a wide accept margin (no
/// added false-rejects). Do NOT assume buffalo_l's 0.60 — AuraFace scale differs.
pub const RGB_MATCH_THRESHOLD: f32 = 0.55;

/// IR-mode (dark) match threshold — HIGHER than RGB because AuraFace-on-IR is
/// less discriminative. Benchmarked on the FULL CBSR NIR dataset (real 850nm,
/// 197 people, 3940 faces, 7.72M impostor pairs): genuine mean 0.855, impostor
/// MAX 0.900 (genuine/impostor OVERLAP), EER ≈0.8% @0.495. FAR/FRR: 0.55→
/// 1.3e-3/1.7%, 0.60→2.7e-4/3.0%, NIST FAR≤1e-4 only @0.635 (FRR 4.6%).
/// 0.55 is the CONVENIENCE balance (~1-in-750 FAR). DARK MODE IS CONVENIENCE-
/// GRADE — high-assurance dark needs a dedicated IR-trained recognizer (proven,
/// not speculation). Live genuine IR ~0.65 sits in the overlap zone.
pub const IR_MATCH_THRESHOLD: f32 = 0.55;

/// Match threshold for ADAPTED IR embeddings (when the IR adapter is loaded).
/// The adapter (models/ir_adapter.onnx) is now trained on CBSR+Oulu COMBINED
/// (multi-sensor) — 5-fold CV: CBSR-held-out EER 0.81%→0.46%, Oulu-held-out
/// 1.20%→1.16% (no degradation, unlike the prior CBSR-only adapter which blew
/// Oulu up to 1.95%). The combined adapter re-shapes the cosine space to a lower
/// scale; CV puts FAR≈1e-3 at 0.363, so 0.40 is the deployment default (security
/// margin over that). MUST be re-validated on the live camera at re-enroll
/// (CBSR/Oulu → our-IR domain gap; re-enroll required when the adapter changes).
pub const IR_ADAPTED_MATCH_THRESHOLD: f32 = 0.40;

/// Extra margin added to the IR threshold when IR is used as a DIM-LIGHT FALLBACK
/// after the RGB match already missed (Secure tier). The fallback grants a second
/// chance via the IR-emitter-lit face when ambient light is too low for RGB
/// recognition — but a second modality adds false-accept risk, so demand a
/// clearer IR match than the pure-dark path. Cross-spectral adaptive-fusion knob;
/// re-tune against live genuine IR-fallback margins.
pub const IR_FALLBACK_MARGIN: f32 = 0.05;

/// Threshold scaling per doubling of the template count. Matching takes the
/// MAX cosine over a profile's N templates, which inflates the false-accept rate
/// roughly linearly in N (union bound: P(any of N exceeds) ≈ N·p). Windows Hello
/// raises its threshold as more *users* enroll for the same reason; irlume is
/// 1:1 (PAM supplies the claimed user), so the equivalent compensation scales
/// with the number of *templates compared against*. Calibration (LFW): ~+0.05
/// cosine halves the impostor tail, so full compensation would be 0.05·log2(N) —
/// but that approaches the genuine floor (~0.71) and would add false-rejects, so
/// this PARTIAL step (0.015·log2(N)) gently raises the bar while preserving the
/// accept margin. A heuristic — tune with a per-N impostor ROC.
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

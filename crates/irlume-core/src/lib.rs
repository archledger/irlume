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

pub mod envelope;
pub mod keyring;
pub mod matcher;
pub mod pcrsig;
pub mod storage;
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

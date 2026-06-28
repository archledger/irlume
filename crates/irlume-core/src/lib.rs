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

/// Interim, evidence-based — refine with cross-session ROC for FMR<=1e-4.
/// Measured: impostor (50-face eval, 1225 pairs) mean 0.105 / p99 0.279 / MAX
/// 0.423; genuine (live, same person + glasses, 5 frames) min 0.712 / mean 0.849.
/// Clean separation (0.42 vs 0.71) → 0.50 sits safely between with margin both
/// ways. CAVEAT: genuine here is SAME-SESSION (optimistic); cross-session /
/// glasses-off pairs score lower, so keep it conservative, don't chase 0.71.
/// Do NOT assume buffalo_l's 0.60 — AuraFace scale differs.
pub const PLACEHOLDER_MATCH_THRESHOLD: f32 = 0.50;

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

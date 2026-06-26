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

pub mod matcher;
pub mod storage;
pub mod tpm;

/// Interim, evidence-based — REPLACE with an ROC-derived value for FMR<=1e-4.
/// Measured impostor distribution (50-face eval, 1225 pairs): mean 0.105,
/// p99 0.279, MAX 0.423. So the threshold must sit above ~0.42; this 0.45 is a
/// safe floor pending genuine pairs (same person, multiple captures) to fix the
/// final operating point. Do NOT assume buffalo_l's 0.60 — AuraFace scale differs.
pub const PLACEHOLDER_MATCH_THRESHOLD: f32 = 0.45;

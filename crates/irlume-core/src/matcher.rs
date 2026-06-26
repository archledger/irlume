//! 1:1 verification: compare a probe embedding against a user's enrolled set.

use irlume_vision::align::cosine;
use irlume_vision::Embedding;

/// Best (max) cosine of `probe` against any enrolled template.
pub fn best_score(probe: &Embedding, enrolled: &[Embedding]) -> f32 {
    enrolled
        .iter()
        .map(|t| cosine(probe, t))
        .fold(f32::NEG_INFINITY, f32::max)
}

/// Verification decision at a fixed threshold (multi-frame fusion happens above
/// this, by feeding several probe frames and requiring consistent passes).
pub fn verify(probe: &Embedding, enrolled: &[Embedding], threshold: f32) -> bool {
    !enrolled.is_empty() && best_score(probe, enrolled) >= threshold
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_enrollment_never_verifies() {
        let p = [0.0f32; irlume_vision::EMBED_DIM];
        assert!(!verify(&p, &[], 0.0));
    }
}

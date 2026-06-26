//! Face alignment to the canonical ArcFace 112x112 template.
//!
//! AuraFace inherits InsightFace's expected geometry, so we warp the detected
//! 5 landmarks onto the standard ArcFace reference points via a similarity
//! transform, then sample a 112x112 chip. Getting this EXACTLY right is the
//! Phase-1 make-or-break: a wrong template/normalization silently wrecks the
//! embeddings (see Detector/Embedder docs).

use crate::Landmarks5;

/// Canonical ArcFace 5-point reference landmarks for a 112x112 chip
/// (left eye, right eye, nose tip, left mouth corner, right mouth corner).
/// These are the InsightFace `arcface_src` constants — do not "tidy" them.
pub const ARCFACE_REF_112: Landmarks5 = [
    (38.2946, 51.6963),
    (73.5318, 51.5014),
    (56.0252, 71.7366),
    (41.5493, 92.3655),
    (70.7299, 92.2041),
];

/// Output chip side length.
pub const OUT_SIZE: u32 = 112;

/// Estimate the similarity transform mapping `src` landmarks onto
/// [`ARCFACE_REF_112`], then warp `frame` and return a 112x112x3 (BGR) chip.
pub fn align_to_arcface(
    _frame: &irlume_camera::Frame,
    _src: &Landmarks5,
) -> irlume_common::Result<Vec<u8>> {
    // TODO: least-squares similarity transform (Umeyama), inverse-warp with
    // bilinear sampling, emit BGR 112x112. Keep channel order BGR to match
    // AuraFace's InsightFace preprocessing.
    todo!()
}

/// Cosine similarity of two L2-normalized embeddings = dot product, clamped.
pub fn cosine(a: &[f32], b: &[f32]) -> f32 {
    debug_assert_eq!(a.len(), b.len());
    a.iter().zip(b).map(|(x, y)| x * y).sum::<f32>().clamp(-1.0, 1.0)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cosine_identity_is_one() {
        // A unit vector against itself must be ~1.0. The runtime analogue of
        // this (same crop -> same embedding -> cosine ~= 1.0) is the Phase-1
        // SelfTest::AlignmentIdentity gate run end-to-end through real ONNX.
        let mut v = [0.0f32; crate::EMBED_DIM];
        v[0] = 1.0;
        assert!((cosine(&v, &v) - 1.0).abs() < 1e-6);
    }
}

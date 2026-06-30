//! Face alignment to the canonical ArcFace 112x112 template, plus the
//! preprocessing and similarity scoring around it.
//!
//! AuraFace inherits InsightFace's expected geometry, so we fit a 2-D similarity
//! transform (scale + rotation + translation, no shear/reflection) from the
//! detected 5 landmarks onto the standard ArcFace reference points, then sample a
//! 112x112 chip. Getting this EXACTLY right is the Phase-1 make-or-break: a wrong
//! template, channel order, or normalization silently wrecks the embeddings
//! (the "identical images score 0.6" symptom). The `selftest align` gate exists
//! to catch exactly that.

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

/// Channel order fed to the recognition net. InsightFace ArcFace recognition
/// models were exported with `blobFromImage(..., swapRB=true)`, i.e. **RGB**.
/// If the Phase-1 self-test or a two-photo match test shows collapsed genuine
/// scores, flip this and re-test — it is the most common alignment-stage bug.
pub const INPUT_IS_RGB: bool = true;

/// A 2x3 affine transform, row-major: maps (x,y) -> (m0·x+m1·y+m2, m3·x+m4·y+m5).
#[derive(Clone, Copy, Debug)]
pub struct Affine2 {
    pub m: [f32; 6],
}

impl Affine2 {
    #[inline]
    pub fn apply(&self, x: f32, y: f32) -> (f32, f32) {
        let m = &self.m;
        (m[0] * x + m[1] * y + m[2], m[3] * x + m[4] * y + m[5])
    }

    /// Invert the affine. Returns `None` if the linear part is singular.
    pub fn invert(&self) -> Option<Affine2> {
        let m = &self.m;
        let det = m[0] * m[4] - m[1] * m[3];
        if det.abs() < 1e-12 {
            return None;
        }
        let inv_det = 1.0 / det;
        let (i00, i01) = (m[4] * inv_det, -m[1] * inv_det);
        let (i10, i11) = (-m[3] * inv_det, m[0] * inv_det);
        Some(Affine2 {
            m: [
                i00,
                i01,
                -(i00 * m[2] + i01 * m[5]),
                i10,
                i11,
                -(i10 * m[2] + i11 * m[5]),
            ],
        })
    }
}

/// Least-squares 2-D similarity transform mapping `src` onto `dst`.
///
/// Model (no reflection): X = a·x − b·y + tx,  Y = b·x + a·y + ty.
/// Each correspondence gives two linear rows in the unknowns θ = [a, b, tx, ty];
/// we solve the 4x4 normal equations directly (no SVD needed for a non-reflective
/// similarity — equivalent to the Umeyama/`skimage.SimilarityTransform` result).
pub fn estimate_similarity(src: &[(f32, f32)], dst: &[(f32, f32)]) -> Option<Affine2> {
    assert_eq!(src.len(), dst.len());
    let mut n = [[0.0f64; 4]; 4]; // AᵀA
    let mut rhs = [0.0f64; 4]; // Aᵀc
    for (&(x, y), &(bx, by)) in src.iter().zip(dst) {
        let (x, y, bx, by) = (x as f64, y as f64, bx as f64, by as f64);
        let rows = [([x, -y, 1.0, 0.0], bx), ([y, x, 0.0, 1.0], by)];
        for (r, t) in rows {
            for i in 0..4 {
                for j in 0..4 {
                    n[i][j] += r[i] * r[j];
                }
                rhs[i] += r[i] * t;
            }
        }
    }
    let theta = solve4(n, rhs)?;
    let (a, b, tx, ty) = (theta[0] as f32, theta[1] as f32, theta[2] as f32, theta[3] as f32);
    Some(Affine2 { m: [a, -b, tx, b, a, ty] })
}

/// Solve a 4x4 system via Gaussian elimination with partial pivoting.
fn solve4(mut a: [[f64; 4]; 4], mut b: [f64; 4]) -> Option<[f64; 4]> {
    for col in 0..4 {
        let mut piv = col;
        for r in (col + 1)..4 {
            if a[r][col].abs() > a[piv][col].abs() {
                piv = r;
            }
        }
        if a[piv][col].abs() < 1e-15 {
            return None;
        }
        a.swap(col, piv);
        b.swap(col, piv);
        for r in 0..4 {
            if r == col {
                continue;
            }
            let f = a[r][col] / a[col][col];
            for c in col..4 {
                a[r][c] -= f * a[col][c];
            }
            b[r] -= f * b[col];
        }
    }
    Some([b[0] / a[0][0], b[1] / a[1][1], b[2] / a[2][2], b[3] / a[3][3]])
}

/// An interleaved RGB8 image view (the RGB capture frame).
pub struct RgbView<'a> {
    pub data: &'a [u8], // width*height*3, R,G,B
    pub width: u32,
    pub height: u32,
}

impl RgbView<'_> {
    #[inline]
    fn pixel(&self, x: i32, y: i32) -> [f32; 3] {
        let x = x.clamp(0, self.width as i32 - 1) as usize;
        let y = y.clamp(0, self.height as i32 - 1) as usize;
        let i = (y * self.width as usize + x) * 3;
        [self.data[i] as f32, self.data[i + 1] as f32, self.data[i + 2] as f32]
    }

    /// Bilinear-sample the RGB image at fractional (x, y), edge-clamped.
    #[inline]
    pub fn sample_bilinear(&self, x: f32, y: f32) -> [f32; 3] {
        let (x0, y0) = (x.floor() as i32, y.floor() as i32);
        let (dx, dy) = (x - x0 as f32, y - y0 as f32);
        let p00 = self.pixel(x0, y0);
        let p10 = self.pixel(x0 + 1, y0);
        let p01 = self.pixel(x0, y0 + 1);
        let p11 = self.pixel(x0 + 1, y0 + 1);
        let mut out = [0.0f32; 3];
        for c in 0..3 {
            let top = p00[c] * (1.0 - dx) + p10[c] * dx;
            let bot = p01[c] * (1.0 - dx) + p11[c] * dx;
            out[c] = top * (1.0 - dy) + bot * dy;
        }
        out
    }
}

/// Align `frame` to the ArcFace template using `src` landmarks; return a
/// 112x112x3 interleaved chip in **RGB** order (u8). Deterministic for fixed
/// inputs (the property the Phase-1 identity gate relies on).
pub fn align_to_arcface(frame: &RgbView, src: &Landmarks5) -> irlume_common::Result<Vec<u8>> {
    let inv = estimate_similarity(src, &ARCFACE_REF_112)
        .and_then(|t| t.invert())
        .ok_or_else(|| irlume_common::Error::Protocol("degenerate landmark geometry".into()))?;
    let n = OUT_SIZE as usize;
    let mut chip = vec![0u8; n * n * 3];
    for v in 0..n {
        for u in 0..n {
            let (sx, sy) = inv.apply(u as f32, v as f32);
            let p = frame.sample_bilinear(sx, sy);
            let o = (v * n + u) * 3;
            for c in 0..3 {
                chip[o + c] = p[c].round().clamp(0.0, 255.0) as u8;
            }
        }
    }
    Ok(chip)
}

/// Preprocess an aligned 112x112 RGB chip into the NCHW f32 tensor the net wants:
/// planar [1,3,112,112], `(px − 127.5) / 128.0`, channel order per [`INPUT_IS_RGB`].
pub fn preprocess_arcface(chip_rgb: &[u8]) -> Vec<f32> {
    let n = (OUT_SIZE * OUT_SIZE) as usize;
    debug_assert_eq!(chip_rgb.len(), n * 3);
    let mut t = vec![0.0f32; 3 * n];
    // Destination channel planes: RGB if INPUT_IS_RGB else BGR.
    let plane_src = if INPUT_IS_RGB { [0usize, 1, 2] } else { [2, 1, 0] };
    for (plane, &src_c) in plane_src.iter().enumerate() {
        let base = plane * n;
        for px in 0..n {
            t[base + px] = (chip_rgb[px * 3 + src_c] as f32 - 127.5) / 128.0;
        }
    }
    t
}

/// Cosine similarity of two L2-normalized embeddings = dot product, clamped.
///
/// Written as an 8-lane unrolled fold so LLVM auto-vectorizes it to SSE/AVX
/// under `target-cpu` / `target-feature=+avx2` (see `.cargo/config.toml`). For
/// a 512-D vector this is already negligible vs ONNX inference — the real
/// acceleration is the ONNX Runtime execution provider, not this loop.
/// Horizontally mirror a 112×112×3 RGB chip (for test-time-augmentation: embed
/// a face and its mirror, then average the two embeddings — a standard ArcFace
/// inference trick that adds robustness for free, no retraining).
pub fn flip_h(chip: &[u8]) -> Vec<u8> {
    let n = OUT_SIZE as usize;
    let mut out = vec![0u8; chip.len()];
    for y in 0..n {
        for x in 0..n {
            let src = (y * n + x) * 3;
            let dst = (y * n + (n - 1 - x)) * 3;
            if src + 2 < chip.len() && dst + 2 < chip.len() {
                out[dst] = chip[src];
                out[dst + 1] = chip[src + 1];
                out[dst + 2] = chip[src + 2];
            }
        }
    }
    out
}

pub fn cosine(a: &[f32], b: &[f32]) -> f32 {
    debug_assert_eq!(a.len(), b.len());
    let mut acc = [0.0f32; 8];
    let chunks = a.len() / 8;
    for k in 0..chunks {
        let base = k * 8;
        for l in 0..8 {
            acc[l] += a[base + l] * b[base + l];
        }
    }
    let mut dot: f32 = acc.iter().sum();
    for i in (chunks * 8)..a.len() {
        dot += a[i] * b[i];
    }
    dot.clamp(-1.0, 1.0)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cosine_identity_is_one() {
        let mut v = [0.0f32; crate::EMBED_DIM];
        v[0] = 0.6;
        v[7] = 0.8; // |v| = 1
        assert!((cosine(&v, &v) - 1.0).abs() < 1e-6);
    }

    #[test]
    fn cosine_matches_naive() {
        let a: Vec<f32> = (0..crate::EMBED_DIM).map(|i| (i as f32).sin()).collect();
        let b: Vec<f32> = (0..crate::EMBED_DIM).map(|i| (i as f32).cos()).collect();
        let naive: f32 = a.iter().zip(&b).map(|(x, y)| x * y).sum::<f32>().clamp(-1.0, 1.0);
        assert!((cosine(&a, &b) - naive).abs() < 1e-4);
    }

    #[test]
    fn similarity_recovers_known_transform() {
        // Apply a known scale/rot/translate to the reference points, then fit.
        let (a, b, tx, ty) = (0.8f32, 0.3f32, 12.0f32, -5.0f32);
        let src: Vec<(f32, f32)> = ARCFACE_REF_112.to_vec();
        let dst: Vec<(f32, f32)> =
            src.iter().map(|&(x, y)| (a * x - b * y + tx, b * x + a * y + ty)).collect();
        let est = estimate_similarity(&src, &dst).unwrap();
        for (&(x, y), &(gx, gy)) in src.iter().zip(&dst) {
            let (px, py) = est.apply(x, y);
            assert!((px - gx).abs() < 1e-2 && (py - gy).abs() < 1e-2);
        }
    }

    #[test]
    fn identity_transform_when_src_equals_template() {
        let est = estimate_similarity(&ARCFACE_REF_112, &ARCFACE_REF_112).unwrap();
        assert!((est.m[0] - 1.0).abs() < 1e-3); // a≈1
        assert!(est.m[1].abs() < 1e-3); // -b≈0
        assert!(est.m[2].abs() < 1e-2 && est.m[5].abs() < 1e-2); // t≈0
    }

    #[test]
    fn align_is_deterministic() {
        // 64x64 RGB gradient; align twice with the same landmarks -> identical bytes.
        let (w, h) = (64u32, 64u32);
        let mut data = vec![0u8; (w * h * 3) as usize];
        for y in 0..h {
            for x in 0..w {
                let i = ((y * w + x) * 3) as usize;
                data[i] = (x * 4) as u8;
                data[i + 1] = (y * 4) as u8;
                data[i + 2] = 128;
            }
        }
        let view = RgbView { data: &data, width: w, height: h };
        let lm: Landmarks5 = [(20.0, 24.0), (44.0, 24.0), (32.0, 36.0), (24.0, 48.0), (40.0, 48.0)];
        let c1 = align_to_arcface(&view, &lm).unwrap();
        let c2 = align_to_arcface(&view, &lm).unwrap();
        assert_eq!(c1, c2);
        assert_eq!(c1.len(), (OUT_SIZE * OUT_SIZE * 3) as usize);
    }

    #[test]
    fn preprocess_shape_and_normalization() {
        let chip = vec![127u8; (OUT_SIZE * OUT_SIZE * 3) as usize];
        let t = preprocess_arcface(&chip);
        assert_eq!(t.len(), 3 * (OUT_SIZE * OUT_SIZE) as usize);
        // (127 - 127.5)/128 = -0.00390625
        assert!((t[0] - (-0.00390625)).abs() < 1e-6);
    }
}

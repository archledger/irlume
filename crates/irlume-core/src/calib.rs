// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright the irlume contributors.

//! Per-enrollment IR calibration (ADR-0004): a ridge-regularized linear map
//! fitted on-device from one profile's own enrollment scans, pulling that
//! person's IR embeddings toward their RGB embeddings. Replaces the shipped
//! global IR adapter: a 2026-07-15 prototype measured the per-person fit
//! halving hard-condition false rejects at the production threshold (FRR
//! 33%→15% at 0.55) with zero measured false-accept inflation against 1,600+
//! strangers, while a globally trained adapter of the same size regressed
//! every unseen-identity benchmark. Fitted state is derived from consented
//! local data and never ships: no license surface exists.
//!
//! Math: rows A (n x d) = the profile's raw IR embeddings, B = its RGB
//! embeddings, both L2-normalized. The ridge solution
//!     W = (AᵀA + λI)⁻¹ (AᵀB + λI)
//! rewrites as W = I + M·N with M = (AᵀA + λI)⁻¹Aᵀ (d x n) and N = B − A
//! (n x d), so the correction has rank ≤ n and is stored as the two factors
//! (2·n·d floats) instead of a d x d matrix. Applying is two thin matrix
//! products: y = normalize(x + (x·M)·N). λ is fixed at [`RIDGE_LAMBDA`]; the
//! prototype's FAR guard showed λ in [0.1, 1] safe and an unregularized
//! shift catastrophic (31% FAR at threshold 0.40), so λ is not a tunable.

use serde::{Deserialize, Serialize};

/// Fixed ridge strength. Prototype (2 identities x 5 enrollment draws,
/// k=10): λ=0.1 and λ=1 both kept FAR at the production thresholds at or
/// below the uncalibrated baseline; 0.5 sits between the two measured-safe
/// endpoints rather than on one.
pub const RIDGE_LAMBDA: f64 = 0.5;
/// Minimum IR/RGB scan pairs before a fit is attempted. Below this the
/// correction is too rank-starved to help and the profile simply has no
/// calibration (raw matching, exactly as before).
pub const MIN_FIT_PAIRS: usize = 3;

/// Fitted per-profile correction, stored beside the templates it was fitted
/// from. `m` is d x n column-major-as-rows (d rows of n), `n_rows` is n x d.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IrCalibration {
    pub m: Vec<Vec<f32>>,
    pub n_rows: Vec<Vec<f32>>,
    pub lambda: f32,
    pub fitted_pairs: usize,
}

fn normalize(v: &mut [f32]) {
    let n = v.iter().map(|x| (*x as f64).powi(2)).sum::<f64>().sqrt() + 1e-9;
    for x in v.iter_mut() {
        *x = (*x as f64 / n) as f32;
    }
}

/// Cholesky factorization of a symmetric positive-definite matrix (lower
/// triangular, in place). `a` is row-major d x d. Returns false if the
/// matrix is not positive-definite (cannot happen for AᵀA + λI with λ > 0,
/// but checked rather than trusted).
// In-place factorization reads two rows at once; index loops are the clear
// form here and iterator rewrites would need split borrows or row copies.
#[allow(clippy::needless_range_loop)]
fn cholesky(a: &mut [Vec<f64>]) -> bool {
    let d = a.len();
    for j in 0..d {
        let mut diag = a[j][j];
        for k in 0..j {
            diag -= a[j][k] * a[j][k];
        }
        if diag <= 0.0 {
            return false;
        }
        let diag = diag.sqrt();
        a[j][j] = diag;
        for i in (j + 1)..d {
            let mut v = a[i][j];
            for k in 0..j {
                v -= a[i][k] * a[j][k];
            }
            a[i][j] = v / diag;
        }
    }
    true
}

/// Solve L·Lᵀ·x = b in place given the Cholesky factor L (lower).
// Same as `cholesky`: triangular substitution reads b[k] while writing b[i];
// index loops are the clear form (newer clippy flags what older allowed).
#[allow(clippy::needless_range_loop)]
fn chol_solve(l: &[Vec<f64>], b: &mut [f64]) {
    let d = l.len();
    for i in 0..d {
        let mut v = b[i];
        for k in 0..i {
            v -= l[i][k] * b[k];
        }
        b[i] = v / l[i][i];
    }
    for i in (0..d).rev() {
        let mut v = b[i];
        for k in (i + 1)..d {
            v -= l[k][i] * b[k];
        }
        b[i] = v / l[i][i];
    }
}

/// Fit the ridge map from paired rows (`ir[i]` ↔ `rgb[i]`). Inputs need not be
/// pre-normalized; rows are normalized here to match apply-time inputs.
/// Returns `None` below [`MIN_FIT_PAIRS`] or on dimension mismatch.
// Gram-matrix accumulation indexes two positions of the same row; index
// loops are the clear form here (see `cholesky`).
#[allow(clippy::needless_range_loop)]
pub fn fit(ir: &[Vec<f32>], rgb: &[Vec<f32>]) -> Option<IrCalibration> {
    let n = ir.len();
    if n < MIN_FIT_PAIRS || n != rgb.len() {
        return None;
    }
    let d = ir[0].len();
    if d == 0 || ir.iter().chain(rgb.iter()).any(|r| r.len() != d) {
        return None;
    }
    let norm_rows = |rows: &[Vec<f32>]| -> Vec<Vec<f64>> {
        rows.iter()
            .map(|r| {
                let mut v: Vec<f32> = r.clone();
                normalize(&mut v);
                v.into_iter().map(|x| x as f64).collect()
            })
            .collect()
    };
    let a = norm_rows(ir);
    let b = norm_rows(rgb);

    // G = AᵀA + λI (d x d), then its Cholesky factor.
    let mut g = vec![vec![0.0f64; d]; d];
    for row in &a {
        for i in 0..d {
            let ri = row[i];
            if ri == 0.0 {
                continue;
            }
            for j in 0..d {
                g[i][j] += ri * row[j];
            }
        }
    }
    for (i, row) in g.iter_mut().enumerate() {
        row[i] += RIDGE_LAMBDA;
    }
    if !cholesky(&mut g) {
        return None;
    }

    // M = G⁻¹Aᵀ, one solve per scan column; stored as d rows of n.
    let mut m = vec![vec![0.0f32; n]; d];
    for (col, row_a) in a.iter().enumerate() {
        let mut x: Vec<f64> = row_a.clone();
        chol_solve(&g, &mut x);
        for i in 0..d {
            m[i][col] = x[i] as f32;
        }
    }
    // N = B − A (n rows of d).
    let n_rows: Vec<Vec<f32>> = a
        .iter()
        .zip(&b)
        .map(|(ra, rb)| ra.iter().zip(rb).map(|(x, y)| (y - x) as f32).collect())
        .collect();
    Some(IrCalibration {
        m,
        n_rows,
        lambda: RIDGE_LAMBDA as f32,
        fitted_pairs: n,
    })
}

impl IrCalibration {
    /// y = normalize(x + (x·M)·N). Returns `None` on dimension mismatch
    /// (e.g. a calibration fitted under a different embedding width).
    pub fn apply(&self, x: &[f32]) -> Option<Vec<f32>> {
        let d = self.m.len();
        if x.len() != d || self.n_rows.iter().any(|r| r.len() != d) {
            return None;
        }
        let r = self.n_rows.len();
        if self.m.iter().any(|row| row.len() != r) {
            return None;
        }
        // t = x·M (length r)
        let mut t = vec![0.0f64; r];
        for (i, &xi) in x.iter().enumerate() {
            if xi == 0.0 {
                continue;
            }
            let mi = &self.m[i];
            for (k, tk) in t.iter_mut().enumerate() {
                *tk += xi as f64 * mi[k] as f64;
            }
        }
        // y = x + t·N
        let mut y: Vec<f32> = x.to_vec();
        for (k, row) in self.n_rows.iter().enumerate() {
            let tk = t[k];
            if tk == 0.0 {
                continue;
            }
            for (yi, &nv) in y.iter_mut().zip(row) {
                *yi = (*yi as f64 + tk * nv as f64) as f32;
            }
        }
        normalize(&mut y);
        Some(y)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn unit(mut v: Vec<f32>) -> Vec<f32> {
        normalize(&mut v);
        v
    }

    #[test]
    fn too_few_pairs_yields_none() {
        let a = vec![vec![1.0f32, 0.0]; 2];
        assert!(fit(&a, &a).is_none());
    }

    #[test]
    fn identical_domains_fit_near_identity() {
        // rgb == ir -> N = 0 -> W = I: apply must be a no-op (post-normalize).
        let rows: Vec<Vec<f32>> = (0..4)
            .map(|i| unit((0..8).map(|j| ((i * 8 + j) as f32).sin()).collect()))
            .collect();
        let c = fit(&rows, &rows).unwrap();
        let x = unit((0..8).map(|j| (j as f32).cos()).collect());
        let y = c.apply(&x).unwrap();
        for (a, b) in x.iter().zip(&y) {
            assert!((a - b).abs() < 1e-5, "{a} vs {b}");
        }
    }

    #[test]
    fn fit_pulls_fitted_ir_toward_rgb() {
        // Distinct IR/RGB clusters: calibrated IR rows must land closer to
        // their RGB counterparts than the raw rows do.
        let ir: Vec<Vec<f32>> = (0..5)
            .map(|i| unit((0..16).map(|j| ((i + j) as f32).sin() + 0.2).collect()))
            .collect();
        let rgb: Vec<Vec<f32>> = (0..5)
            .map(|i| unit((0..16).map(|j| ((i + j) as f32).sin() - 0.3).collect()))
            .collect();
        let c = fit(&ir, &rgb).unwrap();
        for (xi, xr) in ir.iter().zip(&rgb) {
            let raw: f32 = xi.iter().zip(xr).map(|(a, b)| a * b).sum();
            let cal = c.apply(xi).unwrap();
            let adj: f32 = cal.iter().zip(xr).map(|(a, b)| a * b).sum();
            assert!(
                adj > raw,
                "calibration should raise genuine cosine ({adj} vs {raw})"
            );
        }
    }

    #[test]
    fn apply_rejects_wrong_dimension() {
        let rows: Vec<Vec<f32>> = (0..3).map(|_| unit(vec![1.0; 8])).collect();
        let c = fit(&rows, &rows).unwrap();
        assert!(c.apply(&[0.5; 4]).is_none());
    }

    /// Deterministic rows from a 32-bit LCG, bit-identical to the numpy
    /// reference generator used to produce `NUMPY_EXPECTED`.
    fn lcg_rows(seed: u64, n: usize, d: usize) -> Vec<Vec<f32>> {
        let mut x = seed;
        (0..n)
            .map(|_| {
                (0..d)
                    .map(|_| {
                        x = (1664525u64.wrapping_mul(x).wrapping_add(1013904223)) % (1 << 32);
                        (x as f64 / (1u64 << 32) as f64 - 0.5) as f32
                    })
                    .collect()
            })
            .collect()
    }

    #[test]
    fn matches_numpy_reference_solution() {
        // Expected output computed with numpy on 2026-07-15 for the same LCG
        // inputs (n=6, d=16, lambda=0.5): W = solve(AᵀA+λI, AᵀB+λI), rows
        // and probe L2-normalized, y = normalize(probe·W). Guards the
        // Cholesky/rank-form math against drift from the Python prototype.
        const NUMPY_EXPECTED: [f32; 16] = [
            -0.315405, -0.470458, -0.0634562, -0.0160823, 0.0429624, -0.4469, -0.107506, -0.149925,
            0.435608, 0.334933, 0.0974941, -0.0203366, 0.204951, 0.179577, 0.0196648, -0.229804,
        ];
        let a = lcg_rows(1, 6, 16);
        let b = lcg_rows(7, 6, 16);
        let c = fit(&a, &b).unwrap();
        let probe = unit(lcg_rows(42, 1, 16).remove(0));
        let y = c.apply(&probe).unwrap();
        for (got, want) in y.iter().zip(NUMPY_EXPECTED) {
            assert!((got - want).abs() < 1e-4, "{got} vs {want}");
        }
    }

    #[test]
    fn serde_round_trip() {
        let rows: Vec<Vec<f32>> = (0..3)
            .map(|i| unit((0..8).map(|j| ((i * 3 + j) as f32).cos()).collect()))
            .collect();
        let c = fit(&rows, &rows).unwrap();
        let j = serde_json::to_string(&c).unwrap();
        let back: IrCalibration = serde_json::from_str(&j).unwrap();
        assert_eq!(back.fitted_pairs, 3);
        let x = unit(vec![0.3; 8]);
        assert_eq!(c.apply(&x), back.apply(&x));
    }
}

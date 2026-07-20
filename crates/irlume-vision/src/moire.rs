//! Frequency-domain screen/replay deterrent for the RGB-only (convenience) path.
//!
//! A camera pointed at a *display* captures the panel's regular pixel grid (and
//! the moiré beat between that grid and the sensor), a strongly *periodic*
//! texture that shows up as sharp, isolated peaks in the 2D FFT. Real skin has
//! broadband, non-periodic texture, so its spectrum falls off smoothly. We
//! measure "peakiness" (max / mean magnitude) in the high-frequency band: a high
//! value ⇒ periodic ⇒ likely a screen.
//!
//! Model-free (clean BOM). DETERRENT-grade only: high-res panels far from the
//! camera show weak moiré, and very sharp natural texture can read high, so this
//! is one cue layered onto lit + frontal + glare, used only in convenience tier.

use rustfft::{num_complex::Complex, FftPlanner};
use std::f32::consts::PI;

/// Analysis grid size (square). Power-of-two keeps the FFT fast; the caller
/// nearest-resamples the face crop to this (nearest, not bilinear, to preserve
/// the high-frequency grid we're trying to detect).
pub const N: usize = 128;

/// Peakiness of the high-frequency spectrum of an `N`×`N` grayscale face crop:
/// `max / mean` magnitude beyond a low-frequency cutoff. ~low for real faces,
/// higher for displays. Returns 0 on a bad-sized input.
pub fn moire_score(gray: &[u8]) -> f32 {
    if gray.len() < N * N {
        return 0.0;
    }
    // Hann window (both axes) so the crop's border discontinuity doesn't paint a
    // bright "+" of fake energy along the frequency axes; subtract the mean (DC).
    let mean = gray[..N * N].iter().map(|&p| p as f32).sum::<f32>() / (N * N) as f32;
    let win: Vec<f32> = (0..N)
        .map(|i| 0.5 - 0.5 * (2.0 * PI * i as f32 / (N as f32 - 1.0)).cos())
        .collect();
    let mut buf = vec![Complex::new(0.0f32, 0.0); N * N];
    for y in 0..N {
        for x in 0..N {
            let v = (gray[y * N + x] as f32 - mean) * win[y] * win[x];
            buf[y * N + x] = Complex::new(v, 0.0);
        }
    }

    let mut planner = FftPlanner::new();
    let fft = planner.plan_fft_forward(N);
    // Rows, then columns = 2D FFT.
    for y in 0..N {
        fft.process(&mut buf[y * N..(y + 1) * N]);
    }
    let mut col = vec![Complex::new(0.0f32, 0.0); N];
    for x in 0..N {
        for y in 0..N {
            col[y] = buf[y * N + x];
        }
        fft.process(&mut col);
        for y in 0..N {
            buf[y * N + x] = col[y];
        }
    }

    // High-frequency band only (skip DC + low-freq face structure/illumination).
    const R_LOW: f32 = 0.12;
    let (mut sum, mut cnt, mut peak) = (0.0f64, 0u32, 0.0f32);
    for v in 0..N {
        for u in 0..N {
            let fu = u.min(N - u) as f32 / N as f32;
            let fv = v.min(N - v) as f32 / N as f32;
            if (fu * fu + fv * fv).sqrt() >= R_LOW {
                let mag = buf[v * N + u].norm();
                sum += mag as f64;
                cnt += 1;
                if mag > peak {
                    peak = mag;
                }
            }
        }
    }
    if cnt == 0 || sum == 0.0 {
        return 0.0;
    }
    peak / (sum as f32 / cnt as f32)
}

/// Crop `bbox` from an RGB8 frame, grayscale it, and NEAREST-resample to `N`×`N`
/// for [`moire_score`]. Nearest (not bilinear) is deliberate; interpolation
/// low-passes the very grid we want to keep.
pub fn face_gray_n(rgb: &[u8], w: u32, h: u32, bbox: &[f32; 4]) -> Vec<u8> {
    let (w, h) = (w as i32, h as i32);
    let x0 = (bbox[0] as i32).clamp(0, w - 1);
    let y0 = (bbox[1] as i32).clamp(0, h - 1);
    let x1 = (bbox[2] as i32).clamp(x0 + 1, w);
    let y1 = (bbox[3] as i32).clamp(y0 + 1, h);
    let (bw, bh) = ((x1 - x0).max(1), (y1 - y0).max(1));
    let mut out = vec![0u8; N * N];
    for oy in 0..N {
        let sy = y0 + (oy as i32 * bh) / N as i32;
        for ox in 0..N {
            let sx = x0 + (ox as i32 * bw) / N as i32;
            let i = ((sy.min(h - 1) * w + sx.min(w - 1)) * 3) as usize;
            if i + 2 < rgb.len() {
                let luma =
                    (rgb[i] as u32 * 299 + rgb[i + 1] as u32 * 587 + rgb[i + 2] as u32 * 114)
                        / 1000;
                out[oy * N + ox] = luma as u8;
            }
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn flat_image_is_not_peaky() {
        // Uniform gray -> no high-freq energy -> score ~0.
        let g = vec![128u8; N * N];
        assert!(moire_score(&g) < 5.0);
    }

    #[test]
    fn pure_grid_is_very_peaky() {
        // A regular checker/grid (like a pixel matrix) -> one dominant high-freq
        // peak -> high peakiness, well above any smooth-texture baseline.
        let mut g = vec![0u8; N * N];
        for y in 0..N {
            for x in 0..N {
                g[y * N + x] = if (x + y) % 2 == 0 { 0 } else { 255 };
            }
        }
        assert!(moire_score(&g) > 50.0);
    }

    #[test]
    fn short_buffer_scores_zero() {
        assert_eq!(moire_score(&[128u8; N * N - 1]), 0.0);
        assert_eq!(moire_score(&[]), 0.0);
    }

    #[test]
    fn all_black_crop_scores_zero() {
        // Zero-mean, zero-energy input: the sum==0 guard, not a division blowup.
        assert_eq!(moire_score(&vec![0u8; N * N]), 0.0);
    }

    #[test]
    fn periodic_stripes_outscore_broadband_texture() {
        // Skin-analog per the module contract: BROADBAND, non-periodic texture
        // (deterministic pseudo-noise) whose spectrum falls off smoothly.
        let mut noise = vec![0u8; N * N];
        let mut s = 0x2545_F491u32;
        for p in noise.iter_mut() {
            // xorshift32: deterministic, aperiodic over this length.
            s ^= s << 13;
            s ^= s >> 17;
            s ^= s << 5;
            *p = (s >> 24) as u8;
        }
        // Display-like periodicity: vertical stripes of period 4 (frequency
        // 0.25, well inside the analyzed band).
        let mut stripes = vec![0u8; N * N];
        for y in 0..N {
            for x in 0..N {
                stripes[y * N + x] = if (x / 2) % 2 == 0 { 40 } else { 220 };
            }
        }
        let (s_noise, s_stripes) = (moire_score(&noise), moire_score(&stripes));
        assert!(
            s_stripes > 10.0 * s_noise.max(1.0),
            "stripes {s_stripes} vs broadband {s_noise}: periodicity must dominate"
        );
        // A slow one-axis gradient (smooth shading) also stays well under the
        // stripe score, though windowing leakage keeps it above pure noise.
        let mut smooth = vec![0u8; N * N];
        for y in 0..N {
            for x in 0..N {
                smooth[y * N + x] = (x * 255 / N) as u8;
            }
        }
        let s_smooth = moire_score(&smooth);
        assert!(
            s_stripes > 2.0 * s_smooth,
            "stripes {s_stripes} vs gradient {s_smooth}"
        );
    }

    #[test]
    fn face_gray_n_converts_luma_and_resamples() {
        // A 4x4 pure-red frame: BT.601 luma of (255,0,0) is 76.
        let (w, h) = (4u32, 4u32);
        let mut rgb = vec![0u8; (w * h * 3) as usize];
        for px in rgb.chunks_mut(3) {
            px[0] = 255;
        }
        let g = face_gray_n(&rgb, w, h, &[0.0, 0.0, 4.0, 4.0]);
        assert_eq!(g.len(), N * N);
        assert!(g.iter().all(|&p| p == 76), "expected uniform luma 76");
    }

    #[test]
    fn face_gray_n_nearest_resample_preserves_grid_extremes() {
        // A 2x2 black/white checker upsampled 64x: nearest sampling must keep
        // pure 0/255 (bilinear would smear them, killing the FFT peak).
        let (w, h) = (2u32, 2u32);
        let rgb = [
            0u8, 0, 0, 255, 255, 255, //
            255, 255, 255, 0, 0, 0,
        ];
        let g = face_gray_n(&rgb, w, h, &[0.0, 0.0, 2.0, 2.0]);
        assert!(g.iter().all(|&p| p == 0 || p == 255));
        assert!(g.contains(&0) && g.contains(&255));
    }

    #[test]
    fn face_gray_n_clamps_out_of_frame_bboxes() {
        // A bbox hanging off every edge is clamped into the frame; the crop
        // still fills the full analysis grid from real pixels.
        let (w, h) = (8u32, 8u32);
        let rgb = vec![200u8; (w * h * 3) as usize];
        let g = face_gray_n(&rgb, w, h, &[-50.0, -50.0, 500.0, 500.0]);
        assert_eq!(g.len(), N * N);
        assert!(g.iter().all(|&p| p == 200));
        // Degenerate inverted/zero-area bbox: clamped to at least one pixel.
        let g = face_gray_n(&rgb, w, h, &[7.9, 7.9, 7.9, 7.9]);
        assert!(g.iter().all(|&p| p == 200));
    }
}

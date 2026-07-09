//! Illumination normalization for low-light RGB chips, applied to the aligned
//! 112×112 chip just before embedding. Goal: make a DIM probe embed closer to a
//! BRIGHT enrolled template (recover recognition in poor ambient light), without
//! inflating impostor similarity. All methods operate on LUMA and rescale RGB by
//! the per-pixel luma gain, preserving hue. Whether any of these actually helps
//! AuraFace is an empirical question; A/B before wiring (see scripts/lightnorm A/B).

#[inline]
fn luma(r: u8, g: u8, b: u8) -> f32 {
    0.299 * r as f32 + 0.587 * g as f32 + 0.114 * b as f32
}

/// Rescale each RGB pixel so its luma becomes `new_y[i]`, preserving hue.
fn apply_luma_map(chip: &mut [u8], new_y: &[f32]) {
    for (i, px) in chip.chunks_mut(3).enumerate() {
        let y = luma(px[0], px[1], px[2]).max(1.0);
        let gain = (new_y[i] / y).clamp(0.0, 8.0);
        for pc in px.iter_mut() {
            *pc = ((*pc as f32) * gain).round().clamp(0.0, 255.0) as u8;
        }
    }
}

/// Simulate a dimmer capture (test-only): scale every channel by `factor` (<1 darkens).
pub fn darken(chip: &mut [u8], factor: f32) {
    for v in chip.iter_mut() {
        *v = ((*v as f32) * factor).round().clamp(0.0, 255.0) as u8;
    }
}

/// Gamma correction. `g > 1` lifts shadows (brightens dark regions).
pub fn gamma(chip: &mut [u8], g: f32) {
    let inv = 1.0 / g;
    let lut: Vec<u8> = (0..256)
        .map(|v| {
            (255.0 * (v as f32 / 255.0).powf(inv))
                .round()
                .clamp(0.0, 255.0) as u8
        })
        .collect();
    for v in chip.iter_mut() {
        *v = lut[*v as usize];
    }
}

/// Global histogram equalization on luma.
pub fn equalize(chip: &mut [u8]) {
    let n = chip.len() / 3;
    if n == 0 {
        return;
    }
    let ys: Vec<f32> = chip.chunks(3).map(|p| luma(p[0], p[1], p[2])).collect();
    let mut hist = [0u32; 256];
    for &y in &ys {
        hist[y.round().clamp(0.0, 255.0) as usize] += 1;
    }
    let mut cdf = [0f32; 256];
    let mut acc = 0u32;
    for i in 0..256 {
        acc += hist[i];
        cdf[i] = acc as f32 / n as f32;
    }
    let new_y: Vec<f32> = ys
        .iter()
        .map(|&y| cdf[y.round().clamp(0.0, 255.0) as usize] * 255.0)
        .collect();
    apply_luma_map(chip, &new_y);
}

/// Build a clipped-histogram CDF mapping (0..=255 -> 0..=255) for one tile's luma.
fn tile_map(tile_luma: &[f32], clip_frac: f32) -> [f32; 256] {
    let n = tile_luma.len().max(1);
    let mut hist = [0u32; 256];
    for &y in tile_luma {
        hist[y.round().clamp(0.0, 255.0) as usize] += 1;
    }
    // Clip and redistribute the excess uniformly (contrast limiting).
    let limit = ((clip_frac * n as f32 / 256.0).max(1.0)) as u32;
    let mut excess = 0u32;
    for h in hist.iter_mut() {
        if *h > limit {
            excess += *h - limit;
            *h = limit;
        }
    }
    let add = excess / 256;
    let rem = excess % 256;
    for (i, h) in hist.iter_mut().enumerate() {
        *h += add + if (i as u32) < rem { 1 } else { 0 };
    }
    let mut map = [0f32; 256];
    let mut acc = 0u32;
    for i in 0..256 {
        acc += hist[i];
        map[i] = (acc as f32 / n as f32) * 255.0;
    }
    map
}

/// Contrast-Limited Adaptive Histogram Equalization on luma. `grid` tiles per axis
/// (e.g. 8), `clip_frac` is the per-bin clip as a multiple of the uniform count.
pub fn clahe(chip: &mut [u8], side: usize, grid: usize, clip_frac: f32) {
    if side == 0 || grid == 0 || chip.len() < side * side * 3 {
        return;
    }
    let ys: Vec<f32> = chip.chunks(3).map(|p| luma(p[0], p[1], p[2])).collect();
    let tile = side as f32 / grid as f32;
    // Per-tile mapping LUTs.
    let mut maps = vec![[0f32; 256]; grid * grid];
    for ty in 0..grid {
        for tx in 0..grid {
            let x0 = (tx as f32 * tile).floor() as usize;
            let x1 = (((tx + 1) as f32 * tile).ceil() as usize).min(side);
            let y0 = (ty as f32 * tile).floor() as usize;
            let y1 = (((ty + 1) as f32 * tile).ceil() as usize).min(side);
            let mut buf = Vec::with_capacity((x1 - x0) * (y1 - y0));
            for yy in y0..y1 {
                for xx in x0..x1 {
                    buf.push(ys[yy * side + xx]);
                }
            }
            maps[ty * grid + tx] = tile_map(&buf, clip_frac);
        }
    }
    // Bilinear interpolation of the 4 nearest tile-center maps for each pixel.
    let map_at = |t: usize, v: usize| -> f32 { maps[t][v] };
    let mut new_y = vec![0f32; ys.len()];
    for yy in 0..side {
        // tile-center coordinate space
        let gy = ((yy as f32 + 0.5) / tile - 0.5).clamp(0.0, grid as f32 - 1.0);
        let ty0 = gy.floor() as usize;
        let ty1 = (ty0 + 1).min(grid - 1);
        let fy = gy - ty0 as f32;
        for xx in 0..side {
            let gx = ((xx as f32 + 0.5) / tile - 0.5).clamp(0.0, grid as f32 - 1.0);
            let tx0 = gx.floor() as usize;
            let tx1 = (tx0 + 1).min(grid - 1);
            let fx = gx - tx0 as f32;
            let v = ys[yy * side + xx].round().clamp(0.0, 255.0) as usize;
            let top = map_at(ty0 * grid + tx0, v) * (1.0 - fx) + map_at(ty0 * grid + tx1, v) * fx;
            let bot = map_at(ty1 * grid + tx0, v) * (1.0 - fx) + map_at(ty1 * grid + tx1, v) * fx;
            new_y[yy * side + xx] = top * (1.0 - fy) + bot * fy;
        }
    }
    apply_luma_map(chip, &new_y);
}

#[cfg(test)]
mod tests {
    use super::*;

    fn chip(val: u8) -> Vec<u8> {
        vec![val; 112 * 112 * 3]
    }

    #[test]
    fn gamma_lifts_shadows() {
        let mut c = chip(40);
        gamma(&mut c, 2.2);
        assert!(c[0] > 40, "gamma>1 should brighten dark pixel: {}", c[0]);
    }

    #[test]
    fn darken_then_methods_preserve_shape() {
        for f in [
            (|c: &mut [u8]| gamma(c, 2.0)) as fn(&mut [u8]),
            |c: &mut [u8]| equalize(c),
            |c: &mut [u8]| clahe(c, 112, 8, 3.0),
        ] {
            let mut c = chip(80);
            darken(&mut c, 0.4);
            f(&mut c);
            assert_eq!(c.len(), 112 * 112 * 3);
        }
    }

    #[test]
    fn clahe_runs_on_gradient() {
        // a vertical luma gradient -> CLAHE should not panic and should change values
        let mut c = vec![0u8; 112 * 112 * 3];
        for y in 0..112 {
            for x in 0..112 {
                let v = ((y * 255) / 111) as u8;
                let o = (y * 112 + x) * 3;
                c[o] = v;
                c[o + 1] = v;
                c[o + 2] = v;
            }
        }
        let before = c.clone();
        clahe(&mut c, 112, 8, 3.0);
        assert_ne!(before, c, "CLAHE should modify a gradient");
    }
}

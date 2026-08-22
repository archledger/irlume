// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright the irlume contributors.

//! Print the RGB frame's whole-buffer mean — the exact statistic the
//! SecureDark scene gate reads (`frame_mean` over the decoded frame) — for
//! verifying the lit/dark boundary (CONCLUSIVE_SCENE_BRIGHTNESS) per host.
//!
//! Usage: cargo run --release -p irlume-camera --example frame_mean_probe -- \
//!   [rgb_dev] [frames]

fn main() {
    let mut a = std::env::args().skip(1);
    let dev = a.next().unwrap_or_else(|| "/dev/video0".into());
    let n: usize = a.next().and_then(|s| s.parse().ok()).unwrap_or(3);
    for i in 0..n {
        match irlume_camera::capture_rgb_denoised(&dev) {
            Ok(f) => println!(
                "{dev} frame{i}: mean={:.1} ({}x{})",
                irlume_camera::frame_mean(&f.data),
                f.width,
                f.height
            ),
            Err(e) => eprintln!("{dev} frame{i}: {e}"),
        }
    }
}

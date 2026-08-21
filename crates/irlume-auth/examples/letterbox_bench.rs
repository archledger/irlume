// SPDX-License-Identifier: GPL-3.0-or-later.
// Copyright the irlume contributors.

//! Microbench for the detector's grey-frame input path: measures the work the
//! `Grey8View` specialization removes — the `grey_to_rgb` full-frame
//! expansion plus the letterbox's 3-channel sampling — in isolation from the
//! ONNX run. Machine-dependent numbers; no gate.
//!
//! Usage: cargo run --release -p irlume-auth --example letterbox_bench -- \
//!   [width height]   (defaults: 640x400 IR frame shape, 640 letterbox)

use irlume_vision::align::{FrameView, Grey8View, RgbView};
use std::time::Instant;

const LB: usize = 640;

/// The exact loop `letterbox_bgr_into` runs, over any FrameView.
fn letterbox(v: &FrameView<'_>, scale: f32, size: usize, t: &mut [f32]) {
    let plane = size * size;
    let (sw, sh) = (
        (v.width() as f32 * scale) as usize,
        (v.height() as f32 * scale) as usize,
    );
    for y in 0..sh.min(size) {
        for x in 0..sw.min(size) {
            let p = v.sample_bilinear(x as f32 / scale, y as f32 / scale);
            let o = y * size + x;
            t[o] = p[2];
            t[plane + o] = p[1];
            t[2 * plane + o] = p[0];
        }
    }
}

fn main() {
    let w: usize = std::env::args()
        .nth(1)
        .and_then(|s| s.parse().ok())
        .unwrap_or(640);
    let h: usize = std::env::args()
        .nth(2)
        .and_then(|s| s.parse().ok())
        .unwrap_or(400);
    let grey: Vec<u8> = (0..w * h).map(|i| (i * 37 % 251) as u8).collect();

    let expanded = irlume_camera::grey_to_rgb(&grey);
    let grey_via_rgb = FrameView::Rgb(RgbView {
        data: &expanded,
        width: w as u32,
        height: h as u32,
    });
    let grey_native = FrameView::Grey(Grey8View {
        data: &grey,
        width: w as u32,
        height: h as u32,
    });

    let mut scratch = vec![0.0f32; 3 * LB * LB];
    // Warm up.
    for _ in 0..5 {
        letterbox(
            &grey_via_rgb,
            (LB as f32 / w.max(h) as f32).min(1.0),
            LB,
            &mut scratch,
        );
        letterbox(
            &grey_native,
            (LB as f32 / w.max(h) as f32).min(1.0),
            LB,
            &mut scratch,
        );
    }

    const ITERS: usize = 200;
    let scale = (LB as f32 / w.max(h) as f32).min(1.0);

    let t = Instant::now();
    for _ in 0..ITERS {
        letterbox(&grey_via_rgb, scale, LB, &mut scratch);
    }
    let via_rgb_ms = t.elapsed().as_secs_f64() / ITERS as f64 * 1e3;

    let t = Instant::now();
    for _ in 0..ITERS {
        let e = irlume_camera::grey_to_rgb(&grey);
        std::hint::black_box(&e);
    }
    let expand_ms = t.elapsed().as_secs_f64() / ITERS as f64 * 1e3;

    let t = Instant::now();
    for _ in 0..ITERS {
        letterbox(&grey_native, scale, LB, &mut scratch);
    }
    let native_ms = t.elapsed().as_secs_f64() / ITERS as f64 * 1e3;

    // Correctness cross-check: both paths must produce identical tensors.
    let mut a = vec![0.0f32; 3 * LB * LB];
    let mut b = vec![0.0f32; 3 * LB * LB];
    letterbox(&grey_via_rgb, scale, LB, &mut a);
    letterbox(&grey_native, scale, LB, &mut b);
    let identical = a == b;

    println!("grey frame {w}x{h} -> letterbox {LB}x{LB}, {ITERS} iters:");
    println!("  letterbox via RgbView (expanded) : {via_rgb_ms:.3} ms");
    println!(
        "  grey_to_rgb expansion alone      : {expand_ms:.3} ms ({:.1} MB/frame)",
        (w * h * 3) as f64 / 1e6
    );
    println!("  letterbox via Grey8View (new)    : {native_ms:.3} ms");
    println!(
        "  saved per grey frame             : {:+.3} ms",
        (via_rgb_ms + expand_ms) - native_ms
    );
    println!("  outputs bit-identical            : {identical}");
    if !identical {
        std::process::exit(1);
    }

    // Optional end-to-end: full detect() with the real ONNX model, old path
    // (expand to RGB) vs new (grey view), same frame.
    if let Some(det_path) = std::env::args().nth(3) {
        let mut det = irlume_vision::Detector::load_from_file(&det_path).expect("detector");
        for _ in 0..3 {
            let _ = det.detect(grey_via_rgb.as_rgb().expect("rgb"));
        }
        let t = Instant::now();
        for _ in 0..ITERS {
            let _ = det.detect(grey_via_rgb.as_rgb().expect("rgb"));
        }
        let old_ms = t.elapsed().as_secs_f64() / ITERS as f64 * 1e3;
        let t = Instant::now();
        for _ in 0..ITERS {
            let _ = det.detect_any(&grey_native);
        }
        let new_ms = t.elapsed().as_secs_f64() / ITERS as f64 * 1e3;
        println!("  e2e detect via RGB expansion     : {old_ms:.3} ms");
        println!("  e2e detect via Grey8View (new)   : {new_ms:.3} ms");
        println!(
            "  e2e saved per grey detect        : {:+.3} ms",
            old_ms - new_ms
        );
    }
}

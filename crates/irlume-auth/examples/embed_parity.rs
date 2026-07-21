// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright the irlume contributors.

//! Decisive test for the overlapped-capture change: does the concurrent-load
//! RGB dimming shift the face embedding enough to hurt recognition?
//!
//! Captures the user's face several times in SEQUENTIAL mode and several in
//! CONCURRENT mode (real production denoise path), embeds each with AuraFace,
//! and reports: mean brightness per mode, within-mode self-similarity (the
//! recognition ceiling), and cross-mode similarity (bright-enroll vs dim-auth,
//! the worst case). Cross-mode cosine near the within-mode cosine means the
//! dimming is cosmetic to recognition; a large gap means a train/test skew.
//!
//! Usage: cargo run --release -p irlume-auth --example embed_parity -- \
//!   <det.onnx> <model.onnx> <rgb_dev> <ir_dev> [captures_per_mode]
//! Look at the camera throughout.

use irlume_vision::{align, Detector, Embedder};

fn mean(d: &[u8]) -> f32 {
    if d.is_empty() {
        0.0
    } else {
        d.iter().map(|&b| b as u64).sum::<u64>() as f32 / d.len() as f32
    }
}

fn cosine(a: &[f32], b: &[f32]) -> f32 {
    a.iter().zip(b).map(|(x, y)| x * y).sum::<f32>()
}

/// Capture (concurrent or sequential), detect the top face, align, embed.
fn capture_embed(
    det: &mut Detector,
    emb: &mut Embedder,
    rgb_dev: &str,
    concurrent: bool,
    ir_dev: &str,
) -> Option<(f32, Vec<f32>)> {
    let rgb = if concurrent {
        // Overlap an IR capture to reproduce the real concurrent load.
        let ir_dev = ir_dev.to_string();
        std::thread::scope(|s| {
            let ir_t = s.spawn(move || irlume_camera::capture_ir(&ir_dev));
            let rgb = irlume_camera::capture_rgb_denoised(rgb_dev);
            let _ = ir_t.join();
            rgb
        })
    } else {
        irlume_camera::capture_rgb_denoised(rgb_dev)
    }
    .ok()?;
    let brightness = mean(&rgb.data);
    let view = align::RgbView {
        data: &rgb.data,
        width: rgb.width,
        height: rgb.height,
    };
    let faces = det.detect(&view).ok()?;
    let top = faces.iter().max_by(|a, b| a.score.total_cmp(&b.score))?;
    // Same alignment + TTA embedding the production match path uses.
    let chip = align::align_to_arcface(&view, &top.landmarks).ok()?;
    let e = emb.embed_tta(&chip).ok()?;
    Some((brightness, e.to_vec()))
}

fn avg_pairwise(embs: &[Vec<f32>]) -> f32 {
    let mut sum = 0.0;
    let mut n = 0;
    for i in 0..embs.len() {
        for j in (i + 1)..embs.len() {
            sum += cosine(&embs[i], &embs[j]);
            n += 1;
        }
    }
    if n == 0 {
        0.0
    } else {
        sum / n as f32
    }
}

fn main() {
    let mut a = std::env::args().skip(1);
    let det_p = a.next().expect("det.onnx");
    let model_p = a.next().expect("model.onnx");
    let rgb_dev = a.next().unwrap_or_else(|| "/dev/video0".into());
    let ir_dev = a.next().unwrap_or_else(|| "/dev/video2".into());
    let per: usize = a.next().and_then(|s| s.parse().ok()).unwrap_or(5);

    let mut det = Detector::load_from_file(&det_p).expect("load det");
    let mut emb = Embedder::load_from_file(&model_p).expect("load model");
    println!("embed_parity: rgb={rgb_dev} ir={ir_dev} per-mode={per}\nLook at the camera.\n");

    // Grouped, not alternating: all sequential, then all concurrent. Rapid
    // open/close alternation stresses the UVC re-init in a way the daemon (one
    // capture per login) never does, so grouping is the representative test.
    let mut seq = Vec::new();
    let mut con = Vec::new();
    let (mut seq_b, mut con_b) = (Vec::new(), Vec::new());
    let (mut seq_faces, mut con_faces) = (0usize, 0usize);
    for k in 0..per {
        match capture_embed(&mut det, &mut emb, &rgb_dev, false, &ir_dev) {
            Some((b, e)) => {
                println!("  seq  {k}: brightness {b:.0}, face OK");
                seq_b.push(b);
                seq.push(e);
                seq_faces += 1;
            }
            None => println!("  seq  {k}: no face"),
        }
    }
    for k in 0..per {
        match capture_embed(&mut det, &mut emb, &rgb_dev, true, &ir_dev) {
            Some((b, e)) => {
                println!("  conc {k}: brightness {b:.0}, face OK");
                con_b.push(b);
                con.push(e);
                con_faces += 1;
            }
            None => println!("  conc {k}: no face"),
        }
    }

    let mean = |v: &[f32]| v.iter().sum::<f32>() / v.len().max(1) as f32;
    println!("\nface-detection rate: sequential {seq_faces}/{per}, concurrent {con_faces}/{per}");
    println!(
        "RGB brightness: sequential {:.0}, concurrent {:.0}",
        mean(&seq_b),
        mean(&con_b)
    );
    println!("within-mode cosine (recognition ceiling):");
    println!("  sequential self-similarity:  {:.4}", avg_pairwise(&seq));
    println!("  concurrent self-similarity:  {:.4}", avg_pairwise(&con));
    let mut cross = 0.0;
    let mut n = 0;
    for s in &seq {
        for c in &con {
            cross += cosine(s, c);
            n += 1;
        }
    }
    println!(
        "cross-mode cosine (bright-enroll vs dim-auth, worst case): {:.4}",
        if n == 0 { 0.0 } else { cross / n as f32 }
    );
    println!("\n(A match threshold is ~0.40; genuine pairs typically 0.6-0.9. If cross-mode");
    println!(" sits near the within-mode ceilings, the dimming is cosmetic to recognition.)");
}

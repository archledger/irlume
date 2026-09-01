// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright the irlume contributors.

//! Per-stage CPU cost of the biometric pipeline on SYNTHETIC frames, so the
//! numbers are comparable across hosts with no camera in the loop. Each
//! measurement times the full stage call production would pay, including
//! preprocessing. No gate; the output feeds the optimization roadmap
//! (docs/research/2026-08-22-inference-optimization-dossier.md).
//!
//! Usage: cargo run --release -p irlume-auth --example stage_bench -- \
//!   [models_dir]

use irlume_vision::model_input::{
    ArcFaceInput, CanonicalGreyView, CanonicalRgbView, DetectorInput, FlirIrPadInput,
    VitRgbPadInput,
};
use irlume_vision::{Detector, Embedder, FaceMesh, PadIr, PadVit};
use std::time::Instant;

fn bench(name: &str, warmup: usize, iters: usize, mut call: impl FnMut()) {
    for _ in 0..warmup {
        call();
    }
    let t = Instant::now();
    for _ in 0..iters {
        call();
    }
    let per = t.elapsed().as_secs_f64() / iters as f64 * 1e3;
    println!("{name:<34} {per:8.2} ms");
}

fn main() {
    let dir = std::env::args().nth(1).unwrap_or_else(|| "models".into());
    let p = |n: &str| format!("{dir}/{n}");

    // Deterministic synthetic frames: content only needs to be representative
    // in SIZE and cost; models run the same graph regardless of the verdict.
    let (w, h) = (640_u32, 480_u32);
    let grey: Vec<u8> = (0..(w as usize * h as usize))
        .map(|i| ((i * 7 + i / 13) % 256) as u8)
        .collect();
    let rgb: Vec<u8> = (0..(w as usize * h as usize * 3))
        .map(|i| ((i * 5 + i / 11) % 256) as u8)
        .collect();
    let chip: Vec<u8> = (0..112 * 112 * 3).map(|i| ((i * 3) % 256) as u8).collect();
    let bbox = [200.0_f32, 120.0, 440.0, 360.0];

    let mut det = Detector::load_from_file(&p("face_detection_yunet_2023mar.onnx")).expect("det");
    let mut mesh = FaceMesh::load_from_file(&p("face_landmark.onnx")).expect("mesh");
    let mut embed = Embedder::load_from_file(&p("glintr100.onnx")).expect("embedder");
    let mut vit = PadVit::load_from_file(&p("liveness_vit.onnx")).expect("vit");
    let mut flir = PadIr::load_from_file(&p("flir.onnx")).expect("flir");

    let rgb_view = CanonicalRgbView::try_from_parts(&rgb, w, h).expect("rgb input");
    let grey_view = CanonicalGreyView::try_from_parts(&grey, w, h).expect("grey input");
    let vit_input = VitRgbPadInput::new(rgb_view, bbox);
    let flir_input = FlirIrPadInput::new(grey_view, bbox);
    let mesh_input = mesh.prepare_input(rgb_view, bbox).expect("mesh input");
    let embed_input = ArcFaceInput::try_from_aligned_rgb(chip).expect("embed input");

    // Warm-up one ViT call so its 343 MB of weights are paged in before any
    // timing (the E3 experiment measures the un-warmed spike separately).
    let _ = vit.p_spoof(&vit_input);

    bench("detect grey 640x480 (YuNet)", 10, 100, || {
        let _ = det.detect(&DetectorInput::from_grey(grey_view));
    });
    bench("detect rgb 640x480 (YuNet)", 10, 100, || {
        let _ = det.detect(&DetectorInput::from_rgb(rgb_view));
    });
    bench("landmarks (face_landmark)", 10, 200, || {
        let _ = mesh.landmarks(&mesh_input);
    });
    bench("embed 112x112 (glintr100)", 10, 200, || {
        let _ = embed.embed(&embed_input);
    });
    bench("PAD ViT 224 (liveness_vit)", 3, 30, || {
        let _ = vit.p_spoof(&vit_input);
    });
    bench("PAD FLIR 112 (flir)", 10, 200, || {
        let _ = flir.p_fake(&flir_input);
    });
}

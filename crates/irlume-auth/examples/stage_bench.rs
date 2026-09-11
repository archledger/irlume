// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright the irlume contributors.

//! Synthetic full model-call costs, including production preprocessing.
//! No camera, authentication, or latency gate. See docs/research/benchmark-harness.md.

#[path = "benchmark_support/identity.rs"]
mod identity;
#[path = "benchmark_support/sampling.rs"]
mod sampling;

use irlume_vision::align::{FrameView, Grey8View, RgbView};
use irlume_vision::{Detector, Embedder, FaceMesh, PadIr, PadVit};
use std::hint::black_box;
use std::num::NonZeroUsize;
use std::path::{Path, PathBuf};

const HELP: &str = "Usage: stage_bench [models_dir [samples [warmup]]]\nDefaults: models 100 10; samples must be positive.\nSynthetic model calls only; p50/p95 are not login latency.\nModel overrides: IRLUME_DET_MODEL, IRLUME_MODEL, IRLUME_MESH_MODEL, IRLUME_VIT_PAD_MODEL, IRLUME_PAD_IR_MODEL.\nMesh default: face_landmarks_detector.tflite (production native backend).";

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args: Vec<_> = std::env::args().skip(1).collect();
    if args.iter().any(|arg| arg == "--help" || arg == "-h") {
        println!("{HELP}");
        return Ok(());
    }
    if args.len() > 3 {
        return Err(HELP.into());
    }
    let dir = args.first().map_or(Path::new("models"), Path::new);
    let samples = args
        .get(1)
        .map_or(Ok(100), |s| s.parse::<NonZeroUsize>().map(usize::from))?;
    let warmup = args.get(2).map_or(Ok(10), |s| s.parse::<usize>())?;
    let path = |key, name| std::env::var_os(key).map_or_else(|| dir.join(name), PathBuf::from);
    let paths = [
        path("IRLUME_DET_MODEL", "face_detection_yunet_2023mar.onnx"),
        path("IRLUME_MESH_MODEL", "face_landmarks_detector.tflite"),
        path("IRLUME_MODEL", "glintr100.onnx"),
        path("IRLUME_VIT_PAD_MODEL", "liveness_vit.onnx"),
        path("IRLUME_PAD_IR_MODEL", "flir.onnx"),
    ];
    let names: Vec<_> = paths
        .iter()
        .map(|p| p.to_str().ok_or("model path must be UTF-8"))
        .collect::<Result<_, _>>()?;
    identity::header("synthetic independent model calls; not summed pipeline or login latency");
    let mut det = identity::construct("detector", || Detector::load_from_file(names[0]))?;
    let mut mesh = identity::construct("mesh", || FaceMesh::load_from_file(names[1]))?;
    let mut embed = identity::construct("recognizer", || Embedder::load_from_file(names[2]))?;
    let mut vit = identity::construct("rgb_pad", || PadVit::load_from_file(names[3]))?;
    let mut flir = identity::construct("ir_pad", || PadIr::load_from_file(names[4]))?;
    for (label, path) in ["detector", "mesh", "recognizer", "rgb_pad", "ir_pad"]
        .iter()
        .zip(&paths)
    {
        identity::file(label, path)?;
    }
    identity::runtimes()?;

    let (w, h) = (640_u32, 480_u32);
    let grey: Vec<u8> = (0..(w as usize * h as usize))
        .map(|i| ((i * 7 + i / 13) % 256) as u8)
        .collect();
    let rgb: Vec<u8> = (0..(w as usize * h as usize * 3))
        .map(|i| ((i * 5 + i / 11) % 256) as u8)
        .collect();
    let chip: Vec<u8> = (0..112 * 112 * 3).map(|i| ((i * 3) % 256) as u8).collect();
    let bbox = [200.0_f32, 120.0, 440.0, 360.0];
    let rgb_view = RgbView {
        data: &rgb,
        width: w,
        height: h,
    };
    let grey_view = FrameView::Grey(Grey8View {
        data: &grey,
        width: w,
        height: h,
    });
    let rgb_frame = FrameView::Rgb(RgbView {
        data: &rgb,
        width: w,
        height: h,
    });
    println!("input=deterministic-pattern-v1 frame=640x480 chip=112x112 bbox={bbox:?}; no-face results are valid inference samples");

    macro_rules! bench {
        ($name:expr, $call:expr) => {
            sampling::measure($name, warmup, samples, $call, |_, _| {})?
                .print($name, warmup, samples);
        };
    }
    bench!("detect grey 640x480", || det
        .detect_any(black_box(&grey_view)));
    bench!("detect rgb 640x480", || det
        .detect_any(black_box(&rgb_frame)));
    bench!("mesh landmarks", || mesh.landmarks(
        black_box(&rgb_view),
        black_box(&bbox),
        0.25
    ));
    bench!("embed single 112x112", || embed.embed(black_box(&chip)));
    bench!("embed RGB TTA 112x112", || embed
        .embed_tta(black_box(&chip)));
    bench!("PAD RGB ViT", || vit
        .p_spoof(black_box(&rgb_view), black_box(&bbox)));
    bench!("PAD IR FLIR", || flir
        .p_fake(black_box(&rgb_view), black_box(&bbox)));
    Ok(())
}

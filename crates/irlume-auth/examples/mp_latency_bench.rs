// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright the irlume contributors.

//! Latency bench for the MediaPipe-family models irlume ships or evaluates,
//! ONNX (ort) against the bundled native TFLite runtime, on one real frame.
//!
//! Numbers are machine-dependent and carry no gate; the point is the
//! RELATIVE cost of the runtimes and the native threads knob, which the
//! native-mesh switch decision needs. Each measurement times the full stage
//! call production would pay (preprocessing included).
//!
//! Usage: cargo run --release -p irlume-auth --example mp_latency_bench -- \
//!   <yunet.onnx> <face_landmark.onnx> <blaze_face_short_range.onnx> \
//!   <blaze_face_short_range.tflite> <blaze_face_full_range.tflite> \
//!   <face_landmarks_detector.tflite> <frame.ppm>

use irlume_vision::blaze_full::FullRangeBlaze;
use irlume_vision::model_input::{
    BlazeFaceInput, CanonicalRgbView, DetectorInput, FaceMeshMeasurementInput,
    FullRangeBlazeFaceInput, ModelInputContractId,
};
use irlume_vision::tflite::TfliteSession;
use irlume_vision::{
    decode_short_range_best, map_checked_mesh_output, BlazeRescue, Detector, FaceMesh,
    BLAZE_SCORE_THRESHOLD, MESH_N_IRIS,
};
use std::path::Path;
use std::time::Instant;

const SHIPPED_DETECTOR_SHA256: &str =
    "8f2383e4dd3cfbb4553ea8718107fc0423210dc964f9f4280604804ed2552fa4";
const SHIPPED_MESH_SHA256: &str =
    "821683be088447839638f79d64268bd501bdb72e5d9e262ec981c7e252956caf";
const SHIPPED_BLAZE_ONNX_SHA256: &str =
    "c5453678015f6289c1d77bda88a8ba9c87574f01de1a05ba1909b9a7e08b237b";
const NATIVE_BLAZE_SHA256: &str =
    "b4578f35940bf5a1a655214a1cce5cab13eba73c1297cd78e1a04c2380b0152f";
const LANDMARKER_MESH_SHA256: &str =
    "c7d54204ce0448474c7f3fa9af494787c0965cbdd6f20fc72867e43046bd43d5";
const WARMUP: usize = 10;
const ITERS: usize = 100;

fn read_pnm(p: &Path) -> Option<(Vec<u8>, u32, u32)> {
    let data = std::fs::read(p).ok()?;
    let text = String::from_utf8_lossy(&data[..data.len().min(64)]);
    let mut it = text.split_ascii_whitespace();
    let magic = it.next()?;
    let w: usize = it.next()?.parse().ok()?;
    let h: usize = it.next()?.parse().ok()?;
    let max: usize = it.next()?.parse().ok()?;
    if max != 255 {
        return None;
    }
    let (mut seen, mut fields) = (0usize, 0);
    let mut off = 0;
    for (i, b) in data.iter().enumerate() {
        if b.is_ascii_whitespace() {
            if seen > 0 {
                fields += 1;
                seen = 0;
                if fields == 4 {
                    off = i + 1;
                    break;
                }
            }
        } else {
            seen += 1;
        }
    }
    match magic {
        "P6" if data.len() >= off + w * h * 3 => {
            Some((data[off..off + w * h * 3].to_vec(), w as u32, h as u32))
        }
        "P5" if data.len() >= off + w * h => Some((
            irlume_camera::grey_to_rgb(&data[off..off + w * h]),
            w as u32,
            h as u32,
        )),
        _ => None,
    }
}

fn read_pinned(path: &str, expected: &str, label: &str) -> Vec<u8> {
    let bytes = std::fs::read(path).unwrap_or_else(|e| panic!("{path}: read {label}: {e}"));
    let actual = irlume_common::sha256_hex(&bytes);
    assert_eq!(actual, expected, "{path}: not the pinned {label}");
    bytes
}

/// Time `f` and print a CSV row. The result of every iteration is consumed
/// and its face-presence asserted by the caller beforehand, so the closure
/// cannot be optimized into measuring nothing.
fn bench(stage: &str, model: &str, runtime: &str, threads: usize, mut f: impl FnMut()) {
    for _ in 0..WARMUP {
        f();
    }
    let mut ms: Vec<f64> = (0..ITERS)
        .map(|_| {
            let t = Instant::now();
            f();
            t.elapsed().as_secs_f64() * 1e3
        })
        .collect();
    ms.sort_by(f64::total_cmp);
    let mean = ms.iter().sum::<f64>() / ms.len() as f64;
    println!(
        "{stage},{model},{runtime},{threads},{mean:.3},{:.3},{:.3}",
        ms[ITERS / 2],
        ms[ITERS * 95 / 100]
    );
}

fn native_mesh_run(mesh: &mut TfliteSession, input: &FaceMeshMeasurementInput) -> Vec<(f32, f32)> {
    let outputs = mesh.run_f32(input.tensor()).expect("native mesh run");
    let raw = outputs
        .iter()
        .map(|(_, d)| d)
        .find(|d| d.len() == MESH_N_IRIS * 3)
        .expect("478-landmark output");
    let (x0, y0, side) = input.crop();
    map_checked_mesh_output(raw, input.input_side() as f32, x0, y0, side).expect("plausible mesh")
}

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let [yunet_path, mesh_onnx_path, blaze_onnx_path, blaze_tfl_path, full_tfl_path, mesh_tfl_path, frame_path] =
        args.as_slice()
    else {
        panic!(
            "usage: mp_latency_bench <yunet.onnx> <face_landmark.onnx> \
             <blaze_short.onnx> <blaze_short.tflite> <blaze_full_range.tflite> \
             <face_landmarks_detector.tflite> <frame.ppm>"
        );
    };

    let (data, w, h) = read_pnm(Path::new(frame_path)).expect("read frame");
    let side = w.max(h) as f32;

    let yunet_bytes = read_pinned(yunet_path, SHIPPED_DETECTOR_SHA256, "detector");
    let mut yunet = Detector::load_from_memory(&yunet_bytes).expect("load yunet");
    let mesh_onnx_bytes = read_pinned(mesh_onnx_path, SHIPPED_MESH_SHA256, "ONNX mesh");
    let mut mesh_onnx = FaceMesh::load_from_memory(&mesh_onnx_bytes).expect("load onnx mesh");
    let blaze_onnx_bytes = read_pinned(
        blaze_onnx_path,
        SHIPPED_BLAZE_ONNX_SHA256,
        "ONNX short blaze",
    );
    let mut blaze_onnx = BlazeRescue::load_from_memory(&blaze_onnx_bytes).expect("load onnx blaze");
    let blaze_tfl_bytes = std::fs::read(blaze_tfl_path).expect("read tflite blaze");
    let full_bytes = std::fs::read(full_tfl_path).expect("read fullrange");
    let mut full = FullRangeBlaze::from_pinned_bytes(&full_bytes).expect("load fullrange");
    let mesh_tfl_bytes = std::fs::read(mesh_tfl_path).expect("read tflite mesh");

    // The frame must actually carry a face: a mesh timed on a non-face crop
    // or a detector timed into its miss path measures a different code path.
    let model_view = CanonicalRgbView::try_from_parts(&data, w, h).expect("valid input");
    let detector_input = DetectorInput::from_rgb(model_view);
    let blaze_input = BlazeFaceInput::new(model_view);
    let full_blaze_input = FullRangeBlazeFaceInput::new(model_view);
    let faces = yunet.detect(&detector_input).expect("detect");
    let top = faces
        .iter()
        .max_by(|a, b| a.score.total_cmp(&b.score))
        .cloned()
        .expect("bench frame must contain a face");
    assert!(
        blaze_onnx
            .detect_top(&blaze_input)
            .expect("onnx blaze detect")
            .is_some(),
        "bench frame must clear the short-range threshold"
    );
    let anchors = irlume_vision::blaze_anchors();

    println!("stage,model,runtime,threads,mean_ms,p50_ms,p95_ms");
    bench("detection", "yunet", "ort", 0, || {
        let f = yunet.detect(&detector_input).expect("detect");
        assert!(!f.is_empty());
    });
    bench("detection-rescue", "blaze_short", "ort", 0, || {
        let r = blaze_onnx.detect_top(&blaze_input).expect("onnx blaze");
        assert!(r.is_some());
    });
    for threads in [1i32, 2, 4] {
        let mut s =
            TfliteSession::from_pinned_bytes(&blaze_tfl_bytes, NATIVE_BLAZE_SHA256, threads)
                .expect("load native blaze");
        bench(
            "detection-rescue",
            "blaze_short",
            "tflite",
            threads as usize,
            || {
                let outputs = s.run_f32(blaze_input.tensor()).expect("native blaze");
                let (mut reg, mut cls): (Option<&Vec<f32>>, Option<&Vec<f32>>) = (None, None);
                for (_, raw) in &outputs {
                    match raw.len() {
                        l if l == 896 * 16 => reg = Some(raw),
                        896 => cls = Some(raw),
                        _ => {}
                    }
                }
                let r = decode_short_range_best(
                    reg.expect("reg"),
                    cls.expect("cls"),
                    &anchors,
                    BLAZE_SCORE_THRESHOLD,
                );
                assert!(r.map(|(b, _)| b[0] * side).is_some());
            },
        );
    }
    bench("detection-rescue", "blaze_full_range", "tflite", 2, || {
        let r = full.detect_top(&full_blaze_input).expect("fullrange");
        assert!(r.is_some());
    });
    bench("landmarks", "face_landmark_468", "ort", 0, || {
        let mesh_input = mesh_onnx
            .prepare_input(model_view, top.bbox)
            .expect("mesh input");
        let lm = mesh_onnx.landmarks(&mesh_input).expect("onnx mesh");
        assert!(!lm.is_empty());
    });
    for threads in [1i32, 2, 4] {
        let mut s =
            TfliteSession::from_pinned_bytes(&mesh_tfl_bytes, LANDMARKER_MESH_SHA256, threads)
                .expect("load native mesh");
        let shape = s.input_shape().expect("mesh shape");
        let mesh_contract = match shape.as_slice() {
            [1, 192, 192, 3] => ModelInputContractId::FaceMesh192RgbV1,
            [1, 256, 256, 3] => ModelInputContractId::FaceMesh256RgbV1,
            _ => panic!("unsupported native FaceMesh input shape {shape:?}"),
        };
        bench(
            "landmarks",
            "face_landmarks_478",
            "tflite",
            threads as usize,
            || {
                let input = FaceMeshMeasurementInput::new(model_view, top.bbox, mesh_contract)
                    .expect("native mesh input");
                let lm = native_mesh_run(&mut s, &input);
                assert!(lm.len() >= MESH_N_IRIS);
            },
        );
    }
}

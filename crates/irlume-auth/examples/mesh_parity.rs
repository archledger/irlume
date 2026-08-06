// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright the irlume contributors.

//! Mesh parity harness: does the shipped `face_landmark.onnx` (a conversion)
//! say the same thing as Google's `face_landmarks_detector.tflite` (from the
//! published face_landmarker.task, sha256 pinned below) run natively on the
//! bundled TFLite runtime?
//!
//! The question has never been asked with a real method: the ONNX file is
//! what irlume ships, the .tflite is what Google publishes, and until #295
//! there was no way to run the latter unconverted. Both meshes run in ONE
//! process here, on the SAME detector box and the SAME square crop with the
//! same [0,1] NHWC pre-processing, so any difference left is the models',
//! not the harness's.
//!
//! Emits one CSV row per frame; a frame where either mesh declines (no
//! detection, implausible output) carries empty metric fields rather than
//! being dropped, so the downstream bound check sees the full denominator
//! (#298: a dump that silently shrinks turns the comparison into a vacuous
//! pass over whatever survived).
//!
//! Comparison is over the first 468 landmarks (the shared topology; the
//! landmarker-generation model appends 10 iris points) and over x,y only,
//! because x,y is what every irlume consumer reads. NME is normalized by the
//! native mesh's outer-eye distance (canonical indices 33 and 263).
//!
//! Usage: cargo run --release -p irlume-auth --example mesh_parity -- \
//!   <yunet.onnx> <face_landmark.onnx> <face_landmarks_detector.tflite> \
//!   <corpus_root>... > mesh-parity.csv
//!   (IRLUME_TFLITE_LIB overrides the packaged libtensorflowlite_c.so)

use irlume_vision::align::RgbView;
use irlume_vision::tflite::TfliteSession;
use irlume_vision::{map_checked_mesh_output, Detector, FaceMesh, MESH_N, MESH_N_IRIS};
use std::path::Path;

/// The published face_landmarker.task's mesh, May 2023 revision. The pin is
/// the whole point of running through `TfliteSession::from_pinned_bytes`: a
/// silently different file must fail, not measure.
const LANDMARKER_MESH_SHA256: &str =
    "c7d54204ce0448474c7f3fa9af494787c0965cbdd6f20fc72867e43046bd43d5";

/// Same margin the authentication path passes to `FaceMesh::landmarks`.
const MESH_MARGIN: f32 = 0.25;

/// Outer eye corners in the MediaPipe face mesh topology, the standard NME
/// normalizer for it.
const LEFT_EYE_OUTER: usize = 33;
const RIGHT_EYE_OUTER: usize = 263;

fn read_pnm(p: &Path) -> Option<(Vec<u8>, u32, u32)> {
    // Same lossy header parse as blaze_full_parity: the bytes after the
    // header are pixels, not UTF-8.
    let data = std::fs::read(p).ok()?;
    let text = String::from_utf8_lossy(&data[..data.len().min(64)]);
    let mut it = text.split_ascii_whitespace();
    let magic = it.next()?;
    let w: usize = it.next()?.parse().ok()?;
    let h: usize = it.next()?.parse().ok()?;
    let _max: usize = it.next()?.parse().ok()?;
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

/// The native mesh over the SAME crop `FaceMesh::landmarks` uses: identical
/// x0/y0/side arithmetic, identical bilinear sampling, identical [0,1]
/// normalization, and the shared `map_checked_mesh_output` on the way back,
/// so the two runs differ in nothing but the weights.
fn native_landmarks(
    mesh: &mut TfliteSession,
    input_side: usize,
    frame: &RgbView,
    bbox: &[f32; 4],
) -> Result<Vec<(f32, f32)>, String> {
    let (cx, cy) = ((bbox[0] + bbox[2]) * 0.5, (bbox[1] + bbox[3]) * 0.5);
    let half = 0.5 * (bbox[2] - bbox[0]).max(bbox[3] - bbox[1]) * (1.0 + 2.0 * MESH_MARGIN);
    // Instrument self-test: MESH_PARITY_SKEW_PX shifts ONLY the native crop,
    // so a run with it set must report a clearly nonzero NME. A comparison
    // that stays at zero under a known injected difference is measuring
    // nothing (the harness equivalent of a test that cannot fail).
    let skew: f32 = std::env::var("MESH_PARITY_SKEW_PX")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(0.0);
    let (x0, y0) = (cx - half + skew, cy - half);
    let side = 2.0 * half;
    let n = input_side;
    let mut data = vec![0.0f32; n * n * 3];
    for oy in 0..n {
        for ox in 0..n {
            let sx = x0 + (ox as f32 + 0.5) / n as f32 * side;
            let sy = y0 + (oy as f32 + 0.5) / n as f32 * side;
            let p = frame.sample_bilinear(sx, sy);
            let i = (oy * n + ox) * 3;
            data[i] = p[0] / 255.0;
            data[i + 1] = p[1] / 255.0;
            data[i + 2] = p[2] / 255.0;
        }
    }
    let outputs = mesh.run_f32(&data).map_err(|e| e.to_string())?;
    let raw = outputs
        .iter()
        .map(|(_, d)| d)
        .find(|d| d.len() == MESH_N * 3 || d.len() == MESH_N_IRIS * 3)
        .ok_or_else(|| format!("no {MESH_N}/{MESH_N_IRIS}-landmark output"))?;
    map_checked_mesh_output(raw, input_side as f32, x0, y0, side)
}

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let (models, roots) = args.split_at(3.min(args.len()));
    let [det_path, onnx_mesh_path, tflite_mesh_path] = models else {
        panic!(
            "usage: mesh_parity <yunet.onnx> <face_landmark.onnx> \
             <face_landmarks_detector.tflite> <corpus_root>..."
        );
    };
    assert!(!roots.is_empty(), "at least one corpus root is required");

    let mut det = Detector::load_from_file(det_path).expect("load detector");
    let mut onnx_mesh = FaceMesh::load_from_file(onnx_mesh_path).expect("load onnx mesh");
    let tflite_bytes = std::fs::read(tflite_mesh_path).expect("read tflite mesh");
    let mut native = TfliteSession::from_pinned_bytes(&tflite_bytes, LANDMARKER_MESH_SHA256, 1)
        .expect("load native mesh");
    let shape = native.input_shape().expect("native input shape");
    // NHWC [1, S, S, 3] with a square S: anything else is a different model
    // generation and the crop math below would silently distort it.
    assert!(
        shape.len() == 4 && shape[1] == shape[2] && shape[3] == 3,
        "unexpected native input shape {shape:?}"
    );
    let native_side = shape[1];
    eprintln!("native mesh input {native_side}x{native_side}");

    let mut emitted = 0usize;
    let mut compared = 0usize;
    let (mut nme_sum, mut nme_max) = (0.0f64, 0.0f64);
    let (mut total_identical, mut total_points) = (0usize, 0usize);
    println!("camera,segment,kind,frame,eye_px,nme,max_px");
    for root in roots {
        let root = Path::new(root);
        let cam = root
            .file_name()
            .expect("corpus root must have a name")
            .to_string_lossy()
            .into_owned();
        let mut segs: Vec<_> = std::fs::read_dir(root)
            .unwrap_or_else(|e| panic!("{}: read corpus root: {e}", root.display()))
            .map(|e| e.unwrap_or_else(|e| panic!("{}: read entry: {e}", root.display())))
            .filter(|e| e.path().is_dir())
            .collect();
        assert!(!segs.is_empty(), "{}: no segments", root.display());
        segs.sort_by_key(|e| e.file_name());
        for seg in segs {
            for (sub, kind) in [("rgb", "rgb"), ("ir", "ir")] {
                let dir = seg.path().join(sub);
                let mut files: Vec<_> = std::fs::read_dir(&dir)
                    .unwrap_or_else(|e| panic!("{}: read frame dir: {e}", dir.display()))
                    .map(|e| e.unwrap_or_else(|e| panic!("{}: read entry: {e}", dir.display())))
                    .map(|e| e.path())
                    .filter(|p| p.extension().is_some_and(|e| e == "ppm" || e == "pgm"))
                    .collect();
                assert!(!files.is_empty(), "{}: no PNM frames", dir.display());
                files.sort();
                for f in files {
                    let (data, w, h) =
                        read_pnm(&f).unwrap_or_else(|| panic!("{}: invalid PNM", f.display()));
                    let view = RgbView {
                        data: &data,
                        width: w,
                        height: h,
                    };
                    let seg_name = seg.file_name().to_string_lossy().into_owned();
                    let name = format!("{sub}/{}", f.file_name().unwrap().to_string_lossy());
                    emitted += 1;
                    let faces = det
                        .detect(&view)
                        .unwrap_or_else(|e| panic!("{}: detect: {e}", f.display()));
                    let top = faces
                        .iter()
                        .max_by(|a, b| a.score.total_cmp(&b.score))
                        .cloned();
                    let Some(top) = top else {
                        println!("{cam},{seg_name},{kind},{name},,,");
                        continue;
                    };
                    let a = onnx_mesh.landmarks(&view, &top.bbox, MESH_MARGIN);
                    let b = native_landmarks(&mut native, native_side, &view, &top.bbox);
                    let (Ok(a), Ok(b)) = (a, b) else {
                        // One side declining is a finding, not a crash: the
                        // row stays, the metrics are empty, the bound script
                        // counts it.
                        println!("{cam},{seg_name},{kind},{name},,,");
                        continue;
                    };
                    let n = a.len().min(b.len()).min(MESH_N);
                    let (ex, ey) = (
                        b[LEFT_EYE_OUTER].0 - b[RIGHT_EYE_OUTER].0,
                        b[LEFT_EYE_OUTER].1 - b[RIGHT_EYE_OUTER].1,
                    );
                    let eye = (ex * ex + ey * ey).sqrt();
                    if eye < 1.0 {
                        println!("{cam},{seg_name},{kind},{name},{eye:.1},,");
                        continue;
                    }
                    let mut sum = 0.0f64;
                    let mut worst = 0.0f64;
                    let mut identical = 0usize;
                    for k in 0..n {
                        let dx = (a[k].0 - b[k].0) as f64;
                        let dy = (a[k].1 - b[k].1) as f64;
                        let d = (dx * dx + dy * dy).sqrt();
                        sum += d;
                        worst = worst.max(d);
                        if a[k] == b[k] {
                            identical += 1;
                        }
                    }
                    total_identical += identical;
                    total_points += n;
                    let nme = sum / n as f64 / eye as f64;
                    compared += 1;
                    nme_sum += nme;
                    nme_max = nme_max.max(nme);
                    println!("{cam},{seg_name},{kind},{name},{eye:.1},{nme:.3e},{worst:.4}");
                }
            }
        }
    }
    assert!(emitted > 0, "parity corpus produced zero frames");
    assert!(
        compared > 0,
        "zero frames where both meshes ran; nothing was compared"
    );
    eprintln!(
        "emitted {emitted} rows; both-ran {compared}; mean NME {:.3e}; worst NME {nme_max:.3e}; \
         bit-identical points {total_identical}/{total_points}",
        nme_sum / compared as f64
    );
}

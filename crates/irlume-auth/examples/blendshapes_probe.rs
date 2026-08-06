// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright the irlume contributors.

//! Probe for the face_blendshapes.tflite model inside Google's published
//! face_landmarker.task: run it natively over the stage-3 corpus and put its
//! eye-closure coefficients next to irlume's production EAR cue.
//!
//! The model takes 146 of the landmarker-generation mesh's 478 points as
//! [1, 146, 2] pixel coordinates and returns 52 expression coefficients
//! (ARKit blendshape order; index 9/10 = eyeBlinkLeft/Right). The subset
//! includes the 10 iris points (468-477), so the shipped 468-point ONNX
//! mesh CANNOT feed it: this probe runs the native landmarker mesh, and any
//! production use would require the native-mesh switch first.
//!
//! Index list and tensor convention read from
//! mediapipe/tasks/cc/vision/face_landmarker/face_blendshapes_graph.cc
//! (LandmarksToTensorCalculator attributes X,Y, flatten false, landmarks
//! denormalized by image size).
//!
//! Usage: cargo run --release -p irlume-auth --example blendshapes_probe -- \
//!   <yunet.onnx> <face_landmarks_detector.tflite> <face_blendshapes.tflite> \
//!   <corpus_root>... > blendshapes-probe.csv

use irlume_vision::align::RgbView;
use irlume_vision::tflite::TfliteSession;
use irlume_vision::{eye_ear, map_checked_mesh_output, Detector, EAR_LEFT, EAR_RIGHT, MESH_N_IRIS};
use std::path::Path;

/// Pins: repository YuNet, the face_landmarker.task's mesh (mesh_parity's
/// pin), and the task's blendshapes model (unpacked 2026-08-06).
const SHIPPED_DETECTOR_SHA256: &str =
    "8f2383e4dd3cfbb4553ea8718107fc0423210dc964f9f4280604804ed2552fa4";
const LANDMARKER_MESH_SHA256: &str =
    "c7d54204ce0448474c7f3fa9af494787c0965cbdd6f20fc72867e43046bd43d5";
const BLENDSHAPES_SHA256: &str = "4f36dded049db18d76048567439b2a7f58f1daabc00d78bfe8f3ad396a2d2082";

/// Same margin the authentication path passes to `FaceMesh::landmarks`.
const MESH_MARGIN: f32 = 0.25;

/// The 146-landmark subset the blendshapes model eats, in feed order
/// (kLandmarksSubsetIdxs in face_blendshapes_graph.cc). The tail 468-477 is
/// the iris block only the landmarker-generation mesh emits.
const SUBSET: [usize; 146] = [
    0, 1, 4, 5, 6, 7, 8, 10, 13, 14, 17, 21, 33, 37, 39, 40, 46, 52, 53, 54, 55, 58, 61, 63, 65,
    66, 67, 70, 78, 80, 81, 82, 84, 87, 88, 91, 93, 95, 103, 105, 107, 109, 127, 132, 133, 136,
    144, 145, 146, 148, 149, 150, 152, 153, 154, 155, 157, 158, 159, 160, 161, 162, 163, 168, 172,
    173, 176, 178, 181, 185, 191, 195, 197, 234, 246, 249, 251, 263, 267, 269, 270, 276, 282, 283,
    284, 285, 288, 291, 293, 295, 296, 297, 300, 308, 310, 311, 312, 314, 317, 318, 321, 323, 324,
    332, 334, 336, 338, 356, 361, 362, 365, 373, 374, 375, 377, 378, 379, 380, 381, 382, 384, 385,
    386, 387, 388, 389, 390, 397, 398, 400, 402, 405, 409, 415, 454, 466, 468, 469, 470, 471, 472,
    473, 474, 475, 476, 477,
];

/// ARKit-order output indices this probe reports.
const IDX_EYE_BLINK_LEFT: usize = 9;
const IDX_EYE_BLINK_RIGHT: usize = 10;
const IDX_JAW_OPEN: usize = 25;
const IDX_BROW_INNER_UP: usize = 3;

/// Corpus baseline: 512 frames emitted; the compared count is pinned after
/// the first measured run so a silently shrinking denominator fails (#306).
const EXPECTED_EMITTED: usize = 512;
/// Matches mesh_parity's 223: same detector, same crop, same acceptance.
const EXPECTED_COMPARED: usize = 223;

fn read_pnm(p: &Path) -> Option<(Vec<u8>, u32, u32)> {
    // Same lossy header parse as mesh_parity: the bytes after the header are
    // pixels, not UTF-8. 8-bit only.
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

/// The native landmarker mesh over the same crop `FaceMesh::landmarks`
/// uses (mesh_parity's arithmetic, unskewed).
fn native_landmarks(
    mesh: &mut TfliteSession,
    input_side: usize,
    frame: &RgbView,
    bbox: &[f32; 4],
) -> Result<Vec<(f32, f32)>, String> {
    let (cx, cy) = ((bbox[0] + bbox[2]) * 0.5, (bbox[1] + bbox[3]) * 0.5);
    let half = 0.5 * (bbox[2] - bbox[0]).max(bbox[3] - bbox[1]) * (1.0 + 2.0 * MESH_MARGIN);
    let (x0, y0) = (cx - half, cy - half);
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
        .find(|d| d.len() == MESH_N_IRIS * 3)
        .ok_or_else(|| format!("no {MESH_N_IRIS}-landmark output"))?;
    map_checked_mesh_output(raw, input_side as f32, x0, y0, side)
}

fn read_pinned(path: &str, expected: &str, label: &str) -> Vec<u8> {
    let bytes = std::fs::read(path).unwrap_or_else(|e| panic!("{path}: read {label}: {e}"));
    let actual = irlume_common::thirdparty::sha256_hex(&bytes);
    assert_eq!(actual, expected, "{path}: not the pinned {label}");
    bytes
}

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let (models, roots) = args.split_at(3.min(args.len()));
    let [det_path, mesh_path, blend_path] = models else {
        panic!(
            "usage: blendshapes_probe <yunet.onnx> <face_landmarks_detector.tflite> \
             <face_blendshapes.tflite> <corpus_root>..."
        );
    };
    assert!(!roots.is_empty(), "at least one corpus root is required");

    let det_bytes = read_pinned(det_path, SHIPPED_DETECTOR_SHA256, "detector");
    let mut det = Detector::load_from_memory(&det_bytes).expect("load detector");
    let mesh_bytes = std::fs::read(mesh_path).expect("read tflite mesh");
    let mut mesh = TfliteSession::from_pinned_bytes(&mesh_bytes, LANDMARKER_MESH_SHA256, 1)
        .expect("load native mesh");
    let blend_bytes = std::fs::read(blend_path).expect("read blendshapes model");
    let mut blend = TfliteSession::from_pinned_bytes(&blend_bytes, BLENDSHAPES_SHA256, 1)
        .expect("load blendshapes");
    let mesh_shape = mesh.input_shape().expect("mesh input shape");
    assert!(
        mesh_shape.len() == 4 && mesh_shape[1] == mesh_shape[2] && mesh_shape[3] == 3,
        "unexpected mesh input shape {mesh_shape:?}"
    );
    let mesh_side = mesh_shape[1];
    assert_eq!(
        blend.input_shape().expect("blendshapes input shape"),
        vec![1, SUBSET.len(), 2],
        "unexpected blendshapes input shape"
    );
    eprintln!(
        "detector_sha256={SHIPPED_DETECTOR_SHA256} mesh_sha256={LANDMARKER_MESH_SHA256} \
         blendshapes_sha256={BLENDSHAPES_SHA256}"
    );

    let mut emitted = 0usize;
    let mut compared = 0usize;
    // (ear_min, blink_max) pairs for the summary correlation.
    let mut pairs: Vec<(f64, f64)> = Vec::new();
    println!("camera,segment,kind,frame,ear_left,ear_right,blink_left,blink_right,jaw_open,brow_inner_up");
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
                        println!("{cam},{seg_name},{kind},{name},,,,,,");
                        continue;
                    };
                    let lm = match native_landmarks(&mut mesh, mesh_side, &view, &top.bbox) {
                        Ok(lm) => lm,
                        Err(_) => {
                            // One stage declining is a finding, not a crash.
                            println!("{cam},{seg_name},{kind},{name},,,,,,");
                            continue;
                        }
                    };
                    assert!(lm.len() >= MESH_N_IRIS, "mesh returned {} points", lm.len());
                    let mut input = Vec::with_capacity(SUBSET.len() * 2);
                    for &i in &SUBSET {
                        input.push(lm[i].0);
                        input.push(lm[i].1);
                    }
                    let outputs = blend
                        .run_f32(&input)
                        .unwrap_or_else(|e| panic!("{}: blendshapes: {e}", f.display()));
                    let scores = outputs
                        .iter()
                        .map(|(_, d)| d)
                        .find(|d| d.len() == 52)
                        .unwrap_or_else(|| panic!("{}: no 52-score output", f.display()));
                    assert!(
                        scores.iter().all(|v| v.is_finite()),
                        "{}: non-finite blendshape",
                        f.display()
                    );
                    let ear_l = eye_ear(&lm, &EAR_LEFT);
                    let ear_r = eye_ear(&lm, &EAR_RIGHT);
                    let (bl, br) = (scores[IDX_EYE_BLINK_LEFT], scores[IDX_EYE_BLINK_RIGHT]);
                    compared += 1;
                    pairs.push((ear_l.min(ear_r) as f64, bl.max(br) as f64));
                    println!(
                        "{cam},{seg_name},{kind},{name},{ear_l:.4},{ear_r:.4},{bl:.4},{br:.4},{:.4},{:.4}",
                        scores[IDX_JAW_OPEN], scores[IDX_BROW_INNER_UP]
                    );
                }
            }
        }
    }
    // Pearson correlation between per-frame min EAR and max eyeBlink: eye
    // closure narrows EAR and raises eyeBlink, so agreement is NEGATIVE r.
    let n = pairs.len() as f64;
    let (mx, my) = (
        pairs.iter().map(|p| p.0).sum::<f64>() / n,
        pairs.iter().map(|p| p.1).sum::<f64>() / n,
    );
    let (mut sxy, mut sxx, mut syy) = (0.0, 0.0, 0.0);
    for (x, y) in &pairs {
        sxy += (x - mx) * (y - my);
        sxx += (x - mx) * (x - mx);
        syy += (y - my) * (y - my);
    }
    let r = sxy / (sxx.sqrt() * syy.sqrt());
    eprintln!(
        "emitted {emitted} rows; compared {compared}; \
         ear_min mean {mx:.4}; blink_max mean {my:.4}; pearson r {r:.4}"
    );
    assert_eq!(
        emitted, EXPECTED_EMITTED,
        "stage-3 corpus changed; update the pinned baseline deliberately"
    );
    assert_eq!(compared, EXPECTED_COMPARED, "probe coverage changed");
}

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
//! Comparison covers all 478 landmarks, x,y only (x,y is what every irlume
//! consumer reads). Both models emit 478 points; the original #306 run
//! stopped at 468 on the mistaken belief the ONNX conversion lacked the
//! iris tail, which left indices 468-477 (the blendshapes model's input
//! tail) unvalidated. The iris-only worst NME is tracked separately in the
//! summary. NME is normalized by the native mesh's outer-eye distance
//! (canonical indices 33 and 263).
//!
//! Usage: cargo run --release -p irlume-auth --example mesh_parity -- \
//!   <yunet.onnx> <face_landmark.onnx> <face_landmarks_detector.tflite> \
//!   <corpus_root>... > mesh-parity.csv
//!   (IRLUME_TFLITE_LIB overrides the packaged libtensorflowlite_c.so)

use irlume_vision::align::RgbView;
use irlume_vision::model_input::{CanonicalRgbView, DetectorInput};
use irlume_vision::tflite::TfliteSession;
use irlume_vision::{map_checked_mesh_output, Detector, FaceMesh, MESH_N, MESH_N_IRIS};
use std::collections::BTreeMap;
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

/// External-corpus mode (`IRLUME_PARITY_EXTERNAL=1`): the run still binds
/// every frame to the supplied manifest, but the stage-3 count pins are
/// replaced by the manifest's own total, and a missing rgb/ir subdir is
/// skipped instead of refused (external sets are usually RGB-only). The
/// agreement BOUNDS stay enforced: whether the parity claim holds beyond
/// the stage-3 corpus is exactly what an external run asks.
fn external_corpus() -> bool {
    std::env::var_os("IRLUME_PARITY_EXTERNAL").is_some()
}

/// Load the committed corpus manifest, `sha256  camera/segment/kind/frame`
/// per line. The run consumes it entry-for-entry, so a corpus swap that
/// preserves the frame COUNTS still fails (#314 review: a count-only pin
/// lets different evidence satisfy the bounds).
fn load_manifest(path: &str) -> BTreeMap<String, String> {
    let text =
        std::fs::read_to_string(path).unwrap_or_else(|e| panic!("{path}: read manifest: {e}"));
    let mut map = BTreeMap::new();
    for (no, line) in text.lines().enumerate() {
        let (sha, rel) = line
            .split_once("  ")
            .unwrap_or_else(|| panic!("{path}:{}: expected '<sha256>  <path>'", no + 1));
        assert_eq!(sha.len(), 64, "{path}:{}: invalid sha256", no + 1);
        assert!(
            map.insert(rel.to_string(), sha.to_string()).is_none(),
            "{path}:{}: duplicate entry {rel}",
            no + 1
        );
    }
    map
}

/// Check one frame's bytes against the manifest and consume its entry.
fn consume_manifest_entry(manifest: &mut BTreeMap<String, String>, rel: &str, bytes: &[u8]) {
    let expected = manifest
        .remove(rel)
        .unwrap_or_else(|| panic!("{rel}: not in the corpus manifest"));
    let actual = irlume_common::sha256_hex(bytes);
    assert_eq!(actual, expected, "{rel}: content differs from the manifest");
}

fn read_pnm(data: &[u8]) -> Option<(Vec<u8>, u32, u32)> {
    // Same lossy header parse as blaze_full_parity: the bytes after the
    // header are pixels, not UTF-8.
    let text = String::from_utf8_lossy(&data[..data.len().min(64)]);
    let mut it = text.split_ascii_whitespace();
    let magic = it.next()?;
    let w: usize = it.next()?.parse().ok()?;
    let h: usize = it.next()?.parse().ok()?;
    // 8-bit only: a 16-bit PNM (maxval > 255) has two bytes per sample and
    // this reader would decode interleaved garbage instead of failing.
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

/// The native mesh over the SAME crop `FaceMesh::landmarks` uses: identical
/// x0/y0/side arithmetic, identical bilinear sampling, identical [0,1]
/// normalization, and the shared `map_checked_mesh_output` on the way back,
/// so the two runs differ in nothing but the weights.
fn native_landmarks(
    mesh: &mut TfliteSession,
    input_side: usize,
    frame: &RgbView,
    bbox: &[f32; 4],
    skew: f32,
) -> Result<Vec<(f32, f32)>, String> {
    let (cx, cy) = ((bbox[0] + bbox[2]) * 0.5, (bbox[1] + bbox[3]) * 0.5);
    let half = 0.5 * (bbox[2] - bbox[0]).max(bbox[3] - bbox[1]) * (1.0 + 2.0 * MESH_MARGIN);
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

/// Instrument self-test: a nonzero skew shifts ONLY the native crop, and the
/// run must then report a clearly nonzero NME; a comparison that stays at
/// zero under a known injected difference is measuring nothing. Parsed
/// strictly (#306 review): an unparseable or zero value refuses instead of
/// silently becoming an unskewed run that "passes" its self-test.
fn parity_skew() -> Option<f32> {
    match std::env::var("MESH_PARITY_SKEW_PX") {
        Ok(value) => {
            let skew: f32 = value
                .parse()
                .unwrap_or_else(|e| panic!("MESH_PARITY_SKEW_PX={value:?}: {e}"));
            assert!(
                skew.is_finite() && skew != 0.0,
                "MESH_PARITY_SKEW_PX must be finite and nonzero"
            );
            Some(skew)
        }
        Err(_) => None,
    }
}

/// Read a model file and refuse it unless it is the exact artifact this
/// measurement claims to cover (#306 review: a CSV from an unpinned model
/// cannot establish anything about the shipped one).
fn read_pinned(path: &str, expected: &str, label: &str) -> Vec<u8> {
    let bytes = std::fs::read(path).unwrap_or_else(|e| panic!("{path}: read {label}: {e}"));
    let actual = irlume_common::sha256_hex(&bytes);
    assert_eq!(actual, expected, "{path}: not the shipped {label}");
    bytes
}

/// The shipped artifacts this measurement is about, pinned to the repository's
/// own `models/SHA256SUMS`.
const SHIPPED_MESH_SHA256: &str =
    "821683be088447839638f79d64268bd501bdb72e5d9e262ec981c7e252956caf";
const SHIPPED_DETECTOR_SHA256: &str =
    "8f2383e4dd3cfbb4553ea8718107fc0423210dc964f9f4280604804ed2552fa4";

/// The stage-3 corpus baseline and the parity bound this gate enforces. The
/// counts pin the denominator: a corpus or acceptance change must update them
/// DELIBERATELY, not shrink the comparison in silence. The bound sits just
/// above the measured worst (1.502e-6) so any regression past float noise
/// fails the run.
const EXPECTED_EMITTED: usize = 512;
const EXPECTED_COMPARED: usize = 223;
const MAX_ALLOWED_NME: f64 = 2.0e-6;
/// External-corpus bound: see the gate comment.
const MAX_ALLOWED_NME_EXTERNAL: f64 = 5.0e-6;
const MIN_SKEW_MEAN_NME: f64 = 1.0e-3;

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let (fixed, roots) = args.split_at(4.min(args.len()));
    let [manifest_path, det_path, onnx_mesh_path, tflite_mesh_path] = fixed else {
        panic!(
            "usage: mesh_parity <corpus-manifest.sha256> <yunet.onnx> \
             <face_landmark.onnx> <face_landmarks_detector.tflite> <corpus_root>..."
        );
    };
    assert!(!roots.is_empty(), "at least one corpus root is required");
    let mut manifest = load_manifest(manifest_path);
    let manifest_total = manifest.len();
    let skew = parity_skew();

    let det_bytes = read_pinned(det_path, SHIPPED_DETECTOR_SHA256, "detector");
    let mesh_bytes = read_pinned(onnx_mesh_path, SHIPPED_MESH_SHA256, "ONNX mesh");
    let mut det = Detector::load_from_memory(&det_bytes).expect("load detector");
    let mut onnx_mesh = FaceMesh::load_from_memory(&mesh_bytes).expect("load onnx mesh");
    let tflite_bytes = std::fs::read(tflite_mesh_path).expect("read tflite mesh");
    // 2 threads = the production FaceMesh backend's setting; the byte-identical
    // CSV against the 1-thread committed baseline is the multi-thread
    // determinism evidence the switch needed.
    let mut native = TfliteSession::from_pinned_bytes(&tflite_bytes, LANDMARKER_MESH_SHA256, 2)
        .expect("load native mesh");
    eprintln!(
        "detector_sha256={SHIPPED_DETECTOR_SHA256} onnx_mesh_sha256={SHIPPED_MESH_SHA256} \
         tflite_mesh_sha256={LANDMARKER_MESH_SHA256} skew={skew:?}"
    );
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
    let mut iris_nme_max = 0.0f64;
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
                if external_corpus() && !dir.is_dir() {
                    continue;
                }
                let mut files: Vec<_> = std::fs::read_dir(&dir)
                    .unwrap_or_else(|e| panic!("{}: read frame dir: {e}", dir.display()))
                    .map(|e| e.unwrap_or_else(|e| panic!("{}: read entry: {e}", dir.display())))
                    .map(|e| e.path())
                    .filter(|p| p.extension().is_some_and(|e| e == "ppm" || e == "pgm"))
                    .collect();
                assert!(!files.is_empty(), "{}: no PNM frames", dir.display());
                files.sort();
                for f in files {
                    let bytes = std::fs::read(&f)
                        .unwrap_or_else(|e| panic!("{}: read frame: {e}", f.display()));
                    let seg_name = seg.file_name().to_string_lossy().into_owned();
                    let fname = f.file_name().unwrap().to_string_lossy().into_owned();
                    consume_manifest_entry(
                        &mut manifest,
                        &format!("{cam}/{seg_name}/{sub}/{fname}"),
                        &bytes,
                    );
                    let (data, w, h) =
                        read_pnm(&bytes).unwrap_or_else(|| panic!("{}: invalid PNM", f.display()));
                    let view = RgbView {
                        data: &data,
                        width: w,
                        height: h,
                    };
                    let name = format!("{sub}/{fname}");
                    emitted += 1;
                    let model_view = CanonicalRgbView::try_from_align(&view)
                        .unwrap_or_else(|e| panic!("{}: input: {e}", f.display()));
                    let faces = det
                        .detect(&DetectorInput::from_rgb(model_view))
                        .unwrap_or_else(|e| panic!("{}: detect: {e}", f.display()));
                    let top = faces
                        .iter()
                        .max_by(|a, b| a.score.total_cmp(&b.score))
                        .cloned();
                    let Some(top) = top else {
                        println!("{cam},{seg_name},{kind},{name},,,");
                        continue;
                    };
                    let mesh_input = onnx_mesh
                        .prepare_input(model_view, top.bbox)
                        .unwrap_or_else(|e| panic!("{}: mesh input: {e}", f.display()));
                    let a = onnx_mesh.landmarks(&mesh_input);
                    let b = native_landmarks(
                        &mut native,
                        native_side,
                        &view,
                        &top.bbox,
                        skew.unwrap_or(0.0),
                    );
                    let (Ok(a), Ok(b)) = (a, b) else {
                        // One side declining is a finding, not a crash: the
                        // row stays, the metrics are empty, the bound script
                        // counts it.
                        println!("{cam},{seg_name},{kind},{name},,,");
                        continue;
                    };
                    // Full 478-point comparison. The original #306 run
                    // stopped at the 468 shared-topology points on the
                    // belief the shipped ONNX lacked the iris tail; it does
                    // not (measured 2026-08-06, both emit 478), and the
                    // blendshapes model consumes 468-477, so the tail gets
                    // its own tracked worst-NME alongside the whole-set one.
                    let n = a.len().min(b.len()).min(MESH_N_IRIS);
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
                    let mut iris_sum = 0.0f64;
                    let mut identical = 0usize;
                    for k in 0..n {
                        let dx = (a[k].0 - b[k].0) as f64;
                        let dy = (a[k].1 - b[k].1) as f64;
                        let d = (dx * dx + dy * dy).sqrt();
                        sum += d;
                        worst = worst.max(d);
                        if k >= MESH_N {
                            iris_sum += d;
                        }
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
                    if n > MESH_N {
                        let iris_nme = iris_sum / (n - MESH_N) as f64 / eye as f64;
                        iris_nme_max = iris_nme_max.max(iris_nme);
                    }
                    println!("{cam},{seg_name},{kind},{name},{eye:.1},{nme:.3e},{worst:.4}");
                }
            }
        }
    }
    // The GATE (#306 review): without these, one surviving comparison out of
    // 512, or an arbitrarily bad NME, exited zero, and the "regression gate"
    // in the doc was a claim with nothing enforcing it.
    assert!(
        manifest.is_empty(),
        "manifest entries never seen on disk: {:?}",
        manifest.keys().take(4).collect::<Vec<_>>()
    );
    if external_corpus() {
        assert_eq!(
            emitted, manifest_total,
            "external corpus incompletely walked"
        );
        // A run where nothing compared proves nothing; bounds over an empty
        // set pass vacuously (MR !3 review).
        assert!(compared > 0, "external run compared zero frames");
    } else {
        assert_eq!(
            emitted, EXPECTED_EMITTED,
            "stage-3 corpus changed; update the pinned baseline deliberately"
        );
        assert_eq!(
            compared, EXPECTED_COMPARED,
            "mesh acceptance coverage changed"
        );
    }
    let mean_nme = nme_sum / compared as f64;
    // Summary before the gate: a failing bound must still show its numbers
    // (an LFW run lost its mean/iris figures to a bound panic before this
    // moved).
    eprintln!(
        "emitted {emitted} rows; both-ran {compared}; mean NME {mean_nme:.3e}; \
         worst NME {nme_max:.3e}; worst iris NME {iris_nme_max:.3e}; \
         bit-identical points {total_identical}/{total_points}"
    );
    if skew.is_some() {
        assert!(
            mean_nme >= MIN_SKEW_MEAN_NME,
            "instrument self-test did not move the metric: mean NME {mean_nme:.3e}"
        );
        assert_eq!(
            total_identical, 0,
            "instrument self-test left bit-identical landmarks"
        );
    } else {
        // The strict bound encodes the stage-3 corpus's measured float
        // noise. An external corpus asks the same question over a tail 60x
        // longer; measured on 13k LFW frames the worst reached 2.090e-6, so
        // its bound is one magnitude class up, still bit-level fidelity.
        let bound = if external_corpus() {
            MAX_ALLOWED_NME_EXTERNAL
        } else {
            MAX_ALLOWED_NME
        };
        assert!(
            nme_max <= bound,
            "mesh parity exceeded bound: worst NME {nme_max:.3e} > {bound:.3e}"
        );
    }
}

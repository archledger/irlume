// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright the irlume contributors.

//! Short-range BlazeFace parity harness: does the shipped
//! `blaze_face_short_range.onnx` (a conversion) say the same thing as
//! Google's `blaze_face_short_range.tflite` run natively on the bundled
//! TFLite runtime?
//!
//! This is the one shipped model pair that had never been compared on the
//! native runtime (#294 compared irlume's decode against the official
//! MediaPipe PYTHON runtime, a different question with a cross-runtime
//! preprocessing gap in it). Here both models run in ONE process on the
//! IDENTICAL input tensor (`blaze_letterbox_input`, the production
//! preprocessing) through the IDENTICAL decode (`decode_short_range_best`,
//! the production decode), so any difference left is the weights', not the
//! harness's.
//!
//! Emits one CSV row per frame; a frame where neither head clears the
//! measurement floor carries empty metric fields rather than being dropped,
//! so the bound check sees the full denominator (#298: a dump that silently
//! shrinks turns the comparison into a vacuous pass over whatever survived).
//!
//! Usage: cargo run --release -p irlume-auth --example blaze_short_parity -- \
//!   docs/pad-results/2026-08-05-stage3-corpus.sha256 \
//!   <blaze_face_short_range.onnx> <blaze_face_short_range.tflite> \
//!   <corpus_root>... > blaze-short-parity.csv
//!   (IRLUME_TFLITE_LIB overrides the packaged libtensorflowlite_c.so)

use irlume_vision::align::RgbView;
use irlume_vision::tflite::TfliteSession;
use irlume_vision::{blaze_letterbox_input, decode_short_range_best, BlazeRescue, BLAZE_INPUT};
use std::collections::BTreeMap;
use std::path::Path;

/// The shipped conversion, pinned to the repository's own `models/SHA256SUMS`.
const SHIPPED_ONNX_SHA256: &str =
    "c5453678015f6289c1d77bda88a8ba9c87574f01de1a05ba1909b9a7e08b237b";
/// Google's published artifact (also byte-identical to the
/// `face_detector.tflite` inside face_landmarker.task, measured 2026-08-06).
const NATIVE_TFLITE_SHA256: &str =
    "b4578f35940bf5a1a655214a1cce5cab13eba73c1297cd78e1a04c2380b0152f";

/// Measurement floor: low enough to see sub-threshold agreement, matching
/// the fullrange threshold harness.
const FLOOR: f32 = 0.01;

/// The stage-3 corpus baseline and the parity bounds this gate enforces.
/// The counts pin the denominator (#306 review: without them one surviving
/// comparison exits zero and the gate enforces nothing). Bounds sit just
/// above the measured worst so any regression past float noise fails.
const EXPECTED_EMITTED: usize = 512;
/// Every frame's best-of-896 anchor clears the 0.01 measurement floor on
/// both runtimes (empty rooms included), so the comparison is total.
const EXPECTED_COMPARED: usize = 512;
const EXPECTED_ONE_SIDED: usize = 0;
/// Measured 2026-08-06: min IoU 0.999996, max score delta 1.967e-6,
/// 139/512 scores bit-identical.
const MIN_ALLOWED_IOU: f64 = 0.9999;
const MAX_ALLOWED_SCORE_DELTA: f64 = 5.0e-6;
/// Under the instrument self-test's injected shift the mean IoU must fall
/// at least this far below perfect, or the harness is measuring nothing.
const SKEW_MAX_MEAN_IOU: f64 = 0.95;

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
    let actual = irlume_common::thirdparty::sha256_hex(bytes);
    assert_eq!(actual, expected, "{rel}: content differs from the manifest");
}

fn read_pnm(data: &[u8]) -> Option<(Vec<u8>, u32, u32)> {
    // Same lossy header parse as mesh_parity: the bytes after the header are
    // pixels, not UTF-8.
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

/// Instrument self-test: a nonzero pixel shift is applied to ONLY the native
/// input tensor, and the run must then report degraded IoU; a comparison
/// that stays perfect under a known injected difference is measuring
/// nothing. Parsed strictly (#306 review): an unparseable or zero value
/// refuses instead of silently becoming an unskewed run that "passes".
fn parity_skew() -> Option<usize> {
    match std::env::var("BLAZE_PARITY_SKEW_PX") {
        Ok(value) => {
            let skew: usize = value
                .parse()
                .unwrap_or_else(|e| panic!("BLAZE_PARITY_SKEW_PX={value:?}: {e}"));
            assert!(
                skew > 0 && skew < BLAZE_INPUT,
                "BLAZE_PARITY_SKEW_PX must be in 1..{BLAZE_INPUT}"
            );
            Some(skew)
        }
        Err(_) => None,
    }
}

/// Shift the NHWC input tensor `skew` columns right, zero-filling the left
/// edge: a spatial displacement in 128-space the decoded box must follow.
fn shift_columns(data: &[f32], skew: usize) -> Vec<f32> {
    let n = BLAZE_INPUT;
    let mut out = vec![0.0f32; data.len()];
    for oy in 0..n {
        for ox in skew..n {
            let src = (oy * n + ox - skew) * 3;
            let dst = (oy * n + ox) * 3;
            out[dst..dst + 3].copy_from_slice(&data[src..src + 3]);
        }
    }
    out
}

fn read_pinned(path: &str, expected: &str, label: &str) -> Vec<u8> {
    let bytes = std::fs::read(path).unwrap_or_else(|e| panic!("{path}: read {label}: {e}"));
    let actual = irlume_common::thirdparty::sha256_hex(&bytes);
    assert_eq!(actual, expected, "{path}: not the pinned {label}");
    bytes
}

fn iou(a: &[f32; 4], b: &[f32; 4]) -> f64 {
    let ix = (a[2].min(b[2]) - a[0].max(b[0])).max(0.0) as f64;
    let iy = (a[3].min(b[3]) - a[1].max(b[1])).max(0.0) as f64;
    let inter = ix * iy;
    let area = |r: &[f32; 4]| ((r[2] - r[0]) as f64).max(0.0) * ((r[3] - r[1]) as f64).max(0.0);
    let union = area(a) + area(b) - inter;
    if union <= 0.0 {
        return 0.0;
    }
    inter / union
}

/// Native inference over the shared tensor + the shared decode, scaled to
/// frame pixels exactly like `BlazeRescue::detect_top_at`.
fn native_detect(
    session: &mut TfliteSession,
    anchors: &[(f32, f32)],
    input: &[f32],
    side: f32,
) -> Result<Option<([f32; 4], f32)>, String> {
    let outputs = session.run_f32(input).map_err(|e| e.to_string())?;
    let (mut reg, mut cls): (Option<&Vec<f32>>, Option<&Vec<f32>>) = (None, None);
    for (_, raw) in &outputs {
        match raw.len() {
            l if l == 896 * 16 => reg = Some(raw),
            896 => cls = Some(raw),
            _ => {}
        }
    }
    let (Some(reg), Some(cls)) = (reg, cls) else {
        return Err("native blaze: unexpected output tensors".into());
    };
    Ok(
        decode_short_range_best(reg, cls, anchors, FLOOR).map(|(unit, score)| {
            (
                [
                    unit[0] * side,
                    unit[1] * side,
                    unit[2] * side,
                    unit[3] * side,
                ],
                score,
            )
        }),
    )
}

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let (fixed, roots) = args.split_at(3.min(args.len()));
    let [manifest_path, onnx_path, tflite_path] = fixed else {
        panic!(
            "usage: blaze_short_parity <corpus-manifest.sha256> \
             <blaze_face_short_range.onnx> <blaze_face_short_range.tflite> <corpus_root>..."
        );
    };
    assert!(!roots.is_empty(), "at least one corpus root is required");
    let mut manifest = load_manifest(manifest_path);
    let skew = parity_skew();

    let onnx_bytes = read_pinned(onnx_path, SHIPPED_ONNX_SHA256, "ONNX short-range blaze");
    let mut onnx = BlazeRescue::load_from_memory(&onnx_bytes).expect("load onnx blaze");
    let tflite_bytes = std::fs::read(tflite_path).expect("read tflite blaze");
    let mut native = TfliteSession::from_pinned_bytes(&tflite_bytes, NATIVE_TFLITE_SHA256, 1)
        .expect("load native blaze");
    let anchors = irlume_vision::blaze_anchors();
    eprintln!(
        "onnx_sha256={SHIPPED_ONNX_SHA256} tflite_sha256={NATIVE_TFLITE_SHA256} \
         floor={FLOOR} skew={skew:?}"
    );
    let shape = native.input_shape().expect("native input shape");
    assert_eq!(
        shape,
        vec![1, BLAZE_INPUT, BLAZE_INPUT, 3],
        "unexpected native input shape"
    );

    let mut emitted = 0usize;
    let mut compared = 0usize;
    let mut one_sided = 0usize;
    let (mut iou_sum, mut iou_min) = (0.0f64, f64::INFINITY);
    let (mut delta_sum, mut delta_max) = (0.0f64, 0.0f64);
    let mut identical_scores = 0usize;
    println!("camera,segment,kind,frame,onnx_score,native_score,score_delta,iou");
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
                    let side = w.max(h) as f32;
                    let input = blaze_letterbox_input(&view);
                    let native_input = match skew {
                        Some(k) => shift_columns(&input, k),
                        None => input.clone(),
                    };
                    let a = onnx
                        .detect_top_at(&view, FLOOR)
                        .unwrap_or_else(|e| panic!("{}: onnx detect: {e}", f.display()));
                    let b = native_detect(&mut native, &anchors, &native_input, side)
                        .unwrap_or_else(|e| panic!("{}: native detect: {e}", f.display()));
                    match (a, b) {
                        (Some((ba, sa)), Some((bb, sb))) => {
                            let d = (sa as f64 - sb as f64).abs();
                            let i = iou(&ba, &bb);
                            compared += 1;
                            iou_sum += i;
                            iou_min = iou_min.min(i);
                            delta_sum += d;
                            delta_max = delta_max.max(d);
                            if sa == sb {
                                identical_scores += 1;
                            }
                            println!(
                                "{cam},{seg_name},{kind},{name},{sa:.6},{sb:.6},{d:.3e},{i:.6}"
                            );
                        }
                        (None, None) => println!("{cam},{seg_name},{kind},{name},,,,"),
                        (Some((_, sa)), None) => {
                            one_sided += 1;
                            println!("{cam},{seg_name},{kind},{name},{sa:.6},,,");
                        }
                        (None, Some((_, sb))) => {
                            one_sided += 1;
                            println!("{cam},{seg_name},{kind},{name},,{sb:.6},,");
                        }
                    }
                }
            }
        }
    }
    assert!(
        manifest.is_empty(),
        "manifest entries never seen on disk: {:?}",
        manifest.keys().take(4).collect::<Vec<_>>()
    );
    assert_eq!(
        emitted, EXPECTED_EMITTED,
        "stage-3 corpus changed; update the pinned baseline deliberately"
    );
    let mean_iou = iou_sum / compared as f64;
    let mean_delta = delta_sum / compared as f64;
    // Summary before the gate: a failing bound must still show its numbers.
    eprintln!(
        "emitted {emitted} rows; both-ran {compared}; one-sided {one_sided}; \
         mean IoU {mean_iou:.6}; min IoU {iou_min:.6}; mean score delta {mean_delta:.3e}; \
         max score delta {delta_max:.3e}; identical scores {identical_scores}/{compared}"
    );
    if skew.is_some() {
        assert!(
            mean_iou <= SKEW_MAX_MEAN_IOU,
            "instrument self-test did not move the metric: mean IoU {mean_iou:.4}"
        );
        assert_eq!(
            identical_scores, 0,
            "instrument self-test left bit-identical scores"
        );
    } else {
        assert_eq!(compared, EXPECTED_COMPARED, "parity coverage changed");
        assert_eq!(
            one_sided, EXPECTED_ONE_SIDED,
            "one-sided detections changed"
        );
        assert!(
            iou_min >= MIN_ALLOWED_IOU,
            "parity exceeded bound: min IoU {iou_min:.6} < {MIN_ALLOWED_IOU}"
        );
        assert!(
            delta_max <= MAX_ALLOWED_SCORE_DELTA,
            "parity exceeded bound: max score delta {delta_max:.3e} > {MAX_ALLOWED_SCORE_DELTA:.3e}"
        );
    }
}

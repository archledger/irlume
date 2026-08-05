// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright the irlume contributors.

//! Detection/landmarks bench over a stored stage-3 corpus (#276): run YuNet,
//! the BlazeFace short-range rescue, and the FaceMesh over every captured
//! frame and emit one CSV row per (frame, detector), so detection rate,
//! score floors, and landmark stability can be aggregated offline and
//! re-checked long after the session.
//!
//! Corpus layout (what capture-seg.sh wrote): `<root>/<segment>/rgb/*.ppm`
//! and `<root>/<segment>/ir/*.pgm`. Every IR frame is emitted with its
//! mean brightness; the strobe's lit/ambient split happens at aggregation,
//! per burst, because a fixed floor mislabels bright-ambient rooms.
//!
//! Usage: cargo run --release -p irlume-auth --example detect_bench -- \
//!   <det.onnx> <blaze.onnx> <mesh.onnx> <corpus_root> > out.csv

use irlume_vision::align::RgbView;
use irlume_vision::{BlazeRescue, Detector, FaceMesh, EAR_LEFT, EAR_RIGHT};
use std::path::Path;

fn read_ascii_header(data: &[u8], magic: &str) -> Option<(usize, usize, usize)> {
    // P6/P5 header: magic, whitespace-separated width height maxval, one
    // whitespace, then raw bytes. Comments are not written by our tools.
    // LOSSY: the 64-byte prefix includes the first pixel bytes, and a bright
    // top-left corner is not valid UTF-8 (a strict parse silently dropped
    // most RGB frames on the first run while dark IR corners slid through).
    let text = String::from_utf8_lossy(&data[..data.len().min(64)]);
    let mut it = text.split_ascii_whitespace();
    if it.next()? != magic {
        return None;
    }
    let w: usize = it.next()?.parse().ok()?;
    let h: usize = it.next()?.parse().ok()?;
    let _max: usize = it.next()?.parse().ok()?;
    // Offset of the pixel payload: past the 4th token + one whitespace byte.
    let mut seen = 0usize;
    let mut fields = 0;
    for (i, b) in data.iter().enumerate() {
        if b.is_ascii_whitespace() {
            if seen > 0 {
                fields += 1;
                seen = 0;
                if fields == 4 {
                    return Some((w, h, i + 1));
                }
            }
        } else {
            seen += 1;
        }
    }
    None
}

fn load_ppm(p: &Path) -> Option<(Vec<u8>, u32, u32)> {
    let data = std::fs::read(p).ok()?;
    let (w, h, off) = read_ascii_header(&data, "P6")?;
    (data.len() >= off + w * h * 3)
        .then(|| (data[off..off + w * h * 3].to_vec(), w as u32, h as u32))
}

fn load_pgm(p: &Path) -> Option<(Vec<u8>, u32, u32)> {
    let data = std::fs::read(p).ok()?;
    let (w, h, off) = read_ascii_header(&data, "P5")?;
    (data.len() >= off + w * h).then(|| (data[off..off + w * h].to_vec(), w as u32, h as u32))
}

fn central_span(mut v: Vec<f32>) -> f32 {
    v.sort_by(f32::total_cmp);
    let lo = v.len() / 10;
    let hi = v.len().saturating_sub(1 + lo);
    if hi <= lo {
        0.0
    } else {
        v[hi] - v[lo]
    }
}

/// Refuse to run on anything but the SHIPPED artifact for `name`: the bench's
/// claims say "the shipped X", and nothing else binds a CSV to model bytes
/// (a banked legacy mesh loads just as happily). Prints the digest so the
/// measurement doc can record it (#294 review).
fn require_shipped(path: &str, name: &str) -> String {
    let bytes = std::fs::read(path).unwrap_or_else(|e| panic!("read model {path}: {e}"));
    let actual = irlume_common::thirdparty::sha256_hex(&bytes);
    let expected = include_str!("../../../models/SHA256SUMS")
        .lines()
        .find_map(|l| {
            let mut f = l.split_whitespace();
            let digest = f.next()?;
            (f.next()? == name).then(|| digest.to_owned())
        })
        .unwrap_or_else(|| panic!("{name}: missing from models/SHA256SUMS"));
    assert_eq!(actual, expected, "{path}: bytes are not the shipped {name}");
    actual
}

fn fmt(v: Option<f32>) -> String {
    v.map(|x| format!("{x:.4}")).unwrap_or_default()
}

fn main() {
    let a: Vec<String> = std::env::args().skip(1).collect();
    let [det_p, blaze_p, mesh_p, root] = &a[..] else {
        eprintln!("usage: detect_bench <det.onnx> <blaze.onnx> <mesh.onnx> <corpus_root>");
        std::process::exit(2);
    };
    eprintln!(
        "yunet_sha256={}",
        require_shipped(det_p, "face_detection_yunet_2023mar.onnx")
    );
    eprintln!(
        "blaze_sha256={}",
        require_shipped(blaze_p, "blaze_face_short_range.onnx")
    );
    eprintln!(
        "mesh_sha256={}",
        require_shipped(mesh_p, "face_landmark.onnx")
    );
    let mut det = Detector::load_from_file(det_p).expect("yunet");
    let mut blaze = BlazeRescue::load_from_file(blaze_p).expect("blaze");
    let mut mesh = FaceMesh::load_from_file(mesh_p).expect("mesh");

    println!(
        "segment,kind,frame,yunet_n,yunet_score,yunet_fsize,mesh_ok,ear_l,ear_r,span_x,span_y,\
         blaze_score,blaze_fsize,mean"
    );
    let mut segs: Vec<_> = std::fs::read_dir(root)
        .expect("corpus root")
        .flatten()
        .filter(|e| e.path().is_dir())
        .collect();
    segs.sort_by_key(|e| e.file_name());
    for seg in segs {
        let seg_name = seg.file_name().to_string_lossy().into_owned();
        let mut frames: Vec<(String, Vec<u8>, u32, u32, f32)> = Vec::new();
        for (sub, kind) in [("rgb", "rgb"), ("ir", "ir")] {
            let dir = seg.path().join(sub);
            let mut files: Vec<_> = std::fs::read_dir(&dir)
                .into_iter()
                .flatten()
                .flatten()
                .map(|e| e.path())
                .filter(|p| p.extension().is_some_and(|e| e == "ppm" || e == "pgm"))
                .collect();
            files.sort();
            for f in files {
                let name = format!("{kind}/{}", f.file_name().unwrap().to_string_lossy());
                if kind == "rgb" {
                    if let Some((d, w, h)) = load_ppm(&f) {
                        let mean = d.iter().map(|&p| p as f32).sum::<f32>() / d.len().max(1) as f32;
                        frames.push((name, d, w, h, mean));
                    }
                } else if let Some((d, w, h)) = load_pgm(&f) {
                    // Every IR frame is emitted with its mean; the strobe
                    // phase split happens at AGGREGATION, per burst, because
                    // a fixed floor mislabeled bright-ambient segments as lit
                    // on the first run and halved their apparent rate.
                    let mean = d.iter().map(|&p| p as f32).sum::<f32>() / d.len().max(1) as f32;
                    frames.push((name, irlume_camera::grey_to_rgb(&d), w, h, mean));
                }
            }
        }
        for (name, data, w, h, mean) in frames {
            let view = RgbView {
                data: &data,
                width: w,
                height: h,
            };
            // An inference ERROR is not a miss: collapsing them let a
            // runtime failure masquerade as "the model saw no face" (#294
            // review). Detector execution errors abort the run; a mesh error
            // is an intended measurement (refusal) and is logged instead.
            let dets = det
                .detect(&view)
                .unwrap_or_else(|e| panic!("{seg_name}/{name}: YuNet inference failed: {e}"));
            let top = dets.iter().max_by(|a, b| a.score.total_cmp(&b.score));
            let (mut mesh_ok, mut ear_l, mut ear_r, mut span_x, mut span_y) =
                (false, None, None, None, None);
            if let Some(t) = top {
                match mesh.landmarks(&view, &t.bbox, 0.25) {
                    Ok(lm) => {
                        mesh_ok = true;
                        ear_l = Some(irlume_vision::eye_ear(&lm, &EAR_LEFT));
                        ear_r = Some(irlume_vision::eye_ear(&lm, &EAR_RIGHT));
                        span_x = Some(central_span(lm.iter().map(|&(x, _)| x).collect()));
                        span_y = Some(central_span(lm.iter().map(|&(_, y)| y).collect()));
                    }
                    Err(e) => eprintln!("{seg_name}/{name}: mesh refused or failed: {e}"),
                }
            }
            let bl = blaze
                .detect_top(&view)
                .unwrap_or_else(|e| panic!("{seg_name}/{name}: BlazeFace inference failed: {e}"));
            let kind = if name.starts_with("rgb") { "rgb" } else { "ir" };
            println!(
                "{seg_name},{kind},{name},{},{},{},{},{},{},{},{},{},{},{mean:.1}",
                dets.len(),
                fmt(top.map(|t| t.score)),
                fmt(top.map(|t| t.bbox[2] - t.bbox[0])),
                mesh_ok,
                fmt(ear_l),
                fmt(ear_r),
                fmt(span_x),
                fmt(span_y),
                fmt(bl.map(|(_, s)| s)),
                fmt(bl.map(|(b, _)| b[2] - b[0])),
            );
        }
    }
}

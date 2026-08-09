// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright the irlume contributors.

//! Every liveness cue, per frame, from IR PGMs already on disk (#174).
//!
//! Why this exists: #174 says the liveness gates are absolute thresholds on
//! quantities that move with face distance, and that distance is measured and
//! then discarded. Answering that needs the cues paired with a face size across
//! a distance range, on more than one module. Re-capturing to change the
//! analysis is how a measurement ends up describing the session rather than the
//! cue, so this reads stored pixels instead, the same reasoning
//! [`landmark_replay`](landmark_replay.rs) is built on.
//!
//! It computes nothing of its own. Every column is the SHIPPED function the
//! daemon calls, so a row here and a row from a live authentication are
//! comparable; a private reimplementation would be measuring this file.
//!
//! `white` is passed as `Some(255)`, matching what `clipping_white_level`
//! answers for the GREY8 these corpora were captured in. That matters for two
//! columns: `ir_eye_glint` and `ir_saturated_frac` both answer `None` on a
//! railed reading rather than reporting the ceiling as a measurement, and the
//! CSV writes those as empty fields so a consumer cannot average them as zero.
//!
//! Usage: cargo run --release -p irlume-auth --example liveness_replay -- \
//!   <det.onnx> <pgm_dir_or_root> [out.csv]
//!
//! The directory is walked recursively, so pointing it at a corpus root emits
//! one CSV covering every segment, with the relative path as the label.

use irlume_vision::align;
use std::io::Write;

/// Parse a binary 8-bit PGM (`P5`). Copied deliberately from
/// [`landmark_replay`](landmark_replay.rs) rather than shared: these examples
/// are analysis instruments that must keep working when the other is edited,
/// and the parser is the one thing a wrong edit would silently corrupt into
/// off-by-one pixel reads.
///
/// Strict rather than forgiving: a header this does not understand means the
/// file is not what the caller thinks it is.
fn read_pgm(path: &std::path::Path) -> Result<(u32, u32, Vec<u8>), String> {
    let raw = std::fs::read(path).map_err(|e| format!("{}: {e}", path.display()))?;
    if !raw.starts_with(b"P5") {
        return Err(format!("{}: not a binary PGM (no P5)", path.display()));
    }
    let mut fields: Vec<u64> = Vec::new();
    let mut i = 2usize;
    while fields.len() < 3 {
        while i < raw.len() && (raw[i].is_ascii_whitespace() || raw[i] == b'#') {
            if raw[i] == b'#' {
                while i < raw.len() && raw[i] != b'\n' {
                    i += 1;
                }
            } else {
                i += 1;
            }
        }
        let start = i;
        while i < raw.len() && raw[i].is_ascii_digit() {
            i += 1;
        }
        if start == i {
            return Err(format!("{}: truncated PGM header", path.display()));
        }
        let n: u64 = std::str::from_utf8(&raw[start..i])
            .map_err(|_| format!("{}: bad header byte", path.display()))?
            .parse()
            .map_err(|_| format!("{}: bad header number", path.display()))?;
        fields.push(n);
    }
    // EXACTLY one whitespace byte separates header from raster; consuming a
    // non-whitespace byte would shift every pixel by one.
    if !raw.get(i).is_some_and(|b| b.is_ascii_whitespace()) {
        return Err(format!(
            "{}: header is not followed by a whitespace byte",
            path.display()
        ));
    }
    i += 1;
    let (w, h, maxval) = (fields[0], fields[1], fields[2]);
    if maxval != 255 {
        return Err(format!("{}: maxval {maxval}, expected 255", path.display()));
    }
    let want = (w as usize) * (h as usize);
    let pixels = raw
        .get(i..i + want)
        .ok_or_else(|| format!("{}: short raster, expected {want} bytes", path.display()))?
        .to_vec();
    Ok((w as u32, h as u32, pixels))
}

/// Every `.pgm` under `root`, depth first, sorted so a run is reproducible.
fn pgms(root: &std::path::Path, out: &mut Vec<std::path::PathBuf>) {
    let Ok(rd) = std::fs::read_dir(root) else {
        return;
    };
    let mut entries: Vec<_> = rd.flatten().map(|e| e.path()).collect();
    entries.sort();
    for p in entries {
        if p.is_dir() {
            pgms(&p, out);
        } else if p.extension().is_some_and(|e| e == "pgm") {
            out.push(p);
        }
    }
}

/// `None` becomes an EMPTY field, never 0. A cue that refused to answer is not
/// a cue that measured zero, and a consumer averaging a column must be able to
/// tell them apart (#222, #358).
fn opt(v: Option<f32>) -> String {
    v.map_or(String::new(), |x| format!("{x:.4}"))
}

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let [det_path, dir] = &args[..2] else {
        eprintln!(
            "usage: liveness_replay <det.onnx> <pgm_dir_or_root> [out.csv]\n\
             writes one row per IR frame with every shipped liveness cue"
        );
        std::process::exit(2);
    };
    let root = std::path::Path::new(dir);

    let mut det = match irlume_vision::Detector::load_from_file(det_path) {
        Ok(d) => d,
        Err(e) => {
            eprintln!("detector {det_path}: {e}");
            std::process::exit(1);
        }
    };

    let mut files = Vec::new();
    pgms(root, &mut files);
    if files.is_empty() {
        eprintln!("no .pgm under {}", root.display());
        std::process::exit(1);
    }

    let mut sink: Box<dyn Write> = match args.get(2) {
        Some(p) => match std::fs::File::create(p) {
            Ok(f) => Box::new(std::io::BufWriter::new(f)),
            Err(e) => {
                eprintln!("{p}: {e}");
                std::process::exit(1);
            }
        },
        None => Box::new(std::io::stdout().lock()),
    };
    let _ = writeln!(
        sink,
        "segment,frame,width,height,faces,face_frac,ir_face_brightness,\
         ir_center_edge_ratio,ir_eye_glint,ir_saturated_frac"
    );

    let (mut rows, mut skipped) = (0usize, 0usize);
    for path in &files {
        let (w, h, grey) = match read_pgm(path) {
            Ok(v) => v,
            Err(e) => {
                eprintln!("skip {e}");
                skipped += 1;
                continue;
            }
        };
        // The detector wants three channels; the corpus is single-plane grey.
        let rgb = irlume_camera::grey_to_rgb(&grey);
        let view = align::RgbView {
            data: &rgb,
            width: w,
            height: h,
        };
        let faces = match det.detect(&view) {
            Ok(f) => f,
            Err(e) => {
                eprintln!("skip {}: detect: {e}", path.display());
                skipped += 1;
                continue;
            }
        };
        // Highest-scoring detection, the same choice the auth path makes.
        let top = faces
            .iter()
            .max_by(|a, b| a.score.total_cmp(&b.score))
            .filter(|d| irlume_vision::detection_is_finite(d));
        let label = path
            .strip_prefix(root)
            .unwrap_or(path)
            .parent()
            .map(|p| p.display().to_string())
            .unwrap_or_default();
        let name = path.file_name().unwrap_or_default().to_string_lossy();

        // A frame with no face still gets a row. Dropping it would bias every
        // per-segment summary toward the frames that happened to detect, which
        // is the population question #174 is asking about.
        let (frac, bright, ratio, glint, sat) = match top {
            Some(d) => (
                irlume_auth::face_frac_of(Some(&d.bbox), w),
                irlume_auth::mean_in_bbox(&grey, w, h, &d.bbox),
                irlume_auth::center_edge_ratio(&grey, w, h, &d.bbox),
                irlume_auth::eye_glint_of(&grey, w, h, Some(&d.landmarks), Some(255)),
                irlume_auth::saturated_frac_of(&grey, w, h, Some(&d.bbox), Some(255)),
            ),
            None => (0.0, 0.0, 0.0, None, None),
        };
        let _ = writeln!(
            sink,
            "{label},{name},{w},{h},{},{frac:.4},{bright:.2},{ratio:.4},{},{}",
            faces.len(),
            opt(glint),
            opt(sat)
        );
        rows += 1;
    }
    let _ = sink.flush();
    eprintln!("{rows} rows from {} files, {skipped} skipped", files.len());
}

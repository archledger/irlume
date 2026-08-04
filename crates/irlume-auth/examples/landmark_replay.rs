// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright the irlume contributors.

//! [`landmark_dump`](landmark_dump.rs) over frames already on disk: read PGMs
//! from a directory and write the same `frameNN.landmarks.csv` + `index.txt`,
//! so a burst captured earlier (or by `burst_dump`, which stores pixels but no
//! mesh) can be analysed without the subject, the print, or the room.
//!
//! Why this exists: the relief work (#25) needs the SAME instrument applied to
//! corpora captured in different sessions, and re-capturing to change the
//! analysis is how a measurement ends up describing the session rather than the
//! cue. Reading stored pixels also lets a claim be re-checked long after the
//! light is gone.
//!
//! The sampling is deliberately identical to `landmark_dump`'s 3x3 patch mean:
//! the two tools must produce interchangeable rows, or a cross-session
//! comparison is measuring the tooling.
//!
//! Usage: cargo run --release -p irlume-auth --example landmark_replay -- \
//!   <det.onnx> <mesh.onnx> <pgm_dir> [out_dir]
//! With no out_dir the CSVs are written beside the PGMs.

use irlume_vision::{align, Detector, FaceMesh};
use std::io::Write;

/// Mean of the 3x3 patch centered on (x, y), clamped to the frame. Same as
/// `landmark_dump::patch_mean`; one pixel is noisy, a patch tracks the local
/// emitter response.
fn patch_mean(grey: &[u8], w: u32, h: u32, x: f32, y: f32) -> f32 {
    let (cx, cy) = (x.round() as i64, y.round() as i64);
    let (mut sum, mut n) = (0.0f32, 0u32);
    for dy in -1..=1i64 {
        for dx in -1..=1i64 {
            let (px, py) = (cx + dx, cy + dy);
            if px >= 0 && py >= 0 && (px as u32) < w && (py as u32) < h {
                sum += grey[py as usize * w as usize + px as usize] as f32;
                n += 1;
            }
        }
    }
    if n == 0 {
        return 0.0;
    }
    sum / n as f32
}

/// Parse a binary 8-bit PGM (`P5`), the format `burst_dump` and
/// `landmark_dump` write. Returns (width, height, pixels).
///
/// Strict rather than forgiving: a header this does not understand means the
/// file is not what the caller thinks it is, and silently guessing dimensions
/// would produce landmark coordinates that index the wrong pixels.
fn read_pgm(path: &std::path::Path) -> Result<(u32, u32, Vec<u8>), String> {
    let raw = std::fs::read(path).map_err(|e| format!("{}: {e}", path.display()))?;
    // Header: P5 <ws> width <ws> height <ws> maxval <single ws> pixels.
    let mut fields: Vec<u64> = Vec::new();
    let mut i = 0usize;
    if !raw.starts_with(b"P5") {
        return Err(format!("{}: not a binary PGM (no P5)", path.display()));
    }
    i += 2;
    while fields.len() < 3 {
        // Skip whitespace and comment lines.
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
    // Exactly one whitespace byte separates the header from the pixels.
    i += 1;
    let (w, h, maxval) = (fields[0], fields[1], fields[2]);
    if maxval != 255 {
        return Err(format!("{}: maxval {maxval}, expected 255", path.display()));
    }
    let want = (w as usize) * (h as usize);
    let pixels = raw
        .get(i..i + want)
        .ok_or_else(|| {
            format!(
                "{}: {} pixel bytes, expected {want}",
                path.display(),
                raw.len() - i
            )
        })?
        .to_vec();
    Ok((w as u32, h as u32, pixels))
}

fn main() {
    let mut a = std::env::args().skip(1);
    let usage = "usage: landmark_replay <det.onnx> <mesh.onnx> <pgm_dir> [out_dir]";
    let det_path = a.next().expect(usage);
    let mesh_path = a.next().expect(usage);
    let dir = a.next().expect(usage);
    let out = a.next().unwrap_or_else(|| dir.clone());

    let mut det = Detector::load_from_file(&det_path).expect("load detector");
    let mut mesh = FaceMesh::load_from_file(&mesh_path).expect("load mesh");
    std::fs::create_dir_all(&out).expect("create out dir");

    // Sorted, so frameNN order is capture order rather than readdir order.
    let mut pgms: Vec<std::path::PathBuf> = std::fs::read_dir(&dir)
        .unwrap_or_else(|e| panic!("read {dir}: {e}"))
        .flatten()
        .map(|e| e.path())
        .filter(|p| p.extension().is_some_and(|x| x == "pgm"))
        .collect();
    pgms.sort();
    if pgms.is_empty() {
        eprintln!("{dir}: no .pgm frames");
        std::process::exit(2);
    }

    let mut index = std::fs::File::create(format!("{out}/index.txt")).expect("index");
    let (mut detected, mut failed) = (0usize, 0usize);
    for (i, path) in pgms.iter().enumerate() {
        let (w, h, data) = match read_pgm(path) {
            Ok(v) => v,
            Err(e) => {
                // A frame that cannot be read is reported, never skipped
                // silently: a corpus quietly missing frames reads as a
                // condition that produced fewer detections.
                eprintln!("skipping {e}");
                failed += 1;
                continue;
            }
        };
        let mean = irlume_camera::ir_probe::mean(&data);
        let grey_rgb = irlume_camera::grey_to_rgb(&data);
        let view = align::RgbView {
            data: &grey_rgb,
            width: w,
            height: h,
        };
        let top = det
            .detect(&view)
            .expect("detect")
            .into_iter()
            .max_by(|a, b| a.score.total_cmp(&b.score));
        match top {
            Some(t) => {
                let lm = mesh.landmarks(&view, &t.bbox, 0.25).expect("mesh");
                let mut csv = std::fs::File::create(format!("{out}/frame{i:02}.landmarks.csv"))
                    .expect("csv file");
                writeln!(csv, "idx,x,y,brightness").unwrap();
                for (k, &(x, y)) in lm.iter().enumerate() {
                    let bri = patch_mean(&data, w, h, x, y);
                    writeln!(csv, "{k},{x},{y},{bri:.2}").unwrap();
                }
                writeln!(
                    index,
                    "{i:02} {mean:.1} - {:.2} {:.0},{:.0},{:.0},{:.0}",
                    t.score, t.bbox[0], t.bbox[1], t.bbox[2], t.bbox[3]
                )
                .unwrap();
                detected += 1;
            }
            // Timing is a capture-time-only fact, so the ms column that
            // `landmark_dump` fills is '-' here rather than invented.
            None => writeln!(index, "{i:02} {mean:.1} - - -").unwrap(),
        }
    }
    println!(
        "{out}: {} frames read ({failed} unreadable), face+mesh in {detected}",
        pgms.len() - failed
    );
}

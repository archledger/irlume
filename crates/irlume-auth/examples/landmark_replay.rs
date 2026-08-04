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
    // The spec says EXACTLY ONE whitespace byte separates the header from the
    // raster. Checked rather than skipped: consuming a non-whitespace byte
    // would silently shift every pixel by one and produce landmark samples
    // from the wrong place.
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
        .ok_or_else(|| {
            format!(
                "{}: {} pixel bytes, expected {want}",
                path.display(),
                raw.len() - i
            )
        })?
        .to_vec();
    // Trailing bytes mean the file is not the single-frame PGM this assumes;
    // a concatenated or padded file would otherwise read as a valid frame.
    // One trailing newline is tolerated because writers commonly add one.
    let trailing = &raw[i + want..];
    if !trailing.is_empty() && trailing != b"\n" {
        return Err(format!(
            "{}: {} unexpected bytes after the raster",
            path.display(),
            trailing.len()
        ));
    }
    Ok((w as u32, h as u32, pixels))
}

/// The capture number in `frameNN.pgm`.
///
/// Lexicographic path order is not capture order once a corpus passes 99
/// frames (`frame100` sorts before `frame11`), and enumerating the sorted list
/// renumbers frames whenever the sequence has a gap. Both silently re-label
/// results, and the lit/ambient pairing in the relief analysis is done by
/// frame NUMBER, so a re-label pairs a frame with the wrong neighbour (#270
/// review).
fn frame_number(path: &std::path::Path) -> Result<usize, String> {
    let stem = path
        .file_stem()
        .and_then(|s| s.to_str())
        .ok_or_else(|| format!("{}: non-UTF-8 frame name", path.display()))?;
    let digits = stem
        .strip_prefix("frame")
        .ok_or_else(|| format!("{}: expected frameNN.pgm", path.display()))?;
    if digits.is_empty() || !digits.bytes().all(|b| b.is_ascii_digit()) {
        return Err(format!("{}: expected frameNN.pgm", path.display()));
    }
    digits
        .parse()
        .map_err(|_| format!("{}: frame number is too large", path.display()))
}

/// Every `frameNN.pgm` in `dir`, in CAPTURE order, or an error.
///
/// `read_dir` yields per-entry results and its order is filesystem-dependent;
/// flattening the iterator would drop an unreadable entry with no trace, which
/// is the silent-incompleteness this tool exists to avoid.
fn collect_pgms(dir: &std::path::Path) -> Result<Vec<(usize, std::path::PathBuf)>, String> {
    let entries = std::fs::read_dir(dir)
        .map_err(|e| format!("read {}: {e}", dir.display()))?
        .collect::<Result<Vec<_>, _>>()
        .map_err(|e| format!("read an entry in {}: {e}", dir.display()))?;
    let mut pgms = entries
        .into_iter()
        .map(|e| e.path())
        .filter(|p| p.extension().is_some_and(|x| x == "pgm"))
        .map(|p| frame_number(&p).map(|n| (n, p)))
        .collect::<Result<Vec<_>, _>>()?;
    pgms.sort_by_key(|(n, _)| *n);
    for w in pgms.windows(2) {
        if w[0].0 == w[1].0 {
            return Err(format!(
                "duplicate frame number {}: {} and {}",
                w[0].0,
                w[0].1.display(),
                w[1].1.display()
            ));
        }
    }
    if pgms.is_empty() {
        return Err(format!("{}: no .pgm frames", dir.display()));
    }
    Ok(pgms)
}

fn main() -> std::process::ExitCode {
    let mut a = std::env::args().skip(1);
    let usage = "usage: landmark_replay <det.onnx> <mesh.onnx> <pgm_dir> [out_dir]";
    let det_path = a.next().expect(usage);
    let mesh_path = a.next().expect(usage);
    let dir = std::path::PathBuf::from(a.next().expect(usage));
    let out = a
        .next()
        .map(std::path::PathBuf::from)
        .unwrap_or_else(|| dir.clone());

    if let Err(e) = run(&det_path, &mesh_path, &dir, &out) {
        eprintln!("landmark_replay: {e}");
        return std::process::ExitCode::FAILURE;
    }
    std::process::ExitCode::SUCCESS
}

/// Replay every frame, or fail without writing a partial corpus.
///
/// Inputs are read and validated BEFORE any output exists: a corpus silently
/// missing frames is indistinguishable from a condition that produced fewer
/// detections, and an analysis job seeing exit 0 would treat the short set as
/// complete. A frame that fails to parse is a hard error, not a skip.
fn run(
    det_path: &str,
    mesh_path: &str,
    dir: &std::path::Path,
    out: &std::path::Path,
) -> Result<(), String> {
    let pgms = collect_pgms(dir)?;
    // Read every frame first, so a truncated one aborts before the run looks
    // like it produced a complete corpus.
    let frames = pgms
        .iter()
        .map(|(n, p)| read_pgm(p).map(|f| (*n, f)))
        .collect::<Result<Vec<_>, _>>()?;

    std::fs::create_dir_all(out).map_err(|e| format!("create {}: {e}", out.display()))?;
    // Refuse to mix with an existing corpus: stale CSVs from an earlier run
    // survive a re-run that detects fewer frames, and an analysis enumerating
    // CSVs would then read a landmark result the new index does not list. In
    // place over a landmark_dump corpus this forces a fresh directory, which
    // is also what makes the byte-comparison parity check meaningful.
    let stale = std::fs::read_dir(out)
        .map_err(|e| format!("read {}: {e}", out.display()))?
        .collect::<Result<Vec<_>, _>>()
        .map_err(|e| format!("read an entry in {}: {e}", out.display()))?
        .into_iter()
        .any(|e| {
            e.file_name()
                .to_str()
                .is_some_and(|n| n.ends_with(".landmarks.csv") || n == "index.txt")
        });
    if stale {
        return Err(format!(
            "{} already holds replay output; pass a fresh out_dir",
            out.display()
        ));
    }

    let mut det = Detector::load_from_file(det_path).map_err(|e| format!("load detector: {e}"))?;
    let mut mesh = FaceMesh::load_from_file(mesh_path).map_err(|e| format!("load mesh: {e}"))?;

    let index_path = out.join("index.txt");
    let mut index =
        std::fs::File::create(&index_path).map_err(|e| format!("{}: {e}", index_path.display()))?;
    let mut detected = 0usize;
    for (n, (w, h, data)) in &frames {
        let mean = irlume_camera::ir_probe::mean(data);
        let grey_rgb = irlume_camera::grey_to_rgb(data);
        let view = align::RgbView {
            data: &grey_rgb,
            width: *w,
            height: *h,
        };
        let top = det
            .detect(&view)
            .map_err(|e| format!("detect frame {n}: {e}"))?
            .into_iter()
            .max_by(|a, b| a.score.total_cmp(&b.score));
        // The CAPTURE number, never the loop position: a gap in the sequence
        // would otherwise re-label every later frame.
        match top {
            Some(t) => {
                let lm = mesh
                    .landmarks(&view, &t.bbox, 0.25)
                    .map_err(|e| format!("mesh frame {n}: {e}"))?;
                let csv_path = out.join(format!("frame{n:02}.landmarks.csv"));
                let mut csv = std::fs::File::create(&csv_path)
                    .map_err(|e| format!("{}: {e}", csv_path.display()))?;
                let mut w_csv = || -> std::io::Result<()> {
                    writeln!(csv, "idx,x,y,brightness")?;
                    for (k, &(x, y)) in lm.iter().enumerate() {
                        let bri = patch_mean(data, *w, *h, x, y);
                        writeln!(csv, "{k},{x},{y},{bri:.2}")?;
                    }
                    Ok(())
                };
                w_csv().map_err(|e| format!("{}: {e}", csv_path.display()))?;
                writeln!(
                    index,
                    "{n:02} {mean:.1} - {:.2} {:.0},{:.0},{:.0},{:.0}",
                    t.score, t.bbox[0], t.bbox[1], t.bbox[2], t.bbox[3]
                )
                .map_err(|e| format!("{}: {e}", index_path.display()))?;
                detected += 1;
            }
            // Timing is a capture-time-only fact, so the ms column that
            // `landmark_dump` fills is '-' here rather than invented.
            None => writeln!(index, "{n:02} {mean:.1} - - -")
                .map_err(|e| format!("{}: {e}", index_path.display()))?,
        }
    }
    println!(
        "{}: {} frames read, face+mesh in {detected}",
        out.display(),
        frames.len()
    );
    Ok(())
}

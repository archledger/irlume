// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright the irlume contributors.

//! Offline frame-level PAD regression only; no identity match or authentication.
//! Usage: ir_recorded_pad ABS_DETECTOR ABS_FLIR ABS_DIRECTORY
//! All stored PGM frames are processed. Illumination metadata, strobe pairing,
//! burst selection, and other authentication gates are unavailable here.

#[derive(Default)]
struct Counts {
    total_frames: usize,
    no_face: usize,
    pad_evaluated: usize,
    pad_refused: usize,
    pad_below_threshold: usize,
    invalid_or_failed: usize,
}

const MAX_PIXELS: usize = 16 * 1024 * 1024;
const MAX_FILE_BYTES: usize = MAX_PIXELS + 4096;
const MAX_FRAMES: usize = 4096;

/// P5 with a bounded header, 8-bit full-scale pixels, and exactly one raster.
/// Exactly one whitespace byte follows maxval: binary whitespace is pixel data.
fn parse_pgm(raw: &[u8]) -> Result<(u32, u32, &[u8]), ()> {
    if raw.len() > MAX_FILE_BYTES
        || !raw.starts_with(b"P5")
        || !raw.get(2).is_some_and(u8::is_ascii_whitespace)
    {
        return Err(());
    }
    let mut i = 2;
    let mut fields = [0usize; 3];
    for field in &mut fields {
        loop {
            while raw.get(i).is_some_and(u8::is_ascii_whitespace) {
                i += 1;
            }
            if raw.get(i) != Some(&b'#') {
                break;
            }
            while raw.get(i).is_some_and(|b| *b != b'\n') {
                i += 1;
            }
        }
        let start = i;
        while let Some(b) = raw.get(i).filter(|b| b.is_ascii_digit()) {
            *field = field
                .checked_mul(10)
                .and_then(|v| v.checked_add((*b - b'0') as usize))
                .ok_or(())?;
            i += 1;
        }
        if start == i || i > 4095 || !raw.get(i).is_some_and(u8::is_ascii_whitespace) {
            return Err(());
        }
    }
    i += 1;
    let [w, h, maxval] = fields;
    if w == 0 || h == 0 || w > 4096 || h > 4096 || maxval != 255 {
        return Err(());
    }
    let len = w.checked_mul(h).filter(|v| *v <= MAX_PIXELS).ok_or(())?;
    if i.checked_add(len) != Some(raw.len()) {
        return Err(());
    }
    Ok((w as u32, h as u32, &raw[i..]))
}

impl Counts {
    fn record(&mut self, result: Result<Option<f32>, ()>, threshold: f32) {
        self.total_frames += 1;
        match result {
            Ok(None) => self.no_face += 1,
            Ok(Some(p)) if p.is_finite() && (0.0..=1.0).contains(&p) => {
                self.pad_evaluated += 1;
                if p >= threshold {
                    self.pad_refused += 1;
                } else {
                    self.pad_below_threshold += 1;
                }
            }
            _ => self.invalid_or_failed += 1,
        }
    }
    fn exit_code(&self) -> u8 {
        u8::from(self.invalid_or_failed > 0)
    }
}

use std::io::{Read, Write};
use std::os::fd::AsRawFd;
use std::path::{Path, PathBuf};

fn protect_process() -> Result<(), ()> {
    let limits = libc::rlimit {
        rlim_cur: 0,
        rlim_max: 0,
    };
    // SAFETY: limits is an initialized rlimit ABI structure.
    if unsafe { libc::setrlimit(libc::RLIMIT_CORE, &limits) } != 0 {
        return Err(());
    }
    // SAFETY: PR_SET_DUMPABLE consumes scalar arguments and no pointers.
    if unsafe {
        libc::prctl(
            libc::PR_SET_DUMPABLE,
            0 as libc::c_ulong,
            0 as libc::c_ulong,
            0 as libc::c_ulong,
            0 as libc::c_ulong,
        )
    } != 0
    {
        return Err(());
    }
    let null = std::fs::OpenOptions::new()
        .write(true)
        .open("/dev/null")
        .map_err(|_| ())?;
    // SAFETY: null owns a valid FD; stderr is replaced before library threads start.
    if unsafe { libc::dup2(null.as_raw_fd(), libc::STDERR_FILENO) } < 0 {
        return Err(());
    }
    Ok(())
}

fn pgms(root: &Path) -> Result<Vec<PathBuf>, ()> {
    if !root.is_absolute() || !root.is_dir() {
        return Err(());
    }
    let mut paths = Vec::new();
    for entry in std::fs::read_dir(root).map_err(|_| ())? {
        let entry = entry.map_err(|_| ())?;
        if entry.path().extension().is_some_and(|ext| ext == "pgm") {
            if !entry.file_type().map_err(|_| ())?.is_file() || paths.len() == MAX_FRAMES {
                return Err(());
            }
            paths.push(entry.path());
        }
    }
    if paths.is_empty() {
        return Err(());
    }
    paths.sort();
    Ok(paths)
}

fn frame(
    path: &Path,
    det: &mut irlume_vision::Detector,
    pad: &mut irlume_vision::PadIr,
) -> Result<Option<f32>, ()> {
    let file = std::fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
        .open(path)
        .map_err(|_| ())?;
    let metadata = file.metadata().map_err(|_| ())?;
    if !metadata.is_file() || metadata.len() > MAX_FILE_BYTES as u64 {
        return Err(());
    }
    let mut raw = Vec::new();
    file.take((MAX_FILE_BYTES + 1) as u64)
        .read_to_end(&mut raw)
        .map_err(|_| ())?;
    let (width, height, grey) = parse_pgm(&raw)?;
    let rgb = irlume_camera::grey_to_rgb(grey);
    let view = irlume_vision::align::RgbView {
        data: &rgb,
        width,
        height,
    };
    let faces = det.detect(&view).map_err(|_| ())?;
    let Some(face) = faces.iter().max_by(|a, b| a.score.total_cmp(&b.score)) else {
        return Ok(None);
    };
    // Same highest-score selection as authentication; invalid output fails closed.
    if !irlume_vision::detection_is_finite(face)
        || !(0.0..=1.0).contains(&face.score)
        || face.bbox[2] <= face.bbox[0]
        || face.bbox[3] <= face.bbox[1]
    {
        return Err(());
    }
    pad.p_fake(&view, &face.bbox).map(Some).map_err(|_| ())
}

use std::os::unix::fs::OpenOptionsExt;

fn run() -> Result<Counts, ()> {
    let args: Vec<_> = std::env::args().skip(1).collect();
    let [detector, flir, directory] = args.as_slice() else {
        return Err(());
    };
    if irlume_common::dbglog::on()
        || [detector, flir]
            .iter()
            .any(|p| !Path::new(p).is_absolute() || !Path::new(p).is_file())
    {
        return Err(());
    }
    let paths = pgms(Path::new(directory))?;
    let mut det = irlume_vision::Detector::load_from_file(detector).map_err(|_| ())?;
    let mut pad = irlume_vision::PadIr::load_from_file(flir).map_err(|_| ())?;
    let mut counts = Counts::default();
    for path in paths {
        counts.record(
            frame(&path, &mut det, &mut pad),
            irlume_auth::IR_PAD_THRESHOLD,
        );
    }
    Ok(counts)
}

fn main() -> std::process::ExitCode {
    // No input/model reads occur until dump prevention and stderr suppression succeed.
    let result = protect_process().and_then(|()| {
        std::panic::set_hook(Box::new(|_| {}));
        std::panic::catch_unwind(run).map_err(|_| ())?
    });
    // Setup failures have zero frames and one invalid_or_failed operation.
    let counts = result.unwrap_or(Counts {
        invalid_or_failed: 1,
        ..Counts::default()
    });
    let output = serde_json::json!({
        "schema_version": 1, "diagnostic_only": true, "authentication_granted": false,
        "total_frames": counts.total_frames, "no_face": counts.no_face,
        "pad_evaluated": counts.pad_evaluated, "pad_refused": counts.pad_refused,
        "pad_below_threshold": counts.pad_below_threshold, "invalid_or_failed": counts.invalid_or_failed,
    });
    if writeln!(std::io::stdout().lock(), "{output}").is_err() {
        return std::process::ExitCode::FAILURE;
    }
    std::process::ExitCode::from(counts.exit_code())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn preserves_binary_whitespace_and_hash_pixels() {
        let raw = b"P5\n# fixture\n3 1\n255\n\n #";
        assert_eq!(parse_pgm(raw), Ok((3, 1, &b"\n #"[..])));
    }
    #[test]
    fn rejects_malformed_dimensions_headers_and_raster_lengths() {
        for raw in [
            &b"P5\n0 1\n255\n"[..],
            &b"P5\n4097 1\n255\nx"[..],
            &b"P5\n184467440737095516160 1\n255\nx"[..],
            &b"P5\n1 1\n256\nx"[..],
            &b"P5\n1 1\n255x"[..],
            &b"P51 1 255\nx"[..],
            &b"P2\n1 1\n255\nx"[..],
            &b"P5\n1 1\n255\n"[..],
            &b"P5\n1 1\n255\nxy"[..],
            &b"P5\n1x1\n255\nx"[..],
            &b"P5\n# unfinished"[..],
        ] {
            assert!(parse_pgm(raw).is_err());
        }
    }
    #[test]
    fn missing_face_never_credits_pad() {
        let mut c = Counts::default();
        c.record(Ok(None), 0.9);
        assert_eq!(
            (
                c.total_frames,
                c.no_face,
                c.pad_evaluated,
                c.pad_below_threshold,
                c.invalid_or_failed
            ),
            (1, 1, 0, 0, 0)
        );
    }
    #[test]
    fn threshold_equality_refuses_and_invalid_pad_fails() {
        let mut c = Counts::default();
        for p in [0.0, 0.9, 1.0, f32::NAN, f32::INFINITY, -0.1, 1.1] {
            c.record(Ok(Some(p)), 0.9);
        }
        c.record(Err(()), 0.9);
        assert_eq!(
            (
                c.total_frames,
                c.pad_evaluated,
                c.pad_refused,
                c.pad_below_threshold,
                c.invalid_or_failed
            ),
            (8, 3, 2, 1, 5)
        );
        assert_ne!(c.exit_code(), 0);
    }
}

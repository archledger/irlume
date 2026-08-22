// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright the irlume contributors.

//! Native RGB anti-spoof cues, per frame, from RGB PPMs already on disk.
//!
//! Companion to [`liveness_replay`](liveness_replay.rs) for the RGB side: it
//! computes the SHIPPED cues the RGB-only gate consumes — moiré peakiness
//! ([`irlume_vision::moire`]) plus face-box scale and crop luma — from stored
//! frames, with nothing reimplemented. Built for the 2026-08-22 ViT-PAD
//! qualification corpus analysis (does the native cue see the
//! phone-at-login-distance species the ViT missed?), and kept as the replay
//! instrument for any future RGB PAD candidate.
//!
//! Reads binary P6 PPMs (ffmpeg default), walks the root recursively, uses
//! the relative parent directory as the condition label.
//!
//! Usage: cargo run --release -p irlume-auth --example moire_replay -- \
//!   <yunet.onnx> <corpus_root> [out.csv]

use irlume_vision::align::RgbView;
use irlume_vision::moire::{face_gray_n, moire_score};
use irlume_vision::Detector;
use std::io::Write as _;
use std::path::{Path, PathBuf};

/// Strict binary PPM (P6) reader: 8-bit RGB, maxval 255, whitespace/comment
/// tolerant header, no extensions.
fn read_ppm(path: &Path) -> Result<(u32, u32, Vec<u8>), String> {
    let raw = std::fs::read(path).map_err(|e| format!("{}: {e}", path.display()))?;
    if !raw.starts_with(b"P6") {
        return Err(format!("{}: not a binary PPM (no P6)", path.display()));
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
            return Err(format!("{}: truncated PPM header", path.display()));
        }
        fields.push(
            std::str::from_utf8(&raw[start..i])
                .ok()
                .and_then(|s| s.parse().ok())
                .ok_or_else(|| format!("{}: bad PPM header field", path.display()))?,
        );
    }
    // Exactly one whitespace byte after maxval before raster data.
    i += 1;
    let (w, h, maxval) = (fields[0], fields[1], fields[2]);
    if maxval != 255 {
        return Err(format!("{}: maxval {maxval} != 255", path.display()));
    }
    let len = (w * h * 3) as usize;
    if raw.len() < i + len {
        return Err(format!("{}: truncated PPM raster", path.display()));
    }
    Ok((w as u32, h as u32, raw[i..i + len].to_vec()))
}

fn walk_ppms(root: &Path, out: &mut Vec<PathBuf>) {
    if root.is_file() {
        out.push(root.to_path_buf());
        return;
    }
    let mut stack = vec![root.to_path_buf()];
    while let Some(dir) = stack.pop() {
        let Ok(entries) = std::fs::read_dir(&dir) else {
            continue;
        };
        for e in entries.flatten() {
            let p = e.path();
            if p.is_dir() {
                stack.push(p);
            } else if p.extension().is_some_and(|x| x == "ppm") {
                out.push(p);
            }
        }
    }
    out.sort();
}

fn main() -> Result<(), String> {
    let mut args = std::env::args().skip(1);
    let det_path = args
        .next()
        .ok_or("usage: moire_replay <yunet.onnx> <root> [out.csv]")?;
    let root = PathBuf::from(args.next().ok_or("missing corpus root")?);
    let out_path = args.next();

    let mut det = Detector::load_from_file(&det_path).map_err(|e| e.to_string())?;

    let mut files = Vec::new();
    walk_ppms(&root, &mut files);
    if files.is_empty() {
        return Err(format!("no .ppm under {}", root.display()));
    }

    let mut csv = String::from("cond,frame,box_w,box_h,luma,moire\n");
    for f in &files {
        let label = f
            .ancestors()
            .nth(2)
            .map(|a| {
                a.file_name()
                    .unwrap_or_default()
                    .to_string_lossy()
                    .to_string()
            })
            .unwrap_or_else(|| "root".into());
        let (w, h, rgb) = match read_ppm(f) {
            Ok(v) => v,
            Err(e) => {
                csv.push_str(&format!("{label},{f:?},read-err,,,\n"));
                eprintln!("{e}");
                continue;
            }
        };
        let view = RgbView {
            data: &rgb,
            width: w,
            height: h,
        };
        let faces = det.detect(&view).map_err(|e| e.to_string())?;
        let top = faces.iter().max_by(|a, b| {
            let sa = (a.bbox[2] - a.bbox[0]) * (a.bbox[3] - a.bbox[1]);
            let sb = (b.bbox[2] - b.bbox[0]) * (b.bbox[3] - b.bbox[1]);
            sa.partial_cmp(&sb).unwrap_or(std::cmp::Ordering::Equal)
        });
        let Some(top) = top else {
            csv.push_str(&format!(
                "{label},{},no-detect,,,\n",
                f.file_name().unwrap_or_default().to_string_lossy()
            ));
            continue;
        };
        let gray = face_gray_n(&rgb, w, h, &top.bbox);
        let moire = moire_score(&gray);
        let luma = gray.iter().map(|&p| p as u32).sum::<u32>() as f32 / gray.len() as f32;
        csv.push_str(&format!(
            "{label},{},{:.0},{:.0},{:.1},{:.2}\n",
            f.file_name().unwrap_or_default().to_string_lossy(),
            top.bbox[2] - top.bbox[0],
            top.bbox[3] - top.bbox[1],
            luma,
            moire
        ));
    }

    match out_path {
        Some(p) => std::fs::File::create(&p)
            .and_then(|mut f| f.write_all(csv.as_bytes()))
            .map_err(|e| format!("{p:?}: {e}"))?,
        None => {
            std::io::stdout().write_all(csv.as_bytes()).ok();
        }
    }
    Ok(())
}

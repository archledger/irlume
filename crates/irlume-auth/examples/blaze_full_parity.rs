// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright the irlume contributors.

//! Parity harness for the full-range BlazeFace decoder (#295 stage 2): run
//! irlume's `FullRangeBlaze` over the stored stage-3 corpus and emit one
//! CSV row per frame, comparable against the official-runtime CSV from
//! `scripts/mp-face-detector-bench.py`. The short-range decoder earned its
//! place with a 0.94-IoU parity bench against the official runtime; this is
//! the same gate for the full-range one.
//!
//! STRICT on purpose: an unreadable directory, a malformed frame, an empty
//! segment, or zero emitted rows is a loud failure, never a smaller CSV. A
//! dump that silently shrinks turns the downstream comparison
//! (`scripts/compare-blaze-parity.py`) into a vacuous pass over whatever
//! survived (#298 review).
//!
//! Usage: cargo run --release -p irlume-auth --example blaze_full_parity -- \
//!   [--floor F] <blaze_face_full_range.tflite> <corpus_root>... > rust.csv
//!   (--floor overrides the decoder's 0.6 default; threshold MEASUREMENT
//!   needs the sub-floor score distribution, especially on empty scenes)
//!   (IRLUME_TFLITE_LIB must point at libtensorflowlite_c.so)

use irlume_vision::align::RgbView;
use irlume_vision::blaze_full::FullRangeBlaze;
use std::path::Path;

fn read_pnm(p: &Path) -> Option<(Vec<u8>, u32, u32)> {
    // Same lossy header parse as detect_bench: the prefix bytes after the
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

fn main() {
    let mut args: Vec<String> = std::env::args().skip(1).collect();
    let mut floor = irlume_vision::blaze_full::FULL_RANGE_SCORE_THRESHOLD;
    if args.first().map(String::as_str) == Some("--floor") {
        args.remove(0);
        floor = args.remove(0).parse().expect("--floor takes a number");
    }
    let (model_path, roots) = args
        .split_first()
        .expect("usage: blaze_full_parity [--floor F] <model.tflite> <corpus_root>...");
    assert!(!roots.is_empty(), "at least one corpus root is required");
    let bytes = std::fs::read(model_path).expect("read model");
    let mut det = FullRangeBlaze::from_pinned_bytes(&bytes).expect("full-range blaze");

    let mut emitted = 0usize;
    println!("camera,segment,kind,frame,score,x1,y1,x2,y2");
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
                    let top = det
                        .detect_top_at(&view, floor)
                        .unwrap_or_else(|e| panic!("{}: inference: {e}", f.display()));
                    let name = format!("{sub}/{}", f.file_name().unwrap().to_string_lossy());
                    emitted += 1;
                    match top {
                        Some((b, s)) => println!(
                            "{cam},{},{kind},{name},{s:.4},{:.1},{:.1},{:.1},{:.1}",
                            seg.file_name().to_string_lossy(),
                            b[0],
                            b[1],
                            b[2],
                            b[3]
                        ),
                        None => println!(
                            "{cam},{},{kind},{name},,,,,",
                            seg.file_name().to_string_lossy()
                        ),
                    }
                }
            }
        }
    }
    assert!(emitted > 0, "parity corpus produced zero frames");
    eprintln!("emitted {emitted} rows");
}

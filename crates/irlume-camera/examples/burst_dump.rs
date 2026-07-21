// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright the irlume contributors.

//! Dump a raw IR strobe burst to disk as PGM frames plus a means index, so
//! ambient-subtraction and depth-cue tuning can be done offline against real
//! captured conditions (e.g. direct sunlight) long after the light is gone.
//!
//! Usage: cargo run --release -p irlume-camera --example burst_dump -- <out_dir> [ir_dev] [frames]

use irlume_camera::ir_probe;
use std::io::Write;

fn main() {
    let mut a = std::env::args().skip(1);
    let out = a
        .next()
        .expect("usage: burst_dump <out_dir> [ir_dev] [frames]");
    let dev = a.next().unwrap_or_else(|| "/dev/video2".into());
    let n: usize = a.next().and_then(|s| s.parse().ok()).unwrap_or(36);

    std::fs::create_dir_all(&out).expect("create out dir");
    let frames = ir_probe::capture_raw_burst_timed(&dev, n).expect("capture");
    // means.txt columns: index, frame mean, ms since first dequeue. The third
    // column is capture-time-only data (real delivered fps, strobe cadence);
    // everything else about a frame can be recomputed offline from the PGM.
    let mut index = std::fs::File::create(format!("{out}/means.txt")).expect("index");
    for (i, (f, ms)) in frames.iter().enumerate() {
        let mean = ir_probe::mean(&f.data);
        writeln!(index, "{i:02} {mean:.1} {ms:.1}").unwrap();
        let mut pgm = std::fs::File::create(format!("{out}/frame{i:02}.pgm")).expect("frame file");
        write!(pgm, "P5\n{} {}\n255\n", f.width, f.height).unwrap();
        pgm.write_all(&f.data).unwrap();
    }
    let span_ms = frames.last().map(|(_, ms)| *ms).unwrap_or(0.0);
    let fps = if span_ms > 0.0 {
        (frames.len().saturating_sub(1)) as f64 / (span_ms / 1000.0)
    } else {
        0.0
    };
    println!(
        "{}: wrote {} frames ({}x{}) in {:.0} ms ({:.1} fps delivered)",
        out,
        frames.len(),
        frames[0].0.width,
        frames[0].0.height,
        span_ms,
        fps
    );
}

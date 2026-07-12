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
    let frames = ir_probe::capture_raw_burst(&dev, n).expect("capture");
    let mut index = std::fs::File::create(format!("{out}/means.txt")).expect("index");
    for (i, f) in frames.iter().enumerate() {
        let mean = ir_probe::mean(&f.data);
        writeln!(index, "{i:02} {mean:.1}").unwrap();
        let mut pgm = std::fs::File::create(format!("{out}/frame{i:02}.pgm")).expect("frame file");
        write!(pgm, "P5\n{} {}\n255\n", f.width, f.height).unwrap();
        pgm.write_all(&f.data).unwrap();
    }
    println!(
        "{}: wrote {} frames ({}x{})",
        out,
        frames.len(),
        frames[0].width,
        frames[0].height
    );
}

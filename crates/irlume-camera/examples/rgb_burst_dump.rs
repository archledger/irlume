// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright the irlume contributors.

//! Dump RGB frames to disk as PPM, the color-side companion to `burst_dump`:
//! sun-blown or backlit RGB captures feed the detection-floor and fusion
//! analysis offline.
//!
//! Usage: cargo run --release -p irlume-camera --example rgb_burst_dump -- <out_dir> [rgb_dev] [frames]

use std::io::Write;

fn main() {
    let mut a = std::env::args().skip(1);
    let out = a
        .next()
        .expect("usage: rgb_burst_dump <out_dir> [rgb_dev] [frames]");
    let dev = a.next().unwrap_or_else(|| "/dev/video0".into());
    let n: usize = a.next().and_then(|s| s.parse().ok()).unwrap_or(6);

    std::fs::create_dir_all(&out).expect("create out dir");
    for i in 0..n {
        let f = irlume_camera::capture_rgb(&dev).expect("capture");
        let mut ppm = std::fs::File::create(format!("{out}/rgb{i:02}.ppm")).expect("frame file");
        write!(ppm, "P6\n{} {}\n255\n", f.width, f.height).unwrap();
        ppm.write_all(&f.data).unwrap();
        println!("rgb{i:02}: {}x{}", f.width, f.height);
    }
}

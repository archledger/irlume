// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright the irlume contributors.

//! Capture a raw IR strobe burst and dump, per frame, the FaceMesh landmark
//! coordinates plus the IR brightness sampled at each landmark, the input a
//! landmark-anchored relief prototype needs (nose vs cheek vs eye-socket
//! response to the emitter), without writing the capture+detect+mesh glue.
//!
//! Output in <out_dir>:
//!   frameNN.pgm            raw IR frame (as burst_dump writes them)
//!   frameNN.landmarks.csv  idx,x,y,brightness for each mesh point (only
//!                          when a face was detected in that frame)
//!   index.txt              per frame: idx, frame mean, ms since first
//!                          dequeue, detection score (- if none), bbox
//!
//! Brightness is the mean of the 3x3 pixel patch centered on the landmark
//! (clamped at frame borders): one pixel is noisy, a patch tracks the local
//! emitter response. Dark strobe phases usually fail detection and land in
//! index.txt without a CSV; that split is the lit/dark signal, not an error.
//!
//! Usage: cargo run --release -p irlume-auth --example landmark_dump -- \
//!   <det.onnx> <mesh.onnx> <out_dir> [ir_dev] [frames]
//! Look at the camera.

use irlume_camera::ir_probe;
use irlume_vision::{align, Detector, FaceMesh};
use std::io::Write;

/// Mean of the 3x3 patch centered on (x, y), clamped to the frame.
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

fn main() {
    let mut a = std::env::args().skip(1);
    let usage = "usage: landmark_dump <det.onnx> <mesh.onnx> <out_dir> [ir_dev] [frames]";
    let det_path = a.next().expect(usage);
    let mesh_path = a.next().expect(usage);
    let out = a.next().expect(usage);
    let dev = a.next().unwrap_or_else(|| "/dev/video2".into());
    let n: usize = a.next().and_then(|s| s.parse().ok()).unwrap_or(36);

    let mut det = Detector::load_from_file(&det_path).expect("load detector");
    let mut mesh = FaceMesh::load_from_file(&mesh_path).expect("load mesh");

    std::fs::create_dir_all(&out).expect("create out dir");
    let frames = ir_probe::capture_raw_burst_timed(&dev, n).expect("capture");

    let mut index = std::fs::File::create(format!("{out}/index.txt")).expect("index");
    let mut detected = 0usize;
    for (i, (f, ms)) in frames.iter().enumerate() {
        let mean = ir_probe::mean(&f.data);
        let mut pgm = std::fs::File::create(format!("{out}/frame{i:02}.pgm")).expect("frame file");
        write!(pgm, "P5\n{} {}\n255\n", f.width, f.height).unwrap();
        pgm.write_all(&f.data).unwrap();

        let grey_rgb = irlume_camera::grey_to_rgb(&f.data);
        let view = align::RgbView {
            data: &grey_rgb,
            width: f.width,
            height: f.height,
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
                // Full-precision coords (shortest f32 round-trip), so offline
                // re-sampling from the CSV hits the same patch center the tool
                // used; fixed decimals here would shift ~.5-boundary pixels.
                for (k, &(x, y)) in lm.iter().enumerate() {
                    let bri = patch_mean(&f.data, f.width, f.height, x, y);
                    writeln!(csv, "{k},{x},{y},{bri:.2}").unwrap();
                }
                writeln!(
                    index,
                    "{i:02} {mean:.1} {ms:.1} {:.2} {:.0},{:.0},{:.0},{:.0}",
                    t.score, t.bbox[0], t.bbox[1], t.bbox[2], t.bbox[3]
                )
                .unwrap();
                detected += 1;
            }
            None => writeln!(index, "{i:02} {mean:.1} {ms:.1} - -").unwrap(),
        }
    }
    println!(
        "{out}: {} frames ({}x{}), face+mesh in {detected}",
        frames.len(),
        frames[0].0.width,
        frames[0].0.height,
    );
}

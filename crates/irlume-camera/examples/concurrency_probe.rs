// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright the irlume contributors.

//! Measure whether this Hello module really starves when the RGB and IR
//! streams run at the same time (the module doc's "never concurrently" claim).
//!
//! Runs the crate's real capture paths: 3 sequential rounds (RGB then IR,
//! production order) and 3 concurrent rounds (RGB and IR on two threads),
//! printing per-capture wall time and frame mean brightness (a starved or
//! corrupt stream shows up as an error or a black frame). Frames are dropped;
//! nothing is written.
//!
//! Usage: cargo run --example concurrency_probe [rgb_dev] [ir_dev]

fn mean(data: &[u8]) -> f32 {
    if data.is_empty() {
        return 0.0;
    }
    data.iter().map(|&b| b as u64).sum::<u64>() as f32 / data.len() as f32
}

fn main() {
    let mut args = std::env::args().skip(1);
    let rgb_dev = args.next().unwrap_or_else(|| "/dev/video0".into());
    let ir_dev = args.next().unwrap_or_else(|| "/dev/video2".into());
    println!("probe: rgb={rgb_dev} ir={ir_dev}");

    for round in 1..=3 {
        let t0 = std::time::Instant::now();
        let rgb = irlume_camera::capture_rgb(&rgb_dev);
        let t_rgb = t0.elapsed();
        let t1 = std::time::Instant::now();
        let ir = irlume_camera::capture_ir(&ir_dev);
        let t_ir = t1.elapsed();
        match (&rgb, &ir) {
            (Ok(r), Ok(i)) => println!(
                "seq  round {round}: rgb {:?} (mean {:.0}) + ir {:?} (mean {:.0}) = total {:?}",
                t_rgb,
                mean(&r.data),
                t_ir,
                mean(&i.data),
                t0.elapsed()
            ),
            _ => println!(
                "seq  round {round}: rgb {:?} ir {:?}",
                rgb.as_ref().map(|_| "ok").map_err(|e| e.to_string()),
                ir.as_ref().map(|_| "ok").map_err(|e| e.to_string())
            ),
        }
    }

    for round in 1..=3 {
        let ir_dev2 = ir_dev.clone();
        let t0 = std::time::Instant::now();
        let ir_thread = std::thread::spawn(move || {
            let t = std::time::Instant::now();
            let r = irlume_camera::capture_ir(&ir_dev2);
            (r, t.elapsed())
        });
        let rgb = irlume_camera::capture_rgb(&rgb_dev);
        let t_rgb = t0.elapsed();
        let (ir, t_ir) = ir_thread.join().expect("ir thread panicked");
        let total = t0.elapsed();
        match (&rgb, &ir) {
            (Ok(r), Ok(i)) => println!(
                "conc round {round}: rgb {:?} (mean {:.0}) | ir {:?} (mean {:.0}) = total {:?}",
                t_rgb,
                mean(&r.data),
                t_ir,
                mean(&i.data),
                total
            ),
            _ => println!(
                "conc round {round}: rgb {} ir {} (total {:?})",
                rgb.as_ref()
                    .map(|_| "ok".to_string())
                    .unwrap_or_else(|e| e.to_string()),
                ir.as_ref()
                    .map(|_| "ok".to_string())
                    .unwrap_or_else(|e| e.to_string()),
                total
            ),
        }
    }
}

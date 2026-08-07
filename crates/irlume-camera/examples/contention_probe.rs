// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright the irlume contributors.

//! Run the tune contention probe (the same `measure_contention` the daemon's
//! TuneCaptureMode uses) directly against a camera pair and print the report,
//! so a capture-mode verdict can be validated on hardware without the daemon
//! or a config write. Stop irlumed first; both devices are opened directly.
//!
//! Usage: cargo run --release -p irlume-camera --example contention_probe -- \
//!   [rgb_dev] [ir_dev] [rounds]

use irlume_camera::measure_contention;

fn main() {
    let mut a = std::env::args().skip(1);
    let rgb = a.next().unwrap_or_else(|| "/dev/video0".into());
    let ir = a.next().unwrap_or_else(|| "/dev/video2".into());
    let rounds: usize = a.next().and_then(|s| s.parse().ok()).unwrap_or(3);
    println!("contention_probe: rgb={rgb} ir={ir} rounds={rounds}");
    match measure_contention(&rgb, &ir, rounds) {
        Ok(r) => {
            let arm = |name: &str, s: &irlume_camera::PairSample| {
                println!(
                    "{name}: rounds {} failed {} rgb_mean {:.1} ir_mean {:.1} {:.0} ms",
                    s.rounds, s.failed, s.rgb_mean, s.ir_mean, s.total_ms
                );
            };
            arm("sequential", &r.sequential);
            arm("concurrent", &r.concurrent);
            println!(
                "retained: rgb {:.2} ir {:.2}  concurrent_impossible: {}",
                r.retained_rgb(),
                r.retained_ir(),
                r.concurrent_impossible()
            );
            println!("verdict: {:?}", r.recommended_mode());
        }
        Err(e) => {
            eprintln!("probe error: {e}");
            std::process::exit(1);
        }
    }
}

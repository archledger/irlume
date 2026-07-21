// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright the irlume contributors.

//! A/B harness for ambient subtraction under a real ambient-IR or spoof
//! condition. For the given IR device it captures a raw strobe burst and
//! reports the emitter-OFF (ambient) frame brightness (the whole question: is
//! there ambient IR / continuous-source light to subtract? ~0 = nothing
//! present), then reports lit, ambient, and subtracted mean + center/border
//! ratio. Run it pointed at a scene (bright room) or a spoof (screen showing a
//! face).
//!
//! Usage: cargo run --release -p irlume-camera --example ambient_ab -- <ir_dev> [frames]

use irlume_camera::ir_probe;

fn main() {
    let mut a = std::env::args().skip(1);
    let dev = a.next().unwrap_or_else(|| "/dev/video2".into());
    let n: usize = a.next().and_then(|s| s.parse().ok()).unwrap_or(24);

    let frames = match ir_probe::capture_raw_burst(&dev, n) {
        Ok(f) => f,
        Err(e) => {
            eprintln!("capture failed: {e}");
            std::process::exit(1);
        }
    };
    let means: Vec<f64> = frames.iter().map(|f| ir_probe::mean(&f.data)).collect();
    let (w, h) = (frames[0].width, frames[0].height);

    // Split frames into lit (above midpoint) and ambient (below), by brightness.
    let lo = means.iter().cloned().fold(f64::INFINITY, f64::min);
    let hi = means.iter().cloned().fold(f64::NEG_INFINITY, f64::max);
    let mid = (lo + hi) / 2.0;
    let lit_i = means
        .iter()
        .enumerate()
        .max_by(|a, b| a.1.total_cmp(b.1))
        .map(|(i, _)| i)
        .unwrap();
    // Ambient = adjacent off-frame (what capture_ir uses).
    let amb_i = [lit_i.wrapping_sub(1), lit_i + 1]
        .iter()
        .filter(|&&j| j < means.len())
        .min_by(|&&a, &&b| means[a].total_cmp(&means[b]))
        .copied()
        .unwrap();

    let ambient_mean = means[amb_i];
    println!("device {dev}: {n} frames, brightness range {lo:.1}..{hi:.1} (midpoint {mid:.1})");
    println!(
        "  emitter-OFF (ambient) frame mean = {ambient_mean:.1}  <-- ambient IR present here?"
    );
    if ambient_mean < 3.0 {
        println!("  => ~0: no ambient IR / continuous source in view; subtraction is a no-op here");
    } else {
        println!("  => ambient IR present: subtraction has something to remove");
    }

    let sub = ir_probe::subtract(&frames[lit_i].data, &frames[amb_i].data);
    let lit_ratio = ir_probe::center_border_ratio(&frames[lit_i].data, w, h);
    let amb_ratio = ir_probe::center_border_ratio(&frames[amb_i].data, w, h);
    let sub_ratio = ir_probe::center_border_ratio(&sub, w, h);
    println!(
        "  lit mean {:.1} (c/b {lit_ratio:.2}) | ambient mean {ambient_mean:.1} (c/b {amb_ratio:.2}) | subtracted mean {:.1} (c/b {sub_ratio:.2})",
        means[lit_i],
        ir_probe::mean(&sub),
    );
    println!(
        "  subtraction removed {:.1} brightness ({:.0}% of lit)",
        means[lit_i] - ir_probe::mean(&sub),
        100.0 * (means[lit_i] - ir_probe::mean(&sub)) / means[lit_i].max(1.0)
    );
}

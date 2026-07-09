//! Ambient-subtraction feasibility probe. Captures a raw IR burst with the
//! emitter enabled and prints each frame's mean brightness, so we can see
//! whether the module STROBES the 850nm emitter (interleaved bright/dark
//! frames = free ambient frames for passive subtraction) or holds it STEADY
//! (needs an explicit emitter toggle). Then it demonstrates passive
//! subtraction (brightest lit frame minus the darkest frame) and reports how
//! well it isolates the near subject from the background.
//!
//! Usage: cargo run --release -p irlume-camera --example ir_strobe_probe -- <ir_dev> [frames]

use irlume_camera::ir_probe;

fn main() {
    let mut a = std::env::args().skip(1);
    let dev = a.next().unwrap_or_else(|| "/dev/video2".into());
    let n: usize = a.next().and_then(|s| s.parse().ok()).unwrap_or(24);
    println!("ir_strobe_probe: dev={dev} frames={n}\n");

    let frames = match ir_probe::capture_raw_burst(&dev, n) {
        Ok(f) => f,
        Err(e) => {
            eprintln!("capture failed: {e}");
            std::process::exit(1);
        }
    };

    let means: Vec<f64> = frames.iter().map(|f| ir_probe::mean(&f.data)).collect();
    let min = means.iter().cloned().fold(f64::INFINITY, f64::min);
    let max = means.iter().cloned().fold(f64::NEG_INFINITY, f64::max);
    println!("per-frame mean brightness:");
    for (i, m) in means.iter().enumerate() {
        let bar = "#".repeat((*m / 4.0) as usize);
        println!("  frame {i:2}: {m:6.1} {bar}");
    }
    let strobes = max - min > 20.0;
    println!(
        "\nrange {min:.1}..{max:.1} (spread {:.1}) => emitter {}",
        max - min,
        if strobes {
            "STROBES (free ambient frames available)"
        } else {
            "STEADY (needs explicit toggle for ambient)"
        }
    );

    // Passive subtraction: brightest (lit) minus darkest (ambient) frame.
    let lit = means
        .iter()
        .enumerate()
        .max_by(|a, b| a.1.total_cmp(b.1))
        .map(|(i, _)| i)
        .unwrap();
    let amb = means
        .iter()
        .enumerate()
        .min_by(|a, b| a.1.total_cmp(b.1))
        .map(|(i, _)| i)
        .unwrap();
    let sub = ir_probe::subtract(&frames[lit].data, &frames[amb].data);
    println!(
        "\npassive subtraction (frame {lit} lit {:.0} - frame {amb} ambient {:.0}):",
        means[lit], means[amb]
    );
    println!("  subtracted mean {:.1}", ir_probe::mean(&sub));
    // Contrast proxy: how much brighter is the center (near subject, lit by the
    // emitter) than the border (background) before vs after subtraction? A
    // bigger center/border ratio after subtraction means the emitter's light is
    // being isolated (the depth/liveness cue this whole feature strengthens).
    let (w, h) = (frames[lit].width, frames[lit].height);
    let raw_ratio = ir_probe::center_border_ratio(&frames[lit].data, w, h);
    let sub_ratio = ir_probe::center_border_ratio(&sub, w, h);
    println!("  center/border ratio: raw-lit {raw_ratio:.2} -> subtracted {sub_ratio:.2}");
    if sub_ratio > raw_ratio {
        println!("  => subtraction improves subject/background isolation");
    }
}

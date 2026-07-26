// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright the irlume contributors.

//! How long does the IR emitter stay lit after ONE control write?
//!
//! The capture paths re-fire the emitter control on a schedule nobody measured:
//! `capture_ir` fires again halfway through its burst, `capture_ir_sequence`
//! every 8 attempts. Those cadences are guesses about how fast the vendor
//! control self-clears, and they decide whether a stream can be held open across
//! a whole transaction (enrollment, one auth with retries) instead of being torn
//! down and rebuilt per capture.
//!
//! This fires the emitter exactly once, then watches a long single-stream burst
//! WITHOUT re-firing (`ir_probe::capture_raw_burst_timed` does precisely that)
//! and reports when the light goes away, if it does.
//!
//! Reading it: a strobing module interleaves lit and dark frames, so a single
//! frame's mean says nothing. The lit LEVEL is the rolling maximum over a short
//! window; the emitter has self-cleared when that rolling maximum collapses to
//! the dark floor and stays there.
//!
//! Usage: cargo run --release -p irlume-camera --example ir_refire_probe -- [ir_dev] [frames] [runs]

use irlume_camera::ir_probe;

/// Frames the rolling lit-level maximum is taken over. At ~15fps this is ~0.5s,
/// wide enough to contain a strobe cycle and narrow enough to place a collapse.
const WINDOW: usize = 8;

/// Frames skipped before the lit level is measured. The emitter ramp and the
/// sensor's auto-exposure both settle inside the first second; measured on the
/// ASUS built-in, frame 1 read 253.7 (blown) and the first 8-frame window read
/// 48.6 (still ramping) on a feed whose settled lit level is 144.
const WARMUP_FRAMES: usize = 20;

fn rolling_max(means: &[f64], i: usize) -> f64 {
    let lo = i.saturating_sub(WINDOW - 1);
    means[lo..=i]
        .iter()
        .cloned()
        .fold(f64::NEG_INFINITY, f64::max)
}

fn main() {
    let mut a = std::env::args().skip(1);
    let dev = a.next().unwrap_or_else(|| "/dev/video2".into());
    let frames: usize = a.next().and_then(|s| s.parse().ok()).unwrap_or(150);
    let runs: usize = a.next().and_then(|s| s.parse().ok()).unwrap_or(3);
    println!("ir_refire_probe: dev={dev} frames={frames} runs={runs}");
    println!("(emitter fired ONCE at stream start, then never again)\n");

    for run in 1..=runs {
        let burst = match ir_probe::capture_raw_burst_timed(&dev, frames) {
            Ok(b) => b,
            Err(e) => {
                eprintln!("run {run}: capture failed: {e}");
                std::process::exit(1);
            }
        };
        let means: Vec<f64> = burst.iter().map(|(f, _)| ir_probe::mean(&f.data)).collect();
        let times: Vec<f64> = burst.iter().map(|(_, ms)| *ms).collect();
        if means.is_empty() {
            eprintln!("run {run}: no frames");
            continue;
        }

        // The lit level, measured AFTER the opening frames. Those are useless as
        // a baseline in both directions: the first frames of a run measured 48.6
        // (emitter and auto-exposure still ramping) and 253.7 (blown) on the same
        // camera whose steady lit level is 144. Take the median of the rolling
        // maximum over the settled region instead, so neither a ramp nor one
        // saturated frame sets the reference.
        let settle = means.len().min(WARMUP_FRAMES);
        let mut lit_levels: Vec<f64> = (settle.max(WINDOW - 1)..means.len())
            .map(|i| rolling_max(&means, i))
            .collect();
        if lit_levels.is_empty() {
            eprintln!("run {run}: burst too short to establish a lit level");
            continue;
        }
        lit_levels.sort_by(f64::total_cmp);
        let opening = lit_levels[lit_levels.len() / 2];
        let floor = means.iter().cloned().fold(f64::INFINITY, f64::min);
        // "Still lit" = the rolling max is nearer the opening level than the
        // floor. Relative to THIS run's own extremes, so it needs no absolute
        // brightness constant and works on any module.
        let half = floor + (opening - floor) / 2.0;
        let mut cleared_at: Option<f64> = None;
        for (i, &t) in times.iter().enumerate().skip(WINDOW) {
            if rolling_max(&means, i) < half {
                cleared_at = Some(t);
                break;
            }
        }

        let span = times.last().copied().unwrap_or(0.0);
        let fps = if span > 0.0 {
            (means.len() as f64 - 1.0) / (span / 1000.0)
        } else {
            0.0
        };
        println!(
            "run {run}: {} frames over {:.0}ms ({:.1} fps) | lit {:.1} floor {:.1} half {:.1}",
            means.len(),
            span,
            fps,
            opening,
            floor,
            half
        );
        match cleared_at {
            Some(ms) => println!("  emitter went dark at {ms:.0}ms after a single write"),
            None => println!("  still lit at {span:.0}ms: no self-clear observed in this window"),
        }
        // A coarse trace so a slow decay is visible rather than only the verdict.
        let step = (means.len() / 10).max(1);
        let trace: Vec<String> = (0..means.len())
            .step_by(step)
            .map(|i| {
                format!(
                    "{:.0}@{:.0}ms",
                    rolling_max(&means, i.max(WINDOW - 1)),
                    times[i]
                )
            })
            .collect();
        println!("  lit level: {}\n", trace.join("  "));
    }
}

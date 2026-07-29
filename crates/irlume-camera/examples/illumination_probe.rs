// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright the irlume contributors.

//! Does this camera report its own per-frame illumination, and does reading it
//! change which frame the capture path picks?
//!
//! irlume used to decide "was the illuminator on?" by averaging pixels against
//! a fixed threshold. Cameras that implement Microsoft's UVC 1.5 extensions
//! answer directly, per frame. This probe reports which source is in play on
//! the camera in front of it, and what the difference amounts to.
//!
//! Run it on any machine before trusting the metadata path there:
//!
//! ```text
//! cargo run --release -p irlume-camera --example illumination_probe -- /dev/video2 [rounds]
//! ```
//!
//! `camera classified 0/N` means this camera says nothing and brightness still
//! decides, which is a supported outcome, not a failure.

use irlume_camera::capture_ir_with_stats;

fn main() {
    let mut a = std::env::args().skip(1);
    let dev = a.next().unwrap_or_else(|| "/dev/video2".into());
    let rounds: usize = a.next().and_then(|s| s.parse().ok()).unwrap_or(3);
    println!("illumination_probe: dev={dev} rounds={rounds}");
    println!("(set IRLUME_DEBUG_IR=1 for the per-capture frame-selection line)\n");

    let mut classified_total = 0usize;
    let mut frames_total = 0usize;
    for round in 1..=rounds {
        match capture_ir_with_stats(&dev) {
            Ok((frame, stats)) => {
                classified_total += stats.camera_classified_frames;
                frames_total += stats.burst_frames;
                let source = if stats.camera_classified_frames == 0 {
                    "brightness (camera reported nothing)"
                } else {
                    "camera illumination metadata"
                };
                println!(
                    "round {round}: {}x{} lit {:.1} / ambient {:.1} (gap {:.1})  \
                     camera classified {}/{} frames  source: {source}",
                    frame.width,
                    frame.height,
                    stats.lit_mean,
                    stats.ambient_mean,
                    stats.lit_mean - stats.ambient_mean,
                    stats.camera_classified_frames,
                    stats.burst_frames,
                );
            }
            Err(e) => {
                eprintln!("round {round}: capture failed: {e}");
                std::process::exit(1);
            }
        }
    }

    println!("\ntotal: {classified_total}/{frames_total} burst frames classified by the camera");
    if classified_total == 0 {
        println!(
            "this camera does not report illumination; irlume keeps using brightness here, \
             and that is the documented fallback"
        );
    }
}

// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright the irlume contributors.

//! Where does `stream_owner_release` spend its time?
//!
//! The concurrent authentication path arms an RGB and an IR session as a
//! pair, establishes the delivered rate, captures a few pairs, and then drops
//! both sessions before the decision is returned. On the NexiGo N930W that
//! drop measured 1.0–1.2 s per grant in the schema 4 trace (#797), after the
//! identity decision. This probe repeats exactly that lifecycle through the
//! crate's real paths and times the two drops SEPARATELY, in both orders, so
//! the cost can be attributed to a side before anything is reordered.
//!
//! What it found on that camera (2026-09-22, archhost): one ~0.8 s blocking
//! operation per session cycle that lands on whichever V4L2 call the sequence
//! hits at that moment. Stopping RGB first pays it inside the release every
//! time; stopping IR first releases in ~150 ms most rounds but the stall
//! then lands on the next stream start, and in the daemon that showed up as
//! rate-probe misses (+2.8 s) in 2 of 7 warm attempts. So the release ORDER
//! is not the fix; releasing after the decision is sent is (the stall is
//! deterministic where RGB stops first). The daemon keeps RGB-first.
//!
//! Frames are dropped; nothing is written. Run as root (the IR emitter is
//! driven only with device access).
//!
//! Usage: cargo run --release -p irlume-camera --example release_probe -- [rgb_dev] [ir_dev] [rounds] [alternate|ir-first|rgb-first] [pause_ms]

use std::time::Instant;

fn main() {
    let mut a = std::env::args().skip(1);
    let rgb_dev = a.next().unwrap_or_else(|| "/dev/video0".into());
    let ir_dev = a.next().unwrap_or_else(|| "/dev/video2".into());
    let rounds: usize = a.next().and_then(|s| s.parse().ok()).unwrap_or(4);
    // Optional: which order to use every round (`ir-first` / `rgb-first`;
    // default alternates), and a pause in ms between rounds, to see whether a
    // cost that moved to the next arm decays while the camera sits idle.
    let order = a.next().unwrap_or_else(|| "alternate".into());
    let pause_ms: u64 = a.next().and_then(|s| s.parse().ok()).unwrap_or(0);
    println!("release_probe: rgb={rgb_dev} ir={ir_dev} rounds={rounds} order={order} pause={pause_ms}ms\n");

    let operation = irlume_camera::lease::acquire_camera_operation(
        &[rgb_dev.as_str(), ir_dev.as_str()],
        irlume_camera::lease::CameraOperationKind::Diagnostics,
        std::time::Duration::from_secs(2),
    )
    .unwrap_or_else(|error| {
        eprintln!("pair lease failed: {error}");
        std::process::exit(1);
    });
    let rgb_cam = operation.open_rgb(&rgb_dev).unwrap_or_else(|e| {
        eprintln!("rgb open failed: {e}");
        std::process::exit(1);
    });
    let ir_cam = operation.open_ir(&ir_dev).unwrap_or_else(|e| {
        eprintln!("ir open failed: {e}");
        std::process::exit(1);
    });
    let control = irlume_camera::CaptureControl::with_progress(irlume_camera::no_progress());

    for round in 0..rounds {
        let ir_first = match order.as_str() {
            "ir-first" => true,
            "rgb-first" => false,
            _ => round % 2 == 1,
        };
        if round > 0 && pause_ms > 0 {
            std::thread::sleep(std::time::Duration::from_millis(pause_ms));
        }
        let t_arm = Instant::now();
        let mut rgb_s = rgb_cam
            .session_with_control(&control)
            .expect("rgb pair session");
        let mut ir_s = ir_cam
            .session_for_pair_with_control(&control)
            .expect("ir pair session");
        let arm = t_arm.elapsed();
        let t_rate = Instant::now();
        let rate = irlume_camera::establish_pair_rate(&mut rgb_s, &mut ir_s);
        let rate_ms = t_rate.elapsed().as_millis();
        if let Err(e) = rate {
            println!("round {round}: rate establishment failed: {e}");
            continue;
        }
        let t_cap = Instant::now();
        let mut ok = 0;
        for _ in 0..2 {
            let (r, i) = irlume_camera::capture_pair_with(
                &mut rgb_s,
                &mut ir_s,
                |rgb| rgb.denoised().map(|_| ()),
                |ir| ir.capture_with_stats().map(|_| ()),
            );
            if r.is_ok() && i.is_ok() {
                ok += 1;
            }
        }
        let cap_ms = t_cap.elapsed().as_millis();
        // The measurement: each side's drop on its own.
        let (first, second, order) = if ir_first {
            let t = Instant::now();
            drop(ir_s);
            let ir_ms = t.elapsed().as_millis();
            let t = Instant::now();
            drop(rgb_s);
            (ir_ms, t.elapsed().as_millis(), "ir then rgb")
        } else {
            let t = Instant::now();
            drop(rgb_s);
            let rgb_ms = t.elapsed().as_millis();
            let t = Instant::now();
            drop(ir_s);
            (rgb_ms, t.elapsed().as_millis(), "rgb then ir")
        };
        println!(
            "round {round}: arm {}ms, rate {rate_ms}ms, 2 pairs {cap_ms}ms ({ok} ok); release {order}: first {first}ms, second {second}ms, total {}ms",
            arm.as_millis(),
            first + second
        );
    }
}

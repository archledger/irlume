// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright the irlume contributors.

//! What does holding the camera streams open actually save?
//!
//! Runs the same number of RGB+IR capture pairs twice: once through the
//! per-call entry points (open, negotiate, map buffers, STREAMON, warm up, tear
//! down, every time) and once through a held session. The gap is the setup cost
//! that a repeated-capture loop such as enrolment was paying per frame.
//!
//! Usage: cargo run --release -p irlume-camera --example session_bench -- [rgb_dev] [ir_dev] [pairs]

fn main() {
    let mut a = std::env::args().skip(1);
    let rgb_dev = a.next().unwrap_or_else(|| "/dev/video0".into());
    let ir_dev = a.next().unwrap_or_else(|| "/dev/video2".into());
    let pairs: usize = a.next().and_then(|s| s.parse().ok()).unwrap_or(6);
    println!("session_bench: rgb={rgb_dev} ir={ir_dev} pairs={pairs}\n");

    let t0 = std::time::Instant::now();
    let mut per_call_ok = 0;
    for _ in 0..pairs {
        let rgb = irlume_camera::capture_rgb_denoised(&rgb_dev);
        let ir = irlume_camera::capture_ir_with_stats(&ir_dev);
        if rgb.is_ok() && ir.is_ok() {
            per_call_ok += 1;
        }
    }
    let per_call = t0.elapsed();

    let operation = irlume_camera::lease::acquire_camera_operation(
        &[rgb_dev.as_str(), ir_dev.as_str()],
        irlume_camera::lease::CameraOperationKind::Diagnostics,
        std::time::Duration::from_secs(2),
    )
    .unwrap_or_else(|error| {
        eprintln!("pair lease failed: {error}");
        std::process::exit(1);
    });
    let rgb_cam = match operation.open_rgb(&rgb_dev) {
        Ok(c) => c,
        Err(e) => {
            eprintln!("rgb open failed: {e}");
            std::process::exit(1);
        }
    };
    let ir_cam = match operation.open_ir(&ir_dev) {
        Ok(c) => c,
        Err(e) => {
            eprintln!("ir open failed: {e}");
            std::process::exit(1);
        }
    };
    let t1 = std::time::Instant::now();
    let mut held_ok = 0;
    {
        let mut rgb_s = rgb_cam.session().expect("rgb session");
        let mut ir_s = ir_cam.session().expect("ir session");
        for _ in 0..pairs {
            let rgb = rgb_s.denoised();
            let ir = ir_s.capture_with_stats();
            if rgb.is_ok() && ir.is_ok() {
                held_ok += 1;
            }
        }
    }
    let held = t1.elapsed();

    let per_pair = |d: std::time::Duration| d.as_millis() as f64 / pairs as f64;
    println!(
        "per-call sessions : {:>6}ms total, {:>6.0}ms per pair ({per_call_ok}/{pairs} ok)",
        per_call.as_millis(),
        per_pair(per_call)
    );
    println!(
        "held session      : {:>6}ms total, {:>6.0}ms per pair ({held_ok}/{pairs} ok)",
        held.as_millis(),
        per_pair(held)
    );
    let saved = per_pair(per_call) - per_pair(held);
    println!(
        "\nsaved {:.0}ms per capture pair ({:.0}% of the per-call cost)",
        saved,
        saved / per_pair(per_call) * 100.0
    );
}

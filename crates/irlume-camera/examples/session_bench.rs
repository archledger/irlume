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
//!
//! With --features capture-timing, --ir-target-timing ROUNDS measures the exact
//! configured adaptive IR target path and reports fixed numeric stages only.

fn timing_rounds(args: &[String]) -> Result<usize, &'static str> {
    if args.len() != 2
        || !matches!(
            args[0].as_str(),
            "--ir-target-timing" | "--ir-sequential-timing"
        )
    {
        return Err("usage: session_bench --ir-target-timing ROUNDS (1..=10)");
    }
    args[1]
        .parse::<usize>()
        .ok()
        .filter(|n| (1..=10).contains(n))
        .ok_or("rounds must be 1..=10")
}

#[cfg(feature = "capture-timing")]
fn target_timings(rounds: usize, target_bound: bool) -> Result<(), String> {
    use irlume_camera::{CaptureControl, CaptureTimings};
    use std::time::{Duration, Instant};
    // SAFETY: geteuid has no pointers or preconditions.
    if unsafe { libc::geteuid() } != 0 {
        return Err("target timing requires root and authorized camera use".into());
    }
    for round in 0..rounds {
        let started = Instant::now();
        let timings = CaptureTimings::default();
        let control = CaptureControl::with_progress(irlume_camera::no_progress())
            .with_deadline(Some(started + Duration::from_secs(20)))
            .with_capture_timings(Some(timings.clone()));
        let captured = (|| {
            if !target_bound {
                let (_, ir) = irlume_camera::configured_pair_no_probe()
                    .ok_or("configured-pair-unavailable")?;
                return irlume_camera::capture_ir_sequential_with_stats_and_control(&ir, &control)
                    .map_err(|_| "capture-failed");
            }
            let target = irlume_camera::configured_ir_target().map_err(|error| match error {
                irlume_camera::IrTargetError::Unconfigured => "target-unconfigured",
                irlume_camera::IrTargetError::InvalidEndpoint(_) => "target-invalid-endpoint",
                irlume_camera::IrTargetError::BindingUnavailable(_) => "target-binding-unavailable",
                irlume_camera::IrTargetError::UnsupportedTopology(_) => {
                    "target-unsupported-topology"
                }
                irlume_camera::IrTargetError::Changed => "target-changed",
            })?;
            let operation = irlume_camera::lease::acquire_camera_operation(
                &target.lease_endpoints(),
                irlume_camera::lease::CameraOperationKind::Diagnostics,
                Duration::from_secs(2),
            )
            .map_err(|_| "camera-lease-unavailable")?;
            target
                .capture_with_stats_and_control(&operation, &control)
                .map_err(|_| "capture-failed")
        })();
        let summary = match &captured {
            Ok((frame, stats)) => {
                std::hint::black_box(&frame.data);
                serde_json::json!({"width":frame.width,"height":frame.height,
                    "burst_frames":stats.burst_frames,"classified_frames":stats.camera_classified_frames,
                    "lit_frames":stats.camera_lit_frames})
            }
            Err(_) => serde_json::Value::Null,
        };
        let error = captured.as_ref().err().copied();
        drop(captured);
        println!(
            "{}",
            serde_json::json!({"round":round+1,"route":if target_bound {"ir-target"} else {"sequential-ir"},"capture_ok":error.is_none(),
            "error_category":error,"wall_us":started.elapsed().as_micros(),
            "stages_ms":timings.snapshot(),"rate_fill_failure":timings.rate_fill_failure().map(|f|f.as_str()),
            "capture":summary})
        );
        if error.is_some() {
            return Err("IR target capture failed; see the categorical record".into());
        }
    }
    Ok(())
}

#[cfg(not(feature = "capture-timing"))]
fn target_timings(_: usize, _: bool) -> Result<(), String> {
    Err("build session_bench with --features capture-timing".into())
}

fn main() {
    let args: Vec<_> = std::env::args().skip(1).collect();
    if args.iter().any(|arg| arg == "--help" || arg == "-h") {
        println!("session_bench [rgb_dev] [ir_dev] [pairs]\nsession_bench --ir-target-timing ROUNDS (1..=10; requires capture-timing)\nsession_bench --ir-sequential-timing ROUNDS (1..=10; requires capture-timing; RGB must be stopped)\nTiming modes use a 20s per-capture deadline and full production rate/burst checks. Target mode validates the strict IR-only topology; sequential mode exercises the existing general sequential-IR path. Stages may overlap; do not sum them. Camera use requires authorization; no frames are written.");
        return;
    }
    if args.first().is_some_and(|arg| {
        matches!(
            arg.as_str(),
            "--ir-target-timing" | "--ir-sequential-timing"
        )
    }) {
        let result = timing_rounds(&args)
            .map_err(str::to_owned)
            .and_then(|rounds| target_timings(rounds, args[0] == "--ir-target-timing"));
        if let Err(error) = result {
            eprintln!("{error}");
            std::process::exit(1);
        }
        return;
    }
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

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn target_timing_plan_is_bounded_before_camera_access() {
        for mode in ["--ir-target-timing", "--ir-sequential-timing"] {
            for count in ["1", "10"] {
                assert!(timing_rounds(&[mode.into(), count.into()]).is_ok());
            }
            for count in ["0", "11", "-1", "x", "18446744073709551616"] {
                assert!(timing_rounds(&[mode.into(), count.into()]).is_err());
            }
        }
        assert!(timing_rounds(&[]).is_err());
        assert!(timing_rounds(&["--ir-target-timing".into(), "1".into(), "extra".into()]).is_err());
    }
}

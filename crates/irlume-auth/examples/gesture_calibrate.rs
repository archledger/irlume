// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright the irlume contributors.

//! Calibrate the head-nod and head-shake gesture detectors.
//!
//! Captures IR frames, extracts head pose from each detected face, and prints
//! the pitch/yaw ranges and crossing counts that the nod/shake detectors see.
//! Run once for each gesture at each posture (sitting, reclining):
//!
//!   cargo run --release -p irlume-auth --example gesture_calibrate -- \
//!     <det.onnx> <ir_dev> <label> [frames]
//!
//!   # Nod calibration (sitting):
//!   cargo run --release -p irlume-auth --example gesture_calibrate -- \
//!     models/face_detection_yunet_2023mar.onnx /dev/video2 nod-sitting 120
//!
//!   # Shake calibration (sitting):
//!   cargo run --release -p irlume-auth --example gesture_calibrate -- \
//!     models/face_detection_yunet_2023mar.onnx /dev/video2 shake-sitting 120
//!
//!   # Nod calibration (reclining):
//!   cargo run --release -p irlume-auth --example gesture_calibrate -- \
//!     models/face_detection_yunet_2023mar.onnx /dev/video2 nod-reclining 120
//!
//! Output: CSV line with pitch/yaw ranges, crossing counts, and the verdict
//! the shipped detector returns. The numbers are what the thresholds are
//! compared against.

use irlume_liveness;
use irlume_vision::{align, Detector};

fn main() {
    let mut a = std::env::args().skip(1);
    let usage = "usage: gesture_calibrate <det.onnx> <ir_dev> <label> [frames]";
    let det_path = a.next().expect(usage);
    let dev = a.next().expect(usage);
    let label = a.next().expect(usage);
    let n: usize = a.next().and_then(|s| s.parse().ok()).unwrap_or(120);

    let mut det = Detector::load_from_file(&det_path).expect("load detector");

    // Open the IR camera and capture frames. Same path as the daemon's
    // consent_watch: convert grey IR to RGB for the detector, extract 5-point
    // landmarks for head pose.
    let frames =
        irlume_camera::ir_probe::capture_raw_burst_timed(&dev, n).expect("capture IR burst");

    let mut poses: Vec<irlume_liveness::PoseSample> = Vec::new();
    for (i, (frame, _ms)) in frames.iter().enumerate() {
        let bri =
            frame.data.iter().map(|&p| p as f32).sum::<f32>() / frame.data.len().max(1) as f32;
        let grey_rgb = irlume_camera::grey_to_rgb(&frame.data);
        let view = align::RgbView {
            data: &grey_rgb,
            width: frame.width,
            height: frame.height,
        };
        let faces = det.detect(&view).unwrap_or_default();
        if let Some(top) = faces.first() {
            let pose = irlume_vision::head_pose(&top.landmarks);
            poses.push(irlume_liveness::PoseSample {
                idx: i,
                pitch_frac: Some(pose.pitch_frac),
                yaw_signed: Some(pose.yaw_signed),
                bri,
            });
        } else {
            poses.push(irlume_liveness::PoseSample {
                idx: i,
                pitch_frac: None,
                yaw_signed: None,
                bri,
            });
        }
    }

    // Run the shipped detector
    let (verdict, ev) = irlume_liveness::detect_nod_with_evidence(&poses);

    // Compute yaw crossings for shake detection
    let yaw: Vec<f32> = poses.iter().filter_map(|s| s.yaw_signed).collect();
    let yaw_range = if yaw.is_empty() {
        0.0
    } else {
        let (mut lo, mut hi) = (f32::INFINITY, f32::NEG_INFINITY);
        for &v in &yaw {
            lo = lo.min(v);
            hi = hi.max(v);
        }
        hi - lo
    };
    let yaw_crossings = if yaw.is_empty() {
        0
    } else {
        irlume_liveness::signal_crossings(&yaw, yaw_range, irlume_liveness::NOD_CROSSING_AMP_FRAC)
    };

    // CSV output
    println!(
        "gesture,label,frames,pitch_range,yaw_range,pitch_crossings,yaw_crossings,mean_step,verdict"
    );
    println!(
        "{label},{label},{},{:.3},{:.2},{},{},{:.4},{verdict:?}",
        ev.frames, ev.pitch_range, ev.yaw_range, ev.crossings, yaw_crossings, ev.mean_step,
    );
}

// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright the irlume contributors.

//! One full `Engine::authenticate_for` with wall-clock stage timings, for
//! latency work: prints total elapsed plus the stage timings (camera open /
//! stream arm / rate establishment) and the enrollment-load overlap line
//! (IRLUME_LOG=debug), so the TPM-unseal-vs-camera-setup overlap is visible
//! in one run.
//!
//! Usage: IRLUME_LOG=debug cargo run --release -p irlume-auth \
//!   --example auth_timing -- <user> <det.onnx> <model.onnx> [rgb] [ir]
//! Look at the camera when it runs.

use irlume_common::diagnostics::{DiagnosticSink, TraceEventKind};
use std::sync::Mutex;

#[derive(Default)]
struct StageSink {
    stages: Mutex<Vec<(TraceEventKind, std::time::Instant)>>,
}

impl DiagnosticSink for StageSink {
    fn emit_trace(&self, kind: TraceEventKind) {
        if matches!(kind, TraceEventKind::StageTiming { .. }) {
            self.stages
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .push((kind, std::time::Instant::now()));
        }
    }
}

fn main() {
    let mut args = std::env::args().skip(1);
    let user = args.next().expect("user");
    let det = args.next().expect("det.onnx");
    let model = args.next().expect("model.onnx");
    let rgb = args.next().unwrap_or_else(|| "/dev/video0".into());
    let ir = args.next().unwrap_or_else(|| "/dev/video2".into());

    let mut engine = irlume_auth::Engine::load(&det, &model)
        .expect("load engine")
        .with_devices(&rgb, &ir);
    // Attach the shipped PAD cues when their model files exist (ADR-0013),
    // honouring the same env names the daemon unit sets — the dark-session
    // protocol records FLIR p_fake per auth, so the probe must exercise the
    // exact deny-only wiring a real authentication runs (assess_probe
    // pattern).
    for (env_key, attach) in [("IRLUME_VIT_PAD_MODEL", false), ("IRLUME_PAD_IR_MODEL", true)] {
        if let Ok(path) = std::env::var(env_key) {
            if std::path::Path::new(&path).exists() {
                engine = if attach {
                    engine.with_pad_ir(&path).expect("load IR PAD")
                } else {
                    engine.with_vit_pad(&path).expect("load ViT PAD")
                };
                eprintln!("auth_timing: {env_key} cue loaded ({path})");
            }
        }
    }
    let sink = StageSink::default();
    let t0 = std::time::Instant::now();
    let outcome = engine
        .authenticate_for_with_diagnostics(
            &user,
            Some("sudo"),
            irlume_auth::AuthenticationPurpose::Verify,
            &sink,
        )
        .expect("authenticate");
    println!(
        "outcome: granted={} live={} reason={}",
        outcome.granted, outcome.live, outcome.reason
    );
    println!("TOTAL authenticate_for: {:.2?}", t0.elapsed());
    for (kind, at) in sink.stages.lock().unwrap_or_else(|e| e.into_inner()).iter() {
        if let TraceEventKind::StageTiming { stage, elapsed_us } = kind {
            println!(
                "  +{:.2}s  stage {stage:?}: {:.0} ms",
                at.duration_since(t0).as_secs_f64(),
                *elapsed_us as f64 / 1000.0
            );
        }
    }
}

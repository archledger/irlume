// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright the irlume contributors.

//! One `Engine::identify()` with wall-clock timing, for diagnosing the 1:N
//! identify path (the TUI's "Identify me" action): prints the outcome and
//! elapsed time so the sequential pairing budget's effect on identify is
//! visible in one run.
//!
//! Usage: cargo run --release -p irlume-auth --example identify_timing -- \
//!   <det.onnx> <model.onnx> [rgb] [ir]

fn main() {
    let mut args = std::env::args().skip(1);
    let det = args.next().expect("det.onnx");
    let model = args.next().expect("model.onnx");
    let rgb = args.next().unwrap_or_else(|| "/dev/video0".into());
    let ir = args.next().unwrap_or_else(|| "/dev/video2".into());

    let mut engine = irlume_auth::Engine::load(&det, &model)
        .expect("load engine")
        .with_devices(&rgb, &ir);
    let t0 = std::time::Instant::now();
    let out = engine.identify().expect("identify");
    println!(
        "identify: user={:?} profile={:?} live={} score={:.3}\nreason: {}\nTOTAL: {:?}",
        out.user,
        out.profile,
        out.live,
        out.score,
        out.reason,
        t0.elapsed()
    );
}

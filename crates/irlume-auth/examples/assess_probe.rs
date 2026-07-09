//! Drive the real Engine::assess (assess_full, the overlapped-capture +
//! cross-spectrum self-heal path) N times on a given camera pair and report
//! the liveness verdict and whether the RGB self-heal fired (from the
//! Assessment: an RGB face present is the recovered state). Run with
//! IRLUME_LOG=debug to see the per-stage `assess:` trace including the
//! "recapturing RGB alone" line.
//!
//! Usage: cargo run --release -p irlume-auth --example assess_probe -- \
//!   <det.onnx> <model.onnx> <rgb_dev> <ir_dev> [runs]
//! Look at the camera.

fn main() {
    let mut a = std::env::args().skip(1);
    let det = a.next().expect("det.onnx");
    let model = a.next().expect("model.onnx");
    let rgb_dev = a.next().unwrap_or_else(|| "/dev/video0".into());
    let ir_dev = a.next().unwrap_or_else(|| "/dev/video2".into());
    let runs: usize = a.next().and_then(|s| s.parse().ok()).unwrap_or(6);

    let mut engine = irlume_auth::Engine::load(&det, &model)
        .expect("load engine")
        .with_devices(&rgb_dev, &ir_dev);
    println!("assess_probe: rgb={rgb_dev} ir={ir_dev} runs={runs}\nLook at the camera.\n");

    let (mut live, mut rgb_face, mut ir_face) = (0, 0, 0);
    for i in 0..runs {
        match engine.assess() {
            Ok(a) => {
                let has_rgb = a.signals.rgb_face.is_some();
                let has_ir = a.signals.ir_face.is_some();
                if has_rgb {
                    rgb_face += 1;
                }
                if has_ir {
                    ir_face += 1;
                }
                if format!("{:?}", a.verdict) == "Live" {
                    live += 1;
                }
                println!(
                    "run {i}: {:?} (rgb_face={has_rgb} ir_face={has_ir} ir_bright={:.0} ir_depth={:.2}) {}",
                    a.verdict, a.ir_brightness, a.ir_depth, a.reason
                );
            }
            Err(e) => println!("run {i}: error {e}"),
        }
    }
    println!(
        "\nsummary over {runs}: Live {live}/{runs}, RGB face {rgb_face}/{runs}, IR face {ir_face}/{runs}"
    );
}

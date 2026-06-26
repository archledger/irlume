//! `irlume` — operator CLI. A thin, unprivileged client of `irlumed` (same socket
//! protocol as the PAM module). Enrollment requests are authorized by the daemon
//! via SO_PEERCRED, not by this binary.
//!
//! Subcommands (planned):
//!   irlume enroll [--user U] [--profile NAME]   register a face profile
//!   irlume verify [--user U]                     one-shot auth test
//!   irlume profiles [--user U]                   list profiles
//!   irlume delete  --user U --profile NAME       remove a profile
//!   irlume selftest align --model <PATH>         Phase-1 gate: same crop -> ~1.0
//!   irlume selftest liveness                     run the IR PAD cues
//!   irlume doctor                                check cameras/IR/TPM/models

fn flag<'a>(args: &'a [String], name: &str) -> Option<&'a str> {
    args.iter().position(|a| a == name).and_then(|i| args.get(i + 1)).map(String::as_str)
}

fn main() -> std::process::ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    match (args.first().map(String::as_str), args.get(1).map(String::as_str)) {
        (Some("selftest"), Some("align")) => selftest_align(&args),
        (Some("capture"), _) => capture(&args),
        (Some("eval"), _) => eval(&args),
        (Some("doctor"), _) => doctor(),
        (Some(cmd), _) => {
            println!("irlume: '{cmd}' not yet implemented (scaffold)");
            std::process::ExitCode::SUCCESS
        }
        (None, _) => {
            println!("irlume <enroll|verify|profiles|delete|selftest|doctor>");
            std::process::ExitCode::SUCCESS
        }
    }
}

/// Embed every detected face in an image and report the pairwise-cosine
/// distribution. In a group photo every pair is a different person, so this is
/// the IMPOSTOR distribution: it validates AuraFace discriminates (impostors
/// should score low) and sets the threshold floor (must sit above impostor max).
fn eval(args: &[String]) -> std::process::ExitCode {
    let (Some(img), Some(det_path), Some(model)) =
        (flag(args, "--image"), flag(args, "--det"), flag(args, "--model"))
    else {
        eprintln!("usage: irlume eval --image <group.jpg> --det <yunet.onnx> --model <glintr100.onnx>");
        return std::process::ExitCode::from(2);
    };
    let rgb = match image::open(img) {
        Ok(i) => i.to_rgb8(),
        Err(e) => {
            eprintln!("image load failed: {e}");
            return std::process::ExitCode::FAILURE;
        }
    };
    let (w, h) = rgb.dimensions();
    let data = rgb.into_raw();
    let view = irlume_vision::align::RgbView { data: &data, width: w, height: h };

    let run = || -> irlume_common::Result<()> {
        let mut det = irlume_vision::Detector::load_from_file(det_path)?;
        let mut emb = irlume_vision::Embedder::load_from_file(model)?;
        let faces = det.detect(&view)?;
        println!("[eval] {} faces; embedding each…", faces.len());
        let mut embs = Vec::new();
        for f in &faces {
            let chip = irlume_vision::align::align_to_arcface(&view, &f.landmarks)?;
            embs.push(emb.embed(&chip)?);
        }
        // All pairwise cosines = impostor scores (distinct people).
        let mut scores = Vec::new();
        for i in 0..embs.len() {
            for j in (i + 1)..embs.len() {
                scores.push(irlume_vision::align::cosine(&embs[i], &embs[j]));
            }
        }
        if scores.is_empty() {
            println!("[eval] need >=2 faces for pairwise stats.");
            return Ok(());
        }
        scores.sort_by(f32::total_cmp);
        let n = scores.len();
        let mean = scores.iter().sum::<f32>() / n as f32;
        let pct = |p: f32| scores[((p * (n - 1) as f32).round() as usize).min(n - 1)];
        println!("[eval] impostor pairs: {n}");
        println!("  min {:.3}  mean {:.3}  p95 {:.3}  p99 {:.3}  max {:.3}",
            scores[0], mean, pct(0.95), pct(0.99), scores[n - 1]);
        println!("  => threshold floor (above impostor max): {:.3}", scores[n - 1] + 0.02);
        println!("  (genuine pairs — same person, 2 captures — set the ceiling; run two `capture` sessions to measure.)");
        Ok(())
    };
    match run() {
        Ok(()) => std::process::ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("eval error: {e}");
            std::process::ExitCode::FAILURE
        }
    }
}

/// Preflight diagnostics ("preparing"): discover + classify cameras, flag the
/// privacy switch, and confirm models + ONNX Runtime are present.
fn doctor() -> std::process::ExitCode {
    println!("[doctor] camera nodes (classified by pixel format):");
    let nodes = irlume_camera::discover_nodes();
    if nodes.is_empty() {
        println!("  (none found under /dev/video0..9)");
    }
    for (path, role) in &nodes {
        let priv_on = if irlume_camera::privacy_engaged(path) { "  ⚠ PRIVACY SWITCH ON" } else { "" };
        println!("  {path}: {role:?}{priv_on}");
    }
    println!("[doctor] models:");
    for m in ["models/glintr100.onnx", "models/face_detection_yunet_2023mar.onnx"] {
        let ok = std::path::Path::new(m).exists();
        println!("  {m}: {}", if ok { "present ✓" } else { "MISSING ✗" });
    }
    let ort = std::env::var("ORT_DYLIB_PATH").unwrap_or_default();
    println!("[doctor] ORT_DYLIB_PATH: {}", if ort.is_empty() { "(unset)".into() } else { ort });
    std::process::ExitCode::SUCCESS
}

/// Full live pipeline on one camera frame: capture RGB → YuNet detect → align
/// the top face → AuraFace embed. Prints what each stage produced. Needs both
/// model files + `libonnxruntime.so` (ORT_DYLIB_PATH) and camera access.
fn capture(args: &[String]) -> std::process::ExitCode {
    let device = flag(args, "--device").unwrap_or("/dev/video0");
    let (Some(det_path), Some(model)) = (flag(args, "--det"), flag(args, "--model")) else {
        eprintln!("usage: irlume capture --det <yunet.onnx> --model <glintr100.onnx> [--device /dev/videoN]");
        return std::process::ExitCode::from(2);
    };

    // Source: a still image (--image, for validating the decode) or the camera.
    let (data, width, height) = if let Some(path) = flag(args, "--image") {
        match image::open(path) {
            Ok(img) => {
                let rgb = img.to_rgb8();
                let (w, h) = rgb.dimensions();
                println!("[capture] {w}x{h} from image {path}");
                (rgb.into_raw(), w, h)
            }
            Err(e) => {
                eprintln!("image load failed: {e}");
                return std::process::ExitCode::FAILURE;
            }
        }
    } else {
        match irlume_camera::capture_rgb(device) {
            Ok(f) => {
                println!("[capture] {}x{} RGB frame from {device}", f.width, f.height);
                (f.data, f.width, f.height)
            }
            Err(e) => {
                eprintln!("capture failed: {e}");
                return std::process::ExitCode::FAILURE;
            }
        }
    };
    let view = irlume_vision::align::RgbView { data: &data, width, height };

    let run = || -> irlume_common::Result<()> {
        let mut det = irlume_vision::Detector::load_from_file(det_path)?;
        let faces = det.detect(&view)?;
        println!("[detect] {} face(s)", faces.len());
        let Some(top) = faces.iter().max_by(|a, b| a.score.total_cmp(&b.score)) else {
            println!("  no face in frame — sit in view and re-run.");
            return Ok(());
        };
        println!(
            "[detect] top: score {:.3}, bbox [{:.0},{:.0},{:.0},{:.0}]",
            top.score, top.bbox[0], top.bbox[1], top.bbox[2], top.bbox[3]
        );
        let chip = irlume_vision::align::align_to_arcface(&view, &top.landmarks)?;
        let mut emb = irlume_vision::Embedder::load_from_file(model)?;
        let e = emb.embed(&chip)?;
        let norm = e.iter().map(|x| x * x).sum::<f32>().sqrt();
        println!("[embed]  512-D, L2 norm {norm:.4}, head [{:.3}, {:.3}, {:.3}, {:.3}]", e[0], e[1], e[2], e[3]);
        println!("[ok] full pipeline ran: capture → detect → align → embed.");
        Ok(())
    };
    match run() {
        Ok(()) => std::process::ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("pipeline error: {e}");
            std::process::ExitCode::FAILURE
        }
    }
}

/// Phase-1 make-or-break: load the recognition model and embed the same chip
/// twice — cosine MUST be ~1.0. Proves the ONNX path is deterministic and the
/// preprocessing is wired before any matching is trusted. Needs the AuraFace
/// model file and `libonnxruntime.so` available at runtime.
fn selftest_align(args: &[String]) -> std::process::ExitCode {
    let model = match flag(args, "--model") {
        Some(p) => p,
        None => {
            eprintln!("usage: irlume selftest align --model <glintr100.onnx>");
            return std::process::ExitCode::from(2);
        }
    };
    match irlume_vision::Embedder::load_from_file(model) {
        Ok(mut emb) => {
            let (passed, detail) = irlume_vision::selftest_alignment_identity(&mut emb);
            println!("[selftest align] {detail}");
            if passed {
                println!("[selftest align] PASS — ONNX embed path is deterministic.");
                std::process::ExitCode::SUCCESS
            } else {
                eprintln!("[selftest align] FAIL — check preprocessing / channel order.");
                std::process::ExitCode::FAILURE
            }
        }
        Err(e) => {
            eprintln!("[selftest align] could not load model: {e}");
            eprintln!("  (need the .onnx file and libonnxruntime.so on the system)");
            std::process::ExitCode::FAILURE
        }
    }
}

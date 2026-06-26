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
        (Some("genuine"), _) => genuine(&args),
        (Some("liveness"), _) => liveness_probe(&args),
        (Some("enroll"), _) => enroll(&args),
        (Some("verify"), _) => verify(&args),
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

/// One full capture: RGB+IR, liveness verdict, and (if a face) its embedding.
struct Assessment {
    verdict: irlume_liveness::Verdict,
    reason: String,
    embedding: Option<[f32; irlume_vision::EMBED_DIM]>,
    ir_depth: f32,
    ir_brightness: f32,
}

/// Capture RGB+IR, run detect → align → embed (RGB) and the liveness gate.
fn assess(
    det: &mut irlume_vision::Detector,
    emb: &mut irlume_vision::Embedder,
    rgb_dev: &str,
    ir_dev: &str,
) -> irlume_common::Result<Assessment> {
    let rgb = irlume_camera::capture_rgb(rgb_dev)?;
    let rgb_view = irlume_vision::align::RgbView { data: &rgb.data, width: rgb.width, height: rgb.height };
    let rgb_faces = det.detect(&rgb_view)?;
    let rgb_top = rgb_faces.iter().max_by(|a, b| a.score.total_cmp(&b.score));

    let ir = irlume_camera::capture_ir(ir_dev)?;
    let ir_view = {
        let g = irlume_camera::grey_to_rgb(&ir.data);
        // detect on a replicated-grey RGB view (build owned buffer)
        let faces = {
            let v = irlume_vision::align::RgbView { data: &g, width: ir.width, height: ir.height };
            det.detect(&v)?
        };
        (faces,)
    };
    let ir_faces = ir_view.0;
    let ir_top = ir_faces.iter().max_by(|a, b| a.score.total_cmp(&b.score));

    let fbox = |f: &irlume_vision::Detection, w: u32, h: u32| irlume_liveness::FaceBox {
        cx: (f.bbox[0] + f.bbox[2]) / 2.0 / w as f32,
        cy: (f.bbox[1] + f.bbox[3]) / 2.0 / h as f32,
        score: f.score,
    };
    let ir_brightness = ir_top.map(|f| mean_in_bbox(&ir.data, ir.width, ir.height, &f.bbox)).unwrap_or(0.0);
    let ir_depth = ir_top.map(|f| center_edge_ratio(&ir.data, ir.width, ir.height, &f.bbox)).unwrap_or(0.0);
    let signals = irlume_liveness::Signals {
        rgb_face: rgb_top.map(|f| fbox(f, rgb.width, rgb.height)),
        ir_face: ir_top.map(|f| fbox(f, ir.width, ir.height)),
        ir_face_brightness: ir_brightness,
        ir_center_edge_ratio: ir_depth,
        ir_eye_glint: ir_top.map(|f| eye_glint(&ir.data, ir.width, ir.height, &f.landmarks)).unwrap_or(0.0),
    };
    let (verdict, _cues, reason) = irlume_liveness::LivenessGate::new().evaluate(&signals);

    let embedding = match rgb_top {
        Some(f) => {
            let chip = irlume_vision::align::align_to_arcface(&rgb_view, &f.landmarks)?;
            Some(emb.embed(&chip)?)
        }
        None => None,
    };
    Ok(Assessment { verdict, reason, embedding, ir_depth, ir_brightness })
}

/// `irlume enroll --user U` — capture several LIVE frames and store templates.
/// Frames that fail liveness are rejected (you can't enroll from a photo).
fn enroll(args: &[String]) -> std::process::ExitCode {
    let user = flag(args, "--user").unwrap_or("").to_string();
    let (Some(det_path), Some(model)) = (flag(args, "--det"), flag(args, "--model")) else {
        eprintln!("usage: irlume enroll --user U --det <yunet.onnx> --model <glintr100.onnx>");
        return std::process::ExitCode::from(2);
    };
    let user = if user.is_empty() {
        std::env::var("USER").unwrap_or_else(|_| "user".into())
    } else {
        user
    };
    const WANT: usize = 5;
    let run = || -> irlume_common::Result<()> {
        let mut det = irlume_vision::Detector::load_from_file(det_path)?;
        let mut emb = irlume_vision::Embedder::load_from_file(model)?;
        let mut templates = Vec::new();
        let (mut depths, mut brights) = (Vec::new(), Vec::new());
        println!("[enroll] '{user}' — stay in frame; capturing {WANT} live samples…");
        for attempt in 0..(WANT * 3) {
            if templates.len() >= WANT {
                break;
            }
            let a = assess(&mut det, &mut emb, irlume_camera::DEFAULT_RGB_DEVICE, irlume_camera::DEFAULT_IR_DEVICE)?;
            match (a.verdict, a.embedding) {
                (irlume_liveness::Verdict::Live, Some(e)) => {
                    templates.push(e.to_vec());
                    depths.push(a.ir_depth);
                    brights.push(a.ir_brightness);
                    println!("  sample {}/{WANT} ok (live)", templates.len());
                }
                (v, _) => println!("  attempt {} skipped: {:?} — {}", attempt + 1, v, a.reason),
            }
        }
        if templates.len() < WANT {
            return Err(irlume_common::Error::Protocol(format!(
                "only {} live samples — enrollment needs {WANT}; ensure good lighting and face in view",
                templates.len()
            )));
        }
        let profile = irlume_core::storage::Profile {
            user: user.clone(),
            templates,
            ir_depth_samples: depths,
            ir_brightness_samples: brights,
        };
        irlume_core::storage::save(&profile)?;
        println!("[enroll] saved {} templates for '{user}' -> {}", profile.templates.len(), irlume_core::storage::profile_path(&user).display());
        Ok(())
    };
    match run() {
        Ok(()) => std::process::ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("enroll failed: {e}");
            std::process::ExitCode::FAILURE
        }
    }
}

/// `irlume verify --user U` — the full auth decision: liveness gate THEN match.
fn verify(args: &[String]) -> std::process::ExitCode {
    let user = flag(args, "--user").map(str::to_string).unwrap_or_else(|| std::env::var("USER").unwrap_or_else(|_| "user".into()));
    let (Some(det_path), Some(model)) = (flag(args, "--det"), flag(args, "--model")) else {
        eprintln!("usage: irlume verify --user U --det <yunet.onnx> --model <glintr100.onnx>");
        return std::process::ExitCode::from(2);
    };
    let run = || -> irlume_common::Result<bool> {
        let Some(profile) = irlume_core::storage::load(&user)? else {
            eprintln!("no enrollment for '{user}' — run `irlume enroll --user {user} ...` first");
            return Ok(false);
        };
        let mut det = irlume_vision::Detector::load_from_file(det_path)?;
        let mut emb = irlume_vision::Embedder::load_from_file(model)?;
        let a = assess(&mut det, &mut emb, irlume_camera::DEFAULT_RGB_DEVICE, irlume_camera::DEFAULT_IR_DEVICE)?;
        // 1) Liveness first — a spoof never reaches matching.
        if a.verdict != irlume_liveness::Verdict::Live {
            println!("[verify] DENY — liveness {:?}: {}", a.verdict, a.reason);
            return Ok(false);
        }
        // 2) Match against enrolled templates at the fixed threshold.
        let Some(probe) = a.embedding else {
            println!("[verify] DENY — no face embedding");
            return Ok(false);
        };
        let best = profile
            .templates
            .iter()
            .map(|t| irlume_vision::align::cosine(&probe, t))
            .fold(f32::NEG_INFINITY, f32::max);
        let thr = irlume_core::PLACEHOLDER_MATCH_THRESHOLD;
        let granted = best >= thr;
        println!("[verify] live ✓  best match {best:.3} vs threshold {thr:.2} -> {}", if granted { "GRANT ✅" } else { "DENY ❌" });
        Ok(granted)
    };
    match run() {
        Ok(true) => std::process::ExitCode::SUCCESS,
        Ok(false) => std::process::ExitCode::FAILURE,
        Err(e) => {
            eprintln!("verify error: {e}");
            std::process::ExitCode::FAILURE
        }
    }
}

/// Mean brightness (0..255) of an 8-bit greyscale frame inside a bbox region.
fn mean_in_bbox(grey: &[u8], w: u32, h: u32, bbox: &[f32; 4]) -> f32 {
    let x1 = (bbox[0].max(0.0) as u32).min(w.saturating_sub(1));
    let y1 = (bbox[1].max(0.0) as u32).min(h.saturating_sub(1));
    let x2 = (bbox[2].max(0.0) as u32).min(w);
    let y2 = (bbox[3].max(0.0) as u32).min(h);
    let (mut sum, mut n) = (0u64, 0u64);
    for y in y1..y2 {
        for x in x1..x2 {
            sum += grey[(y * w + x) as usize] as u64;
            n += 1;
        }
    }
    if n == 0 {
        0.0
    } else {
        sum as f32 / n as f32
    }
}

/// Center-to-edge IR brightness ratio inside a face bbox (anti-flat depth cue):
/// mean of the inner half vs. the surrounding border. >1 ⇒ 3D falloff.
fn center_edge_ratio(grey: &[u8], w: u32, h: u32, bbox: &[f32; 4]) -> f32 {
    let (bw, bh) = (bbox[2] - bbox[0], bbox[3] - bbox[1]);
    if bw <= 4.0 || bh <= 4.0 {
        return 0.0;
    }
    // Inner box = central 50%.
    let inner = [bbox[0] + bw * 0.25, bbox[1] + bh * 0.25, bbox[2] - bw * 0.25, bbox[3] - bh * 0.25];
    let center = mean_in_bbox(grey, w, h, &inner);
    let whole = mean_in_bbox(grey, w, h, bbox);
    // Edge mean ≈ (whole*area - center*inner_area) / edge_area.
    let edge = (whole * 1.0 - center * 0.25) / 0.75; // areas: inner=0.25, edge=0.75
    if edge <= 1.0 {
        0.0
    } else {
        center / edge
    }
}

/// Peak IR brightness near the eye landmarks (corneal glint, supporting cue).
fn eye_glint(grey: &[u8], w: u32, h: u32, landmarks: &irlume_vision::Landmarks5) -> f32 {
    let mut peak = 0u8;
    for &(ex, ey) in &landmarks[0..2] {
        let r = 8i32;
        for dy in -r..=r {
            for dx in -r..=r {
                let x = ex as i32 + dx;
                let y = ey as i32 + dy;
                if x >= 0 && y >= 0 && (x as u32) < w && (y as u32) < h {
                    peak = peak.max(grey[(y as u32 * w + x as u32) as usize]);
                }
            }
        }
    }
    peak as f32
}

/// P2 probe: capture RGB + IR and report what the IR stream gives us — mean/min/
/// max brightness (is the emitter illuminating?), and whether YuNet finds a face
/// in each spectrum (the basis for the cross-spectrum liveness cue). Diagnostic,
/// not yet a gate.
fn liveness_probe(args: &[String]) -> std::process::ExitCode {
    let rgb_dev = flag(args, "--rgb").unwrap_or(irlume_camera::DEFAULT_RGB_DEVICE);
    let ir_dev = flag(args, "--ir").unwrap_or(irlume_camera::DEFAULT_IR_DEVICE);
    let Some(det_path) = flag(args, "--det") else {
        eprintln!("usage: irlume liveness --det <yunet.onnx> [--rgb /dev/video0] [--ir /dev/video2]");
        return std::process::ExitCode::from(2);
    };
    let run = || -> irlume_common::Result<()> {
        let mut det = irlume_vision::Detector::load_from_file(det_path)?;
        // RGB
        let rgb = irlume_camera::capture_rgb(rgb_dev)?;
        let rgb_view =
            irlume_vision::align::RgbView { data: &rgb.data, width: rgb.width, height: rgb.height };
        let rgb_faces = det.detect(&rgb_view)?;
        let rgb_top = rgb_faces.iter().map(|f| f.score).fold(0.0f32, f32::max);
        println!("[RGB] {}x{}  faces {}  top score {:.3}", rgb.width, rgb.height, rgb_faces.len(), rgb_top);
        // IR
        let ir = irlume_camera::capture_ir(ir_dev)?;
        let (mn, mx, sum) = ir.data.iter().fold((255u8, 0u8, 0u64), |(mn, mx, s), &p| {
            (mn.min(p), mx.max(p), s + p as u64)
        });
        let mean = sum as f64 / ir.data.len() as f64;
        println!("[IR ] {}x{}  brightness mean {:.1} min {} max {}", ir.width, ir.height, mean, mn, mx);
        let ir_rgb = irlume_camera::grey_to_rgb(&ir.data);
        let ir_view =
            irlume_vision::align::RgbView { data: &ir_rgb, width: ir.width, height: ir.height };
        let ir_faces = det.detect(&ir_view)?;
        let ir_top_face = ir_faces.iter().max_by(|a, b| a.score.total_cmp(&b.score));
        println!("[IR ] faces {}  top score {:.3}", ir_faces.len(), ir_top_face.map_or(0.0, |f| f.score));

        // Build signals for the gate.
        let to_fbox = |f: &irlume_vision::Detection, w: u32, h: u32| irlume_liveness::FaceBox {
            cx: (f.bbox[0] + f.bbox[2]) / 2.0 / w as f32,
            cy: (f.bbox[1] + f.bbox[3]) / 2.0 / h as f32,
            score: f.score,
        };
        let ir_face_brightness = ir_top_face
            .map(|f| mean_in_bbox(&ir.data, ir.width, ir.height, &f.bbox))
            .unwrap_or(0.0);
        let ir_center_edge_ratio =
            ir_top_face.map(|f| center_edge_ratio(&ir.data, ir.width, ir.height, &f.bbox)).unwrap_or(0.0);
        let ir_eye_glint =
            ir_top_face.map(|f| eye_glint(&ir.data, ir.width, ir.height, &f.landmarks)).unwrap_or(0.0);
        let signals = irlume_liveness::Signals {
            rgb_face: rgb_faces.iter().max_by(|a, b| a.score.total_cmp(&b.score)).map(|f| to_fbox(f, rgb.width, rgb.height)),
            ir_face: ir_top_face.map(|f| to_fbox(f, ir.width, ir.height)),
            ir_face_brightness,
            ir_center_edge_ratio,
            ir_eye_glint,
        };
        let (verdict, cues, reason) = irlume_liveness::LivenessGate::new().evaluate(&signals);
        println!("[gate] IR face brightness {ir_face_brightness:.0}  center/edge {ir_center_edge_ratio:.2}  eye-glint {ir_eye_glint:.0}");
        println!("[gate] cues: rgb={} ir={} aligned={} ir_reflective={} depth={} glint={}",
            cues.face_in_rgb, cues.face_in_ir, cues.cross_spectrum_aligned, cues.ir_reflectance_ok, cues.depth_ok, cues.glint_present);
        println!("[GATE] {verdict:?} — {reason}");
        Ok(())
    };
    match run() {
        Ok(()) => std::process::ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("liveness probe error: {e}");
            std::process::ExitCode::FAILURE
        }
    }
}

/// Capture several frames of the (one) live person, embed each, and report the
/// GENUINE cosine distribution. Compared to the impostor ceiling (~0.42 from
/// `eval`), this shows the separation and lets us set the operating threshold.
fn genuine(args: &[String]) -> std::process::ExitCode {
    let device = flag(args, "--device").unwrap_or("/dev/video0");
    let (Some(det_path), Some(model)) = (flag(args, "--det"), flag(args, "--model")) else {
        eprintln!("usage: irlume genuine --det <yunet.onnx> --model <glintr100.onnx>");
        return std::process::ExitCode::from(2);
    };
    const FRAMES: usize = 5;
    let run = || -> irlume_common::Result<()> {
        let mut det = irlume_vision::Detector::load_from_file(det_path)?;
        let mut emb = irlume_vision::Embedder::load_from_file(model)?;
        let mut embs = Vec::new();
        println!("[genuine] stay in frame — capturing {FRAMES} frames…");
        for k in 0..FRAMES {
            let f = irlume_camera::capture_rgb(device)?;
            let view = irlume_vision::align::RgbView { data: &f.data, width: f.width, height: f.height };
            let faces = det.detect(&view)?;
            match faces.iter().max_by(|a, b| a.score.total_cmp(&b.score)) {
                Some(top) => {
                    let chip = irlume_vision::align::align_to_arcface(&view, &top.landmarks)?;
                    embs.push(emb.embed(&chip)?);
                    println!("  frame {}: face score {:.3}", k + 1, top.score);
                }
                None => println!("  frame {}: no face", k + 1),
            }
        }
        if embs.len() < 2 {
            println!("[genuine] need >=2 frames with a face — re-run staying in view.");
            return Ok(());
        }
        let mut scores = Vec::new();
        for i in 0..embs.len() {
            for j in (i + 1)..embs.len() {
                scores.push(irlume_vision::align::cosine(&embs[i], &embs[j]));
            }
        }
        scores.sort_by(f32::total_cmp);
        let mean = scores.iter().sum::<f32>() / scores.len() as f32;
        println!("[genuine] {} pairs: min {:.3}  mean {:.3}  max {:.3}",
            scores.len(), scores[0], mean, scores[scores.len() - 1]);
        let impostor_max = 0.423;
        println!("  impostor max (from eval): {impostor_max:.3}");
        if scores[0] > impostor_max {
            let mid = (scores[0] + impostor_max) / 2.0;
            println!("  ✓ SEPARABLE — genuine min {:.3} > impostor max {:.3}; midpoint threshold ≈ {:.3}",
                scores[0], impostor_max, mid);
        } else {
            println!("  ⚠ overlap — genuine min {:.3} ≤ impostor max; needs better alignment/lighting or per-profile (e.g. glasses) enrollment",
                scores[0]);
        }
        Ok(())
    };
    match run() {
        Ok(()) => std::process::ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("genuine error: {e}");
            std::process::ExitCode::FAILURE
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

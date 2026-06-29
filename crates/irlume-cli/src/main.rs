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

mod fingerprint;

fn flag<'a>(args: &'a [String], name: &str) -> Option<&'a str> {
    args.iter().position(|a| a == name).and_then(|i| args.get(i + 1)).map(String::as_str)
}

fn main() -> std::process::ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    match (args.first().map(String::as_str), args.get(1).map(String::as_str)) {
        (Some("selftest"), Some("align")) => selftest_align(&args),
        (Some("capture"), _) => capture(&args),
        (Some("eval"), _) => eval(&args),
        (Some("irbench"), _) => irbench(&args),
        (Some("genuine"), _) => genuine(&args),
        (Some("liveness"), _) => liveness_probe(&args),
        (Some("enroll"), _) => enroll(&args),
        (Some("profiles"), sub) => profiles(sub, &args),
        (Some("verify"), _) => verify(&args),
        (Some("keyring"), sub) => keyring(sub, &args),
        (Some("fingerprint"), sub) => fingerprint::run(sub, &args),
        (Some("ir-setup"), _) => ir_setup(&args),
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

/// `irlume enroll --user U [--name "..."]` — enroll a NEW face profile (captures
/// the default number of scans) via the daemon, which owns the camera. Default
/// profile name is "Face Profile N".
fn enroll(args: &[String]) -> std::process::ExitCode {
    use irlume_common::{Request, Response};
    let user = user_arg(args);
    let name = flag(args, "--name").map(String::from);
    let scans = flag(args, "--scans").and_then(|s| s.parse::<usize>().ok());
    eprintln!("[enroll] '{user}' — capturing a new face profile; stay in frame, look at the camera…");
    match daemon_request(&Request::Enroll { user, profile: name, scans }) {
        Ok(Response::Ok(msg)) => { println!("[enroll] {msg}"); std::process::ExitCode::SUCCESS }
        Ok(Response::Error(e)) => { eprintln!("enroll failed: {e}"); std::process::ExitCode::FAILURE }
        Ok(other) => { eprintln!("enroll: unexpected response {other:?}"); std::process::ExitCode::FAILURE }
        Err(e) => { eprintln!("enroll: {e}"); std::process::ExitCode::FAILURE }
    }
}

/// `irlume profiles [list|add-scan|rename|delete|eyes-open] ...` — manage the up-
/// to-3 face profiles and their scans via the daemon.
fn profiles(sub: Option<&str>, args: &[String]) -> std::process::ExitCode {
    use irlume_common::{Request, Response};
    let user = user_arg(args);
    let req = match sub {
        None | Some("list") => Request::ListProfiles { user },
        Some("add-scan") => match flag(args, "--profile") {
            Some(p) => { eprintln!("[profiles] adding a scan to '{p}' — stay in frame…"); Request::AddScan { user, profile: p.into() } }
            None => return usage_profiles(),
        },
        Some("delete") => match (flag(args, "--profile"), flag(args, "--scan")) {
            (Some(p), Some(s)) => Request::DeleteScan { user, profile: p.into(), scan: s.into() },
            (Some(p), None) => Request::DeleteProfile { user, profile: p.into() },
            _ => return usage_profiles(),
        },
        Some("rename") => match (flag(args, "--profile"), flag(args, "--scan"), flag(args, "--name")) {
            (Some(p), Some(s), Some(n)) => Request::RenameScan { user, profile: p.into(), scan: s.into(), new_name: n.into() },
            (Some(p), None, Some(n)) => Request::RenameProfile { user, profile: p.into(), new_name: n.into() },
            _ => return usage_profiles(),
        },
        Some("eyes-open") => {
            let on = args.iter().any(|a| a == "on");
            let off = args.iter().any(|a| a == "off");
            if on == off { eprintln!("usage: irlume profiles eyes-open <on|off> [--user U]"); return std::process::ExitCode::from(2); }
            Request::SetRequireEyesOpen { user, on }
        }
        _ => return usage_profiles(),
    };
    match daemon_request(&req) {
        Ok(Response::Enrollment { profiles, require_eyes_open }) => {
            if profiles.is_empty() {
                println!("[profiles] none enrolled");
            } else {
                println!("[profiles] require-eyes-open: {}", if require_eyes_open { "ON" } else { "off" });
                for p in &profiles {
                    println!("  {} ({} scans)", p.name, p.scans.len());
                    for s in &p.scans { println!("      - {s}"); }
                }
            }
            std::process::ExitCode::SUCCESS
        }
        Ok(Response::Ok(msg)) => { println!("[profiles] {msg}"); std::process::ExitCode::SUCCESS }
        Ok(Response::Error(e)) => { eprintln!("[profiles] {e}"); std::process::ExitCode::FAILURE }
        Ok(other) => { eprintln!("[profiles] unexpected response {other:?}"); std::process::ExitCode::FAILURE }
        Err(e) => { eprintln!("[profiles] {e}"); std::process::ExitCode::FAILURE }
    }
}

/// `irlume ir-setup [--dry-run]` — auto-enable the IR emitter via the daemon
/// (integrated linux-enable-ir-emitter). `--dry-run` only lists XU controls.
fn ir_setup(args: &[String]) -> std::process::ExitCode {
    use irlume_common::{Request, Response};
    let dry = args.iter().any(|a| a == "--dry-run");
    if !dry {
        eprintln!("[ir-setup] probing the IR camera and trying to enable the 850nm emitter (a few seconds)…");
    }
    match daemon_request(&Request::SetupIrEmitter { dry_run: dry }) {
        Ok(Response::Ok(msg)) => { println!("[ir-setup] {msg}"); std::process::ExitCode::SUCCESS }
        Ok(Response::Error(e)) => { eprintln!("[ir-setup] {e}"); std::process::ExitCode::FAILURE }
        Ok(other) => { eprintln!("[ir-setup] unexpected response {other:?}"); std::process::ExitCode::FAILURE }
        Err(e) => { eprintln!("[ir-setup] {e}"); std::process::ExitCode::FAILURE }
    }
}

fn usage_profiles() -> std::process::ExitCode {
    eprintln!("usage: irlume profiles [--user U] <subcommand>\n  \
        (no sub) | list                         list profiles + scans\n  \
        add-scan --profile P                    add a scan to P (improve recognition)\n  \
        rename --profile P [--scan S] --name N  rename a profile or a scan\n  \
        delete --profile P [--scan S]           delete a profile or a scan\n  \
        eyes-open <on|off>                      require eyes open to unlock");
    std::process::ExitCode::from(2)
}

/// `irlume verify --user U` — full auth via the engine: liveness gate then match
/// (RGB recognition in light, IR recognition in the dark).
fn verify(args: &[String]) -> std::process::ExitCode {
    let (Some(det), Some(model)) = (flag(args, "--det"), flag(args, "--model")) else {
        eprintln!("usage: irlume verify --user U --det <yunet.onnx> --model <glintr100.onnx> [--rgb ..] [--ir ..]");
        return std::process::ExitCode::from(2);
    };
    let user = user_arg(args);
    match engine(det, model, args).and_then(|mut e| e.authenticate(&user)) {
        Ok(o) => {
            println!("[verify] live={} score {:.3} -> {} ({})", o.live, o.score, if o.granted { "GRANT \u{2705}" } else { "DENY \u{274c}" }, o.reason);
            if o.granted { std::process::ExitCode::SUCCESS } else { std::process::ExitCode::FAILURE }
        }
        Err(e) => {
            eprintln!("verify error: {e}");
            std::process::ExitCode::FAILURE
        }
    }
}

/// `irlume keyring <arm|status|forget>` — manage the TPM-sealed login password
/// that lets a face login unlock the GNOME-keyring / KWallet. Talks to `irlumed`
/// over the socket (the daemon owns the TPM + the root-only sealed store).
fn keyring(sub: Option<&str>, args: &[String]) -> std::process::ExitCode {
    let user = user_arg(args);
    match sub {
        Some("arm") => {
            println!(
                "[keyring] Arming face-driven keyring unlock for '{user}'.\n\
                 Enter this user's LOGIN password (it will be sealed in the TPM, never stored in plaintext)."
            );
            // No-echo prompt on a real terminal; fall back to a plain stdin line
            // when piped (scripts / tests), where /dev/tty isn't available.
            let pw = if std::io::IsTerminal::is_terminal(&std::io::stdin()) {
                let first = match rpassword::prompt_password("Login password: ") {
                    Ok(p) => p,
                    Err(e) => { eprintln!("[keyring] could not read password: {e}"); return std::process::ExitCode::FAILURE; }
                };
                // Confirm to catch typos — a mistyped seal silently fails to
                // unlock the wallet at the next face login (key mismatch).
                let confirm = match rpassword::prompt_password("Confirm login password: ") {
                    Ok(p) => p,
                    Err(e) => { eprintln!("[keyring] could not read password: {e}"); return std::process::ExitCode::FAILURE; }
                };
                if first != confirm {
                    eprintln!("[keyring] passwords do not match — aborted (nothing sealed).");
                    return std::process::ExitCode::from(2);
                }
                first
            } else {
                use std::io::BufRead;
                let mut line = String::new();
                if std::io::stdin().lock().read_line(&mut line).is_err() {
                    eprintln!("[keyring] could not read password from stdin"); return std::process::ExitCode::FAILURE;
                }
                line.trim_end_matches(['\n', '\r']).to_string()
            };
            if pw.is_empty() { eprintln!("[keyring] empty password — aborted"); return std::process::ExitCode::from(2); }
            let req = irlume_common::Request::SealPassword {
                user: user.clone(),
                password: irlume_common::SecretBytes::new(pw.into_bytes()),
            };
            match daemon_request(&req) {
                Ok(irlume_common::Response::PasswordSealed) => {
                    println!("[keyring] \u{2705} armed. After a face login, your wallet will unlock automatically.");
                    println!("[keyring] NOTE: if you change your login password, re-run `irlume keyring arm`.");
                    std::process::ExitCode::SUCCESS
                }
                Ok(other) => { eprintln!("[keyring] unexpected response: {other:?}"); std::process::ExitCode::FAILURE }
                Err(e) => { eprintln!("[keyring] arm failed: {e}"); std::process::ExitCode::FAILURE }
            }
        }
        Some("status") => match daemon_request(&irlume_common::Request::HasSealedPassword { user: user.clone() }) {
            Ok(irlume_common::Response::HasPassword(armed)) => {
                println!("[keyring] '{user}': keyring unlock is {}", if armed { "ARMED \u{2705}" } else { "not armed" });
                std::process::ExitCode::SUCCESS
            }
            Ok(other) => { eprintln!("[keyring] unexpected response: {other:?}"); std::process::ExitCode::FAILURE }
            Err(e) => { eprintln!("[keyring] status failed: {e}"); std::process::ExitCode::FAILURE }
        },
        Some("forget") => match daemon_request(&irlume_common::Request::ForgetPassword { user: user.clone() }) {
            Ok(irlume_common::Response::PasswordForgotten) => {
                println!("[keyring] '{user}': sealed password erased — keyring unlock disarmed.");
                std::process::ExitCode::SUCCESS
            }
            Ok(other) => { eprintln!("[keyring] unexpected response: {other:?}"); std::process::ExitCode::FAILURE }
            Err(e) => { eprintln!("[keyring] forget failed: {e}"); std::process::ExitCode::FAILURE }
        },
        _ => {
            eprintln!("usage: irlume keyring <arm|status|forget> [--user U]");
            std::process::ExitCode::from(2)
        }
    }
}

/// Round-trip one request to `irlumed` over the Unix socket and return its reply.
pub(crate) fn daemon_request(req: &irlume_common::Request) -> Result<irlume_common::Response, String> {
    use std::io::{BufRead, BufReader, Write};
    use std::os::unix::net::UnixStream;
    let path = std::env::var("IRLUME_SOCKET").unwrap_or_else(|_| irlume_common::SOCKET_PATH.into());
    let stream = UnixStream::connect(&path).map_err(|e| format!("connect {path}: {e} (is irlumed running?)"))?;
    stream.set_read_timeout(Some(std::time::Duration::from_secs(120))).ok();
    let mut line = serde_json::to_vec(req).map_err(|e| e.to_string())?;
    line.push(b'\n');
    (&stream).write_all(&line).map_err(|e| e.to_string())?;
    let mut reader = BufReader::new(&stream);
    let mut resp = String::new();
    reader.read_line(&mut resp).map_err(|e| e.to_string())?;
    serde_json::from_str(resp.trim()).map_err(|e| e.to_string())
}

pub(crate) fn user_arg(args: &[String]) -> String {
    flag(args, "--user").map(str::to_string).filter(|s| !s.is_empty())
        .unwrap_or_else(|| std::env::var("USER").unwrap_or_else(|_| "user".into()))
}

/// Build an Engine: optional --rgb/--ir device overrides, and auto-load the IR
/// adapter from models/ir_adapter.onnx (or --adapter PATH) if present.
fn engine(det: &str, model: &str, args: &[String]) -> irlume_common::Result<irlume_auth::Engine> {
    let e = irlume_auth::Engine::load(det, model)?;
    let e = match (flag(args, "--rgb"), flag(args, "--ir")) {
        (Some(r), Some(i)) => e.with_devices(r, i),
        _ => e,
    };
    let adapter = flag(args, "--adapter").unwrap_or("models/ir_adapter.onnx");
    let e = e.with_ir_adapter(adapter)?;
    if e.has_ir_adapter() {
        eprintln!("[engine] IR adapter loaded ({adapter}) — dark mode uses adapted recognition");
    }
    Ok(e)
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

/// `irlume irbench --dir <nir_images> --det .. --model ..` — the real IR
/// recognition benchmark: embed real NIR faces (YuNet detect → align → AuraFace),
/// group by person (filename prefix), and report genuine vs impostor cosine
/// distributions + EER + FAR/FRR. Answers "does AuraFace-on-IR discriminate?".
fn irbench(args: &[String]) -> std::process::ExitCode {
    let (Some(dir), Some(det_path), Some(model)) =
        (flag(args, "--dir"), flag(args, "--det"), flag(args, "--model"))
    else {
        eprintln!("usage: irlume irbench --dir <imgdir> --det <yunet.onnx> --model <glintr100.onnx> [--max-persons N] [--lfw] [--impostor-only [--max-images N]]");
        return std::process::ExitCode::from(2);
    };
    let max_persons: usize = flag(args, "--max-persons").and_then(|s| s.parse().ok()).unwrap_or(80);

    // Impostor-only / FALSE-ACCEPT mode: a directory of distinct-identity images
    // (e.g. SFHQ synthetic faces — every file is a different person), so every
    // pair is an impostor pair. Measures FAR only (no genuine pairs / FRR).
    if args.iter().any(|a| a == "--impostor-only") {
        return farbench(dir, det_path, model, args);
    }

    // Collect images (recursive, jpg/png/bmp) grouped by person identity.
    // Default key = prefix before first '-' (CBSR convention). With --lfw the key
    // is the filename stem minus a trailing _<digits> image index, i.e. the LFW
    // convention `AJ_Cook_0001.jpg` -> person `AJ_Cook`.
    let lfw = args.iter().any(|a| a == "--lfw");
    let mut all: Vec<std::path::PathBuf> = Vec::new();
    collect_images(std::path::Path::new(dir), &mut all);
    if all.is_empty() {
        eprintln!("no jpg/png/bmp images under {dir}");
        return std::process::ExitCode::FAILURE;
    }
    all.sort(); // deterministic
    let mut by_person: std::collections::BTreeMap<String, Vec<std::path::PathBuf>> = Default::default();
    for p in all {
        let Some(name) = p.file_stem().and_then(|s| s.to_str()) else { continue };
        let person = if lfw {
            match name.rsplit_once('_') {
                Some((head, idx)) if !idx.is_empty() && idx.bytes().all(|b| b.is_ascii_digit()) => head.to_string(),
                _ => name.to_string(),
            }
        } else {
            name.split('-').next().unwrap_or(name).to_string()
        };
        by_person.entry(person).or_default().push(p);
    }
    let persons: Vec<_> = by_person.into_iter().take(max_persons).collect();
    println!("[irbench] {} persons, {} images; embedding (YuNet→align→AuraFace)…",
        persons.len(), persons.iter().map(|(_, v)| v.len()).sum::<usize>());

    let mut det = match irlume_vision::Detector::load_from_file(det_path) {
        Ok(d) => d, Err(e) => { eprintln!("det load: {e}"); return std::process::ExitCode::FAILURE; }
    };
    let mut emb = match irlume_vision::Embedder::load_from_file(model) {
        Ok(d) => d, Err(e) => { eprintln!("emb load: {e}"); return std::process::ExitCode::FAILURE; }
    };

    // (person_index, embedding)
    let mut embs: Vec<(usize, [f32; irlume_vision::EMBED_DIM])> = Vec::new();
    let mut nodet = 0usize;
    for (pi, (_person, files)) in persons.iter().enumerate() {
        for f in files {
            let Ok(img) = image::open(f) else { continue };
            let rgb = img.to_rgb8();
            let (w, h) = rgb.dimensions();
            let data = rgb.into_raw();
            let view = irlume_vision::align::RgbView { data: &data, width: w, height: h };
            let Ok(faces) = det.detect(&view) else { continue };
            let Some(top) = faces.iter().max_by(|a, b| a.score.total_cmp(&b.score)) else { nodet += 1; continue };
            if let Ok(chip) = irlume_vision::align::align_to_arcface(&view, &top.landmarks) {
                if let Ok(e) = emb.embed(&chip) {
                    embs.push((pi, e));
                }
            }
        }
    }
    println!("[irbench] embedded {} faces ({} images had no detectable face)", embs.len(), nodet);

    // Optional: dump (person_index, 512-D embedding) per line for offline training.
    if let Some(out) = flag(args, "--export") {
        use std::io::Write;
        match std::fs::File::create(out) {
            Ok(mut f) => {
                for (pi, e) in &embs {
                    let mut line = pi.to_string();
                    for v in e.iter() {
                        line.push(' ');
                        line.push_str(&format!("{v:.6}"));
                    }
                    let _ = writeln!(f, "{line}");
                }
                println!("[irbench] exported {} embeddings -> {out}", embs.len());
            }
            Err(e) => eprintln!("export failed: {e}"),
        }
    }

    // Genuine = same person, impostor = different person.
    let mut genuine = Vec::new();
    let mut impostor = Vec::new();
    for i in 0..embs.len() {
        for j in (i + 1)..embs.len() {
            let c = irlume_vision::align::cosine(&embs[i].1, &embs[j].1);
            if embs[i].0 == embs[j].0 { genuine.push(c) } else { impostor.push(c) }
        }
    }
    if genuine.is_empty() || impostor.is_empty() {
        eprintln!("not enough data");
        return std::process::ExitCode::FAILURE;
    }
    genuine.sort_by(f32::total_cmp);
    impostor.sort_by(f32::total_cmp);
    let pct = |v: &[f32], p: f32| v[((p * (v.len() - 1) as f32) as usize).min(v.len() - 1)];
    let mean = |v: &[f32]| v.iter().sum::<f32>() / v.len() as f32;
    println!("[genuine ] n={:6}  min {:.3}  mean {:.3}  median {:.3}", genuine.len(), genuine[0], mean(&genuine), pct(&genuine, 0.5));
    println!("[impostor] n={:6}  mean {:.3}  p99 {:.3}  p99.9 {:.3}  max {:.3}", impostor.len(), mean(&impostor), pct(&impostor, 0.99), pct(&impostor, 0.999), impostor[impostor.len() - 1]);

    // FAR/FRR sweep + EER + the threshold meeting FAR=1e-4.
    let far = |t: f32| impostor.iter().filter(|&&c| c >= t).count() as f64 / impostor.len() as f64;
    let frr = |t: f32| genuine.iter().filter(|&&c| c < t).count() as f64 / genuine.len() as f64;
    for t in [0.40f32, 0.45, 0.50, 0.55, 0.60] {
        println!("  thr {t:.2}: FAR {:.5}  FRR {:.4}", far(t), frr(t));
    }
    // EER: scan thresholds for |FAR-FRR| min.
    let mut eer = (1.0f64, 0.0f32);
    let mut t = 0.0;
    while t < 1.0 {
        let (a, r) = (far(t), frr(t));
        if (a - r).abs() < eer.0 { eer = ((a - r).abs(), t); }
        t += 0.005;
    }
    let et = eer.1;
    println!("[EER] ~{:.3} at threshold {et:.3}", (far(et) + frr(et)) / 2.0);
    // threshold achieving FAR<=1e-4, and its FRR
    let mut t14 = 1.0f32;
    let mut s = 0.30;
    while s <= 0.95 { if far(s) <= 1e-4 { t14 = s; break; } s += 0.005; }
    println!("[FAR≤1e-4] threshold {t14:.3} -> FRR {:.4} (reject rate for genuine at NIST-grade FAR)", frr(t14));
    std::process::ExitCode::SUCCESS
}

/// Large-scale RGB FALSE-ACCEPT benchmark (the visible-light sibling of the IR
/// `irbench`). Every image under `--dir` is treated as a distinct identity — true
/// for SFHQ synthetic faces — so every pair is an impostor pair. Embeds each face
/// through the real auth pipeline (YuNet → align → AuraFace) and reports the
/// impostor cosine tail + FAR at the auth thresholds + the threshold achieving
/// NIST-grade FAR ≤ 1e-4. Histogram-based, so it scales to millions of pairs
/// without storing them. FAR only — genuine/FRR come from live captures, not here.
fn farbench(dir: &str, det_path: &str, model: &str, args: &[String]) -> std::process::ExitCode {
    let max_images: usize = flag(args, "--max-images").and_then(|s| s.parse().ok()).unwrap_or(20_000);

    let mut files: Vec<std::path::PathBuf> = Vec::new();
    collect_images(std::path::Path::new(dir), &mut files);
    files.sort(); // deterministic sample
    files.truncate(max_images);
    if files.len() < 2 {
        eprintln!("[farbench] need >=2 images under {dir} (found {})", files.len());
        return std::process::ExitCode::FAILURE;
    }
    println!("[farbench] {} images; embedding (YuNet→align→AuraFace)…", files.len());

    let mut det = match irlume_vision::Detector::load_from_file(det_path) {
        Ok(d) => d, Err(e) => { eprintln!("det load: {e}"); return std::process::ExitCode::FAILURE; }
    };
    let mut emb = match irlume_vision::Embedder::load_from_file(model) {
        Ok(d) => d, Err(e) => { eprintln!("emb load: {e}"); return std::process::ExitCode::FAILURE; }
    };

    let mut embs: Vec<[f32; irlume_vision::EMBED_DIM]> = Vec::with_capacity(files.len());
    let mut nodet = 0usize;
    for (i, f) in files.iter().enumerate() {
        if i > 0 && i % 1000 == 0 {
            println!("[farbench]   {}/{} embedded ({} no-face)…", embs.len(), i, nodet);
        }
        let Ok(img) = image::open(f) else { continue };
        let rgb = img.to_rgb8();
        let (w, h) = rgb.dimensions();
        let data = rgb.into_raw();
        let view = irlume_vision::align::RgbView { data: &data, width: w, height: h };
        let Ok(faces) = det.detect(&view) else { continue };
        let Some(top) = faces.iter().max_by(|a, b| a.score.total_cmp(&b.score)) else { nodet += 1; continue };
        if let Ok(chip) = irlume_vision::align::align_to_arcface(&view, &top.landmarks) {
            if let Ok(e) = emb.embed(&chip) {
                embs.push(e);
            }
        }
    }
    println!("[farbench] embedded {} faces ({} images had no detectable face)", embs.len(), nodet);
    if embs.len() < 2 {
        eprintln!("[farbench] too few embeddings for pairwise stats");
        return std::process::ExitCode::FAILURE;
    }

    // Optional: dump the raw 512-D embeddings (one per line) for offline analysis
    // — e.g. apply a debiasing adapter and recompute FAR per demographic group.
    if let Some(out) = flag(args, "--export") {
        use std::io::Write;
        if let Ok(mut f) = std::fs::File::create(out) {
            for e in &embs {
                let line: Vec<String> = e.iter().map(|v| format!("{v:.6}")).collect();
                let _ = writeln!(f, "{}", line.join(" "));
            }
            println!("[farbench] exported {} embeddings -> {out}", embs.len());
        } else {
            eprintln!("[farbench] export failed to create {out}");
        }
    }

    // All-pairs impostor cosines into a histogram over [-1, 1] (bin width 0.001).
    const BINS: usize = 2000;
    let mut hist = vec![0u64; BINS];
    let mut total: u64 = 0;
    let mut sum_c: f64 = 0.0;
    for i in 0..embs.len() {
        for j in (i + 1)..embs.len() {
            let c = irlume_vision::align::cosine(&embs[i], &embs[j]);
            let b = (((c + 1.0) * 0.5 * BINS as f32) as usize).min(BINS - 1);
            hist[b] += 1;
            total += 1;
            sum_c += c as f64;
        }
    }

    // suffix[k] = #pairs in bins >= k, i.e. cos >= -1 + 2k/BINS → FAR numerator.
    let mut suffix = vec![0u64; BINS + 1];
    for k in (0..BINS).rev() { suffix[k] = suffix[k + 1] + hist[k]; }
    let far_at = |t: f32| -> f64 {
        let k = (((t + 1.0) * 0.5 * BINS as f32).ceil() as i64).clamp(0, BINS as i64) as usize;
        suffix[k] as f64 / total as f64
    };
    let pct = |p: f64| -> f32 {
        let target = (p * total as f64) as u64;
        let mut cum = 0u64;
        for k in 0..BINS { cum += hist[k]; if cum >= target { return -1.0 + 2.0 * k as f32 / BINS as f32; } }
        1.0
    };
    let max_imp = (0..BINS).rev().find(|&k| hist[k] > 0)
        .map(|k| -1.0 + 2.0 * (k as f32 + 1.0) / BINS as f32).unwrap_or(1.0);

    println!("[impostor] pairs={total}  mean {:.3}  p99 {:.3}  p99.9 {:.3}  p99.99 {:.3}  max {:.3}",
        sum_c / total as f64, pct(0.99), pct(0.999), pct(0.9999), max_imp);
    println!("[FAR sweep]");
    for t in [0.40f32, 0.45, 0.50, 0.55, 0.60] {
        println!("  thr {t:.2}: FAR {:.6}  (1 in {:.0})", far_at(t),
            if far_at(t) > 0.0 { 1.0 / far_at(t) } else { f64::INFINITY });
    }
    let mut t14 = 1.0f32; let mut s = 0.30f32;
    while s <= 0.95 { if far_at(s) <= 1e-4 { t14 = s; break; } s += 0.005; }
    println!("[FAR≤1e-4] threshold {t14:.3}  (RGB auth threshold 0.50 → FAR {:.6})", far_at(0.50));
    std::process::ExitCode::SUCCESS
}

/// Recursively collect jpg/jpeg/png/bmp files under `dir`.
fn collect_images(dir: &std::path::Path, out: &mut Vec<std::path::PathBuf>) {
    let Ok(rd) = std::fs::read_dir(dir) else { return };
    for e in rd.flatten() {
        let p = e.path();
        if p.is_dir() {
            collect_images(&p, out);
        } else if p.extension().and_then(|x| x.to_str())
            .map(|x| matches!(x.to_ascii_lowercase().as_str(), "jpg" | "jpeg" | "png" | "bmp"))
            .unwrap_or(false)
        {
            out.push(p);
        }
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
        let rgb_top = rgb_faces.iter().max_by(|a, b| a.score.total_cmp(&b.score));
        let pose = rgb_top.map(|f| irlume_vision::head_pose(&f.landmarks));
        let signals = irlume_liveness::Signals {
            rgb_face: rgb_top.map(|f| to_fbox(f, rgb.width, rgb.height)),
            ir_face: ir_top_face.map(|f| to_fbox(f, ir.width, ir.height)),
            ir_face_brightness,
            ir_center_edge_ratio,
            ir_eye_glint,
            head_yaw_asym: pose.map(|p| p.yaw_asym).unwrap_or(0.0),
            head_pitch_frac: pose.map(|p| p.pitch_frac).unwrap_or(0.5),
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
        let grey = args.iter().any(|a| a == "--grey");
        let faces = det.detect(&view)?;
        println!("[eval] {} faces; embedding each{}…", faces.len(), if grey { " (GREYSCALE / IR-proxy)" } else { "" });
        let mut embs = Vec::new();
        for f in &faces {
            let mut chip = irlume_vision::align::align_to_arcface(&view, &f.landmarks)?;
            if grey {
                // Simulate the IR modality: drop colour, keep luminance (BT.601),
                // replicate to 3 channels. Isolates AuraFace's colour-removal loss.
                for px in chip.chunks_exact_mut(3) {
                    let y = (0.299 * px[0] as f32 + 0.587 * px[1] as f32 + 0.114 * px[2] as f32) as u8;
                    px[0] = y; px[1] = y; px[2] = y;
                }
            }
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

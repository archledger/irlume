//! `irlume`: operator CLI. A thin, unprivileged client of `irlumed` (same socket
//! protocol as the PAM module). Enrollment requests are authorized by the daemon
//! via SO_PEERCRED, not by this binary.
//!
//! Run `irlume help` for the user-facing subcommands, or `irlume tui` for the
//! guided setup. Developer/benchmark tools are gated behind `IRLUME_DEV=1`.
//! A selection of the main subcommands:
//!   irlume tui                                   guided setup + live dashboard
//!   irlume enroll [--user U] [--profile NAME]   register a face profile
//!   irlume identify                              1:N "who is this?"
//!   irlume doctor                                check cameras/IR/TPM/models
//!   irlume keyring <arm|status|forget>           TPM-sealed keyring/wallet unlock
//!   irlume recovery <status|setup|restore|forget> template-key recovery passphrase
//!   irlume fingerprint <status|add|enable|disable> fprintd companion factor
//!   irlume login <status|enable|disable>         wire face auth into PAM (dry-run)
//!   irlume logs [-f] [debug on|off]              face-auth journal view + tracing switch
//!   irlume tui                                   interactive setup/management UI

mod commands;
mod fingerprint;
mod logs;
mod pad;
mod pamwire;
mod recovery;
mod suncal;
mod tui;

pub(crate) fn flag<'a>(args: &'a [String], name: &str) -> Option<&'a str> {
    args.iter()
        .position(|a| a == name)
        .and_then(|i| args.get(i + 1))
        .map(String::as_str)
}

/// Developer / benchmark / research subcommands: hidden from `help` and gated
/// behind `IRLUME_DEV=1`. They open the camera directly (bypassing the daemon,
/// so they EBUSY-conflict on a running install) and some, like `calcapture`,
/// write RAW face embeddings to a plaintext file; not for end users.
const DEV_CMDS: &[&str] = &[
    "capture",
    "eval",
    "irbench",
    "genuine",
    "calcapture",
    "normprobe",
    "liveness",
    "meshprobe",
    "selftest",
    "padcapture",
    "padreport",
    "verify",
    "enrolldev",
    "suncal",
];

fn main() -> std::process::ExitCode {
    // Rust ignores SIGPIPE by default, turning a closed stdout (`irlume … | head`,
    // `| less` then quit, `| grep -q`) into a "failed printing to stdout: Broken
    // pipe" panic + exit 101. Restore the Unix default so we exit quietly like any
    // other CLI when a downstream reader goes away.
    unsafe {
        libc::signal(libc::SIGPIPE, libc::SIG_DFL);
    }
    let args: Vec<String> = std::env::args().skip(1).collect();
    // Gate the developer tools unless IRLUME_DEV is set.
    if let Some(cmd) = args.first().map(String::as_str) {
        if DEV_CMDS.contains(&cmd) && std::env::var_os("IRLUME_DEV").is_none() {
            eprintln!(
                "[irlume] '{cmd}' is a developer/benchmark tool (opens the camera directly, \
                       not for normal use). Set IRLUME_DEV=1 to enable it."
            );
            return std::process::ExitCode::from(2);
        }
    }
    match (
        args.first().map(String::as_str),
        args.get(1).map(String::as_str),
    ) {
        (Some("selftest"), Some("align")) => selftest_align(&args),
        (Some("capture"), _) => capture(&args),
        (Some("eval"), _) => eval(&args),
        (Some("irbench"), _) => irbench(&args),
        (Some("genuine"), _) => genuine(&args),
        (Some("calcapture"), _) => calcapture(&args),
        (Some("padcapture"), _) => pad::padcapture(&args),
        (Some("padreport"), _) => pad::padreport(&args),
        (Some("suncal"), _) => suncal::run(&args),
        (Some("liveness"), _) => liveness_probe(&args),
        (Some("meshprobe"), _) => meshprobe(&args),
        (Some("enroll"), _) => enroll(&args),
        (Some("profiles"), sub) => profiles(sub, &args),
        (Some("verify"), _) => verify(&args),
        (Some("enrolldev"), _) => enrolldev(&args),
        (Some("keyring"), sub) => keyring(sub, &args),
        (Some("recovery"), sub) => recovery::run(sub, &args),
        (Some("fingerprint"), sub) => fingerprint::run(sub, &args),
        (Some("login"), sub) => pamwire::run(sub, &args),
        (Some("logs"), sub) => logs::run(sub, &args),
        (Some("ir-setup"), _) => ir_setup(&args),
        (Some("set-cameras"), _) => set_cameras(&args),
        (Some("update"), _) => commands::update(&args),
        (Some("version"), _) | (Some("--version"), _) | (Some("-V"), _) => {
            println!("irlume {}", env!("CARGO_PKG_VERSION"));
            std::process::ExitCode::SUCCESS
        }
        (Some("doctor"), _) => doctor(),
        (Some("normprobe"), _) => normprobe(&args),
        (Some("status"), _) => commands::status(&args),
        (Some("detect"), _) => commands::detect(&args),
        (Some("identify"), _) => commands::identify(&args),
        (Some("diag"), _) => commands::diag(&args),
        (Some("deps"), _) => commands::deps(&args),
        (Some("reseal"), _) => commands::reseal(&args),
        (Some("selinux"), sub) => commands::selinux(sub, &args),
        (Some("setup"), _) => commands::setup(&args),
        (Some("help" | "--help" | "-h"), _) => commands::help(),
        (Some("tui"), _) => match tui::run() {
            Ok(()) => std::process::ExitCode::SUCCESS,
            Err(e) => {
                eprintln!("tui: {e}");
                std::process::ExitCode::FAILURE
            }
        },
        (Some(cmd), _) => {
            eprintln!("irlume: unknown command '{cmd}'; run `irlume help`");
            std::process::ExitCode::from(2)
        }
        (None, _) => commands::help(),
    }
}

/// `irlume enroll --user U [--name "..."]`: enroll a NEW face profile (captures
/// the default number of scans) via the daemon, which owns the camera. Default
/// profile name is "Face Profile N".
fn enroll(args: &[String]) -> std::process::ExitCode {
    use irlume_common::{Request, Response};
    let user = user_arg(args);
    let name = flag(args, "--name").map(String::from);
    let scans = flag(args, "--scans").and_then(|s| s.parse::<usize>().ok());
    let reset = args.iter().any(|a| a == "--reset");
    if reset {
        eprintln!("[enroll] --reset: wiping '{user}'s existing enrollment first (clears any stale camera binding)");
    }
    eprintln!(
        "[enroll] '{user}': capturing a new face profile; stay in frame, look at the camera…"
    );
    match daemon_request(&Request::Enroll {
        user,
        profile: name,
        scans,
        reset,
    }) {
        Ok(Response::Ok(msg)) => {
            println!("[enroll] {msg}");
            std::process::ExitCode::SUCCESS
        }
        Ok(Response::Error(e)) => {
            eprintln!("enroll failed: {e}");
            std::process::ExitCode::FAILURE
        }
        Ok(other) => {
            eprintln!("enroll: unexpected response {other:?}");
            std::process::ExitCode::FAILURE
        }
        Err(e) => {
            eprintln!("enroll: {e}");
            std::process::ExitCode::FAILURE
        }
    }
}

/// `irlume profiles [list|add-scan|rename|delete|eyes-open] ...`: manage the up-
/// to-3 face profiles and their scans via the daemon.
fn profiles(sub: Option<&str>, args: &[String]) -> std::process::ExitCode {
    use irlume_common::{Request, Response};
    let user = user_arg(args);
    let req = match sub {
        None | Some("list") => Request::ListProfiles { user },
        Some("add-scan") => match flag(args, "--profile") {
            Some(p) => {
                eprintln!("[profiles] adding a scan to '{p}'; stay in frame…");
                Request::AddScan {
                    user,
                    profile: p.into(),
                }
            }
            None => return usage_profiles(),
        },
        Some("delete") => match (flag(args, "--profile"), flag(args, "--scan")) {
            (Some(p), Some(s)) => Request::DeleteScan {
                user,
                profile: p.into(),
                scan: s.into(),
            },
            (Some(p), None) => Request::DeleteProfile {
                user,
                profile: p.into(),
            },
            _ => return usage_profiles(),
        },
        Some("rename") => match (
            flag(args, "--profile"),
            flag(args, "--scan"),
            flag(args, "--name"),
        ) {
            (Some(p), Some(s), Some(n)) => Request::RenameScan {
                user,
                profile: p.into(),
                scan: s.into(),
                new_name: n.into(),
            },
            (Some(p), None, Some(n)) => Request::RenameProfile {
                user,
                profile: p.into(),
                new_name: n.into(),
            },
            _ => return usage_profiles(),
        },
        Some("eyes-open") => {
            let on = args.iter().any(|a| a == "on");
            let off = args.iter().any(|a| a == "off");
            if on == off {
                eprintln!("usage: irlume profiles eyes-open <on|off> [--user U]");
                return std::process::ExitCode::from(2);
            }
            Request::SetRequireEyesOpen { user, on }
        }
        Some("challenge") => {
            let on = args.iter().any(|a| a == "on");
            let off = args.iter().any(|a| a == "off");
            if on == off {
                eprintln!("usage: irlume profiles challenge <on|off> [--user U]");
                return std::process::ExitCode::from(2);
            }
            Request::SetRequireChallenge { user, on }
        }
        _ => return usage_profiles(),
    };
    match daemon_request(&req) {
        Ok(Response::Enrollment {
            profiles,
            require_eyes_open,
            require_challenge,
        }) => {
            if profiles.is_empty() {
                println!("[profiles] none enrolled");
            } else {
                println!(
                    "[profiles] require-eyes-open: {}  ·  require-challenge (blink): {}",
                    if require_eyes_open { "ON" } else { "off" },
                    if require_challenge { "ON" } else { "off" }
                );
                for p in &profiles {
                    println!("  {} ({} scans)", p.name, p.scans.len());
                    for s in &p.scans {
                        println!("      - {s}");
                    }
                }
            }
            std::process::ExitCode::SUCCESS
        }
        Ok(Response::Ok(msg)) => {
            println!("[profiles] {msg}");
            std::process::ExitCode::SUCCESS
        }
        Ok(Response::Error(e)) => {
            eprintln!("[profiles] {e}");
            std::process::ExitCode::FAILURE
        }
        Ok(other) => {
            eprintln!("[profiles] unexpected response {other:?}");
            std::process::ExitCode::FAILURE
        }
        Err(e) => {
            eprintln!("[profiles] {e}");
            std::process::ExitCode::FAILURE
        }
    }
}

/// `irlume ir-setup [--dry-run]`: auto-enable the IR emitter via the daemon
/// (integrated linux-enable-ir-emitter). `--dry-run` only lists XU controls.
/// `irlume set-cameras <rgb> <ir>`: persist the active RGB+IR pair. Root only
/// (the daemon writes /etc/irlume/cameras.conf); the TUI camera picker runs this
/// via sudo. Not shown in help; it's the picker's backing command.
fn set_cameras(args: &[String]) -> std::process::ExitCode {
    use irlume_common::{Request, Response};
    let (Some(rgb), Some(ir)) = (args.get(1), args.get(2)) else {
        eprintln!(
            "usage: irlume set-cameras <rgb-node> <ir-node>   (root; e.g. /dev/video0 /dev/video2)"
        );
        return std::process::ExitCode::from(2);
    };
    match daemon_request(&Request::SetCameras {
        rgb: rgb.clone(),
        ir: ir.clone(),
    }) {
        Ok(Response::Ok(msg)) => {
            println!("[set-cameras] {msg}");
            std::process::ExitCode::SUCCESS
        }
        Ok(Response::Error(e)) => {
            eprintln!("[set-cameras] {e}");
            std::process::ExitCode::FAILURE
        }
        Ok(other) => {
            eprintln!("[set-cameras] unexpected response {other:?}");
            std::process::ExitCode::FAILURE
        }
        Err(e) => {
            eprintln!("[set-cameras] {e}");
            std::process::ExitCode::FAILURE
        }
    }
}

fn ir_setup(args: &[String]) -> std::process::ExitCode {
    use irlume_common::{Request, Response};
    let dry = args.iter().any(|a| a == "--dry-run");
    if !dry {
        eprintln!("[ir-setup] probing the IR camera and trying to enable the 850nm emitter (a few seconds)…");
    }
    match daemon_request(&Request::SetupIrEmitter { dry_run: dry }) {
        Ok(Response::Ok(msg)) => {
            println!("[ir-setup] {msg}");
            std::process::ExitCode::SUCCESS
        }
        Ok(Response::Error(e)) => {
            eprintln!("[ir-setup] {e}");
            std::process::ExitCode::FAILURE
        }
        Ok(other) => {
            eprintln!("[ir-setup] unexpected response {other:?}");
            std::process::ExitCode::FAILURE
        }
        Err(e) => {
            eprintln!("[ir-setup] {e}");
            std::process::ExitCode::FAILURE
        }
    }
}

fn usage_profiles() -> std::process::ExitCode {
    eprintln!(
        "usage: irlume profiles [--user U] <subcommand>\n  \
        (no sub) | list                         list profiles + scans\n  \
        add-scan --profile P                    add a scan to P (improve recognition)\n  \
        rename --profile P [--scan S] --name N  rename a profile or a scan\n  \
        delete --profile P [--scan S]           delete a profile or a scan\n  \
        eyes-open <on|off>                      require eyes open to unlock\n  \
        challenge <on|off>                      opt-in passive blink liveness"
    );
    std::process::ExitCode::from(2)
}

/// `irlume verify --user U`: full auth via the engine: liveness gate then match
/// (RGB recognition in light, IR recognition in the dark).
fn verify(args: &[String]) -> std::process::ExitCode {
    let (Some(det), Some(model)) = (flag(args, "--det"), flag(args, "--model")) else {
        eprintln!("usage: irlume verify --user U --det <yunet.onnx> --model <glintr100.onnx> [--rgb ..] [--ir ..]");
        return std::process::ExitCode::from(2);
    };
    let user = user_arg(args);
    match engine(det, model, args).and_then(|mut e| e.authenticate(&user)) {
        Ok(o) => {
            println!(
                "[verify] live={} score {:.3} -> {} ({})",
                o.live,
                o.score,
                if o.granted {
                    "GRANT \u{2705}"
                } else {
                    "DENY \u{274c}"
                },
                o.reason
            );
            if o.granted {
                std::process::ExitCode::SUCCESS
            } else {
                std::process::ExitCode::FAILURE
            }
        }
        Err(e) => {
            eprintln!("verify error: {e}");
            std::process::ExitCode::FAILURE
        }
    }
}

/// `irlume keyring <arm|status|forget>`: manage the TPM-sealed login password
/// that lets a face login unlock the GNOME-keyring / KWallet. Talks to `irlumed`
/// over the socket (the daemon owns the TPM + the root-only sealed store).
pub(crate) fn keyring(sub: Option<&str>, args: &[String]) -> std::process::ExitCode {
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
                    Err(e) => {
                        eprintln!("[keyring] could not read password: {e}");
                        return std::process::ExitCode::FAILURE;
                    }
                };
                // Confirm to catch typos: a mistyped seal silently fails to
                // unlock the wallet at the next face login (key mismatch).
                let confirm = match rpassword::prompt_password("Confirm login password: ") {
                    Ok(p) => p,
                    Err(e) => {
                        eprintln!("[keyring] could not read password: {e}");
                        return std::process::ExitCode::FAILURE;
                    }
                };
                if first != confirm {
                    eprintln!("[keyring] passwords do not match; aborted (nothing sealed).");
                    return std::process::ExitCode::from(2);
                }
                first
            } else {
                use std::io::BufRead;
                let mut line = String::new();
                if std::io::stdin().lock().read_line(&mut line).is_err() {
                    eprintln!("[keyring] could not read password from stdin");
                    return std::process::ExitCode::FAILURE;
                }
                line.trim_end_matches(['\n', '\r']).to_string()
            };
            if pw.is_empty() {
                eprintln!("[keyring] empty password; aborted");
                return std::process::ExitCode::from(2);
            }
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
                Ok(irlume_common::Response::Error(e)) => {
                    eprintln!("[keyring] arm failed: {e}");
                    std::process::ExitCode::FAILURE
                }
                Ok(other) => {
                    eprintln!("[keyring] unexpected response: {other:?}");
                    std::process::ExitCode::FAILURE
                }
                Err(e) => {
                    eprintln!("[keyring] arm failed: {e}");
                    std::process::ExitCode::FAILURE
                }
            }
        }
        Some("status") => {
            match daemon_request(&irlume_common::Request::HasSealedPassword { user: user.clone() })
            {
                Ok(irlume_common::Response::HasPassword(armed)) => {
                    println!(
                        "[keyring] '{user}': keyring unlock is {}",
                        if armed { "ARMED \u{2705}" } else { "not armed" }
                    );
                    std::process::ExitCode::SUCCESS
                }
                Ok(irlume_common::Response::Error(e)) => {
                    eprintln!("[keyring] status failed: {e}");
                    std::process::ExitCode::FAILURE
                }
                Ok(other) => {
                    eprintln!("[keyring] unexpected response: {other:?}");
                    std::process::ExitCode::FAILURE
                }
                Err(e) => {
                    eprintln!("[keyring] status failed: {e}");
                    std::process::ExitCode::FAILURE
                }
            }
        }
        Some("forget") => match daemon_request(&irlume_common::Request::ForgetPassword {
            user: user.clone(),
        }) {
            Ok(irlume_common::Response::PasswordForgotten) => {
                println!("[keyring] '{user}': sealed password erased; keyring unlock disarmed.");
                std::process::ExitCode::SUCCESS
            }
            Ok(irlume_common::Response::Error(e)) => {
                eprintln!("[keyring] forget failed: {e}");
                std::process::ExitCode::FAILURE
            }
            Ok(other) => {
                eprintln!("[keyring] unexpected response: {other:?}");
                std::process::ExitCode::FAILURE
            }
            Err(e) => {
                eprintln!("[keyring] forget failed: {e}");
                std::process::ExitCode::FAILURE
            }
        },
        _ => {
            eprintln!("usage: irlume keyring <arm|status|forget> [--user U]");
            std::process::ExitCode::from(2)
        }
    }
}

/// Round-trip one request to `irlumed` over the Unix socket and return its reply.
pub(crate) fn daemon_request(
    req: &irlume_common::Request,
) -> Result<irlume_common::Response, String> {
    // Shared client: bounded connect timeout + zeroized wire buffers. The 120s
    // read budget covers slow operations (guided enroll capture loops).
    irlume_common::client::request_with_timeout(req, std::time::Duration::from_secs(120)).map_err(
        |e| {
            // The connect-failure message already names irlumed and the exact
            // fix (client.rs); only append the hint where it adds information.
            let m = e.to_string();
            if m.contains("irlumed") {
                m
            } else {
                format!("{m} (is irlumed running?)")
            }
        },
    )
}

pub(crate) fn user_arg(args: &[String]) -> String {
    flag(args, "--user")
        .map(str::to_string)
        .filter(|s| !s.is_empty())
        .unwrap_or_else(|| {
            // Under `sudo irlume …` (which status/diag themselves recommend
            // for envelope detail) $USER is root, but the person almost
            // always means their own profile: prefer the invoking user.
            std::env::var("SUDO_USER")
                .ok()
                .filter(|s| !s.is_empty() && unsafe { libc::geteuid() } == 0)
                .or_else(|| std::env::var("USER").ok())
                .unwrap_or_else(|| "user".into())
        })
}

/// Build an Engine: optional --rgb/--ir device overrides, and auto-load the IR
/// adapter from models/ir_adapter.onnx (or --adapter PATH) if present.
/// `irlume enrolldev --user U --det <yunet.onnx> --model <glintr100.onnx>
///   [--name N] [--scans K] [--adapter P] [--rgb ..] [--ir ..]`
///
/// Direct-mode enrollment (no daemon), the enroll-side companion to `verify`:
/// drives `Engine::enroll_profile` against the current `IRLUME_STATE_DIR`, so
/// matching-path changes (e.g. the ADR-0004 per-enrollment calibration) can
/// be exercised end-to-end in an isolated state dir without touching the
/// installed daemon or production enrollments. `--adapter /nonexistent`
/// forces the raw-IR pipeline, which is where the calibration activates.
fn enrolldev(args: &[String]) -> std::process::ExitCode {
    let (Some(det), Some(model)) = (flag(args, "--det"), flag(args, "--model")) else {
        eprintln!("usage: irlume enrolldev --user U --det <yunet.onnx> --model <glintr100.onnx> [--name N] [--scans K] [--adapter P] [--rgb ..] [--ir ..]");
        return std::process::ExitCode::from(2);
    };
    let user = user_arg(args);
    let name = flag(args, "--name").map(String::from);
    let want = flag(args, "--scans")
        .and_then(|s| s.parse().ok())
        .unwrap_or(irlume_core::storage::DEFAULT_ENROLL_SCANS);
    eprintln!("[enrolldev] '{user}': {want} scans into IRLUME_STATE_DIR; stay in frame…");
    match engine(det, model, args).and_then(|mut e| e.enroll_profile(&user, name, want)) {
        Ok((profile, n)) => {
            println!("[enrolldev] enrolled '{profile}' ({n} scans)");
            std::process::ExitCode::SUCCESS
        }
        Err(e) => {
            eprintln!("enrolldev error: {e}");
            std::process::ExitCode::FAILURE
        }
    }
}

fn engine(det: &str, model: &str, args: &[String]) -> irlume_common::Result<irlume_auth::Engine> {
    let e = irlume_auth::Engine::load(det, model)?;
    let e = match (flag(args, "--rgb"), flag(args, "--ir")) {
        (Some(r), Some(i)) => e.with_devices(r, i),
        _ => e,
    };
    let adapter = flag(args, "--adapter").unwrap_or("models/ir_adapter.onnx");
    let e = e.with_ir_adapter(adapter)?;
    if e.has_ir_adapter() {
        eprintln!("[engine] IR adapter loaded ({adapter}); dark mode uses adapted recognition");
    }
    let mesh = flag(args, "--mesh").unwrap_or("models/face_landmark.onnx");
    let e = e.with_mesh(mesh)?;
    if e.has_mesh() {
        eprintln!("[engine] FaceMesh loaded ({mesh}); passive EAR liveness available");
    }
    let blaze = flag(args, "--blaze").unwrap_or("models/blaze_face_short_range.onnx");
    let e = e.with_blaze_rescue(blaze)?;
    if e.has_blaze_rescue() {
        eprintln!("[engine] BlazeFace rescue loaded ({blaze}); detection cascade active");
    }
    Ok(e)
}

// Brightness/depth cue helpers live in irlume-auth (the daemon-side pipeline
// owns them); re-exported so the dev tools here and in pad.rs measure with the
// exact same code the gate uses.
pub(crate) use irlume_auth::{center_edge_ratio, mean_in_bbox};

/// `irlume irbench --dir <nir_images> --det .. --model ..`: the real IR
/// recognition benchmark: embed real NIR faces (YuNet detect → align → AuraFace),
/// group by person (filename prefix), and report genuine vs impostor cosine
/// distributions + EER + FAR/FRR. Answers "does AuraFace-on-IR discriminate?".
fn irbench(args: &[String]) -> std::process::ExitCode {
    let (Some(dir), Some(det_path), Some(model)) = (
        flag(args, "--dir"),
        flag(args, "--det"),
        flag(args, "--model"),
    ) else {
        eprintln!("usage: irlume irbench --dir <imgdir> --det <yunet.onnx> --model <glintr100.onnx> [--max-persons N] [--lfw] [--impostor-only [--max-images N]]");
        return std::process::ExitCode::from(2);
    };
    let max_persons: usize = flag(args, "--max-persons")
        .and_then(|s| s.parse().ok())
        .unwrap_or(80);

    // Impostor-only / FALSE-ACCEPT mode: a directory of distinct-identity images
    // (e.g. SFHQ synthetic faces; every file is a different person), so every
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
    let mut by_person: std::collections::BTreeMap<String, Vec<std::path::PathBuf>> =
        Default::default();
    for p in all {
        let Some(name) = p.file_stem().and_then(|s| s.to_str()) else {
            continue;
        };
        let person = if lfw {
            match name.rsplit_once('_') {
                Some((head, idx)) if !idx.is_empty() && idx.bytes().all(|b| b.is_ascii_digit()) => {
                    head.to_string()
                }
                _ => name.to_string(),
            }
        } else {
            name.split('-').next().unwrap_or(name).to_string()
        };
        by_person.entry(person).or_default().push(p);
    }
    let persons: Vec<_> = by_person.into_iter().take(max_persons).collect();
    println!(
        "[irbench] {} persons, {} images; embedding (YuNet→align→AuraFace)…",
        persons.len(),
        persons.iter().map(|(_, v)| v.len()).sum::<usize>()
    );

    let mut det = match irlume_vision::Detector::load_from_file(det_path) {
        Ok(d) => d,
        Err(e) => {
            eprintln!("det load: {e}");
            return std::process::ExitCode::FAILURE;
        }
    };
    let mut emb = match irlume_vision::Embedder::load_from_file(model) {
        Ok(d) => d,
        Err(e) => {
            eprintln!("emb load: {e}");
            return std::process::ExitCode::FAILURE;
        }
    };

    // Experiment knob: --tta = test-time augmentation (embed chip + its mirror,
    // average, renormalize). Standard ArcFace inference trick; no retraining.
    let tta = args.iter().any(|a| a == "--tta");
    // Low-light experiment knobs (applied to the aligned chip BEFORE embedding):
    //   --darken F        simulate a dim capture (scale pixels by F<1)
    //   --lightnorm MODE  illumination normalization: gamma|he|clahe (recover dim probe)
    let darken: Option<f32> = flag(args, "--darken").and_then(|s| s.parse().ok());
    let lightnorm: Option<String> = flag(args, "--lightnorm").map(|s| s.to_string());
    // (person_index, embedding)
    let mut embs: Vec<(usize, [f32; irlume_vision::EMBED_DIM])> = Vec::new();
    let mut nodet = 0usize;
    for (pi, (_person, files)) in persons.iter().enumerate() {
        for f in files {
            let Ok(img) = image::open(f) else { continue };
            let rgb = img.to_rgb8();
            let (w, h) = rgb.dimensions();
            let data = rgb.into_raw();
            let view = irlume_vision::align::RgbView {
                data: &data,
                width: w,
                height: h,
            };
            let Ok(faces) = det.detect(&view) else {
                continue;
            };
            let Some(top) = faces.iter().max_by(|a, b| a.score.total_cmp(&b.score)) else {
                nodet += 1;
                continue;
            };
            if let Ok(mut chip) = irlume_vision::align::align_to_arcface(&view, &top.landmarks) {
                if let Some(f) = darken {
                    irlume_vision::light::darken(&mut chip, f);
                }
                match lightnorm.as_deref() {
                    Some("gamma") => irlume_vision::light::gamma(&mut chip, 2.2),
                    Some("he") => irlume_vision::light::equalize(&mut chip),
                    Some("clahe") => irlume_vision::light::clahe(
                        &mut chip,
                        irlume_vision::align::OUT_SIZE as usize,
                        8,
                        3.0,
                    ),
                    _ => {}
                }
                if tta {
                    if let (Ok(a), Ok(b)) = (
                        emb.embed(&chip),
                        emb.embed(&irlume_vision::align::flip_h(&chip)),
                    ) {
                        let mut v = [0f32; irlume_vision::EMBED_DIM];
                        let mut norm = 0f32;
                        for k in 0..irlume_vision::EMBED_DIM {
                            v[k] = a[k] + b[k];
                            norm += v[k] * v[k];
                        }
                        let norm = norm.sqrt().max(1e-12);
                        for vk in v.iter_mut() {
                            *vk /= norm;
                        }
                        embs.push((pi, v));
                    }
                } else if let Ok(e) = emb.embed(&chip) {
                    embs.push((pi, e));
                }
            }
        }
    }
    println!(
        "[irbench] embedded {} faces ({} images had no detectable face){}",
        embs.len(),
        nodet,
        if tta { " [TTA flip-avg]" } else { "" }
    );

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
            if embs[i].0 == embs[j].0 {
                genuine.push(c)
            } else {
                impostor.push(c)
            }
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
    println!(
        "[genuine ] n={:6}  min {:.3}  mean {:.3}  median {:.3}",
        genuine.len(),
        genuine[0],
        mean(&genuine),
        pct(&genuine, 0.5)
    );
    println!(
        "[impostor] n={:6}  mean {:.3}  p99 {:.3}  p99.9 {:.3}  max {:.3}",
        impostor.len(),
        mean(&impostor),
        pct(&impostor, 0.99),
        pct(&impostor, 0.999),
        impostor[impostor.len() - 1]
    );

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
        if (a - r).abs() < eer.0 {
            eer = ((a - r).abs(), t);
        }
        t += 0.005;
    }
    let et = eer.1;
    println!(
        "[EER] ~{:.3} at threshold {et:.3}",
        (far(et) + frr(et)) / 2.0
    );
    // threshold achieving FAR<=1e-4, and its FRR
    let mut t14 = 1.0f32;
    let mut s = 0.30;
    while s <= 0.95 {
        if far(s) <= 1e-4 {
            t14 = s;
            break;
        }
        s += 0.005;
    }
    println!(
        "[FAR≤1e-4] threshold {t14:.3} -> FRR {:.4} (reject rate for genuine at NIST-grade FAR)",
        frr(t14)
    );
    std::process::ExitCode::SUCCESS
}

/// Large-scale RGB FALSE-ACCEPT benchmark (the visible-light sibling of the IR
/// `irbench`). Every image under `--dir` is treated as a distinct identity (true
/// for SFHQ synthetic faces), so every pair is an impostor pair. Embeds each face
/// through the real auth pipeline (YuNet → align → AuraFace) and reports the
/// impostor cosine tail + FAR at the auth thresholds + the threshold achieving
/// NIST-grade FAR ≤ 1e-4. Histogram-based, so it scales to millions of pairs
/// without storing them. FAR only; genuine/FRR come from live captures, not here.
fn farbench(dir: &str, det_path: &str, model: &str, args: &[String]) -> std::process::ExitCode {
    let max_images: usize = flag(args, "--max-images")
        .and_then(|s| s.parse().ok())
        .unwrap_or(20_000);

    let mut files: Vec<std::path::PathBuf> = Vec::new();
    collect_images(std::path::Path::new(dir), &mut files);
    files.sort(); // deterministic sample
    files.truncate(max_images);
    if files.len() < 2 {
        eprintln!(
            "[farbench] need >=2 images under {dir} (found {})",
            files.len()
        );
        return std::process::ExitCode::FAILURE;
    }
    println!(
        "[farbench] {} images; embedding (YuNet→align→AuraFace)…",
        files.len()
    );

    let mut det = match irlume_vision::Detector::load_from_file(det_path) {
        Ok(d) => d,
        Err(e) => {
            eprintln!("det load: {e}");
            return std::process::ExitCode::FAILURE;
        }
    };
    let mut emb = match irlume_vision::Embedder::load_from_file(model) {
        Ok(d) => d,
        Err(e) => {
            eprintln!("emb load: {e}");
            return std::process::ExitCode::FAILURE;
        }
    };

    let mut embs: Vec<[f32; irlume_vision::EMBED_DIM]> = Vec::with_capacity(files.len());
    let mut nodet = 0usize;
    for (i, f) in files.iter().enumerate() {
        if i > 0 && i % 1000 == 0 {
            println!(
                "[farbench]   {}/{} embedded ({} no-face)…",
                embs.len(),
                i,
                nodet
            );
        }
        let Ok(img) = image::open(f) else { continue };
        let rgb = img.to_rgb8();
        let (w, h) = rgb.dimensions();
        let data = rgb.into_raw();
        let view = irlume_vision::align::RgbView {
            data: &data,
            width: w,
            height: h,
        };
        let Ok(faces) = det.detect(&view) else {
            continue;
        };
        let Some(top) = faces.iter().max_by(|a, b| a.score.total_cmp(&b.score)) else {
            nodet += 1;
            continue;
        };
        if let Ok(chip) = irlume_vision::align::align_to_arcface(&view, &top.landmarks) {
            if let Ok(e) = emb.embed(&chip) {
                embs.push(e);
            }
        }
    }
    println!(
        "[farbench] embedded {} faces ({} images had no detectable face)",
        embs.len(),
        nodet
    );
    if embs.len() < 2 {
        eprintln!("[farbench] too few embeddings for pairwise stats");
        return std::process::ExitCode::FAILURE;
    }

    // Optional: dump the raw 512-D embeddings (one per line) for offline analysis
    // (e.g. apply a debiasing adapter and recompute FAR per demographic group).
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
    for k in (0..BINS).rev() {
        suffix[k] = suffix[k + 1] + hist[k];
    }
    let far_at = |t: f32| -> f64 {
        let k = (((t + 1.0) * 0.5 * BINS as f32).ceil() as i64).clamp(0, BINS as i64) as usize;
        suffix[k] as f64 / total as f64
    };
    let pct = |p: f64| -> f32 {
        let target = (p * total as f64) as u64;
        let mut cum = 0u64;
        for (k, &h) in hist.iter().enumerate() {
            cum += h;
            if cum >= target {
                return -1.0 + 2.0 * k as f32 / BINS as f32;
            }
        }
        1.0
    };
    let max_imp = (0..BINS)
        .rev()
        .find(|&k| hist[k] > 0)
        .map(|k| -1.0 + 2.0 * (k as f32 + 1.0) / BINS as f32)
        .unwrap_or(1.0);

    println!(
        "[impostor] pairs={total}  mean {:.3}  p99 {:.3}  p99.9 {:.3}  p99.99 {:.3}  max {:.3}",
        sum_c / total as f64,
        pct(0.99),
        pct(0.999),
        pct(0.9999),
        max_imp
    );
    println!("[FAR sweep]");
    for t in [0.40f32, 0.45, 0.50, 0.55, 0.60] {
        println!(
            "  thr {t:.2}: FAR {:.6}  (1 in {:.0})",
            far_at(t),
            if far_at(t) > 0.0 {
                1.0 / far_at(t)
            } else {
                f64::INFINITY
            }
        );
    }
    let mut t14 = 1.0f32;
    let mut s = 0.30f32;
    while s <= 0.95 {
        if far_at(s) <= 1e-4 {
            t14 = s;
            break;
        }
        s += 0.005;
    }
    println!(
        "[FAR≤1e-4] threshold {t14:.3}  (RGB auth threshold 0.50 → FAR {:.6})",
        far_at(0.50)
    );
    std::process::ExitCode::SUCCESS
}

/// Recursively collect jpg/jpeg/png/bmp files under `dir`.
/// Darken a 112x112x3 RGB chip (simulate low light): pixel *= factor.
fn darken_chip(chip: &[u8], factor: f32) -> Vec<u8> {
    chip.iter()
        .map(|&p| (p as f32 * factor).round().clamp(0.0, 255.0) as u8)
        .collect()
}

/// 3x3 box-blur a 112x112x3 RGB chip (simulate motion/focus blur).
fn blur_chip(chip: &[u8]) -> Vec<u8> {
    let n = 112i32;
    let mut out = chip.to_vec();
    for y in 0..n {
        for x in 0..n {
            for c in 0..3 {
                let (mut sum, mut cnt) = (0u32, 0u32);
                for dy in -1..=1 {
                    for dx in -1..=1 {
                        let (yy, xx) = (y + dy, x + dx);
                        if yy >= 0 && yy < n && xx >= 0 && xx < n {
                            sum += chip[((yy * n + xx) * 3 + c) as usize] as u32;
                            cnt += 1;
                        }
                    }
                }
                out[((y * n + x) * 3 + c) as usize] = (sum / cnt) as u8;
            }
        }
    }
    out
}

/// `irlume normprobe --dir <imgs> --det <yunet> --model <glintr100> [--max N]`
/// Experiment: validate the AdaFace/MagFace feature-norm-as-quality signal on
/// AuraFace. For each face, embed the full chip and degraded (darkened, blurred)
/// versions, comparing the PRE-normalization feature norm. If degraded < full
/// consistently, the norm is a usable quality signal for irlume's fusion.
fn normprobe(args: &[String]) -> std::process::ExitCode {
    let dir = flag(args, "--dir").unwrap_or("");
    let det_path = flag(args, "--det").unwrap_or("models/face_detection_yunet_2023mar.onnx");
    let model = flag(args, "--model").unwrap_or("models/glintr100.onnx");
    let max = flag(args, "--max")
        .and_then(|s| s.parse::<usize>().ok())
        .unwrap_or(40);
    if dir.is_empty() {
        eprintln!("usage: irlume normprobe --dir <imgs> [--det Y] [--model G] [--max N]");
        return std::process::ExitCode::from(2);
    }
    let mut det = match irlume_vision::Detector::load_from_file(det_path) {
        Ok(d) => d,
        Err(e) => {
            eprintln!("det load: {e}");
            return std::process::ExitCode::FAILURE;
        }
    };
    let mut emb = match irlume_vision::Embedder::load_from_file(model) {
        Ok(d) => d,
        Err(e) => {
            eprintln!("emb load: {e}");
            return std::process::ExitCode::FAILURE;
        }
    };
    let mut files = Vec::new();
    collect_images(std::path::Path::new(dir), &mut files);
    files.truncate(max);
    let (mut sf, mut sd, mut sb, mut n) = (0f64, 0f64, 0f64, 0u32);
    let (mut dark_lower, mut blur_lower) = (0u32, 0u32);
    for f in &files {
        let Ok(img) = image::open(f) else { continue };
        let rgb = img.to_rgb8();
        let (w, h) = rgb.dimensions();
        let data = rgb.into_raw();
        let view = irlume_vision::align::RgbView {
            data: &data,
            width: w,
            height: h,
        };
        let Ok(faces) = det.detect(&view) else {
            continue;
        };
        let Some(top) = faces.iter().max_by(|a, b| a.score.total_cmp(&b.score)) else {
            continue;
        };
        let Ok(chip) = irlume_vision::align::align_to_arcface(&view, &top.landmarks) else {
            continue;
        };
        let (Ok((_, nf)), Ok((_, nd)), Ok((_, nb))) = (
            emb.embed_with_norm(&chip),
            emb.embed_with_norm(&darken_chip(&chip, 0.35)),
            emb.embed_with_norm(&blur_chip(&chip)),
        ) else {
            continue;
        };
        sf += nf as f64;
        sd += nd as f64;
        sb += nb as f64;
        n += 1;
        if nd < nf {
            dark_lower += 1;
        }
        if nb < nf {
            blur_lower += 1;
        }
    }
    if n == 0 {
        eprintln!("[normprobe] no faces");
        return std::process::ExitCode::FAILURE;
    }
    let (nf, nd, nb) = (sf / n as f64, sd / n as f64, sb / n as f64);
    println!("[normprobe] {n} faces, mean feature norm:");
    println!("  full   {nf:.2}");
    println!(
        "  dark   {nd:.2}  ({:+.1}%, lower in {}/{n} = {:.0}%)",
        (nd - nf) / nf * 100.0,
        dark_lower,
        dark_lower as f32 / n as f32 * 100.0
    );
    println!(
        "  blur   {nb:.2}  ({:+.1}%, lower in {}/{n} = {:.0}%)",
        (nb - nf) / nf * 100.0,
        blur_lower,
        blur_lower as f32 / n as f32 * 100.0
    );
    let verdict = if nd < nf * 0.97 && nb < nf * 0.97 && dark_lower as f32 / n as f32 > 0.8 {
        "✓ feature norm TRACKS quality on AuraFace; usable as a quality signal"
    } else {
        "✗ weak/no correlation; feature norm NOT a reliable quality signal here"
    };
    println!("[normprobe] {verdict}");
    std::process::ExitCode::SUCCESS
}

fn collect_images(dir: &std::path::Path, out: &mut Vec<std::path::PathBuf>) {
    let Ok(rd) = std::fs::read_dir(dir) else {
        return;
    };
    for e in rd.flatten() {
        let p = e.path();
        if p.is_dir() {
            collect_images(&p, out);
        } else if p
            .extension()
            .and_then(|x| x.to_str())
            .map(|x| {
                matches!(
                    x.to_ascii_lowercase().as_str(),
                    "jpg" | "jpeg" | "png" | "bmp"
                )
            })
            .unwrap_or(false)
        {
            out.push(p);
        }
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

/// P2 probe: capture RGB + IR and report what the IR stream gives us: mean/min/
/// max brightness (is the emitter illuminating?), and whether YuNet finds a face
/// in each spectrum (the basis for the cross-spectrum liveness cue). Diagnostic,
/// not yet a gate.
fn liveness_probe(args: &[String]) -> std::process::ExitCode {
    let rgb_dev = flag(args, "--rgb").unwrap_or(irlume_camera::DEFAULT_RGB_DEVICE);
    let ir_dev = flag(args, "--ir").unwrap_or(irlume_camera::DEFAULT_IR_DEVICE);
    let Some(det_path) = flag(args, "--det") else {
        eprintln!(
            "usage: irlume liveness --det <yunet.onnx> [--rgb /dev/video0] [--ir /dev/video2]"
        );
        return std::process::ExitCode::from(2);
    };
    let run = || -> irlume_common::Result<()> {
        let mut det = irlume_vision::Detector::load_from_file(det_path)?;
        // RGB
        let rgb = irlume_camera::capture_rgb(rgb_dev)?;
        let rgb_view = irlume_vision::align::RgbView {
            data: &rgb.data,
            width: rgb.width,
            height: rgb.height,
        };
        let rgb_faces = det.detect(&rgb_view)?;
        let rgb_top = rgb_faces.iter().map(|f| f.score).fold(0.0f32, f32::max);
        println!(
            "[RGB] {}x{}  faces {}  top score {:.3}",
            rgb.width,
            rgb.height,
            rgb_faces.len(),
            rgb_top
        );
        // IR
        let ir = irlume_camera::capture_ir(ir_dev)?;
        let (mn, mx, sum) = ir.data.iter().fold((255u8, 0u8, 0u64), |(mn, mx, s), &p| {
            (mn.min(p), mx.max(p), s + p as u64)
        });
        let mean = sum as f64 / ir.data.len() as f64;
        println!(
            "[IR ] {}x{}  brightness mean {:.1} min {} max {}",
            ir.width, ir.height, mean, mn, mx
        );
        let ir_rgb = irlume_camera::grey_to_rgb(&ir.data);
        let ir_view = irlume_vision::align::RgbView {
            data: &ir_rgb,
            width: ir.width,
            height: ir.height,
        };
        let ir_faces = det.detect(&ir_view)?;
        let ir_top_face = ir_faces.iter().max_by(|a, b| a.score.total_cmp(&b.score));
        println!(
            "[IR ] faces {}  top score {:.3}",
            ir_faces.len(),
            ir_top_face.map_or(0.0, |f| f.score)
        );

        // Build signals for the gate.
        let to_fbox = |f: &irlume_vision::Detection, w: u32, h: u32| irlume_liveness::FaceBox {
            cx: (f.bbox[0] + f.bbox[2]) / 2.0 / w as f32,
            cy: (f.bbox[1] + f.bbox[3]) / 2.0 / h as f32,
            score: f.score,
        };
        let ir_face_brightness = ir_top_face
            .map(|f| mean_in_bbox(&ir.data, ir.width, ir.height, &f.bbox))
            .unwrap_or(0.0);
        let ir_center_edge_ratio = ir_top_face
            .map(|f| center_edge_ratio(&ir.data, ir.width, ir.height, &f.bbox))
            .unwrap_or(0.0);
        let ir_eye_glint = ir_top_face
            .map(|f| eye_glint(&ir.data, ir.width, ir.height, &f.landmarks))
            .unwrap_or(0.0);
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
            rgb_face_brightness: 0.0,
            rgb_specular_frac: 0.0,
            rgb_moire_score: 0.0,
        };
        let (verdict, cues, reason) = irlume_liveness::LivenessGate::new().evaluate(&signals);
        println!("[gate] IR face brightness {ir_face_brightness:.0}  center/edge {ir_center_edge_ratio:.2}  eye-glint {ir_eye_glint:.0}");
        println!(
            "[gate] cues: rgb={} ir={} aligned={} ir_reflective={} depth={} glint={}",
            cues.face_in_rgb,
            cues.face_in_ir,
            cues.cross_spectrum_aligned,
            cues.ir_reflectance_ok,
            cues.depth_ok,
            cues.glint_present
        );
        println!("[GATE] {verdict:?}: {reason}");
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

/// `irlume meshprobe --det <yunet> --mesh <face_landmark.onnx> [--rgb ..] [--ir ..] [--n 30] [--burst 2]`
/// Diagnostic for the ADR-0002 passive-EAR liveness (MediaPipe FaceMesh). First a
/// single RGB frame as a sanity check (does the mesh give a sane open-eye EAR ~0.3
/// at all?), then an IR sequence to see whether EAR survives the RGB→IR domain gap
/// and whether a natural blink shows. Blink naturally a couple times during the IR
/// capture.
fn meshprobe(args: &[String]) -> std::process::ExitCode {
    let ir_dev = flag(args, "--ir").unwrap_or(irlume_camera::DEFAULT_IR_DEVICE);
    let (Some(det_path), Some(mesh_path)) = (flag(args, "--det"), flag(args, "--mesh")) else {
        eprintln!("usage: irlume meshprobe --det <yunet.onnx> --mesh <face_landmark.onnx> [--ir ..] [--n 40] [--burst 2] [--reps 1]");
        eprintln!("  to record a PAD-style validation run: --species NAME --kind bonafide|attack --out ear.jsonl");
        return std::process::ExitCode::from(2);
    };
    let n: usize = flag(args, "--n").and_then(|s| s.parse().ok()).unwrap_or(75);
    let burst: usize = flag(args, "--burst")
        .and_then(|s| s.parse().ok())
        .unwrap_or(1);
    let reps: usize = flag(args, "--reps")
        .and_then(|s| s.parse().ok())
        .unwrap_or(1);
    let trace_on = args.iter().any(|a| a == "--trace");
    // Optional recording (reuses the padreport JSONL format: Blinked→Live,
    // NoBlink→Uncertain/non-response, NoEyes→Spoof).
    let record = match (
        flag(args, "--species"),
        flag(args, "--kind"),
        flag(args, "--out"),
    ) {
        (Some(s), Some(k), Some(o)) => Some((s.to_string(), k.to_string(), o.to_string())),
        _ => None,
    };
    let run = || -> irlume_common::Result<usize> {
        use std::io::Write;
        let mut det = irlume_vision::Detector::load_from_file(det_path)?;
        let mut mesh = irlume_vision::FaceMesh::load_from_file(mesh_path)?;
        let mut out_file = match &record {
            Some((_, _, o)) => Some(
                std::fs::OpenOptions::new()
                    .create(true)
                    .append(true)
                    .open(o)
                    .map_err(|e| irlume_common::Error::Io(e.to_string()))?,
            ),
            None => None,
        };
        let mut written = 0usize;
        for rep in 0..reps {
            let frames = irlume_camera::capture_ir_sequence(ir_dev, n, burst)?;
            let mut ears: Vec<f32> = Vec::new();
            // Per-frame corneal-specular CONTRAST (the candidate 2nd cue): peak eye
            // contrast over the window. Banner ≤70, no-glasses live ~120; the open
            // question is where glasses-genuine lands (does it clear the floor?).
            let mut contrast_max = 0.0f32;
            // Full EarSample stream (index + EAR-if-face + frame brightness): the
            // brightness column doubles as an emitter duty-cycle probe in dark rooms.
            let mut samples: Vec<irlume_liveness::EarSample> = Vec::new();
            for (i, f) in frames.iter().enumerate() {
                let bri =
                    f.data.iter().map(|&p| p as f32).sum::<f32>() / f.data.len().max(1) as f32;
                let ir_rgb = irlume_camera::grey_to_rgb(&f.data);
                let iv = irlume_vision::align::RgbView {
                    data: &ir_rgb,
                    width: f.width,
                    height: f.height,
                };
                let mut ear_i = None;
                let (mut cx, mut cy, mut fsize, mut contrast) = (0.0, 0.0, 0.0, 0.0);
                if let Some(t) = det
                    .detect(&iv)?
                    .into_iter()
                    .max_by(|a, b| a.score.total_cmp(&b.score))
                {
                    let lm = mesh.landmarks(&iv, &t.bbox, 0.25)?;
                    let ear = irlume_vision::eye_ear(&lm, &irlume_vision::EAR_LEFT)
                        .min(irlume_vision::eye_ear(&lm, &irlume_vision::EAR_RIGHT));
                    ears.push(ear);
                    ear_i = Some(ear);
                    contrast =
                        irlume_auth::eye_glint_contrast(&f.data, f.width, f.height, &t.landmarks);
                    contrast_max = contrast_max.max(contrast);
                    cx = (t.bbox[0] + t.bbox[2]) * 0.5;
                    cy = (t.bbox[1] + t.bbox[3]) * 0.5;
                    fsize = (t.bbox[2] - t.bbox[0]).max(0.0);
                }
                samples.push(irlume_liveness::EarSample {
                    idx: i,
                    ear: ear_i,
                    bri,
                    cx,
                    cy,
                    fsize,
                    contrast,
                });
            }
            if trace_on {
                for s in &samples {
                    match s.ear {
                        Some(e) => {
                            println!("    trace {:>3}  ear {e:.3}  bri {:>5.1}", s.idx, s.bri)
                        }
                        None => println!(
                            "    trace {:>3}  ear   -    bri {:>5.1}  (no face)",
                            s.idx, s.bri
                        ),
                    }
                }
            }
            let verdict = irlume_liveness::detect_blink(&samples);
            let (vs, live) = match verdict {
                irlume_liveness::BlinkResult::Blinked => ("Live", true),
                irlume_liveness::BlinkResult::NoBlink => ("Uncertain", false),
                irlume_liveness::BlinkResult::NoEyes => ("Spoof", false),
            };
            let (mut mn, mut mx) = (1.0f32, 0.0f32);
            for &e in &ears {
                mn = mn.min(e);
                mx = mx.max(e);
            }
            let flag_note = match (&record, live) {
                (Some((_, k, _)), true) if k == "attack" => " ‼ ACCEPTED (breach!)",
                (Some((_, k, _)), false) if k == "bonafide" => " ✗ live user not confirmed",
                _ => "",
            };
            let (_, mot_med, _) = irlume_liveness::face_speeds(&samples);
            let (open_c, dip_c) = irlume_liveness::contrast_signature(&samples);
            let drop = if dip_c > 0.0 { open_c / dip_c } else { 0.0 };
            println!("  [rep {:>2}/{reps}] EAR open {mx:.3} min {mn:.3}  contrast open {open_c:>4.0} dip {dip_c:>4.0} drop {drop:.2}  motion med {mot_med:.3}  (n={}) -> {vs}{flag_note}", rep + 1, ears.len());
            if let (Some(f), Some((sp, kind, _))) = (out_file.as_mut(), &record) {
                let rec = serde_json::json!({
                    "species": sp, "kind": kind, "path": "ear", "idx": rep,
                    "verdict": vs, "reason": format!("passive EAR ({verdict:?})"),
                    "ear_open": json_f32(mx), "ear_min": json_f32(mn), "ear_samples": ears.len(),
                    "contrast_max": json_f32(contrast_max),
                    "caught": Vec::<String>::new(),
                });
                writeln!(f, "{rec}").map_err(|e| irlume_common::Error::Io(e.to_string()))?;
                written += 1;
            }
        }
        Ok(written)
    };
    match run() {
        Ok(w) => {
            if let Some((_, _, o)) = &record {
                println!("[meshprobe] appended {w} presentations to {o}; run `irlume padreport --in {o}`");
            }
            std::process::ExitCode::SUCCESS
        }
        Err(e) => {
            eprintln!("meshprobe error: {e}");
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
        println!("[genuine] stay in frame; capturing {FRAMES} frames…");
        for k in 0..FRAMES {
            let f = irlume_camera::capture_rgb(device)?;
            let view = irlume_vision::align::RgbView {
                data: &f.data,
                width: f.width,
                height: f.height,
            };
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
            println!("[genuine] need >=2 frames with a face; re-run staying in view.");
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
        println!(
            "[genuine] {} pairs: min {:.3}  mean {:.3}  max {:.3}",
            scores.len(),
            scores[0],
            mean,
            scores[scores.len() - 1]
        );
        let impostor_max = 0.423;
        println!("  impostor max (from eval): {impostor_max:.3}");
        if scores[0] > impostor_max {
            let mid = (scores[0] + impostor_max) / 2.0;
            println!(
                "  ✓ SEPARABLE: genuine min {:.3} > impostor max {:.3}; midpoint threshold ≈ {:.3}",
                scores[0], impostor_max, mid
            );
        } else {
            println!("  ⚠ overlap: genuine min {:.3} ≤ impostor max; needs better alignment/lighting or per-profile (e.g. glasses) enrollment",
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

/// `irlume calcapture --user U --det <yunet> --model <glintr100> [--adapter <ir>]
///   [--rgb /dev/video0] [--ir /dev/video2] [--n 40] [--tag bright] --out cal.jsonl`
///
/// REAL-ASUS calibration/validation capture: direct camera access (run with the
/// daemon stopped to avoid EBUSY). Grabs N live RGB+IR samples of the enrolled
/// user and, per sample, records the genuine cosine vs the user's own templates
/// (RGB TTA-512 space; IR in the deployed v1-adapter space) plus face brightness
/// and the RAW 512-D RGB and IR embeddings. The dump feeds two offline jobs:
///   #3 Platt recalibration: real genuine RGB/IR cosine+brightness distribution
///      (the academic-fit consts in fusion.rs are a prior; this is ground truth);
///   #4 adapter-v3 validation: raw IR embeddings re-scored through v1 vs the
///      banked residZero+ASnorm adapter, with academic impostors, before deploy.
/// Capture across lighting with `--tag bright` now and `--tag dim` at sunset.
fn calcapture(args: &[String]) -> std::process::ExitCode {
    let user = user_arg(args);
    let (Some(det_path), Some(model), Some(out)) = (
        flag(args, "--det"),
        flag(args, "--model"),
        flag(args, "--out"),
    ) else {
        eprintln!("usage: irlume calcapture --user U --det <yunet.onnx> --model <glintr100.onnx> --out <cal.jsonl> [--adapter <ir.onnx>] [--rgb /dev/video0] [--ir /dev/video2] [--n 40] [--tag bright]");
        return std::process::ExitCode::from(2);
    };
    let rgb_dev = flag(args, "--rgb").unwrap_or("/dev/video0");
    let ir_dev = flag(args, "--ir").unwrap_or("/dev/video2");
    let n: usize = flag(args, "--n").and_then(|s| s.parse().ok()).unwrap_or(40);
    let tag = flag(args, "--tag").unwrap_or("untagged").to_string();

    // mean luma (RGB, BT.601) / mean grey (IR) inside a detector bbox, clamped.
    let mean_bbox = |data: &[u8], w: u32, h: u32, ch: usize, bbox: &[f32; 4]| -> f32 {
        let (x1, y1) = (bbox[0].max(0.0) as u32, bbox[1].max(0.0) as u32);
        let (x2, y2) = ((bbox[2] as u32).min(w), (bbox[3] as u32).min(h));
        if x2 <= x1 || y2 <= y1 {
            return 0.0;
        }
        let (mut sum, mut cnt) = (0.0f64, 0u64);
        for y in y1..y2 {
            for x in x1..x2 {
                let i = ((y * w + x) as usize) * ch;
                let v = if ch == 3 {
                    0.299 * data[i] as f32 + 0.587 * data[i + 1] as f32 + 0.114 * data[i + 2] as f32
                } else {
                    data[i] as f32
                };
                sum += v as f64;
                cnt += 1;
            }
        }
        if cnt == 0 {
            0.0
        } else {
            (sum / cnt as f64) as f32
        }
    };

    // Luma at (x, y) for 3-channel RGB or 1-channel grey data.
    let luma = |data: &[u8], w: u32, ch: usize, x: u32, y: u32| -> f32 {
        let i = ((y * w + x) as usize) * ch;
        if ch == 3 {
            0.299 * data[i] as f32 + 0.587 * data[i + 1] as f32 + 0.114 * data[i + 2] as f32
        } else {
            data[i] as f32
        }
    };

    // Fraction of pixels at/above 250 (near clipping) across the whole frame:
    // the saturated-background signature that blinds detection outdoors.
    let sat_pct = |data: &[u8], w: u32, h: u32, ch: usize| -> f32 {
        let (mut sat, mut cnt) = (0u64, 0u64);
        for y in 0..h {
            for x in 0..w {
                if luma(data, w, ch, x, y) >= 250.0 {
                    sat += 1;
                }
                cnt += 1;
            }
        }
        if cnt == 0 {
            0.0
        } else {
            sat as f32 / cnt as f32
        }
    };

    // Sharpness: variance of the 3x3 Laplacian inside the face bbox (the
    // standard blur/focus measure; low = defocused or motion-smeared sample).
    let laplacian_var_bbox = |data: &[u8], w: u32, h: u32, ch: usize, bbox: &[f32; 4]| -> f32 {
        let (x1, y1) = (bbox[0].max(1.0) as u32, bbox[1].max(1.0) as u32);
        let (x2, y2) = (
            (bbox[2] as u32).min(w.saturating_sub(1)),
            (bbox[3] as u32).min(h.saturating_sub(1)),
        );
        if x2 <= x1 || y2 <= y1 {
            return 0.0;
        }
        let (mut sum, mut sum2, mut cnt) = (0.0f64, 0.0f64, 0u64);
        for y in y1..y2 {
            for x in x1..x2 {
                let lap = 4.0 * luma(data, w, ch, x, y)
                    - luma(data, w, ch, x - 1, y)
                    - luma(data, w, ch, x + 1, y)
                    - luma(data, w, ch, x, y - 1)
                    - luma(data, w, ch, x, y + 1);
                sum += lap as f64;
                sum2 += (lap * lap) as f64;
                cnt += 1;
            }
        }
        if cnt == 0 {
            0.0
        } else {
            let mean = sum / cnt as f64;
            (sum2 / cnt as f64 - mean * mean) as f32
        }
    };

    // Face contrast: p90 - p10 luma spread inside the bbox. A dim-but-usable
    // face keeps its spread; a flat backlit face (the "IR face too dark"
    // failure axis) loses it, which mean brightness alone cannot show.
    let contrast_bbox = |data: &[u8], w: u32, h: u32, ch: usize, bbox: &[f32; 4]| -> f32 {
        let (x1, y1) = (bbox[0].max(0.0) as u32, bbox[1].max(0.0) as u32);
        let (x2, y2) = ((bbox[2] as u32).min(w), (bbox[3] as u32).min(h));
        if x2 <= x1 || y2 <= y1 {
            return 0.0;
        }
        let mut v: Vec<f32> = (y1..y2)
            .flat_map(|y| (x1..x2).map(move |x| (x, y)))
            .map(|(x, y)| luma(data, w, ch, x, y))
            .collect();
        v.sort_by(f32::total_cmp);
        v[(v.len() - 1) * 9 / 10] - v[(v.len() - 1) / 10]
    };

    // 5-point landmarks flattened to [x0,y0,...,x4,y4] + inter-ocular pixel
    // distance (the distance-to-camera proxy; landmarks 0,1 are the eyes).
    let lm_flat = |lm: &irlume_vision::Landmarks5| -> Vec<f32> {
        lm.iter().flat_map(|&(x, y)| [x, y]).collect()
    };
    let iod_px = |lm: &irlume_vision::Landmarks5| -> f32 {
        ((lm[1].0 - lm[0].0).powi(2) + (lm[1].1 - lm[0].1).powi(2)).sqrt()
    };

    let run = || -> irlume_common::Result<usize> {
        // Enrolled templates are encrypted at rest (TPM-sealed key, root-only), so a
        // user-space run can't decrypt them. That's fine: we always dump the raw
        // embeddings and derive genuine cosines pairwise among the captures offline.
        // When templates ARE available (run as root, daemon stopped) we additionally
        // record the true probe-vs-enrolled cosine.
        let enr = match irlume_core::storage::load(&user) {
            Ok(Some(e)) => Some(e),
            Ok(None) => {
                eprintln!("[calcapture] note: '{user}' not enrolled; cosines from pairwise only");
                None
            }
            Err(e) => {
                eprintln!(
                    "[calcapture] note: templates unavailable ({e}); cosines from pairwise only"
                );
                None
            }
        };
        let rgb_scans = enr.as_ref().map(|e| e.rgb_scans()).unwrap_or_default();
        let ir_scans = enr.as_ref().map(|e| e.ir_scans()).unwrap_or_default();
        let mut det = irlume_vision::Detector::load_from_file(det_path)?;
        let mut emb = irlume_vision::Embedder::load_from_file(model)?;
        let mut adapter = match flag(args, "--adapter") {
            Some(p) => Some(irlume_vision::Adapter::load_from_file(p)?),
            None => None,
        };
        let best = |probe: &[f32], scans: &[(&str, &str, &[f32])]| -> f32 {
            scans
                .iter()
                .map(|(_, _, t)| irlume_vision::align::cosine(probe, t))
                .fold(f32::NEG_INFINITY, f32::max)
        };
        let mut f =
            std::fs::File::create(out).map_err(|e| irlume_common::Error::Io(e.to_string()))?;
        use std::io::Write;
        println!("[calcapture] user={user} tag={tag} n={n} -> {out}");
        println!(
            "[calcapture] rgb_templates={} ir_templates={} adapter={}",
            rgb_scans.len(),
            ir_scans.len(),
            if adapter.is_some() { "yes" } else { "no" }
        );
        println!("[calcapture] sit naturally in frame; vary pose slightly between samples.");

        // Session header (first line): hardware + model provenance, so the
        // dataset self-documents which sensor and which recognizer produced
        // the embeddings. Loaders that want samples skip records without
        // embedding fields. sha256 prefixes match the space-tagging scheme.
        let file_sha12 = |p: &str| -> serde_json::Value {
            match std::fs::read(p) {
                Ok(b) => {
                    let d = format!("{:x}", <sha2::Sha256 as sha2::Digest>::digest(&b));
                    d[..12].to_string().into()
                }
                Err(_) => serde_json::Value::Null,
            }
        };
        let epoch = || -> f64 {
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_secs_f64())
                .unwrap_or(0.0)
        };
        let mut hdr = serde_json::Map::new();
        hdr.insert("session".into(), true.into());
        hdr.insert("user".into(), user.clone().into());
        hdr.insert("tag".into(), tag.clone().into());
        hdr.insert("n".into(), n.into());
        hdr.insert(
            "host".into(),
            std::fs::read_to_string("/proc/sys/kernel/hostname")
                .map(|s| s.trim().to_string())
                .unwrap_or_default()
                .into(),
        );
        hdr.insert(
            "rgb_camera".into(),
            irlume_camera::device_identity(rgb_dev)
                .unwrap_or_else(|| rgb_dev.to_string())
                .into(),
        );
        hdr.insert(
            "ir_camera".into(),
            irlume_camera::device_identity(ir_dev)
                .unwrap_or_else(|| ir_dev.to_string())
                .into(),
        );
        hdr.insert(
            "irlume_version".into(),
            env!("CARGO_PKG_VERSION").to_string().into(),
        );
        hdr.insert("det_sha256".into(), file_sha12(det_path));
        hdr.insert("model_sha256".into(), file_sha12(model));
        hdr.insert(
            "adapter_sha256".into(),
            flag(args, "--adapter")
                .map(file_sha12)
                .unwrap_or(serde_json::Value::Null),
        );
        hdr.insert("ts_unix".into(), epoch().into());
        writeln!(f, "{}", serde_json::Value::Object(hdr))
            .map_err(|e| irlume_common::Error::Io(e.to_string()))?;

        let mut written = 0usize;
        let t0 = std::time::Instant::now();
        for idx in 0..n {
            // RGB (median-denoised, matches the auth path) + IR (brightest-of-burst).
            let rgbf = irlume_camera::capture_rgb_denoised(rgb_dev)?;
            let rv = irlume_vision::align::RgbView {
                data: &rgbf.data,
                width: rgbf.width,
                height: rgbf.height,
            };
            let rgb_top = det
                .detect(&rv)?
                .into_iter()
                .max_by(|a, b| a.score.total_cmp(&b.score));

            let (irf, ir_stats) = irlume_camera::capture_ir_with_stats(ir_dev)?;
            let ir_rgb = irlume_camera::grey_to_rgb(&irf.data);
            let iv = irlume_vision::align::RgbView {
                data: &ir_rgb,
                width: irf.width,
                height: irf.height,
            };
            let ir_top = det
                .detect(&iv)?
                .into_iter()
                .max_by(|a, b| a.score.total_cmp(&b.score));

            let mut rec = serde_json::Map::new();
            rec.insert("idx".into(), idx.into());
            rec.insert("tag".into(), tag.clone().into());
            // Wall clock since the first sample: real capture cadence (the
            // per-sample rate is camera-I/O-bound and varies with USB load).
            rec.insert(
                "elapsed_ms".into(),
                json_f32(t0.elapsed().as_secs_f32() * 1000.0),
            );
            // Whole-frame saturation: fraction of pixels at/above 250. High
            // values are the outdoor failure signature (saturated background
            // blinding the detector), worth stratifying training data by.
            rec.insert(
                "rgb_sat_pct".into(),
                json_f32(sat_pct(&rgbf.data, rgbf.width, rgbf.height, 3)),
            );
            rec.insert(
                "ir_sat_pct".into(),
                json_f32(sat_pct(&irf.data, irf.width, irf.height, 1)),
            );
            // Capture resolution per modality: the driver may deliver a
            // different mode than requested, and detection/sharpness numbers
            // only compare across samples of the same resolution.
            rec.insert("rgb_res".into(), vec![rgbf.width, rgbf.height].into());
            rec.insert("ir_res".into(), vec![irf.width, irf.height].into());
            rec.insert("ts_unix".into(), epoch().into());
            // Per-capture ambient IR from the burst's darkest (emitter-off)
            // frame, and the strobe gap: the ambient-relative gate's inputs,
            // only observable at capture time.
            rec.insert("ir_ambient".into(), json_f32(ir_stats.ambient_mean));
            rec.insert(
                "ir_strobe_gap".into(),
                json_f32(ir_stats.lit_mean - ir_stats.ambient_mean),
            );

            let (mut rgb_cos, mut rgb_bri) = (f32::NAN, 0.0f32);
            if let Some(t) = &rgb_top {
                let chip = irlume_vision::align::align_to_arcface(&rv, &t.landmarks)?;
                let e = emb.embed_tta(&chip)?; // RGB path = TTA flip-average
                rgb_bri = mean_bbox(&rgbf.data, rgbf.width, rgbf.height, 3, &t.bbox);
                if !rgb_scans.is_empty() {
                    rgb_cos = best(&e, &rgb_scans);
                }
                rec.insert("rgb_face_score".into(), json_f32(t.score));
                rec.insert("rgb_cos".into(), json_f32(rgb_cos));
                rec.insert("rgb_brightness".into(), json_f32(rgb_bri));
                rec.insert(
                    "rgb_sharpness".into(),
                    json_f32(laplacian_var_bbox(
                        &rgbf.data,
                        rgbf.width,
                        rgbf.height,
                        3,
                        &t.bbox,
                    )),
                );
                rec.insert(
                    "rgb_contrast".into(),
                    json_f32(contrast_bbox(
                        &rgbf.data,
                        rgbf.width,
                        rgbf.height,
                        3,
                        &t.bbox,
                    )),
                );
                rec.insert(
                    "rgb_bbox".into(),
                    serde_json::to_value(t.bbox.to_vec()).unwrap(),
                );
                rec.insert(
                    "rgb_landmarks".into(),
                    serde_json::to_value(lm_flat(&t.landmarks)).unwrap(),
                );
                rec.insert("rgb_iod_px".into(), json_f32(iod_px(&t.landmarks)));
                rec.insert("rgb_emb".into(), serde_json::to_value(e.to_vec()).unwrap());
            }
            rec.insert("rgb_present".into(), rgb_top.is_some().into());

            let (mut ir_cos, mut ir_bri, mut ir_depth, mut ir_glint) =
                (f32::NAN, 0.0f32, 0.0f32, 0.0f32);
            if let Some(t) = &ir_top {
                let chip = irlume_vision::align::align_to_arcface(&iv, &t.landmarks)?;
                let raw = emb.embed(&chip)?; // IR = plain embed (no TTA), RAW 512-D
                ir_bri = mean_bbox(&irf.data, irf.width, irf.height, 1, &t.bbox);
                // Ambient-INDEPENDENT liveness cues (the depth-primary-floor candidates):
                // center/edge IR ratio (3D face structure) and corneal glint peak.
                ir_depth =
                    irlume_auth::center_edge_ratio(&irf.data, irf.width, irf.height, &t.bbox);
                ir_glint = irlume_auth::eye_glint(&irf.data, irf.width, irf.height, &t.landmarks);
                if let Some(a) = adapter.as_mut() {
                    let adapted = a.apply(&raw)?;
                    if !ir_scans.is_empty() {
                        ir_cos = best(&adapted, &ir_scans);
                    }
                }
                rec.insert("ir_face_score".into(), json_f32(t.score));
                rec.insert("ir_cos_v1".into(), json_f32(ir_cos));
                rec.insert("ir_brightness".into(), json_f32(ir_bri));
                rec.insert(
                    "ir_sharpness".into(),
                    json_f32(laplacian_var_bbox(
                        &irf.data, irf.width, irf.height, 1, &t.bbox,
                    )),
                );
                rec.insert(
                    "ir_contrast".into(),
                    json_f32(contrast_bbox(&irf.data, irf.width, irf.height, 1, &t.bbox)),
                );
                rec.insert(
                    "ir_bbox".into(),
                    serde_json::to_value(t.bbox.to_vec()).unwrap(),
                );
                rec.insert(
                    "ir_landmarks".into(),
                    serde_json::to_value(lm_flat(&t.landmarks)).unwrap(),
                );
                rec.insert("ir_iod_px".into(), json_f32(iod_px(&t.landmarks)));
                rec.insert(
                    "ir_eyes_open".into(),
                    irlume_auth::both_eyes_open(&irf.data, irf.width, irf.height, &t.landmarks)
                        .into(),
                );
                rec.insert("ir_depth".into(), json_f32(ir_depth));
                rec.insert("ir_glint".into(), json_f32(ir_glint));
                rec.insert(
                    "ir_emb_raw".into(),
                    serde_json::to_value(raw.to_vec()).unwrap(),
                );
            }
            rec.insert("ir_present".into(), ir_top.is_some().into());

            writeln!(f, "{}", serde_json::Value::Object(rec))
                .map_err(|e| irlume_common::Error::Io(e.to_string()))?;
            written += 1;
            println!(
                "  [{:>2}/{n}] rgb {} bri {:>5.1} | ir {} bri {:>5.1} depth {:>5.2} glint {:>3.0}",
                idx + 1,
                if rgb_top.is_some() { "✓" } else { "·" },
                rgb_bri,
                if ir_top.is_some() { "✓" } else { "·" },
                ir_bri,
                ir_depth,
                ir_glint
            );
        }
        Ok(written)
    };
    match run() {
        Ok(w) => {
            println!("[calcapture] wrote {w} samples to {out}");
            std::process::ExitCode::SUCCESS
        }
        Err(e) => {
            eprintln!("calcapture error: {e}");
            std::process::ExitCode::FAILURE
        }
    }
}

/// JSON number from an f32, mapping non-finite to JSON null (so `NaN` for an
/// absent cosine round-trips cleanly instead of breaking the encoder).
fn json_f32(x: f32) -> serde_json::Value {
    serde_json::Number::from_f64(x as f64)
        .map(serde_json::Value::Number)
        .unwrap_or(serde_json::Value::Null)
}

/// Embed every detected face in an image and report the pairwise-cosine
/// distribution. In a group photo every pair is a different person, so this is
/// the IMPOSTOR distribution: it validates AuraFace discriminates (impostors
/// should score low) and sets the threshold floor (must sit above impostor max).
fn eval(args: &[String]) -> std::process::ExitCode {
    let (Some(img), Some(det_path), Some(model)) = (
        flag(args, "--image"),
        flag(args, "--det"),
        flag(args, "--model"),
    ) else {
        eprintln!(
            "usage: irlume eval --image <group.jpg> --det <yunet.onnx> --model <glintr100.onnx>"
        );
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
    let view = irlume_vision::align::RgbView {
        data: &data,
        width: w,
        height: h,
    };

    let run = || -> irlume_common::Result<()> {
        let mut det = irlume_vision::Detector::load_from_file(det_path)?;
        let mut emb = irlume_vision::Embedder::load_from_file(model)?;
        let grey = args.iter().any(|a| a == "--grey");
        let faces = det.detect(&view)?;
        println!(
            "[eval] {} faces; embedding each{}…",
            faces.len(),
            if grey { " (GREYSCALE / IR-proxy)" } else { "" }
        );
        let mut embs = Vec::new();
        for f in &faces {
            let mut chip = irlume_vision::align::align_to_arcface(&view, &f.landmarks)?;
            if grey {
                // Simulate the IR modality: drop colour, keep luminance (BT.601),
                // replicate to 3 channels. Isolates AuraFace's colour-removal loss.
                for px in chip.chunks_exact_mut(3) {
                    let y =
                        (0.299 * px[0] as f32 + 0.587 * px[1] as f32 + 0.114 * px[2] as f32) as u8;
                    px[0] = y;
                    px[1] = y;
                    px[2] = y;
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
        println!(
            "  min {:.3}  mean {:.3}  p95 {:.3}  p99 {:.3}  max {:.3}",
            scores[0],
            mean,
            pct(0.95),
            pct(0.99),
            scores[n - 1]
        );
        println!(
            "  => threshold floor (above impostor max): {:.3}",
            scores[n - 1] + 0.02
        );
        println!("  (genuine pairs of the same person across 2 captures set the ceiling; run two `capture` sessions to measure.)");
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
/// TPM character device the kernel exposes, if any (resource-managed preferred).
pub(crate) fn tpm_device() -> Option<&'static str> {
    ["/dev/tpmrm0", "/dev/tpm0"]
        .into_iter()
        .find(|d| std::path::Path::new(d).exists())
}

fn doctor() -> std::process::ExitCode {
    use irlume_common::secureboot;
    // --- platform / trust anchors ------------------------------------------
    println!(
        "[doctor] platform: {}",
        irlume_common::platform::distro_family().as_str()
    );
    println!(
        "[doctor] install origin: {}",
        commands::install_origin().describe()
    );
    match tpm_device() {
        Some(d) => println!("[doctor] TPM 2.0: {d} ✓"),
        None => println!("[doctor] TPM 2.0: none (/dev/tpmrm0 absent) ✗; required for sealing"),
    }
    if !secureboot::secure_boot_present() {
        println!("[doctor] Secure Boot: unknown (not a UEFI boot?)");
    } else if secureboot::is_secure_boot_enabled() {
        println!("[doctor] Secure Boot: enabled ✓");
    } else if secureboot::is_setup_mode() {
        println!(
            "[doctor] Secure Boot: SETUP MODE ⚠ (keys not enrolled); PCR-7 binding is NOT enforcing"
        );
    } else {
        println!("[doctor] Secure Boot: disabled ⚠ (TPM PCR-7 binding is weak; enable for trust)");
    }
    println!(
        "[doctor] boot mode: {}",
        secureboot::detect_boot_mode().as_str()
    );
    println!(
        "[doctor] signed PCR policy: {}",
        if irlume_core::pcrsig::signed_policy_available() {
            "systemd PCR-11 signature present ✓; kernel updates won't need re-seal"
        } else {
            "none (no Tier 1 on this boot chain)"
        }
    );
    println!(
        "[doctor] pcrlock: {}",
        match irlume_core::tpm::pcrlock_provisioned() {
            Some(nv) => format!(
                "provisioned, NV 0x{nv:x}; an arm binds to it if it unseals on this boot (Tier 2)"
            ),
            None => "not provisioned: seals use the literal PCR-7 policy + recovery passphrase \
                     (re-arm/restore after firmware updates); `systemd-pcrlock make-policy` \
                     enables Tier 2"
                .to_string(),
        }
    );

    // --- cameras -----------------------------------------------------------
    println!("[doctor] camera nodes (classified by pixel format):");
    let nodes = irlume_camera::discover_nodes();
    if nodes.is_empty() {
        println!("  (none found under /dev/video0..9)");
    }
    for (path, role) in &nodes {
        let priv_on = if irlume_camera::privacy_engaged(path) {
            "  ⚠ PRIVACY SWITCH ON"
        } else {
            ""
        };
        println!("  {path}: {role:?}{priv_on}");
    }

    // --- models / runtime --------------------------------------------------
    println!("[doctor] models:");
    if commands::daemon_models_loaded() == Some(true) {
        println!("  loaded by the daemon ✓");
    } else {
        for (f, env) in commands::REQUIRED_MODELS {
            match commands::resolve_model(f, env) {
                Some(p) => println!("  {f}: present ✓ ({})", p.display()),
                None => {
                    println!("  {f}: not found; install the irlume package (or run from the repo)")
                }
            }
        }
    }
    let ort = std::env::var("ORT_DYLIB_PATH").unwrap_or_default();
    println!(
        "[doctor] ORT_DYLIB_PATH: {}",
        if ort.is_empty() {
            "(unset)".into()
        } else {
            ort
        }
    );

    // --- companion factors / data-at-rest ----------------------------------
    let fp = match irlume_fingerprint::device_name() {
        Some(n) => format!("{n} ✓ (manage with `irlume fingerprint`)"),
        None if irlume_fingerprint::available() => "present ✓".into(),
        None => "none".into(),
    };
    println!("[doctor] fingerprint reader: {fp}");

    // Template encryption + recovery come from the daemon (root-only store).
    let user = user_arg(&[]);
    match daemon_request(&irlume_common::Request::RecoveryStatus { user: user.clone() }) {
        Ok(irlume_common::Response::RecoveryStatus { encrypted, recovery_set, .. }) => {
            println!(
                "[doctor] templates ({user}): {} · recovery passphrase {}",
                if encrypted { "ENCRYPTED ✓" } else { "plaintext at rest" },
                if recovery_set { "SET ✓" } else { "not set (run `irlume recovery setup`)" },
            );
        }
        _ => println!("[doctor] templates ({user}): unknown (daemon not reachable; run `irlume recovery status`)"),
    }

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
    let view = irlume_vision::align::RgbView {
        data: &data,
        width,
        height,
    };

    let run = || -> irlume_common::Result<()> {
        let mut det = irlume_vision::Detector::load_from_file(det_path)?;
        let faces = det.detect(&view)?;
        println!("[detect] {} face(s)", faces.len());
        let Some(top) = faces.iter().max_by(|a, b| a.score.total_cmp(&b.score)) else {
            println!("  no face in frame; sit in view and re-run.");
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
        println!(
            "[embed]  512-D, L2 norm {norm:.4}, head [{:.3}, {:.3}, {:.3}, {:.3}]",
            e[0], e[1], e[2], e[3]
        );
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
/// twice: cosine MUST be ~1.0. Proves the ONNX path is deterministic and the
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
                println!("[selftest align] PASS: ONNX embed path is deterministic.");
                std::process::ExitCode::SUCCESS
            } else {
                eprintln!("[selftest align] FAIL: check preprocessing / channel order.");
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

//! `irlume models`: opt-in third-party model management.
//!
//!   irlume models                 list the catalog + what is enabled
//!   sudo irlume models enable X   fetch, verify, and enable a catalog model
//!   sudo irlume models disable    delete the weights and revert to defaults
//!
//! These are models irlume can fetch onto THIS machine but does not ship,
//! mirror, or warrant (catalog + rationale: `irlume_common::thirdparty`;
//! measurements: docs/pad-results/). Enabling is deliberately high-friction
//! (license + provenance shown, model name typed back, then a final y/N);
//! disabling is one confirmation, deletes the weights, and returns the daemon
//! to the shipped stack. The daemon wires an enabled model as a DENY-ONLY
//! liveness cue and refuses to load a file whose checksum stops matching.

use irlume_common::thirdparty::{self, ThirdPartyModel};
use std::io::{BufRead, Write};
use std::process::{Command, ExitCode};

pub fn run(sub: Option<&str>, args: &[String]) -> ExitCode {
    match sub {
        None | Some("list") => list(),
        Some("enable") => enable(args.get(2).map(String::as_str)),
        Some("disable") => disable(),
        _ => usage(),
    }
}

fn usage() -> ExitCode {
    eprintln!("usage: irlume models [list]");
    eprintln!("       sudo irlume models enable <name>");
    eprintln!("       sudo irlume models disable");
    ExitCode::from(2)
}

/// The catalog name currently enabled in settings.conf, if any.
fn enabled_name() -> Option<String> {
    irlume_common::config::read_kv("settings.conf", thirdparty::SETTINGS_KEY)
}

fn file_state(m: &ThirdPartyModel) -> &'static str {
    let path = thirdparty::model_path(m);
    match std::fs::read(&path) {
        Ok(bytes) => {
            use sha2::Digest;
            if format!("{:x}", sha2::Sha256::digest(&bytes)) == m.sha256 {
                "weights present, checksum ok"
            } else {
                "weights present but CHECKSUM MISMATCH (daemon will refuse them)"
            }
        }
        Err(_) => "weights not fetched",
    }
}

fn list() -> ExitCode {
    let enabled = enabled_name();
    println!("Third-party models irlume can fetch but does not ship or warrant.");
    println!("Each entry was measured on real hardware before listing (docs/pad-results/).");
    println!();
    for m in thirdparty::CATALOG {
        let state = if enabled.as_deref() == Some(m.name) {
            format!("ENABLED ({})", file_state(m))
        } else {
            "disabled".into()
        };
        println!("  {}  [{state}]", m.name);
        println!("    license:    {}", m.license);
        println!("    provenance: {}", m.provenance);
        println!(
            "    role:       deny-only liveness cue, threshold {}",
            m.threshold
        );
        println!("    measured:   {}", m.summary);
    }
    println!();
    match enabled {
        Some(n) => println!("enabled: {n} · disable with: sudo irlume models disable"),
        None => println!("none enabled · enable with: sudo irlume models enable <name>"),
    }
    ExitCode::SUCCESS
}

fn enable(name: Option<&str>) -> ExitCode {
    let Some(name) = name else {
        return usage();
    };
    let Some(m) = thirdparty::by_name(name) else {
        eprintln!("[models] '{name}' is not in the catalog; run `irlume models` to list it");
        return ExitCode::FAILURE;
    };
    if !is_root() {
        eprintln!("[models] needs root: sudo irlume models enable {name}");
        return ExitCode::FAILURE;
    }
    if !stdin_is_tty() {
        eprintln!(
            "[models] enabling needs an interactive terminal (the license and provenance \
             must be read and confirmed); for sandboxes use the IRLUME_THIRDPARTY_PAD env override"
        );
        return ExitCode::FAILURE;
    }
    if enabled_name().as_deref() == Some(m.name) {
        println!(
            "[models] '{}' is already enabled ({})",
            m.name,
            file_state(m)
        );
        println!("[models] re-fetching and re-verifying anyway.");
    }

    println!("Enabling third-party model '{}'", m.name);
    println!();
    println!("  license:    {}", m.license);
    println!("  provenance: {}", m.provenance);
    println!("  measured:   {}", m.summary);
    println!("  effect:     adds a DENY-ONLY liveness cue on the lit IR frame; it can");
    println!("              reject a presentation, it can never approve one the built-in");
    println!("              gate rejected. False fires cost a retry or the password.");
    println!();
    println!("  irlume does not distribute these weights. They download now, once, from");
    println!("  the publisher's origin, and complying with the license above is on you.");
    println!();
    print!("Type the model name to continue: ");
    let _ = std::io::stdout().flush();
    let mut typed = String::new();
    if std::io::stdin().lock().read_line(&mut typed).is_err() || typed.trim() != m.name {
        println!("[models] name mismatch; nothing was changed.");
        return ExitCode::FAILURE;
    }
    print!("Fetch, verify, and enable '{}'? [y/N] ", m.name);
    let _ = std::io::stdout().flush();
    let mut yn = String::new();
    if std::io::stdin().lock().read_line(&mut yn).is_err()
        || !matches!(yn.trim(), "y" | "Y" | "yes")
    {
        println!("[models] cancelled; nothing was changed.");
        return ExitCode::FAILURE;
    }

    let dir = thirdparty::dir();
    if let Err(e) = std::fs::create_dir_all(&dir) {
        eprintln!("[models] could not create {}: {e}", dir.display());
        return ExitCode::FAILURE;
    }
    let tmp = dir.join(format!(".{}.part", m.file));
    println!("[models] downloading from the publisher's origin ...");
    let status = Command::new("curl")
        .args(["-fSL", "--max-time", "300", "-o"])
        .arg(&tmp)
        .arg(m.url)
        .status();
    if !matches!(status, Ok(s) if s.success()) {
        let _ = std::fs::remove_file(&tmp);
        eprintln!(
            "[models] download failed (offline, or the publisher moved the file?); nothing enabled"
        );
        return ExitCode::FAILURE;
    }
    let bytes = match std::fs::read(&tmp) {
        Ok(b) => b,
        Err(e) => {
            let _ = std::fs::remove_file(&tmp);
            eprintln!("[models] could not read the download: {e}");
            return ExitCode::FAILURE;
        }
    };
    use sha2::Digest;
    let digest = format!("{:x}", sha2::Sha256::digest(&bytes));
    if digest != m.sha256 {
        let _ = std::fs::remove_file(&tmp);
        eprintln!("[models] CHECKSUM MISMATCH: got sha256 {digest}");
        eprintln!("[models] expected            {}", m.sha256);
        eprintln!(
            "[models] the publisher's file changed since it was measured; refusing to enable."
        );
        return ExitCode::FAILURE;
    }
    let path = thirdparty::model_path(m);
    if let Err(e) = std::fs::rename(&tmp, &path) {
        let _ = std::fs::remove_file(&tmp);
        eprintln!("[models] could not install {}: {e}", path.display());
        return ExitCode::FAILURE;
    }
    if let Err(e) =
        irlume_common::config::write_kv("settings.conf", thirdparty::SETTINGS_KEY, m.name)
    {
        eprintln!("[models] weights installed but settings.conf update failed: {e}");
        return ExitCode::FAILURE;
    }
    restart_daemon();
    println!(
        "[models] '{}' enabled (sha256 verified) and the daemon restarted.",
        m.name
    );
    println!("[models] check with: irlume doctor · disable with: sudo irlume models disable");
    ExitCode::SUCCESS
}

fn disable() -> ExitCode {
    if !is_root() {
        eprintln!("[models] needs root: sudo irlume models disable");
        return ExitCode::FAILURE;
    }
    let Some(name) = enabled_name() else {
        println!("[models] no third-party model is enabled; nothing to do.");
        return ExitCode::SUCCESS;
    };
    print!("Disable '{name}' and delete its weights? [y/N] ");
    let _ = std::io::stdout().flush();
    let mut yn = String::new();
    if std::io::stdin().lock().read_line(&mut yn).is_err()
        || !matches!(yn.trim(), "y" | "Y" | "yes")
    {
        println!("[models] cancelled; nothing was changed.");
        return ExitCode::FAILURE;
    }
    if let Some(m) = thirdparty::by_name(&name) {
        match std::fs::remove_file(thirdparty::model_path(m)) {
            Ok(()) | Err(_) => {} // absent is fine; the goal is "not on disk"
        }
    }
    let _ = std::fs::remove_dir(thirdparty::dir()); // only if now empty
    if let Err(e) = irlume_common::config::write_kv("settings.conf", thirdparty::SETTINGS_KEY, "") {
        eprintln!("[models] weights deleted but settings.conf update failed: {e}");
        return ExitCode::FAILURE;
    }
    restart_daemon();
    println!("[models] '{name}' disabled: weights deleted, daemon back on the shipped stack.");
    ExitCode::SUCCESS
}

fn restart_daemon() {
    let _ = Command::new("systemctl").arg("daemon-reload").status();
    let _ = Command::new("systemctl")
        .args(["try-restart", "irlumed.service"])
        .status();
}

fn is_root() -> bool {
    unsafe { libc::geteuid() == 0 }
}

fn stdin_is_tty() -> bool {
    unsafe { libc::isatty(0) == 1 }
}

/// One doctor line: which third-party model is enabled and whether its file
/// still matches the pin (unprivileged read of the file; the settings key may
/// be unreadable to a normal user, in which case the daemon log is the truth).
pub fn doctor_line() -> String {
    match enabled_name() {
        Some(name) => match thirdparty::by_name(&name) {
            Some(m) => format!("{name} enabled ({}; deny-only cue)", file_state(m)),
            None => format!(
                "{name} set in settings.conf but NOT in the catalog (ignored by the daemon)"
            ),
        },
        None => "none (default; see `irlume models`)".into(),
    }
}

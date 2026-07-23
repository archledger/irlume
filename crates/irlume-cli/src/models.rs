// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright the irlume contributors.

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

use crate::is_root;
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
pub(crate) fn enabled_name() -> Option<String> {
    irlume_common::config::read_kv("settings.conf", thirdparty::SETTINGS_KEY)
}

fn file_state(m: &ThirdPartyModel) -> &'static str {
    use thirdparty::WeightState::*;
    match thirdparty::weight_state(m) {
        ChecksumOk => "weights present, checksum ok",
        ChecksumMismatch => "weights present but CHECKSUM MISMATCH (daemon will refuse them)",
        Absent => "weights not fetched",
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
    let digest = thirdparty::sha256_hex(&bytes);
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

fn stdin_is_tty() -> bool {
    unsafe { libc::isatty(0) == 1 }
}

/// One doctor line: which third-party model is enabled and whether its file
/// still matches the pin. settings.conf is root-only, so an unprivileged
/// caller cannot read the enabled key; the weights file (0644) is readable,
/// so installed-but-unconfirmable gets reported instead of a false "none".
pub fn doctor_line() -> String {
    if let Some(name) = enabled_name() {
        return match thirdparty::by_name(&name) {
            Some(m) => format!("{name} enabled ({}; deny-only cue)", file_state(m)),
            None => format!(
                "{name} set in settings.conf but NOT in the catalog (ignored by the daemon)"
            ),
        };
    }
    if !is_root() {
        if let Some(m) = thirdparty::CATALOG
            .iter()
            .find(|m| thirdparty::model_path(m).exists())
        {
            return format!(
                "'{}' weights installed ({}); enabled state is root-only, check with `sudo irlume doctor` or the daemon startup log",
                m.name,
                file_state(m)
            );
        }
    }
    "none (default; see `irlume models`)".into()
}

#[cfg(test)]
mod tests {
    use super::*;

    /// doctor_line's classification: enabled name vs catalog membership vs
    /// weight state, all against sandboxed config/state dirs.
    #[test]
    fn doctor_line_reports_catalog_membership_and_weight_state() {
        let _guard = crate::testenv::ENV_LOCK
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        if is_root() {
            return; // the unprivileged branches are what is under test
        }
        let root = std::env::temp_dir().join(format!("irlume-models-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        let (cfg, state) = (root.join("cfg"), root.join("state"));
        std::fs::create_dir_all(&cfg).unwrap();
        std::fs::create_dir_all(&state).unwrap();
        let old_cfg = std::env::var_os("IRLUME_CONFIG_DIR");
        let old_state = std::env::var_os("IRLUME_STATE_DIR");
        std::env::set_var("IRLUME_CONFIG_DIR", &cfg);
        std::env::set_var("IRLUME_STATE_DIR", &state);

        // Nothing enabled, nothing on disk.
        assert!(
            doctor_line().starts_with("none (default"),
            "got: {}",
            doctor_line()
        );

        // Weights on disk but no readable enabled key: report the file without
        // claiming an enabled state the caller cannot confirm.
        let m = &thirdparty::CATALOG[0];
        std::fs::create_dir_all(thirdparty::dir()).unwrap();
        std::fs::write(thirdparty::model_path(m), b"garbage").unwrap();
        let line = doctor_line();
        assert!(line.contains("weights installed"), "got: {line}");
        assert!(line.contains("root-only"), "got: {line}");
        std::fs::remove_file(thirdparty::model_path(m)).unwrap();

        // An enabled name that is not in the catalog is called out.
        std::fs::write(cfg.join("settings.conf"), "third_party_pad=ghost\n").unwrap();
        assert!(
            doctor_line().contains("NOT in the catalog"),
            "got: {}",
            doctor_line()
        );

        // Enabled catalog model, weights never fetched.
        std::fs::write(
            cfg.join("settings.conf"),
            format!("third_party_pad={}\n", m.name),
        )
        .unwrap();
        assert_eq!(
            doctor_line(),
            format!("{} enabled (weights not fetched; deny-only cue)", m.name)
        );

        // Enabled with weights whose checksum no longer matches the pin.
        std::fs::write(thirdparty::model_path(m), b"garbage").unwrap();
        assert!(
            doctor_line().contains("CHECKSUM MISMATCH"),
            "got: {}",
            doctor_line()
        );

        match old_cfg {
            Some(v) => std::env::set_var("IRLUME_CONFIG_DIR", v),
            None => std::env::remove_var("IRLUME_CONFIG_DIR"),
        }
        match old_state {
            Some(v) => std::env::set_var("IRLUME_STATE_DIR", v),
            None => std::env::remove_var("IRLUME_STATE_DIR"),
        }
        let _ = std::fs::remove_dir_all(&root);
    }

    /// `enabled_name` reads the third-party key from settings.conf: absent file
    /// → None, a set key → its value. `file_state` classifies the weights file
    /// as absent vs checksum-mismatch (the on-disk states we can produce without
    /// the real pinned bytes).
    #[test]
    fn enabled_name_and_file_state_read_config_and_weights() {
        let _guard = crate::testenv::ENV_LOCK
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        let root = std::env::temp_dir().join(format!("irlume-models-cfg-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        let (cfg, state) = (root.join("cfg"), root.join("state"));
        std::fs::create_dir_all(&cfg).unwrap();
        std::fs::create_dir_all(&state).unwrap();
        let old_cfg = std::env::var_os("IRLUME_CONFIG_DIR");
        let old_state = std::env::var_os("IRLUME_STATE_DIR");
        std::env::set_var("IRLUME_CONFIG_DIR", &cfg);
        std::env::set_var("IRLUME_STATE_DIR", &state);

        // No settings.conf → nothing enabled.
        assert_eq!(enabled_name(), None);
        let m = &thirdparty::CATALOG[0];

        // The weights file is absent until fetched.
        assert_eq!(file_state(m), "weights not fetched");

        // Bytes that do not match the pinned sha256 classify as a mismatch.
        std::fs::create_dir_all(thirdparty::dir()).unwrap();
        std::fs::write(thirdparty::model_path(m), b"not the real weights").unwrap();
        assert!(file_state(m).contains("CHECKSUM MISMATCH"));
        std::fs::remove_file(thirdparty::model_path(m)).unwrap();

        // A set key is read back verbatim.
        std::fs::write(
            cfg.join("settings.conf"),
            format!("{}={}\n", thirdparty::SETTINGS_KEY, m.name),
        )
        .unwrap();
        assert_eq!(enabled_name().as_deref(), Some(m.name));

        match old_cfg {
            Some(v) => std::env::set_var("IRLUME_CONFIG_DIR", v),
            None => std::env::remove_var("IRLUME_CONFIG_DIR"),
        }
        match old_state {
            Some(v) => std::env::set_var("IRLUME_STATE_DIR", v),
            None => std::env::remove_var("IRLUME_STATE_DIR"),
        }
        let _ = std::fs::remove_dir_all(&root);
    }
}

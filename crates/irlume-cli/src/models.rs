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
        Some("add") => add(
            args.get(2).map(String::as_str),
            args.get(3).map(String::as_str),
        ),
        Some("disable") => disable(),
        _ => usage(),
    }
}

fn usage() -> ExitCode {
    eprintln!("usage: irlume models [list]");
    eprintln!("       sudo irlume models enable <name>          (irlume fetches it)");
    eprintln!("       sudo irlume models add <name> <path>      (you supply the file)");
    eprintln!("       sudo irlume models disable");
    ExitCode::from(2)
}

/// Install a model from a file the USER obtained, verified against the pin
/// irlume measured.
///
/// This is the whole point of the two tiers: irlume will not fetch a model
/// whose licence makes that the user's decision, but it still knows exactly
/// which artifact it measured. A file that hashes to the catalog's `sha256` is
/// that artifact and gets its measured threshold; anything else is refused,
/// because scoring an unknown model against another model's threshold is the
/// guess this catalog exists to prevent.
fn add(name: Option<&str>, path: Option<&str>) -> ExitCode {
    let (Some(name), Some(path)) = (name, path) else {
        return usage();
    };
    let Some(m) = thirdparty::by_name(name) else {
        eprintln!("[models] '{name}' is not in the catalog; run `irlume models` to list it");
        return ExitCode::FAILURE;
    };
    // Refused again at the installer choke point; this early copy exists so
    // the user learns before reading a file that the answer is no.
    if !m.stage.open() {
        eprintln!(
            "[models] '{}' is a {} model, and the {} stage is not open to third-party \
             models yet (#276); nothing was changed",
            m.name,
            m.stage.as_str(),
            m.stage.as_str()
        );
        return ExitCode::FAILURE;
    }
    if !is_root() {
        eprintln!("[models] needs root: sudo irlume models add {name} {path}");
        return ExitCode::FAILURE;
    }
    let bytes = match std::fs::read(path) {
        Ok(b) => b,
        Err(e) => {
            eprintln!("[models] cannot read {path}: {e}");
            return ExitCode::FAILURE;
        }
    };
    let digest = thirdparty::sha256_hex(&bytes);
    if digest != m.sha256 {
        eprintln!("[models] this file is NOT the artifact irlume measured.");
        eprintln!("[models]   got      sha256 {digest}");
        eprintln!("[models]   expected sha256 {}", m.sha256);
        eprintln!(
            "[models] refusing: irlume's threshold for '{}' was measured on the expected\n\
             [models] artifact, and applying it to different weights would be a guess.",
            m.name
        );
        return ExitCode::FAILURE;
    }
    println!("Adding third-party model '{}' from {path}", m.name);
    println!();
    println!("  license:    {}", m.license);
    println!("  provenance: {}", m.provenance);
    println!("  measured:   {}", m.summary);
    println!("  effect:     adds a DENY-ONLY liveness cue on the lit IR frame; it can");
    println!("              reject a presentation, it can never approve one the built-in");
    println!("              gate rejected. False fires cost a retry or the password.");
    println!();
    println!("  sha256 matches the artifact irlume measured. Complying with the license");
    println!("  above, for your use, is your determination and not irlume's.");
    println!();
    if !stdin_is_tty() {
        eprintln!("[models] enabling needs an interactive terminal to confirm the license");
        return ExitCode::FAILURE;
    }
    print!("Enable '{}'? [y/N] ", m.name);
    let _ = std::io::stdout().flush();
    let mut yn = String::new();
    if std::io::stdin().lock().read_line(&mut yn).is_err()
        || !matches!(yn.trim(), "y" | "Y" | "yes")
    {
        println!("[models] cancelled; nothing was changed.");
        return ExitCode::FAILURE;
    }
    install_verified(m, &bytes)
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
    println!("Third-party models irlume has MEASURED but does not ship or warrant.");
    println!("Nothing is listed here that was not measured on real hardware");
    println!("(docs/pad-results/, docs/THIRD-PARTY-MODELS.md).");
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
            "    stage:      {}{}",
            m.stage.as_str(),
            if m.stage.open() {
                ""
            } else {
                " (NOT OPEN to third-party models yet, #276)"
            }
        );
        println!(
            "    role:       deny-only liveness cue, threshold {}",
            m.threshold
        );
        println!("    measured:   {}", m.summary);
        println!(
            "    obtain:     {}",
            match m.url {
                Some(_) => format!("irlume fetches it: sudo irlume models enable {}", m.name),
                None => format!(
                    "you supply the file: sudo irlume models add {} <path>",
                    m.name
                ),
            }
        );
    }
    println!();
    match enabled {
        Some(n) => println!("enabled: {n} · disable with: sudo irlume models disable"),
        None => println!("none enabled · see the 'obtain' line above for each model"),
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
    // Refused again at the installer choke point; early copy for the message.
    if !m.stage.open() {
        eprintln!(
            "[models] '{}' is a {} model, and the {} stage is not open to third-party \
             models yet (#276); nothing was changed",
            m.name,
            m.stage.as_str(),
            m.stage.as_str()
        );
        return ExitCode::FAILURE;
    }
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

    if m.url.is_none() {
        println!(
            "[models] '{}' is measured by irlume but not fetched by it: its license makes\n\
             [models] obtaining the file your decision. See docs/THIRD-PARTY-MODELS.md, then:\n\
             [models]   sudo irlume models add {} <path-to-{}>",
            m.name, m.name, m.file
        );
        return ExitCode::FAILURE;
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

    fetch_and_enable(m)
}

/// Download, checksum-verify and enable `m`, restarting the daemon.
///
/// Split out of [`enable`] so `irlume setup` can offer the model without
/// duplicating the download or, worse, reimplementing the pin check: the
/// catalog's sha256 is the only thing standing between a user and unpinned
/// third-party weights, so exactly one code path may install them.
///
/// The CONSENT is the caller's to obtain, and the two callers ask differently
/// on purpose. `models enable` makes the user type the model name, because
/// someone reaching for that command may not have read anything. Setup shows
/// the same license and provenance and accepts a default-yes answer, because
/// it has just told them a printed photograph defeats the built-in gate and
/// the decision is in front of them.
pub(crate) fn fetch_and_enable(m: &thirdparty::ThirdPartyModel) -> ExitCode {
    let dir = thirdparty::dir();
    if let Err(e) = std::fs::create_dir_all(&dir) {
        eprintln!("[models] could not create {}: {e}", dir.display());
        return ExitCode::FAILURE;
    }
    let Some(url) = m.url else {
        // Reached only if a caller forgets the check at the call site; the
        // catalog says this model is not irlume's to fetch.
        eprintln!(
            "[models] '{}' is not fetchable by irlume; obtain the file yourself, then:\n\
             [models]   sudo irlume models add {} <path>",
            m.name, m.name
        );
        return ExitCode::FAILURE;
    };
    let tmp = dir.join(format!(".{}.part", m.file));
    println!("[models] downloading from the publisher's origin ...");
    let status = Command::new("curl")
        .args(["-fSL", "--max-time", "300", "-o"])
        .arg(&tmp)
        .arg(url)
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
    let _ = std::fs::remove_file(&tmp);
    install_verified(m, &bytes)
}

/// Are these the exact weights irlume measured?
///
/// A value rather than an inline comparison so the refusal is testable: this
/// is the only thing standing between a user and a threshold applied to
/// weights it was never measured on.
fn pin_matches(m: &ThirdPartyModel, bytes: &[u8]) -> bool {
    thirdparty::sha256_hex(bytes) == m.sha256
}

/// Write already-verified `bytes` into place and enable the cue.
///
/// The single installer for both tiers. Callers must have checked the sha256
/// first; this re-states that in one place so a future third caller cannot
/// install unpinned weights by forgetting the check.
fn install_verified(m: &ThirdPartyModel, bytes: &[u8]) -> ExitCode {
    if !place_verified(m, bytes) {
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

/// The disk half of an install: verify the pin, place the weights atomically,
/// record the choice. Split from the daemon restart so a test can exercise the
/// pin against a real writable directory without restarting a service, which
/// is what a test of the refusal needs: refusing because the directory is
/// unwritable proves nothing about the pin.
fn place_verified(m: &ThirdPartyModel, bytes: &[u8]) -> bool {
    // The stage gate (#276): stages open to third-party models one at a time,
    // and this is the choke point every install goes through, so a catalog
    // entry for a stage whose wiring does not exist yet cannot be placed on
    // disk no matter which command reached here.
    if !m.stage.open() {
        eprintln!(
            "[models] '{}' is a {} model, and the {} stage is not open to \
             third-party models yet (#276); nothing was installed",
            m.name,
            m.stage.as_str(),
            m.stage.as_str()
        );
        return false;
    }
    if !pin_matches(m, bytes) {
        eprintln!(
            "[models] refusing to install unpinned weights for '{}'",
            m.name
        );
        return false;
    }
    let dir = thirdparty::dir();
    if let Err(e) = std::fs::create_dir_all(&dir) {
        eprintln!("[models] could not create {}: {e}", dir.display());
        return false;
    }
    let path = thirdparty::model_path(m);
    // Atomic replace, never a truncating write. settings.conf keeps naming
    // this model, so a half-written file is not a failed update: it is a
    // checksum mismatch the daemon answers by running WITHOUT the cue, and
    // the built-in gate that remains accepts the print attack. A rename
    // either publishes the whole artifact or leaves the previous one intact.
    if let Err(e) = irlume_common::write_atomic_mode(&path, bytes, 0o644) {
        eprintln!("[models] could not install {}: {e}", path.display());
        return false;
    }
    if let Err(e) =
        irlume_common::config::write_kv("settings.conf", thirdparty::SETTINGS_KEY, m.name)
    {
        eprintln!("[models] weights installed but settings.conf update failed: {e}");
        return false;
    }
    true
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
/// Condensed third-party-model state for a TUI status row, so it can show a
/// ●/○ icon like the other Settings sections instead of a bare text blob.
pub(crate) enum TuiState {
    /// A catalog model is enabled in settings.conf; carries its name and the
    /// weight health (checksum ok / mismatch).
    Enabled { name: String, detail: String },
    /// Weights are installed but the enabled flag is root-only and we are not
    /// root, so we can report presence but not the on/off state.
    InstalledUnknown { name: String },
    /// No third-party model enabled (the default).
    None,
}

pub(crate) fn tui_state() -> TuiState {
    if let Some(name) = enabled_name() {
        let detail = match thirdparty::by_name(&name) {
            Some(m) => format!("deny-only cue · {}", file_state(m)),
            None => "set in settings.conf but NOT in the catalog (daemon ignores it)".into(),
        };
        return TuiState::Enabled { name, detail };
    }
    if !is_root() {
        if let Some(m) = thirdparty::CATALOG
            .iter()
            .find(|m| thirdparty::model_path(m).exists())
        {
            return TuiState::InstalledUnknown {
                name: m.name.to_string(),
            };
        }
    }
    TuiState::None
}

/// One pipeline stage's model status: what would run, where it came from, and
/// whether the stage is open to third-party models. One builder serves the
/// human doctor and the machine API so the two cannot disagree (#276).
pub(crate) struct StageStatus {
    /// Stage name, machine-API vocabulary ([`irlume_common::thirdparty::Stage::as_str`]).
    pub stage: &'static str,
    /// Whether the stage accepts third-party models today.
    pub open: bool,
    /// The shipped model file this stage runs, `None` for the PAD stage whose
    /// built-in gate is code, not a swappable file.
    pub file: Option<&'static str>,
    /// Resolved path and its origin (`"shipped"` / `"env-override"`); `None`
    /// when the file was not found anywhere the daemon looks.
    pub resolved: Option<(std::path::PathBuf, &'static str)>,
    /// Whether the daemon refuses to start without this file.
    pub required: bool,
}

/// The pipeline stages in order, with what each would load.
///
/// The blaze rescue detector and the IR adapter are deliberately absent: they
/// are auxiliaries of the detection and recognition stages, not stages of
/// their own, and the BYO plan (#276) opens stages, not files.
pub(crate) fn stage_statuses() -> Vec<StageStatus> {
    use irlume_common::thirdparty::Stage;
    let shipped = [
        (
            Stage::Detection,
            "face_detection_yunet_2023mar.onnx",
            "IRLUME_DET_MODEL",
            true,
        ),
        (
            Stage::Landmarks,
            "face_landmark.onnx",
            "IRLUME_MESH_MODEL",
            false,
        ),
        (Stage::Recognition, "glintr100.onnx", "IRLUME_MODEL", true),
    ];
    let mut out: Vec<StageStatus> = shipped
        .into_iter()
        .map(|(stage, file, env, required)| StageStatus {
            stage: stage.as_str(),
            open: stage.open(),
            file: Some(file),
            resolved: crate::commands::resolve_model_origin(file, env),
            required,
        })
        .collect();
    out.push(StageStatus {
        stage: Stage::Pad.as_str(),
        open: Stage::Pad.open(),
        file: None,
        resolved: None,
        required: false,
    });
    out
}

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
    // Named as a gap rather than a neutral default. The built-in gate does not
    // stop a life-size print: measured 2026-06-30 and again 2026-08-02, an
    // angled vinyl print of the enrolled face reads a centre/edge ratio above
    // the genuine range, so no threshold separates them and the gate accepts
    // it. This cue denied the same print at p_fake 0.999 and above. A user
    // reading `doctor` should learn that from the line, not from an issue.
    "none — RECOMMENDED: `sudo irlume models enable flir`. Without it the \
     built-in gate is the only anti-spoof layer, and it does not stop a \
     life-size print of your face (docs/PAD_SELFTEST.md)"
        .into()
}

#[cfg(test)]
mod tests {

    /// A synthetic bring-your-own entry. The catalog has no such model yet, so
    /// the tier the code must handle would otherwise be untested until one is
    /// measured, which is exactly when a regression would be discovered.
    fn byo_fixture() -> ThirdPartyModel {
        ThirdPartyModel {
            name: "fixture-byo",
            stage: irlume_common::thirdparty::Stage::Pad,
            file: "fixture-byo.onnx",
            url: None,
            sha256: "0000000000000000000000000000000000000000000000000000000000000000",
            license: "fixture",
            provenance: "fixture",
            threshold: 0.9,
            summary: "fixture",
        }
    }

    #[test]
    fn every_catalog_entry_carries_a_pin_and_only_fetchable_ones_carry_an_origin() {
        for m in thirdparty::CATALOG {
            if let Some(u) = m.url {
                assert!(
                    u.starts_with("https://"),
                    "{}: origin must be https",
                    m.name
                );
            }
            // Both tiers: the pin is how irlume knows WHICH model is loaded
            // rather than trusting the file that appeared in the directory.
            assert_eq!(m.sha256.len(), 64, "{}: every tier needs a pin", m.name);
        }
        // And the bring-your-own tier itself, which no catalog entry exercises
        // today: it must be pinned like any other and must have no origin.
        let byo = byo_fixture();
        assert!(byo.url.is_none());
        assert_eq!(byo.sha256.len(), 64);
    }

    #[test]
    fn the_installer_refuses_a_closed_stage_even_with_a_matching_pin() {
        // The stage gate (#276): a catalog entry for a stage whose wiring does
        // not exist must not be installable, however correct its bytes. Runs
        // in a sandboxed state dir so the refusal can only come from the gate,
        // and the same bytes install under an OPEN stage as the control that
        // proves which check refused.
        let _guard = crate::testenv::ENV_LOCK
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        let root = std::env::temp_dir().join(format!("irlume-stage-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        let (cfg, state) = (root.join("cfg"), root.join("state"));
        std::fs::create_dir_all(&cfg).unwrap();
        std::fs::create_dir_all(&state).unwrap();
        let old_cfg = std::env::var_os("IRLUME_CONFIG_DIR");
        let old_state = std::env::var_os("IRLUME_STATE_DIR");
        std::env::set_var("IRLUME_CONFIG_DIR", &cfg);
        std::env::set_var("IRLUME_STATE_DIR", &state);

        let bytes = b"the measured artifact";
        const SHA: &str = "b9a5820dd4ae8eb1eb7025b3b9b1351d9ff90e658e0c1d22a027e55be4f6f48e";
        assert_eq!(thirdparty::sha256_hex(bytes), SHA);
        let mut closed = byo_fixture();
        closed.name = "fixture-closed";
        closed.file = "fixture-closed.onnx";
        closed.stage = irlume_common::thirdparty::Stage::Recognition;
        closed.sha256 = SHA;
        let refused = place_verified(&closed, bytes);
        let nothing_written = !thirdparty::model_path(&closed).exists();

        let mut open = closed;
        open.stage = irlume_common::thirdparty::Stage::Pad;
        let accepted = place_verified(&open, bytes);
        let written = thirdparty::model_path(&open).exists();

        match (old_cfg, old_state) {
            (Some(c), Some(st)) => {
                std::env::set_var("IRLUME_CONFIG_DIR", c);
                std::env::set_var("IRLUME_STATE_DIR", st);
            }
            _ => {
                std::env::remove_var("IRLUME_CONFIG_DIR");
                std::env::remove_var("IRLUME_STATE_DIR");
            }
        }
        let _ = std::fs::remove_dir_all(&root);

        assert!(!refused, "a closed-stage entry must not install");
        assert!(
            nothing_written,
            "a refused closed-stage install must leave nothing behind"
        );
        assert!(
            accepted,
            "the same bytes must install under an open stage, or the refusal \
             above proves nothing about the stage gate"
        );
        assert!(written, "the open-stage control must actually reach disk");
    }

    #[test]
    fn stage_statuses_resolve_with_an_honest_origin() {
        // The env var the daemon honors must label the resolution
        // "env-override", and its absence must fall to the shipped search;
        // the per-stage report keys the origin column off this.
        let _guard = crate::testenv::ENV_LOCK
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        let dir = std::env::temp_dir().join(format!("irlume-origin-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let file = dir.join("det-override.onnx");
        std::fs::write(&file, b"weights").unwrap();
        let old = std::env::var_os("IRLUME_DET_MODEL");
        std::env::set_var("IRLUME_DET_MODEL", &file);

        let with_env = crate::commands::resolve_model_origin(
            "face_detection_yunet_2023mar.onnx",
            "IRLUME_DET_MODEL",
        );
        std::env::remove_var("IRLUME_DET_MODEL");
        let without_env = crate::commands::resolve_model_origin(
            "face_detection_yunet_2023mar.onnx",
            "IRLUME_DET_MODEL",
        );

        if let Some(v) = old {
            std::env::set_var("IRLUME_DET_MODEL", v);
        }
        let _ = std::fs::remove_dir_all(&dir);

        assert_eq!(with_env, Some((file, "env-override")));
        // Without the env var the answer depends on whether this machine has
        // the packaged or repo models; when it resolves, it must not claim an
        // override that was not set.
        if let Some((_, origin)) = without_env {
            assert_eq!(origin, "shipped");
        }
        // The four stages, in pipeline order, exactly one open (pad).
        let stages = stage_statuses();
        let names: Vec<&str> = stages.iter().map(|s| s.stage).collect();
        assert_eq!(names, ["detection", "landmarks", "recognition", "pad"]);
        assert_eq!(
            stages
                .iter()
                .filter(|s| s.open)
                .map(|s| s.stage)
                .collect::<Vec<_>>(),
            ["pad"]
        );
    }

    #[test]
    fn fetching_a_bring_your_own_model_is_refused_before_any_download() {
        // The tier's whole point: irlume must not download a model whose
        // licence made obtaining it the user's decision. `fetch_and_enable`
        // guards this even though the call sites check first, because a
        // future caller will not.
        let byo = byo_fixture();
        assert!(
            !matches!(fetch_and_enable(&byo), c if format!("{c:?}") == format!("{:?}", ExitCode::SUCCESS)),
            "a urlless model must never reach the downloader"
        );
    }

    #[test]
    fn the_installer_refuses_bytes_that_do_not_match_the_pin() {
        // Sandboxed state dir, so the WRITE would genuinely succeed and the
        // pin is the only thing that can refuse. Without this the test passes
        // for the wrong reason: an unprivileged process cannot write to the
        // real state dir, so it returns FAILURE whether the guard exists or
        // not, and a mutant deleting the guard survives.
        let _guard = crate::testenv::ENV_LOCK
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        let root = std::env::temp_dir().join(format!("irlume-pin-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        let (cfg, state) = (root.join("cfg"), root.join("state"));
        std::fs::create_dir_all(&cfg).unwrap();
        std::fs::create_dir_all(&state).unwrap();
        let old_cfg = std::env::var_os("IRLUME_CONFIG_DIR");
        let old_state = std::env::var_os("IRLUME_STATE_DIR");
        std::env::set_var("IRLUME_CONFIG_DIR", &cfg);
        std::env::set_var("IRLUME_STATE_DIR", &state);

        let m = byo_fixture();
        let path = thirdparty::model_path(&m);
        assert!(!pin_matches(&m, b"not the model"));
        let refused = place_verified(&m, b"not the model");
        let nothing_written = !path.exists();
        // The control: the same call with MATCHING bytes must install, which
        // is what proves the refusal above came from the pin and not from an
        // unwritable directory.
        // Precomputed rather than Box::leak'd into a &'static str: leaking to
        // satisfy a lifetime is a real leak, and LeakSanitizer is right to
        // report it. The constant is asserted against the hasher below, so a
        // change to either is caught rather than silently diverging.
        let good = b"the measured artifact";
        const GOOD_SHA: &str = "b9a5820dd4ae8eb1eb7025b3b9b1351d9ff90e658e0c1d22a027e55be4f6f48e";
        assert_eq!(
            thirdparty::sha256_hex(good),
            GOOD_SHA,
            "the fixture's precomputed digest no longer matches the hasher"
        );
        let mut ok = m;
        ok.sha256 = GOOD_SHA;
        let accepted = place_verified(&ok, good);
        let written = thirdparty::model_path(&ok).exists();

        match (old_cfg, old_state) {
            (Some(c), Some(st)) => {
                std::env::set_var("IRLUME_CONFIG_DIR", c);
                std::env::set_var("IRLUME_STATE_DIR", st);
            }
            _ => {
                std::env::remove_var("IRLUME_CONFIG_DIR");
                std::env::remove_var("IRLUME_STATE_DIR");
            }
        }
        let _ = std::fs::remove_dir_all(&root);

        assert!(!refused, "unpinned bytes must not install");
        assert!(
            nothing_written,
            "a refused install must leave nothing behind"
        );
        assert!(
            accepted,
            "matching bytes must install, or the refusal above proves nothing"
        );
        assert!(written, "the control install must actually reach disk");
    }
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

        // Nothing enabled, nothing on disk. The line must name the absence AND
        // what it costs: reported as a bare default it reads as a setting the
        // user has already made, which is how a machine ends up with no defence
        // against a printed face and nothing saying so.
        let none_line = doctor_line();
        assert!(none_line.starts_with("none"), "got: {none_line}");
        assert!(
            none_line.contains("models enable flir") && none_line.contains("life-size print"),
            "got: {none_line}"
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

        // tui_state mirrors the same config: an enabled name -> Enabled row.
        match tui_state() {
            TuiState::Enabled { name, .. } => assert_eq!(name, m.name),
            _ => panic!("expected Enabled after setting the config key"),
        }

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

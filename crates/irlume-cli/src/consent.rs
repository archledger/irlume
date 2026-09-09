// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright the irlume contributors.

//! Machine-owner control of the existing privileged PAM intent policy.
//! This command changes no PAM wiring and starts no authentication attempt.

use irlume_common::config;
use std::process::ExitCode;

pub(crate) const OVERRIDE: &str = "IRLUME_PRIVILEGED_FACE_CONSENT";
pub(crate) const SCOPE: &str =
    "Applies machine-wide to configured privileged prompts, including sudo and polkit.";
pub(crate) const WARNING: &str = "A prompt raised by an app, script or another person can authenticate while you are in view. Face matching, anti-spoofing and password fallback stay in place.";

pub(crate) fn state_label(required: Option<bool>) -> &'static str {
    match required {
        Some(true) => "confirmation required (default)",
        Some(false) => "hands-free (owner opt-in)",
        None => "unknown: cannot read settings; confirmation remains required",
    }
}

pub(crate) fn overridden() -> bool {
    std::env::var_os(OVERRIDE).is_some()
}

pub(crate) fn run(args: &[String]) -> ExitCode {
    let required = match args {
        [] => None,
        [status] if status == "status" => None,
        [mode] if mode == "required" => Some(true),
        [mode] if mode == "hands-free" => {
            eprintln!("[consent] {SCOPE}\n{WARNING}\nTo accept: sudo irlume auth consent hands-free --yes");
            return ExitCode::from(2);
        }
        [mode, yes] if mode == "hands-free" && yes == "--yes" => Some(false),
        _ => {
            eprintln!("[consent] usage: irlume auth consent <status|required|hands-free --yes>");
            return ExitCode::from(2);
        }
    };
    let Some(required) = required else {
        println!(
            "[consent] privileged face authentication: {}",
            state_label(config::privileged_face_consent_visible())
        );
        println!("{SCOPE}");
        if overridden() {
            println!("Local environment override: {OVERRIDE}; the daemon may have a different environment.");
        }
        println!("Login and lock-screen start behavior is configured separately.");
        return ExitCode::SUCCESS;
    };
    // Do not claim the new file value changed a policy hidden by an override.
    if overridden() {
        eprintln!("[consent] environment override {OVERRIDE} is set; remove it before changing the saved setting.");
        return ExitCode::FAILURE;
    }
    if !crate::is_root() {
        eprintln!(
            "[consent] needs root: run sudo irlume auth consent {}",
            if required {
                "required"
            } else {
                "hands-free --yes"
            }
        );
        return ExitCode::FAILURE;
    }
    let update = || -> std::io::Result<()> {
        let _lock = config::lock_exclusive("settings.conf")?;
        // write_kv preserves unrelated values, but its legacy read-error
        // fallback is empty content. Never use that fallback for this control.
        if let config::KvObservation::Unknown(error) =
            config::observe_kv("settings.conf", "privileged_face_consent")
        {
            return Err(error);
        }
        config::write_kv(
            "settings.conf",
            "privileged_face_consent",
            if required { "1" } else { "0" },
        )
    };
    if let Err(error) = update() {
        eprintln!("[consent] could not update settings.conf: {error}");
        return ExitCode::FAILURE;
    }
    println!(
        "[consent] saved privileged face authentication: {}",
        state_label(Some(required))
    );
    println!("{SCOPE} Takes effect on subsequent attempts unless overridden in the PAM or daemon environment.");
    if !required {
        println!("{WARNING}");
    }
    ExitCode::SUCCESS
}

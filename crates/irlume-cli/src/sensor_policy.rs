// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright the irlume contributors.

//! Explicit owner selection and camera-free observation of face sensors.

use irlume_common::config::{
    self, FaceSensorPolicy as Policy, FaceSensorPolicyObservation as State,
};
use irlume_common::{Request, Response};
use std::process::ExitCode;

pub(crate) const WARNING: &str = "EXPERIMENTAL: IR-only omits RGB and cross-spectrum evidence. It is not qualified for authentication assurance. Missing prerequisites use password fallback; no silent RGB fallback is permitted.";

pub(crate) fn state_label(state: State) -> &'static str {
    match state {
        State::DefaultDual => "dual (default)",
        State::Explicit(Policy::Dual) => "dual (explicit)",
        State::Explicit(Policy::IrOnlyExperimental) => {
            "EXPERIMENTAL IR-only (owner opt-in; not qualified)"
        }
        State::Invalid => "invalid sensor policy; face must remain unavailable",
        State::Unreadable => "unreadable sensor policy; state unknown",
    }
}

pub(crate) fn local_status_line() -> String {
    format!(
        "local saved: {}",
        state_label(config::observe_face_sensor_policy())
    )
}

pub(crate) fn status_line() -> String {
    match irlume_common::client::request_poll(&Request::FaceSensorStatus { user: None }) {
        Ok(Response::FaceSensorStatus { policy, .. }) => {
            format!("daemon observed: {}", state_label(policy))
        }
        _ => format!("{}; daemon sensor policy unavailable", local_status_line()),
    }
}

pub(crate) fn run(args: &[String]) -> ExitCode {
    let selected = match args {
        [] => None,
        [status] if status == "status" => None,
        [mode] if mode == "dual" => Some(Policy::Dual),
        [mode] if mode == "ir-only" => {
            eprintln!("[sensor] {WARNING}\nTo accept: sudo irlume auth sensor ir-only --yes");
            return ExitCode::from(2);
        }
        [mode, yes] if mode == "ir-only" && yes == "--yes" => Some(Policy::IrOnlyExperimental),
        [preflight] if preflight == "preflight" => return preflight_for(crate::user_arg(&[])),
        [preflight, flag, user]
            if preflight == "preflight" && flag == "--user" && valid_user(user) =>
        {
            return preflight_for(user.clone())
        }
        [preflight, flag]
            if preflight == "preflight" && flag.strip_prefix("--user=").is_some_and(valid_user) =>
        {
            return preflight_for(flag[7..].into())
        }
        [preflight, user] if preflight == "preflight" && valid_user(user) => {
            return preflight_for(user.clone())
        }
        _ => {
            eprintln!(
                "[sensor] usage: irlume auth sensor <status|preflight [--user U]|dual|ir-only --yes>"
            );
            return ExitCode::from(2);
        }
    };
    let Some(selected) = selected else {
        println!("[sensor] {}", status_line());
        println!("Sensor policy is separate from dual-camera scheduling, PAM wiring and per-attempt consent. Use `irlume auth sensor preflight` to check prerequisites.");
        return ExitCode::SUCCESS;
    };
    if !crate::is_root() {
        eprintln!("[sensor] changing the machine-wide sensor policy requires root");
        return ExitCode::FAILURE;
    }
    let update = || -> std::io::Result<()> {
        let _lock = config::lock_exclusive("settings.conf")?;
        if matches!(
            config::observe_face_sensor_policy(),
            State::Unreadable | State::Invalid
        ) {
            return Err(std::io::Error::other("settings cannot be safely updated"));
        }
        config::write_kv(
            "settings.conf",
            "face_sensor_policy",
            match selected {
                Policy::Dual => "dual",
                Policy::IrOnlyExperimental => "ir-only-experimental",
            },
        )
    };
    if update().is_err() {
        eprintln!("[sensor] could not update settings.conf; inspect unreadable or invalid settings before changing the policy");
        return ExitCode::FAILURE;
    }
    println!("[sensor] saved: {}", state_label(State::Explicit(selected)));
    println!("Readiness is not established. Check `irlume auth sensor preflight`; face may fall back to password. PAM wiring, camera scheduling and consent settings are unchanged.");
    if selected == Policy::IrOnlyExperimental {
        println!("{WARNING}");
    }
    ExitCode::SUCCESS
}

fn valid_user(user: &str) -> bool {
    !user.is_empty() && !user.starts_with('-') && !user.chars().any(char::is_control)
}

fn preflight_for(user: String) -> ExitCode {
    match crate::daemon_request(&Request::FaceSensorStatus { user: Some(user) }) {
        Ok(Response::FaceSensorStatus {
            policy,
            ir_readiness: Some(readiness),
        }) => {
            println!("[sensor] daemon observed: {}", state_label(policy));
            match policy.resolve() {
                Ok(Policy::IrOnlyExperimental) => {}
                Ok(Policy::Dual) => {
                    eprintln!("[sensor] experimental IR-only preflight unavailable: IR-only is not selected. Dual-camera authentication remains selected; use your password if face authentication is unavailable.");
                    return ExitCode::FAILURE;
                }
                Err(_) => {
                    eprintln!("[sensor] sensor policy is invalid or unreadable; inspect settings.conf and use your password");
                    return ExitCode::FAILURE;
                }
            }
            use irlume_common::IrOnlyReadiness as Readiness;
            let refusal = match readiness {
                Readiness::ReadyForExperimentalAttempt => {
                    println!("[sensor] EXPERIMENTAL IR-only prerequisites are ready for an attempt. This does not prove capture success or a usable login and is not qualified for authentication assurance; the service deadline still applies.");
                    return ExitCode::SUCCESS;
                }
                Readiness::Unavailable => {
                    "experimental IR-only preflight unavailable; check the daemon and use your password"
                }
                Readiness::InvalidPolicy => {
                    "sensor policy is invalid; inspect and select dual or IR-only again, then use your password"
                }
                Readiness::TargetUnavailable => {
                    "configured IR target is unavailable or unsupported; configure a supported IR target and use your password"
                }
                Readiness::BindingUnavailable => {
                    "IR enrollment has no camera binding; add fresh scans with the configured camera and use your password"
                }
                Readiness::BindingMismatch => {
                    "enrollment belongs to a different IR camera; use the enrolled camera or add fresh scans, then use your password"
                }
                Readiness::ModelsUnavailable => {
                    "required face models are unavailable; repair the installed models, restart the daemon, and use your password"
                }
                Readiness::PadUnavailable => {
                    "required IR anti-spoofing is unavailable; repair the IR PAD model, restart the daemon, and use your password"
                }
                Readiness::EnrollmentUnavailable => {
                    "face enrollment is unavailable; enroll or restore the protected enrollment, then use your password"
                }
                Readiness::IncompatibleEnrollment => {
                    "no compatible IR scans are enrolled; add fresh scans with the current setup, then use your password"
                }
            };
            eprintln!("[sensor] {refusal}");
        }
        _ => eprintln!(
            "[sensor] daemon could not establish experimental IR-only readiness; use your password"
        ),
    }
    ExitCode::FAILURE
}

// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright the irlume contributors.

//! Explicit owner selection and camera-free observation of face sensors.

use irlume_common::config::{
    self, FaceSensorPolicy as Policy, FaceSensorPolicyObservation as State,
};
use irlume_common::{Request, Response};
use std::process::ExitCode;

pub(crate) const WARNING: &str = "EXPERIMENTAL: IR-only omits RGB and cross-spectrum evidence. It is not qualified for authentication assurance. Missing prerequisites use password fallback; no silent RGB fallback is permitted.";

pub(crate) const PAIRED_SUPPORT_NOTE: &str = "Paired camera support does not establish experimental IR-only readiness; check `irlume auth sensor preflight`.";

fn target_issue_message(issue: Option<irlume_common::IrTargetIssue>) -> &'static str {
    use irlume_common::IrTargetIssue as Issue;
    match issue {
        Some(Issue::Unconfigured) => "no explicit RGB and IR camera pair is configured; persist your verified pair with `sudo irlume set-cameras <RGB> <IR>`, then rerun preflight. Use your password until ready",
        Some(Issue::UnsupportedTopology) => "the configured camera layout is unsupported by experimental IR-only; changing the saved pair cannot make an unsupported layout compatible. Paired-camera support is a separate capability; use your password",
        Some(Issue::Unavailable) => "a configured camera endpoint is missing, unreadable, or unavailable; check the connection and saved pair, then rerun preflight and use your password",
        Some(Issue::BindingUnavailable) => "the configured IR camera identity could not be established from device metadata; check the device and configuration, then rerun preflight and use your password",
        Some(Issue::Changed) => "the configured IR target changed during validation; check the connection and saved pair, rerun preflight, and use your password",
        Some(Issue::Unknown) | None => "configured IR target is unavailable or unsupported; configure a supported IR target and use your password",
    }
}

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

/// The scope line: the enrollment the configured pair resolved to, with
/// an added camera's position in the store (an ordinal, never an identity).
fn scope_label(scope: irlume_common::IrScope, index: Option<usize>) -> String {
    match (scope, index) {
        (irlume_common::IrScope::Primary, _) => "scope: primary enrollment".into(),
        (irlume_common::IrScope::Secondary, Some(index)) => {
            format!("scope: added camera #{index}")
        }
        (irlume_common::IrScope::Secondary, None) => "scope: added camera".into(),
        (irlume_common::IrScope::Unknown, _) => "scope: unknown to this client".into(),
    }
}

fn valid_user(user: &str) -> bool {
    !user.is_empty() && !user.starts_with('-') && !user.chars().any(char::is_control)
}

fn preflight_for(user: String) -> ExitCode {
    match crate::daemon_request(&Request::FaceSensorStatus { user: Some(user) }) {
        Ok(Response::FaceSensorStatus {
            policy,
            ir_readiness: Some(compatible),
            ir_target_issue,
            ir_readiness_detail,
            ir_scope,
            ir_scope_index,
        }) => {
            // A new daemon sends the precise cause beside the compatible
            // value; an older one sends only the latter (ADR-0028 §3).
            let readiness = ir_readiness_detail.unwrap_or(compatible);
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
            if ir_target_issue.is_some() && readiness != Readiness::TargetUnavailable {
                eprintln!("[sensor] daemon returned inconsistent target readiness; rerun preflight and use your password");
                return ExitCode::FAILURE;
            }
            if let Some(scope) = ir_scope {
                println!("[sensor] {}", scope_label(scope, ir_scope_index));
            }
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
                    target_issue_message(ir_target_issue)
                }
                Readiness::BindingUnavailable => {
                    "IR enrollment has no camera binding; add fresh scans with the configured camera and use your password"
                }
                Readiness::BindingMismatch => {
                    "the configured cameras are neither the enrolled pair nor an added camera; use an enrolled camera or add this one, then use your password"
                }
                Readiness::SecondaryInactive => {
                    "this camera's authorization is inactive since the primary enrollment changed; remove your added cameras and add back the ones you use, then use your password"
                }
                Readiness::SecondaryUnvalidated => {
                    "IR-only on additional cameras is not yet validated on this build; use your password"
                }
                Readiness::Unknown => {
                    "the daemon reported a readiness this client does not know; update the client and use your password"
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

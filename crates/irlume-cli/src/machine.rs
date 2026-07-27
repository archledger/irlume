// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright the irlume contributors.

//! Public, versioned machine output for desktop integrations.
//!
//! Keep this module deliberately narrower than the daemon's private wire
//! protocol. A capability is advertised only after its public command, output
//! shape, and compatibility rules are covered here and in `docs/MACHINE-API.md`.

use irlume_common::{OperationErrorCode, ProfileSummary, Request, Response};
use serde::Serialize;
use serde_json::{json, Value};
use std::process::ExitCode;

/// Lowest contract this build can speak.
pub const CONTRACT_MIN: u32 = 1;
/// Highest contract this build can speak. Bumping this is a deliberate act: it
/// means a second set of semantics now exists and both must be served.
pub const CONTRACT_MAX: u32 = 1;

/// What a caller gets when it does not say which contract it implements.
///
/// This is pinned to the FIRST contract and must never track `CONTRACT_MAX`.
/// A consumer written against contract 1 that omits the flag has to keep
/// receiving contract 1 on an engine that has since learned contract 2, or the
/// engine would silently change the meaning of a response under a program that
/// never asked for it. "Newest" is the one thing a default must not mean here.
pub const CONTRACT_DEFAULT: u32 = 1;

const CAPABILITIES: &[&str] = &[
    "version-json",
    "profiles-list-json",
    "status-json",
    "doctor-json",
];

/// The contract the caller asked for, or the failure to report.
///
/// Parsed before anything else happens, so an unsupported request is refused
/// before the daemon is contacted and before any command with side effects can
/// begin. There are no mutating machine commands yet; this exists so that when
/// one arrives it cannot be reached without an agreed contract.
enum Contract {
    Agreed(u32),
    Malformed,
    Unsupported,
}

/// Read `--contract N` out of an argument list.
///
/// Deliberately tolerant of absence and intolerant of everything else: a
/// repeated flag, a missing value, a non-numeric value and an out-of-range
/// version are all refusals rather than guesses.
fn negotiate(args: &[String]) -> Contract {
    let mut requested: Option<u32> = None;
    let mut index = 0;
    while index < args.len() {
        if args[index] == "--contract" {
            if requested.is_some() {
                return Contract::Malformed;
            }
            let Some(raw) = args.get(index + 1) else {
                return Contract::Malformed;
            };
            let Ok(version) = raw.parse::<u32>() else {
                return Contract::Malformed;
            };
            requested = Some(version);
            index += 2;
            continue;
        }
        index += 1;
    }
    match requested {
        None => Contract::Agreed(CONTRACT_DEFAULT),
        Some(v) if (CONTRACT_MIN..=CONTRACT_MAX).contains(&v) => Contract::Agreed(v),
        Some(_) => Contract::Unsupported,
    }
}

/// Strip `--contract N` so each command's own validator sees only its flags.
fn without_contract(args: &[String]) -> Vec<String> {
    let mut out = Vec::with_capacity(args.len());
    let mut index = 0;
    while index < args.len() {
        if args[index] == "--contract" {
            index += 2;
            continue;
        }
        out.push(args[index].clone());
        index += 1;
    }
    out
}

#[derive(Serialize)]
struct Document {
    contract_version: u32,
    engine_version: &'static str,
    command: &'static str,
    ok: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    data: Option<Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    error: Option<MachineError>,
}

#[derive(Serialize)]
struct MachineError {
    code: &'static str,
    retryable: bool,
}

fn success(command: &'static str, data: Value, contract: u32) -> Document {
    Document {
        // Echo the contract actually in force, so a consumer can assert the
        // engine agreed to the one it implements rather than inferring it.
        contract_version: contract,
        engine_version: env!("CARGO_PKG_VERSION"),
        command,
        ok: true,
        data: Some(data),
        error: None,
    }
}

fn failure(command: &'static str, code: &'static str, retryable: bool, contract: u32) -> Document {
    Document {
        contract_version: contract,
        engine_version: env!("CARGO_PKG_VERSION"),
        command,
        ok: false,
        data: None,
        error: Some(MachineError { code, retryable }),
    }
}

/// Map a daemon outcome to a published error code. The mapping is total: an
/// `Unknown` code from a newer daemon degrades to the generic failure rather
/// than inventing a meaning for it.
fn error_code(code: OperationErrorCode) -> &'static str {
    match code {
        OperationErrorCode::NotAuthorized => "not-authorized",
        OperationErrorCode::OperationFailed | OperationErrorCode::Unknown => "operation-failed",
    }
}

fn emit(document: &Document, exit: ExitCode) -> ExitCode {
    // Serialization only contains compile-time strings and serde_json values,
    // so failure would be a programming error. Keep stdout machine-only even
    // in that case and report the detail on stderr.
    match serde_json::to_string(document) {
        Ok(line) => {
            println!("{line}");
            exit
        }
        Err(error) => {
            eprintln!("irlume machine output serialization failed: {error}");
            ExitCode::FAILURE
        }
    }
}

pub fn version(args: &[String]) -> ExitCode {
    let contract = match negotiate(args) {
        Contract::Agreed(v) => v,
        Contract::Malformed => {
            return emit(
                &failure("version", "usage-error", false, CONTRACT_DEFAULT),
                ExitCode::from(2),
            )
        }
        Contract::Unsupported => {
            return emit(
                &failure("version", "unsupported-contract", false, CONTRACT_DEFAULT),
                ExitCode::from(2),
            )
        }
    };
    if without_contract(args) != ["version", "--json"] {
        return emit(
            &failure("version", "usage-error", false, contract),
            ExitCode::from(2),
        );
    }
    emit(
        &success(
            "version",
            json!({
                "capabilities": CAPABILITIES,
                // The range this build can speak. A consumer should pick a
                // version inside it and pass `--contract`, rather than reading
                // `contract_version` off a response and hoping.
                "contract_versions": { "min": CONTRACT_MIN, "max": CONTRACT_MAX },
                "limits": {
                    // Read the engine's own constant rather than repeating the
                    // number. A consumer displays this as the enrollment limit,
                    // so a literal here would silently start lying the day the
                    // store's limit changes.
                    "max_profiles": irlume_core::storage::MAX_PROFILES
                }
            }),
            contract,
        ),
        ExitCode::SUCCESS,
    )
}

/// `irlume status --json`: the readiness summary a desktop integration needs,
/// as values rather than prose.
///
/// Deliberately narrower than the human `status`. It omits camera device paths
/// and the account name: a consumer needs to know whether an IR camera is
/// usable, not which node it is, and it already knows which account it asked
/// about. Everything here is derived from the same sources the human command
/// reads, so the two cannot disagree about the machine's state, only about how
/// it is worded.
pub fn status(args: &[String]) -> ExitCode {
    const COMMAND: &str = "status";
    let contract = match negotiate(args) {
        Contract::Agreed(v) => v,
        Contract::Malformed => {
            return emit(
                &failure(COMMAND, "usage-error", false, CONTRACT_DEFAULT),
                ExitCode::from(2),
            )
        }
        Contract::Unsupported => {
            return emit(
                &failure(COMMAND, "unsupported-contract", false, CONTRACT_DEFAULT),
                ExitCode::from(2),
            )
        }
    };
    let args = &without_contract(args);
    if !valid_status_args(args) {
        return emit(
            &failure(COMMAND, "usage-error", false, contract),
            ExitCode::from(2),
        );
    }
    let user = crate::user_arg(args);

    // Reachability is reported, not fatal: a consumer wants to render "the
    // daemon is not answering" rather than receive an error with no detail, and
    // the fields that do not need the daemon are still worth having.
    let daemon = match crate::commands::daemon_reach() {
        crate::commands::DaemonReach::Running => "running",
        crate::commands::DaemonReach::AccessDenied => "access-denied",
        crate::commands::DaemonReach::Down => "unreachable",
    };

    let method = irlume_core::policy::method();
    let enrollment = match crate::daemon_request(&Request::ListProfiles {
        user: user.clone(),
        structured_errors: true,
    }) {
        Ok(Response::Enrollment { profiles, .. }) => {
            let scans: usize = profiles.iter().map(|p| p.scans.len()).sum();
            json!({ "known": true, "profiles": profiles.len(), "scans": scans })
        }
        // Unknown is not zero. A consumer must be able to tell "this account has
        // no face enrolled" from "we could not find out".
        _ => json!({ "known": false }),
    };

    let keyring = match crate::daemon_request(&Request::KeyringInfo { user: user.clone() }) {
        Ok(Response::KeyringInfo { armed, policy, .. }) => {
            json!({ "known": true, "armed": armed, "policy": policy })
        }
        _ => json!({ "known": false }),
    };

    let (templates, recovery) = match crate::daemon_request(&Request::RecoveryStatus { user }) {
        Ok(Response::RecoveryStatus {
            encrypted,
            recovery_set,
            ..
        }) => (
            json!(if encrypted { "encrypted" } else { "plaintext" }),
            json!({ "known": true, "passphrase_set": recovery_set }),
        ),
        _ => (json!("unknown"), json!({ "known": false })),
    };

    // Camera capability, not camera identity: whether each spectrum resolved to
    // a device, never which one.
    let (rgb, ir) = irlume_camera::select_pair();
    let camera = json!({
        "rgb": !rgb.is_empty(),
        "ir": !ir.is_empty(),
    });

    emit(
        &success(
            COMMAND,
            json!({
                "daemon": daemon,
                "auth_method": format!("{method:?}").to_lowercase(),
                "face_disabled": method.face_disabled(),
                "enrollment": enrollment,
                "templates": templates,
                "keyring": keyring,
                "recovery": recovery,
                "camera": camera,
                "fingerprint": irlume_fingerprint::device_name().is_some(),
            }),
            contract,
        ),
        ExitCode::SUCCESS,
    )
}

fn valid_status_args(args: &[String]) -> bool {
    if args.first().map(String::as_str) != Some("status") {
        return false;
    }
    let mut saw_json = false;
    let mut saw_user = false;
    let mut index = 1;
    while index < args.len() {
        match args[index].as_str() {
            "--json" if !saw_json => {
                saw_json = true;
                index += 1;
            }
            "--user" if !saw_user => {
                saw_user = true;
                let Some(user) = args.get(index + 1) else {
                    return false;
                };
                if user.is_empty() || user.starts_with('-') {
                    return false;
                }
                index += 2;
            }
            _ => return false,
        }
    }
    saw_json
}

/// `irlume doctor --json`: every readiness check as an identified result.
///
/// The array is complete. A consumer may assume that a check it knows about and
/// does not find here was not run by this engine version, rather than that it
/// passed silently, which is why this shipped all at once instead of check by
/// check.
pub fn doctor(args: &[String]) -> ExitCode {
    const COMMAND: &str = "doctor";
    let contract = match negotiate(args) {
        Contract::Agreed(v) => v,
        Contract::Malformed => {
            return emit(
                &failure(COMMAND, "usage-error", false, CONTRACT_DEFAULT),
                ExitCode::from(2),
            )
        }
        Contract::Unsupported => {
            return emit(
                &failure(COMMAND, "unsupported-contract", false, CONTRACT_DEFAULT),
                ExitCode::from(2),
            )
        }
    };
    let args = without_contract(args);
    if args != ["doctor", "--json"] {
        return emit(
            &failure(COMMAND, "usage-error", false, contract),
            ExitCode::from(2),
        );
    }
    let mut report = crate::doctor_report::Report::new(crate::doctor_report::Mode::Collect);
    // Same pass the human report makes, printing nothing.
    let _ = crate::doctor_run(&mut report);
    let checks = report.into_checks();
    emit(
        &success(COMMAND, json!({ "checks": checks }), contract),
        ExitCode::SUCCESS,
    )
}

pub fn profiles_list(args: &[String]) -> ExitCode {
    const COMMAND: &str = "profiles.list";
    // Negotiate first: an unsupported contract is refused before the daemon is
    // contacted at all.
    let contract = match negotiate(args) {
        Contract::Agreed(v) => v,
        Contract::Malformed => {
            return emit(
                &failure(COMMAND, "usage-error", false, CONTRACT_DEFAULT),
                ExitCode::from(2),
            )
        }
        Contract::Unsupported => {
            return emit(
                &failure(COMMAND, "unsupported-contract", false, CONTRACT_DEFAULT),
                ExitCode::from(2),
            )
        }
    };
    let args = &without_contract(args);
    if !valid_profiles_list_args(args) {
        return emit(
            &failure(COMMAND, "usage-error", false, contract),
            ExitCode::from(2),
        );
    }
    let user = crate::user_arg(args);
    // Ask for typed failures. An older daemon ignores the field and answers
    // with prose, which the `Response::Error` arm below still maps.
    match crate::daemon_request(&Request::ListProfiles {
        user,
        structured_errors: true,
    }) {
        Ok(Response::Enrollment {
            profiles,
            require_eyes_open,
            require_challenge,
            ..
        }) => emit(
            &success(
                COMMAND,
                profiles_data(profiles, require_eyes_open, require_challenge),
                contract,
            ),
            ExitCode::SUCCESS,
        ),
        Ok(Response::OperationError { code, retryable }) => emit(
            &failure(COMMAND, error_code(code), retryable, contract),
            ExitCode::FAILURE,
        ),
        // An older daemon predates the typed variant and answers with prose.
        // Its text is deliberately not inspected: matching on daemon wording
        // would make a message change a breaking API change.
        Ok(Response::Error(_)) => emit(
            &failure(COMMAND, "operation-failed", false, contract),
            ExitCode::FAILURE,
        ),
        Ok(_) => emit(
            &failure(COMMAND, "protocol-error", false, contract),
            ExitCode::FAILURE,
        ),
        Err(_) => emit(
            &failure(COMMAND, "daemon-unavailable", true, contract),
            ExitCode::FAILURE,
        ),
    }
}

fn valid_profiles_list_args(args: &[String]) -> bool {
    if args.first().map(String::as_str) != Some("profiles")
        || args.get(1).map(String::as_str) != Some("list")
    {
        return false;
    }
    let mut saw_json = false;
    let mut saw_user = false;
    let mut index = 2;
    while index < args.len() {
        match args[index].as_str() {
            "--json" if !saw_json => {
                saw_json = true;
                index += 1;
            }
            "--user" if !saw_user => {
                saw_user = true;
                let Some(user) = args.get(index + 1) else {
                    return false;
                };
                if user.is_empty() || user.starts_with('-') {
                    return false;
                }
                index += 2;
            }
            _ => return false,
        }
    }
    saw_json
}

fn profiles_data(
    profiles: Vec<ProfileSummary>,
    require_eyes_open: bool,
    require_challenge: bool,
) -> Value {
    // The current enrollment store identifies profiles and scans by their
    // names. Do not falsely present those names as opaque stable IDs. A later
    // contract capability can add mutation-safe IDs after the store owns them.
    let profiles = profiles
        .into_iter()
        .map(|profile| {
            json!({
                "display_name": profile.name,
                "scans": profile.scans.into_iter().map(|name| {
                    json!({ "display_name": name })
                }).collect::<Vec<_>>()
            })
        })
        .collect::<Vec<_>>();
    json!({
        "profiles": profiles,
        "require_eyes_open": require_eyes_open,
        "require_challenge": require_challenge
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn an_absent_contract_flag_always_means_the_first_contract() {
        // The load-bearing rule. A consumer written against contract 1 that
        // omits the flag must keep getting contract 1 after the engine learns
        // contract 2, so this must never be expressed as "the newest".
        assert_eq!(CONTRACT_DEFAULT, 1);
        assert_eq!(CONTRACT_DEFAULT, CONTRACT_MIN);
        let args = |v: &[&str]| v.iter().map(|s| s.to_string()).collect::<Vec<_>>();
        match negotiate(&args(&["version", "--json"])) {
            Contract::Agreed(v) => assert_eq!(v, CONTRACT_DEFAULT),
            _ => panic!("an absent flag must agree, not refuse"),
        }
    }

    #[test]
    fn a_supported_contract_is_agreed_and_an_unsupported_one_is_refused() {
        let args = |v: &[&str]| v.iter().map(|s| s.to_string()).collect::<Vec<_>>();
        for v in CONTRACT_MIN..=CONTRACT_MAX {
            match negotiate(&args(&["version", "--contract", &v.to_string(), "--json"])) {
                Contract::Agreed(got) => assert_eq!(got, v),
                _ => panic!("contract {v} is in range and must be agreed"),
            }
        }
        // Above the range: a consumer built for a contract this engine does not
        // implement must be told so, not served contract 1 semantics silently.
        assert!(matches!(
            negotiate(&args(&["version", "--contract", "2", "--json"])),
            Contract::Unsupported
        ));
        // Zero is not a contract.
        assert!(matches!(
            negotiate(&args(&["version", "--contract", "0", "--json"])),
            Contract::Unsupported
        ));
    }

    #[test]
    fn a_malformed_contract_flag_is_refused_rather_than_guessed() {
        let args = |v: &[&str]| v.iter().map(|s| s.to_string()).collect::<Vec<_>>();
        for bad in [
            vec!["version", "--contract"],                  // no value
            vec!["version", "--contract", "one", "--json"], // not a number
            vec!["version", "--contract", "-1", "--json"],  // not unsigned
            vec!["version", "--contract", "1", "--contract", "1", "--json"], // repeated
        ] {
            assert!(
                matches!(negotiate(&args(&bad)), Contract::Malformed),
                "{bad:?} must be refused"
            );
        }
    }

    #[test]
    fn stripping_the_flag_leaves_the_command_its_own_arguments() {
        let args = |v: &[&str]| v.iter().map(|s| s.to_string()).collect::<Vec<_>>();
        assert_eq!(
            without_contract(&args(&["profiles", "list", "--contract", "1", "--json"])),
            args(&["profiles", "list", "--json"])
        );
        // A command that never saw the flag is untouched.
        assert_eq!(
            without_contract(&args(&["profiles", "list", "--json"])),
            args(&["profiles", "list", "--json"])
        );
    }

    #[test]
    fn version_freezes_the_public_envelope_and_capabilities() {
        let document = serde_json::to_value(success(
            "version",
            json!({
                "capabilities": CAPABILITIES,
                "limits": { "max_profiles": 3 }
            }),
            CONTRACT_DEFAULT,
        ))
        .unwrap();

        assert_eq!(document["contract_version"], 1);
        assert_eq!(document["command"], "version");
        assert_eq!(document["ok"], true);
        assert_eq!(
            document["data"]["capabilities"],
            json!([
                "version-json",
                "profiles-list-json",
                "status-json",
                "doctor-json"
            ])
        );
        assert!(document.get("error").is_none());
    }

    #[test]
    fn profile_listing_does_not_claim_unimplemented_opaque_ids() {
        let data = profiles_data(
            vec![ProfileSummary {
                name: "Face Profile 1".into(),
                scans: vec!["Scan 1".into()],
            }],
            true,
            false,
        );

        assert_eq!(data["profiles"][0]["display_name"], "Face Profile 1");
        assert_eq!(data["profiles"][0]["scans"][0]["display_name"], "Scan 1");
        assert!(data["profiles"][0].get("profile_id").is_none());
        assert!(data["profiles"][0]["scans"][0].get("scan_id").is_none());
        assert_eq!(data["require_eyes_open"], true);
        assert_eq!(data["require_challenge"], false);
    }

    #[test]
    fn errors_have_stable_codes_without_daemon_prose() {
        let document = serde_json::to_value(failure(
            "profiles.list",
            "daemon-unavailable",
            true,
            CONTRACT_DEFAULT,
        ))
        .unwrap();

        assert_eq!(document["ok"], false);
        assert_eq!(document["error"]["code"], "daemon-unavailable");
        assert_eq!(document["error"]["retryable"], true);
        assert!(document.get("data").is_none());
    }

    #[test]
    fn profiles_list_rejects_unknown_missing_and_duplicate_flags() {
        let args = |values: &[&str]| {
            values
                .iter()
                .map(|value| value.to_string())
                .collect::<Vec<_>>()
        };
        assert!(valid_profiles_list_args(&args(&[
            "profiles", "list", "--json"
        ])));
        assert!(valid_profiles_list_args(&args(&[
            "profiles", "list", "--user", "alice", "--json"
        ])));
        assert!(!valid_profiles_list_args(&args(&["profiles", "list"])));
        assert!(!valid_profiles_list_args(&args(&[
            "profiles",
            "list",
            "--json",
            "--verbose"
        ])));
        assert!(!valid_profiles_list_args(&args(&[
            "profiles", "list", "--json", "--json"
        ])));
        assert!(!valid_profiles_list_args(&args(&[
            "profiles", "list", "--json", "--user"
        ])));
    }
}

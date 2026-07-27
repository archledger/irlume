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

pub const CONTRACT_VERSION: u32 = 1;

const CAPABILITIES: &[&str] = &["version-json", "profiles-list-json"];

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

fn success(command: &'static str, data: Value) -> Document {
    Document {
        contract_version: CONTRACT_VERSION,
        engine_version: env!("CARGO_PKG_VERSION"),
        command,
        ok: true,
        data: Some(data),
        error: None,
    }
}

fn failure(command: &'static str, code: &'static str, retryable: bool) -> Document {
    Document {
        contract_version: CONTRACT_VERSION,
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
    if args != ["version", "--json"] {
        return emit(&failure("version", "usage-error", false), ExitCode::from(2));
    }
    emit(
        &success(
            "version",
            json!({
                "capabilities": CAPABILITIES,
                "limits": {
                    // Read the engine's own constant rather than repeating the
                    // number. A consumer displays this as the enrollment limit,
                    // so a literal here would silently start lying the day the
                    // store's limit changes.
                    "max_profiles": irlume_core::storage::MAX_PROFILES
                }
            }),
        ),
        ExitCode::SUCCESS,
    )
}

pub fn profiles_list(args: &[String]) -> ExitCode {
    const COMMAND: &str = "profiles.list";
    if !valid_profiles_list_args(args) {
        return emit(&failure(COMMAND, "usage-error", false), ExitCode::from(2));
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
            ),
            ExitCode::SUCCESS,
        ),
        Ok(Response::OperationError { code, retryable }) => emit(
            &failure(COMMAND, error_code(code), retryable),
            ExitCode::FAILURE,
        ),
        // An older daemon predates the typed variant and answers with prose.
        // Its text is deliberately not inspected: matching on daemon wording
        // would make a message change a breaking API change.
        Ok(Response::Error(_)) => emit(
            &failure(COMMAND, "operation-failed", false),
            ExitCode::FAILURE,
        ),
        Ok(_) => emit(
            &failure(COMMAND, "protocol-error", false),
            ExitCode::FAILURE,
        ),
        Err(_) => emit(
            &failure(COMMAND, "daemon-unavailable", true),
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
    fn version_freezes_the_public_envelope_and_capabilities() {
        let document = serde_json::to_value(success(
            "version",
            json!({
                "capabilities": CAPABILITIES,
                "limits": { "max_profiles": 3 }
            }),
        ))
        .unwrap();

        assert_eq!(document["contract_version"], 1);
        assert_eq!(document["command"], "version");
        assert_eq!(document["ok"], true);
        assert_eq!(
            document["data"]["capabilities"],
            json!(["version-json", "profiles-list-json"])
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
        let document =
            serde_json::to_value(failure("profiles.list", "daemon-unavailable", true)).unwrap();

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

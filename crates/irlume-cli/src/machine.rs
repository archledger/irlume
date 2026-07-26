// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright the irlume contributors.

//! Public, versioned machine output for desktop integrations.
//!
//! Keep this module deliberately narrower than the daemon's private wire
//! protocol. A capability is advertised only after its public command, output
//! shape, and compatibility rules are covered here and in `docs/MACHINE-API.md`.

use irlume_common::{ProfileMutationKind, ProfileSummary, Request, Response};
use serde::Serialize;
use serde_json::{json, Value};
use std::process::ExitCode;

pub const CONTRACT_VERSION: u32 = 1;

const CAPABILITIES: &[&str] = &["version-json", "profiles-json", "profile-mutations-json"];

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
                    "max_profiles": 3,
                    "max_scans_per_profile": 20
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
    match crate::daemon_request(&Request::ListProfiles { user }) {
        Ok(Response::Enrollment {
            profiles,
            require_eyes_open,
            require_challenge,
            ..
        }) => match profiles_data(profiles, require_eyes_open, require_challenge) {
            Ok(data) => emit(&success(COMMAND, data), ExitCode::SUCCESS),
            Err(code) => emit(&failure(COMMAND, code, false), ExitCode::FAILURE),
        },
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

pub fn profiles_delete(args: &[String]) -> ExitCode {
    const COMMAND: &str = "profiles.delete";
    let Some(parsed) = parse_profile_mutation_args(args, false) else {
        return emit(&failure(COMMAND, "usage-error", false), ExitCode::from(2));
    };
    let user = crate::user_arg(args);
    let request = match parsed.scan_id {
        Some(scan_id) => Request::DeleteScanById {
            user,
            profile_id: parsed.profile_id,
            scan_id,
        },
        None => Request::DeleteProfileById {
            user,
            profile_id: parsed.profile_id,
        },
    };
    emit_profile_mutation(COMMAND, request)
}

pub fn profiles_rename(args: &[String]) -> ExitCode {
    const COMMAND: &str = "profiles.rename";
    let Some(parsed) = parse_profile_mutation_args(args, true) else {
        return emit(&failure(COMMAND, "usage-error", false), ExitCode::from(2));
    };
    let user = crate::user_arg(args);
    let new_name = parsed.new_name.expect("rename parser requires a name");
    let request = match parsed.scan_id {
        Some(scan_id) => Request::RenameScanById {
            user,
            profile_id: parsed.profile_id,
            scan_id,
            new_name,
        },
        None => Request::RenameProfileById {
            user,
            profile_id: parsed.profile_id,
            new_name,
        },
    };
    emit_profile_mutation(COMMAND, request)
}

fn emit_profile_mutation(command: &'static str, request: Request) -> ExitCode {
    match crate::daemon_request(&request) {
        Ok(Response::ProfileMutation {
            operation,
            profile_id,
            profile_name_before,
            profile_name_after,
            scan_id,
            scan_name_before,
            scan_name_after,
            total_scans,
        }) => emit(
            &success(
                command,
                mutation_data(
                    operation,
                    profile_id,
                    profile_name_before,
                    profile_name_after,
                    scan_id,
                    scan_name_before,
                    scan_name_after,
                    total_scans,
                ),
            ),
            ExitCode::SUCCESS,
        ),
        Ok(Response::Error(_)) => emit(
            &failure(command, "operation-failed", false),
            ExitCode::FAILURE,
        ),
        Ok(_) => emit(
            &failure(command, "protocol-error", false),
            ExitCode::FAILURE,
        ),
        Err(_) => emit(
            &failure(command, "daemon-unavailable", true),
            ExitCode::FAILURE,
        ),
    }
}

#[allow(clippy::too_many_arguments)]
fn mutation_data(
    operation: ProfileMutationKind,
    profile_id: String,
    profile_name_before: Option<String>,
    profile_name_after: Option<String>,
    scan_id: Option<String>,
    scan_name_before: Option<String>,
    scan_name_after: Option<String>,
    total_scans: Option<usize>,
) -> Value {
    let record = |profile_name: Option<String>, scan_name: Option<String>| {
        profile_name.map(|profile_name| {
            json!({
                "profile_id": profile_id,
                "profile_name": profile_name,
                "scan_id": scan_id,
                "scan_name": scan_name
            })
        })
    };
    let before = record(profile_name_before, scan_name_before);
    let after = record(profile_name_after, scan_name_after);
    let deleted = matches!(
        operation,
        ProfileMutationKind::DeleteProfile | ProfileMutationKind::DeleteScan
    );
    json!({
        "operation": operation,
        "profile_id": profile_id,
        "scan_id": scan_id,
        "before": before,
        "after": after,
        "total_scans": total_scans,
        "deleted": deleted,
        "mutated_other_profiles": false
    })
}

struct MutationArgs {
    profile_id: String,
    scan_id: Option<String>,
    new_name: Option<String>,
}

fn parse_profile_mutation_args(args: &[String], rename: bool) -> Option<MutationArgs> {
    let expected_subcommand = if rename { "rename" } else { "delete" };
    if args.first().map(String::as_str) != Some("profiles")
        || args.get(1).map(String::as_str) != Some(expected_subcommand)
    {
        return None;
    }
    let mut profile_id = None;
    let mut scan_id = None;
    let mut new_name = None;
    let mut saw_json = false;
    let mut saw_user = false;
    let mut index = 2;
    while index < args.len() {
        let (slot, validate_id): (&mut Option<String>, bool) = match args[index].as_str() {
            "--profile-id" if profile_id.is_none() => (&mut profile_id, true),
            "--scan-id" if scan_id.is_none() => (&mut scan_id, true),
            "--name" if rename && new_name.is_none() => (&mut new_name, false),
            "--user" if !saw_user => {
                saw_user = true;
                let user = args.get(index + 1)?;
                if user.is_empty() || user.starts_with('-') {
                    return None;
                }
                index += 2;
                continue;
            }
            "--json" if !saw_json => {
                saw_json = true;
                index += 1;
                continue;
            }
            _ => return None,
        };
        let value = args.get(index + 1)?;
        if value.is_empty() || value.starts_with('-') {
            return None;
        }
        if validate_id {
            let valid = if args[index] == "--profile-id" {
                irlume_core::storage::valid_profile_id(value)
            } else {
                irlume_core::storage::valid_scan_id(value)
            };
            if !valid {
                return None;
            }
        } else if value.trim() != value
            || value.chars().count() > 80
            || value.chars().any(char::is_control)
        {
            return None;
        }
        *slot = Some(value.clone());
        index += 2;
    }
    if !saw_json || profile_id.is_none() || rename != new_name.is_some() {
        return None;
    }
    Some(MutationArgs {
        profile_id: profile_id.expect("checked"),
        scan_id,
        new_name,
    })
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
) -> Result<Value, &'static str> {
    let mut output = Vec::with_capacity(profiles.len());
    for profile in profiles {
        if !irlume_core::storage::valid_profile_id(&profile.id)
            || profile.scans.len() != profile.scan_ids.len()
        {
            return Err("unsupported-daemon");
        }
        let mut scans = Vec::with_capacity(profile.scans.len());
        for (name, id) in profile.scans.into_iter().zip(profile.scan_ids) {
            if !irlume_core::storage::valid_scan_id(&id) {
                return Err("unsupported-daemon");
            }
            scans.push(json!({
                "scan_id": id,
                "display_name": name
            }));
        }
        output.push(json!({
            "profile_id": profile.id,
            "display_name": profile.name,
            "scans": scans
        }));
    }
    Ok(json!({
        "profiles": output,
        "require_eyes_open": require_eyes_open,
        "require_challenge": require_challenge
    }))
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
            json!(["version-json", "profiles-json", "profile-mutations-json"])
        );
        assert!(document.get("error").is_none());
    }

    #[test]
    fn profile_listing_exposes_stored_opaque_ids() {
        let data = profiles_data(
            vec![ProfileSummary {
                id: "profile-0123456789abcdef0123456789abcdef".into(),
                name: "Face Profile 1".into(),
                scans: vec!["Scan 1".into()],
                scan_ids: vec!["scan-fedcba9876543210fedcba9876543210".into()],
            }],
            true,
            false,
        )
        .unwrap();

        assert_eq!(
            data["profiles"][0]["profile_id"],
            "profile-0123456789abcdef0123456789abcdef"
        );
        assert_eq!(data["profiles"][0]["display_name"], "Face Profile 1");
        assert_eq!(data["profiles"][0]["scans"][0]["display_name"], "Scan 1");
        assert_eq!(
            data["profiles"][0]["scans"][0]["scan_id"],
            "scan-fedcba9876543210fedcba9876543210"
        );
        assert_eq!(data["require_eyes_open"], true);
        assert_eq!(data["require_challenge"], false);
    }

    #[test]
    fn profile_listing_refuses_missing_or_misaligned_ids() {
        let profile = |scan_ids| ProfileSummary {
            id: "profile-0123456789abcdef0123456789abcdef".into(),
            name: "Primary".into(),
            scans: vec!["Scan 1".into()],
            scan_ids,
        };
        assert_eq!(
            profiles_data(vec![profile(vec![])], false, false).unwrap_err(),
            "unsupported-daemon"
        );
        let mut missing = profile(vec!["scan-fedcba9876543210fedcba9876543210".into()]);
        missing.id.clear();
        assert_eq!(
            profiles_data(vec![missing], false, false).unwrap_err(),
            "unsupported-daemon"
        );
    }

    #[test]
    fn mutation_args_require_safe_ids_json_and_bounded_names() {
        let args = |values: &[&str]| {
            values
                .iter()
                .map(|value| value.to_string())
                .collect::<Vec<_>>()
        };
        let profile = "profile-0123456789abcdef0123456789abcdef";
        let scan = "scan-fedcba9876543210fedcba9876543210";
        assert!(parse_profile_mutation_args(
            &args(&[
                "profiles",
                "rename",
                "--profile-id",
                profile,
                "--scan-id",
                scan,
                "--name",
                "Glasses",
                "--json"
            ]),
            true
        )
        .is_some());
        assert!(parse_profile_mutation_args(
            &args(&["profiles", "delete", "--profile-id", profile, "--json"]),
            false
        )
        .is_some());
        assert!(parse_profile_mutation_args(
            &args(&["profiles", "delete", "--profile-id", "../unsafe", "--json"]),
            false
        )
        .is_none());
        assert!(parse_profile_mutation_args(
            &args(&[
                "profiles",
                "rename",
                "--profile-id",
                profile,
                "--name",
                " padded ",
                "--json"
            ]),
            true
        )
        .is_none());
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

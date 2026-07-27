// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright the irlume contributors.

use serde_json::Value;
use std::process::Command;

#[test]
fn version_json_is_one_machine_document() {
    let output = Command::new(env!("CARGO_BIN_EXE_irlume"))
        .args(["version", "--json"])
        .output()
        .expect("run irlume");

    assert!(output.status.success());
    assert!(output.stderr.is_empty());
    assert_eq!(
        output.stdout.iter().filter(|&&byte| byte == b'\n').count(),
        1
    );
    let document: Value = serde_json::from_slice(&output.stdout).expect("valid JSON");
    assert_eq!(document["contract_version"], 1);
    assert_eq!(document["command"], "version");
    assert_eq!(document["ok"], true);
    assert_eq!(
        document["data"]["capabilities"],
        serde_json::json!([
            "version-json",
            "profiles-list-json",
            "status-json",
            "doctor-json",
            "login-status-json"
        ])
    );
}

#[test]
fn advertised_limits_track_the_engine_constants() {
    // Not a tautology: this runs the real binary and compares its published
    // limit against the engine's own constant, so reverting to a literal in
    // machine.rs fails here rather than silently misinforming a consumer that
    // renders this as the enrollment limit.
    let output = Command::new(env!("CARGO_BIN_EXE_irlume"))
        .args(["version", "--json"])
        .output()
        .expect("run irlume");
    let document: Value = serde_json::from_slice(&output.stdout).expect("valid JSON");
    assert_eq!(
        document["data"]["limits"]["max_profiles"],
        serde_json::json!(irlume_core::storage::MAX_PROFILES),
        "published max_profiles must come from irlume_core::storage::MAX_PROFILES"
    );
}

#[test]
fn unavailable_daemon_is_a_typed_json_error() {
    let socket = std::env::temp_dir().join(format!(
        "irlume-machine-api-no-daemon-{}",
        std::process::id()
    ));
    let output = Command::new(env!("CARGO_BIN_EXE_irlume"))
        .args(["profiles", "list", "--json"])
        .env("IRLUME_SOCKET", socket)
        .output()
        .expect("run irlume");

    assert!(!output.status.success());
    assert!(output.stderr.is_empty());
    assert_eq!(
        output.stdout.iter().filter(|&&byte| byte == b'\n').count(),
        1
    );
    let document: Value = serde_json::from_slice(&output.stdout).expect("valid JSON");
    assert_eq!(document["command"], "profiles.list");
    assert_eq!(document["ok"], false);
    assert_eq!(document["error"]["code"], "daemon-unavailable");
    assert_eq!(document["error"]["retryable"], true);
}

#[test]
fn unknown_machine_flags_are_a_typed_usage_error() {
    let output = Command::new(env!("CARGO_BIN_EXE_irlume"))
        .args(["version", "--json", "--verbose"])
        .output()
        .expect("run irlume");

    assert_eq!(output.status.code(), Some(2));
    assert!(output.stderr.is_empty());
    let document: Value = serde_json::from_slice(&output.stdout).expect("valid JSON");
    assert_eq!(document["command"], "version");
    assert_eq!(document["ok"], false);
    assert_eq!(document["error"]["code"], "usage-error");
    assert_eq!(document["error"]["retryable"], false);
}

#[test]
fn status_json_is_one_machine_document_with_no_device_paths() {
    // status is the command a desktop integration polls, so it is also the one
    // most likely to leak. It must carry camera CAPABILITY without camera
    // IDENTITY, and must not name the account.
    let output = Command::new(env!("CARGO_BIN_EXE_irlume"))
        .args(["status", "--json"])
        .env("IRLUME_SOCKET", "/nonexistent/irlume-status-test.sock")
        .output()
        .expect("run irlume");

    assert!(output.stderr.is_empty(), "stdout must stay machine-only");
    assert_eq!(
        output.stdout.iter().filter(|&&b| b == b'\n').count(),
        1,
        "exactly one document"
    );
    let raw = String::from_utf8(output.stdout).expect("utf-8");
    assert!(
        !raw.contains("/dev/video"),
        "device paths must not appear in machine output: {raw}"
    );

    let document: Value = serde_json::from_str(&raw).expect("valid JSON");
    assert_eq!(document["command"], "status");
    assert_eq!(document["contract_version"], 1);
    let data = &document["data"];
    // Camera is a capability summary, so both spectra are booleans.
    assert!(data["camera"]["rgb"].is_boolean());
    assert!(data["camera"]["ir"].is_boolean());
    // With no daemon reachable, the daemon-derived facts must say they are
    // unknown rather than defaulting to a confident zero.
    assert_eq!(data["daemon"], "unreachable");
    assert_eq!(data["enrollment"]["known"], false);
    assert!(
        data["enrollment"].get("profiles").is_none(),
        "an unknown enrollment must not report a count"
    );
    assert_eq!(data["keyring"]["known"], false);
}

#[test]
fn status_json_refuses_an_unsupported_contract_before_reading_anything() {
    let output = Command::new(env!("CARGO_BIN_EXE_irlume"))
        .args(["status", "--contract", "9", "--json"])
        .env("IRLUME_SOCKET", "/nonexistent/irlume-status-test.sock")
        .output()
        .expect("run irlume");
    assert_eq!(output.status.code(), Some(2));
    let document: Value = serde_json::from_slice(&output.stdout).expect("valid JSON");
    assert_eq!(document["error"]["code"], "unsupported-contract");
}

#[test]
fn login_status_json_lists_every_surface_by_service_name() {
    // The surface list is COMPLETE: services that do not exist on this machine
    // stay in the array with `present: false`, so a consumer reading an id it
    // knows and cannot find may conclude the engine does not wire that service
    // rather than that the service is unwired here. That distinction is the
    // whole reason this command exists, so it is asserted on a machine where
    // most of these files are certainly absent.
    let output = Command::new(env!("CARGO_BIN_EXE_irlume"))
        .args(["login", "status", "--json"])
        .output()
        .expect("run irlume");

    assert!(output.stderr.is_empty(), "stdout must stay machine-only");
    assert_eq!(
        output.stdout.iter().filter(|&&b| b == b'\n').count(),
        1,
        "exactly one document"
    );
    let raw = String::from_utf8(output.stdout).expect("utf-8");
    assert!(
        !raw.contains("/etc/pam.d"),
        "machine output publishes service names, never PAM file paths: {raw}"
    );
    assert!(
        !raw.contains("[login]"),
        "the human report must not leak into machine mode: {raw}"
    );

    let document: Value = serde_json::from_str(&raw).expect("valid JSON");
    assert_eq!(document["command"], "login.status");
    assert_eq!(document["contract_version"], 1);
    assert_eq!(document["ok"], true);

    let surfaces = document["data"]["surfaces"]
        .as_array()
        .expect("surfaces must be an array");
    // Public API: this list may grow, but an id is never renamed or reused.
    for required in [
        "gdm-password",
        "sddm",
        "lightdm",
        "plasmalogin",
        "cosmic-greeter",
        "greetd",
        "gdm-fingerprint",
        "kde",
        "sudo",
        "polkit-1",
    ] {
        assert!(
            surfaces.iter().any(|s| s["id"] == required),
            "surface `{required}` is missing from the array"
        );
    }

    for surface in surfaces {
        assert!(surface["present"].is_boolean(), "{surface}");
        assert!(surface["wired"].is_boolean(), "{surface}");
        let role = surface["role"].as_str().expect("role must be a string");
        assert!(
            [
                "login-screen",
                "login-screen-fingerprint",
                "lock-screen",
                "sudo",
                "polkit"
            ]
            .contains(&role),
            "unexpected role `{role}`"
        );
        match surface["mode"].as_str() {
            Some(mode) => {
                assert_eq!(
                    surface["wired"], true,
                    "a mode without wiring would describe how nothing fires: {surface}"
                );
                assert!(
                    ["face-first", "on-demand", "keyring", "verify"].contains(&mode),
                    "unexpected mode `{mode}`"
                );
            }
            // Absent, not null: there is no mode for an unwired surface.
            None => assert!(surface.get("mode").is_none(), "{surface}"),
        }
    }

    let mut ids: Vec<_> = surfaces.iter().map(|s| s["id"].as_str().unwrap()).collect();
    let before = ids.len();
    ids.sort_unstable();
    ids.dedup();
    assert_eq!(before, ids.len(), "surface ids must be unique");

    // A login manager the engine could not determine says so; it never reports
    // a name it does not have.
    let manager = &document["data"]["login_manager"];
    if manager["known"] == false {
        assert!(manager.get("name").is_none(), "{manager}");
    } else {
        assert!(manager["name"].is_string(), "{manager}");
        assert!(manager["recognized"].is_boolean(), "{manager}");
    }

    assert!(["loaded", "not-loaded", "unknown"]
        .contains(&document["data"]["selinux_module"].as_str().unwrap()));
}

#[test]
fn login_status_json_refuses_an_unsupported_contract() {
    let output = Command::new(env!("CARGO_BIN_EXE_irlume"))
        .args(["login", "status", "--contract", "9", "--json"])
        .output()
        .expect("run irlume");
    assert_eq!(output.status.code(), Some(2));
    let document: Value = serde_json::from_slice(&output.stdout).expect("valid JSON");
    assert_eq!(document["command"], "login.status");
    assert_eq!(document["error"]["code"], "unsupported-contract");
}

#[test]
fn doctor_json_reports_every_check_with_a_stable_id() {
    // The array must be COMPLETE. A consumer is entitled to read a missing id as
    // "this engine does not run that check", so a check that silently drops out
    // under some condition would be read as one that passed.
    let output = Command::new(env!("CARGO_BIN_EXE_irlume"))
        .args(["doctor", "--json"])
        .env("IRLUME_SOCKET", "/nonexistent/irlume-doctor-test.sock")
        .output()
        .expect("run irlume");

    assert!(output.stderr.is_empty(), "stdout must stay machine-only");
    assert_eq!(
        output.stdout.iter().filter(|&&b| b == b'\n').count(),
        1,
        "exactly one document"
    );
    let raw = String::from_utf8(output.stdout).expect("utf-8");
    assert!(
        !raw.contains("[doctor]"),
        "the human report must not leak into machine mode: {raw}"
    );

    let document: Value = serde_json::from_str(&raw).expect("valid JSON");
    assert_eq!(document["command"], "doctor");
    let checks = document["data"]["checks"]
        .as_array()
        .expect("checks must be an array");

    // Ids a consumer keys off. These are public API: this list may grow, but an
    // entry may never be renamed or repurposed, so removing one here should be
    // as uncomfortable as it looks.
    for required in [
        "platform",
        "install-origin",
        "tpm",
        "secure-boot",
        "boot-mode",
        "signed-pcr-policy",
        "pcrlock",
        "camera-nodes",
        "models",
        "templates",
        "recovery-passphrase",
        "credential-release-challenge",
        "login-wiring",
        "display-manager",
        "install-hygiene",
        "keyring-secrets",
    ] {
        assert!(
            checks.iter().any(|c| c["id"] == required),
            "check `{required}` is missing from the array"
        );
    }

    // Every entry is well-formed and uses the published state vocabulary.
    for c in checks {
        assert!(c["id"].is_string(), "each check needs an id: {c}");
        let state = c["state"].as_str().expect("state must be a string");
        assert!(
            ["pass", "warn", "fail", "unknown", "info"].contains(&state),
            "unexpected state `{state}`"
        );
    }

    // Ids are unique: a duplicate would make a consumer's lookup ambiguous.
    let mut ids: Vec<_> = checks.iter().map(|c| c["id"].as_str().unwrap()).collect();
    let before = ids.len();
    ids.sort_unstable();
    ids.dedup();
    assert_eq!(before, ids.len(), "check ids must be unique");
}

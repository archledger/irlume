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
            "login-status-json",
            "auth-test-events",
            "login-plan-json",
            "login-transactions"
        ])
    );
}

/// A refusal happens before the stream begins, so it must arrive as the single
/// document every other refusal uses. A consumer that mis-invoked the command
/// should not have to parse NDJSON to discover it mis-invoked the command.
#[test]
fn auth_test_refusals_are_one_document_not_a_stream() {
    let cases: [(&[&str], &str); 3] = [
        (&["auth", "test"], "usage-error"),
        (
            &["auth", "test", "--events=jsonl", "--contract", "9"],
            "unsupported-contract",
        ),
        (
            &["auth", "test", "--events=jsonl", "--preview=ir-jpeg"],
            "usage-error",
        ),
    ];
    for (args, expected) in cases {
        let output = Command::new(env!("CARGO_BIN_EXE_irlume"))
            .args(args)
            .output()
            .expect("run irlume");
        assert_eq!(
            output.status.code(),
            Some(2),
            "{args:?} must exit 2, stdout: {}",
            String::from_utf8_lossy(&output.stdout)
        );
        assert_eq!(
            output.stdout.iter().filter(|&&byte| byte == b'\n').count(),
            1,
            "{args:?} must emit exactly one document"
        );
        let document: Value = serde_json::from_slice(&output.stdout).expect("valid JSON");
        assert_eq!(document["command"], "auth.test");
        assert_eq!(document["ok"], false);
        assert_eq!(document["error"]["code"], expected, "for {args:?}");
        // A refusal carries no stream fields: there is no stream.
        assert!(document.get("sequence").is_none());
        assert!(document.get("operation_id").is_none());
    }
}

/// The published fixture is a real capture, so it is also the regression test
/// for the three stream promises. Checked here as well as in the conformance
/// script, because a Rust change can break the shape while nobody runs Python.
#[test]
fn the_event_stream_fixture_keeps_its_promises() {
    let raw = std::fs::read_to_string(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../schemas/fixtures/v1/auth-test-events.ndjson"
    ))
    .expect("read the published stream fixture");
    let lines: Vec<Value> = raw
        .lines()
        .filter(|line| !line.trim().is_empty())
        .map(|line| serde_json::from_str(line).expect("each line is a JSON document"))
        .collect();
    assert!(!lines.is_empty(), "fixture must contain events");

    for (index, line) in lines.iter().enumerate() {
        assert_eq!(line["sequence"], index as u64, "gapless from zero");
        assert_eq!(line["contract_version"], 1);
        assert_eq!(line["command"], "auth.test");
        // Asserted as a present, well-formed string rather than compared as
        // values: two ABSENT fields both index to Null and would compare equal,
        // so equality alone passes a stream that carries no operation_id.
        let id = line["operation_id"]
            .as_str()
            .unwrap_or_else(|| panic!("line {index} has no operation_id"));
        assert_eq!(id.len(), 32, "operation_id is 128 bits, hex encoded");
        assert!(id.chars().all(|c| c.is_ascii_hexdigit()));
        assert_eq!(id, lines[0]["operation_id"].as_str().expect("first id"));
        // No username, and no match score: a score would let a caller
        // hill-climb a presentation against the threshold.
        let text = line.to_string();
        assert!(!text.contains("score"), "line {index} leaks a score");
        assert!(!text.contains("/dev/video"), "line {index} leaks a device");
    }
    let terminals: Vec<bool> = lines
        .iter()
        .map(|line| line["terminal"].as_bool().unwrap_or(false))
        .collect();
    assert_eq!(
        terminals.iter().filter(|t| **t).count(),
        1,
        "exactly one terminal event"
    );
    assert!(*terminals.last().expect("non-empty"), "terminal is last");

    let result = lines.last().expect("non-empty");
    assert_eq!(result["event"], "result");
    assert!(matches!(
        result["data"]["reason"].as_str(),
        Some("granted") | Some("not-live") | Some("no-match")
    ));
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
fn every_doctor_check_id_is_documented_and_every_documented_id_exists() {
    // Check ids are public API, so an id that ships undocumented is a promise
    // nobody can read, and a documented id that no longer ships is a promise
    // broken quietly. The registry table in MACHINE-API.md is the contract; this
    // holds it to the engine in both directions.
    let doc = std::fs::read_to_string(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../docs/MACHINE-API.md"
    ))
    .expect("read docs/MACHINE-API.md");
    // The registry is one table among several with the same row shape, so take
    // the rows under its header and stop at the blank line that ends it.
    let documented: std::collections::BTreeSet<&str> = doc
        .lines()
        .skip_while(|line| !line.starts_with("| Check id |"))
        .take_while(|line| !line.trim().is_empty())
        .filter_map(|line| line.strip_prefix("| `"))
        .filter_map(|rest| rest.split_once("` |"))
        .map(|(id, _)| id)
        .collect();
    assert!(
        documented.contains("tpm"),
        "the registry table was not found; did its formatting change?"
    );

    let output = Command::new(env!("CARGO_BIN_EXE_irlume"))
        .args(["doctor", "--json"])
        .env("IRLUME_SOCKET", "/nonexistent/irlume-doctor-doc-test.sock")
        .output()
        .expect("run irlume");
    let document: Value = serde_json::from_slice(&output.stdout).expect("valid JSON");
    let emitted: std::collections::BTreeSet<&str> = document["data"]["checks"]
        .as_array()
        .expect("checks array")
        .iter()
        .map(|c| c["id"].as_str().expect("id"))
        .collect();

    let undocumented: Vec<_> = emitted.difference(&documented).collect();
    assert!(
        undocumented.is_empty(),
        "these check ids ship without a row in the MACHINE-API.md registry: {undocumented:?}"
    );
    let missing: Vec<_> = documented.difference(&emitted).collect();
    assert!(
        missing.is_empty(),
        "these ids are documented but no longer emitted: {missing:?}"
    );
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

/// The transaction commands, exercised through the real binary. Their bodies
/// need root to reach the writing half, but every refusal and the read-only
/// plan run as an ordinary user, which is also how a desktop first meets them.
#[test]
fn login_plan_answers_for_both_actions() {
    for action in ["enable", "disable"] {
        let output = Command::new(env!("CARGO_BIN_EXE_irlume"))
            .args(["login", "plan", "--action", action, "--json"])
            .output()
            .expect("run irlume");
        assert!(output.status.success(), "plan {action} should succeed");
        let document: Value = serde_json::from_slice(&output.stdout).expect("valid JSON");
        assert_eq!(document["command"], "login.plan");
        assert_eq!(document["data"]["action"], action);
        // Every wirable surface is listed, present or not, so a consumer that
        // knows an id can always find it.
        let changes = document["data"]["changes"]
            .as_array()
            .expect("changes is an array");
        assert!(!changes.is_empty());
        for change in changes {
            assert!(change["surface"].is_string());
            assert!(change["writes"].is_boolean());
        }
        // requires_root must agree with the write count rather than being an
        // independent claim a consumer could act on wrongly.
        let writes = document["data"]["writes"].as_u64().expect("writes");
        assert_eq!(document["data"]["requires_root"], writes > 0);
        let counted = changes
            .iter()
            .filter(|c| c["writes"] == serde_json::json!(true))
            .count() as u64;
        assert_eq!(writes, counted, "the count must match the entries");
        // No PAM paths: surfaces are named by service.
        let text = String::from_utf8_lossy(&output.stdout);
        assert!(
            !text.contains("/etc/pam.d"),
            "a plan must not publish paths"
        );
    }
}

#[test]
fn a_plan_id_is_stable_for_an_unchanged_machine() {
    let id = |action: &str| -> String {
        let output = Command::new(env!("CARGO_BIN_EXE_irlume"))
            .args(["login", "plan", "--action", action, "--json"])
            .output()
            .expect("run irlume");
        let document: Value = serde_json::from_slice(&output.stdout).expect("valid JSON");
        document["data"]["plan_id"]
            .as_str()
            .expect("plan_id")
            .to_string()
    };
    let first = id("enable");
    assert_eq!(first.len(), 32);
    assert_eq!(first, id("enable"), "same machine, same intent, same id");
    assert_ne!(
        first,
        id("disable"),
        "a different intent is a different plan"
    );
}

#[test]
fn the_transaction_commands_refuse_before_they_write() {
    let cases: [(&[&str], &str, i32); 6] = [
        // apply without a plan id would act on changes nobody was shown.
        (
            &["login", "apply", "--action", "enable", "--json"],
            "usage-error",
            2,
        ),
        (
            &[
                "login",
                "apply",
                "--action",
                "enable",
                "--plan-id",
                "nothex",
                "--json",
            ],
            "usage-error",
            2,
        ),
        // An id shaped like a path is refused, not cleaned: it becomes a filename.
        (
            &[
                "login",
                "verify",
                "--transaction-id",
                "../../etc/passwd",
                "--json",
            ],
            "usage-error",
            2,
        ),
        (
            &[
                "login",
                "rollback",
                "--transaction-id",
                "../../etc/shadow",
                "--apply",
                "--json",
            ],
            "usage-error",
            2,
        ),
        (&["login", "verify", "--json"], "usage-error", 2),
        // A well-formed id that names no record.
        (
            &[
                "login",
                "verify",
                "--transaction-id",
                "0123456789abcdef0123456789abcdef",
                "--json",
            ],
            "not-found",
            1,
        ),
    ];
    // Point the store at an empty directory this test owns. Without it the
    // answer depends on the machine: a host whose real /var/lib/irlume store
    // exists but is not readable by this user correctly returns not-authorized
    // rather than not-found, which is the very distinction this PR added. The
    // test read the host's state and so passed here and failed on the runner.
    let store = std::env::temp_dir().join(format!("irlume-tx-empty-{}", std::process::id()));
    std::fs::create_dir_all(&store).expect("temp store");
    for (args, expected, exit) in cases {
        let output = Command::new(env!("CARGO_BIN_EXE_irlume"))
            .args(args)
            .env("IRLUME_STATE_DIR", &store)
            .output()
            .expect("run irlume");
        let document: Value = serde_json::from_slice(&output.stdout).unwrap_or_else(|e| {
            panic!(
                "{args:?}: {e}, stdout {:?}",
                String::from_utf8_lossy(&output.stdout)
            )
        });
        assert_eq!(document["ok"], false, "{args:?}");
        assert_eq!(document["error"]["code"], expected, "{args:?}");
        assert_eq!(output.status.code(), Some(exit), "{args:?}");
    }
    let _ = std::fs::remove_dir_all(&store);
}

/// Applying needs root, and that is checked BEFORE anything is written: a
/// mutating command that loses permission partway leaves a stack half-changed.
/// Skipped when the suite happens to run as root, rather than asserting the
/// opposite and quietly testing nothing.
#[test]
fn applying_without_root_is_refused_up_front() {
    // SAFETY: geteuid cannot fail and touches no memory.
    if unsafe { libc::geteuid() } == 0 {
        eprintln!("running as root; the unprivileged refusal cannot be exercised here");
        return;
    }
    let plan = Command::new(env!("CARGO_BIN_EXE_irlume"))
        .args(["login", "plan", "--action", "enable", "--json"])
        .output()
        .expect("run irlume");
    let plan: Value = serde_json::from_slice(&plan.stdout).expect("valid JSON");
    let plan_id = plan["data"]["plan_id"].as_str().expect("plan_id");

    let output = Command::new(env!("CARGO_BIN_EXE_irlume"))
        .args([
            "login",
            "apply",
            "--action",
            "enable",
            "--plan-id",
            plan_id,
            "--json",
        ])
        .output()
        .expect("run irlume");
    let document: Value = serde_json::from_slice(&output.stdout).expect("valid JSON");
    assert_eq!(document["command"], "login.apply");
    assert_eq!(document["error"]["code"], "not-authorized");
    assert_eq!(document["error"]["retryable"], false);
}

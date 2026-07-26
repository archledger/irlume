// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright the irlume contributors.

use serde_json::Value;
use std::io::{BufRead, BufReader, Write};
use std::os::unix::net::UnixListener;
use std::process::Command;
use std::thread;

fn serve_once(
    socket: &std::path::Path,
    respond: impl Fn(irlume_common::Request) -> irlume_common::Response + Send + 'static,
) -> thread::JoinHandle<()> {
    let listener = UnixListener::bind(socket).expect("bind test socket");
    thread::spawn(move || {
        let (mut stream, _) = listener.accept().expect("accept client");
        let mut line = String::new();
        BufReader::new(stream.try_clone().unwrap())
            .read_line(&mut line)
            .expect("read request");
        let request = serde_json::from_str(&line).expect("parse request");
        let response = serde_json::to_string(&respond(request)).expect("serialize response");
        writeln!(stream, "{response}").expect("write response");
    })
}

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
        serde_json::json!(["version-json", "profiles-json", "profile-mutations-json"])
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
fn unsafe_profile_mutation_ids_are_typed_usage_errors() {
    let output = Command::new(env!("CARGO_BIN_EXE_irlume"))
        .args(["profiles", "delete", "--profile-id", "../unsafe", "--json"])
        .output()
        .expect("run irlume");

    assert_eq!(output.status.code(), Some(2));
    assert!(output.stderr.is_empty());
    let document: Value = serde_json::from_slice(&output.stdout).expect("valid JSON");
    assert_eq!(document["command"], "profiles.delete");
    assert_eq!(document["ok"], false);
    assert_eq!(document["error"]["code"], "usage-error");
}

#[test]
fn profile_delete_json_targets_the_opaque_id_and_returns_exact_identity() {
    let profile_id = "profile-0123456789abcdef0123456789abcdef";
    let socket =
        std::env::temp_dir().join(format!("irlume-machine-api-delete-{}", std::process::id()));
    let server = serve_once(&socket, move |request| match request {
        irlume_common::Request::DeleteProfileById {
            user,
            profile_id: requested,
        } => {
            assert!(!user.is_empty());
            assert_eq!(requested, profile_id);
            irlume_common::Response::ProfileMutation {
                operation: irlume_common::ProfileMutationKind::DeleteProfile,
                profile_id: requested,
                profile_name_before: Some("Primary".into()),
                profile_name_after: None,
                scan_id: None,
                scan_name_before: None,
                scan_name_after: None,
                total_scans: None,
            }
        }
        other => panic!("unexpected request: {other:?}"),
    });

    let output = Command::new(env!("CARGO_BIN_EXE_irlume"))
        .args(["profiles", "delete", "--profile-id", profile_id, "--json"])
        .env("IRLUME_SOCKET", &socket)
        .output()
        .expect("run irlume");
    server.join().expect("server thread");
    let _ = std::fs::remove_file(socket);

    assert!(output.status.success());
    assert!(output.stderr.is_empty());
    let document: Value = serde_json::from_slice(&output.stdout).expect("valid JSON");
    assert_eq!(document["command"], "profiles.delete");
    assert_eq!(document["ok"], true);
    assert_eq!(document["data"]["profile_id"], profile_id);
    assert_eq!(document["data"]["before"]["profile_name"], "Primary");
    assert!(document["data"]["after"].is_null());
    assert_eq!(document["data"]["deleted"], true);
    assert_eq!(document["data"]["mutated_other_profiles"], false);
}

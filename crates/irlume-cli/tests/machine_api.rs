// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright the irlume contributors.

use serde_json::Value;
use std::io::{BufRead, BufReader, Read, Write};
use std::os::unix::net::UnixListener;
use std::process::Command;
use std::process::Stdio;
use std::sync::mpsc;
use std::thread;
use std::time::{Duration, Instant};

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

fn serve_many(
    socket: &std::path::Path,
    count: usize,
    mut respond: impl FnMut(irlume_common::Request) -> irlume_common::Response + Send + 'static,
) -> thread::JoinHandle<()> {
    let listener = UnixListener::bind(socket).expect("bind test socket");
    listener.set_nonblocking(true).unwrap();
    thread::spawn(move || {
        for _ in 0..count {
            let deadline = Instant::now() + Duration::from_secs(10);
            let (mut stream, _) = loop {
                match listener.accept() {
                    Ok(connection) => break connection,
                    Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                        assert!(Instant::now() < deadline, "timed out accepting client");
                        thread::sleep(Duration::from_millis(10));
                    }
                    Err(error) => panic!("accept client: {error}"),
                }
            };
            let mut line = String::new();
            BufReader::new(stream.try_clone().unwrap())
                .read_line(&mut line)
                .expect("read request");
            let request = serde_json::from_str(&line).expect("parse request");
            let response = serde_json::to_string(&respond(request)).expect("serialize response");
            writeln!(stream, "{response}").expect("write response");
        }
    })
}

fn serve_many_with_final_disconnect(
    socket: &std::path::Path,
    count: usize,
    mut respond: impl FnMut(irlume_common::Request) -> irlume_common::Response + Send + 'static,
) -> thread::JoinHandle<()> {
    let listener = UnixListener::bind(socket).expect("bind test socket");
    listener.set_nonblocking(true).unwrap();
    thread::spawn(move || {
        for index in 0..count {
            let deadline = Instant::now() + Duration::from_secs(10);
            let (mut stream, _) = loop {
                match listener.accept() {
                    Ok(connection) => break connection,
                    Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                        assert!(Instant::now() < deadline, "timed out accepting client");
                        thread::sleep(Duration::from_millis(10));
                    }
                    Err(error) => panic!("accept client: {error}"),
                }
            };
            let mut line = String::new();
            BufReader::new(stream.try_clone().unwrap())
                .read_line(&mut line)
                .expect("read request");
            let request = serde_json::from_str(&line).expect("parse request");
            let response = serde_json::to_string(&respond(request)).expect("serialize response");
            let result = writeln!(stream, "{response}");
            if index + 1 == count {
                assert_eq!(
                    result.unwrap_err().kind(),
                    std::io::ErrorKind::BrokenPipe,
                    "cancelled mutation must close its socket before the reply"
                );
            } else {
                result.expect("write response");
            }
        }
    })
}

fn preview_sample() -> irlume_common::PreviewSample {
    use base64::{engine::general_purpose::STANDARD, Engine as _};
    use image::codecs::jpeg::JpegEncoder;

    let image = image::GrayImage::from_pixel(32, 24, image::Luma([96]));
    let mut jpeg = Vec::new();
    JpegEncoder::new_with_quality(&mut jpeg, 70)
        .encode_image(&image)
        .unwrap();
    irlume_common::PreviewSample {
        frame_jpeg_base64: STANDARD.encode(jpeg),
        width: 32,
        height: 24,
        spectrum: "ir".into(),
        landmarks: (0..478)
            .map(|index| {
                [
                    0.2 + 0.6 * (index % 22) as f32 / 21.0,
                    0.1 + 0.8 * (index / 22) as f32 / 21.0,
                ]
            })
            .collect(),
        face_box: [0.2, 0.1, 0.6, 0.8],
        position: irlume_common::PositionReport {
            face: true,
            face_frac: 0.4,
            centered: true,
            yaw_asym: 0.0,
            pitch_frac: 0.5,
            brightness: 96.0,
            ir_ok: true,
            quality: 94,
            well_framed: true,
            guidance: "Hold still".into(),
        },
    }
}

fn run_enroll_events(socket: &std::path::Path) -> std::process::Output {
    Command::new(env!("CARGO_BIN_EXE_irlume"))
        .args([
            "enroll",
            "--events=jsonl",
            "--preview=ir-jpeg",
            "--preview-max-fps=8",
            "--preview-max-size=640x480",
        ])
        .env("IRLUME_SOCKET", socket)
        .output()
        .expect("run event command")
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
        serde_json::json!([
            "version-json",
            "profiles-json",
            "profile-mutations-json",
            "events-jsonl",
            "position-report",
            "preview-ir-jpeg",
            "login-transactions"
        ])
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
fn daemon_operation_errors_keep_stable_codes_and_retryability() {
    for (suffix, code, retryable) in [
        ("busy", irlume_common::OperationErrorCode::CameraBusy, true),
        (
            "authz",
            irlume_common::OperationErrorCode::NotAuthorized,
            false,
        ),
        (
            "precondition",
            irlume_common::OperationErrorCode::PreconditionFailed,
            false,
        ),
    ] {
        let socket = std::env::temp_dir().join(format!(
            "irlume-machine-api-error-{suffix}-{}",
            std::process::id()
        ));
        let server = serve_once(&socket, move |request| {
            assert!(matches!(
                request,
                irlume_common::Request::PreviewSample { .. }
            ));
            irlume_common::Response::OperationError { code, retryable }
        });
        let output = run_enroll_events(&socket);
        server.join().unwrap();
        let _ = std::fs::remove_file(socket);

        assert!(!output.status.success());
        assert!(output.stderr.is_empty());
        let events = output
            .stdout
            .split(|byte| *byte == b'\n')
            .filter(|line| !line.is_empty())
            .map(|line| serde_json::from_slice::<Value>(line).unwrap())
            .collect::<Vec<_>>();
        assert_eq!(events.len(), 2);
        assert_eq!(events[1]["terminal"], true);
        assert_eq!(events[1]["error"]["code"], code_name(code));
        assert_eq!(events[1]["error"]["retryable"], retryable);
    }
}

fn code_name(code: irlume_common::OperationErrorCode) -> &'static str {
    match code {
        irlume_common::OperationErrorCode::CameraBusy => "camera-busy",
        irlume_common::OperationErrorCode::NotAuthorized => "not-authorized",
        irlume_common::OperationErrorCode::PreconditionFailed => "precondition-failed",
        _ => panic!("unexpected test code"),
    }
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

#[test]
fn enroll_event_stream_has_monotonic_identity_and_one_terminal_event() {
    let profile_id = "profile-0123456789abcdef0123456789abcdef";
    let socket =
        std::env::temp_dir().join(format!("irlume-machine-api-enroll-{}", std::process::id()));
    let server = serve_many(&socket, 4, move |request| match request {
        irlume_common::Request::PreviewSample { .. } => {
            irlume_common::Response::Preview(preview_sample())
        }
        irlume_common::Request::Enroll { reset, .. } => {
            assert!(!reset);
            irlume_common::Response::Enrolled {
                profile_id: profile_id.into(),
                profile: "Primary".into(),
                created: true,
                added: 3,
                total: 3,
                added_scans: vec!["Scan 1".into(), "Scan 2".into(), "Scan 3".into()],
                added_scan_ids: vec![
                    "scan-0123456789abcdef0123456789abcdef".into(),
                    "scan-1123456789abcdef0123456789abcdef".into(),
                    "scan-2123456789abcdef0123456789abcdef".into(),
                ],
            }
        }
        other => panic!("unexpected request: {other:?}"),
    });

    let output = Command::new(env!("CARGO_BIN_EXE_irlume"))
        .args([
            "enroll",
            "--events=jsonl",
            "--preview=ir-jpeg",
            "--preview-max-fps=8",
            "--preview-max-size=640x480",
        ])
        .env("IRLUME_SOCKET", &socket)
        .output()
        .expect("run irlume");
    server.join().expect("server thread");
    let _ = std::fs::remove_file(socket);

    assert!(output.status.success());
    assert!(output.stderr.is_empty());
    let events = output
        .stdout
        .split(|byte| *byte == b'\n')
        .filter(|line| !line.is_empty())
        .map(|line| serde_json::from_slice::<Value>(line).expect("valid event"))
        .collect::<Vec<_>>();
    assert_eq!(events.len(), 6);
    let operation_id = events[0]["operation_id"].as_str().unwrap();
    let session_id = events[0]["session_id"].as_str().unwrap();
    for (sequence, event) in events.iter().enumerate() {
        assert_eq!(event["sequence"], sequence);
        assert_eq!(event["operation_id"], operation_id);
        assert_eq!(event["session_id"], session_id);
        assert_eq!(event["command"], "enroll");
    }
    assert_eq!(events[0]["event"], "started");
    assert!(events[1..4].iter().all(|event| event["event"] == "preview"));
    assert_eq!(events[1]["data"]["position"]["countdown"], 3);
    assert_eq!(events[2]["data"]["position"]["countdown"], 2);
    assert_eq!(events[3]["data"]["position"]["countdown"], 1);
    assert_eq!(events[4]["event"], "stage");
    assert_eq!(events[5]["event"], "completed");
    assert_eq!(events[5]["terminal"], true);
    assert_eq!(events[5]["data"]["profile_id"], profile_id);
    assert_eq!(
        events
            .iter()
            .filter(|event| event["terminal"] == true)
            .count(),
        1
    );
}

#[test]
fn event_stream_omits_frames_unless_preview_is_explicitly_requested() {
    let profile_id = "profile-6123456789abcdef0123456789abcdef";
    let socket = std::env::temp_dir().join(format!(
        "irlume-machine-api-no-frame-{}",
        std::process::id()
    ));
    let server = serve_many(&socket, 4, move |request| match request {
        irlume_common::Request::PreviewSample { .. } => {
            irlume_common::Response::Preview(preview_sample())
        }
        irlume_common::Request::Enroll { .. } => irlume_common::Response::Enrolled {
            profile_id: profile_id.into(),
            profile: "Primary".into(),
            created: true,
            added: 1,
            total: 1,
            added_scans: vec!["Scan 1".into()],
            added_scan_ids: vec!["scan-6123456789abcdef0123456789abcdef".into()],
        },
        other => panic!("unexpected request: {other:?}"),
    });

    let output = Command::new(env!("CARGO_BIN_EXE_irlume"))
        .args(["enroll", "--events=jsonl"])
        .env("IRLUME_SOCKET", &socket)
        .output()
        .expect("run event command");
    server.join().unwrap();
    let _ = std::fs::remove_file(socket);

    assert!(output.status.success());
    let events = output
        .stdout
        .split(|byte| *byte == b'\n')
        .filter(|line| !line.is_empty())
        .map(|line| serde_json::from_slice::<Value>(line).unwrap())
        .collect::<Vec<_>>();
    for event in events.iter().filter(|event| event["event"] == "preview") {
        assert!(event["data"].get("position").is_some());
        for forbidden in [
            "frame_jpeg_base64",
            "width",
            "height",
            "spectrum",
            "landmarks",
            "face_box",
        ] {
            assert!(
                event["data"].get(forbidden).is_none(),
                "{forbidden} must require --preview=ir-jpeg"
            );
        }
    }
}

#[test]
fn cancellation_during_enrollment_disconnects_before_terminal_event() {
    let profile_id = "profile-3123456789abcdef0123456789abcdef";
    let socket =
        std::env::temp_dir().join(format!("irlume-machine-api-cancel-{}", std::process::id()));
    let (enrolled_tx, enrolled_rx) = mpsc::channel();
    let mut enrolled_tx = Some(enrolled_tx);
    let mut previews = 0;
    let server = serve_many_with_final_disconnect(&socket, 4, move |request| match request {
        irlume_common::Request::PreviewSample { .. } => {
            previews += 1;
            irlume_common::Response::Preview(preview_sample())
        }
        irlume_common::Request::Enroll { .. } => {
            assert_eq!(previews, 3);
            enrolled_tx.take().unwrap().send(()).unwrap();
            thread::sleep(Duration::from_millis(250));
            irlume_common::Response::Enrolled {
                profile_id: profile_id.into(),
                profile: "Temporary".into(),
                created: true,
                added: 1,
                total: 1,
                added_scans: vec!["Scan 1".into()],
                added_scan_ids: vec!["scan-4123456789abcdef0123456789abcdef".into()],
            }
        }
        other => panic!("unexpected request: {other:?}"),
    });

    let mut child = Command::new(env!("CARGO_BIN_EXE_irlume"))
        .args([
            "enroll",
            "--events=jsonl",
            "--preview=ir-jpeg",
            "--preview-max-fps=8",
            "--preview-max-size=640x480",
        ])
        .env("IRLUME_SOCKET", &socket)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn irlume");
    let mut child_stdout = child.stdout.take().unwrap();
    let mut child_stderr = child.stderr.take().unwrap();
    let stdout_reader = thread::spawn(move || {
        let mut bytes = Vec::new();
        child_stdout.read_to_end(&mut bytes).unwrap();
        bytes
    });
    let stderr_reader = thread::spawn(move || {
        let mut bytes = Vec::new();
        child_stderr.read_to_end(&mut bytes).unwrap();
        bytes
    });
    if enrolled_rx.recv_timeout(Duration::from_secs(15)).is_err() {
        let _ = child.kill();
        let status = child.wait().expect("wait for failed child");
        let stdout = stdout_reader.join().unwrap();
        let stderr = stderr_reader.join().unwrap();
        panic!(
            "timed out waiting for enrollment request ({status}); stdout={} stderr={}",
            String::from_utf8_lossy(&stdout),
            String::from_utf8_lossy(&stderr)
        );
    }
    unsafe {
        libc::kill(child.id() as libc::pid_t, libc::SIGTERM);
    }
    let cancellation_started = Instant::now();
    let status = child.wait().expect("wait for irlume");
    let stdout = stdout_reader.join().unwrap();
    let stderr = stderr_reader.join().unwrap();
    server.join().expect("server thread");
    let _ = std::fs::remove_file(socket);

    assert_eq!(status.code(), Some(130));
    assert!(
        cancellation_started.elapsed() < Duration::from_secs(1),
        "SIGTERM must not wait for the camera operation timeout"
    );
    assert!(stderr.is_empty());
    let events = stdout
        .split(|byte| *byte == b'\n')
        .filter(|line| !line.is_empty())
        .map(|line| serde_json::from_slice::<Value>(line).expect("valid event"))
        .collect::<Vec<_>>();
    assert_eq!(events.last().unwrap()["event"], "cancelled");
    assert_eq!(events.last().unwrap()["terminal"], true);
    assert!(!events.iter().any(|event| event["event"] == "completed"));
    assert_eq!(
        events
            .iter()
            .filter(|event| event["terminal"] == true)
            .count(),
        1
    );
}

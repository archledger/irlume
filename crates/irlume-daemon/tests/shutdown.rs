// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright the irlume contributors.

//! The daemon must exit promptly on SIGTERM so a package-upgrade restart never
//! stalls. irlume installs no signal handler, so SIGTERM uses the default
//! disposition (immediate terminate); this test guards against a future change
//! that adds a SIGINT-only handler and accidentally swallows SIGTERM, the exact
//! bug that made a sibling project hang 90s on every restart.
//!
//! Gated: needs the ONNX models and libonnxruntime to boot the daemon. CI
//! provides both; without them the test returns early.

use std::io::ErrorKind;
use std::path::PathBuf;
use std::process::Command;
use std::time::{Duration, Instant};

fn models_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../models")
}

fn ort_dylib() -> Option<String> {
    if let Ok(p) = std::env::var("ORT_DYLIB_PATH") {
        if PathBuf::from(&p).exists() {
            return Some(p);
        }
    }
    for c in [
        "/usr/share/irlume/onnxruntime/lib/libonnxruntime.so",
        "/usr/lib64/libonnxruntime.so",
        "/usr/lib/libonnxruntime.so",
        "/usr/lib/x86_64-linux-gnu/libonnxruntime.so",
    ] {
        if PathBuf::from(c).exists() {
            return Some(c.to_string());
        }
    }
    None
}

// The child is killed on every failure path and reaped on success; a panicking
// test process is itself reaped by the OS (which cleans up the child), so the
// zombie-process lint does not apply to this integration test.
#[allow(clippy::zombie_processes)]
#[test]
#[ignore = "needs ONNX models + onnxruntime to boot the daemon (CI provides them)"]
fn daemon_exits_promptly_on_sigterm() {
    let models = models_dir();
    let det = models.join("face_detection_yunet_2023mar.onnx");
    let model = models.join("glintr100.onnx");
    let mesh = models.join("face_landmark.onnx");
    let blaze = models.join("blaze_face_short_range.onnx");
    let Some(ort) = ort_dylib() else {
        eprintln!("SKIP: no libonnxruntime found");
        return;
    };
    if !det.exists() || !model.exists() {
        eprintln!("SKIP: models not present (git lfs pull)");
        return;
    }

    let dir = std::env::temp_dir().join(format!("irlumed-sigterm-{}", std::process::id()));
    let _ = std::fs::create_dir_all(&dir);
    let socket = dir.join("irlumed.sock");

    let mut child = Command::new(env!("CARGO_BIN_EXE_irlumed"))
        .env("IRLUME_SOCKET", &socket)
        .env("IRLUME_DET_MODEL", &det)
        .env("IRLUME_MODEL", &model)
        .env("IRLUME_MESH_MODEL", &mesh)
        .env("IRLUME_BLAZE_MODEL", &blaze)
        .env("ORT_DYLIB_PATH", &ort)
        // No real camera work: point the pair at nonexistent nodes so the
        // daemon does not contend with a running instance on this machine.
        .env("IRLUME_RGB_DEVICE", "/nonexistent-rgb")
        .env("IRLUME_IR_DEVICE", "/nonexistent-ir")
        .spawn()
        .expect("spawn irlumed");

    // Wait for the socket (model load can take a few seconds).
    let deadline = Instant::now() + Duration::from_secs(30);
    while !socket.exists() && Instant::now() < deadline {
        if let Ok(Some(status)) = child.try_wait() {
            panic!("daemon exited during startup: {status}");
        }
        std::thread::sleep(Duration::from_millis(100));
    }
    assert!(socket.exists(), "daemon never bound its socket");

    // SIGTERM and require exit within 3s (default disposition is immediate;
    // this fails loudly if a handler ever swallows it).
    let pid = child.id() as i32;
    let rc = unsafe { libc::kill(pid, libc::SIGTERM) };
    assert_eq!(
        rc,
        0,
        "kill(SIGTERM) failed: {}",
        std::io::Error::last_os_error()
    );

    let stop = Instant::now() + Duration::from_secs(3);
    let mut exited = false;
    while Instant::now() < stop {
        match child.try_wait() {
            Ok(Some(_)) => {
                exited = true;
                break;
            }
            Ok(None) => std::thread::sleep(Duration::from_millis(50)),
            Err(e) if e.kind() == ErrorKind::Other => break,
            Err(e) => panic!("try_wait: {e}"),
        }
    }
    if !exited {
        let _ = child.kill();
        let _ = std::fs::remove_dir_all(&dir);
        panic!("daemon did not exit within 3s of SIGTERM (a signal handler may be swallowing it)");
    }
    let _ = std::fs::remove_dir_all(&dir);
}

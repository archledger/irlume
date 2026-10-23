// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright the irlume contributors.

use std::io::{self, Write};
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
use std::process::Command;
use std::time::{Duration, Instant};

#[test]
fn startup_refusal_terminates_before_the_continuation() {
    for (mode, code) in [("marked", 1), ("normal", 0)] {
        let mut command = Command::new(std::env::current_exe().unwrap());
        command
            .args(["--exact", "startup_child", "--ignored", "--nocapture"])
            .env("IRLUME_TEST_EVIDENCE_STARTUP_CHILD", mode);
        let output = irlume_common::process::output_until(
            &mut command,
            Instant::now() + Duration::from_secs(5),
        )
        .unwrap();
        assert_eq!(output.status.code(), Some(code));
        let stdout = String::from_utf8(output.stdout).unwrap();
        let stderr = String::from_utf8(output.stderr).unwrap();
        if mode == "marked" {
            assert!(!stdout.contains("startup-continued"));
            // Termination cannot wait for an unscheduled or blocked writer.
            assert!(stderr.is_empty() || stderr == "irlume: refusing to run a hardware-evidence build as a shipped component\n");
        } else {
            assert!(stdout.contains("startup-continued"));
            assert!(stdout.contains("1 passed; 0 failed"));
            assert!(stderr.is_empty());
        }
    }
}

#[test]
#[ignore = "subprocess driver invoked by startup_refusal_terminates_before_the_continuation"]
fn startup_child() {
    let mode = std::env::var("IRLUME_TEST_EVIDENCE_STARTUP_CHILD").unwrap();
    let marked = match mode.as_str() {
        "marked" | "blocked" | "closed" => true,
        "normal" => false,
        _ => panic!("startup_child requires its parent test"),
    };
    let _reader = if mode == "blocked" {
        Some(block_stderr())
    } else {
        None
    };
    if mode == "closed" {
        // SAFETY: this child owns its stderr descriptor and exits immediately.
        assert_eq!(unsafe { libc::close(libc::STDERR_FILENO) }, 0);
    }
    irlume_common::build_mode::refuse_evidence_startup(marked);
    println!("startup-continued");
}

fn block_stderr() -> OwnedFd {
    let mut fds = [-1; 2];
    // SAFETY: fds has room for the two descriptors returned by pipe2.
    let opened = unsafe { libc::pipe2(fds.as_mut_ptr(), libc::O_CLOEXEC | libc::O_NONBLOCK) };
    assert_eq!(opened, 0);
    // SAFETY: pipe2 returned fresh descriptors owned by this child.
    let reader = unsafe { OwnedFd::from_raw_fd(fds[0]) };
    // SAFETY: the other fresh pipe descriptor has no other Rust owner.
    let mut writer = unsafe { std::fs::File::from_raw_fd(fds[1]) };
    loop {
        match writer.write(&[0; 4096]) {
            Ok(n) => assert!(n > 0),
            Err(error) => {
                assert_eq!(error.kind(), io::ErrorKind::WouldBlock);
                break;
            }
        }
    }
    // SAFETY: writer owns a valid descriptor; F_GETFL takes no extra argument.
    let flags = unsafe { libc::fcntl(writer.as_raw_fd(), libc::F_GETFL) };
    assert!(flags >= 0);
    // SAFETY: only this child uses the write end before it becomes stderr.
    let blocking =
        unsafe { libc::fcntl(writer.as_raw_fd(), libc::F_SETFL, flags & !libc::O_NONBLOCK) };
    assert_eq!(blocking, 0);
    // SAFETY: dup2 replaces only this test child's stderr with its private pipe.
    let redirected = unsafe { libc::dup2(writer.as_raw_fd(), libc::STDERR_FILENO) };
    assert_eq!(redirected, libc::STDERR_FILENO);
    reader
}

#[test]
fn startup_refusal_survives_blocked_and_closed_stderr() {
    for mode in ["blocked", "closed"] {
        let mut command = Command::new(std::env::current_exe().unwrap());
        command
            .args(["--exact", "startup_child", "--ignored", "--nocapture"])
            .env("IRLUME_TEST_EVIDENCE_STARTUP_CHILD", mode);
        let output = irlume_common::process::output_until(
            &mut command,
            Instant::now() + Duration::from_secs(5),
        )
        .unwrap();
        assert_eq!(output.status.code(), Some(1), "{mode}");
        assert!(!String::from_utf8_lossy(&output.stdout).contains("startup-continued"));
    }
}

#[test]
fn common_marker_describes_its_actual_build() {
    assert_eq!(
        irlume_common::HARDWARE_EVIDENCE_BUILD,
        cfg!(irlume_hw_evidence)
    );
}

// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright the irlume contributors.

//! Run real startup inside disposable namespaces, including on regressions.

use std::fs;
use std::os::unix::fs::MetadataExt;
use std::os::unix::net::UnixListener;
use std::path::PathBuf;
use std::process::Command;
use std::time::{Duration, Instant};

struct Fixture(PathBuf);

impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

#[test]
fn selected_closed_fd_startup_does_not_unlink_or_rebind_the_socket() {
    let fixture = Fixture(
        std::env::temp_dir().join(format!("irlume-activation-startup-{}", std::process::id())),
    );
    fs::create_dir(&fixture.0).unwrap();
    let path = fixture.0.join("activation.sock");
    let _listener = UnixListener::bind(&path).unwrap();
    let original = fs::metadata(&path).unwrap();

    let mut command = Command::new("/usr/bin/bwrap");
    command.env_clear().args([
        "--unshare-all",
        "--die-with-parent",
        "--new-session",
        "--cap-drop",
        "ALL",
        "--ro-bind",
        "/",
        "/",
        "--tmpfs",
        "/etc",
        "--tmpfs",
        "/var",
        "--tmpfs",
        "/run",
        "--tmpfs",
        "/tmp",
        "--dev",
        "/dev",
        "--proc",
        "/proc",
        "--bind",
    ]);
    command
        .arg(&fixture.0)
        .args(["/tmp/fixture", "--ro-bind"])
        // Bind sources name the caller's filesystem. Pin the built executable
        // inside the private /tmp even when its host target path is masked.
        .arg(env!("CARGO_BIN_EXE_irlumed"))
        .args([
            "/tmp/irlumed-under-test",
            "--chdir",
            "/tmp/fixture",
            "--setenv",
            "PATH",
            "/usr/bin:/bin",
            "--setenv",
            "IRLUME_SOCKET",
            "/tmp/fixture/activation.sock",
            "--setenv",
            "LISTEN_FDS",
            "1",
            "--setenv",
            "LISTEN_FDNAMES",
            "irlume",
            "--setenv",
            "LISTEN_PIDFDID",
            "unused",
            "--",
            "/bin/sh",
            "-c",
            // This child alone changes fd3. The shell and daemon keep the same PID
            // across exec. Even faulty later startup sees no host /etc, /var, /run
            // or devices; the rest of the host filesystem is read-only.
            "export LISTEN_PID=$$; exec 3<&-; exec \"$1\"",
            "activation-startup",
            "/tmp/irlumed-under-test",
        ]);
    let output =
        irlume_common::process::output_until(&mut command, Instant::now() + Duration::from_secs(5))
            .expect("bubblewrap must run the actual daemon in a disposable sandbox");
    let current = fs::metadata(&path).expect("startup must not unlink the original socket");
    assert_eq!(
        (current.dev(), current.ino()),
        (original.dev(), original.ino()),
        "startup must not replace the original socket"
    );
    let logs = format!(
        "{}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(output.status.code(), Some(1), "{logs}");
    assert!(logs.contains("cannot secure activation listener"), "{logs}");
    assert!(logs.contains("os error 9"), "{logs}");
    assert!(
        logs.contains("face authentication is unavailable; passwords still work"),
        "{logs}"
    );
}

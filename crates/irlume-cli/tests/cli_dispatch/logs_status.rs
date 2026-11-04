// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright the irlume contributors.

use super::{run, support, Sandbox, BIN};
use std::os::unix::fs::PermissionsExt;
use std::path::PathBuf;
use std::process::Command;

struct RestorePermissions(PathBuf);

impl Drop for RestorePermissions {
    fn drop(&mut self) {
        std::fs::set_permissions(&self.0, std::fs::Permissions::from_mode(0o700)).unwrap();
    }
}

fn status(mode: &str, action: &str) -> (i32, String, String) {
    let sandbox = Sandbox::new(&format!("debug-status-{mode}-{action}"));
    let system = sandbox.path("system");
    let parent = system.join("irlumed.service.d");
    std::fs::create_dir_all(&parent).unwrap();
    if mode != "absent" {
        std::fs::write(
            parent.join("50-irlume-debug.conf"),
            "[Service]\nEnvironment=IRLUME_LOG=debug\n",
        )
        .unwrap();
    }
    let _restore = if mode == "unreadable" {
        std::fs::set_permissions(&parent, std::fs::Permissions::from_mode(0o000)).unwrap();
        Some(RestorePermissions(parent.clone()))
    } else {
        None
    };
    sandbox.fake_tool(
        "systemctl",
        "printf 'unexpected command\\n' > \"$IRLUME_TEST_CALLS\"; exit 91",
    );
    let script = "if [ \"$1\" = unreadable ]; then if [ -x /etc/systemd/system/irlumed.service.d ]; then echo 'fixture is searchable' >&2; exit 93; fi; echo UNREADABLE_CONFIRMED; fi; if [ \"$3\" = bare ]; then exec \"$2\" logs debug; else exec \"$2\" logs debug status; fi";
    let template = support::isolated_root_command(
        &sandbox.root,
        "/bin/sh",
        &["-c", script, "status-test", mode, BIN, action],
        &["systemctl"],
        &[],
        &[(&system, "/etc/systemd/system")],
    );
    let mut command = Command::new(template.get_program());
    // Drop DAC bypass even on a root-run test host. The same private namespace
    // and coverage collection as other CLI fixtures remain in use.
    command
        .args(["--cap-drop", "ALL"])
        .args(template.get_args())
        .env("IRLUME_TEST_CALLS", sandbox.path("calls"))
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped());
    for (key, value) in template.get_envs() {
        match value {
            Some(value) => {
                command.env(key, value);
            }
            None => {
                command.env_remove(key);
            }
        }
    }
    let result = run(&mut command, "logs debug status");
    assert!(
        !sandbox.path("calls").exists(),
        "status must not run systemctl"
    );
    if mode == "unreadable" {
        assert!(
            result.1.contains("UNREADABLE_CONFIRMED"),
            "{}\n{}",
            result.1,
            result.2
        );
    }
    result
}

#[test]
fn debug_status_known_presence_and_absence_remain_read_only() {
    for action in ["bare", "status"] {
        for mode in ["present", "absent"] {
            let (code, stdout, stderr) = status(mode, action);
            assert_eq!(code, 0, "{stdout}\n{stderr}");
            assert!(stdout.contains(if mode == "present" {
                "daemon diagnostic tracing: ON (drop-in present)"
            } else {
                "daemon diagnostic tracing: off"
            }));
        }
    }
}

fn assert_unknown(action: &str) {
    let (code, stdout, stderr) = status("unreadable", action);
    assert!(stdout.contains("unknown"), "{stdout}\n{stderr}");
    assert!(!stdout.contains("daemon diagnostic tracing: off"));
    assert!(!stdout.contains("toggle: sudo irlume logs debug on"));
    assert!(stdout.contains("sudo irlume logs debug status"));
    assert_eq!(code, 1);
}

#[test]
fn debug_status_unknown_bare_is_not_off() {
    assert_unknown("bare");
}

#[test]
fn debug_status_unknown_explicit_is_not_off() {
    assert_unknown("status");
}

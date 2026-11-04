// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright the irlume contributors.

use super::{run, support, Sandbox, BIN};
use irlume_common::Request;
use std::io::{BufRead as _, Write as _};
use std::os::unix::net::UnixListener;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::Duration;

const STATE_QUERY: &str = "show --property=ActiveState --value irlumed.service";

struct PingServer {
    done: Arc<AtomicBool>,
    pings: Arc<AtomicUsize>,
    thread: Option<std::thread::JoinHandle<()>>,
}

impl PingServer {
    fn start(sandbox: &Sandbox) -> Self {
        let listener = UnixListener::bind(sandbox.sock()).unwrap();
        listener.set_nonblocking(true).unwrap();
        let done = Arc::new(AtomicBool::new(false));
        let pings = Arc::new(AtomicUsize::new(0));
        let (stopped, count) = (done.clone(), pings.clone());
        let thread = std::thread::spawn(move || {
            while !stopped.load(Ordering::Relaxed) {
                match listener.accept() {
                    Ok((mut stream, _)) => {
                        stream
                            .set_read_timeout(Some(Duration::from_secs(2)))
                            .unwrap();
                        let mut line = String::new();
                        std::io::BufReader::new(&stream)
                            .read_line(&mut line)
                            .unwrap();
                        assert!(matches!(
                            serde_json::from_str::<Request>(&line).unwrap(),
                            Request::Ping
                        ));
                        count.fetch_add(1, Ordering::Relaxed);
                        stream.write_all(b"\"Pong\"\n").unwrap();
                    }
                    Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                        std::thread::sleep(Duration::from_millis(5));
                    }
                    Err(error) => panic!("fake Ping listener: {error}"),
                }
            }
        });
        Self {
            done,
            pings,
            thread: Some(thread),
        }
    }
}

impl Drop for PingServer {
    fn drop(&mut self) {
        self.done.store(true, Ordering::Relaxed);
        if let Some(thread) = self.thread.take() {
            let result = thread.join();
            if !std::thread::panicking() {
                result.unwrap();
            }
        }
    }
}

fn systemctl(sandbox: &Sandbox, failure: &str) {
    systemctl_state(sandbox, failure, "active");
}

fn systemctl_state(sandbox: &Sandbox, failure: &str, state: &str) {
    sandbox.fake_tool("systemctl", &format!(
        "printf '%s\\n' \"$*\" >> \"$IRLUME_TEST_CALLS\"\nif [ \"$1\" = '{failure}' ]; then exit 7; fi\nif [ \"$1\" = show ]; then printf '%s\\n' '{state}'; fi\nexit 0"
    ));
}

fn toggle(sandbox: &Sandbox, action: &str, have_systemctl: bool) -> (i32, String, String) {
    let system = sandbox.path("system");
    std::fs::create_dir_all(&system).unwrap();
    let tools = if have_systemctl {
        &["systemctl"][..]
    } else {
        &[]
    };
    let mut command = support::isolated_root_command(
        &sandbox.root,
        BIN,
        &["logs", "debug", action],
        tools,
        &[],
        &[(&system, "/etc/systemd/system")],
    );
    command.env("IRLUME_TEST_CALLS", sandbox.path("calls"));
    run(&mut command, "logs debug")
}

fn calls(sandbox: &Sandbox) -> Vec<String> {
    std::fs::read_to_string(sandbox.path("calls"))
        .unwrap_or_default()
        .lines()
        .map(str::to_owned)
        .collect()
}

fn existing_dropin(sandbox: &Sandbox) {
    let directory = sandbox.path("system/irlumed.service.d");
    std::fs::create_dir_all(&directory).unwrap();
    std::fs::write(
        directory.join("50-irlume-debug.conf"),
        "[Service]\nEnvironment=IRLUME_LOG=debug\n",
    )
    .unwrap();
}

#[test]
fn debug_toggle_success_waits_for_serving_and_preserves_try_restart() {
    for action in ["on", "off"] {
        let sandbox = Sandbox::new(&format!("debug-success-{action}"));
        if action == "off" {
            existing_dropin(&sandbox);
        }
        systemctl(&sandbox, "never");
        let server = PingServer::start(&sandbox);
        let (code, stdout, stderr) = toggle(&sandbox, action, true);
        assert_eq!(code, 0, "{stderr}");
        assert!(stdout.contains("daemon serving again"));
        assert_eq!(
            calls(&sandbox),
            ["daemon-reload", "try-restart irlumed.service", STATE_QUERY]
        );
        assert!(server.pings.load(Ordering::Relaxed) > 0);
    }
}

#[test]
fn debug_reload_failure_stops_before_restart_and_ping() {
    let sandbox = Sandbox::new("debug-reload-failed");
    systemctl(&sandbox, "daemon-reload");
    let server = PingServer::start(&sandbox);
    let (code, stdout, stderr) = toggle(&sandbox, "on", true);
    assert_eq!(code, 1, "{stdout}\n{stderr}");
    assert!(stderr.contains("daemon-reload"));
    assert!(!stdout.contains("tracing ON"));
    assert!(stderr.contains("configuration saved"));
    assert!(stderr.contains("runtime tracing is unconfirmed"));
    assert!(stderr.contains("Retry: sudo irlume logs debug on"));
    assert!(
        std::fs::read_to_string(sandbox.path("system/irlumed.service.d/50-irlume-debug.conf"))
            .unwrap()
            .contains("Environment=IRLUME_LOG=debug")
    );
    assert_eq!(calls(&sandbox), ["daemon-reload"]);
    assert_eq!(server.pings.load(Ordering::Relaxed), 0);
}

#[test]
fn debug_restart_failure_never_claims_application() {
    for action in ["on", "off"] {
        let sandbox = Sandbox::new(&format!("debug-restart-failed-{action}"));
        if action == "off" {
            existing_dropin(&sandbox);
        }
        systemctl(&sandbox, "try-restart");
        let server = PingServer::start(&sandbox);
        let (code, stdout, stderr) = toggle(&sandbox, action, true);
        assert_eq!(code, 1, "{stdout}\n{stderr}");
        assert!(stderr.contains("try-restart"));
        assert!(!stdout.contains("tracing ON") && !stdout.contains("tracing off"));
        assert!(stderr.contains(&format!("Retry: sudo irlume logs debug {action}")));
        assert_eq!(
            sandbox
                .path("system/irlumed.service.d/50-irlume-debug.conf")
                .exists(),
            action == "on"
        );
        assert_eq!(
            calls(&sandbox),
            ["daemon-reload", "try-restart irlumed.service"]
        );
        assert_eq!(server.pings.load(Ordering::Relaxed), 0);
    }
}

#[test]
fn debug_missing_systemctl_is_application_failure() {
    let sandbox = Sandbox::new("debug-command-missing");
    let server = PingServer::start(&sandbox);
    let (code, stdout, stderr) = toggle(&sandbox, "on", false);
    assert_eq!(code, 1, "{stdout}\n{stderr}");
    assert!(stderr.contains("systemctl"));
    assert!(!stdout.contains("tracing ON"));
    assert_eq!(server.pings.load(Ordering::Relaxed), 0);
}

#[test]
fn debug_disable_retries_application_after_partial_failure() {
    let sandbox = Sandbox::new("debug-off-retry");
    existing_dropin(&sandbox);
    systemctl(&sandbox, "try-restart");
    let server = PingServer::start(&sandbox);
    let (code, _, _) = toggle(&sandbox, "off", true);
    assert_eq!(code, 1);
    assert!(!sandbox
        .path("system/irlumed.service.d/50-irlume-debug.conf")
        .exists());
    systemctl(&sandbox, "never");
    let (code, stdout, stderr) = toggle(&sandbox, "off", true);
    assert_eq!(code, 0, "{stderr}");
    assert!(stdout.contains("daemon serving again"));
    assert_eq!(
        calls(&sandbox),
        [
            "daemon-reload",
            "try-restart irlumed.service",
            "daemon-reload",
            "try-restart irlumed.service",
            STATE_QUERY,
        ]
    );
    assert!(server.pings.load(Ordering::Relaxed) > 0);
}

#[test]
fn debug_inactive_daemon_is_not_probed() {
    for action in ["on", "off"] {
        let sandbox = Sandbox::new(&format!("debug-inactive-{action}"));
        systemctl_state(&sandbox, "never", "inactive");
        // A listening socket can activate a stopped service. Even a Ping must
        // therefore be withheld when systemd reports that it is inactive.
        let server = PingServer::start(&sandbox);
        let (code, stdout, stderr) = toggle(&sandbox, action, true);
        assert_eq!(code, 0, "{stdout}\n{stderr}");
        assert_eq!(server.pings.load(Ordering::Relaxed), 0);
        assert!(stdout.contains("next start"));
        assert!(!stdout.contains("daemon serving again"));
        if action == "on" {
            assert!(stdout.contains("DENIED attempts"));
            assert!(stdout.contains("sudo irlume logs debug off"));
        }
        assert_eq!(
            calls(&sandbox),
            ["daemon-reload", "try-restart irlumed.service", STATE_QUERY]
        );
    }
}

#[test]
fn debug_state_inspection_failure_does_not_ping() {
    let sandbox = Sandbox::new("debug-state-failed");
    systemctl(&sandbox, "show");
    let server = PingServer::start(&sandbox);
    let (code, stdout, stderr) = toggle(&sandbox, "on", true);
    assert_eq!(code, 1, "{stdout}\n{stderr}");
    assert!(stderr.contains("systemctl show"));
    assert_eq!(server.pings.load(Ordering::Relaxed), 0);
}

#[test]
fn debug_unconfirmed_service_states_do_not_ping() {
    for state in [
        "failed",
        "deactivating",
        "unknown-state",
        "",
        "active\ninactive",
    ] {
        let sandbox = Sandbox::new(&format!("debug-state-{state}"));
        systemctl_state(&sandbox, "never", state);
        let server = PingServer::start(&sandbox);
        let (code, stdout, stderr) = toggle(&sandbox, "on", true);
        assert_eq!(code, 1, "{stdout}\n{stderr}");
        assert!(stderr.contains("unconfirmed"));
        assert_eq!(server.pings.load(Ordering::Relaxed), 0);
    }
}

#[test]
fn debug_remove_error_stops_before_service_commands() {
    let sandbox = Sandbox::new("debug-remove-error");
    let dropin = sandbox.path("system/irlumed.service.d/50-irlume-debug.conf");
    std::fs::create_dir_all(&dropin).unwrap();
    systemctl(&sandbox, "never");
    let server = PingServer::start(&sandbox);
    let (code, stdout, stderr) = toggle(&sandbox, "off", true);
    assert_eq!(code, 1, "{stdout}\n{stderr}");
    assert!(stderr.contains("could not remove"));
    assert!(dropin.is_dir());
    assert!(calls(&sandbox).is_empty());
    assert_eq!(server.pings.load(Ordering::Relaxed), 0);
}

#[test]
fn debug_active_transition_states_wait_for_serving() {
    for state in ["activating", "reloading"] {
        let sandbox = Sandbox::new(&format!("debug-transition-{state}"));
        systemctl_state(&sandbox, "never", state);
        let server = PingServer::start(&sandbox);
        let (code, stdout, stderr) = toggle(&sandbox, "on", true);
        assert_eq!(code, 0, "{stdout}\n{stderr}");
        assert!(stdout.contains("daemon serving again"));
        assert!(server.pings.load(Ordering::Relaxed) > 0);
    }
}

#[test]
fn debug_invalid_utf8_state_is_not_probed() {
    let sandbox = Sandbox::new("debug-state-invalid-utf8");
    sandbox.fake_tool(
        "systemctl",
        "if [ \"$1\" = show ]; then printf '\\377'; fi; exit 0",
    );
    let server = PingServer::start(&sandbox);
    let (code, stdout, stderr) = toggle(&sandbox, "on", true);
    assert_eq!(code, 1, "{stdout}\n{stderr}");
    assert!(stderr.contains("invalid service state"));
    assert_eq!(server.pings.load(Ordering::Relaxed), 0);
}

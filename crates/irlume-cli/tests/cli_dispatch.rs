// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright the irlume contributors.

//! Black-box tests for the `irlume` binary's dispatch / usage / error arms that
//! `tests/cli.rs` does not already reach. These target the `ExitCode`-returning
//! branches that a unit test cannot assert (`std::process::ExitCode` is not
//! `PartialEq`) but a real process spawn can: exit code + stdout/stderr
//! substrings drawn verbatim from the subcommands' own source strings.
//!
//! The gap `cli.rs` leaves is the daemon-DRIVEN branches: the `Response::Error`
//! and unexpected-response arms of each command, and the state-dependent
//! rendering arms of `status` / `diag` / `identify` / `setup`. Every one is
//! reached by pointing the CLI at a per-test fake `irlumed` (a `UnixListener`
//! speaking the real line-JSON `Request`/`Response` protocol) that returns the
//! exact canned answer the arm expects.
//!
//! Isolation is identical to `cli.rs`: `IRLUME_SOCKET` / `IRLUME_CONFIG_DIR` /
//! `IRLUME_STATE_DIR` / `IRLUME_KEYRING_DIR` / `IRLUME_METHOD_CONF` all point
//! into a per-test temp tree, shelled-out tools are PATH-shadowed with fakes,
//! and nothing touches the network, a camera, the TPM, root, or the machine's
//! package database. Every spawn is watchdogged: a child that has not exited
//! after 30s is killed and the test fails, naming the command.

use std::io::{Read as _, Write as _};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

use irlume_common::{ProfileSummary, Request, Response};

const BIN: &str = env!("CARGO_BIN_EXE_irlume");
const SPAWN_TIMEOUT: Duration = Duration::from_secs(30);

fn is_root() -> bool {
    #[expect(clippy::undocumented_unsafe_blocks, reason = "doc backlog")]
    unsafe {
        libc::geteuid() == 0
    }
}

/// Per-test sandbox tree; deleted when the test ends.
struct Sandbox {
    root: PathBuf,
}

impl Sandbox {
    fn new(tag: &str) -> Self {
        let root = std::env::temp_dir().join(format!(
            "irlume-cli-disp-{tag}-{}-{:?}",
            std::process::id(),
            std::thread::current().id()
        ));
        let _ = std::fs::remove_dir_all(&root);
        for d in ["cfg", "state", "keyring", "bin", "work"] {
            std::fs::create_dir_all(root.join(d)).unwrap();
        }
        Sandbox { root }
    }

    fn path(&self, rel: &str) -> PathBuf {
        self.root.join(rel)
    }

    fn sock(&self) -> PathBuf {
        self.root.join("no-daemon.sock")
    }

    /// Drop a fake `#!/bin/sh` executable into the sandbox bin dir.
    fn fake_tool(&self, name: &str, body: &str) {
        use std::os::unix::fs::PermissionsExt;
        let p = self.root.join("bin").join(name);
        std::fs::write(&p, format!("#!/bin/sh\n{body}\n")).unwrap();
        std::fs::set_permissions(&p, std::fs::Permissions::from_mode(0o755)).unwrap();
    }

    /// A Command for the irlume binary, isolated from the host system.
    fn cmd(&self, args: &[&str]) -> Command {
        let mut c = Command::new(BIN);
        c.args(args)
            .env("IRLUME_SOCKET", self.sock())
            .env("IRLUME_CONFIG_DIR", self.root.join("cfg"))
            .env("IRLUME_STATE_DIR", self.root.join("state"))
            .env("IRLUME_KEYRING_DIR", self.root.join("keyring"))
            .env("IRLUME_METHOD_CONF", self.root.join("cfg").join("method"))
            .env_remove("IRLUME_DEV")
            .env_remove("IRLUME_CONSENT_GESTURE")
            .env_remove("ORT_DYLIB_PATH")
            .env_remove("IRLUME_MODEL")
            .env_remove("IRLUME_DET_MODEL")
            .current_dir(self.root.join("work"))
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        c
    }

    /// Like `cmd`, but with the sandbox bin dir prepended to PATH so fake tools
    /// shadow the real ones.
    fn cmd_with_fakes(&self, args: &[&str]) -> Command {
        let mut c = self.cmd(args);
        c.env(
            "PATH",
            format!(
                "{}:{}",
                self.root.join("bin").display(),
                std::env::var("PATH").unwrap_or_default()
            ),
        );
        c
    }
}

impl Drop for Sandbox {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.root);
    }
}

/// Drain a spawned child under a 30s watchdog. stdout/stderr are read on their
/// own threads so a full pipe buffer can never deadlock the wait, and a child
/// that overruns the deadline is killed and the test fails naming the command.
fn drive(mut child: Child, desc: &str) -> (i32, String, String) {
    let mut so = child.stdout.take().expect("piped stdout");
    let mut se = child.stderr.take().expect("piped stderr");
    let ho = std::thread::spawn(move || {
        let mut s = String::new();
        let _ = so.read_to_string(&mut s);
        s
    });
    let he = std::thread::spawn(move || {
        let mut s = String::new();
        let _ = se.read_to_string(&mut s);
        s
    });
    let start = Instant::now();
    let status = loop {
        match child.try_wait().expect("try_wait irlume") {
            Some(st) => break st,
            None => {
                if start.elapsed() > SPAWN_TIMEOUT {
                    let _ = child.kill();
                    let _ = child.wait();
                    panic!("TIMEOUT: `irlume {desc}` did not exit within {SPAWN_TIMEOUT:?}");
                }
                std::thread::sleep(Duration::from_millis(20));
            }
        }
    };
    let out = ho.join().unwrap_or_default();
    let err = he.join().unwrap_or_default();
    (
        status
            .code()
            .unwrap_or_else(|| panic!("`irlume {desc}` died from a signal")),
        out,
        err,
    )
}

/// Run and collect (exit code, stdout, stderr).
fn run(cmd: &mut Command, desc: &str) -> (i32, String, String) {
    let child = cmd.spawn().expect("spawn irlume");
    drive(child, desc)
}

/// Run with `input` piped to stdin.
fn run_stdin(cmd: &mut Command, input: &str, desc: &str) -> (i32, String, String) {
    let mut child = cmd.stdin(Stdio::piped()).spawn().expect("spawn irlume");
    child
        .stdin
        .take()
        .unwrap()
        .write_all(input.as_bytes())
        .unwrap();
    drive(child, desc)
}

/// Serve canned responses on `sock` (one request per connection, the same
/// line-JSON protocol `irlumed` speaks). The accept thread is detached; it ends
/// with the test process and the socket lives in the sandbox (deleted on drop).
fn serve(sock: &Path, respond: impl Fn(&Request) -> Response + Send + 'static) {
    use std::io::{BufRead, BufReader};
    let _ = std::fs::remove_file(sock);
    let listener = std::os::unix::net::UnixListener::bind(sock).unwrap();
    std::thread::spawn(move || {
        for stream in listener.incoming() {
            let Ok(stream) = stream else { break };
            let mut line = String::new();
            if BufReader::new(&stream).read_line(&mut line).is_err() {
                continue;
            }
            let Ok(req) = serde_json::from_str::<Request>(&line) else {
                continue;
            };
            let mut reply = serde_json::to_string(&respond(&req)).unwrap();
            reply.push('\n');
            let _ = (&stream).write_all(reply.as_bytes());
        }
    });
}

fn one_profile() -> Vec<ProfileSummary> {
    vec![ProfileSummary {
        name: "Face Profile 1".into(),
        scans: vec!["Scan 1".into(), "Scan 2".into()],
        scans_by_recognizer: Default::default(),
        live_recognizer: None,
    }]
}

fn write_test_seal_without_pcr_snapshot(path: &Path) {
    use irlume_core::envelope::{PolicyKind, SealedEnvelope, SecretKind, CURRENT_VERSION};

    std::fs::create_dir_all(path.parent().expect("test seal has a parent")).unwrap();
    let envelope = SealedEnvelope {
        version: CURRENT_VERSION,
        policy: PolicyKind::PcrLiteral,
        secret: SecretKind::LoginPassword,
        pcrs: vec![7],
        public: vec![1, 2, 3],
        private: vec![4, 5, 6],
        pcr_values: Vec::new(),
        password_wrap: None,
    };
    std::fs::write(path, serde_json::to_vec(&envelope).unwrap()).unwrap();
}

// ---------------------------------------------------------------- status arms

// status renders one arm per daemon answer; cli.rs pins the all-green dashboard,
// so these pin the OTHER branches: a legacy eyes-open blocker, an un-armed
// KeyringInfo, plaintext/not-set recovery, and the opt-in biopolicy gate ON.
#[test]
fn status_eyes_open_unarmed_plaintext_and_biopolicy_enforcing() {
    let sb = Sandbox::new("statusA");
    std::fs::write(sb.path("cfg/settings.conf"), "enforce_biopolicy=1\n").unwrap();
    serve(&sb.sock(), |req| match req {
        Request::Ping => Response::Pong,
        Request::ListProfiles { .. } => Response::Enrollment {
            profiles: one_profile(),
            require_eyes_open: true,
            closure_calibrated: false,
            ir_ratio_calibrated: false,
        },
        Request::KeyringInfo { .. } => Response::KeyringInfo {
            armed: false,
            policy: None,
            pcrs: vec![],
            drifted: None,
            kind: None,
        },
        Request::RecoveryStatus { .. } => Response::RecoveryStatus {
            encrypted: false,
            recovery_set: false,
            tpm_present: true,
            key_present: false,
        },
        _ => Response::Error("unexpected request".into()),
    });
    let (code, out, _) = run(&mut sb.cmd(&["status", "--user", "tester"]), "status");
    assert_eq!(code, 0, "status always reports, never gates");
    assert!(out.contains("daemon        : running"), "{out}");
    assert!(
        out.contains("legacy policy blocks authentication")
            && out.contains("sudo irlume profiles eyes-open off --user 'tester'"),
        "{out}"
    );
    assert!(out.contains("keyring unlock: not armed"), "{out}");
    assert!(out.contains("templates     : plaintext"), "{out}");
    assert!(out.contains("recovery pass : not set"), "{out}");
    assert!(out.contains("biopolicy     : ENFORCING"), "{out}");
}

#[test]
fn status_empty_legacy_enrollment_keeps_the_targeted_cleanup() {
    let sb = Sandbox::new("status-empty-legacy");
    serve(&sb.sock(), |req| match req {
        Request::Ping => Response::Pong,
        Request::ListProfiles { .. } => Response::Enrollment {
            profiles: Vec::new(),
            require_eyes_open: true,
            closure_calibrated: false,
            ir_ratio_calibrated: false,
        },
        Request::KeyringInfo { .. } => Response::KeyringInfo {
            armed: false,
            policy: None,
            pcrs: vec![],
            drifted: None,
            kind: None,
        },
        Request::RecoveryStatus { .. } => Response::RecoveryStatus {
            encrypted: false,
            recovery_set: false,
            tpm_present: true,
            key_present: false,
        },
        _ => Response::Error("unexpected request".into()),
    });

    let (code, out, _) = run(
        &mut sb.cmd(&["status", "--user", "tester"]),
        "status-empty-legacy",
    );
    assert_eq!(code, 0, "status always reports");
    assert!(out.contains("enrollment    : none"), "{out}");
    assert!(
        out.contains("legacy policy blocks authentication")
            && out.contains("sudo irlume profiles eyes-open off --user 'tester'"),
        "{out}"
    );
}

// The credential-release challenge command: DEFAULT-OFF reporting, the root gate,
// and the global toggle. Off is the default (a greeter cold login and logout
// release the keyring with no nod), so neither direction confirms or warns; the
// exact strings a user acts on are pinned here.
#[test]
fn credential_release_challenge_reports_defaults_and_toggles() {
    let sb = Sandbox::new("crc");
    let cfg = sb.path("cfg/settings.conf");
    let cmd = "credential-release-challenge";

    // No settings.conf at all: defaults shown, and status never fails.
    let (code, out, _) = run(&mut sb.cmd(&[cmd, "status"]), cmd);
    assert_eq!(code, 0);
    assert!(out.contains("sudo: REQUIRED"), "{out}");
    assert!(out.contains("polkit-1: REQUIRED"), "{out}");
    assert!(out.contains("credential_release: off (default)"), "{out}");
    assert!(
        out.contains("global credential_release_challenge: off (default)"),
        "{out}"
    );

    // No subcommand behaves as status (same as `irlume biopolicy`).
    let (code, out, _) = run(&mut sb.cmd(&[cmd]), cmd);
    assert_eq!(code, 0);
    assert!(out.contains("sudo:"), "{out}");

    // The per-service status form, still with no settings.conf. The usage
    // line has always promised `[<service>] <on|off|status>`, and the TUI,
    // setup and doctor all teach it, but the parser accepted only
    // `<svc> on|off`: the exact command four surfaces recommended exited 2.
    let (code, out, _) = run(&mut sb.cmd(&[cmd, "sudo", "status"]), cmd);
    assert_eq!(code, 0, "the taught per-service form must work: {out}");
    assert!(out.contains("sudo: REQUIRED"), "{out}");
    assert!(
        !out.contains("polkit-1:"),
        "one service asked, one service answered: {out}"
    );
    // A service without a verb is still a usage error, not a guess.
    let (code, _, err) = run(&mut sb.cmd(&[cmd, "sudo"]), cmd);
    assert_eq!(code, 2, "{err}");

    // Opted IN globally: the global state and the keyring line show REQUIRED.
    std::fs::write(&cfg, "credential_release_challenge=1\n").unwrap();
    let (code, out, _) = run(&mut sb.cmd(&[cmd, "status"]), cmd);
    assert_eq!(code, 0);
    assert!(
        out.contains("global credential_release_challenge: REQUIRED"),
        "{out}"
    );
    assert!(out.contains("credential_release: REQUIRED"), "{out}");

    // An unrecognized value reads as the default (off), not on.
    std::fs::write(&cfg, "credential_release_challenge=enabled\n").unwrap();
    let (_, out, _) = run(&mut sb.cmd(&[cmd, "status"]), cmd);
    assert!(
        out.contains("global credential_release_challenge: off (default)"),
        "a typo must read as the default (off):\n{out}"
    );

    // Bad subcommand: usage, exit 2, and nothing written.
    let (code, _, err) = run(&mut sb.cmd(&[cmd, "maybe"]), cmd);
    assert_eq!(code, 2);
    assert!(
        err.contains("usage: irlume credential-release-challenge"),
        "{err}"
    );

    if !is_root() {
        // Writing needs root, and says the command to re-run.
        for v in ["on", "off"] {
            let (code, _, err) = run(&mut sb.cmd(&[cmd, v]), cmd);
            assert_eq!(code, 1, "{v} must refuse without root");
            assert!(
                err.contains(&format!("sudo irlume credential-release-challenge {v}")),
                "{err}"
            );
        }
        // The refusal must not have touched the file.
        assert!(
            std::fs::read_to_string(&cfg).unwrap().contains("=enabled"),
            "a refused write must leave settings.conf alone"
        );
        return;
    }

    // Running as root (containerized CI): the global toggle needs no confirm in
    // either direction. `on` adds the opt-in gesture; `off` returns to the default.
    let (code, out, _) = run(&mut sb.cmd(&[cmd, "on"]), cmd);
    assert_eq!(code, 0);
    assert!(out.contains("REQUIRED") && out.contains("nod"), "{out}");
    assert!(std::fs::read_to_string(&cfg).unwrap().contains("=1"));

    let (code, out, _) = run(&mut sb.cmd(&[cmd, "off"]), cmd);
    assert_eq!(code, 0);
    assert!(out.contains("off (the default)"), "{out}");
    assert!(std::fs::read_to_string(&cfg).unwrap().contains("=0"));
}

#[test]
fn credential_release_status_names_the_winning_gesture_migration_source() {
    let sb = Sandbox::new("crc-source");
    let cfg = sb.path("cfg/settings.conf");
    let cmd = "credential-release-challenge";

    for (value, expected) in [
        (
            "closure",
            "cannot approve: eye closure is retired; remove consent_gesture from settings.conf or set it to nod",
        ),
        (
            "banana",
            "cannot approve: consent_gesture is invalid; remove consent_gesture from settings.conf or set it to nod",
        ),
    ] {
        std::fs::write(&cfg, format!("consent_gesture={value}\n")).unwrap();
        let (code, out, err) = run(&mut sb.cmd(&[cmd, "status"]), cmd);
        assert_eq!(code, 0, "{err}");
        assert!(out.contains(expected), "{value}: {out}");
        assert!(!out.contains("unset IRLUME_CONSENT_GESTURE"), "{out}");
        if value == "banana" {
            assert!(!err.contains(value), "arbitrary value was echoed: {err}");
        }
    }

    std::fs::write(&cfg, "consent_gesture=nod\n").unwrap();
    for (value, expected) in [
        (
            "closure",
            "cannot approve: eye closure is retired; unset IRLUME_CONSENT_GESTURE or set it to nod",
        ),
        (
            "banana",
            "cannot approve: consent_gesture is invalid; unset IRLUME_CONSENT_GESTURE or set it to nod",
        ),
    ] {
        let (code, out, err) = run(
            sb.cmd(&[cmd, "status"])
                .env("IRLUME_CONSENT_GESTURE", value),
            cmd,
        );
        assert_eq!(code, 0, "{err}");
        assert!(out.contains(expected), "{value}: {out}");
        assert!(!out.contains("from settings.conf"), "{out}");
        if value == "banana" {
            assert!(!err.contains(value), "arbitrary value was echoed: {err}");
        }
    }
}

// enrollment-query error is a distinct arm from "none"/populated; and when the
// daemon can't answer KeyringInfo, status falls back to the plain armed bit.
#[test]
fn status_enrollment_error_and_keyring_fallback_armed() {
    let sb = Sandbox::new("statusB");
    serve(&sb.sock(), |req| match req {
        Request::Ping => Response::Pong,
        Request::ListProfiles { .. } => Response::Error("db locked".into()),
        // KeyringInfo unsupported (older daemon) -> status retries HasSealedPassword.
        Request::KeyringInfo { .. } => Response::Error("no such request".into()),
        Request::HasSealedPassword { .. } => Response::HasPassword(true),
        _ => Response::Error("unexpected request".into()),
    });
    let (code, out, _) = run(&mut sb.cmd(&["status", "--user", "tester"]), "status");
    assert_eq!(code, 0);
    assert!(out.contains("enrollment    : error: db locked"), "{out}");
    assert!(
        out.contains("keyring unlock: armed"),
        "the KeyringInfo->HasSealedPassword fallback must render armed: {out}"
    );
}

// The "none enrolled" enrollment arm, plus the fallback rendering "not armed".
#[test]
fn status_enrollment_none_and_keyring_fallback_not_armed() {
    let sb = Sandbox::new("statusC");
    serve(&sb.sock(), |req| match req {
        Request::Ping => Response::Pong,
        Request::ListProfiles { .. } => Response::Enrollment {
            profiles: Vec::new(),
            require_eyes_open: false,
            closure_calibrated: false,
            ir_ratio_calibrated: false,
        },
        Request::KeyringInfo { .. } => Response::Error("no such request".into()),
        Request::HasSealedPassword { .. } => Response::HasPassword(false),
        _ => Response::Error("unexpected request".into()),
    });
    let (code, out, _) = run(&mut sb.cmd(&["status", "--user", "tester"]), "status");
    assert_eq!(code, 0);
    assert!(out.contains("enrollment    : none"), "{out}");
    assert!(out.contains("keyring unlock: not armed"), "{out}");
}

// --------------------------------------------------------------- identify arms

// cli.rs covers a match and a live-but-unenrolled miss; these are the remaining
// arms: a NON-live capture, and the daemon returning an error.
#[test]
fn identify_no_live_face_and_daemon_error() {
    let sb = Sandbox::new("identnolive");
    serve(&sb.sock(), |_| Response::Identified {
        user: None,
        profile: None,
        score: 0.0,
        live: false,
        reason: "no face in frame".into(),
    });
    let (code, out, _) = run(&mut sb.cmd(&["identify"]), "identify");
    assert_eq!(code, 1, "no live face is a non-match (exit 1)");
    assert!(
        out.contains("no match: no live face (no face in frame)"),
        "{out}"
    );

    let sb2 = Sandbox::new("identerr");
    serve(&sb2.sock(), |_| Response::Error("engine offline".into()));
    let (code, _, err) = run(&mut sb2.cmd(&["identify"]), "identify");
    assert_eq!(code, 1);
    assert!(err.contains("[identify] error: engine offline"), "{err}");
}

// ------------------------------------------------------------------- diag arms

// With neither root-only envelope readable in the sandbox but a reachable
// daemon, diag must name the keyring and template-key seals independently.
// Collapsing them back into one generic "seal envelope" row recreates #472:
// a healthy keyring seal can hide the broken template seal that face auth uses.
#[test]
fn diag_reports_both_seals_from_daemon_when_envelopes_are_unreadable() {
    let sb = Sandbox::new("diagarmed");
    serve(&sb.sock(), |request| match request {
        Request::HasSealedPassword { .. } => Response::HasPassword(true),
        Request::RecoveryStatus { .. } => Response::RecoveryStatus {
            encrypted: true,
            recovery_set: true,
            tpm_present: true,
            key_present: true,
        },
        _ => Response::Error("unexpected request".into()),
    });
    let (code, out, _) = run(&mut sb.cmd(&["diag", "--user", "tester"]), "diag");
    assert_eq!(code, 0);
    assert!(out.contains("irlume diag for 'tester'"), "{out}");
    assert!(
        out.contains("keyring seal  : armed, but not readable here"),
        "{out}"
    );
    assert!(
        out.contains("template seal : sealed, but not readable here"),
        "{out}"
    );

    let sb2 = Sandbox::new("diagunarmed");
    serve(&sb2.sock(), |request| match request {
        Request::HasSealedPassword { .. } => Response::HasPassword(false),
        Request::RecoveryStatus { .. } => Response::RecoveryStatus {
            encrypted: false,
            recovery_set: false,
            tpm_present: true,
            key_present: false,
        },
        _ => Response::Error("unexpected request".into()),
    });
    let (code, out, _) = run(&mut sb2.cmd(&["diag", "--user", "tester"]), "diag");
    assert_eq!(code, 0);
    assert!(out.contains("keyring seal  : not armed"), "{out}");
    assert!(
        out.contains("template seal : not present (templates are plaintext at rest)"),
        "{out}"
    );
}

#[test]
fn diag_reports_keyring_and_template_states_independently() {
    let armed_keyring = Sandbox::new("diag-keyring-only");
    serve(&armed_keyring.sock(), |request| match request {
        Request::HasSealedPassword { .. } => Response::HasPassword(true),
        Request::RecoveryStatus { .. } => Response::RecoveryStatus {
            encrypted: true,
            recovery_set: false,
            tpm_present: true,
            key_present: false,
        },
        _ => Response::Error("unexpected request".into()),
    });
    let (code, out, _) = run(
        &mut armed_keyring.cmd(&["diag", "--user", "tester"]),
        "diag",
    );
    assert_eq!(code, 0);
    assert!(out.contains("keyring seal  : armed"), "{out}");
    assert!(out.contains("template seal : MISSING ✗"), "{out}");

    let sealed_template = Sandbox::new("diag-template-only");
    serve(&sealed_template.sock(), |request| match request {
        Request::HasSealedPassword { .. } => Response::HasPassword(false),
        Request::RecoveryStatus { .. } => Response::RecoveryStatus {
            encrypted: true,
            recovery_set: true,
            tpm_present: true,
            key_present: true,
        },
        _ => Response::Error("unexpected request".into()),
    });
    let (code, out, _) = run(
        &mut sealed_template.cmd(&["diag", "--user", "tester"]),
        "diag",
    );
    assert_eq!(code, 0);
    assert!(out.contains("keyring seal  : not armed"), "{out}");
    assert!(
        out.contains("template seal : sealed, but not readable here"),
        "{out}"
    );
}

#[test]
fn diag_does_not_call_a_seal_healthy_without_a_recorded_pcr_snapshot() {
    let sb = Sandbox::new("diag-no-pcr-snapshot");
    write_test_seal_without_pcr_snapshot(&sb.path("keyring/tester.json"));
    write_test_seal_without_pcr_snapshot(&sb.path("state/template-keys/tester.json"));

    let (code, out, _) = run(&mut sb.cmd(&["diag", "--user", "tester"]), "diag");

    assert_eq!(code, 0);
    assert!(out.contains("keyring seal  :"), "{out}");
    assert!(out.contains("template seal :"), "{out}");
    assert_eq!(
        out.matches(
            "PCR drift   : unknown ⚠ (envelope has no recorded PCR snapshot; unseal was not tested)"
        )
        .count(),
        2,
        "{out}"
    );
    assert!(!out.contains("can unseal"), "{out}");
}

#[test]
fn diag_reports_malformed_envelopes_as_corrupt_instead_of_falling_back() {
    let sb = Sandbox::new("diag-corrupt-envelopes");
    std::fs::write(sb.path("keyring/tester.json"), b"{not-json").unwrap();
    std::fs::create_dir_all(sb.path("state/template-keys")).unwrap();
    std::fs::write(
        sb.path("state/template-keys/tester.json"),
        b"{also-not-json",
    )
    .unwrap();

    let (code, out, _) = run(&mut sb.cmd(&["diag", "--user", "tester"]), "diag");

    assert_eq!(code, 0);
    assert!(
        out.contains(
            "keyring seal  : CORRUPT ✗ (envelope JSON is malformed; preserve the file and do not force-forget it)"
        ),
        "{out}"
    );
    assert!(
        out.contains(
            "template seal : CORRUPT ✗ (envelope JSON is malformed; preserve the file; run `irlume recovery restore` if a recovery passphrase was set, otherwise re-enroll)"
        ),
        "{out}"
    );
    assert!(!out.contains("daemon unreachable"), "{out}");
}

#[test]
fn diag_reports_an_encrypted_store_with_no_template_key_as_unrecoverable() {
    let sb = Sandbox::new("diag-missing-template-key");
    serve(&sb.sock(), |request| match request {
        Request::HasSealedPassword { .. } => Response::HasPassword(false),
        Request::RecoveryStatus { .. } => Response::RecoveryStatus {
            encrypted: true,
            recovery_set: false,
            tpm_present: true,
            key_present: false,
        },
        _ => Response::Error("unexpected request".into()),
    });

    let (code, out, _) = run(&mut sb.cmd(&["diag", "--user", "tester"]), "diag");

    assert_eq!(code, 0);
    assert!(
        out.contains("template seal : MISSING ✗ (encrypted templates cannot be opened; re-enroll)"),
        "{out}"
    );
    assert!(
        !out.contains("template seal : sealed, but not readable here"),
        "{out}"
    );
}

#[test]
fn diag_reports_a_missing_template_key_as_recoverable_when_a_recovery_wrap_exists() {
    let sb = Sandbox::new("diag-recoverable-template-key");
    serve(&sb.sock(), |request| match request {
        Request::HasSealedPassword { .. } => Response::HasPassword(false),
        Request::RecoveryStatus { .. } => Response::RecoveryStatus {
            encrypted: true,
            recovery_set: true,
            tpm_present: true,
            key_present: false,
        },
        _ => Response::Error("unexpected request".into()),
    });

    let (code, out, _) = run(&mut sb.cmd(&["diag", "--user", "tester"]), "diag");

    assert_eq!(code, 0);
    assert!(
        out.contains("template seal : MISSING ⚠ (recoverable: run `irlume recovery restore`)"),
        "{out}"
    );
    assert!(!out.contains("re-enroll"), "{out}");
}

#[test]
fn diag_does_not_call_a_reachable_daemon_unreachable_when_its_reply_is_unexpected() {
    let sb = Sandbox::new("diag-unexpected-reply");
    serve(&sb.sock(), |_| Response::Pong);

    let (code, out, _) = run(&mut sb.cmd(&["diag", "--user", "tester"]), "diag");

    assert_eq!(code, 0);
    assert!(
        out.contains("keyring seal  : unknown (daemon returned an unexpected response)"),
        "{out}"
    );
    assert!(
        out.contains("template seal : unknown (daemon returned an unexpected response)"),
        "{out}"
    );
    assert!(!out.contains("daemon unreachable"), "{out}");
}

// ---------------------------------------------------------------- selinux load

// cli.rs covers `selinux status` + a bogus sub; this covers the `load` arm:
// the module file missing, the full success sequence, a failed semodule, and
// a failed relabel. The .pp is pinned through IRLUME_SELINUX_PP: the
// cwd-relative lookup is GONE (running `sudo irlume selinux load` from a
// directory holding a packaging/selinux/irlume.pp used to install the
// caller's file as system policy), and every tool the sequence runs is a
// fake on PATH. The first version of this test faked only semodule, so on a
// host with the packaged .pp installed it found the REAL module and drove
// the REAL systemctl through a try-restart of the host's daemon: a test
// that touches the machine it runs on is the bug, not the coverage.
#[test]
fn selinux_load_handles_missing_module_and_semodule_outcomes() {
    let sb = Sandbox::new("selinuxload");
    // No irlume.pp anywhere reachable: the not-found guard fires. Pin the
    // lookup with the env override so a host that really has the packaged
    // .pp installed (/usr/share/selinux/packages) cannot satisfy it.
    let mut miss = sb.cmd(&["selinux", "load"]);
    miss.env("IRLUME_SELINUX_PP", sb.path("does-not-exist.pp"));
    let (code, _, err) = run(&mut miss, "selinux load");
    assert_eq!(code, 1);
    assert!(err.contains("irlume.pp not found"), "{err}");

    let pp = sb.path("irlume.pp");
    std::fs::write(&pp, b"\x00").unwrap();
    let with_pp = |sb: &Sandbox| {
        let mut c = sb.cmd_with_fakes(&["selinux", "load"]);
        c.env("IRLUME_SELINUX_PP", &pp);
        c
    };

    // The whole sequence succeeds: load, restart, relabel.
    sb.fake_tool("semodule", "exit 0");
    sb.fake_tool("systemctl", "exit 0");
    sb.fake_tool("restorecon", "exit 0");
    let (code, out, _) = run(&mut with_pp(&sb), "selinux load");
    assert_eq!(code, 0);
    assert!(out.contains("loaded"), "{out}");

    // semodule fails: no success claim, and no relabel attempt behind it.
    sb.fake_tool("semodule", "exit 5");
    let (code, _, err) = run(&mut with_pp(&sb), "selinux load");
    assert_eq!(code, 1);
    assert!(err.contains("semodule exited"), "{err}");

    // The module loads but the relabel half fails: the old code claimed
    // success here (both statuses were discarded), which is the same false
    // done-report the shared sequence exists to prevent.
    sb.fake_tool("semodule", "exit 0");
    sb.fake_tool("restorecon", "exit 1");
    let (code, _, err) = run(&mut with_pp(&sb), "selinux load");
    assert_eq!(code, 1, "a failed relabel must not exit success: {err}");
    assert!(err.contains("relabel FAILED"), "{err}");
}

// ----------------------------------------------------------------- reseal arms

// cli.rs covers reseal success and the not-armed refusal. These are the armed
// paths that then go wrong: an empty piped password aborts (exit 2), and a
// nonsense seal response is reported, not trusted (exit 1).
#[test]
fn reseal_aborts_on_empty_password_and_flags_unexpected_response() {
    let sb = Sandbox::new("resealempty");
    serve(&sb.sock(), |req| match req {
        Request::HasSealedPassword { .. } => Response::HasPassword(true),
        Request::SealPassword { .. } => Response::PasswordSealed,
        _ => Response::Error("unexpected request".into()),
    });
    // Armed, but the piped password is empty -> abort before sealing.
    let (code, out, _) = run_stdin(&mut sb.cmd(&["reseal", "--user", "tester"]), "\n", "reseal");
    assert_eq!(code, 2);
    assert!(out.contains("Re-binding 'tester'"), "{out}");

    let sb2 = Sandbox::new("resealbad");
    serve(&sb2.sock(), |req| match req {
        Request::HasSealedPassword { .. } => Response::HasPassword(true),
        _ => Response::Pong, // wrong answer to SealPassword
    });
    let (code, _, err) = run_stdin(
        &mut sb2.cmd(&["reseal", "--user", "tester"]),
        "pw\n",
        "reseal",
    );
    assert_eq!(code, 1);
    assert!(err.contains("[reseal] unexpected response"), "{err}");
}

// ------------------------------------------------------------------ setup arms

// The already-enrolled branch (re-enroll prompt defaults to no on a non-tty),
// and the keyring-arm step reporting a daemon error. setup always exits 0.
#[test]
fn setup_already_enrolled_skips_reenroll_and_reports_arm_failure() {
    let sb = Sandbox::new("setupenrolled");
    serve(&sb.sock(), |req| match req {
        Request::Ping => Response::Pong,
        Request::Health => Response::Health {
            tier: "secure".into(),
            rgb_dev: None,
            ir_dev: None,
            mesh: true,
            adapter: false,
            version: env!("CARGO_PKG_VERSION").into(),
            third_party_pad: None,
            third_party_recognizer: None,
            third_party_detector: None,
            apparmor: None,
        },
        Request::ListProfiles { .. } => Response::Enrollment {
            profiles: one_profile(),
            require_eyes_open: false,
            closure_calibrated: false,
            ir_ratio_calibrated: false,
        },
        Request::SealPassword { .. } => Response::Error("tpm busy".into()),
        _ => Response::Error("unexpected request".into()),
    });
    let (code, out, err) = run_stdin(&mut sb.cmd(&["setup", "--user", "tester"]), "pw\n", "setup");
    assert_eq!(code, 0);
    assert!(out.contains("already enrolled."), "{out}");
    assert!(out.contains("[7/7] PAM login wiring"), "{out}");
    assert!(
        err.contains("arm failed"),
        "the SealPassword error must surface: {err}"
    );
}

// The not-enrolled path where enroll MERGES into an existing face (created=false)
// vs where enroll fails outright. Both are run_enroll arms cli.rs never hits
// (its setup enroll returns created=true).
#[test]
fn setup_enroll_merge_and_enroll_failure_paths() {
    let sb = Sandbox::new("setupmerge");
    serve(&sb.sock(), |req| match req {
        Request::Ping => Response::Pong,
        Request::Health => Response::Health {
            tier: "secure".into(),
            rgb_dev: None,
            ir_dev: None,
            mesh: true,
            adapter: false,
            version: env!("CARGO_PKG_VERSION").into(),
            third_party_pad: None,
            third_party_recognizer: None,
            third_party_detector: None,
            apparmor: None,
        },
        Request::ListProfiles { .. } => Response::Enrollment {
            profiles: Vec::new(),
            require_eyes_open: false,
            closure_calibrated: false,
            ir_ratio_calibrated: false,
        },
        Request::Enroll { .. } => Response::Enrolled {
            profile: "Face Profile 1".into(),
            created: false,
            added: 2,
            total: 8,
            room: Some(22),
            added_scans: Vec::new(),
            ambient_lit: None,
        },
        Request::SealPassword { .. } => Response::PasswordSealed,
        _ => Response::Error("unexpected request".into()),
    });
    let (code, out, _) = run_stdin(&mut sb.cmd(&["setup", "--user", "tester"]), "pw\n", "setup");
    assert_eq!(code, 0);
    assert!(
        out.contains("this face is already enrolled as 'Face Profile 1'"),
        "the merge arm names the existing profile: {out}"
    );
    assert!(out.contains("8 total"), "{out}");

    let sb2 = Sandbox::new("setupfail");
    serve(&sb2.sock(), |req| match req {
        Request::Ping => Response::Pong,
        Request::Health => Response::Health {
            tier: "secure".into(),
            rgb_dev: None,
            ir_dev: None,
            mesh: true,
            adapter: false,
            version: env!("CARGO_PKG_VERSION").into(),
            third_party_pad: None,
            third_party_recognizer: None,
            third_party_detector: None,
            apparmor: None,
        },
        Request::ListProfiles { .. } => Response::Enrollment {
            profiles: Vec::new(),
            require_eyes_open: false,
            closure_calibrated: false,
            ir_ratio_calibrated: false,
        },
        Request::Enroll { .. } => Response::Error("camera busy".into()),
        Request::SealPassword { .. } => Response::PasswordSealed,
        _ => Response::Error("unexpected request".into()),
    });
    let (code, _, err) = run_stdin(
        &mut sb2.cmd(&["setup", "--user", "tester"]),
        "pw\n",
        "setup",
    );
    assert_eq!(code, 0);
    assert!(err.contains("enroll failed"), "{err}");
}

// ------------------------------------------------ per-command daemon-error arms

// A daemon that answers every request with an error: each command must surface
// its own "<action> failed" / "[cmd] <err>" line and exit 1. These are the
// Ok(Response::Error(_)) arms (distinct from the dead-socket Err arms cli.rs
// already covers).
#[test]
fn daemon_error_responses_surface_per_command() {
    let sb = Sandbox::new("allerr");
    serve(&sb.sock(), |_| Response::Error("nope".into()));

    // (argv, stdin, needle in stderr)
    let cases: &[(&[&str], &str, &str)] = &[
        (&["enroll", "--user", "tester"], "", "enroll failed: nope"),
        (
            &["profiles", "list", "--user", "tester"],
            "",
            "[profiles] nope",
        ),
        (
            &["set-cameras", "/dev/video0", "/dev/video2"],
            "",
            "[set-cameras] nope",
        ),
        (&["ir-setup", "--dry-run"], "", "[ir-setup] nope"),
        (
            &["keyring", "status", "--user", "tester"],
            "",
            "status failed: nope",
        ),
        (
            &["keyring", "forget", "--user", "tester"],
            "",
            "forget failed: nope",
        ),
        (
            &["keyring", "arm", "--user", "tester"],
            "pw\n",
            "arm failed: nope",
        ),
        (
            &["recovery", "restore", "--user", "tester"],
            "pass\n",
            "restore failed: nope",
        ),
        (
            &["recovery", "forget", "--user", "tester"],
            "",
            "forget failed: nope",
        ),
    ];
    for (argv, input, needle) in cases {
        let desc = argv.join(" ");
        let (code, _, err) = if input.is_empty() {
            run(&mut sb.cmd(argv), &desc)
        } else {
            run_stdin(&mut sb.cmd(argv), input, &desc)
        };
        assert_eq!(code, 1, "`{desc}` on a daemon error must exit 1: {err}");
        assert!(err.contains(needle), "`{desc}` stderr: {err}");
    }
}

#[test]
fn forget_model_sends_the_resolved_space_over_the_wire() {
    // The CLI resolves a catalog name to its embedding-space tag; the daemon
    // only ever sees the tag. The fake daemon asserts the exact request, so a
    // resolver regression (wrong pin, name passed through raw) fails here and
    // not on a real enrollment.
    let sb = Sandbox::new("forgetwire");
    let rec = irlume_common::thirdparty::CATALOG
        .iter()
        .find(|m| m.stage == irlume_common::thirdparty::Stage::Recognition)
        .expect("the catalog carries a recognizer");
    let want = format!("embed:{}", rec.sha256);
    serve(&sb.sock(), move |req| match req {
        Request::ForgetRecognizer { user, space } if user == "tester" && *space == want => {
            Response::Ok(format!("forgot recognizer {space}: 2 scan(s) removed"))
        }
        other => Response::Error(format!("unexpected request {other:?}")),
    });
    let (code, out, err) = run(
        &mut sb.cmd(&["profiles", "forget-model", rec.name, "--user", "tester"]),
        "forget-model",
    );
    assert_eq!(code, 0, "{err}");
    assert!(out.contains("2 scan(s) removed"), "{out}");
}

// The write-side commands' unexpected-response arms (keyring arm/forget,
// recovery setup/restore/forget). cli.rs's Pong sweep does not include these.
#[test]
fn unexpected_responses_for_keyring_and_recovery_writes() {
    let sb = Sandbox::new("pongwrites");
    serve(&sb.sock(), |_| Response::Pong);
    let cases: &[(&[&str], &str)] = &[
        (&["keyring", "arm", "--user", "tester"], "pw\n"),
        (&["keyring", "forget", "--user", "tester"], ""),
        // Must clear the 12-character floor, or the CLI refuses it before the
        // daemon is asked and this case stops testing the response handling.
        (
            &["recovery", "setup", "--user", "tester"],
            "correct horse battery\n",
        ),
        (&["recovery", "restore", "--user", "tester"], "pass\n"),
        (&["recovery", "forget", "--user", "tester"], ""),
    ];
    for (argv, input) in cases {
        let desc = argv.join(" ");
        let (code, _, err) = if input.is_empty() {
            run(&mut sb.cmd(argv), &desc)
        } else {
            run_stdin(&mut sb.cmd(argv), input, &desc)
        };
        assert_eq!(code, 1, "`{desc}` must reject a nonsense response: {err}");
        assert!(
            err.contains("unexpected response"),
            "`{desc}` stderr: {err}"
        );
    }
}

// ------------------------------------------------------------- fingerprint arm

// `fingerprint enable` as a normal user: with no usable reader it stops at the
// capability check, and with a reader present it stops at the root guard. Either
// way it exits 1 without touching the sensor. (cli.rs covers `disable`'s guard;
// this covers `enable`'s two pre-hardware exits.)
#[test]
fn fingerprint_enable_exits_without_privilege_or_reader() {
    if is_root() {
        return; // the unprivileged guards are what is under test
    }
    let sb = Sandbox::new("fpenable");
    let (code, _, err) = run(
        &mut sb.cmd(&["fingerprint", "enable"]),
        "fingerprint enable",
    );
    assert_eq!(code, 1);
    assert!(
        err.contains("no usable reader") || err.contains("sudo irlume fingerprint enable"),
        "enable must exit at the reader check or the root guard: {err}"
    );
}

// -------------------------------------------------------------------- logs arm

// The `logs` spawn-failure arm: with journalctl absent from PATH, the exec fails
// and the command reports it (exit 1) rather than panicking. cli.rs covers the
// argv assembly and a non-zero journalctl exit, not the un-spawnable case.
#[test]
fn logs_reports_when_journalctl_cannot_be_run() {
    let sb = Sandbox::new("logsnojournal");
    // PATH is ONLY the (journalctl-free) sandbox bin dir, so the lookup fails.
    let mut cmd = sb.cmd(&["logs"]);
    cmd.env("PATH", sb.path("bin"));
    let (code, _, err) = run(&mut cmd, "logs");
    assert_eq!(code, 1);
    assert!(err.contains("could not run journalctl"), "{err}");
}

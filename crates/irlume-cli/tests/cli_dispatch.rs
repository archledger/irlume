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
    unsafe { libc::geteuid() == 0 }
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
    }]
}

// ---------------------------------------------------------------- status arms

// status renders one arm per daemon answer; cli.rs pins the all-green dashboard,
// so these pin the OTHER branches: eyes-open-required enrollment, an un-armed
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
            require_challenge: false,
            closure_calibrated: false,
        },
        Request::KeyringInfo { .. } => Response::KeyringInfo {
            armed: false,
            policy: None,
            pcrs: vec![],
            drifted: None,
        },
        Request::RecoveryStatus { .. } => Response::RecoveryStatus {
            encrypted: false,
            recovery_set: false,
            tpm_present: true,
        },
        _ => Response::Error("unexpected request".into()),
    });
    let (code, out, _) = run(&mut sb.cmd(&["status", "--user", "tester"]), "status");
    assert_eq!(code, 0, "status always reports, never gates");
    assert!(out.contains("daemon        : running"), "{out}");
    assert!(out.contains("eyes-open required"), "{out}");
    assert!(out.contains("keyring unlock: not armed"), "{out}");
    assert!(out.contains("templates     : plaintext"), "{out}");
    assert!(out.contains("recovery pass : not set"), "{out}");
    assert!(out.contains("biopolicy     : ENFORCING"), "{out}");
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
            require_challenge: false,
            closure_calibrated: false,
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

// With no readable envelope in the sandbox keyring dir but a reachable daemon,
// diag reports the sealed state from HasSealedPassword: armed-but-unreadable,
// and not-armed. cli.rs only reaches the dead-socket "unknown" arm.
#[test]
fn diag_reports_sealed_state_from_daemon_when_envelope_unreadable() {
    let sb = Sandbox::new("diagarmed");
    serve(&sb.sock(), |_| Response::HasPassword(true));
    let (code, out, _) = run(&mut sb.cmd(&["diag", "--user", "tester"]), "diag");
    assert_eq!(code, 0);
    assert!(out.contains("irlume diag for 'tester'"), "{out}");
    assert!(
        out.contains("seal envelope : armed, but not readable here"),
        "{out}"
    );

    let sb2 = Sandbox::new("diagunarmed");
    serve(&sb2.sock(), |_| Response::HasPassword(false));
    let (code, out, _) = run(&mut sb2.cmd(&["diag", "--user", "tester"]), "diag");
    assert_eq!(code, 0);
    assert!(out.contains("seal envelope : not armed"), "{out}");
}

// ---------------------------------------------------------------- selinux load

// cli.rs covers `selinux status` + a bogus sub; this covers the `load` arm:
// the module file missing, and (with a fake .pp under cwd) a semodule that
// succeeds and one that fails.
#[test]
fn selinux_load_handles_missing_module_and_semodule_outcomes() {
    let sb = Sandbox::new("selinuxload");
    // No irlume.pp anywhere reachable: the not-found guard fires.
    let (code, _, err) = run(&mut sb.cmd(&["selinux", "load"]), "selinux load");
    assert_eq!(code, 1);
    assert!(err.contains("irlume.pp not found"), "{err}");

    // A .pp relative to the working dir makes the module resolvable; the fake
    // semodule then decides success vs failure.
    std::fs::create_dir_all(sb.path("work/packaging/selinux")).unwrap();
    std::fs::write(sb.path("work/packaging/selinux/irlume.pp"), b"\x00").unwrap();

    sb.fake_tool("semodule", "exit 0");
    let (code, out, _) = run(&mut sb.cmd_with_fakes(&["selinux", "load"]), "selinux load");
    assert_eq!(code, 0);
    assert!(out.contains("loaded"), "{out}");

    sb.fake_tool("semodule", "exit 5");
    let (code, _, err) = run(&mut sb.cmd_with_fakes(&["selinux", "load"]), "selinux load");
    assert_eq!(code, 1);
    assert!(err.contains("semodule exited"), "{err}");
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
        },
        Request::ListProfiles { .. } => Response::Enrollment {
            profiles: one_profile(),
            require_eyes_open: false,
            require_challenge: false,
            closure_calibrated: false,
        },
        Request::SealPassword { .. } => Response::Error("tpm busy".into()),
        _ => Response::Error("unexpected request".into()),
    });
    let (code, out, err) = run_stdin(&mut sb.cmd(&["setup", "--user", "tester"]), "pw\n", "setup");
    assert_eq!(code, 0);
    assert!(out.contains("already enrolled."), "{out}");
    assert!(out.contains("[6/6] PAM login wiring"), "{out}");
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
        },
        Request::ListProfiles { .. } => Response::Enrollment {
            profiles: Vec::new(),
            require_eyes_open: false,
            require_challenge: false,
            closure_calibrated: false,
        },
        Request::Enroll { .. } => Response::Enrolled {
            profile: "Face Profile 1".into(),
            created: false,
            added: 2,
            total: 8,
            added_scans: Vec::new(),
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
        },
        Request::ListProfiles { .. } => Response::Enrollment {
            profiles: Vec::new(),
            require_eyes_open: false,
            require_challenge: false,
            closure_calibrated: false,
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

// The write-side commands' unexpected-response arms (keyring arm/forget,
// recovery setup/restore/forget). cli.rs's Pong sweep does not include these.
#[test]
fn unexpected_responses_for_keyring_and_recovery_writes() {
    let sb = Sandbox::new("pongwrites");
    serve(&sb.sock(), |_| Response::Pong);
    let cases: &[(&[&str], &str)] = &[
        (&["keyring", "arm", "--user", "tester"], "pw\n"),
        (&["keyring", "forget", "--user", "tester"], ""),
        (&["recovery", "setup", "--user", "tester"], "pass\n"),
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

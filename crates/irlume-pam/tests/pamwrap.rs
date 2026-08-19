// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright the irlume contributors.

//! End-to-end tests of the real `pam_irlume.so` driven through a real PAM
//! stack, no root and no daemon binary required.
//!
//! How: `pamtester` (a small CLI that calls `pam_authenticate` etc.) is spawned
//! with cwrap's pam_wrapper LD_PRELOADed. pam_wrapper redirects libpam's
//! service-file lookup to `PAM_WRAPPER_SERVICE_DIR`, where each test writes a
//! stack whose lines reference the ABSOLUTE path of the freshly built
//! `libpam_irlume.so`. The module's daemon socket is pointed (via
//! `IRLUME_SOCKET`) at an in-process fake speaking the real line-JSON
//! `irlume_common` protocol, the same pattern as the swtpm and v4l2loopback
//! harnesses elsewhere in this repo. So the full production path runs: libpam
//! dlopens the cdylib, the stack executes, the module talks JSON over a Unix
//! socket, and the test asserts pamtester's exit status plus the exact requests
//! the fake daemon received.
//!
//! Tool contract (all userspace, no privileges):
//!   * Fedora: `dnf install pam_wrapper pamtester`
//!     wrapper at /usr/lib64/libpam_wrapper.so
//!   * Ubuntu/Debian: `apt-get install libpam-wrapper pamtester`
//!     wrapper at /usr/lib/x86_64-linux-gnu/libpam_wrapper.so
//!   * Anywhere else: set `PAM_WRAPPER_SO=/path/to/libpam_wrapper.so`.
//!     `pam_set_items.so` (ships in the same package) is found in the
//!     `pam_wrapper/` directory next to the wrapper library.
//!
//! The tests are `#[ignore]`d so a bare `cargo test` stays green on boxes
//! without the tools; CI (and anyone with them installed) runs
//! `cargo test -p irlume-pam -- --include-ignored`. Each test also returns
//! early with a note if the tools are missing, so `--include-ignored` is safe
//! everywhere.
//!
//! What pamtester cannot drive: `pam_sm_setcred` (pamtester has no `setcred`
//! operation; the module's is a constant `SUCCESS` one-liner) and the
//! greeter-buffered conversations of a real display manager. Everything else
//! (authenticate in every module mode, open_session, close_session) is covered.

use irlume_common::{IntentAttestation, Request, Response};
use std::io::{BufRead, BufReader, Write};
use std::os::unix::net::UnixListener;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::{Arc, Mutex};

// ---------------------------------------------------------------- harness

/// Everything a test needs: tool paths, a per-test scratch dir with the
/// pam_wrapper service dir, and the socket path the fake daemon binds.
struct Harness {
    /// libpam_wrapper.so, to LD_PRELOAD into pamtester.
    wrapper: PathBuf,
    /// pam_wrapper's pam_set_items.so: pre-sets PAM items (e.g. PAM_AUTHTOK)
    /// from pamtester's environment, standing in for a greeter/earlier module.
    set_items: PathBuf,
    /// Exports PAM items to the PAM environment so a required child can assert
    /// that the confirmation response never became PAM_AUTHTOK.
    get_items: PathBuf,
    /// pam_wrapper's plaintext test authenticator. It provides a real second
    /// password prompt so the intent response cannot masquerade as PAM_AUTHTOK.
    matrix: PathBuf,
    /// The freshly built pam_irlume.so under test.
    module: PathBuf,
    /// Directory of per-service stack files (PAM_WRAPPER_SERVICE_DIR).
    service_dir: PathBuf,
    /// IRLUME_CONFIG_DIR for the module: keeps a run from reading the HOST's
    /// /etc/irlume/settings.conf, which would make a test's verdict depend on how
    /// the developer's own machine is configured.
    config_dir: PathBuf,
    /// Where this test's fake daemon listens (IRLUME_SOCKET).
    socket: PathBuf,
    root: PathBuf,
}

impl Harness {
    /// `None` (after an explanatory eprintln) when pam_wrapper or pamtester is
    /// not installed; tests early-return so `--include-ignored` never breaks a
    /// box without the tools.
    fn try_new(name: &str) -> Option<Self> {
        let Some(wrapper) = wrapper_lib() else {
            eprintln!(
                "skipping: libpam_wrapper.so not found \
                 (Fedora: dnf install pam_wrapper; Ubuntu: apt-get install libpam-wrapper; \
                 or set PAM_WRAPPER_SO)"
            );
            return None;
        };
        let set_items = wrapper
            .parent()
            .expect("wrapper lib has a parent dir")
            .join("pam_wrapper/pam_set_items.so");
        let matrix = wrapper
            .parent()
            .expect("wrapper lib has a parent dir")
            .join("pam_wrapper/pam_matrix.so");
        let get_items = wrapper
            .parent()
            .expect("wrapper lib has a parent dir")
            .join("pam_wrapper/pam_get_items.so");
        assert!(
            set_items.exists(),
            "pam_set_items.so not next to {}; pam_wrapper installs both",
            wrapper.display()
        );
        assert!(
            matrix.exists(),
            "pam_matrix.so not next to {}; pam_wrapper installs both",
            wrapper.display()
        );
        assert!(
            get_items.exists(),
            "pam_get_items.so not next to {}; pam_wrapper installs both",
            wrapper.display()
        );
        if !pamtester_available() {
            eprintln!("skipping: pamtester not on PATH (dnf/apt-get install pamtester)");
            return None;
        }

        // Keep the socket under /tmp when TMPDIR is deep: sun_path caps a Unix
        // socket path at 108 bytes and CI/scratch TMPDIRs can exceed it.
        let base = std::env::temp_dir();
        let base = if base.as_os_str().len() > 60 {
            PathBuf::from("/tmp")
        } else {
            base
        };
        let root = base.join(format!("irlume-pamwrap-{}-{name}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        let service_dir = root.join("services");
        std::fs::create_dir_all(&service_dir).unwrap();
        let config_dir = root.join("cfg");
        std::fs::create_dir_all(&config_dir).unwrap();
        Some(Harness {
            wrapper,
            set_items,
            get_items,
            matrix,
            module: built_module(),
            socket: root.join("irlumed.sock"),
            service_dir,
            config_dir,
            root,
        })
    }

    /// Write this run's settings.conf (the module reads it live). `None` removes
    /// it, which is the default-everything state a fresh install has.
    fn write_settings(&self, body: Option<&str>) {
        let p = self.config_dir.join("settings.conf");
        match body {
            Some(b) => std::fs::write(&p, b).unwrap(),
            None => {
                let _ = std::fs::remove_file(&p);
            }
        }
    }

    /// Write a pam_wrapper service file. `lines` are ordinary pam.d lines;
    /// system modules may use bare names (libpam resolves them in its default
    /// module dir), ours must be the absolute path.
    fn write_service(&self, service: &str, lines: &[String]) {
        let mut body = lines.join("\n");
        body.push('\n');
        std::fs::write(self.service_dir.join(service), body).unwrap();
    }

    /// Run `pamtester <service> <user> <ops...>` under pam_wrapper, feeding
    /// `stdin` to the PAM conversation. `authtok_env` sets `PAM_AUTHTOK` in
    /// pamtester's environment for a leading pam_set_items.so line. Returns
    /// (succeeded, combined stdout+stderr).
    fn run(
        &self,
        service: &str,
        ops: &[&str],
        stdin: &str,
        authtok_env: Option<&str>,
    ) -> (bool, String) {
        self.run_with_consent_env(service, ops, stdin, authtok_env, None)
    }

    fn run_with_consent_env(
        &self,
        service: &str,
        ops: &[&str],
        stdin: &str,
        authtok_env: Option<&str>,
        consent_env: Option<&str>,
    ) -> (bool, String) {
        let mut cmd = Command::new("pamtester");
        cmd.arg(service).arg("tester").args(ops);
        cmd.env("LD_PRELOAD", &self.wrapper)
            .env("PAM_WRAPPER", "1")
            .env("PAM_WRAPPER_SERVICE_DIR", &self.service_dir)
            .env("IRLUME_SOCKET", &self.socket)
            .env("IRLUME_CONFIG_DIR", &self.config_dir)
            .env_remove("IRLUME_CREDENTIAL_RELEASE_CHALLENGE")
            .env_remove("IRLUME_CONSENT_GESTURE")
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        match authtok_env {
            Some(tok) => cmd.env("PAM_AUTHTOK", tok),
            None => cmd.env_remove("PAM_AUTHTOK"),
        };
        if let Some(value) = consent_env {
            cmd.env("IRLUME_CONSENT_GESTURE", value);
        }
        let mut child = cmd.spawn().expect("spawn pamtester");
        child.stdin.take().unwrap().write_all(stdin.as_bytes()).ok();
        let out = child.wait_with_output().expect("wait for pamtester");
        let mut text = String::from_utf8_lossy(&out.stdout).into_owned();
        text.push_str(&String::from_utf8_lossy(&out.stderr));
        (out.status.success(), text)
    }

    /// `auth <control> <pam_irlume.so> <args>` line for this build's module.
    fn auth_line(&self, control: &str, args: &str) -> String {
        format!("auth {control} {} {args}", self.module.display())
    }
}

impl Drop for Harness {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.root);
    }
}

/// Find libpam_wrapper.so: `PAM_WRAPPER_SO` override first, then the packaged
/// locations on Fedora/RHEL, Debian/Ubuntu, and Arch.
fn wrapper_lib() -> Option<PathBuf> {
    if let Some(p) = std::env::var_os("PAM_WRAPPER_SO") {
        let p = PathBuf::from(p);
        return p.exists().then_some(p);
    }
    [
        "/usr/lib64/libpam_wrapper.so",
        "/usr/lib/x86_64-linux-gnu/libpam_wrapper.so",
        "/usr/lib/aarch64-linux-gnu/libpam_wrapper.so",
        "/usr/lib/libpam_wrapper.so",
    ]
    .iter()
    .map(PathBuf::from)
    .find(|p| p.exists())
}

fn pamtester_available() -> bool {
    // Bare `pamtester` prints usage and exits non-zero; all we need is that it
    // spawns (i.e. exists on PATH).
    Command::new("pamtester")
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .is_ok()
}

/// The cdylib cargo built for this test run. `cargo test -p irlume-pam` builds
/// the lib target (producing libpam_irlume.so) alongside this test binary, so
/// the authoritative location is THIS executable's own artifact dir: that is
/// what keeps a `cargo llvm-cov` run loading the instrumented .so from
/// target/llvm-cov-target instead of a stale plain-target build (the test
/// process does not see CARGO_TARGET_DIR, so env-based resolution picks the
/// wrong tree there). Fallbacks cover direct `cargo build` layouts.
fn built_module() -> PathBuf {
    let mut candidates = Vec::new();
    if let Ok(exe) = std::env::current_exe() {
        // <target>/<profile>/deps/pamwrap-<hash> → the cdylib sits in the same
        // deps dir (unhashed name), or uplifted one level up by `cargo build`.
        if let Some(deps) = exe.parent() {
            candidates.push(deps.to_path_buf());
            if let Some(profile_dir) = deps.parent() {
                candidates.push(profile_dir.to_path_buf());
            }
        }
    }
    let profile = if cfg!(debug_assertions) {
        "debug"
    } else {
        "release"
    };
    let workspace = Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
    if let Some(dir) = std::env::var_os("CARGO_TARGET_DIR") {
        let dir = PathBuf::from(dir);
        // A relative CARGO_TARGET_DIR is relative to where cargo was invoked,
        // which for this workspace is its root.
        let dir = if dir.is_absolute() {
            dir
        } else {
            workspace.join(dir)
        };
        candidates.push(dir.join(profile).join("deps"));
        candidates.push(dir.join(profile));
    }
    candidates.push(workspace.join("target").join(profile).join("deps"));
    candidates.push(workspace.join("target").join(profile));
    for dir in &candidates {
        let so = dir.join("libpam_irlume.so");
        if so.exists() {
            return so;
        }
    }
    panic!(
        "libpam_irlume.so not found under {candidates:?}; \
         `cargo test -p irlume-pam` builds it, so this points at a target-dir \
         resolution bug in this harness"
    );
}

// ------------------------------------------------------------- fake daemon

/// Serve canned responses on `sock` with the daemon's line-JSON protocol (one
/// request per connection), logging every parsed request so tests can assert
/// exactly what the module sent. Same pattern as the irlume-cli test daemon.
fn serve(
    sock: &Path,
    respond: impl Fn(&Request) -> Response + Send + 'static,
) -> Arc<Mutex<Vec<Request>>> {
    let _ = std::fs::remove_file(sock);
    let listener = UnixListener::bind(sock).unwrap();
    let log = Arc::new(Mutex::new(Vec::new()));
    let thread_log = log.clone();
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
            thread_log.lock().unwrap().push(req);
            let _ = (&stream).write_all(reply.as_bytes());
        }
    });
    log
}

/// A daemon that answers every request with a non-JSON line.
fn serve_garbage(sock: &Path) {
    let _ = std::fs::remove_file(sock);
    let listener = UnixListener::bind(sock).unwrap();
    std::thread::spawn(move || {
        for stream in listener.incoming() {
            let Ok(stream) = stream else { break };
            let mut line = String::new();
            let _ = BufReader::new(&stream).read_line(&mut line);
            let _ = (&stream).write_all(b"segfault in sector 7G\n");
        }
    });
}

fn grant() -> Response {
    Response::AuthResult {
        granted: true,
        score: 0.93,
        live: true,
        reason: "match".into(),
        declined_by_gesture: false,
        refused_by_policy: false,
    }
}

fn unsealed(pw: &str) -> Response {
    Response::PasswordUnsealed {
        kind: irlume_common::KeyringSecretKind::LoginPassword,
        secret: irlume_common::SecretBytes::new(pw.as_bytes().to_vec()),
    }
}

// ------------------------------------------------------------------ tests
//
// All #[ignore] strings are identical: needs pam_wrapper + pamtester
// (attribute literals cannot reference a const).

/// Fail-closed floor: with irlumed unreachable (no socket at all) the module
/// returns IGNORE, and a stack containing only it can grant nobody. The second
/// half proves the failure really was the dead daemon: the identical stack
/// with a granting daemon succeeds.
#[test]
#[ignore = "needs pam_wrapper + pamtester (CI installs them; see this file's header)"]
fn pamwrap_dead_daemon_is_pam_ignore_fail_closed() {
    let Some(h) = Harness::try_new("dead") else {
        return;
    };
    h.write_service("irlume-dead", &[h.auth_line("required", "")]);

    // No listener bound: connect fails, module IGNOREs, nothing granted.
    let (ok, out) = h.run("irlume-dead", &["authenticate"], "", None);
    assert!(!ok, "dead daemon must not authenticate anyone: {out}");

    // Control: same stack, live granting daemon.
    let log = serve(&h.socket, |req| match req {
        Request::Authenticate { .. } => grant(),
        _ => Response::Error("unexpected request".into()),
    });
    let (ok, out) = h.run("irlume-dead", &["authenticate"], "", None);
    assert!(ok, "granting daemon must authenticate: {out}");
    assert_eq!(log.lock().unwrap().len(), 1, "exactly one capture");
}

/// The default verify path (sudo / in-session unlock): no typed password, so
/// the module sends one `Authenticate` carrying the user and the PAM service
/// name, and a grant becomes PAM success.
#[test]
#[ignore = "needs pam_wrapper + pamtester (CI installs them; see this file's header)"]
fn pamwrap_granting_daemon_face_path() {
    let Some(h) = Harness::try_new("verify") else {
        return;
    };
    h.write_service("irlume-face", &[h.auth_line("required", "")]);
    let log = serve(&h.socket, |req| match req {
        Request::Authenticate { .. } => grant(),
        _ => Response::Error("unexpected request".into()),
    });

    let (ok, out) = h.run("irlume-face", &["authenticate"], "", None);
    assert!(ok, "live match must grant: {out}");

    let reqs = log.lock().unwrap();
    assert_eq!(reqs.len(), 1, "one capture, no retries: {reqs:?}");
    match &reqs[0] {
        Request::Authenticate { user, service, .. } => {
            assert_eq!(user, "tester");
            assert_eq!(
                service.as_deref(),
                Some("irlume-face"),
                "the PAM service name must reach the daemon for tier gating"
            );
        }
        other => panic!("expected Authenticate, daemon saw {other:?}"),
    }
}

const FACE_INTENT_PROMPT: &str =
    "Face authentication: type yes and press Enter (input hidden), or press Enter for password:";

/// Every privileged spelling comes from the shared service table. A hidden
/// `yes` authorizes exactly one request, and that request carries the typed
/// assertion rather than relying on its service string alone.
#[test]
#[ignore = "needs pam_wrapper + pamtester (CI installs them; see this file's header)"]
fn pamwrap_privileged_yes_prompts_once_and_attests_every_service() {
    let Some(h) = Harness::try_new("intent-yes") else {
        return;
    };
    let log = serve(&h.socket, |req| match req {
        Request::Authenticate { .. } => grant(),
        _ => Response::Error("unexpected request".into()),
    });
    let services = [
        "sudo",
        "sudo-i",
        "su",
        "su-l",
        "runuser",
        "runuser-l",
        "doas",
        "polkit-1",
        "polkit",
    ];

    for service in services {
        h.write_service(service, &[h.auth_line("required", "")]);
        let (ok, out) = h.run(service, &["authenticate"], "yes\n", None);
        assert!(ok, "{service} confirmed face path must grant: {out}");
        assert_eq!(
            out.matches(FACE_INTENT_PROMPT).count(),
            1,
            "{service} must show exactly one hidden confirmation: {out}"
        );
    }

    let reqs = log.lock().unwrap();
    assert_eq!(reqs.len(), services.len(), "one request per service");
    for (request, expected_service) in reqs.iter().zip(services) {
        match request {
            Request::Authenticate {
                user,
                service,
                intent_confirmation,
            } => {
                assert_eq!(user, "tester");
                assert_eq!(service.as_deref(), Some(expected_service));
                assert_eq!(
                    *intent_confirmation,
                    Some(IntentAttestation::PamConversation)
                );
            }
            other => panic!("expected Authenticate, daemon saw {other:?}"),
        }
    }
}

/// Any response other than bounded ASCII `yes`, including EOF/conversation
/// failure, chooses the ordinary fallback and never contacts the daemon.
#[test]
#[ignore = "needs pam_wrapper + pamtester (CI installs them; see this file's header)"]
fn pamwrap_privileged_fallback_responses_send_no_request() {
    let Some(h) = Harness::try_new("intent-fallback") else {
        return;
    };
    let log = serve(&h.socket, |_| grant());
    h.write_service(
        "sudo",
        &[
            h.auth_line("sufficient", ""),
            "auth required pam_permit.so".into(),
        ],
    );

    for input in ["\n", "no\n", "junk\n", ""] {
        let (ok, out) = h.run("sudo", &["authenticate"], input, None);
        assert!(
            ok,
            "fallback must reach the password-module stand-in: {out}"
        );
        assert!(out.contains(FACE_INTENT_PROMPT), "prompt missing: {out}");
    }
    assert!(
        log.lock().unwrap().is_empty(),
        "fallback responses must not start a face request"
    );
}

/// Privileged PAM stacks must never turn one response into a retry loop or a
/// credential-release request, even when an administrator miswires arguments.
#[test]
#[ignore = "needs pam_wrapper + pamtester (CI installs them; see this file's header)"]
fn pamwrap_privileged_wait_and_unseal_send_no_request() {
    let Some(h) = Harness::try_new("intent-miswired") else {
        return;
    };
    let log = serve(&h.socket, |request| match request {
        Request::Authenticate { .. } => grant(),
        Request::UnsealPassword { .. } => unsealed("hunter2"),
        _ => Response::Error("unexpected request".into()),
    });

    for (args, input) in [("wait", "yes\n"), ("unseal", "\n")] {
        h.write_service(
            "sudo",
            &[
                h.auth_line("sufficient", args),
                "auth required pam_permit.so".into(),
            ],
        );
        let (ok, out) = h.run("sudo", &["authenticate"], input, None);
        assert!(ok, "{args} must fall through without face auth: {out}");
    }
    assert!(
        log.lock().unwrap().is_empty(),
        "miswired privileged modes must not reach the daemon"
    );
}

/// A password typed at the new hidden confirmation is discarded. pam_get_items
/// plus a required checker proves PAM_AUTHTOK is still empty; pam_matrix then
/// provides a real fresh password prompt before the fallback stack completes.
#[test]
#[ignore = "needs pam_wrapper + pamtester (CI installs them; see this file's header)"]
fn pamwrap_confirmation_response_is_hidden_and_never_becomes_authtok() {
    let Some(h) = Harness::try_new("intent-authtok") else {
        return;
    };
    let log = serve(&h.socket, |_| Response::Error("must not be called".into()));
    let passdb = h.root.join("matrix.passdb");
    std::fs::write(&passdb, "tester:real-password:sudo\n").unwrap();
    let no_authtok = h.root.join("no-authtok.sh");
    std::fs::write(&no_authtok, "#!/bin/sh\n[ -z \"${PAM_AUTHTOK:-}\" ]\n").unwrap();
    use std::os::unix::fs::PermissionsExt as _;
    std::fs::set_permissions(&no_authtok, std::fs::Permissions::from_mode(0o700)).unwrap();
    h.write_service(
        "sudo",
        &[
            h.auth_line("sufficient", ""),
            format!("auth required {}", h.get_items.display()),
            format!("auth required pam_exec.so {}", no_authtok.display()),
            format!(
                "auth optional {} passdb={}",
                h.matrix.display(),
                passdb.display()
            ),
            "auth required pam_permit.so".into(),
        ],
    );

    let (ok, out) = h.run(
        "sudo",
        &["authenticate"],
        "not-the-real-password\nreal-password\n",
        None,
    );
    assert!(ok, "fallback stack must complete after a fresh prompt: {out}");
    assert!(out.contains(FACE_INTENT_PROMPT), "prompt missing: {out}");
    assert!(
        !out.contains("not-the-real-password") && !out.contains("real-password"),
        "echo-off conversations must not display either secret: {out}"
    );
    assert!(
        log.lock().unwrap().is_empty(),
        "a non-yes response must not contact the daemon"
    );
}

/// Login, lock, credential-release helpers, and remote services keep their
/// existing behavior. None may inherit the privileged confirmation merely
/// because all of them share the same PAM module.
#[test]
#[ignore = "needs pam_wrapper + pamtester (CI installs them; see this file's header)"]
fn pamwrap_nonprivileged_modes_never_show_privileged_confirmation() {
    let Some(h) = Harness::try_new("intent-scope") else {
        return;
    };
    let log = serve(&h.socket, |request| match request {
        Request::Authenticate { .. } => grant(),
        Request::UnsealPassword { .. } | Request::UnsealKeyring { .. } => unsealed("hunter2"),
        _ => Response::Error("unexpected request".into()),
    });

    h.write_service("kde", &[h.auth_line("required", "")]);
    let (ok, out) = h.run("kde", &["authenticate"], "", None);
    assert!(ok, "lock verify must keep working: {out}");
    assert!(!out.contains(FACE_INTENT_PROMPT), "{out}");

    h.write_service("sddm", &[h.auth_line("required", "unseal")]);
    let (ok, out) = h.run("sddm", &["authenticate"], "\n", None);
    assert!(ok, "greeter unseal must keep working: {out}");
    assert!(!out.contains(FACE_INTENT_PROMPT), "{out}");

    for mode in ["keyring", "reseal"] {
        h.write_service(
            "sddm",
            &[
                h.auth_line("sufficient", mode),
                "auth required pam_permit.so".into(),
            ],
        );
        let (ok, out) = h.run("sddm", &["authenticate"], "", None);
        assert!(ok, "{mode} must keep fallback: {out}");
        assert!(!out.contains(FACE_INTENT_PROMPT), "{mode}: {out}");
    }

    h.write_service(
        "sshd",
        &[
            h.auth_line("sufficient", ""),
            "auth required pam_permit.so".into(),
        ],
    );
    let (ok, out) = h.run("sshd", &["authenticate"], "", None);
    assert!(ok, "remote face path must fall through: {out}");
    assert!(!out.contains(FACE_INTENT_PROMPT), "{out}");

    let reqs = log.lock().unwrap();
    assert!(matches!(
        &reqs[0],
        Request::Authenticate {
            service: Some(service),
            intent_confirmation: None,
            ..
        } if service == "kde"
    ));
    assert!(matches!(
        &reqs[1],
        Request::UnsealPassword { service: Some(service), .. } if service == "sddm"
    ));
    assert!(matches!(
        &reqs[2],
        Request::UnsealKeyring { service: Some(service), .. } if service == "sddm"
    ));
    assert_eq!(reqs.len(), 3, "reseal and sshd must send nothing: {reqs:?}");
}

/// The login path (`unseal`): submitting an EMPTY password is the face
/// gesture. The module asks the daemon to release the TPM-sealed password,
/// sets it as PAM_AUTHTOK, and returns success.
#[test]
#[ignore = "needs pam_wrapper + pamtester (CI installs them; see this file's header)"]
fn pamwrap_unseal_face_login_releases_sealed_password() {
    let Some(h) = Harness::try_new("unseal") else {
        return;
    };
    h.write_service("irlume-login", &[h.auth_line("required", "unseal")]);
    let log = serve(&h.socket, |req| match req {
        Request::UnsealPassword { .. } => unsealed("hunter2"),
        _ => Response::Error("unexpected request".into()),
    });

    // The module actively prompts ("Password: "); an empty line = face chosen.
    let (ok, out) = h.run("irlume-login", &["authenticate"], "\n", None);
    assert!(ok, "unseal grant must authenticate: {out}");

    let reqs = log.lock().unwrap();
    assert_eq!(reqs.len(), 1, "{reqs:?}");
    match &reqs[0] {
        Request::UnsealPassword { user, service } => {
            assert_eq!(user, "tester");
            assert_eq!(service.as_deref(), Some("irlume-login"));
        }
        other => panic!("expected UnsealPassword, daemon saw {other:?}"),
    }
}

/// The credential-release challenge instruction, through a real PAM conversation.
///
/// Releasing the sealed keyring password CAN require a deliberate gesture, and a
/// greeter that only says "Password:" gives the user no way to know that, so the
/// module states it WHEN the gesture is required. The gate defaults OFF (a greeter
/// cold login and logout release with no nod), so silence is the default. Two
/// properties are pinned: the instruction appears exactly where the gesture is
/// actually required (opted in, on a non-wait greeter), and it is silent
/// everywhere else. A user told to nod on a screen that never asks for a nod would
/// learn to ignore the message.
#[test]
#[ignore = "needs pam_wrapper + pamtester (CI installs them; see this file's header)"]
fn pamwrap_credential_release_challenge_instructs_only_the_greeter() {
    const READY: &str = "keep nodding your head to unlock your keyring; shake your head to decline";
    const DECLINE: &str = "shake your head to decline";
    let Some(h) = Harness::try_new("crc-hint") else {
        return;
    };
    // Every arm denies: the instruction is emitted before the outcome, and a deny
    // is the case where the user most needs to know what was expected of them.
    serve(&h.socket, |_| {
        Response::Error("face not granted: nod your head to approve".into())
    });

    h.write_service(
        "irlume-crc-login",
        &[
            h.auth_line("sufficient", "unseal"),
            "auth required pam_permit.so".into(),
        ],
    );

    // Default (no settings.conf): the gate is OFF, so the greeter stays silent.
    h.write_settings(None);
    let (ok, out) = h.run("irlume-crc-login", &["authenticate"], "\n", None);
    assert!(ok, "a refused release must keep password fallback: {out}");
    assert!(
        !out.contains(READY),
        "the default (off) must stay silent: {out}"
    );

    // Opted in with absent or explicit legacy `nod`: name both supported head
    // gestures and preserve the password fallback after the daemon refusal.
    for settings in [
        "credential_release_challenge=1\n",
        "credential_release_challenge=1\nconsent_gesture=nod\n",
    ] {
        h.write_settings(Some(settings));
        let (ok, out) = h.run("irlume-crc-login", &["authenticate"], "\n", None);
        assert!(ok, "a refused release must keep password fallback: {out}");
        assert!(
            out.contains(READY),
            "a ready gate must name nod + shake: {out}"
        );
    }

    // Retired closure and malformed settings get only their actionable blocker.
    for (settings, blocker) in [
        (
            "credential_release_challenge=1\nconsent_gesture=closure\n",
            "eye closure is retired; remove consent_gesture from settings.conf or set it to nod",
        ),
        (
            "credential_release_challenge=1\nconsent_gesture=banana\n",
            "consent_gesture is invalid; remove consent_gesture from settings.conf or set it to nod",
        ),
    ] {
        h.write_settings(Some(settings));
        let (ok, out) = h.run("irlume-crc-login", &["authenticate"], "\n", None);
        assert!(ok, "a blocked release must keep password fallback: {out}");
        assert!(
            out.contains(blocker),
            "a blocked gate must name its migration: {out}"
        );
        assert!(
            !out.contains(READY) && !out.contains(DECLINE) && !out.contains("close your eyes"),
            "a blocked gate must print only its migration blocker: {out}"
        );
    }

    // Explicitly off: silent, the same as the default. Telling the user to nod
    // would be a lie that costs them a login attempt.
    h.write_settings(Some("credential_release_challenge=0\n"));
    let (ok, out) = h.run("irlume-crc-login", &["authenticate"], "\n", None);
    assert!(ok, "an opted-out release must keep fallback: {out}");
    assert!(!out.contains(READY), "opted out must stay silent: {out}");

    // Opted in, but `wait` (the KDE lock screen runs us as a parallel biometric
    // device): an unsolicited message there competes with the password field.
    h.write_settings(Some("credential_release_challenge=1\n"));
    h.write_service("irlume-crc-lock", &[h.auth_line("required", "unseal wait")]);
    let (_, out) = h.run("irlume-crc-lock", &["authenticate"], "", None);
    assert!(!out.contains(READY), "wait mode must stay silent: {out}");

    // Plain verify (sudo): releases no credential, so no gesture and no message.
    h.write_service("irlume-crc-verify", &[h.auth_line("required", "")]);
    let (_, out) = h.run("irlume-crc-verify", &["authenticate"], "", None);
    assert!(!out.contains(READY), "verify must stay silent: {out}");
}

/// Conventional confirmation always comes first on polkit. The optional head
/// instruction appears only after `yes` and only when explicitly enabled.
#[test]
#[ignore = "needs pam_wrapper + pamtester (CI installs them; see this file's header)"]
fn pamwrap_polkit_confirmation_precedes_the_optional_gesture() {
    const APPROVE: &str = "keep nodding your head to approve";
    const DECLINE: &str = "shake your head to decline";
    let Some(h) = Harness::try_new("polkit-consent") else {
        return;
    };
    // The instruction is emitted before the verdict, so a deny still shows it;
    // the message is what we pin, not the outcome.
    serve(&h.socket, |_| Response::AuthResult {
        granted: false,
        score: 0.0,
        live: false,
        reason: "face not granted".into(),
        declined_by_gesture: false,
        refused_by_policy: false,
    });

    // A plain verify (no `unseal`) on the polkit service.
    h.write_service("polkit-1", &[h.auth_line("required", "")]);

    // Default off: `yes` reaches face auth without claiming a gesture is needed.
    h.write_settings(None);
    let (_, out) = h.run("polkit-1", &["authenticate"], "yes\n", None);
    assert!(
        out.contains(FACE_INTENT_PROMPT),
        "confirmation missing: {out}"
    );
    assert!(
        !out.contains(APPROVE) && !out.contains(DECLINE),
        "default-off gesture must stay silent: {out}"
    );

    // Explicit opt-in: confirmation is followed by both gesture instructions.
    h.write_settings(Some("service_gesture.polkit-1=1\nconsent_gesture=nod\n"));
    let (_, out) = h.run("polkit-1", &["authenticate"], "yes\n", None);
    assert!(
        out.contains(FACE_INTENT_PROMPT),
        "confirmation missing: {out}"
    );
    assert!(out.contains(APPROVE), "approval instruction missing: {out}");
    assert!(out.contains(DECLINE), "decline instruction missing: {out}");

    // Misconfigured mode: the instruction is a diagnostic sentence naming the bad
    // setting; the decline clause is suppressed so it does not bury the fix.
    h.write_settings(Some("service_gesture.polkit-1=1\nconsent_gesture=banana\n"));
    let (_, out) = h.run("polkit-1", &["authenticate"], "yes\n", None);
    assert!(
        out.contains(
            "consent_gesture is invalid; remove consent_gesture from settings.conf or set it to nod"
        ),
        "a misconfigured mode must name the bad setting: {out}"
    );
    assert!(
        !out.contains(DECLINE),
        "a misconfigured diagnostic must not carry a decline clause: {out}"
    );

    // Retired closure is blocked: print only the migration action and no gesture.
    h.write_settings(Some(
        "service_gesture.polkit-1=1\nconsent_gesture=closure\n",
    ));
    let (_, out) = h.run("polkit-1", &["authenticate"], "yes\n", None);
    assert!(
        out.contains(
            "eye closure is retired; remove consent_gesture from settings.conf or set it to nod"
        ),
        "closure mode must name the migration action: {out}"
    );
    assert!(
        !out.contains(APPROVE) && !out.contains(DECLINE) && !out.contains("close your eyes"),
        "closure mode must print only its blocker: {out}"
    );

    // Elevation uses the same explicit additional-gesture contract.
    h.write_settings(Some("service_gesture.sudo=1\n"));
    h.write_service("sudo", &[h.auth_line("required", "")]);
    let (_, out) = h.run("sudo", &["authenticate"], "yes\n", None);
    assert!(out.contains(APPROVE) && out.contains(DECLINE), "{out}");
}

#[test]
#[ignore = "needs pam_wrapper + pamtester (CI installs them; see this file's header)"]
fn pamwrap_polkit_migration_remedy_tracks_the_environment_override() {
    let Some(h) = Harness::try_new("polkit-consent-env") else {
        return;
    };
    serve(&h.socket, |_| Response::AuthResult {
        granted: false,
        score: 0.0,
        live: false,
        reason: "face not granted".into(),
        declined_by_gesture: false,
        refused_by_policy: false,
    });
    h.write_service("polkit-1", &[h.auth_line("required", "")]);
    h.write_settings(Some("service_gesture.polkit-1=1\nconsent_gesture=nod\n"));

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
        let (_, out) = h.run_with_consent_env(
            "polkit-1",
            &["authenticate"],
            "yes\n",
            None,
            Some(value),
        );
        assert!(out.contains(expected), "{value}: {out}");
        assert!(!out.contains("from settings.conf"), "{out}");
        if value == "banana" {
            assert!(!out.contains(value), "arbitrary value was echoed: {out}");
        }
    }
}

/// A head-shake on a polkit dialog ABORTS the PAM stack, so the password module
/// after the abort=die control is never reached (and the agent closes its window).
/// The SAME shake on a NON-polkit service, and a plain no-match on polkit, must
/// instead IGNORE and fall through to the password module: the fallback survives
/// unless the user deliberately declined a POLKIT dialog. `pam_permit` stands in
/// for the distro password module and grants ONLY if the stack reaches it, so
/// `ok == false` means "aborted before the password".
///
/// This is the fail-safe boundary; three mutations die here. Case (1): folding
/// ABORT into IGNORE, or try_verify not returning ABORT, makes it fall through and
/// grant. Case (2): dropping the `is_polkit_consent` guard makes try_verify ABORT
/// for the non-polkit service too. Case (2) wires that service under the SAME
/// abort=die control ON PURPOSE, as a test instrument, so the module's ABORT is
/// observable: under plain `sufficient` an ABORT is `default=ignore`d and IGNORE
/// vs ABORT would be indistinguishable, leaving the guard unpinned. Case (3):
/// matching a non-shake decline makes a plain no-match abort.
#[test]
#[ignore = "needs pam_wrapper + pamtester (CI installs them; see this file's header)"]
fn pamwrap_polkit_shake_aborts_only_the_polkit_stack() {
    use std::sync::atomic::{AtomicBool, Ordering};
    let Some(h) = Harness::try_new("polkit-abort") else {
        return;
    };
    // The daemon reports a denial; `declined_by_gesture` is flipped per case to
    // model "deliberate shake" (true) vs "plain no-match" (false).
    let declined = Arc::new(AtomicBool::new(true));
    let d = declined.clone();
    let log = serve(&h.socket, move |_| Response::AuthResult {
        granted: false,
        score: 0.0,
        live: false,
        reason: "denied".into(),
        declined_by_gesture: d.load(Ordering::SeqCst),
        refused_by_policy: false,
    });
    h.write_settings(Some("service_gesture.polkit-1=1\nservice_gesture.sudo=1\n"));

    // pam_irlume under a control line, then pam_permit as the distro
    // password-module stand-in: reached only if pam_irlume did NOT abort. BOTH
    // services here carry the abort=die control (POLKIT_CONTROL), as a test
    // instrument, so the module's ABORT-vs-IGNORE is observable on each; under
    // plain `sufficient` an ABORT is `default=ignore`d and the scoping guard could
    // not be tested. In production only the polkit stanza carries abort=die and
    // sudo keeps plain `sufficient`, but pam_irlume never returns ABORT for sudo
    // (the is_polkit_consent guard), so sudo's real control cannot change the outcome.
    const POLKIT_CONTROL: &str = "[success=done new_authtok_reqd=done abort=die default=ignore]";
    let permit_after = |service: &str, control: &str| {
        h.write_service(
            service,
            &[
                h.auth_line(control, ""),
                "auth required pam_permit.so".into(),
            ],
        );
    };

    // (1) polkit + deliberate shake: ABORT under abort=die, so pam_permit is never reached.
    declined.store(true, Ordering::SeqCst);
    permit_after("polkit-1", POLKIT_CONTROL);
    let (ok, out) = h.run("polkit-1", &["authenticate"], "yes\n", None);
    assert!(
        !ok,
        "a polkit shake must abort before the password module: {out}"
    );

    // (2) sudo + shake: NOT a polkit dialog, so try_verify must IGNORE, never ABORT.
    // Under the abort=die instrument, IGNORE -> default=ignore -> pam_permit grants
    // (ok); a dropped is_polkit_consent guard would ABORT -> die -> no grant, failing
    // this assertion. That is the mutation this case exists to kill.
    declined.store(true, Ordering::SeqCst);
    permit_after("sudo", POLKIT_CONTROL);
    let (ok, out) = h.run("sudo", &["authenticate"], "yes\n", None);
    assert!(
        ok,
        "a non-polkit shake must IGNORE (keep the password), not ABORT: {out}"
    );

    // (3) polkit + plain no-match (not a shake): IGNORE, so it falls through to
    // permit even under abort=die (only a PAM_ABORT dies; IGNORE does not).
    declined.store(false, Ordering::SeqCst);
    permit_after("polkit-1", POLKIT_CONTROL);
    let (ok, out) = h.run("polkit-1", &["authenticate"], "yes\n", None);
    assert!(
        ok,
        "a non-shake polkit denial must keep the password fallback: {out}"
    );

    // The daemon really was asked each time (defect #26: absent vs broken), so the
    // aborts and fall-throughs are real verdicts, not "pam_irlume never ran".
    let reqs = log.lock().unwrap();
    assert_eq!(
        reqs.iter()
            .filter(|r| matches!(r, Request::Authenticate { .. }))
            .count(),
        3,
        "each case must reach the daemon: {reqs:?}"
    );
    assert!(reqs.iter().all(|request| matches!(
        request,
        Request::Authenticate {
            intent_confirmation: Some(IntentAttestation::PamConversation),
            ..
        }
    )));
}

/// THE fail-safe that makes the challenge acceptable when it is on: when the
/// gesture is not performed, the daemon refuses to release the password, and the
/// PAM stack must carry on to the password module rather than fail the
/// transaction.
///
/// Both greeter layouts are exercised, because the failure would be layout-shaped:
/// the Fedora `[success=1 default=ignore]` jump form, where an IGNORE must fall
/// through to the next line and NOT take the jump, and the Debian/Arch
/// `sufficient` include form. `pam_permit` stands in for the distro's password
/// module: it grants only if the stack actually reaches it.
#[test]
#[ignore = "needs pam_wrapper + pamtester (CI installs them; see this file's header)"]
fn pamwrap_refused_challenge_falls_through_to_the_password_module() {
    let Some(h) = Harness::try_new("crc-fallback") else {
        return;
    };
    h.write_settings(None);
    let log = serve(&h.socket, |_| {
        Response::Error("face not granted: nod your head to approve".into())
    });

    // Fedora-style jump layout. success=1 would skip the password module; a
    // refused release must instead land on it.
    h.write_service(
        "irlume-crc-jump",
        &[
            h.auth_line("[success=1 default=ignore]", "unseal"),
            "auth required pam_permit.so".into(),
            "auth optional pam_deny.so".into(), // the landing the jump would hit
        ],
    );
    let (ok, out) = h.run("irlume-crc-jump", &["authenticate"], "\n", None);
    assert!(
        ok,
        "a refused release must fall through to the password module: {out}"
    );

    // Debian/Arch-style include layout, same requirement.
    h.write_service(
        "irlume-crc-sufficient",
        &[
            h.auth_line("sufficient", "unseal ondemand kr"),
            "auth required pam_permit.so".into(),
        ],
    );
    let (ok, out) = h.run("irlume-crc-sufficient", &["authenticate"], "\n", None);
    assert!(ok, "sufficient layout must also fall through: {out}");

    // The daemon really was asked, so the fall-through is a REFUSED release and
    // not "face never ran". Each layout opens with UnsealPassword; `ondemand` then
    // adds its documented warm-unlock retry (a refused release still lets a live
    // lock screen unlock on identity alone), which releases no token and so does
    // not weaken the gate.
    let reqs = log.lock().unwrap();
    assert!(
        matches!(reqs.first(), Some(Request::UnsealPassword { .. })),
        "the jump layout must attempt a release first: {reqs:?}"
    );
    assert_eq!(
        reqs.iter()
            .filter(|r| matches!(r, Request::UnsealPassword { .. }))
            .count(),
        2,
        "one release attempt per layout: {reqs:?}"
    );
    assert!(
        reqs.iter().all(|r| matches!(
            r,
            Request::UnsealPassword { .. } | Request::Authenticate { .. }
        )),
        "no other request kind belongs on this path: {reqs:?}"
    );
}

/// The documented privacy property: typing a password NEVER starts a scan.
/// Both discovery paths are covered: the active greeter probe (`unseal`
/// prompts, the user types) and the passive peek (an earlier module already
/// set PAM_AUTHTOK, here pam_set_items standing in for the greeter). In both
/// cases the recording daemon must see ZERO requests, and since nothing else
/// in the stack grants, authentication fails.
#[test]
#[ignore = "needs pam_wrapper + pamtester (CI installs them; see this file's header)"]
fn pamwrap_typed_password_never_fires_the_camera() {
    let Some(h) = Harness::try_new("typed") else {
        return;
    };
    let log = serve(&h.socket, |_| grant());

    // Active probe: `unseal` asks, the user answers with a real password.
    h.write_service("irlume-typed-login", &[h.auth_line("required", "unseal")]);
    let (ok, out) = h.run("irlume-typed-login", &["authenticate"], "hunter2\n", None);
    assert!(!ok, "module must IGNORE on a typed password: {out}");

    // Passive peek: PAM_AUTHTOK pre-set before our line (verify mode). The
    // control neutralizes pam_set_items' own SUCCESS verdict so the stack
    // outcome is decided solely by our module (IGNORE ⇒ nobody granted).
    h.write_service(
        "sudo",
        &[
            format!(
                "auth [success=ignore default=bad] {}",
                h.set_items.display()
            ),
            h.auth_line("required", ""),
        ],
    );
    let (ok, out) = h.run("sudo", &["authenticate"], "", Some("hunter2"));
    assert!(!ok, "module must IGNORE on a cached password: {out}");

    let reqs = log.lock().unwrap();
    assert!(
        reqs.is_empty(),
        "typing a password must never reach the daemon (no camera): {reqs:?}"
    );
}

/// A daemon that answers with a line that is not JSON: the reply fails to
/// parse, the module IGNOREs, and the stack fails closed.
#[test]
#[ignore = "needs pam_wrapper + pamtester (CI installs them; see this file's header)"]
fn pamwrap_malformed_daemon_reply_is_ignore_fail_closed() {
    let Some(h) = Harness::try_new("garbage") else {
        return;
    };
    h.write_service("irlume-garbage", &[h.auth_line("required", "")]);
    serve_garbage(&h.socket);

    let (ok, out) = h.run("irlume-garbage", &["authenticate"], "", None);
    assert!(!ok, "a garbage reply must never authenticate: {out}");
}

/// `wait` mode (lock screen): a declined attempt is retried after the gap
/// instead of falling through to the password, and the retry's grant wins.
/// The whole exchange must stay far inside the 20s budget (deny + one 400ms
/// gap + grant), proving success exits the loop immediately.
#[test]
#[ignore = "needs pam_wrapper + pamtester (CI installs them; see this file's header)"]
fn pamwrap_wait_mode_retries_until_a_match() {
    let Some(h) = Harness::try_new("wait") else {
        return;
    };
    h.write_service("irlume-lock", &[h.auth_line("required", "wait")]);
    // First capture: not the user. Second: match.
    let calls = Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let calls_in_daemon = calls.clone();
    let log = serve(&h.socket, move |req| match req {
        Request::Authenticate { .. } => {
            if calls_in_daemon.fetch_add(1, std::sync::atomic::Ordering::SeqCst) == 0 {
                Response::AuthResult {
                    granted: false,
                    score: 0.10,
                    live: true,
                    reason: "below threshold".into(),
                    declined_by_gesture: false,
                    refused_by_policy: false,
                }
            } else {
                grant()
            }
        }
        _ => Response::Error("unexpected request".into()),
    });

    let started = std::time::Instant::now();
    let (ok, out) = h.run("irlume-lock", &["authenticate"], "", None);
    assert!(ok, "the retried match must authenticate: {out}");
    assert_eq!(log.lock().unwrap().len(), 2, "deny, one gap, grant");
    assert!(
        started.elapsed() < std::time::Duration::from_secs(10),
        "a grant must exit the wait loop immediately, not sit out the budget"
    );
}

/// A daemon reply whose unsealed secret contains a NUL byte cannot become a
/// PAM_AUTHTOK (C string); the module must treat it as a decline, and with
/// nothing else in the stack the authentication fails closed.
#[test]
#[ignore = "needs pam_wrapper + pamtester (CI installs them; see this file's header)"]
fn pamwrap_nul_poisoned_secret_is_ignore_fail_closed() {
    let Some(h) = Harness::try_new("nul") else {
        return;
    };
    h.write_service("irlume-nul", &[h.auth_line("required", "unseal")]);
    serve(&h.socket, |req| match req {
        Request::UnsealPassword { .. } => Response::PasswordUnsealed {
            kind: irlume_common::KeyringSecretKind::LoginPassword,
            secret: irlume_common::SecretBytes::new(b"hun\0ter".to_vec()),
        },
        _ => Response::Error("unexpected request".into()),
    });

    let (ok, out) = h.run("irlume-nul", &["authenticate"], "\n", None);
    assert!(!ok, "a NUL-poisoned secret must never authenticate: {out}");
}

/// `ondemand` (GDM/cosmic single-service wiring): when the unseal is refused
/// (convenience tier / un-armed keyring) the module falls back to a plain
/// verify before giving up, so a warm screen unlock still works.
#[test]
#[ignore = "needs pam_wrapper + pamtester (CI installs them; see this file's header)"]
fn pamwrap_ondemand_unseal_falls_back_to_verify() {
    let Some(h) = Harness::try_new("ondemand") else {
        return;
    };
    h.write_service(
        "irlume-cosmic",
        &[h.auth_line("required", "unseal ondemand")],
    );
    let log = serve(&h.socket, |req| match req {
        Request::UnsealPassword { .. } => Response::Error("keyring not armed".into()),
        Request::Authenticate { .. } => grant(),
        _ => Response::Error("unexpected request".into()),
    });

    let (ok, out) = h.run("irlume-cosmic", &["authenticate"], "\n", None);
    assert!(ok, "verify fallback must rescue the warm unlock: {out}");

    let reqs = log.lock().unwrap();
    assert_eq!(
        reqs.len(),
        2,
        "unseal attempt then verify fallback: {reqs:?}"
    );
    assert!(matches!(reqs[0], Request::UnsealPassword { .. }));
    assert!(matches!(reqs[1], Request::Authenticate { .. }));
}

/// `keyring` mode (fingerprint path, post-auth landing): the module always
/// asks the daemon, and REPORTS whether the transaction already holds a
/// password rather than deciding on it. That decision moved daemon-side with
/// #250: a token-armed keyring does not open with the typed password, so only
/// the daemon, which can read the envelope's kind, can tell whether the unseal
/// is pointless. Either way the module returns IGNORE (best-effort), so the
/// trailing pam_permit decides the stack.
#[test]
#[ignore = "needs pam_wrapper + pamtester (CI installs them; see this file's header)"]
fn pamwrap_keyring_mode_reports_whether_a_password_is_present() {
    let Some(h) = Harness::try_new("keyring") else {
        return;
    };
    let log = serve(&h.socket, |req| match req {
        Request::UnsealKeyring { .. } => unsealed("hunter2"),
        _ => Response::Error("unexpected request".into()),
    });
    h.write_service(
        "irlume-fp",
        &[
            h.auth_line("required", "keyring"),
            "auth required pam_permit.so".into(),
        ],
    );
    h.write_service(
        "irlume-fp-pw",
        &[
            format!("auth required {}", h.set_items.display()),
            h.auth_line("required", "keyring"),
            "auth required pam_permit.so".into(),
        ],
    );

    // No password in the transaction: unseal the keyring secret.
    let (ok, out) = h.run("irlume-fp", &["authenticate"], "", None);
    assert!(ok, "keyring mode must never block the login: {out}");
    {
        let reqs = log.lock().unwrap();
        assert_eq!(reqs.len(), 1, "{reqs:?}");
        match &reqs[0] {
            Request::UnsealKeyring {
                user,
                service,
                have_password,
            } => {
                assert_eq!(user, "tester");
                assert_eq!(service.as_deref(), Some("irlume-fp"));
                assert!(!have_password, "no password was set in this transaction");
            }
            other => panic!("expected UnsealKeyring, daemon saw {other:?}"),
        }
        // (drop the guard before the next run appends)
    }

    // Password already present: still asked, but flagged, so the daemon can
    // answer KeyringUnlockNotNeeded for a password envelope without spending a
    // TPM unseal, and can still release a token for a token envelope.
    let (ok, out) = h.run("irlume-fp-pw", &["authenticate"], "", Some("hunter2"));
    assert!(ok, "{out}");
    let reqs = log.lock().unwrap();
    assert_eq!(
        reqs.len(),
        2,
        "the daemon decides, so it must be asked: {reqs:?}"
    );
    match &reqs[1] {
        Request::UnsealKeyring { have_password, .. } => assert!(
            *have_password,
            "a password IS present; reporting false would make the daemon spend a \
             pointless TPM unseal"
        ),
        other => panic!("expected UnsealKeyring, daemon saw {other:?}"),
    }
}

/// `kr` (Debian `@include` keyring-continue): a COLD face login that released
/// the password returns IGNORE instead of SUCCESS, so a `sufficient` control
/// CONTINUES down the stack (here into pam_deny, making the outcome
/// distinguishable) instead of short-circuiting. Without `kr` the identical
/// stack short-circuits at our line. "tester" has no live session, so the
/// login counts as cold.
#[test]
#[ignore = "needs pam_wrapper + pamtester (CI installs them; see this file's header)"]
fn pamwrap_kr_cold_login_continues_instead_of_short_circuiting() {
    let Some(h) = Harness::try_new("kr") else {
        return;
    };
    let log = serve(&h.socket, |req| match req {
        Request::UnsealPassword { .. } => unsealed("hunter2"),
        _ => Response::Error("unexpected request".into()),
    });
    h.write_service(
        "irlume-kr",
        &[
            h.auth_line("sufficient", "unseal kr"),
            "auth required pam_deny.so".into(),
        ],
    );
    h.write_service(
        "irlume-nokr",
        &[
            h.auth_line("sufficient", "unseal"),
            "auth required pam_deny.so".into(),
        ],
    );

    // kr + cold + password released → IGNORE → sufficient continues → deny.
    let (ok, out) = h.run("irlume-kr", &["authenticate"], "\n", None);
    assert!(!ok, "kr cold login must continue past our line: {out}");
    assert_eq!(
        log.lock().unwrap().len(),
        1,
        "the unseal must still have happened (that is what kr hands on)"
    );

    // Same stack minus kr: SUCCESS short-circuits before pam_deny.
    let (ok, out) = h.run("irlume-nokr", &["authenticate"], "\n", None);
    assert!(ok, "without kr a sufficient grant short-circuits: {out}");
}

/// The `reseal` self-heal, whole transaction: the AUTH line only STASHES the
/// (pam_set_items-provided, i.e. verified-by-the-stack) password and must not
/// contact the daemon; the SESSION line, which PAM only reaches after auth
/// succeeded, hands exactly that password to the daemon for re-sealing.
/// close_session is driven too (constant IGNORE; permit carries the stack).
#[test]
#[ignore = "needs pam_wrapper + pamtester (CI installs them; see this file's header)"]
fn pamwrap_reseal_stashes_on_auth_and_reseals_on_session() {
    let Some(h) = Harness::try_new("reseal") else {
        return;
    };
    let log = serve(&h.socket, |req| match req {
        Request::ResealPassword { .. } => Response::PasswordResealed {
            armed: true,
            changed: true,
        },
        _ => Response::Error("unexpected request".into()),
    });
    h.write_service(
        "irlume-reseal",
        &[
            format!("auth required {}", h.set_items.display()),
            h.auth_line("required", "reseal"),
            "auth required pam_permit.so".into(),
            format!("session required {} reseal", h.module.display()),
            "session required pam_permit.so".into(),
        ],
    );

    let (ok, out) = h.run(
        "irlume-reseal",
        &["authenticate", "open_session", "close_session"],
        "",
        Some("hunter2"),
    );
    assert!(ok, "auth + session must both pass: {out}");

    let reqs = log.lock().unwrap();
    // The AUTH phase must still contact nobody: acting on a token there is the
    // bug that let a typo overwrite a good seal. The SESSION phase now makes
    // two requests, in this order.
    assert_eq!(
        reqs.len(),
        2,
        "reseal, then the token-delivery query, both in the session phase: {reqs:?}"
    );
    // A typed-password login releases no token in the auth phase, so there is
    // no stash for open_session to deliver; without asking the daemon here, a
    // token-armed account's keyring would never be unlocked by a password
    // login. `have_password: true` lets the daemon answer a password-armed
    // user without touching the TPM, so the cost lands only on token users.
    match &reqs[1] {
        Request::UnsealKeyring {
            user,
            have_password,
            ..
        } => {
            assert_eq!(user, "tester");
            assert!(have_password, "the session phase holds the typed password");
        }
        other => panic!("expected the delivery query second, got {other:?}"),
    }
    match &reqs[0] {
        Request::ResealPassword { user, password } => {
            assert_eq!(user, "tester");
            assert_eq!(
                password.expose(),
                b"hunter2",
                "the session phase must reseal the stack-verified password verbatim"
            );
        }
        other => panic!("expected ResealPassword, daemon saw {other:?}"),
    }
    drop(reqs);

    // A pure face login stashes nothing (blank submit ⇒ empty PAM_AUTHTOK), so
    // the session half must have nothing to RESEAL. It still asks the daemon
    // whether a token needs delivering, because a face login that released one
    // is exactly the case that needs it.
    h.write_service(
        "irlume-reseal-empty",
        &[
            h.auth_line("required", "reseal"),
            "auth required pam_permit.so".into(),
            format!("session required {} reseal", h.module.display()),
            "session required pam_permit.so".into(),
        ],
    );
    let (ok, out) = h.run(
        "irlume-reseal-empty",
        &["authenticate", "open_session"],
        "",
        None,
    );
    assert!(ok, "{out}");
    let reqs = log.lock().unwrap();
    assert_eq!(
        reqs.len(),
        3,
        "the two from the run above, plus this run's delivery query and no \
         reseal: {reqs:?}"
    );
    assert!(
        !reqs
            .iter()
            .any(|r| matches!(r, Request::ResealPassword { .. })
                && reqs
                    .iter()
                    .filter(|x| matches!(x, Request::ResealPassword { .. }))
                    .count()
                    > 1),
        "an empty stash must never produce a SECOND reseal request: {reqs:?}"
    );
    match &reqs[2] {
        // `true` even though nothing was typed: the flag means "a
        // password-keyed keyring is already served", which by the session
        // phase it is, and answering it saves the daemon a TPM unseal this
        // hook would only discard.
        Request::UnsealKeyring { have_password, .. } => assert!(
            *have_password,
            "the session-phase delivery query always reports a served keyring"
        ),
        other => panic!("expected only the delivery query, got {other:?}"),
    }
}

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

use irlume_common::{Request, Response};
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
    /// The freshly built pam_irlume.so under test.
    module: PathBuf,
    /// Directory of per-service stack files (PAM_WRAPPER_SERVICE_DIR).
    service_dir: PathBuf,
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
        assert!(
            set_items.exists(),
            "pam_set_items.so not next to {}; pam_wrapper installs both",
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
        Some(Harness {
            wrapper,
            set_items,
            module: built_module(),
            socket: root.join("irlumed.sock"),
            service_dir,
            root,
        })
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
        let mut cmd = Command::new("pamtester");
        cmd.arg(service).arg("tester").args(ops);
        cmd.env("LD_PRELOAD", &self.wrapper)
            .env("PAM_WRAPPER", "1")
            .env("PAM_WRAPPER_SERVICE_DIR", &self.service_dir)
            .env("IRLUME_SOCKET", &self.socket)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        match authtok_env {
            Some(tok) => cmd.env("PAM_AUTHTOK", tok),
            None => cmd.env_remove("PAM_AUTHTOK"),
        };
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
    }
}

fn unsealed(pw: &str) -> Response {
    Response::PasswordUnsealed {
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
        Request::Authenticate { user, service } => {
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
        "irlume-typed-sudo",
        &[
            format!(
                "auth [success=ignore default=bad] {}",
                h.set_items.display()
            ),
            h.auth_line("required", ""),
        ],
    );
    let (ok, out) = h.run("irlume-typed-sudo", &["authenticate"], "", Some("hunter2"));
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

/// `keyring` mode (fingerprint path, post-auth landing): with no password in
/// the transaction the module asks for the sealed password to unlock the
/// keyring; with one already present it stays silent. Either way it returns
/// IGNORE (best-effort), so the trailing pam_permit decides the stack.
#[test]
#[ignore = "needs pam_wrapper + pamtester (CI installs them; see this file's header)"]
fn pamwrap_keyring_mode_unseals_only_without_a_password() {
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
            Request::UnsealKeyring { user, service } => {
                assert_eq!(user, "tester");
                assert_eq!(service.as_deref(), Some("irlume-fp"));
            }
            other => panic!("expected UnsealKeyring, daemon saw {other:?}"),
        }
        // (drop the guard before the next run appends)
    }

    // Password already present: the keyring self-unlocks from it; no request.
    let (ok, out) = h.run("irlume-fp-pw", &["authenticate"], "", Some("hunter2"));
    assert!(ok, "{out}");
    assert_eq!(
        log.lock().unwrap().len(),
        1,
        "a present password must mean no daemon contact"
    );
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
    assert_eq!(
        reqs.len(),
        1,
        "exactly one reseal, and none during the auth phase: {reqs:?}"
    );
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
    // the session half must have nothing to heal with: no daemon contact.
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
    assert_eq!(
        log.lock().unwrap().len(),
        1,
        "an empty stash must never produce a reseal request"
    );
}

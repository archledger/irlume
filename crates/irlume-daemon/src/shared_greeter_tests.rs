// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright the irlume contributors.

// Included inside the daemon's tests module. Only session facts and the
// biometric result are injected; dispatch, peer credentials, process binding,
// admission, reply delivery, retry bookkeeping and PAM are production code.
pub(super) mod shared_greeter {
    use super::*;
    use crate::shared_unlock::{Session, REFUSED};
    use std::cell::{Cell, RefCell};
    use std::io::{BufRead, BufReader};
    use std::os::unix::net::UnixListener;
    use std::path::{Path, PathBuf};
    use std::process::{Command, Stdio};
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::sync::Arc;
    use std::time::{Duration, Instant};

    #[derive(Clone)]
    struct Fixture {
        session: Result<Session, &'static str>,
        after_auth: Option<Result<Session, &'static str>>,
        cancel_after_auth: Option<Arc<AtomicBool>>,
        biometric_calls: usize,
        observed_pids: Vec<i32>,
    }

    impl Fixture {
        fn new(session: Result<Session, &'static str>) -> Self {
            Self {
                session,
                after_auth: None,
                cancel_after_auth: None,
                biometric_calls: 0,
                observed_pids: Vec::new(),
            }
        }
    }

    thread_local! {
        static FIXTURE: RefCell<Option<Fixture>> = const { RefCell::new(None) };
    }

    struct Reset;
    impl Drop for Reset {
        fn drop(&mut self) {
            FIXTURE.with(|value| *value.borrow_mut() = None);
        }
    }

    pub(crate) fn session_result(peer: &Peer) -> Option<Result<Session, &'static str>> {
        FIXTURE.with(|value| {
            let mut value = value.borrow_mut();
            let fixture = value.as_mut()?;
            fixture.observed_pids.push(peer.pid);
            Some(fixture.session.clone())
        })
    }

    pub(crate) fn biometric_outcome() -> Option<irlume_auth::Outcome> {
        FIXTURE.with(|value| {
            let mut value = value.borrow_mut();
            let fixture = value.as_mut()?;
            fixture.biometric_calls += 1;
            if let Some(session) = &fixture.after_auth {
                fixture.session = session.clone();
            }
            if let Some(cancel) = &fixture.cancel_after_auth {
                cancel.store(true, Ordering::SeqCst);
            }
            Some(irlume_auth::Outcome {
                granted: true,
                live: true,
                score: 0.9,
                reason: "synthetic valid biometric/PAD result".into(),
                kind: irlume_auth::OutcomeKind::Granted,
                cause: None,
            })
        })
    }

    fn local_session(uid: u32) -> Session {
        Session {
            owner: ":1.42".into(),
            path: "/org/freedesktop/login1/session/_32".into(),
            id: "2".into(),
            uid,
            seat: "seat0".into(),
            kind: "wayland".into(),
            class: "user".into(),
            state: "active".into(),
            active: true,
            remote: false,
            created: 1234,
        }
    }

    struct Harness {
        root: PathBuf,
        driver: PathBuf,
        password: PathBuf,
        wrapper: PathBuf,
        module: PathBuf,
        user: String,
        uid: u32,
        next_case: Cell<u32>,
    }

    struct Case {
        service: &'static str,
        mode: &'static str,
        fixture: Fixture,
        after_dispatch: Option<Result<Session, &'static str>>,
        password: Option<&'static str>,
        remote: bool,
        selected_user: Option<String>,
    }

    impl Case {
        fn new(
            service: &'static str,
            mode: &'static str,
            session: Result<Session, &'static str>,
        ) -> Self {
            Self {
                service,
                mode,
                fixture: Fixture::new(session),
                after_dispatch: None,
                password: None,
                remote: false,
                selected_user: None,
            }
        }
    }

    #[derive(Debug)]
    struct ResultCase {
        success: bool,
        requests: usize,
        biometric_calls: usize,
        prepared_grant: bool,
    }

    impl Harness {
        fn new(root: &Path) -> Self {
            let wrapper = [
                "/usr/lib/libpam_wrapper.so",
                "/usr/lib64/libpam_wrapper.so",
                "/usr/lib/x86_64-linux-gnu/libpam_wrapper.so",
            ]
            .into_iter()
            .map(PathBuf::from)
            .find(|path| path.is_file())
            .expect("install pam_wrapper for this explicitly requested integration test");
            let exe = std::env::current_exe().unwrap();
            let deps = exe.parent().unwrap();
            let module = [
                deps.join("libpam_irlume.so"),
                deps.parent().unwrap().join("libpam_irlume.so"),
            ]
            .into_iter()
            .find(|path| path.is_file())
            .expect("build irlume-pam with the same toolchain/target directory first");
            let source = root.join("driver.c");
            std::fs::write(&source, include_str!("../tests/shared_greeter_driver.c")).unwrap();
            let driver = root.join("pam-driver");
            let password = root.join("pam_fixture_password.so");
            for (output, flags) in [
                (&driver, vec![]),
                (&password, vec!["-DPASSWORD_MODULE", "-fPIC", "-shared"]),
            ] {
                let result = Command::new("cc")
                    .args(["-Wall", "-Wextra", "-Werror"])
                    .args(flags)
                    .arg(&source)
                    .args(["-lpam", "-o"])
                    .arg(output)
                    .output()
                    .unwrap();
                assert!(
                    result.status.success(),
                    "{}",
                    String::from_utf8_lossy(&result.stderr)
                );
            }
            std::fs::create_dir(root.join("services")).unwrap();
            // SAFETY: getuid only reads this process's real UID.
            let uid = unsafe { libc::getuid() };
            let user = users::name_for_uid(uid).unwrap();
            Self {
                root: root.to_owned(),
                driver,
                password,
                wrapper,
                module,
                uid,
                next_case: Cell::new(0),
                user,
            }
        }

        fn run(&self, engine: &mut irlume_auth::Engine, case: Case) -> ResultCase {
            // Cases are independent transactions. Keep the real retry store,
            // but isolate its history so deliberately abandoned grants do not
            // hit the existing five-strike cooldown in a later case.
            let number = self.next_case.get();
            self.next_case.set(number + 1);
            let state = self.root.join(format!("case-{number}"));
            std::fs::create_dir(&state).unwrap();
            std::env::set_var("IRLUME_STATE_DIR", state);
            let fallback = case.password.map_or_else(
                || "pam_deny.so".to_owned(),
                |_| self.password.display().to_string(),
            );
            std::fs::write(
                self.root.join("services").join(case.service),
                format!(
                    "auth sufficient {} unseal {} kr\nauth required {fallback}\n",
                    self.module.display(),
                    case.mode
                ),
            )
            .unwrap();
            let cancelled = case.fixture.cancel_after_auth.clone().unwrap_or_default();
            engine.set_request_cancel_signal(Arc::new(move || cancelled.load(Ordering::SeqCst)));
            FIXTURE.with(|value| *value.borrow_mut() = Some(case.fixture));
            let _reset = Reset;
            let socket = self.root.join("pam.sock");
            let _ = std::fs::remove_file(&socket);
            let listener = UnixListener::bind(&socket).unwrap();
            listener.set_nonblocking(true).unwrap();
            let mut command = Command::new(&self.driver);
            command
                .args([
                    case.service,
                    case.selected_user.as_deref().unwrap_or(&self.user),
                    case.password.unwrap_or(""),
                ])
                .env("LD_PRELOAD", &self.wrapper)
                .env("PAM_WRAPPER", "1")
                .env("PAM_WRAPPER_SERVICE_DIR", self.root.join("services"))
                .env("IRLUME_SOCKET", &socket)
                .env_remove("SSH_CONNECTION")
                .env_remove("SSH_TTY")
                .stdout(Stdio::null())
                .stderr(Stdio::null());
            if case.remote {
                command.env("SSH_CONNECTION", "192.0.2.1 1234 192.0.2.2 22");
            }
            let mut child = command.spawn().unwrap();
            let pid = child.id() as i32;
            let deadline = Instant::now() + Duration::from_secs(10);
            let mut requests = 0;
            let mut prepared_grant = false;
            let status = loop {
                if let Some(status) = child.try_wait().unwrap() {
                    break status;
                }
                if Instant::now() >= deadline {
                    let _ = child.kill();
                    let _ = child.wait();
                    panic!("PAM transaction did not finish");
                }
                match listener.accept() {
                    Ok((stream, _)) => {
                        stream
                            .set_read_timeout(Some(Duration::from_secs(2)))
                            .unwrap();
                        let peer = peer_cred(&stream).unwrap();
                        assert_eq!((peer.pid, peer.uid), (pid, self.uid));
                        let mut line = String::new();
                        BufReader::new(&stream).read_line(&mut line).unwrap();
                        let req: Request = serde_json::from_str(&line).unwrap();
                        assert!(
                            matches!(
                                (requests, &req),
                                (0, Request::UnsealPassword { .. })
                                    | (1, Request::Authenticate { .. })
                            ),
                            "expected unavailable-release then identity fallback, got {req:?}"
                        );
                        requests += 1;
                        let state = diagnostics::DiagnosticState::default();
                        let scope = state.begin(diagnostic_operation_class(&req));
                        let reply =
                            dispatch_scoped_session(req, &peer, engine, &scope, None, None, None);
                        prepared_grant |= is_face_grant(&reply.response);
                        if is_face_grant(&reply.response) {
                            if let Some(session) = &case.after_dispatch {
                                FIXTURE.with(|value| {
                                    value.borrow_mut().as_mut().unwrap().session = session.clone()
                                });
                            }
                        }
                        // A failed last-moment admission closes the socket. The
                        // actual PAM client must then take password fallback.
                        let _ = reply.respond(stream);
                    }
                    Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                        std::thread::sleep(Duration::from_millis(5))
                    }
                    Err(error) => panic!("accept: {error}"),
                }
            };
            engine.set_request_cancel_signal(Arc::new(|| false));
            let fixture = FIXTURE.with(|value| value.borrow().as_ref().unwrap().clone());
            assert!(fixture
                .observed_pids
                .iter()
                .all(|observed| *observed == pid));
            ResultCase {
                success: status.success(),
                requests,
                biometric_calls: fixture.biometric_calls,
                prepared_grant,
            }
        }
    }

    #[test]
    #[ignore = "requires freshly built irlume-pam, pam_wrapper and a C compiler"]
    fn shared_greeter_real_daemon_and_pam_refuse_cold_login_with_runtime() {
        let _guard = env_lock();
        let sandbox = sandbox("ms04-pam-cold");
        let mut engine = engine();
        let harness = Harness::new(&sandbox.dir);
        for service in ["gdm-password", "cosmic-greeter"] {
            for mode in ["ondemand", "facefirst"] {
                // Linger-only, another session and unavailable logind cannot
                // supply a session for this peer, regardless of /run/user.
                let mut wrong_user = local_session(harness.uid);
                wrong_user.uid = NOBODY;
                let mut remote = local_session(harness.uid);
                remote.remote = true;
                let mut greeter = local_session(harness.uid);
                greeter.class = "greeter".into();
                let mut tty = local_session(harness.uid);
                tty.kind = "tty".into();
                for session in [
                    Err(REFUSED),
                    Ok(wrong_user),
                    Ok(remote),
                    Ok(greeter),
                    Ok(tty),
                ] {
                    let result = harness.run(&mut engine, Case::new(service, mode, session));
                    assert!(
                        !result.success,
                        "{service}/{mode}: cold login must not grant"
                    );
                    assert_eq!(result.requests, 2, "UnsealUnavailable then Authenticate");
                    assert_eq!(
                        result.biometric_calls, 0,
                        "policy refusal must precede capture"
                    );
                }
                // An unrelated local session must not rescue GDM's ambiguous
                // worker context either. There is no qualified GDM adapter yet.
                if service == "gdm-password" {
                    let result = harness.run(
                        &mut engine,
                        Case::new(service, mode, Ok(local_session(harness.uid))),
                    );
                    assert!(!result.success);
                    assert_eq!(result.biometric_calls, 0);
                }
            }
        }
    }

    #[test]
    #[ignore = "requires freshly built irlume-pam, pam_wrapper and a C compiler"]
    fn shared_greeter_real_daemon_and_pam_preserve_bound_unlock_and_password() {
        let _guard = env_lock();
        let sandbox = sandbox("ms04-pam-bound");
        let mut engine = engine();
        let harness = Harness::new(&sandbox.dir);
        for mode in ["ondemand", "facefirst"] {
            for service in ["cosmic-greeter", "kde"] {
                let result = harness.run(
                    &mut engine,
                    Case::new(service, mode, Ok(local_session(harness.uid))),
                );
                assert!(result.success, "bound {service}/{mode}");
                assert_eq!(result.requests, 2);
                assert_eq!(result.biometric_calls, 1);
            }
            for service in ["gdm-password", "cosmic-greeter"] {
                for password in ["fixture-password", "wrong-password"] {
                    let mut case = Case::new(service, mode, Err(REFUSED));
                    case.password = Some(password);
                    let result = harness.run(&mut engine, case);
                    assert_eq!(result.success, password == "fixture-password");
                    assert_eq!(result.biometric_calls, 0);
                }
                let mut case = Case::new(service, mode, Ok(local_session(harness.uid)));
                case.remote = true;
                let result = harness.run(&mut engine, case);
                assert!(!result.success);
                assert_eq!(
                    result.requests, 0,
                    "PAM must refuse explicit remote context before the socket"
                );
            }
        }
    }

    #[test]
    #[ignore = "requires freshly built irlume-pam, pam_wrapper and a C compiler"]
    fn shared_greeter_real_daemon_and_pam_recheck_before_grant_and_delivery() {
        let _guard = env_lock();
        let sandbox = sandbox("ms04-pam-change");
        let mut engine = engine();
        let harness = Harness::new(&sandbox.dir);
        let mut replaced = local_session(harness.uid);
        replaced.created += 1;
        let mut restarted = local_session(harness.uid);
        restarted.owner = ":1.43".into();
        let mut moved = local_session(harness.uid);
        moved.id = "3".into();
        moved.path = "/org/freedesktop/login1/session/_33".into();
        for changed in [Err(REFUSED), Ok(replaced), Ok(restarted), Ok(moved)] {
            let mut case = Case::new(
                "cosmic-greeter",
                "facefirst",
                Ok(local_session(harness.uid)),
            );
            case.fixture.after_auth = Some(changed.clone());
            let result = harness.run(&mut engine, case);
            assert!(!result.success && !result.prepared_grant);
            assert_eq!(result.biometric_calls, 1);
            let mut case = Case::new(
                "cosmic-greeter",
                "facefirst",
                Ok(local_session(harness.uid)),
            );
            case.after_dispatch = Some(changed);
            let result = harness.run(&mut engine, case);
            assert!(
                !result.success && result.prepared_grant,
                "prepared grant must not escape changed delivery context: {result:?}"
            );
        }
        let mut case = Case::new(
            "cosmic-greeter",
            "facefirst",
            Ok(local_session(harness.uid)),
        );
        case.fixture.cancel_after_auth = Some(Arc::new(AtomicBool::new(false)));
        let result = harness.run(&mut engine, case);
        assert!(!result.success && !result.prepared_grant);
        let mut case = Case::new(
            "cosmic-greeter",
            "facefirst",
            Ok(local_session(harness.uid)),
        );
        case.selected_user = Some(if harness.uid == 0 { "nobody" } else { "root" }.into());
        let result = harness.run(&mut engine, case);
        assert!(!result.success);
        assert_eq!(result.biometric_calls, 0);
    }

    #[test]
    #[ignore = "requires bubblewrap, freshly built irlume-pam, pam_wrapper and a C compiler"]
    fn shared_greeter_real_daemon_and_pam_with_real_runtime_directory() {
        let _guard = env_lock();
        let parent_namespace = std::fs::read_link("/proc/self/ns/mnt").unwrap();
        let result = Command::new("/usr/bin/timeout")
            .args(["--kill-after=5", "90", "/usr/bin/bwrap"])
            .args([
                "--die-with-parent",
                "--unshare-user",
                "--uid",
                "0",
                "--gid",
                "0",
                "--unshare-pid",
                "--unshare-net",
                "--unshare-ipc",
                "--unshare-uts",
                "--ro-bind",
                "/",
                "/",
                "--tmpfs",
                "/run",
                "--dir",
                "/run/user/0",
                "--tmpfs",
                "/tmp",
                "--proc",
                "/proc",
                "--dev",
                "/dev",
                "--",
            ])
            .arg(std::env::current_exe().unwrap())
            .args([
                "--exact",
                "tests::shared_greeter::shared_greeter_namespace_child",
                "--ignored",
                "--nocapture",
                "--test-threads=1",
            ])
            .env("IRLUME_TEST_SHARED_GREETER_PARENT_MNT", parent_namespace)
            .env("TMPDIR", "/tmp")
            .output()
            .expect("timeout and bubblewrap are required for the runtime-directory regression");
        assert!(
            result.status.success(),
            "namespace regression failed: {}\n{}",
            String::from_utf8_lossy(&result.stdout),
            String::from_utf8_lossy(&result.stderr)
        );
        assert!(
            String::from_utf8_lossy(&result.stdout).contains("MS04_REAL_RUNTIME_DIRECTORY_CHECKED"),
            "child must execute the directory assertions and complete the PAM matrix"
        );
    }

    #[test]
    #[ignore = "child entry point for the isolated runtime-directory regression"]
    fn shared_greeter_namespace_child() {
        let Some(parent_namespace) = std::env::var_os("IRLUME_TEST_SHARED_GREETER_PARENT_MNT")
        else {
            return;
        };
        assert_ne!(
            std::fs::read_link("/proc/self/ns/mnt").unwrap(),
            PathBuf::from(parent_namespace)
        );
        // SAFETY: getuid only reads this process's real UID.
        assert_eq!(unsafe { libc::getuid() }, 0);
        // This is the exact path the old heuristic read for the selected root
        // account, created by bubblewrap inside a private /run tmpfs. The host's
        // runtime directories are never created, mounted over or removed.
        assert!(Path::new("/run/user/0").is_dir());
        shared_greeter_real_daemon_and_pam_refuse_cold_login_with_runtime();
        shared_greeter_real_daemon_and_pam_preserve_bound_unlock_and_password();
        shared_greeter_real_daemon_and_pam_recheck_before_grant_and_delivery();
        println!("MS04_REAL_RUNTIME_DIRECTORY_CHECKED");
    }

    #[test]
    fn shared_unlock_binding_refuses_an_exited_process_and_wrong_peer_identity() {
        let _guard = env_lock();
        // SAFETY: getuid only reads this process's real UID.
        let uid = unsafe { libc::getuid() };
        let user = users::name_for_uid(uid).unwrap();
        FIXTURE.with(|value| *value.borrow_mut() = Some(Fixture::new(Ok(local_session(uid)))));
        let _reset = Reset;
        let mut child = Command::new("sleep").arg("30").spawn().unwrap();
        let peer = Peer {
            pid: child.id() as i32,
            uid,
            gid: uid,
        };
        let binding = shared_unlock::Binding::capture(&user, &peer).unwrap();
        assert!(binding.validate().is_ok());
        let mut wrong = peer.clone();
        wrong.uid = NOBODY;
        assert!(shared_unlock::Binding::capture(&user, &wrong).is_err());
        child.kill().unwrap();
        child.wait().unwrap();
        assert!(
            binding.validate().is_err(),
            "old proc fd must not follow a replacement PID"
        );
        assert!(shared_unlock::Binding::capture(&user, &peer).is_err());
    }
}

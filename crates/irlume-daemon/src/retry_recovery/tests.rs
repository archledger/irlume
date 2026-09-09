use super::*;
use std::os::unix::fs::PermissionsExt;
use std::sync::atomic::{AtomicU64, Ordering};
static SERIAL: AtomicU64 = AtomicU64::new(0);
fn env_lock() -> std::sync::RwLockWriteGuard<'static, ()> {
    crate::test_support::env_write()
}
struct Fixture {
    path: std::path::PathBuf,
    old: Option<std::ffi::OsString>,
}
impl Fixture {
    fn new() -> Self {
        let path = std::env::temp_dir().join(format!(
            "irlume-retry-dispatch-{}-{}",
            std::process::id(),
            SERIAL.fetch_add(1, Ordering::SeqCst)
        ));
        std::fs::create_dir(&path).unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o700)).unwrap();
        let old = std::env::var_os("IRLUME_STATE_DIR");
        std::env::set_var("IRLUME_STATE_DIR", &path);
        Self { path, old }
    }
    fn face(&self, peer: &Peer, user: &str) -> std::path::PathBuf {
        let dir = self.path.join("retry");
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o700)).unwrap();
        let file = dir.join(format!("{}.json", peer.uid));
        irlume_common::write_atomic_reporting(&file,serde_json::to_string(&serde_json::json!({"version":1,"uid":peer.uid,"account":user,"strikes":4,"cooldown":null})).unwrap().as_bytes(),0o600).unwrap();
        file
    }
    fn helper(&self, body: &str) -> std::path::PathBuf {
        let file = self.path.join("helper");
        std::fs::write(&file, format!("#!/bin/sh\n{body}\n")).unwrap();
        std::fs::set_permissions(&file, std::fs::Permissions::from_mode(0o700)).unwrap();
        file
    }
}
impl Drop for Fixture {
    fn drop(&mut self) {
        match &self.old {
            Some(v) => std::env::set_var("IRLUME_STATE_DIR", v),
            None => std::env::remove_var("IRLUME_STATE_DIR"),
        }
        std::fs::remove_dir_all(&self.path).unwrap();
    }
}
fn peer() -> Peer {
    // SAFETY: credential getters have no preconditions.
    let (uid, gid) = unsafe { (libc::getuid(), libc::getgid()) };
    Peer {
        uid,
        gid,
        pid: std::process::id() as i32,
    }
}
#[test]
fn own_account_reset_binds_password_proof_and_preserves_state_on_refusal() {
    let _env = env_lock();
    let f = Fixture::new();
    let peer = peer();
    let user = crate::users::name_for_uid(peer.uid).unwrap();
    let face = f.face(&peer, &user);
    let (_client, server) = UnixStream::pair().unwrap();
    let request = Request::RetryReset {
        user: user.clone(),
        password: irlume_common::SecretBytes::new(b"synthetic password".to_vec()),
    };
    if peer.uid != 0 {
        let result = dispatch_using(&request, &peer, &server, true, |u, p, active| {
            assert_eq!(u, user);
            assert_eq!(p, b"synthetic password");
            assert!(active());
            Err(REFUSED)
        });
        assert!(matches!(result, Response::Error(_)));
        let value: serde_json::Value =
            serde_json::from_slice(&std::fs::read(&face).unwrap()).unwrap();
        assert_eq!(value["strikes"], 4);
    }
    let result = dispatch_using(&request, &peer, &server, true, |_, _, active| {
        assert!(active());
        Ok(())
    });
    assert!(matches!(result, Response::Ok(_)), "{result:?}");
    let value: serde_json::Value = serde_json::from_slice(&std::fs::read(face).unwrap()).unwrap();
    assert_eq!(value["strikes"], 0);
}
#[test]
fn cross_account_reset_refuses_before_creating_state_or_verifying() {
    let _env = env_lock();
    let f = Fixture::new();
    let owner = peer();
    let user = crate::users::name_for_uid(owner.uid).unwrap();
    let other = Peer {
        uid: owner.uid + 1,
        gid: owner.gid,
        pid: owner.pid,
    };
    let (_client, server) = UnixStream::pair().unwrap();
    let request = Request::RetryReset {
        user,
        password: irlume_common::SecretBytes::new(b"synthetic".to_vec()),
    };
    let result = dispatch_using(&request, &other, &server, true, |_, _, _| {
        panic!("unauthorized verifier")
    });
    assert!(matches!(result,Response::Error(ref e) if e.contains("not authorized")));
    assert!(!f.path.join("retry").exists());
}
#[test]
fn disconnected_client_cannot_reset_or_verify() {
    let _env = env_lock();
    let f = Fixture::new();
    let peer = peer();
    let user = crate::users::name_for_uid(peer.uid).unwrap();
    let face = f.face(&peer, &user);
    let (client, server) = UnixStream::pair().unwrap();
    drop(client);
    let request = Request::RetryReset {
        user,
        password: irlume_common::SecretBytes::new(b"synthetic".to_vec()),
    };
    assert!(matches!(
        dispatch_using(&request, &peer, &server, true, |_, _, _| panic!(
            "disconnected verifier"
        )),
        Response::Error(_)
    ));
    let value: serde_json::Value = serde_json::from_slice(&std::fs::read(face).unwrap()).unwrap();
    assert_eq!(value["strikes"], 4);
}
#[test]
fn verifier_timeout_kills_and_reaps_the_exact_process() {
    let _env = env_lock();
    let f = Fixture::new();
    let pidfile = f.path.join("pid");
    let helper = f.helper(&format!(
        "echo $$ > '{}'\nexec /bin/sleep 60",
        pidfile.display()
    ));
    let t = Instant::now();
    assert!(run_helper(
        &helper,
        "fixture",
        b"synthetic",
        Duration::from_millis(100),
        || true
    )
    .is_err());
    assert!(t.elapsed() < Duration::from_secs(3));
    let pid = std::fs::read_to_string(pidfile).unwrap();
    assert!(!Path::new("/proc").join(pid.trim()).exists());
}
#[test]
fn helper_exit_status_and_cancel_control_verification() {
    let _env = env_lock();
    let f = Fixture::new();
    let success = f.helper("exit 0");
    assert!(run_helper(
        &success,
        "fixture",
        b"synthetic",
        Duration::from_secs(2),
        || true
    )
    .is_ok());
    assert!(run_helper(
        &success,
        "fixture",
        b"synthetic",
        Duration::from_secs(2),
        || false
    )
    .is_err());
    let failure = f.helper("exit 1");
    assert!(run_helper(
        &failure,
        "fixture",
        b"synthetic",
        Duration::from_secs(2),
        || true
    )
    .is_err());
    assert!(run_helper(&success, "fixture", b"", Duration::from_secs(2), || true).is_err());
}

#[test]
fn only_the_qualified_password_service_is_accepted() {
    let exact = "auth required pam_unix.so nodelay\naccount required pam_unix.so\n";
    assert!(supported_service(exact));
    assert!(supported_service("# local passwords\n auth   required pam_unix.so nodelay # no PAM delay\n\naccount required pam_unix.so\n"));
    for unsupported in [
        exact.replace("nodelay", "nullok"),
        exact.replace("required", "sufficient"),
        exact.replace("pam_unix.so", "pam_irlume.so"),
        exact.replace(
            "account required pam_unix.so",
            "account include system-auth",
        ),
        format!("{exact}auth optional pam_permit.so\n"),
        "auth required pam_unix.so nodelay\n".into(),
    ] {
        assert!(!supported_service(&unsupported), "{unsupported}");
    }
}

#[test]
fn retry_status_answers_while_models_are_not_ready() {
    use std::io::BufRead;
    let _env = env_lock();
    let _fixture = Fixture::new();
    let user = crate::users::name_for_uid(peer().uid).unwrap();
    let arbiter = crate::arbiter::Arbiter::<crate::Queued>::new();
    let ready = std::sync::atomic::AtomicBool::new(false);
    let diagnostic = crate::diagnostics::DiagnosticState::default();
    std::thread::scope(|scope| {
        let (mut client, server) = UnixStream::pair().unwrap();
        let worker = scope.spawn(|| crate::serve(server, &arbiter, &ready, &diagnostic).unwrap());
        client
            .set_read_timeout(Some(Duration::from_secs(2)))
            .unwrap();
        let wire = serde_json::to_vec(&Request::RetryStatus { user }).unwrap();
        client.write_all(&wire).unwrap();
        client.write_all(b"\n").unwrap();
        let mut line = String::new();
        std::io::BufReader::new(&client)
            .read_line(&mut line)
            .unwrap();
        let response: Response = serde_json::from_str(&line).unwrap();
        assert!(
            matches!(response, Response::RetryStatus { failures: 0, .. }),
            "{response:?}"
        );
        drop(client);
        worker.join().unwrap();
    });
}

#[test]
fn buffered_input_cannot_hide_client_disconnect_from_reset() {
    let _env = env_lock();
    let f = Fixture::new();
    let peer = peer();
    let user = crate::users::name_for_uid(peer.uid).unwrap();
    let face = f.face(&peer, &user);
    let (mut client, server) = UnixStream::pair().unwrap();
    client.write_all(b"extra").unwrap();
    drop(client);
    let request = Request::RetryReset {
        user,
        password: irlume_common::SecretBytes::new(b"synthetic".to_vec()),
    };
    let result = dispatch_using(&request, &peer, &server, true, |_, _, _| {
        panic!("closed connection must not verify")
    });
    assert!(matches!(result, Response::Error(_)));
    let value: serde_json::Value = serde_json::from_slice(&std::fs::read(face).unwrap()).unwrap();
    assert_eq!(value["strikes"], 4);
}

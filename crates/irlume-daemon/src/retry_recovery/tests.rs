// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright the irlume contributors.

use super::*;
use std::os::unix::fs::PermissionsExt;
use std::sync::atomic::{AtomicU64, Ordering};
static SERIAL: AtomicU64 = AtomicU64::new(0);
/// Bound for a wait whose outcome must not depend on the clock. A helper run
/// that ends on its own returns as soon as the helper exits, so this only caps
/// a hang, with room for a sanitizer build on a loaded runner.
const UNHURRIED: Duration = Duration::from_secs(30);
/// Exits 0 only when stdin is exactly the fixture's password followed by EOF,
/// the input the real helper verifies. `read` succeeds only when it finds a
/// newline, so a newline or anything after one refuses; without one it reads
/// until `run_helper` closes stdin. A helper that exits without reading can
/// close the pipe before `run_helper` writes, which refuses the run however
/// the helper exits.
const ACCEPTS: &str = "IFS= read -r secret && exit 1\n[ \"$secret\" = synthetic ]";
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
    /// A helper script for [`run_script`].
    fn script(&self, name: &str, body: &str) -> std::path::PathBuf {
        let file = self.path.join(name);
        std::fs::write(&file, format!("{body}\n")).unwrap();
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
/// Runs `script` as the password helper. `/bin/sh` is the program exec'd and
/// the script its one argument (the account name in production), so no test
/// execs a file it wrote: exec fails with ETXTBSY while any process holds the
/// file open for writing, and a sibling test that forks during the write
/// leaves its child such a descriptor.
fn run_script(
    script: &Path,
    password: &[u8],
    budget: Duration,
    active: impl Fn() -> bool,
) -> Result<(), &'static str> {
    let script = script.to_str().unwrap();
    run_helper(Path::new("/bin/sh"), script, password, budget, active)
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
    let sleeper = f.script(
        "sleeper",
        &format!("echo $$ > '{}'\nexec /bin/sleep 60", pidfile.display()),
    );
    let recorded = || {
        std::fs::read_to_string(&pidfile)
            .ok()
            .filter(|pid| pid.ends_with('\n'))
    };
    // `run_helper` calls `active` once before it spawns, then on every poll.
    // The first poll waits until the helper has recorded its pid, so a helper
    // that starts late on a loaded runner is not killed before there is a pid
    // to check. The 100 ms budget still ends the run, not the helper's 60 s.
    let calls = std::cell::Cell::new(0);
    let running = std::cell::Cell::new(None);
    let active = || {
        calls.set(calls.get() + 1);
        if calls.get() == 2 {
            let until = Instant::now() + UNHURRIED;
            while recorded().is_none() && Instant::now() < until {
                std::thread::sleep(Duration::from_millis(5));
            }
            running.set(Some(Instant::now()));
        }
        true
    };
    assert_eq!(
        run_script(&sleeper, b"synthetic", Duration::from_millis(100), active),
        Err(REFUSED)
    );
    let running = running.get().expect("run_helper polled the helper");
    assert!(running.elapsed() < Duration::from_secs(3));
    let pid = recorded().expect("the helper recorded its pid");
    assert!(!Path::new("/proc").join(pid.trim()).exists());
}
#[test]
fn helper_exit_status_and_cancel_control_verification() {
    let _env = env_lock();
    let f = Fixture::new();
    let accepts = f.script("accepts", ACCEPTS);
    assert_eq!(
        run_script(&accepts, b"synthetic", UNHURRIED, || true),
        Ok(())
    );
    assert_eq!(
        run_script(&accepts, b"synthetic", UNHURRIED, || false),
        Err(REFUSED)
    );
    // The helper reads this password and exits 1: only its status refuses.
    assert_eq!(
        run_script(&accepts, b"wrong", UNHURRIED, || true),
        Err(REFUSED)
    );
    assert_eq!(run_script(&accepts, b"", UNHURRIED, || true), Err(REFUSED));
}

#[test]
fn fixture_helper_runs_while_its_script_is_open_for_writing() {
    // A sibling test that forks while `Fixture::script` writes leaves its
    // child a write descriptor; holding one here pins that case.
    let _env = env_lock();
    let f = Fixture::new();
    let accepts = f.script("accepts", ACCEPTS);
    let _writer = std::fs::OpenOptions::new()
        .append(true)
        .open(&accepts)
        .unwrap();
    assert_eq!(
        run_script(&accepts, b"synthetic", UNHURRIED, || true),
        Ok(())
    );
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
        client.set_read_timeout(Some(UNHURRIED)).unwrap();
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

// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright the irlume contributors.

//! Activation descriptor regressions. Only isolated children manipulate fd3.

use crate::{inherited_listener, socket_activated};
use std::fs::{self, File};
use std::io::{Read, Write};
use std::os::fd::{AsRawFd, FromRawFd, IntoRawFd, OwnedFd};
use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::PathBuf;
use std::time::{Duration, Instant};

const ACTIVATION_FD: i32 = 3;

fn flags(fd: i32, command: i32) -> i32 {
    // SAFETY: these fcntl commands take no pointer argument and only read flags.
    let value = unsafe { libc::fcntl(fd, command) };
    assert!(value >= 0, "fcntl: {}", std::io::Error::last_os_error());
    value
}

fn identity(fd: i32) -> (u64, u64) {
    let metadata = fs::metadata(format!("/proc/self/fd/{fd}")).unwrap();
    (metadata.dev(), metadata.ino())
}

struct ActivationSocket {
    dir: PathBuf,
    path: PathBuf,
    fd: Option<OwnedFd>,
    identity: (u64, u64),
    status_flags: i32,
}

impl ActivationSocket {
    // Call only after test_support::isolated has entered the dedicated child.
    fn new() -> Self {
        let dir = std::env::temp_dir().join(format!("irlume-listener-{}", std::process::id()));
        fs::create_dir(&dir).unwrap();
        let path = dir.join("activation.sock");
        let listener = UnixListener::bind(&path).unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o620)).unwrap();
        listener.set_nonblocking(true).unwrap();
        let original: OwnedFd = listener.into();
        let fd = if original.as_raw_fd() == ACTIVATION_FD {
            original
        } else {
            // SAFETY: original is live, and fd3 is replaced only in this
            // isolated process, never in the parallel parent test harness.
            let duplicated = unsafe { libc::dup2(original.as_raw_fd(), ACTIVATION_FD) };
            assert_eq!(duplicated, ACTIVATION_FD);
            drop(original);
            // SAFETY: dup2 returned the newly owned fd3; no other owner exists.
            unsafe { OwnedFd::from_raw_fd(duplicated) }
        };
        let old_flags = flags(ACTIVATION_FD, libc::F_GETFD);
        // SAFETY: F_SETFD takes an integer and fd is owned by this fixture.
        let result =
            unsafe { libc::fcntl(ACTIVATION_FD, libc::F_SETFD, old_flags & !libc::FD_CLOEXEC) };
        assert_eq!(result, 0);
        assert_eq!(flags(ACTIVATION_FD, libc::F_GETFD) & libc::FD_CLOEXEC, 0);
        let identity = identity(ACTIVATION_FD);
        let status_flags = flags(ACTIVATION_FD, libc::F_GETFL);
        assert_ne!(status_flags & libc::O_NONBLOCK, 0);
        assert!(!socket_activated(), "a fresh child must not be activated");
        println!("fixture proved non-CLOEXEC fd3; socket={identity:?}; status={status_flags}");
        Self {
            dir,
            path,
            fd: Some(fd),
            identity,
            status_flags,
        }
    }

    fn select(&mut self) {
        std::env::set_var("LISTEN_PID", std::process::id().to_string());
        std::env::set_var("LISTEN_FDS", "1");
        std::env::set_var("LISTEN_FDNAMES", "irlume");
        std::env::set_var("LISTEN_PIDFDID", "not-interpreted-by-this-protocol");
        // Transfer ownership to the production adoption call, without duping
        // or changing the descriptor's close-on-exec state along the way.
        assert_eq!(self.fd.take().unwrap().into_raw_fd(), ACTIVATION_FD);
    }
}

impl Drop for ActivationSocket {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.dir);
    }
}

fn assert_environment_consumed() {
    assert!(std::env::var_os("LISTEN_PID").is_none());
    assert!(std::env::var_os("LISTEN_FDS").is_none());
    assert!(std::env::var_os("LISTEN_FDNAMES").is_none());
    assert!(std::env::var_os("LISTEN_PIDFDID").is_none());
}

fn exchange(listener: &UnixListener, mut client: UnixStream) {
    client
        .set_read_timeout(Some(Duration::from_secs(1)))
        .unwrap();
    client
        .set_write_timeout(Some(Duration::from_secs(1)))
        .unwrap();
    client.write_all(b"ping").unwrap();
    let (mut accepted, _) = listener.accept().unwrap();
    accepted
        .set_read_timeout(Some(Duration::from_secs(1)))
        .unwrap();
    accepted
        .set_write_timeout(Some(Duration::from_secs(1)))
        .unwrap();
    let mut request = [0; 4];
    accepted.read_exact(&mut request).unwrap();
    assert_eq!(&request, b"ping");
    accepted.write_all(b"pong").unwrap();
    let mut response = [0; 4];
    client.read_exact(&mut response).unwrap();
    assert_eq!(&response, b"pong");
}

#[test]
fn adoption_preserves_socket_backlog_status_and_activation_state() {
    const NAME: &str =
        "listener_tests::adoption_preserves_socket_backlog_status_and_activation_state";
    if crate::test_support::isolated(NAME) {
        return;
    }
    let _env = crate::tests::env_lock();
    let mut fixture = ActivationSocket::new();
    let first = UnixStream::connect(&fixture.path).unwrap();
    let second = UnixStream::connect(&fixture.path).unwrap();
    let path_identity = fs::metadata(&fixture.path).unwrap().ino();
    fixture.select();
    let listener = inherited_listener()
        .expect("selected socket must be secured")
        .expect("selected socket must be adopted");
    assert_eq!(identity(listener.as_raw_fd()), fixture.identity);
    assert_eq!(
        flags(listener.as_raw_fd(), libc::F_GETFL),
        fixture.status_flags
    );
    assert_eq!(fs::metadata(&fixture.path).unwrap().ino(), path_identity);
    assert_eq!(fs::metadata(&fixture.path).unwrap().mode() & 0o777, 0o620);
    assert_eq!(
        listener.local_addr().unwrap().as_pathname(),
        Some(fixture.path.as_path())
    );
    assert!(socket_activated());
    assert_environment_consumed();
    exchange(&listener, first);
    exchange(&listener, second);
    exchange(&listener, UnixStream::connect(&fixture.path).unwrap());
}

#[test]
fn adoption_sets_close_on_exec() {
    const NAME: &str = "listener_tests::adoption_sets_close_on_exec";
    if crate::test_support::isolated(NAME) {
        return;
    }
    let _env = crate::tests::env_lock();
    let mut fixture = ActivationSocket::new();
    fixture.select();
    let listener = inherited_listener()
        .expect("selected socket must be secured")
        .expect("selected socket must be adopted");
    assert_eq!(identity(listener.as_raw_fd()), fixture.identity);
    assert_environment_consumed();
    assert!(socket_activated());
    assert_ne!(
        flags(listener.as_raw_fd(), libc::F_GETFD) & libc::FD_CLOEXEC,
        0,
        "adoption must secure the original listener against exec inheritance"
    );
}

#[test]
fn adopted_socket_is_absent_after_exec() {
    const NAME: &str = "listener_tests::adopted_socket_is_absent_after_exec";
    const IDENTITY: &str = "IRLUME_TEST_ACTIVATION_SOCKET_IDENTITY";
    const MARKER: &str = "activation-exec-child-checked";
    if let Ok(expected) = std::env::var(IDENTITY) {
        let _env = crate::tests::env_lock();
        assert_environment_consumed();
        // A runtime or this open may reuse fd3. Test the original object across
        // all open descriptors, not whether one descriptor number is absent.
        let _replacement = File::open("/dev/null").unwrap();
        let mut inherited = Vec::new();
        for entry in fs::read_dir("/proc/self/fd").unwrap() {
            let entry = entry.unwrap();
            match fs::metadata(entry.path()) {
                Ok(metadata) => {
                    if format!("{}:{}", metadata.dev(), metadata.ino()) == expected {
                        inherited.push(entry.file_name());
                    }
                }
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
                Err(error) => panic!("cannot inspect child descriptor: {error}"),
            }
        }
        println!("{MARKER}: inherited original socket descriptors={inherited:?}");
        assert!(
            inherited.is_empty(),
            "original activation listener survived exec"
        );
        return;
    }
    if crate::test_support::isolated(NAME) {
        return;
    }
    let _env = crate::tests::env_lock();
    let mut fixture = ActivationSocket::new();
    fixture.select();
    let listener = inherited_listener()
        .expect("selected socket must be secured")
        .expect("selected socket must be adopted");
    assert_eq!(identity(listener.as_raw_fd()), fixture.identity);
    assert_environment_consumed();
    let mut command = std::process::Command::new(std::env::current_exe().unwrap());
    command
        .args(["--exact", NAME, "--nocapture", "--test-threads=1"])
        .env(
            IDENTITY,
            format!("{}:{}", fixture.identity.0, fixture.identity.1),
        );
    let output =
        irlume_common::process::output_until(&mut command, Instant::now() + Duration::from_secs(3))
            .unwrap();
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        output.status.success() && stdout.contains(MARKER) && stdout.contains("1 passed; 0 failed"),
        "exec child failed or ran no test: {}\nstdout: {stdout}\nstderr: {}",
        output.status,
        String::from_utf8_lossy(&output.stderr)
    );
    // Keep the successful child observation in direct --nocapture evidence.
    println!("{stdout}");
    exchange(&listener, UnixStream::connect(&fixture.path).unwrap());
}

#[test]
fn unselected_activation_consumes_environment_without_taking_fd() {
    const NAME: &str =
        "listener_tests::unselected_activation_consumes_environment_without_taking_fd";
    if crate::test_support::isolated(NAME) {
        return;
    }
    let _env = crate::tests::env_lock();
    let fixture = ActivationSocket::new();
    let ours = std::process::id().to_string();
    for (pid, count) in [
        (None, None),
        (Some("0"), Some("1")),
        (Some("bad-pid"), Some("1")),
        (Some(ours.as_str()), None),
        (Some(ours.as_str()), Some("bad-count")),
        (Some(ours.as_str()), Some("0")),
        (Some(ours.as_str()), Some("2")),
    ] {
        std::env::set_var("LISTEN_FDNAMES", "unselected");
        std::env::set_var("LISTEN_PIDFDID", "unselected");
        for (key, value) in [("LISTEN_PID", pid), ("LISTEN_FDS", count)] {
            if let Some(value) = value {
                std::env::set_var(key, value);
            } else {
                std::env::remove_var(key);
            }
        }
        assert!(inherited_listener().unwrap().is_none());
        assert!(!socket_activated());
        assert_environment_consumed();
        assert_eq!(identity(ACTIVATION_FD), fixture.identity);
        assert_eq!(flags(ACTIVATION_FD, libc::F_GETFD) & libc::FD_CLOEXEC, 0);
    }
}

#[test]
fn selected_closed_fd_is_an_error_without_activation() {
    const NAME: &str = "listener_tests::selected_closed_fd_is_an_error_without_activation";
    if crate::test_support::isolated(NAME) {
        return;
    }
    let _env = crate::tests::env_lock();
    let mut fixture = ActivationSocket::new();
    std::env::set_var("LISTEN_PID", std::process::id().to_string());
    std::env::set_var("LISTEN_FDS", "1");
    std::env::set_var("LISTEN_FDNAMES", "irlume");
    std::env::set_var("LISTEN_PIDFDID", "unused");
    drop(fixture.fd.take().unwrap());
    // SAFETY: F_GETFD takes no pointers; the descriptor is deliberately closed
    // only in this isolated test child.
    assert_eq!(unsafe { libc::fcntl(ACTIVATION_FD, libc::F_GETFD) }, -1);
    let error = inherited_listener().expect_err("selected closed fd must not permit self-binding");
    assert_eq!(error.raw_os_error(), Some(libc::EBADF));
    assert!(!socket_activated());
    assert_environment_consumed();
}

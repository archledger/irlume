// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright the irlume contributors.

//! Blocking client for the `irlumed` socket, shared by the CLI (user session)
//! and the PAM module (root, inside the auth stack). One request per
//! connection: send a newline-terminated JSON [`Request`], read a
//! newline-terminated [`Response`].
//!
//! Two protections live here so every caller gets them: a bounded CONNECT
//! timeout (`UnixStream::connect` has none, so a stalled listener could
//! otherwise freeze a login/sudo prompt indefinitely), and zeroizing of the
//! serialized request/response line buffers (they may carry a password or an
//! unsealed secret in transit, before it lands inside a zeroizing `SecretBytes`).

use crate::{Request, Response, SOCKET_PATH};
use std::io::{self, BufRead, BufReader, Write};
use std::os::unix::net::UnixStream;
use std::path::{Path, PathBuf};
use std::time::Duration;
use zeroize::Zeroize;

/// Bounded wait for the initial connect (distinct from the read timeout, which
/// must be long enough for a camera capture).
const CONNECT_TIMEOUT: Duration = Duration::from_secs(5);
/// Short budgets for the TUI status poll, so a wedged daemon doesn't freeze the
/// UI: fail fast and let the next tick retry.
const POLL_CONNECT_TIMEOUT: Duration = Duration::from_millis(1200);
const POLL_RW_TIMEOUT: Duration = Duration::from_millis(1500);
/// Default read/write timeout for management requests.
const DEFAULT_RW_TIMEOUT: Duration = Duration::from_secs(30);

/// Read an environment override that must NEVER be honoured in a
/// secure-execution context. `pam_irlume` is linked into setuid-root PAM stacks
/// (notably `/etc/pam.d/sudo` under `--with-sudo`), which inherit the invoking
/// user's environment. If the socket path were taken from `getenv` there, a
/// local user could run `IRLUME_SOCKET=/tmp/evil.sock sudo …`, point the module
/// at a fake daemon that always replies "granted", and get root with no password
/// or face. `secure_getenv` returns NULL under AT_SECURE (setuid/setgid/added
/// capabilities), so in exactly those contexts the compiled default wins, while
/// the daemon (a clean systemd environment) and dev/test clients keep the
/// override.
fn secure_env(name: &str) -> Option<std::ffi::OsString> {
    use std::os::unix::ffi::OsStringExt;
    // glibc's secure_getenv; not surfaced by the `libc` crate, so declare it
    // (the shipping targets are all glibc: Fedora, Debian/Ubuntu, Arch).
    extern "C" {
        fn secure_getenv(name: *const libc::c_char) -> *mut libc::c_char;
    }
    let key = std::ffi::CString::new(name).ok()?;
    // SAFETY: `key` is a valid NUL-terminated C string. secure_getenv returns a
    // pointer into the environ block (or NULL); we copy the bytes out before
    // returning, so the borrow of environ does not escape this function.
    let ptr = unsafe { secure_getenv(key.as_ptr()) };
    if ptr.is_null() {
        return None;
    }
    let bytes = unsafe { std::ffi::CStr::from_ptr(ptr) }.to_bytes().to_vec();
    Some(std::ffi::OsString::from_vec(bytes))
}

/// Resolve the socket path. `IRLUME_SOCKET` overrides it for the daemon and
/// dev/test, but is ignored in a setuid/secure-execution context (via
/// `secure_env`/`secure_getenv`) so a PAM module in a setuid stack cannot be
/// redirected to a rogue daemon.
pub fn socket_path() -> PathBuf {
    secure_env("IRLUME_SOCKET")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from(SOCKET_PATH))
}

/// Send `req` with the default read/write timeout.
pub fn request(req: &Request) -> io::Result<Response> {
    request_with_timeout(req, DEFAULT_RW_TIMEOUT)
}

/// A short-budget poll: used by the TUI's periodic status refresh so a busy or
/// wedged daemon (mid-capture, not accepting) fails fast instead of stalling the
/// UI thread for the full connect/read budget on every probe.
pub fn request_poll(req: &Request) -> io::Result<Response> {
    request_with_timeouts(req, POLL_CONNECT_TIMEOUT, POLL_RW_TIMEOUT)
}

/// Send `req`, allowing `rw_timeout` for the reply (e.g. a longer budget for an
/// unseal that does a full camera capture + liveness + match first).
pub fn request_with_timeout(req: &Request, rw_timeout: Duration) -> io::Result<Response> {
    request_with_timeouts(req, CONNECT_TIMEOUT, rw_timeout)
}

/// Map a "nobody is listening" error to the actionable start-the-daemon
/// message. A missing socket / dead peer is the #1 first-run failure (fresh
/// package install, unit disabled by distro preset policy), so name the daemon
/// and the exact command instead of a raw errno. Covers every errno the
/// no-listener case produces across kernels: ENOENT (no socket file),
/// ECONNREFUSED (socket file, no accept), ECONNRESET / EPIPE (stale socket that
/// connects then resets on first I/O, seen on newer kernels).
fn map_not_running(e: io::Error) -> io::Error {
    match e.kind() {
        io::ErrorKind::NotFound
        | io::ErrorKind::ConnectionRefused
        | io::ErrorKind::ConnectionReset
        | io::ErrorKind::BrokenPipe => io::Error::new(
            e.kind(),
            "irlumed is not running; start it with: sudo systemctl enable --now irlumed",
        ),
        _ => e,
    }
}

fn request_with_timeouts(
    req: &Request,
    connect_timeout: Duration,
    rw_timeout: Duration,
) -> io::Result<Response> {
    let stream = connect_with_timeout(&socket_path(), connect_timeout).map_err(map_not_running)?;
    stream.set_read_timeout(Some(rw_timeout))?;
    stream.set_write_timeout(Some(rw_timeout))?;

    let mut line =
        serde_json::to_vec(req).map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;
    line.push(b'\n');
    // Map send/first-read failures too, not just connect: on newer kernels
    // (7.1.4-zen, found by the self-hosted runner) a stale socket file CONNECTS
    // successfully and only resets on the first write/read, so a connect-only
    // mapping left a raw ECONNRESET. Before any bytes are exchanged, a reset or
    // broken pipe still means "nobody is really listening".
    (&stream).write_all(&line).map_err(map_not_running)?;
    (&stream).flush().map_err(map_not_running)?;
    // The request may carry a password (SealPassword/RecoverySetup); wipe it.
    line.zeroize();

    let mut reader = BufReader::new(&stream);
    let mut buf = String::new();
    reader.read_line(&mut buf).map_err(map_not_running)?;
    if buf.is_empty() {
        return Err(io::Error::new(
            io::ErrorKind::UnexpectedEof,
            "daemon closed connection without responding",
        ));
    }
    let parsed =
        serde_json::from_str(buf.trim()).map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e));
    // The response may carry an unsealed secret; wipe the raw JSON now that the
    // bytes live inside a zeroizing `SecretBytes` in the parsed value.
    buf.zeroize();
    parsed
}

/// `UnixStream::connect` has no timeout, so a stalled listener (backlog full /
/// `accept()` stuck) would hang the caller. Connect on a detached helper thread
/// and give up after `timeout`.
fn connect_with_timeout(path: &Path, timeout: Duration) -> io::Result<UnixStream> {
    let (tx, rx) = std::sync::mpsc::channel();
    let p = path.to_path_buf();
    std::thread::spawn(move || {
        let _ = tx.send(UnixStream::connect(&p));
    });
    match rx.recv_timeout(timeout) {
        Ok(res) => res,
        Err(_) => Err(io::Error::new(
            io::ErrorKind::TimedOut,
            "timed out connecting to irlumed socket",
        )),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testenv;
    use std::io::Read as _;
    use std::os::unix::net::UnixListener;
    use std::path::PathBuf;

    /// A per-test socket path in the temp dir (kept short: sun_path is 108 bytes).
    fn sock(tag: &str) -> PathBuf {
        let p = std::env::temp_dir().join(format!("irlume-cl-{tag}-{}.sock", std::process::id()));
        let _ = std::fs::remove_file(&p);
        p
    }

    #[test]
    fn socket_path_honours_the_env_override() {
        let _g = testenv::lock();
        std::env::remove_var("IRLUME_SOCKET");
        assert_eq!(socket_path(), PathBuf::from(SOCKET_PATH));
        std::env::set_var("IRLUME_SOCKET", "/tmp/x.sock");
        assert_eq!(socket_path(), PathBuf::from("/tmp/x.sock"));
        std::env::remove_var("IRLUME_SOCKET");
    }

    #[test]
    fn request_round_trips_against_a_real_socket_server() {
        let _g = testenv::lock();
        let path = sock("rt");
        let listener = UnixListener::bind(&path).unwrap();
        std::env::set_var("IRLUME_SOCKET", &path);

        let server = std::thread::spawn(move || {
            let (stream, _) = listener.accept().unwrap();
            let mut line = String::new();
            BufReader::new(&stream).read_line(&mut line).unwrap();
            // The wire format is one newline-terminated JSON request.
            assert!(line.ends_with('\n'), "request must be newline-terminated");
            let req: Request = serde_json::from_str(line.trim()).unwrap();
            match req {
                Request::ListProfiles { user } => assert_eq!(user, "alice"),
                other => panic!("server expected ListProfiles, got {other:?}"),
            }
            let reply = Response::Profiles(vec!["Face Profile 1".into()]);
            let mut out = serde_json::to_vec(&reply).unwrap();
            out.push(b'\n');
            (&stream).write_all(&out).unwrap();
        });

        let resp = request(&Request::ListProfiles {
            user: "alice".into(),
        })
        .expect("round trip");
        match resp {
            Response::Profiles(p) => assert_eq!(p, vec!["Face Profile 1".to_string()]),
            other => panic!("expected Profiles, got {other:?}"),
        }
        server.join().unwrap();
        std::env::remove_var("IRLUME_SOCKET");
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn missing_daemon_error_names_the_service_and_the_fix() {
        let _g = testenv::lock();
        // Nothing at the path at all: ENOENT.
        let path = sock("gone");
        std::env::set_var("IRLUME_SOCKET", &path);
        let err = request(&Request::Ping).unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::NotFound);
        assert!(
            err.to_string().contains(
                "irlumed is not running; start it with: sudo systemctl enable --now irlumed"
            ),
            "got: {err}"
        );
        // A stale socket file nobody listens on: ECONNREFUSED on most kernels;
        // on newer kernels (7.1.4-zen observed) connect() succeeds and the
        // first write/read resets (ECONNRESET) or breaks the pipe (EPIPE). All
        // must yield the same actionable guidance, whichever the kernel picks.
        let stale = sock("stale");
        drop(UnixListener::bind(&stale).unwrap()); // bind then close: file remains
        std::env::set_var("IRLUME_SOCKET", &stale);
        let err = request(&Request::Ping).unwrap_err();
        assert!(
            matches!(
                err.kind(),
                io::ErrorKind::ConnectionRefused
                    | io::ErrorKind::ConnectionReset
                    | io::ErrorKind::BrokenPipe
            ),
            "stale socket must read as nobody-listening, got: {:?}",
            err.kind()
        );
        assert!(
            err.to_string().contains("irlumed is not running"),
            "got: {err}"
        );
        std::env::remove_var("IRLUME_SOCKET");
        let _ = std::fs::remove_file(&stale);
    }

    #[test]
    fn server_closing_without_a_reply_is_unexpected_eof() {
        let _g = testenv::lock();
        let path = sock("eof");
        let listener = UnixListener::bind(&path).unwrap();
        std::env::set_var("IRLUME_SOCKET", &path);
        let server = std::thread::spawn(move || {
            let (stream, _) = listener.accept().unwrap();
            let mut line = String::new();
            let _ = BufReader::new(&stream).read_line(&mut line);
            // Drop without answering.
        });
        let err = request(&Request::Ping).unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::UnexpectedEof);
        assert!(
            err.to_string()
                .contains("daemon closed connection without responding"),
            "got: {err}"
        );
        server.join().unwrap();
        std::env::remove_var("IRLUME_SOCKET");
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn garbage_reply_is_invalid_data_not_a_panic() {
        let _g = testenv::lock();
        let path = sock("bad");
        let listener = UnixListener::bind(&path).unwrap();
        std::env::set_var("IRLUME_SOCKET", &path);
        let server = std::thread::spawn(move || {
            let (stream, _) = listener.accept().unwrap();
            let mut line = String::new();
            let _ = BufReader::new(&stream).read_line(&mut line);
            (&stream).write_all(b"i am not json\n").unwrap();
        });
        let err = request_with_timeout(&Request::Ping, Duration::from_secs(5)).unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::InvalidData);
        server.join().unwrap();
        std::env::remove_var("IRLUME_SOCKET");
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn silent_server_times_out_within_the_poll_budget() {
        let _g = testenv::lock();
        let path = sock("silent");
        let listener = UnixListener::bind(&path).unwrap();
        std::env::set_var("IRLUME_SOCKET", &path);
        let server = std::thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            // Read the request, then answer nothing and hold the connection
            // open until the client gives up and drops its end (read -> 0).
            let mut buf = [0u8; 4096];
            while matches!(stream.read(&mut buf), Ok(n) if n > 0) {}
        });
        let t = std::time::Instant::now();
        let err = request_poll(&Request::Ping).unwrap_err();
        let waited = t.elapsed();
        // SO_RCVTIMEO expiry surfaces as WouldBlock (EAGAIN) on Linux.
        assert!(
            matches!(
                err.kind(),
                io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut
            ),
            "expected a timeout kind, got {err:?}"
        );
        // It must have waited (at least) the 1500ms poll read budget, i.e. the
        // failure came from the deadline, not an instant error.
        assert!(
            waited >= Duration::from_millis(1400),
            "gave up too early: {waited:?}"
        );
        std::env::remove_var("IRLUME_SOCKET");
        drop(_g); // release the env lock before the blocking join cleanup
        let _ = std::fs::remove_file(&path);
        server.join().unwrap();
    }

    #[test]
    fn stalled_listener_hits_the_bounded_connect_timeout() {
        let _g = testenv::lock();
        let path = sock("backlog");
        // A listener that never accepts, with the smallest backlog Linux
        // allows, so queued fillers exhaust it and further connects BLOCK
        // (the exact hang connect_with_timeout exists to bound).
        let fd = unsafe { libc::socket(libc::AF_UNIX, libc::SOCK_STREAM, 0) };
        assert!(fd >= 0);
        let mut addr: libc::sockaddr_un = unsafe { std::mem::zeroed() };
        addr.sun_family = libc::AF_UNIX as libc::sa_family_t;
        let bytes = path.as_os_str().as_encoded_bytes();
        assert!(bytes.len() < addr.sun_path.len());
        for (i, b) in bytes.iter().enumerate() {
            addr.sun_path[i] = *b as libc::c_char;
        }
        let len = std::mem::size_of::<libc::sa_family_t>() + bytes.len() + 1;
        // SAFETY: addr is a properly initialized sockaddr_un for `len` bytes.
        let rc = unsafe {
            libc::bind(
                fd,
                &addr as *const _ as *const libc::sockaddr,
                len as libc::socklen_t,
            )
        };
        assert_eq!(rc, 0, "bind: {}", io::Error::last_os_error());
        assert_eq!(unsafe { libc::listen(fd, 0) }, 0);

        // Saturate the accept queue. The fillers that no longer fit block in
        // their own threads (detached; they die with the process).
        for _ in 0..4 {
            let p = path.clone();
            std::thread::spawn(move || {
                let _stream = UnixStream::connect(&p);
                std::thread::sleep(Duration::from_secs(30));
            });
        }
        std::thread::sleep(Duration::from_millis(200)); // let the fillers queue up
        std::env::set_var("IRLUME_SOCKET", &path);
        let err = request_poll(&Request::Ping).unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::TimedOut);
        assert!(
            err.to_string().contains("timed out connecting"),
            "got: {err}"
        );
        std::env::remove_var("IRLUME_SOCKET");
        unsafe { libc::close(fd) };
        let _ = std::fs::remove_file(&path);
    }
}

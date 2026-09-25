// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright the irlume contributors.

//! Unlock a user's GNOME login keyring with their sealed keyring token (#250).
//!
//! On a token-armed account the login keyring is keyed to a random token, not
//! the login password, so after a face or fingerprint login (and after a typed
//! password login, whose password no longer opens it) something must hand the
//! token to `gnome-keyring-daemon`. That channel is the daemon's control
//! socket, `$XDG_RUNTIME_DIR/keyring/control`, with the `UNLOCK` operation:
//! the exact channel and operation `pam_gnome_keyring` itself uses.
//!
//! This exists as a separate program for the same reason `irlume-kwallet-init`
//! does: `pam_irlume` is loaded into sshd, login and every greeter, and it has
//! no privilege dropping. The control socket authenticates the peer's uid
//! (`gkr-pam-client.c` does its own seteuid dance for the same reason), so the
//! connection must be made AS the target user, and becoming the user
//! permanently in a short-lived helper keeps the module's blast radius
//! unchanged.
//!
//! Invoked as `irlume-gkr-unlock <username>` with the token on **stdin**,
//! never in argv, which is world-readable through `/proc`. Exit status 0 means
//! the daemon reported the keyring unlocked; anything else is a refusal or an
//! error, printed to stderr.

use irlume_common::gkr_wire::{self, ControlResult, Op};
use std::ffi::CString;
use std::io::Read;
use std::os::fd::AsFd as _;
use std::os::unix::ffi::{OsStrExt, OsStringExt};
use std::os::unix::net::UnixStream;
use std::path::PathBuf;
use zeroize::Zeroizing;

/// Ceiling on the token read from stdin. The armed token is 64 bytes of hex;
/// the margin tolerates a future longer format without accepting arbitrary
/// stream lengths from a confused caller.
const MAX_TOKEN_LEN: usize = 256;

/// Deadline for each control-socket read and write. The daemon imposes none,
/// and this runs inside the PAM session phase, so an unbounded wait is a hung
/// login. Generous enough for a socket-activated daemon's cold start.
const IO_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(10);

fn main() -> std::process::ExitCode {
    let mut args = std::env::args_os().skip(1);
    let Some(user) = args.next() else {
        eprintln!("usage: irlume-gkr-unlock <username>  (token on stdin)");
        return std::process::ExitCode::from(2);
    };
    let user = user.to_string_lossy().into_owned();

    match run(&user) {
        Ok(()) => std::process::ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("irlume-gkr-unlock: {e}");
            std::process::ExitCode::FAILURE
        }
    }
}

fn run(user: &str) -> Result<(), String> {
    // Read the token first, before any privilege change, so a malformed
    // invocation fails without side effects.
    let token = read_token_from_stdin()?;

    let pw = lookup_user(user)?;
    // Refuse when there is no login keyring to unlock.
    //
    // UNLOCK is not read-only: `unlock_or_create_login()` CREATES the login
    // keyring keyed to whatever secret it was handed when none exists
    // (gnome-keyring's `daemon/login/gkd-login.c`). Firing blind after the
    // user deleted their keyring would silently mint a new one whose password
    // is a 64-character random token they have never seen and no GNOME
    // interface can tell them. Unlocking an existing keyring is this program's
    // whole job; creating one is not.
    let keyring = login_keyring_path(&pw)?;
    if !keyring.exists() {
        return Err(format!(
            "{} does not exist; refusing to UNLOCK, which would CREATE a login keyring \
             keyed to the sealed token instead of unlocking one. Run `irlume keyring \
             forget` to disarm, or create the keyring first.",
            keyring.display()
        ));
    }
    let runtime_dir = runtime_dir_for(&pw)?;

    // EVERYTHING below runs as the target user: the daemon compares the
    // connecting peer's uid against its own, and root pathname work inside a
    // user-owned directory is the CVE-2018-10380 shape this codebase refuses
    // to repeat.
    drop_privileges(&pw)?;

    let sock = gkr_wire::control_socket_path(&runtime_dir);
    let mut stream = connect_with_deadline(&sock)?;
    // The daemon applies NO timeout of its own to a control connection
    // (`gkd-control-server.c` drives the fd from the main loop with no timer),
    // and the socket may be a systemd listener whose daemon is still starting.
    // Without deadlines here, a wedged or slow-starting daemon would hang the
    // PAM session phase, i.e. the login.
    stream
        .set_read_timeout(Some(IO_TIMEOUT))
        .and_then(|()| stream.set_write_timeout(Some(IO_TIMEOUT)))
        .map_err(|e| format!("setting control socket timeouts: {e}"))?;
    match gkr_wire::call(&mut stream, Op::Unlock, &[token.as_slice()])? {
        ControlResult::Ok => Ok(()),
        // A DENIED here is not merely a failed unlock. The daemon remembers
        // the rejected secret (`gkm_wrap_layer_mark_login_unlock_failure`) and
        // re-keys the login keyring TO IT the next time the user unlocks that
        // keyring through a successful prompt. If the token we sent is the one
        // in the envelope, that self-heal is benign (it converges on the token
        // irlume holds); if it is stale, the keyring ends up keyed to a secret
        // nobody has. Say so loudly rather than exiting quietly, because the
        // journal line is the only place this becomes visible.
        ControlResult::Denied => Err(format!(
            "keyring UNLOCK denied: the login keyring is not keyed to the sealed token. \
             gnome-keyring has cached this rejected secret and may re-key the keyring to \
             it after the next manual unlock; re-run `irlume keyring arm` (or `irlume \
             keyring forget`) as {user} to put the keyring and the envelope back in step."
        )),
        other => Err(format!("keyring UNLOCK: {}", other.describe())),
    }
}

/// Read and check the token on stdin.
///
/// `Stdin` would keep a second copy in its process-wide buffer, which nothing
/// wipes. An unbuffered `File` on a clone of the descriptor reads straight
/// into the buffer [`read_token`] wipes, and closes the clone when done.
fn read_token_from_stdin() -> Result<Zeroizing<Vec<u8>>, String> {
    let input = std::io::stdin()
        .as_fd()
        .try_clone_to_owned()
        .map_err(|e| format!("reading the token from stdin: {e}"))?;
    read_token(std::fs::File::from(input))
}

/// Read one token of at most [`MAX_TOKEN_LEN`] printable bytes from `input`,
/// into a buffer that is wiped when it is dropped, on every return path.
fn read_token(mut input: impl Read) -> Result<Zeroizing<Vec<u8>>, String> {
    // One allocation with room for a byte past the limit, which is how an
    // oversized token shows. It never grows, so no reallocation frees a
    // partial copy before the wipe.
    let mut token = Zeroizing::new(vec![0u8; MAX_TOKEN_LEN + 1]);
    // Best effort, as in irlume-kwallet-init: keep the pages out of swap and
    // core dumps before any token byte lands in them.
    irlume_common::memlock::lock_slice(&token);
    let mut len = 0;
    while len < token.len() {
        match input.read(&mut token[len..]) {
            Ok(0) => break,
            Ok(n) => len += n,
            Err(e) if e.kind() == std::io::ErrorKind::Interrupted => {}
            Err(e) => return Err(format!("reading the token from stdin: {e}")),
        }
    }
    // Shrinks the length, not the allocation, so the wipe still covers every
    // byte read.
    token.truncate(len);
    if token.is_empty() {
        return Err("empty token on stdin".into());
    }
    if token.len() > MAX_TOKEN_LEN {
        return Err(format!("token longer than {MAX_TOKEN_LEN} bytes; refusing"));
    }
    // The keyring credential is a string; a token with a NUL or control bytes
    // is not one this program ever produced, so refuse it rather than let a
    // truncated comparison "succeed" somewhere downstream.
    if token.iter().any(|b| !b.is_ascii_graphic()) {
        return Err("token contains non-printable bytes; refusing".into());
    }
    Ok(token)
}

/// Connect to the control socket without ever blocking past [`IO_TIMEOUT`].
///
/// `UnixStream::connect` creates a BLOCKING socket and completes the connection
/// before any timeout can be installed, so setting read and write deadlines
/// afterwards leaves the connect itself unbounded. That matters here: a full
/// listen backlog, or a socket-activated unit whose service is wedged, blocks
/// the PAM session phase, which blocks the login.
fn connect_with_deadline(sock: &std::path::Path) -> Result<UnixStream, String> {
    use std::os::unix::io::{AsRawFd, FromRawFd};

    #[expect(clippy::undocumented_unsafe_blocks, reason = "doc backlog")]
    let mut addr: libc::sockaddr_un = unsafe { std::mem::zeroed() };
    let bytes = sock.as_os_str().as_bytes();
    if bytes.len() >= std::mem::size_of_val(&addr.sun_path) {
        return Err(format!("socket path too long: {}", sock.display()));
    }
    addr.sun_family = libc::AF_UNIX as libc::sa_family_t;
    for (slot, b) in addr.sun_path.iter_mut().zip(bytes) {
        *slot = *b as libc::c_char;
    }

    // SAFETY: a fresh socket, wrapped in an owning UnixStream before any
    // fallible step so it cannot leak.
    let fd = unsafe {
        libc::socket(
            libc::AF_UNIX,
            libc::SOCK_STREAM | libc::SOCK_CLOEXEC | libc::SOCK_NONBLOCK,
            0,
        )
    };
    if fd < 0 {
        return Err(format!("socket: {}", std::io::Error::last_os_error()));
    }
    #[expect(clippy::undocumented_unsafe_blocks, reason = "doc backlog")]
    let stream = unsafe { UnixStream::from_raw_fd(fd) };

    // SAFETY: addr is fully initialised above; the length is its real size.
    let rc = unsafe {
        libc::connect(
            fd,
            &addr as *const _ as *const libc::sockaddr,
            std::mem::size_of::<libc::sockaddr_un>() as libc::socklen_t,
        )
    };
    if rc != 0 {
        let e = std::io::Error::last_os_error();
        if e.raw_os_error() != Some(libc::EINPROGRESS) {
            return Err(format!(
                "connect {}: {e} (no gnome-keyring-daemon control socket; is \
                 gnome-keyring installed and socket-activated?)",
                sock.display()
            ));
        }
        // In progress: wait for writability, bounded.
        let mut pfd = libc::pollfd {
            fd,
            events: libc::POLLOUT,
            revents: 0,
        };
        // SAFETY: one descriptor this scope owns.
        let n = unsafe { libc::poll(&mut pfd, 1, IO_TIMEOUT.as_millis() as libc::c_int) };
        if n == 0 {
            return Err(format!(
                "connect {} timed out after {:?}",
                sock.display(),
                IO_TIMEOUT
            ));
        }
        if n < 0 {
            return Err(format!("poll: {}", std::io::Error::last_os_error()));
        }
        // Poll reports readiness, not success; the error is in SO_ERROR.
        let mut err: libc::c_int = 0;
        let mut len = std::mem::size_of::<libc::c_int>() as libc::socklen_t;
        // SAFETY: reading a fixed-size option into a matching local.
        let rc = unsafe {
            libc::getsockopt(
                fd,
                libc::SOL_SOCKET,
                libc::SO_ERROR,
                &mut err as *mut _ as *mut libc::c_void,
                &mut len,
            )
        };
        // Read errno immediately: anything below could clobber it.
        let probe_errno = std::io::Error::last_os_error()
            .raw_os_error()
            .unwrap_or(libc::EIO);
        if let Some(why) = pending_connect_failure(rc, err, probe_errno) {
            return Err(format!("connect {}: {why}", sock.display()));
        }
    }

    // Back to blocking, now that the read and write deadlines below apply.
    stream
        .set_nonblocking(false)
        .map_err(|e| format!("clearing non-blocking: {e}"))?;
    let _ = stream.as_raw_fd();
    Ok(stream)
}

/// Why a non-blocking connect that `poll` reported ready did not actually
/// connect, or `None` when it did.
///
/// `rc` is `getsockopt(SO_ERROR)`'s own return value, `so_error` the value it
/// wrote, `probe_errno` the errno at the moment it failed. Discarding `rc` is
/// the bug this exists to prevent: a failed `getsockopt` never touches the
/// out-parameter, so `so_error` keeps its initial 0 and every failed connect
/// reads as a success, handing the caller an unconnected socket it then tries
/// to unlock a keyring over. Fail closed, and keep the two causes apart: one
/// says the connect failed, the other says we could not find out.
fn pending_connect_failure(
    rc: libc::c_int,
    so_error: libc::c_int,
    probe_errno: libc::c_int,
) -> Option<String> {
    if rc != 0 {
        return Some(format!(
            "could not read SO_ERROR ({}), so whether the connect succeeded is unknown",
            std::io::Error::from_raw_os_error(probe_errno)
        ));
    }
    (so_error != 0).then(|| std::io::Error::from_raw_os_error(so_error).to_string())
}

/// The login keyring file, under the home NSS reports.
///
/// `$HOME` is deliberately not consulted: this may run as root with the login
/// stack's environment, where `$HOME` is root's or unset.
/// `IRLUME_GKR_HOME` overrides it under the same not-privileged rule as
/// [`runtime_dir_for`], so the harness can point at a throwaway home.
fn login_keyring_path(pw: &User) -> Result<PathBuf, String> {
    let home = match std::env::var_os("IRLUME_GKR_HOME") {
        Some(over) if !privileged() => PathBuf::from(over),
        Some(_) => {
            return Err(
                "IRLUME_GKR_HOME is set but this process is privileged; refusing to take \
                 the home directory from the environment"
                    .into(),
            )
        }
        None => PathBuf::from(&pw.home),
    };
    Ok(home.join(".local/share/keyrings/login.keyring"))
}

/// Whether this process holds privilege that the environment must not steer.
fn privileged() -> bool {
    #[expect(clippy::undocumented_unsafe_blocks, reason = "doc backlog")]
    let (euid, uid) = unsafe { (libc::geteuid(), libc::getuid()) };
    euid == 0 || uid == 0
}

/// Where the target user's control socket lives.
///
/// Derived from the uid, NOT from `XDG_RUNTIME_DIR`. When this runs from the
/// PAM stack it runs as root, and the environment is the caller's: honouring
/// an inherited path there would let whoever controls that environment name
/// the socket this program writes the token to, which is a direct secret leak.
///
/// `IRLUME_GKR_RUNTIME_DIR` overrides it for the test harness, and ONLY when
/// this process is not privileged. An unprivileged process can already reach
/// everything its own uid can, so the override grants nothing; refusing it
/// under root keeps the production path environment-independent.
///
/// This is a deliberate divergence from `gkr-pam`, which prefers
/// `$GNOME_KEYRING_CONTROL` and only then falls back to `$XDG_RUNTIME_DIR`
/// (`get_control_file()` in `gkr-pam-module.c`). That module already runs
/// inside the user's own environment; this one runs as root with whatever
/// environment the login stack happened to carry, and honouring a variable
/// from there would let it name the socket a secret is written to. The
/// fallback path is what gnome-keyring's own systemd units bind
/// (`ListenStream=%t/keyring/control`), so the divergence only shows up on a
/// setup that relocates the socket by hand.
fn runtime_dir_for(pw: &User) -> Result<PathBuf, String> {
    let dir = match std::env::var_os("IRLUME_GKR_RUNTIME_DIR") {
        Some(over) if !privileged() => PathBuf::from(over),
        Some(_) => {
            return Err(
                "IRLUME_GKR_RUNTIME_DIR is set but this process is privileged; refusing to \
                 take the socket path from the environment"
                    .into(),
            )
        }
        None => PathBuf::from(format!("/run/user/{}", pw.uid)),
    };
    if !dir.is_dir() {
        return Err(format!(
            "{} does not exist; the session is not far enough along for a keyring",
            dir.display()
        ));
    }
    Ok(dir)
}

/// Become the target user, permanently. Same order and same paranoia as
/// `irlume-kwallet-init`: groups and gid before uid, then verify the drop
/// took, because a drop that silently failed would leave the control-socket
/// connection coming from root and everything below running with privilege it
/// must not have.
fn drop_privileges(pw: &User) -> Result<(), String> {
    // Already the target user (the test harness, and any future caller that
    // runs in-session): there is nothing to drop, and `initgroups` would fail
    // with EPERM for an unprivileged process. Verified below either way, so
    // this cannot skip a drop that was actually needed.
    // SAFETY: getuid, geteuid, getgid and getegid take no arguments, read
    // only the calling process's own credentials, and are specified as
    // always succeeding, so none has a precondition for the caller to uphold.
    let already = unsafe { libc::getuid() } == pw.uid
        && unsafe { libc::geteuid() } == pw.uid
        && unsafe { libc::getgid() } == pw.gid
        && unsafe { libc::getegid() } == pw.gid;
    if already {
        return Ok(());
    }
    #[expect(clippy::undocumented_unsafe_blocks, reason = "doc backlog")]
    if unsafe { libc::initgroups(pw.name.as_ptr(), pw.gid) } != 0 {
        return Err(format!("initgroups: {}", std::io::Error::last_os_error()));
    }
    #[expect(clippy::undocumented_unsafe_blocks, reason = "doc backlog")]
    if unsafe { libc::setgid(pw.gid) } != 0 {
        return Err(format!("setgid: {}", std::io::Error::last_os_error()));
    }
    #[expect(clippy::undocumented_unsafe_blocks, reason = "doc backlog")]
    if unsafe { libc::setuid(pw.uid) } != 0 {
        return Err(format!("setuid: {}", std::io::Error::last_os_error()));
    }
    // SAFETY: getuid, geteuid, getgid and getegid take no arguments, read
    // only the calling process's own credentials, and are specified as
    // always succeeding, so none has a precondition for the caller to uphold.
    if unsafe { libc::getuid() } != pw.uid
        // SAFETY: takes no arguments, reads only this process's own
        // credentials, and is specified as always succeeding.
        || unsafe { libc::geteuid() } != pw.uid
        // SAFETY: takes no arguments, reads only this process's own
        // credentials, and is specified as always succeeding.
        || unsafe { libc::getgid() } != pw.gid
        // SAFETY: takes no arguments, reads only this process's own
        // credentials, and is specified as always succeeding.
        || unsafe { libc::getegid() } != pw.gid
    {
        return Err("privilege drop did not take effect".into());
    }
    Ok(())
}

struct User {
    uid: libc::uid_t,
    gid: libc::gid_t,
    name: CString,
    /// Home directory, read from NSS rather than `$HOME`: this may run as root
    /// with the login stack's environment, where `$HOME` is not yet the user's.
    home: std::ffi::OsString,
}

fn lookup_user(user: &str) -> Result<User, String> {
    let cname = CString::new(user).map_err(|_| "username contains a NUL".to_string())?;
    // SAFETY: getpwnam returns a pointer into a static buffer, read before any
    // further libc call that could overwrite it.
    let pw = unsafe { libc::getpwnam(cname.as_ptr()) };
    if pw.is_null() {
        return Err(format!("no such user: {user}"));
    }
    #[expect(clippy::undocumented_unsafe_blocks, reason = "doc backlog")]
    let (uid, gid) = unsafe { ((*pw).pw_uid, (*pw).pw_gid) };
    if uid == 0 {
        return Err("refusing to unlock a keyring for uid 0".to_string());
    }
    // SAFETY: same static buffer as above, still valid; copied out immediately.
    let home = unsafe {
        let d = (*pw).pw_dir;
        if d.is_null() {
            return Err(format!("no home directory for {user}"));
        }
        std::ffi::OsString::from_vec(std::ffi::CStr::from_ptr(d).to_bytes().to_vec())
    };
    Ok(User {
        uid,
        gid,
        name: cname,
        home,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_failed_so_error_probe_is_a_failed_connect_not_a_successful_one() {
        // The defect this pins: `getsockopt` writing nothing on failure leaves
        // the out-parameter at its initial 0, so a caller that reads only the
        // out-parameter treats "the probe failed" as "the connect succeeded"
        // and goes on to hand a keyring token to an unconnected socket.
        let why = pending_connect_failure(-1, 0, libc::EBADF)
            .expect("a failed SO_ERROR probe must not read as a connected socket");
        assert!(
            why.contains("could not read SO_ERROR"),
            "the two causes must stay apart in the message: {why}"
        );
    }

    #[test]
    fn a_probe_that_reports_a_connect_error_names_that_error() {
        let why = pending_connect_failure(0, libc::ECONNREFUSED, 0)
            .expect("ECONNREFUSED in SO_ERROR is a failed connect");
        assert_eq!(
            why,
            std::io::Error::from_raw_os_error(libc::ECONNREFUSED).to_string()
        );
        assert!(
            !why.contains("could not read SO_ERROR"),
            "a refused connect must not be reported as an unreadable probe: {why}"
        );
    }

    #[test]
    fn a_clean_probe_reporting_no_error_is_a_connected_socket() {
        assert!(pending_connect_failure(0, 0, 0).is_none());
    }

    /// A printable token with [`MARKER`] past offset 0, so a buffer that
    /// clears only its first byte on drop still counts as unwiped.
    const TOKEN: &[u8] = b"tok-irlume-wipe-check-5c1e";
    const MARKER: &[u8] = b"irlume-wipe-check-5c1e";
    /// Stdin bytes for the refused case: more than the limit plus the one
    /// byte read past it, so some must stay in the pipe.
    const OVERSIZED_LEN: usize = 300;
    /// No account has this name, so `run` stops at the user lookup, after it
    /// has read and checked the token and before any privilege change.
    const NO_SUCH_USER: &str = "irlume-test-no-such-user-5c1e";

    #[test]
    fn the_freed_block_check_sees_an_unwiped_copy() {
        let unwiped = freed_blocks::count_unwiped(MARKER, || {
            drop(std::hint::black_box(TOKEN.to_vec()));
        });
        assert_eq!(unwiped, 1, "the freed-block check is not installed");
    }

    /// The UNLOCK packet `gkr_wire::call` builds around the token is wiped
    /// before its memory is freed.
    #[test]
    fn the_unlock_packet_is_wiped_after_it_is_sent() {
        struct Daemon {
            sent: usize,
            reply: &'static [u8],
        }
        impl std::io::Write for Daemon {
            fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
                self.sent += buf.len();
                Ok(buf.len())
            }
            fn flush(&mut self) -> std::io::Result<()> {
                Ok(())
            }
        }
        impl std::io::Read for Daemon {
            fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
                self.reply.read(buf)
            }
        }
        // Declared length 8, result 0 (OK).
        const OK_REPLY: &[u8] = &[0, 0, 0, 8, 0, 0, 0, 0];

        let mut daemon = Daemon {
            sent: 0,
            reply: OK_REPLY,
        };
        let unwiped = freed_blocks::count_unwiped(MARKER, || {
            let result = gkr_wire::call(&mut daemon, Op::Unlock, &[TOKEN]);
            assert_eq!(result, Ok(ControlResult::Ok));
        });
        assert_eq!(unwiped, 0, "the UNLOCK packet was freed without a wipe");
        // The credentials byte, the 8-byte header and one length-prefixed
        // argument.
        assert_eq!(daemon.sent, 1 + 8 + 4 + TOKEN.len());
    }

    /// The token goes from the stdin pipe straight into a buffer that is
    /// wiped before it is freed, on the accepted path and on a refused one.
    /// Each case runs in a fresh process whose stdin is a pipe this test
    /// fills and closes.
    #[test]
    fn the_stdin_token_is_read_unbuffered_and_wiped() {
        use std::io::Write as _;
        let oversized: Vec<u8> = MARKER.iter().copied().cycle().take(OVERSIZED_LEN).collect();
        for (child, input) in [
            ("tests::token_stdin_child", TOKEN),
            ("tests::oversized_token_stdin_child", &oversized[..]),
        ] {
            let mut proc = std::process::Command::new(std::env::current_exe().unwrap())
                .args(["--ignored", "--exact", child])
                .stdin(std::process::Stdio::piped())
                .stdout(std::process::Stdio::piped())
                .spawn()
                .unwrap();
            let mut pipe = proc.stdin.take().unwrap();
            pipe.write_all(input).unwrap();
            drop(pipe);
            let out = proc.wait_with_output().unwrap();
            let stdout = String::from_utf8_lossy(&out.stdout);
            assert!(out.status.success(), "{child} failed:\n{stdout}");
            // An `--exact` name that matches nothing also exits 0.
            assert!(
                stdout.contains("test result: ok. 1 passed"),
                "{child} did not run:\n{stdout}"
            );
        }
    }

    #[test]
    fn read_token_keeps_the_checks_and_returns_a_wiping_buffer() {
        let token: Zeroizing<Vec<u8>> = read_token(TOKEN).expect("a printable token");
        assert_eq!(token.as_slice(), TOKEN);

        let limit = vec![b'a'; MAX_TOKEN_LEN];
        assert_eq!(
            read_token(&limit[..]).expect("at the limit").len(),
            MAX_TOKEN_LEN
        );

        let over = vec![b'a'; MAX_TOKEN_LEN + 1];
        let why = read_token(&over[..]).expect_err("one byte over the limit");
        assert!(why.contains("longer than 256 bytes"), "{why}");

        let why = read_token(&b""[..]).expect_err("no token");
        assert!(why.contains("empty token"), "{why}");

        for bad in [&b"tok\0en"[..], b"tok en", b"token\n"] {
            let why = read_token(bad).expect_err("non-printable byte");
            assert!(why.contains("non-printable"), "{why}");
        }
    }

    #[test]
    fn read_token_retries_an_interrupted_read_and_reports_a_failed_one() {
        /// Fails each read once with `kind`, then serves from `rest`.
        struct Flaky {
            kind: Option<std::io::ErrorKind>,
            rest: &'static [u8],
        }
        impl std::io::Read for Flaky {
            fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
                match self.kind.take() {
                    Some(kind) => Err(kind.into()),
                    None => self.rest.read(buf),
                }
            }
        }

        let token = read_token(Flaky {
            kind: Some(std::io::ErrorKind::Interrupted),
            rest: TOKEN,
        })
        .expect("an interrupted read is retried");
        assert_eq!(token.as_slice(), TOKEN);

        let why = read_token(Flaky {
            kind: Some(std::io::ErrorKind::BrokenPipe),
            rest: TOKEN,
        })
        .expect_err("a failed read is an error");
        assert!(why.starts_with("reading the token from stdin"), "{why}");
    }

    /// A pipe may hand the token over in pieces. One byte per read still
    /// gives the whole token in order, and the refusal comes after exactly
    /// one byte past the limit.
    #[test]
    fn read_token_joins_one_byte_reads() {
        /// Serves `rest` one byte per call.
        struct Trickle<'a> {
            rest: &'a [u8],
        }
        impl std::io::Read for Trickle<'_> {
            fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
                let n = self.rest.len().min(buf.len()).min(1);
                buf[..n].copy_from_slice(&self.rest[..n]);
                self.rest = &self.rest[n..];
                Ok(n)
            }
        }

        let mut input = Trickle { rest: TOKEN };
        let token = read_token(&mut input).expect("a printable token");
        assert_eq!(token.as_slice(), TOKEN);

        // Every printable byte in turn, so a byte out of place shows.
        let limit: Vec<u8> = (b'!'..=b'~').cycle().take(MAX_TOKEN_LEN).collect();
        let mut input = Trickle { rest: &limit };
        let token = read_token(&mut input).expect("at the limit");
        assert_eq!(token.as_slice(), &limit[..]);

        let over = vec![b'a'; OVERSIZED_LEN];
        let mut input = Trickle { rest: &over };
        let why = read_token(&mut input).expect_err("over the limit");
        assert!(why.contains("longer than 256 bytes"), "{why}");
        assert_eq!(input.rest.len(), OVERSIZED_LEN - (MAX_TOKEN_LEN + 1));
    }

    #[test]
    #[ignore = "fresh-exec child invoked by the_stdin_token_is_read_unbuffered_and_wiped"]
    fn token_stdin_child() {
        let unwiped = freed_blocks::count_unwiped(MARKER, || {
            let why = run(NO_SUCH_USER).expect_err("no account has this name");
            assert!(why.contains("no such user"), "{why}");
        });
        assert_eq!(unwiped, 0, "the token was freed without a wipe");
        assert_eq!(stdin_bytes_left(), 0);
    }

    #[test]
    #[ignore = "fresh-exec child invoked by the_stdin_token_is_read_unbuffered_and_wiped"]
    fn oversized_token_stdin_child() {
        let unwiped = freed_blocks::count_unwiped(MARKER, || {
            let why = run(NO_SUCH_USER).expect_err("an oversized token is refused");
            assert!(why.contains("longer than 256 bytes"), "{why}");
        });
        assert_eq!(unwiped, 0, "the refused token was freed without a wipe");
        // Only the limit and the one byte past it leave the pipe. A buffered
        // reader would have drained the rest into memory nothing wipes.
        assert_eq!(stdin_bytes_left(), OVERSIZED_LEN - (MAX_TOKEN_LEN + 1));
    }

    /// Bytes still unread in the stdin pipe.
    fn stdin_bytes_left() -> usize {
        let mut left: libc::c_int = 0;
        // SAFETY: FIONREAD writes one int through this valid pointer; it
        // reads no bytes from the pipe and does not take the descriptor.
        let rc = unsafe { libc::ioctl(libc::STDIN_FILENO, libc::FIONREAD, &mut left) };
        assert_eq!(rc, 0, "FIONREAD: {}", std::io::Error::last_os_error());
        usize::try_from(left).expect("FIONREAD is never negative")
    }

    /// The allocator of this test binary, which can find a secret in freed
    /// memory.
    ///
    /// It zero-fills every block it hands out. While [`count_unwiped`] runs
    /// on a thread, each block that thread frees is read as bytes and
    /// searched for a marker first; other threads and other times forward to
    /// `System` unchanged. Use `count_unwiped` only around code that frees
    /// byte buffers (`Vec<u8>`, `String`, `CString`): a typed write can leave
    /// padding bytes uninitialized, and those must not be read as `u8`.
    ///
    /// A copy of the module of the same name in `crates/irlume-pam/src/lib.rs`.
    mod freed_blocks {
        use std::alloc::{GlobalAlloc, Layout, System};
        use std::cell::Cell;

        struct CheckFreed;

        #[global_allocator]
        static CHECK_FREED: CheckFreed = CheckFreed;

        thread_local! {
            static MARKER: Cell<Option<&'static [u8]>> = const { Cell::new(None) };
            static UNWIPED: Cell<usize> = const { Cell::new(0) };
        }

        /// Run `f` and count the blocks it frees that still hold `marker`.
        /// `f` must free only byte buffers (see the module doc).
        pub(super) fn count_unwiped(marker: &'static [u8], f: impl FnOnce()) -> usize {
            struct Disarm;
            impl Drop for Disarm {
                fn drop(&mut self) {
                    let _ = MARKER.try_with(|m| m.set(None));
                }
            }
            assert!(!marker.is_empty());
            UNWIPED.with(|n| n.set(0));
            MARKER.with(|m| m.set(Some(marker)));
            let disarm = Disarm;
            f();
            drop(disarm);
            UNWIPED.with(Cell::get)
        }

        // SAFETY: `alloc` returns `System.alloc_zeroed` for the same layout,
        // and `dealloc` returns the caller's pointer and layout to `System`
        // after reading the block, so `System`'s guarantees carry over. The
        // default `realloc` and `alloc_zeroed` go through these two.
        unsafe impl GlobalAlloc for CheckFreed {
            unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
                // SAFETY: `alloc_zeroed` has the contract the caller keeps
                // for `alloc`: a layout of non-zero size.
                unsafe { System.alloc_zeroed(layout) }
            }

            unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
                if let Some(marker) = MARKER.try_with(Cell::get).ok().flatten() {
                    // SAFETY: `ptr` is a live block of `layout.size()` bytes
                    // from `alloc` above, read before it is freed. Every byte
                    // is initialized: `alloc` zero-filled the block, and while
                    // a marker is set the only blocks freed are byte buffers
                    // (see the module doc), whose writes are bytes with no
                    // padding.
                    let block = unsafe { std::slice::from_raw_parts(ptr, layout.size()) };
                    if block.windows(marker.len()).any(|w| w == marker) {
                        let _ = UNWIPED.try_with(|n| n.set(n.get() + 1));
                    }
                }
                // SAFETY: the caller passes a block from `alloc` above, which
                // came from `System`, with the layout it was allocated with.
                unsafe { System.dealloc(ptr, layout) }
            }
        }
    }
}

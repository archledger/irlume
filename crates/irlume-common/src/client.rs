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
use std::io::{self, Read, Write};
use std::os::unix::net::UnixStream;
use std::path::{Path, PathBuf};
use std::time::Duration;
use zeroize::Zeroizing;

mod position_session;
pub use position_session::PositionSession;

/// Bounded wait for the initial connect (distinct from the read timeout, which
/// must be long enough for a camera capture).
const CONNECT_TIMEOUT: Duration = Duration::from_secs(5);
/// Short budgets for the TUI status poll, so a wedged daemon doesn't freeze the
/// UI: fail fast and let the next tick retry.
const POLL_CONNECT_TIMEOUT: Duration = Duration::from_millis(1200);
const POLL_RW_TIMEOUT: Duration = Duration::from_millis(1500);
/// Largest response this client will accept. The daemon's own replies are far
/// smaller; the cap exists so a peer that is not the daemon cannot make a
/// client read forever. Matches the daemon's request cap.
const MAX_RESPONSE_BYTES: u64 = 64 * 1024;

/// Default read/write timeout for management requests.
const DEFAULT_RW_TIMEOUT: Duration = Duration::from_secs(30);
/// Operator-selected ceiling that also covers a stalled NSS lookup or
/// filesystem without hanging a login session.
const WALLET_SALT_HELPER_TIMEOUT: Duration = Duration::from_secs(15);

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
pub fn secure_env(name: &str) -> Option<std::ffi::OsString> {
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
    #[expect(clippy::undocumented_unsafe_blocks, reason = "doc backlog")]
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

/// Read the KDE wallet salt through the account-scoped helper.
///
/// `Ok(None)` has one narrow meaning: the helper proved the salt path absent.
/// Permission, type, credential, timeout, malformed-output and execution
/// failures remain errors, so automatic kind selection cannot silently fall
/// back to a login password after a denied KDE lookup.
///
/// # Errors
/// Returns a generic error without the target path or helper output.
pub fn read_wallet_salt(user: &str) -> io::Result<Option<crate::WalletSalt>> {
    read_wallet_salt_with_timeout(user, WALLET_SALT_HELPER_TIMEOUT)
}

fn read_wallet_salt_with_timeout(
    user: &str,
    timeout: Duration,
) -> io::Result<Option<crate::WalletSalt>> {
    read_wallet_salt_with_timeout_and_clock(user, timeout, |_| {}, std::time::Instant::now)
}

fn read_wallet_salt_with_timeout_and_clock(
    user: &str,
    timeout: Duration,
    mut after_poll: impl FnMut(bool),
    mut now: impl FnMut() -> std::time::Instant,
) -> io::Result<Option<crate::WalletSalt>> {
    use std::os::fd::AsRawFd as _;
    use std::process::{Command, Stdio};

    let helper = secure_env("IRLUME_KWALLET_INIT")
        .filter(|path| !path.is_empty())
        .unwrap_or_else(|| std::ffi::OsString::from(crate::KWALLET_INIT_PATH));
    let mut child = Command::new(helper)
        .args(["--read-salt", user])
        .env_clear()
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .map_err(|_| wallet_salt_error(io::ErrorKind::Other))?;
    let Some(mut stdout) = child.stdout.take() else {
        kill_wallet_salt_helper(&mut child);
        return Err(wallet_salt_error(io::ErrorKind::Other));
    };
    let fd = stdout.as_raw_fd();
    // SAFETY: both fcntl calls operate on the live stdout fd owned above and
    // do not retain pointers or references.
    let flags = unsafe { libc::fcntl(fd, libc::F_GETFL) };
    // SAFETY: same owned fd; the only change is adding nonblocking mode.
    if flags < 0 || unsafe { libc::fcntl(fd, libc::F_SETFL, flags | libc::O_NONBLOCK) } < 0 {
        kill_wallet_salt_helper(&mut child);
        return Err(wallet_salt_error(io::ErrorKind::Other));
    }

    let deadline = now() + timeout;
    let mut output = Zeroizing::new(Vec::with_capacity(crate::kwallet_wire::SALT_LEN));
    let mut chunk = Zeroizing::new([0u8; 64]);
    let status = loop {
        if now() >= deadline {
            kill_wallet_salt_helper(&mut child);
            return Err(wallet_salt_error(io::ErrorKind::TimedOut));
        }
        let read = stdout.read(&mut chunk[..]);
        after_poll(matches!(read, Ok(n) if n > 0));
        if now() >= deadline {
            kill_wallet_salt_helper(&mut child);
            return Err(wallet_salt_error(io::ErrorKind::TimedOut));
        }
        match read {
            Ok(0) => {
                let waited = child.try_wait();
                after_poll(false);
                if now() >= deadline {
                    kill_wallet_salt_helper(&mut child);
                    return Err(wallet_salt_error(io::ErrorKind::TimedOut));
                }
                match waited {
                    Ok(Some(status)) => break status,
                    Ok(None) => {
                        std::thread::sleep(Duration::from_millis(10));
                    }
                    Err(_) => {
                        kill_wallet_salt_helper(&mut child);
                        return Err(wallet_salt_error(io::ErrorKind::Other));
                    }
                }
            }
            Ok(n) => {
                if output.len() + n > crate::kwallet_wire::SALT_LEN {
                    kill_wallet_salt_helper(&mut child);
                    return Err(wallet_salt_error(io::ErrorKind::InvalidData));
                }
                output.extend_from_slice(&chunk[..n]);
            }
            Err(error) if error.kind() == io::ErrorKind::Interrupted => {}
            Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                if now() >= deadline {
                    kill_wallet_salt_helper(&mut child);
                    return Err(wallet_salt_error(io::ErrorKind::TimedOut));
                }
                std::thread::sleep(Duration::from_millis(10));
            }
            Err(_) => {
                kill_wallet_salt_helper(&mut child);
                return Err(wallet_salt_error(io::ErrorKind::Other));
            }
        }
    };
    if now() >= deadline {
        kill_wallet_salt_helper(&mut child);
        return Err(wallet_salt_error(io::ErrorKind::TimedOut));
    }
    if status.success() && output.len() == crate::kwallet_wire::SALT_LEN {
        return crate::WalletSalt::new(std::mem::take(&mut *output))
            .map(Some)
            .ok_or_else(|| wallet_salt_error(io::ErrorKind::InvalidData));
    }
    if status.code() == Some(crate::kwallet_wire::SALT_ABSENT_EXIT) && output.is_empty() {
        return Ok(None);
    }
    Err(wallet_salt_error(io::ErrorKind::InvalidData))
}

fn wallet_salt_error(kind: io::ErrorKind) -> io::Error {
    io::Error::new(kind, "account-scoped wallet salt lookup failed")
}

fn kill_wallet_salt_helper(child: &mut std::process::Child) {
    let _ = child.kill();
    let deadline = std::time::Instant::now() + Duration::from_millis(200);
    while std::time::Instant::now() < deadline {
        match child.try_wait() {
            Ok(Some(_)) | Err(_) => return,
            Ok(None) => std::thread::sleep(Duration::from_millis(10)),
        }
    }
    // As in the PAM helper path, an uninterruptible kernel sleep can outlive
    // this bound. The caller must not trade a hung login for an unbounded reap;
    // init reaps the process after the caller exits.
}

/// Send `req` with the default read/write timeout.
#[expect(clippy::missing_errors_doc, reason = "doc backlog")]
pub fn request(req: &Request) -> io::Result<Response> {
    request_with_timeout(req, DEFAULT_RW_TIMEOUT)
}

/// Send a request while allowing a guided operation to cancel its reply wait.
///
/// Dropping the connection informs the daemon to cancel its pending approval
/// or capture. The flag is checked at least once per 100 ms socket-read slice.
///
/// # Errors
/// Returns transport/decoding errors, `ConnectionAborted` on cancellation, or
/// `TimedOut` when the overall reply budget expires.
pub fn request_cancellable(
    req: &Request,
    rw_timeout: Duration,
    cancelled: &std::sync::atomic::AtomicBool,
) -> io::Result<Response> {
    request_with_timeouts_inner(req, CONNECT_TIMEOUT, rw_timeout, Some(cancelled), None)
}

/// A short-budget poll: used by the TUI's periodic status refresh so a busy or
/// wedged daemon (mid-capture, not accepting) fails fast instead of stalling the
/// UI thread for the full connect/read budget on every probe.
#[expect(clippy::missing_errors_doc, reason = "doc backlog")]
pub fn request_poll(req: &Request) -> io::Result<Response> {
    request_with_timeouts(req, POLL_CONNECT_TIMEOUT, POLL_RW_TIMEOUT)
}

/// Send `req`, allowing `rw_timeout` for the reply (e.g. a longer budget for an
/// unseal that does a full camera capture + liveness + match first).
#[expect(clippy::missing_errors_doc, reason = "doc backlog")]
pub fn request_with_timeout(req: &Request, rw_timeout: Duration) -> io::Result<Response> {
    request_with_timeouts(req, CONNECT_TIMEOUT, rw_timeout)
}

/// Send one observation within a deadline shared with other observations.
///
/// The same deadline covers connection, writing and reading; an expired
/// observation never opens a connection. Existing authentication timeout APIs
/// retain their separate connect/reply budgets.
///
/// # Errors
/// Returns transport/decoding errors or `TimedOut` when the deadline expires.
pub fn request_until(req: &Request, deadline: std::time::Instant) -> io::Result<Response> {
    let remaining = observation_remaining(deadline)?;
    request_with_timeouts_inner(
        req,
        remaining.min(POLL_CONNECT_TIMEOUT),
        remaining,
        None,
        Some(deadline),
    )
}

fn observation_remaining(deadline: std::time::Instant) -> io::Result<Duration> {
    let remaining = deadline.saturating_duration_since(std::time::Instant::now());
    if remaining.is_zero() {
        Err(io::Error::new(
            io::ErrorKind::TimedOut,
            "observation deadline expired",
        ))
    } else {
        Ok(remaining)
    }
}

/// Open a bounded-time connection for a protocol that keeps reading after its
/// first response line (currently the privileged diagnostic trace).
///
/// # Errors
///
/// Returns the same mapped connection/permission failures as [`request`], or a
/// socket timeout configuration failure.
pub fn connect_stream(rw_timeout: Duration) -> io::Result<UnixStream> {
    let stream =
        connect_with_timeout(&socket_path(), CONNECT_TIMEOUT).map_err(map_connect_failure)?;
    stream.set_read_timeout(Some(rw_timeout))?;
    stream.set_write_timeout(Some(rw_timeout))?;
    Ok(stream)
}

/// Read progress and answer merge decisions on the one authorized connection.
/// No automatic retry: a lost final reply must never duplicate enrollment.
///
/// # Errors
/// Returns connection, framing, timeout, cancellation or callback errors.
pub fn enrollment_session(
    req: &Request,
    cancelled: &std::sync::atomic::AtomicBool,
    mut event: impl FnMut(crate::EnrollmentEvent) -> io::Result<Option<bool>>,
) -> io::Result<Response> {
    if !matches!(req, Request::EnrollmentSession { .. }) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "expected enrollment session",
        ));
    }
    let stream = connect_stream(Duration::from_millis(100))?;
    (&stream).write_all(&serialize_request(req)?)?;
    let deadline = std::time::Instant::now() + Duration::from_secs(380);
    let reader = CancellableReply {
        stream: &stream,
        cancelled,
        deadline,
    };
    let mut reader = std::io::BufReader::new(reader);
    // The scan cap is 30, with one probe/merge and occasional target updates.
    // A fake endpoint cannot send an unbounded event stream.
    for _ in 0..128 {
        if cancelled.load(std::sync::atomic::Ordering::Relaxed) {
            return Err(io::Error::new(
                io::ErrorKind::ConnectionAborted,
                "enrollment cancelled",
            ));
        }
        if std::time::Instant::now() >= deadline {
            return Err(io::Error::new(
                io::ErrorKind::TimedOut,
                "enrollment timed out",
            ));
        }
        let mut buf = Zeroizing::new(Vec::with_capacity(MAX_RESPONSE_BYTES as usize));
        std::io::BufRead::read_until(&mut (&mut reader).take(MAX_RESPONSE_BYTES), b'\n', &mut buf)?;
        if buf.len() as u64 >= MAX_RESPONSE_BYTES || !buf.ends_with(b"\n") {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "invalid enrollment response size",
            ));
        }
        let response: Response = serde_json::from_slice(buf.trim_ascii())
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;
        match response {
            Response::EnrollmentSession(progress) => {
                let merge = matches!(progress, crate::EnrollmentEvent::Merge { .. });
                let answer = event(progress)?;
                if merge {
                    let accept = answer.ok_or_else(|| {
                        io::Error::new(io::ErrorKind::InvalidInput, "merge needs a decision")
                    })?;
                    let mut line = serde_json::to_vec(&crate::EnrollmentDecision { accept })?;
                    line.push(b'\n');
                    (&stream).write_all(&line)?;
                } else if answer.is_some() {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidInput,
                        "unexpected enrollment decision",
                    ));
                }
            }
            terminal => return Ok(terminal),
        }
    }
    Err(io::Error::new(
        io::ErrorKind::InvalidData,
        "too many enrollment events",
    ))
}

/// Whether this failure PROVES nobody is listening on the socket.
///
/// The distinction matters wherever "the daemon is not there" licenses an act
/// that would be unsafe if it were: classifying camera nodes is the case that
/// motivated this. A timeout does NOT prove absence. A daemon busy mid-capture
/// is exactly what a timed-out short poll looks like, and that is precisely
/// when it holds the video nodes, so treating a timeout as absence would open
/// the devices at the worst possible moment (#187). EACCES says the same thing
/// from the other side: the socket is there and the daemon is very likely fine,
/// this uid just may not connect.
pub fn proves_daemon_absent(e: &io::Error) -> bool {
    matches!(
        e.kind(),
        io::ErrorKind::NotFound
            | io::ErrorKind::ConnectionRefused
            | io::ErrorKind::ConnectionReset
            | io::ErrorKind::BrokenPipe
    )
}

/// Map a connect failure to an actionable message.
///
/// Two cases, and conflating them was a real bug: a user whose uid could not
/// open the socket was told the daemon was down and sent to `systemctl status`
/// on a healthy service.
///
/// "Nobody is listening" is the #1 first-run failure (fresh package install,
/// unit disabled by distro preset policy), so name the daemon and the exact
/// command instead of a raw errno. Covers every errno that case produces across
/// kernels: ENOENT (no socket file), ECONNREFUSED (socket file, no accept),
/// ECONNRESET / EPIPE (stale socket that connects then resets on first I/O,
/// seen on newer kernels).
///
/// EACCES/EPERM means the opposite: the socket is there and the daemon is very
/// likely fine, but this uid may not connect. Say that, and do not suggest
/// `sudo` or a chmod, because both hide whatever set the mode.
fn map_connect_failure(e: io::Error) -> io::Error {
    match e.kind() {
        io::ErrorKind::NotFound
        | io::ErrorKind::ConnectionRefused
        | io::ErrorKind::ConnectionReset
        | io::ErrorKind::BrokenPipe => io::Error::new(
            e.kind(),
            "irlumed is not running; start it with: sudo systemctl enable --now irlumed",
        ),
        io::ErrorKind::PermissionDenied => io::Error::new(
            e.kind(),
            format!(
                "not permitted to connect to irlumed at {} (EACCES); the daemon may be \
                 running fine. Check the socket permissions and, on SELinux systems, the \
                 audit log for a denial.",
                socket_path().display()
            ),
        ),
        _ => e,
    }
}

/// Serialize a request into a buffer that wipes itself on every exit path.
///
/// `SealPassword`, `ResealPassword`, `RecoverySetup` and `RecoveryRestore`
/// carry a `SecretBytes`, and serialization copies those bytes into this buffer
/// as plain JSON. Returning a wiping owner rather than wiping after the send is
/// what covers the error paths: the send is two fallible calls, and an early
/// return from either used to free this buffer with the secret still in it.
fn serialize_request(req: &Request) -> io::Result<Zeroizing<Vec<u8>>> {
    let mut line = Zeroizing::new(
        serde_json::to_vec(req).map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?,
    );
    line.push(b'\n');
    Ok(line)
}

fn request_with_timeouts(
    req: &Request,
    connect_timeout: Duration,
    rw_timeout: Duration,
) -> io::Result<Response> {
    request_with_timeouts_inner(req, connect_timeout, rw_timeout, None, None)
}

fn request_with_timeouts_inner(
    req: &Request,
    connect_timeout: Duration,
    rw_timeout: Duration,
    cancelled: Option<&std::sync::atomic::AtomicBool>,
    observation_deadline: Option<std::time::Instant>,
) -> io::Result<Response> {
    let stream =
        connect_with_timeout(&socket_path(), connect_timeout).map_err(map_connect_failure)?;
    stream.set_read_timeout(Some(rw_timeout))?;
    stream.set_write_timeout(Some(rw_timeout))?;

    let line = serialize_request(req)?;
    // Map send/first-read failures too, not just connect: on newer kernels
    // (7.1.4-zen, found by the self-hosted runner) a stale socket file CONNECTS
    // successfully and only resets on the first write/read, so a connect-only
    // mapping left a raw ECONNRESET. Before any bytes are exchanged, a reset or
    // broken pipe still means "nobody is really listening".
    //
    // Those two `?` are why `line` is a wiping owner rather than a plain Vec
    // wiped after the writes: either one returns early, and the buffer holding
    // the serialized password would have been freed unwiped on exactly the
    // path the comment above says happens in the field.
    if let Some(deadline) = observation_deadline {
        let mut pending = line.as_slice();
        while !pending.is_empty() {
            stream.set_write_timeout(Some(observation_remaining(deadline)?))?;
            match (&stream).write(pending) {
                Ok(0) => {
                    return Err(io::Error::new(
                        io::ErrorKind::WriteZero,
                        "daemon write stalled",
                    ))
                }
                Ok(n) => pending = &pending[n..],
                Err(e) if e.kind() == io::ErrorKind::Interrupted => continue,
                Err(e) => return Err(map_connect_failure(e)),
            }
        }
        observation_remaining(deadline)?;
    } else {
        (&stream).write_all(&line).map_err(map_connect_failure)?;
        (&stream).flush().map_err(map_connect_failure)?;
    }

    // SO_RCVTIMEO restarts on each read. One monotonic reply deadline must
    // cover every partial read, including ordinary PAM requests. Keep the
    // existing wiping framing buffer; an unseal reply can contain a secret.
    let never_cancelled = std::sync::atomic::AtomicBool::new(false);
    let mut reader = CancellableReply {
        stream: &stream,
        cancelled: cancelled.unwrap_or(&never_cancelled),
        deadline: observation_deadline.unwrap_or_else(|| std::time::Instant::now() + rw_timeout),
    };
    let buf = read_response_line(reader.by_ref().take(MAX_RESPONSE_BYTES))
        .map_err(map_connect_failure)?;
    if buf.len() as u64 >= MAX_RESPONSE_BYTES {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "response exceeded the size limit; refusing it",
        ));
    }
    if buf.is_empty() {
        return Err(io::Error::new(
            io::ErrorKind::UnexpectedEof,
            "daemon closed connection without responding",
        ));
    }
    // The response may carry an unsealed secret. `buf` wipes itself when this
    // frame ends, and by then the bytes live inside a zeroizing `SecretBytes`
    // in the parsed value.
    let response = serde_json::from_slice(buf.trim_ascii())
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;
    reader.check()?;
    Ok(response)
}

struct CancellableReply<'a> {
    stream: &'a UnixStream,
    cancelled: &'a std::sync::atomic::AtomicBool,
    deadline: std::time::Instant,
}

impl CancellableReply<'_> {
    fn check(&self) -> io::Result<()> {
        if self.cancelled.load(std::sync::atomic::Ordering::Relaxed) {
            return Err(io::Error::new(
                io::ErrorKind::ConnectionAborted,
                "request cancelled",
            ));
        }
        if std::time::Instant::now() >= self.deadline {
            return Err(io::Error::new(
                io::ErrorKind::TimedOut,
                "daemon reply timed out",
            ));
        }
        Ok(())
    }
}

impl Read for CancellableReply<'_> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        loop {
            self.check()?;
            // Never spend a full cancellation poll after the remaining budget.
            let remaining = self
                .deadline
                .saturating_duration_since(std::time::Instant::now());
            if remaining.is_zero() {
                continue;
            }
            self.stream
                .set_read_timeout(Some(remaining.min(Duration::from_millis(100))))?;
            let result = self.stream.read(buf);
            // A successful blocking read can itself finish after expiry or
            // cancellation. Do not admit those bytes merely because it succeeded.
            self.check()?;
            match result {
                Err(e)
                    if matches!(
                        e.kind(),
                        io::ErrorKind::WouldBlock
                            | io::ErrorKind::TimedOut
                            | io::ErrorKind::Interrupted
                    ) => {}
                result => return result,
            }
        }
    }
}

/// Read one newline-terminated response line into a buffer that wipes itself,
/// returning it with the newline still attached (like `BufRead::read_line`).
///
/// Not `BufReader::read_line`, and that is the whole point: `BufReader` keeps
/// its own 8 KiB copy of everything it has read, nothing can reach that copy to
/// wipe it, and an `UnsealPassword` response carries the user's login password
/// in cleartext JSON. Zeroizing only the caller's `String` left the secret
/// sitting in the reader's heap until the allocator handed the block out again,
/// which contradicts this module's own promise.
///
/// `src` must already be capped with [`Read::take`]; on hitting the cap this
/// returns whatever arrived, which the caller refuses on length. The buffer is
/// sized up front so no reallocation can strand a half-copy of the response in
/// a freed block. Reading past the newline is harmless and expected: one
/// response per connection, and the stream is dropped immediately after.
fn read_response_line(mut src: impl Read) -> io::Result<Zeroizing<Vec<u8>>> {
    /// One page per syscall. The real responses are a few hundred bytes; the
    /// cap only matters for a peer that is not the daemon.
    const CHUNK: usize = 4096;
    let mut buf = Zeroizing::new(Vec::with_capacity(MAX_RESPONSE_BYTES as usize));
    let mut chunk = Zeroizing::new([0u8; CHUNK]);
    loop {
        let n = match src.read(&mut chunk[..]) {
            Ok(n) => n,
            // `read_line` swallows EINTR too; a signal during a login must not
            // read as a dead daemon.
            Err(e) if e.kind() == io::ErrorKind::Interrupted => continue,
            Err(e) => return Err(e),
        };
        if n == 0 {
            // EOF or the `take` cap: no newline is coming.
            return Ok(buf);
        }
        buf.extend_from_slice(&chunk[..n]);
        if let Some(i) = buf.iter().position(|b| *b == b'\n') {
            buf.truncate(i + 1);
            return Ok(buf);
        }
    }
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
    // The test servers still use `BufReader`: they are the peer, not the
    // client, and nothing secret crosses in that direction.
    use std::io::{BufRead, BufReader};
    use std::os::unix::net::UnixListener;
    use std::path::PathBuf;

    /// A per-test socket path in the temp dir (kept short: sun_path is 108 bytes).
    fn sock(tag: &str) -> PathBuf {
        let p = std::env::temp_dir().join(format!("irlume-cl-{tag}-{}.sock", std::process::id()));
        let _ = std::fs::remove_file(&p);
        p
    }

    #[test]
    fn expired_observation_deadline_does_not_connect() {
        let _guard = testenv::lock();
        let path = sock("already-expired");
        let listener = UnixListener::bind(&path).unwrap();
        listener.set_nonblocking(true).unwrap();
        std::env::set_var("IRLUME_SOCKET", &path);
        let result = request_until(&Request::Ping, std::time::Instant::now());
        std::env::remove_var("IRLUME_SOCKET");
        std::fs::remove_file(path).unwrap();
        assert_eq!(result.unwrap_err().kind(), io::ErrorKind::TimedOut);
        assert_eq!(
            listener.accept().unwrap_err().kind(),
            io::ErrorKind::WouldBlock
        );
    }

    #[test]
    fn observation_deadline_is_shared_by_successive_requests() {
        let _guard = testenv::lock();
        let path = sock("shared-deadline");
        let listener = UnixListener::bind(&path).unwrap();
        std::env::set_var("IRLUME_SOCKET", &path);
        let server = std::thread::spawn(move || {
            for delay in [300, 600] {
                let (mut stream, _) = listener.accept().unwrap();
                let mut request = String::new();
                BufReader::new(&stream).read_line(&mut request).unwrap();
                std::thread::sleep(Duration::from_millis(delay));
                let _ = stream.write_all(b"\"Pong\"\n");
            }
        });
        let deadline = std::time::Instant::now() + Duration::from_millis(800);
        assert!(matches!(
            request_until(&Request::Ping, deadline),
            Ok(Response::Pong)
        ));
        let result = request_until(&Request::Ping, deadline);
        server.join().unwrap();
        std::env::remove_var("IRLUME_SOCKET");
        std::fs::remove_file(path).unwrap();
        assert_eq!(result.unwrap_err().kind(), io::ErrorKind::TimedOut);
    }

    #[test]
    fn ordinary_reply_trickle_cannot_extend_overall_read_budget() {
        let _guard = testenv::lock();
        let path = sock("deadline-trickle");
        let listener = UnixListener::bind(&path).unwrap();
        std::env::set_var("IRLUME_SOCKET", &path);
        let server = std::thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            let mut request = String::new();
            BufReader::new(&stream).read_line(&mut request).unwrap();
            // Every individual pause fits the 100ms SO_RCVTIMEO, but the
            // complete valid reply exceeds the single request budget.
            for byte in b"\"Pong\"\n" {
                if stream.write_all(&[*byte]).is_err() {
                    break;
                }
                std::thread::sleep(Duration::from_millis(35));
            }
        });
        let result = request_with_timeout(&Request::Ping, Duration::from_millis(100));
        server.join().unwrap();
        std::env::remove_var("IRLUME_SOCKET");
        let _ = std::fs::remove_file(&path);
        assert!(
            matches!(result, Err(ref error) if error.kind() == io::ErrorKind::TimedOut),
            "trickled reply must expire, got {result:?}"
        );
    }

    #[test]
    fn enrollment_cancellation_wins_over_already_buffered_success() {
        let _g = testenv::lock();
        let path = sock("enrollment-cancel");
        let listener = UnixListener::bind(&path).unwrap();
        std::env::set_var("IRLUME_SOCKET", &path);
        let server = std::thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            let mut line = String::new();
            BufReader::new(&stream).read_line(&mut line).unwrap();
            stream
                .write_all(b"{\"EnrollmentSession\":\"Started\"}\n{\"Ok\":\"finished\"}\n")
                .unwrap();
        });
        let stop = std::sync::atomic::AtomicBool::new(false);
        let result = enrollment_session(
            &Request::EnrollmentSession {
                user: "alice".into(),
                profile: None,
                scans: 10,
                improve: false,
            },
            &stop,
            |_| {
                stop.store(true, std::sync::atomic::Ordering::Relaxed);
                Ok(None)
            },
        );
        server.join().unwrap();
        std::env::remove_var("IRLUME_SOCKET");
        std::fs::remove_file(path).unwrap();
        assert!(
            matches!(result,Err(ref e) if e.kind()==io::ErrorKind::ConnectionAborted),
            "{result:?}"
        );
    }

    #[test]
    fn enrollment_stream_preserves_coalesced_events_and_scopes_the_decision() {
        let _g = testenv::lock();
        let path = sock("enrollment-stream");
        let listener = UnixListener::bind(&path).unwrap();
        std::env::set_var("IRLUME_SOCKET", &path);
        let server = std::thread::spawn(move || {
            let (stream, _) = listener.accept().unwrap();
            stream
                .set_read_timeout(Some(Duration::from_secs(2)))
                .unwrap();
            let mut reader = BufReader::new(&stream);
            let mut line = String::new();
            reader.read_line(&mut line).unwrap();
            assert!(matches!(
                serde_json::from_str::<Request>(&line).unwrap(),
                Request::EnrollmentSession {
                    scans: 10,
                    improve: false,
                    ..
                }
            ));
            let frames = [
                Response::EnrollmentSession(crate::EnrollmentEvent::Started),
                Response::EnrollmentSession(crate::EnrollmentEvent::Progress {
                    captured: 1,
                    target: 10,
                }),
                Response::EnrollmentSession(crate::EnrollmentEvent::Merge {
                    profile: "Existing".into(),
                    remaining: 9,
                }),
            ];
            let payload = frames
                .iter()
                .map(|v| serde_json::to_string(v).unwrap() + "\n")
                .collect::<String>();
            (&stream).write_all(payload.as_bytes()).unwrap();
            line.clear();
            let received = reader.read_line(&mut line);
            if received.is_err() {
                return false;
            }
            let decision: crate::EnrollmentDecision = serde_json::from_str(&line).unwrap();
            (&stream).write_all(b"{\"Ok\":\"finished\"}\n").unwrap();
            decision.accept
        });
        let stop = std::sync::atomic::AtomicBool::new(false);
        let mut progress = Vec::new();
        let result = enrollment_session(
            &Request::EnrollmentSession {
                user: "alice".into(),
                profile: None,
                scans: 10,
                improve: false,
            },
            &stop,
            |event| {
                match event {
                    crate::EnrollmentEvent::Started => {}
                    crate::EnrollmentEvent::Progress { captured, target } => {
                        progress.push((captured, target))
                    }
                    crate::EnrollmentEvent::Merge { profile, remaining } => {
                        assert_eq!(profile, "Existing");
                        assert_eq!(remaining, 9);
                        return Ok(Some(true));
                    }
                }
                Ok(None)
            },
        );
        let accepted = server.join().unwrap();
        std::env::remove_var("IRLUME_SOCKET");
        std::fs::remove_file(path).unwrap();
        assert!(
            matches!(result, Ok(Response::Ok(ref s)) if s == "finished"),
            "{result:?}"
        );
        assert_eq!(progress, vec![(1, 10)]);
        assert!(accepted);
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
                Request::ListProfiles { user, .. } => assert_eq!(user, "alice"),
                other => panic!("server expected ListProfiles, got {other:?}"),
            }
            let reply = Response::Profiles(vec!["Face Profile 1".into()]);
            let mut out = serde_json::to_vec(&reply).unwrap();
            out.push(b'\n');
            (&stream).write_all(&out).unwrap();
        });

        let resp = request(&Request::ListProfiles {
            user: "alice".into(),
            structured_errors: false,
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

    /// A `Read` that hands back one scripted answer per call, so the reader's
    /// loop can be driven through short reads and EINTR without a socket.
    struct Scripted(std::vec::IntoIter<io::Result<Vec<u8>>>);

    impl Read for Scripted {
        fn read(&mut self, out: &mut [u8]) -> io::Result<usize> {
            match self.0.next() {
                Some(Ok(bytes)) => {
                    let n = bytes.len().min(out.len());
                    out[..n].copy_from_slice(&bytes[..n]);
                    Ok(n)
                }
                Some(Err(e)) => Err(e),
                None => Ok(0),
            }
        }
    }

    fn scripted(steps: Vec<io::Result<Vec<u8>>>) -> Scripted {
        Scripted(steps.into_iter())
    }

    #[test]
    fn the_response_line_stops_at_the_first_newline_and_keeps_it() {
        // `read_line`'s contract, which the callers' length check depends on:
        // the newline counts toward the length, and nothing the peer sends
        // after it becomes part of the response.
        let line = read_response_line(scripted(vec![Ok(b"{\"Ok\":\"hi\"}\nJUNK".to_vec())]))
            .expect("a complete line");
        assert_eq!(&line[..], b"{\"Ok\":\"hi\"}\n");
    }

    #[test]
    fn a_dribbled_response_is_reassembled_across_reads() {
        // A peer that sends a byte at a time is the case `BufReader` used to
        // handle; the loop must keep reading until the newline arrives.
        let steps = b"{\"Ok\":\"hi\"}\n"
            .iter()
            .map(|b| Ok(vec![*b]))
            .collect::<Vec<_>>();
        let line = read_response_line(scripted(steps)).expect("a complete line");
        assert_eq!(&line[..], b"{\"Ok\":\"hi\"}\n");
    }

    #[test]
    fn an_interrupted_read_is_retried_rather_than_reported_as_a_dead_daemon() {
        // EINTR maps to ECONNRESET-shaped advice through `map_connect_failure`
        // at the call site, so swallowing it here is what stops a signal during
        // a login from printing "irlumed is not running".
        let line = read_response_line(scripted(vec![
            Err(io::Error::new(io::ErrorKind::Interrupted, "signal")),
            Ok(b"{\"Ok\":\"hi\"}\n".to_vec()),
        ]))
        .expect("EINTR must not end the read");
        assert_eq!(&line[..], b"{\"Ok\":\"hi\"}\n");
    }

    #[test]
    fn a_read_error_that_is_not_eintr_propagates() {
        let err = read_response_line(scripted(vec![Err(io::Error::new(
            io::ErrorKind::ConnectionReset,
            "peer went away",
        ))]))
        .expect_err("a reset must not read as a response");
        assert_eq!(err.kind(), io::ErrorKind::ConnectionReset);
    }

    #[test]
    fn a_truncated_response_comes_back_whole_for_the_caller_to_judge() {
        // EOF with no newline is not an error here: the caller distinguishes
        // "nothing at all" (UnexpectedEof) from "some bytes, no newline", and
        // it can only do that if it receives the bytes.
        let empty = read_response_line(scripted(vec![])).expect("EOF is not an error");
        assert!(empty.is_empty());
        let partial = read_response_line(scripted(vec![Ok(b"{\"Ok\"".to_vec())]))
            .expect("EOF is not an error");
        assert_eq!(&partial[..], b"{\"Ok\"");
    }

    #[test]
    fn an_oversized_reply_is_refused_by_length_not_read_forever() {
        let _g = testenv::lock();
        let path = sock("huge");
        let listener = UnixListener::bind(&path).unwrap();
        std::env::set_var("IRLUME_SOCKET", &path);
        let server = std::thread::spawn(move || {
            let (stream, _) = listener.accept().unwrap();
            let mut line = String::new();
            let _ = BufReader::new(&stream).read_line(&mut line);
            // No newline anywhere, more than the cap: the shape a peer that is
            // not the daemon uses to make a client read without end.
            let flood = vec![b'x'; MAX_RESPONSE_BYTES as usize * 2];
            let _ = (&stream).write_all(&flood);
        });
        let err = request_with_timeout(&Request::Ping, Duration::from_secs(5))
            .expect_err("an unbounded reply must be refused");
        assert_eq!(err.kind(), io::ErrorKind::InvalidData);
        assert!(
            err.to_string().contains("response exceeded the size limit"),
            "got: {err}"
        );
        let _ = server.join();
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
        #[expect(clippy::undocumented_unsafe_blocks, reason = "doc backlog")]
        let fd = unsafe { libc::socket(libc::AF_UNIX, libc::SOCK_STREAM, 0) };
        assert!(fd >= 0);
        #[expect(clippy::undocumented_unsafe_blocks, reason = "doc backlog")]
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
        // SAFETY: `fd` is the socket created above and bound on the line before
        // this one, and it stays open for the rest of this function.
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
        #[expect(clippy::undocumented_unsafe_blocks, reason = "doc backlog")]
        unsafe {
            libc::close(fd)
        };
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn eacces_does_not_claim_the_daemon_is_down() {
        // Regression: a mode-restricted socket made every unprivileged client
        // report "irlumed is not running" and point the user at `systemctl
        // status` for a healthy service. EACCES means the opposite.
        let denied = io::Error::from_raw_os_error(libc::EACCES);
        let mapped = map_connect_failure(denied);
        assert_eq!(mapped.kind(), io::ErrorKind::PermissionDenied);
        let text = mapped.to_string();
        assert!(text.contains("not permitted to connect"), "got: {text}");
        assert!(text.contains("EACCES"), "got: {text}");
        // Must not tell the user to start a running daemon, and must not
        // prescribe sudo or a chmod: both hide whatever set the mode.
        assert!(!text.contains("is not running"), "got: {text}");
        assert!(!text.contains("systemctl enable"), "got: {text}");
        assert!(!text.contains("chmod"), "got: {text}");

        // The no-listener errnos keep their actionable start-the-daemon message.
        for kind in [
            io::ErrorKind::NotFound,
            io::ErrorKind::ConnectionRefused,
            io::ErrorKind::ConnectionReset,
            io::ErrorKind::BrokenPipe,
        ] {
            let mapped = map_connect_failure(io::Error::new(kind, "x"));
            assert!(
                mapped.to_string().contains("irlumed is not running"),
                "{kind:?} lost its message"
            );
        }
    }

    #[test]
    fn a_serialized_request_is_owned_by_a_wiping_buffer() {
        // The send is two fallible calls, and `?` on either skips anything
        // written after them, so wiping the buffer after the flush left the
        // secret on the heap on exactly the reset/broken-pipe path this file
        // documents as happening in the field. The wipe therefore has to ride
        // on the type, and the type is what gets pinned: heap hygiene is not
        // observable at runtime, so this stops compiling rather than failing.
        fn accepts_only_a_wiping_serializer(_: fn(&Request) -> io::Result<Zeroizing<Vec<u8>>>) {}
        accepts_only_a_wiping_serializer(serialize_request);

        // The buffer still has to be the wire format the daemon parses: one
        // JSON object, newline-terminated.
        let line = serialize_request(&Request::Ping).expect("Ping serializes");
        assert!(line.ends_with(b"\n"), "requests are newline-terminated");
        assert!(
            serde_json::from_slice::<Request>(&line[..line.len() - 1]).is_ok(),
            "the wiping buffer still carries parseable JSON"
        );
    }

    fn salt_helper_script() -> PathBuf {
        use std::os::unix::fs::PermissionsExt as _;
        let path =
            std::env::temp_dir().join(format!("irlume-wallet-salt-helper-{}", std::process::id()));
        std::fs::write(
            &path,
            r#"#!/bin/sh
test "$1" = --read-salt && test "$#" -eq 2 || exit 9
case "$2" in
  present) printf '%056d' 0 ;;
  absent) exit 3 ;;
  denied) exit 1 ;;
  partial) printf x; exit 1 ;;
  oversized) printf '%057d' 0 ;;
  envcheck) test -z "$IRLUME_WALLET_LEAK" && printf '%056d' 0 ;;
  stalled) printf '%s\n' "$$" > "$0.pid"; exec /usr/bin/sleep 30 ;;
  *) exit 9 ;;
esac
"#,
        )
        .unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o700)).unwrap();
        path
    }

    #[test]
    fn wallet_salt_helper_contract_is_bounded_and_unambiguous() {
        let _guard = testenv::lock();
        let helper = salt_helper_script();
        std::env::set_var("IRLUME_KWALLET_INIT", &helper);

        let salt = read_wallet_salt_with_timeout("present", Duration::from_secs(2))
            .unwrap()
            .expect("present salt");
        assert_eq!(salt.expose(), &[b'0'; crate::kwallet_wire::SALT_LEN]);
        std::env::set_var("IRLUME_WALLET_LEAK", "must-not-reach-helper");
        assert!(
            read_wallet_salt_with_timeout("envcheck", Duration::from_secs(2))
                .unwrap()
                .is_some()
        );
        std::env::remove_var("IRLUME_WALLET_LEAK");
        assert!(
            read_wallet_salt_with_timeout("absent", Duration::from_secs(2))
                .unwrap()
                .is_none()
        );
        for user in ["denied", "partial", "oversized"] {
            let error = read_wallet_salt_with_timeout(user, Duration::from_secs(2))
                .expect_err("only clean exit 3 with zero output means absent");
            assert_eq!(error.kind(), io::ErrorKind::InvalidData);
            assert!(!error.to_string().contains(user));
        }
        let started = std::time::Instant::now();
        let error = read_wallet_salt_with_timeout("stalled", Duration::from_millis(150))
            .expect_err("stalled helper must be killed");
        assert_eq!(error.kind(), io::ErrorKind::TimedOut);
        assert!(started.elapsed() < Duration::from_secs(2));
        let pid: u32 = std::fs::read_to_string(helper.with_extension("pid"))
            .unwrap()
            .trim()
            .parse()
            .unwrap();
        assert!(
            !std::path::Path::new(&format!("/proc/{pid}")).exists(),
            "ordinary timeout child must be killed and reaped"
        );

        std::env::remove_var("IRLUME_KWALLET_INIT");
        std::fs::remove_file(helper.with_extension("pid")).unwrap();
        std::fs::remove_file(helper).unwrap();
    }

    #[test]
    fn wallet_salt_result_is_not_accepted_after_the_deadline() {
        let _guard = testenv::lock();
        let helper = salt_helper_script();
        std::env::set_var("IRLUME_KWALLET_INIT", &helper);
        let expired = std::rc::Rc::new(std::cell::Cell::new(false));
        let mark_expired = std::rc::Rc::clone(&expired);
        let clock_expired = std::rc::Rc::clone(&expired);
        let start = std::time::Instant::now();
        let error = read_wallet_salt_with_timeout_and_clock(
            "present",
            Duration::from_millis(10),
            |received_bytes| {
                if received_bytes {
                    mark_expired.set(true);
                }
            },
            || {
                if clock_expired.get() {
                    start + Duration::from_millis(50)
                } else {
                    start
                }
            },
        )
        .expect_err("a complete helper result arriving after the budget must be refused");
        assert!(
            expired.get(),
            "the seam must expire only after reading bytes"
        );
        assert_eq!(error.kind(), io::ErrorKind::TimedOut);
        std::env::remove_var("IRLUME_KWALLET_INIT");
        std::fs::remove_file(helper).unwrap();
    }
}

#[cfg(test)]
mod cancellation_tests {
    use super::*;
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::time::Instant;

    #[test]
    fn cancellation_interrupts_a_partial_reply_without_waiting_for_newline() {
        let (reader, mut writer) = UnixStream::pair().unwrap();
        reader
            .set_read_timeout(Some(Duration::from_millis(10)))
            .unwrap();
        writer.write_all(b"{\"unfinished\":").unwrap();
        let cancelled = AtomicBool::new(false);
        std::thread::scope(|scope| {
            scope.spawn(|| {
                std::thread::sleep(Duration::from_millis(20));
                cancelled.store(true, Ordering::Relaxed);
            });
            let result = read_response_line(
                CancellableReply {
                    stream: &reader,
                    cancelled: &cancelled,
                    deadline: Instant::now() + Duration::from_secs(2),
                }
                .take(MAX_RESPONSE_BYTES),
            );
            assert_eq!(result.unwrap_err().kind(), io::ErrorKind::ConnectionAborted);
        });
    }

    #[test]
    fn cancellable_reply_decodes_complete_lines_and_enforces_overall_deadline() {
        let (reader, mut writer) = UnixStream::pair().unwrap();
        reader
            .set_read_timeout(Some(Duration::from_millis(10)))
            .unwrap();
        let cancelled = AtomicBool::new(false);
        writer.write_all(b"\"Pong\"\n").unwrap();
        let result = read_response_line(
            CancellableReply {
                stream: &reader,
                cancelled: &cancelled,
                deadline: Instant::now() + Duration::from_secs(2),
            }
            .take(MAX_RESPONSE_BYTES),
        )
        .unwrap();
        assert_eq!(&*result, b"\"Pong\"\n");
        let expired = read_response_line(
            CancellableReply {
                stream: &reader,
                cancelled: &cancelled,
                deadline: Instant::now(),
            }
            .take(MAX_RESPONSE_BYTES),
        );
        assert_eq!(expired.unwrap_err().kind(), io::ErrorKind::TimedOut);
    }
}

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
/// Default read/write timeout for management requests.
const DEFAULT_RW_TIMEOUT: Duration = Duration::from_secs(30);

/// Resolve the socket path, honouring `IRLUME_SOCKET` for dev/test.
pub fn socket_path() -> PathBuf {
    std::env::var_os("IRLUME_SOCKET")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from(SOCKET_PATH))
}

/// Send `req` with the default read/write timeout.
pub fn request(req: &Request) -> io::Result<Response> {
    request_with_timeout(req, DEFAULT_RW_TIMEOUT)
}

/// Send `req`, allowing `rw_timeout` for the reply (e.g. a longer budget for an
/// unseal that does a full camera capture + liveness + match first).
pub fn request_with_timeout(req: &Request, rw_timeout: Duration) -> io::Result<Response> {
    let stream = connect_with_timeout(&socket_path(), CONNECT_TIMEOUT)?;
    stream.set_read_timeout(Some(rw_timeout))?;
    stream.set_write_timeout(Some(rw_timeout))?;

    let mut line = serde_json::to_vec(req)
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;
    line.push(b'\n');
    (&stream).write_all(&line)?;
    (&stream).flush()?;
    // The request may carry a password (SealPassword/RecoverySetup); wipe it.
    line.zeroize();

    let mut reader = BufReader::new(&stream);
    let mut buf = String::new();
    reader.read_line(&mut buf)?;
    if buf.is_empty() {
        return Err(io::Error::new(
            io::ErrorKind::UnexpectedEof,
            "daemon closed connection without responding",
        ));
    }
    let parsed = serde_json::from_str(buf.trim())
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e));
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

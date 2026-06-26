//! `pam_irlume.so` — the thin, UNPRIVILEGED PAM module.
//!
//! It does almost nothing itself: open the Unix socket to `irlumed`, send an
//! `Authenticate { user }` request, and map the `AuthResult` to a PAM return
//! code. No camera, no models, no templates, no image data ever live here —
//! that is the whole point of the privilege split.
//!
//! Per NIST SP 800-63B-4, face is one factor of MFA and a non-biometric fallback
//! MUST always exist: on any failure/timeout we return an error so the stack
//! falls through to the password module. Configure as
//! `auth sufficient pam_irlume.so` above `pam_unix.so`.

use irlume_common::{Request, Response, SOCKET_PATH};
use pamsm::{pam_module, Pam, PamError, PamFlags, PamLibExt, PamServiceModule};
use std::io::{BufRead, BufReader, Write};
use std::os::unix::net::UnixStream;
use std::time::Duration;

struct IrlumePam;

impl PamServiceModule for IrlumePam {
    fn authenticate(pamh: Pam, _flags: PamFlags, _args: Vec<String>) -> PamError {
        let user = match pamh.get_user(None) {
            Ok(Some(u)) => u.to_string_lossy().into_owned(),
            _ => return PamError::AUTH_ERR,
        };
        match ask_daemon(&user) {
            Ok(true) => PamError::SUCCESS,
            Ok(false) => PamError::AUTH_ERR, // recognized-but-denied / spoof -> fall through
            // Daemon unreachable / error: don't block login, defer to password.
            Err(_) => PamError::AUTHINFO_UNAVAIL,
        }
    }

    fn setcred(_pamh: Pam, _flags: PamFlags, _args: Vec<String>) -> PamError {
        PamError::SUCCESS
    }
}

/// Round-trip one `Authenticate` request to `irlumed`. Returns Ok(granted).
fn ask_daemon(user: &str) -> std::io::Result<bool> {
    let path = std::env::var("IRLUME_SOCKET").unwrap_or_else(|_| SOCKET_PATH.into());
    let stream = UnixStream::connect(&path)?;
    stream.set_read_timeout(Some(Duration::from_secs(20)))?;
    stream.set_write_timeout(Some(Duration::from_secs(5)))?;

    let req = Request::Authenticate { user: user.to_string() };
    let mut line = serde_json::to_vec(&req)?;
    line.push(b'\n');
    (&stream).write_all(&line)?;

    let mut reader = BufReader::new(&stream);
    let mut resp = String::new();
    reader.read_line(&mut resp)?;
    match serde_json::from_str::<Response>(resp.trim())? {
        Response::AuthResult { granted, live, .. } => Ok(granted && live),
        _ => Ok(false),
    }
}

pam_module!(IrlumePam);

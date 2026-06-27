//! `pam_irlume.so` — the thin, UNPRIVILEGED PAM module.
//!
//! It does almost nothing itself: open the Unix socket to `irlumed`, send a
//! request, and map the reply to a PAM return code. No camera, no models, no
//! templates, no image data ever live here — that is the privilege split.
//!
//! Two modes, selected by a module argument in the PAM line:
//!   * default (`auth sufficient pam_irlume.so`) — VERIFY only. Sends
//!     `Authenticate`; a live match grants WITHOUT touching the password. Use for
//!     `sudo`, polkit, and in-session unlocks where the keyring is already open.
//!   * `unseal` (`auth sufficient pam_irlume.so unseal`) — VERIFY + KEYRING
//!     UNLOCK. Sends `UnsealPassword`; on a live match the daemon releases the
//!     TPM-sealed login password, which we set as `PAM_AUTHTOK` so a downstream
//!     `pam_kwallet5` / `pam_gnome_keyring` unlocks the wallet. Use for login
//!     (SDDM/GDM) and the lock screen after a cold boot.
//!
//! An additional `wait` argument (combinable with either mode) makes the module
//! keep retrying for ~20s instead of doing a single capture. This is what the
//! KDE lock screen needs: kscreenlocker starts the non-interactive auth stack
//! the moment the screen appears, so the window is what lets the user sit back
//! down and be recognized without touching a key. A one-shot capture fires long
//! before they return and is useless there.
//!
//! Per NIST SP 800-63B-4, face is one factor and a non-biometric fallback MUST
//! always exist: on any decline/timeout we return `PAM_IGNORE` so the stack
//! cleanly cascades to the password module (never `AUTH_ERR`, which would just
//! log a failure — the password is always the floor).

use irlume_common::{Request, Response, SOCKET_PATH};
use pamsm::{pam_module, Pam, PamError, PamFlags, PamLibExt, PamServiceModule};
use std::ffi::CString;
use std::io::{BufRead, BufReader, Write};
use std::os::unix::net::UnixStream;
use std::time::{Duration, Instant};

/// How long `wait` keeps retrying before giving up to the password fallback.
const WAIT_BUDGET: Duration = Duration::from_secs(20);
/// Pause between attempts in `wait` mode — lets the daemon release the camera
/// (avoids back-to-back EBUSY) and keeps us from busy-looping.
const WAIT_RETRY_GAP: Duration = Duration::from_millis(400);

struct IrlumePam;

impl PamServiceModule for IrlumePam {
    fn authenticate(pamh: Pam, _flags: PamFlags, args: Vec<String>) -> PamError {
        let user = match pamh.get_user(None) {
            Ok(Some(u)) => u.to_string_lossy().into_owned(),
            _ => return PamError::IGNORE,
        };
        let unseal = args.iter().any(|a| a == "unseal");
        let wait = args.iter().any(|a| a == "wait");

        // In `wait` mode, retry until a match or the budget runs out; otherwise
        // a single attempt. Every non-SUCCESS path returns PAM_IGNORE so the
        // stack always cascades to the password (NIST: a fallback must exist).
        let deadline = Instant::now() + WAIT_BUDGET;
        loop {
            let attempt = if unseal {
                try_unseal(&pamh, &user)
            } else {
                try_verify(&user)
            };
            if attempt == PamError::SUCCESS {
                return PamError::SUCCESS;
            }
            if !wait || Instant::now() >= deadline {
                return PamError::IGNORE;
            }
            std::thread::sleep(WAIT_RETRY_GAP);
        }
    }

    fn setcred(_pamh: Pam, _flags: PamFlags, _args: Vec<String>) -> PamError {
        PamError::SUCCESS
    }
}

/// One verify attempt (sudo / in-session unlock): no password released.
/// Returns `SUCCESS` on a live match, `IGNORE` on anything else.
fn try_verify(user: &str) -> PamError {
    match request(&Request::Authenticate { user: user.to_string() }) {
        Ok(Response::AuthResult { granted: true, live: true, .. }) => PamError::SUCCESS,
        _ => PamError::IGNORE,
    }
}

/// One unseal attempt (login / cold-boot lock screen): release the sealed
/// password and set it as `PAM_AUTHTOK` so the keyring/wallet module unlocks
/// the wallet. `IGNORE` on decline/error so the password fallback runs.
fn try_unseal(pamh: &Pam, user: &str) -> PamError {
    match request(&Request::UnsealPassword { user: user.to_string() }) {
        Ok(Response::PasswordUnsealed { secret }) => {
            // CString copies the bytes; PAM then copies them into its own store.
            // A login password cannot contain a NUL, so this only fails on a
            // malformed secret — treat as decline.
            match CString::new(secret.expose()) {
                Ok(tok) => match pamh.set_authtok(&tok) {
                    Ok(()) => PamError::SUCCESS,
                    Err(_) => PamError::IGNORE,
                },
                Err(_) => PamError::IGNORE,
            }
        }
        _ => PamError::IGNORE,
    }
}

/// Round-trip one request to `irlumed` and return its reply.
fn request(req: &Request) -> std::io::Result<Response> {
    let path = std::env::var("IRLUME_SOCKET").unwrap_or_else(|_| SOCKET_PATH.into());
    let stream = UnixStream::connect(&path)?;
    // Generous read timeout: an unseal does a full camera capture + liveness +
    // match before the TPM unseal.
    stream.set_read_timeout(Some(Duration::from_secs(25)))?;
    stream.set_write_timeout(Some(Duration::from_secs(5)))?;

    let mut line = serde_json::to_vec(req)?;
    line.push(b'\n');
    (&stream).write_all(&line)?;

    let mut reader = BufReader::new(&stream);
    let mut resp = String::new();
    reader.read_line(&mut resp)?;
    serde_json::from_str(resp.trim())
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))
}

pam_module!(IrlumePam);

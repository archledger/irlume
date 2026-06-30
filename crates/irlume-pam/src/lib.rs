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

use irlume_common::{Request, Response, SecretBytes};
use pamsm::{pam_module, Pam, PamError, PamFlags, PamLibExt, PamServiceModule};
use std::ffi::CString;
use std::time::{Duration, Instant};

/// How long `wait` keeps retrying before giving up to the password fallback.
const WAIT_BUDGET: Duration = Duration::from_secs(20);
/// Pause between attempts in `wait` mode — lets the daemon release the camera
/// (avoids back-to-back EBUSY) and keeps us from busy-looping.
const WAIT_RETRY_GAP: Duration = Duration::from_millis(400);

/// PAM-data key under which the `reseal` AUTH line stashes the typed password for
/// the `reseal` SESSION line to pick up. Namespaced to this module.
const RESEAL_STASH_KEY: &str = "pam_irlume_reseal_authtok";

struct IrlumePam;

impl PamServiceModule for IrlumePam {
    fn authenticate(pamh: Pam, _flags: PamFlags, args: Vec<String>) -> PamError {
        let user = match pamh.get_user(None) {
            Ok(Some(u)) => u.to_string_lossy().into_owned(),
            _ => return PamError::IGNORE,
        };
        let unseal = args.iter().any(|a| a == "unseal");
        let wait = args.iter().any(|a| a == "wait");
        let reseal = args.iter().any(|a| a == "reseal");

        // `reseal` AUTH line (placed AFTER password-auth): STASH ONLY. We copy the
        // current PAM_AUTHTOK into PAM transaction data so the matching `reseal`
        // SESSION line can re-bind it later. We deliberately do NOT contact the
        // daemon or touch the TPM here, because this auth line runs even after a
        // FAILED password attempt — acting on the token here is exactly the bug
        // that let a typo overwrite the good seal. The mutation happens in
        // open_session, which PAM only runs once auth has SUCCEEDED, so the token
        // it acts on is always one pam_unix accepted. Always IGNORE.
        if reseal {
            stash_authtok(&pamh);
            return PamError::IGNORE;
        }

        // If the user has typed a password, defer to it — don't power up the
        // camera at all. Scanning a face when they already chose to type would be
        // a 2-3s annoyance for nothing, and we lose no capability by skipping:
        // pam_kwallet5/pam_gnome_keyring open the wallet from the typed password
        // exactly as they would from an unsealed one. Returning IGNORE keeps the
        // password fallback intact.
        //
        // Learning whether they typed depends on the surface:
        //
        //  * Active probe (interactive login greeter — `unseal`, no `wait`): the
        //    plasmalogin/SDDM greeter does NOT pre-set PAM_AUTHTOK; the typed
        //    password only reaches PAM when a module asks for it. So we ask, once:
        //    `pam_get_authtok` returns whatever the user already entered (an empty
        //    string if they submitted a blank field to choose face) WITHOUT
        //    re-prompting — the greeter answers it immediately from the password
        //    it buffered on submit — and caches a non-empty answer as PAM_AUTHTOK
        //    so the downstream pam_unix reuses it with no second prompt. Any
        //    typed character ⇒ non-empty ⇒ we bail before the camera.
        //
        //  * Passive peek (everything else — sudo verify, lock screen `wait`): just
        //    read PAM_AUTHTOK if some earlier module/greeter already set it. We must
        //    NOT actively prompt here: in `wait` mode KDE runs us as a PARALLEL
        //    biometric device (kde-fingerprint) and cancels us natively the moment
        //    a key is pressed, so an echo-off prompt from us would hijack the
        //    password field; and a TTY `sudo` should keep "just look at the camera"
        //    working without forcing the user to press Enter past a prompt first.
        let typed = if unseal && !wait {
            pamh.get_authtok(Some("Password: "))
        } else {
            pamh.get_cached_authtok()
        };
        if let Ok(Some(tok)) = typed {
            if !tok.to_bytes().is_empty() {
                return PamError::IGNORE;
            }
        }

        // In `wait` mode, retry until a match or the budget runs out; otherwise
        // a single attempt. Every non-SUCCESS path returns PAM_IGNORE so the
        // stack always cascades to the password (NIST: a fallback must exist).
        let deadline = Instant::now() + WAIT_BUDGET;
        loop {
            let attempt = if unseal {
                try_unseal(&pamh, &user)
            } else {
                try_verify(&pamh, &user)
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

    /// `reseal` SESSION line: the actual self-heal. Reached ONLY after auth +
    /// account succeeded, so the password the `reseal` AUTH line stashed is one
    /// the system accepted. Hand it to the daemon, which re-binds the TPM-sealed
    /// password to today's PCRs iff it is armed and has gone stale (PCR move or a
    /// changed password). Best-effort and always IGNORE: a session must never
    /// fail because of this, and other modes (unseal/verify/wait) wire no session
    /// line so they fall straight through.
    fn open_session(pamh: Pam, _flags: PamFlags, args: Vec<String>) -> PamError {
        if args.iter().any(|a| a == "reseal") {
            if let Ok(Some(u)) = pamh.get_user(None) {
                try_reseal_session(&pamh, &u.to_string_lossy());
            }
        }
        PamError::IGNORE
    }

    fn close_session(_pamh: Pam, _flags: PamFlags, _args: Vec<String>) -> PamError {
        PamError::IGNORE
    }
}

/// AUTH-phase half of `reseal`: copy the current PAM_AUTHTOK into PAM
/// transaction data for the SESSION half to pick up. Pure read + stash — no
/// daemon, no TPM. If auth ultimately fails the session never opens and PAM
/// drops this data without it ever being acted on. We stash only a non-empty
/// token (a blank submit on the face path has nothing to heal with).
fn stash_authtok(pamh: &Pam) {
    if let Ok(Some(tok)) = pamh.get_cached_authtok() {
        let bytes = tok.to_bytes();
        if !bytes.is_empty() {
            // send_bytes copies into PAM-owned storage; the retrieved copy in the
            // session phase is wrapped in zeroizing SecretBytes before use.
            let _ = pamh.send_bytes(RESEAL_STASH_KEY, bytes.to_vec(), None);
        }
    }
}

/// SESSION-phase half of `reseal`: retrieve the stashed (already-verified)
/// password and ask the daemon to re-seal it if the envelope is armed and stale.
/// Best-effort and silent: a login session must never fail because of this.
fn try_reseal_session(pamh: &Pam, user: &str) {
    let pw = match pamh.retrieve_bytes(RESEAL_STASH_KEY) {
        Ok(bytes) if !bytes.is_empty() => SecretBytes::new(bytes),
        // No stash (e.g. a pure face login that submitted a blank field, or auth
        // took a path that never set a token) — nothing to heal.
        _ => return,
    };
    let _ = request(&Request::ResealPassword {
        user: user.to_string(),
        password: pw,
    });
}

/// One verify attempt (sudo / in-session unlock): no password released.
/// Returns `SUCCESS` on a live match, `IGNORE` on anything else. Passes the PAM
/// service so the daemon can apply tier×operation-class gating (an RGB-only
/// convenience device honours only a screen-unlock service).
fn try_verify(pamh: &Pam, user: &str) -> PamError {
    let service = pamh.get_service().ok().flatten()
        .map(|s| s.to_string_lossy().into_owned());
    match request(&Request::Authenticate { user: user.to_string(), service }) {
        Ok(Response::AuthResult { granted: true, live: true, .. }) => PamError::SUCCESS,
        _ => PamError::IGNORE,
    }
}

/// One unseal attempt (login / cold-boot lock screen): release the sealed
/// password and set it as `PAM_AUTHTOK` so the keyring/wallet module unlocks
/// the wallet. `IGNORE` on decline/error so the password fallback runs.
fn try_unseal(pamh: &Pam, user: &str) -> PamError {
    // Pass the PAM service name so the daemon can apply opt-in biopolicy
    // operation-class gating (e.g. refuse credential release to a remote service).
    let service = pamh.get_service().ok().flatten()
        .and_then(|c| c.to_str().ok().map(str::to_string));
    match request(&Request::UnsealPassword { user: user.to_string(), service }) {
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

/// Round-trip one request to `irlumed` and return its reply. Delegates to the
/// shared client (bounded connect timeout so a stalled daemon never hangs the
/// auth prompt; wire buffers zeroized). The 25s read budget covers a full
/// camera capture + liveness + match before the TPM unseal.
fn request(req: &Request) -> std::io::Result<Response> {
    irlume_common::client::request_with_timeout(req, Duration::from_secs(25))
}

pam_module!(IrlumePam);

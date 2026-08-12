// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright the irlume contributors.

//! `pam_irlume.so`: the thin, UNPRIVILEGED PAM module.
//!
//! It does almost nothing itself: open the Unix socket to `irlumed`, send a
//! request, and map the reply to a PAM return code. No camera, no models, no
//! templates, no image data ever live here; that is the privilege split.
//!
//! Two modes, selected by a module argument in the PAM line:
//!   * default (`auth sufficient pam_irlume.so`): VERIFY only. Sends
//!     `Authenticate`; a live match grants WITHOUT touching the password. Use for
//!     `sudo`, polkit, and in-session unlocks where the keyring is already open.
//!   * `unseal` (`auth sufficient pam_irlume.so unseal`): VERIFY + KEYRING
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
//! log a failure; the password is always the floor).

use irlume_common::{Request, Response, SecretBytes};
use pamsm::{pam_module, Pam, PamError, PamFlags, PamLibExt, PamServiceModule};
use std::ffi::CString;
use std::time::{Duration, Instant};

/// How long `wait` keeps retrying before giving up to the password fallback.
const WAIT_BUDGET: Duration = Duration::from_secs(20);
/// Pause between attempts in `wait` mode: lets the daemon release the camera
/// (avoids back-to-back EBUSY) and keeps us from busy-looping.
const WAIT_RETRY_GAP: Duration = Duration::from_millis(400);

/// PAM-data key under which the `reseal` AUTH line stashes the typed password for
/// the `reseal` SESSION line to pick up. Namespaced to this module.
const RESEAL_STASH_KEY: &str = "pam_irlume_reseal_authtok";

/// PAM-data key for a released GNOME keyring token, carried from the auth
/// phase to `open_session`, which hands it to the unlock helper. A token never
/// rides `PAM_AUTHTOK`: on a Debian-style `kr` stack `pam_unix` would consume
/// it as the Unix password and fail the login it was meant to decorate.
const GKR_TOKEN_STASH_KEY: &str = "pam_irlume_gkr_token";

struct IrlumePam;

/// Panic firewall for the PAM entry points. Unwinding across the C FFI boundary
/// into libpam is undefined behavior, and a crashing auth module historically
/// takes the calling process (sudo, the greeter) down with it or wedges the
/// stack in a fail-open state. Any panic in this module or a dependency maps to
/// `PAM_IGNORE`: the stack cascades to the password, the floor factor.
fn firewall(body: impl FnOnce() -> PamError) -> PamError {
    match std::panic::catch_unwind(std::panic::AssertUnwindSafe(body)) {
        Ok(code) => code,
        Err(_) => PamError::IGNORE,
    }
}

/// True when the PAM transaction is for a remote (non-local) session, so the
/// local camera must not be engaged. Checks PAM_RHOST first (set by sshd and
/// other network services to the client host); an empty, "localhost", or
/// loopback (127.0.0.1 / ::1) rhost is local. Falls back to the SSH_CONNECTION
/// / SSH_TTY environment markers for services that do not set rhost but run
/// under an ssh session (e.g. `sudo` in an ssh shell).
fn is_remote_session(pamh: &Pam) -> bool {
    if let Ok(Some(rhost)) = pamh.get_rhost() {
        let h = rhost.to_string_lossy();
        let h = h.trim();
        let local = h.is_empty()
            || h.eq_ignore_ascii_case("localhost")
            || h.eq_ignore_ascii_case("localhost.localdomain")
            || h == "127.0.0.1"
            || h == "::1";
        if !local {
            return true;
        }
    }
    // Remote-desktop PAM services (xrdp / VNC / xpra / NoMachine) frequently set
    // NEITHER a PAM_RHOST nor the SSH_* markers, yet the person driving them is
    // NOT the one at the local camera. Deny face auth for those services by name:
    // xrdp-sesman in particular includes common-auth on many distros, which is
    // the exact vector by which a locally-oriented biometric runs during a remote
    // login (see xrdp issue #1546). Logind seat/session data that could prove a
    // local seat is not populated yet at authenticate() time (pam_systemd runs in
    // the later session phase), so the service-name deny-list plus the rhost/SSH_*
    // checks are the best available authenticate()-time signal. They are NOT a
    // complete remote-desktop policy (see the residual below).
    if let Ok(Some(svc)) = pamh.get_service() {
        if is_remote_desktop_service(&svc.to_string_lossy()) {
            return true;
        }
    }
    // RESIDUAL (documented in docs/THREAT_MODEL.md): a deny-list by service name
    // cannot catch every remote login. Two known classes:
    //  - Remote-control software attached to the GENUINE local greeter/desktop on
    //    seat0 (x11vnc of :0, an RDP screen-share, NoMachine to the physical
    //    session): the PAM request originates from the real local GDM/SDDM and is
    //    intentionally indistinguishable from someone typing at the monitor.
    //  - GNOME Remote Desktop's headless multi-user RDP mode spins up a remote GDM
    //    login that authenticates through the ORDINARY `gdm-password` service (a
    //    permitted local name), so if that transaction sets no PAM_RHOST it is not
    //    distinguishable here either.
    // Both must be handled outside the module: do not expose the greeter/lock
    // screen to remote control, and do not wire face auth where GNOME Remote Login
    // is enabled.
    std::env::var_os("SSH_CONNECTION").is_some() || std::env::var_os("SSH_TTY").is_some()
}

/// Known remote-desktop / remote-shell PAM service names whose sessions are not
/// physically at the local camera. Matched conservatively (a curated set, not a
/// broad substring sweep) so a legitimate local greeter is never stranded; an
/// unmatched service just falls through to the ordinary remote checks. Face auth
/// standing down here means IGNORE -> the password path, never a denied login.
fn is_remote_desktop_service(service: &str) -> bool {
    let s = service.trim().to_ascii_lowercase();
    s.starts_with("xrdp")            // xrdp, xrdp-sesman
        || s.contains("vnc")         // tigervnc, x11vnc, vncserver, kde vnc, ...
        || s.starts_with("xpra")
        || s == "nx"                 // NoMachine
        || s.starts_with("nxagent")
        || s.starts_with("nxnode")
        || s.starts_with("nxserver")
        || s == "sshd" // belt-and-suspenders alongside the rhost / SSH_* checks
}

impl PamServiceModule for IrlumePam {
    fn authenticate(pamh: Pam, _flags: PamFlags, args: Vec<String>) -> PamError {
        firewall(move || {
            let user = match pamh.get_user(None) {
                Ok(Some(u)) => u.to_string_lossy().into_owned(),
                _ => return PamError::IGNORE,
            };
            // Remote-session guard: never fire the local camera for an SSH / remote
            // login or sudo. The camera is physically at the machine, so whoever is
            // in front of it (not the remote user) would grant the remote session.
            // A non-empty PAM_RHOST (or the SSH_* env markers) means remote; return
            // IGNORE so the password/other factor authenticates instead. Always-on,
            // independent of biopolicy or how the stack is wired (a hand-added
            // pam_irlume line in system-auth is covered too).
            if is_remote_session(&pamh) {
                return PamError::IGNORE;
            }
            let unseal = args.iter().any(|a| a == "unseal");
            let wait = args.iter().any(|a| a == "wait");
            let reseal = args.iter().any(|a| a == "reseal");
            let keyring = args.iter().any(|a| a == "keyring");
            // `kr` (keyring-continue): on a Debian `@include` greeter whose face line
            // is `sufficient`, a plain SUCCESS short-circuits before pam_gnome_keyring,
            // so a COLD face login leaves the login keyring locked. With `kr` we
            // instead return IGNORE on a cold login that released the password;
            // `sufficient` then CONTINUES, pam_unix authenticates with the token, and
            // pam_gnome_keyring unlocks the keyring. A WARM lock still returns SUCCESS
            // (short-circuit: keyring already open, and cosmic's locker needs it).
            // Opt-in, so the Fedora success=1 layout (no `kr`) is unchanged.
            let kr = args.iter().any(|a| a == "kr");

            // `keyring` mode: post-auth login-keyring unlock for the FINGERPRINT
            // path. This line sits at the auth landing, after a trusted factor has
            // already succeeded. If a password is present (the user typed one, or an
            // earlier face `unseal` set it) the keyring unlocks from it; do nothing.
            // If PAM_AUTHTOK is empty (a fingerprint login provides no password), ask
            // the daemon to release the TPM-sealed password and set it, so a later
            // pam_gnome_keyring/pam_kwallet opens the wallet. ALWAYS IGNORE: keyring
            // unlock is best-effort and must never fail or block the login.
            if keyring {
                // A typed password used to be an early return here. It cannot
                // be one any more: a token-armed keyring (#250) does not open
                // with the typed password, so the release must proceed even
                // then. The daemon makes that call, because only it can read
                // the envelope's kind: for `have_password: true` against a
                // password envelope it answers KeyringUnlockNotNeeded without
                // spending a TPM unseal, which is the old early return, moved
                // to where the deciding fact lives.
                let have_password = matches!(
                    pamh.get_cached_authtok(),
                    Ok(Some(tok)) if !tok.to_bytes().is_empty()
                );
                let service = pamh
                    .get_service()
                    .ok()
                    .flatten()
                    .and_then(|c| c.to_str().ok().map(str::to_string));
                if let Ok(Response::PasswordUnsealed { secret, kind }) =
                    request(&Request::UnsealKeyring {
                        user: user.clone(),
                        service,
                        have_password,
                    })
                {
                    // Routed by kind, not assumed: on KDE this starts the wallet
                    // daemon, a GNOME token is stashed for the session helper,
                    // and only a login password becomes an AUTHTOK. Best-effort
                    // either way; the IGNORE below never becomes a failed login.
                    let _ = release_secret(&pamh, &user, &secret, kind);
                }
                return PamError::IGNORE;
            }
            // `facefirst` (GNOME/GDM wiring): GDM's PAM conversation BLOCKS on the
            // active password probe until the user types (unlike plasmalogin/SDDM,
            // which answer instantly from the buffered field), so skip the probe and
            // scan right away; a typed password still wins via the modules after us.
            let facefirst = args.iter().any(|a| a == "facefirst");

            // `ondemand` (COSMIC / cosmic-greeter): a greeter that DOES answer the
            // active probe from the buffered field (like plasmalogin) but drives BOTH
            // the cold login and the live lock screen through ONE service (like GDM).
            // So we want the on-demand ACTIVE probe (face engages only when the user
            // submits an empty field; never ambient, never after a typed/rejected
            // password) AND the warm `unseal→verify` fallback below (so the lock
            // screen still unlocks). It is `facefirst`'s warm-fallback WITHOUT its
            // scan-immediately probe. Uses the active-probe path (it never sets
            // `facefirst`, so the `!facefirst` probe test below stays true).
            let ondemand = args.iter().any(|a| a == "ondemand");

            // `reseal` AUTH line (placed AFTER password-auth): STASH ONLY. We copy the
            // current PAM_AUTHTOK into PAM transaction data so the matching `reseal`
            // SESSION line can re-bind it later. We deliberately do NOT contact the
            // daemon or touch the TPM here, because this auth line runs even after a
            // FAILED password attempt; acting on the token here is exactly the bug
            // that let a typo overwrite the good seal. The mutation happens in
            // open_session, which PAM only runs once auth has SUCCEEDED, so the token
            // it acts on is always one pam_unix accepted. Always IGNORE.
            if reseal {
                stash_authtok(&pamh);
                return PamError::IGNORE;
            }

            // If the user has typed a password, defer to it; don't power up the
            // camera at all. Scanning a face when they already chose to type would be
            // a 2-3s annoyance for nothing, and we lose no capability by skipping:
            // pam_kwallet5/pam_gnome_keyring open the wallet from the typed password
            // exactly as they would from an unsealed one. Returning IGNORE keeps the
            // password fallback intact.
            //
            // Learning whether they typed depends on the surface:
            //
            //  * Active probe (interactive login greeter; `unseal`, no `wait`): the
            //    plasmalogin/SDDM greeter does NOT pre-set PAM_AUTHTOK; the typed
            //    password only reaches PAM when a module asks for it. So we ask, once:
            //    `pam_get_authtok` returns whatever the user already entered (an empty
            //    string if they submitted a blank field to choose face) WITHOUT
            //    re-prompting (the greeter answers it immediately from the password
            //    it buffered on submit) and caches a non-empty answer as PAM_AUTHTOK
            //    so the downstream pam_unix reuses it with no second prompt. Any
            //    typed character ⇒ non-empty ⇒ we bail before the camera.
            //
            //  * Passive peek (everything else: sudo verify, lock screen `wait`): just
            //    read PAM_AUTHTOK if some earlier module/greeter already set it. We must
            //    NOT actively prompt here: in `wait` mode KDE runs us as a PARALLEL
            //    biometric device (kde-fingerprint) and cancels us natively the moment
            //    a key is pressed, so an echo-off prompt from us would hijack the
            //    password field; and a TTY `sudo` should keep "just look at the camera"
            //    working without forcing the user to press Enter past a prompt first.
            let typed = if unseal && !wait && !facefirst {
                pamh.get_authtok(Some("Password: "))
            } else {
                pamh.get_cached_authtok()
            };
            if let Ok(Some(tok)) = typed {
                if !tok.to_bytes().is_empty() {
                    return PamError::IGNORE;
                }
            }

            // On a polkit prompt the daemon requires a deliberate consent gesture,
            // which is not discoverable from the dialog, so tell the user what to do.
            // Best-effort text info (the KDE/GNOME agent shows it inline); shown
            // once, before the capture, only for the polkit service so sudo / lock
            // screen are unaffected.
            //
            // The text comes from the same `consent_gesture_mode` parse the engine
            // gates on, exactly as the credential-release probe below does. It used
            // to be a hardcoded string naming both gestures, which told a
            // `closure`-only user to nod at a gate that would not accept a nod: the
            // failure `ConsentGesture` was introduced to prevent.
            // From the shared table, so this cannot drift from the class the
            // daemon enforces or the window the grace loop uses (#362). Out of
            // step, this produces the worst version of the bug: a mandatory
            // gesture the user is never told to make.
            let is_polkit = pamh
                .get_service()
                .ok()
                .flatten()
                .and_then(|c| c.to_str().ok().map(str::to_string))
                .and_then(|s| irlume_common::pam_service::classify(&s))
                .is_some_and(irlume_common::pam_service::ServiceKind::wants_consent_instruction);
            if is_polkit && !unseal {
                let mode = irlume_common::config::consent_gesture_mode();
                let how = mode.instruction("approve");
                // Name how to approve, and, ONLY in the modes where a shake is
                // actually detected, that a head shake declines and closes the
                // window. The shake-cancel is NOT mode-independent: the daemon's
                // consent watch reads a Shake only inside `if allow_nod`
                // (irlume-auth consent_watch), and `gestures_permitted_by` grants
                // `allow_nod` to Nod and Either only. In Closure mode a shake is
                // never seen, so the clause is suppressed rather than promising a
                // gesture that does nothing. Misconfigured already returns a full
                // diagnostic sentence, so it gets no clause either.
                let msg = match mode {
                    irlume_common::config::ConsentGesture::Nod
                    | irlume_common::config::ConsentGesture::Either => {
                        // "decline", NOT "closes the window". A shake ends THIS
                        // attempt; polkit-kde then decides whether to re-prompt, and
                        // measured on Plasma 6 (2026-08-11) it closes only after its
                        // own retry count, about three failed attempts. Promising an
                        // immediate close would be the same false instruction the
                        // closure-mode clause was corrected for.
                        format!("irlume: {how}; shake your head to decline")
                    }
                    irlume_common::config::ConsentGesture::Closure
                    | irlume_common::config::ConsentGesture::Misconfigured => {
                        format!("irlume: {how}")
                    }
                };
                let _ = pamh.conv(Some(&msg), pamsm::PamMsgStyle::TEXT_INFO);
            }

            // Same discoverability problem on the credential-release path: by
            // default the daemon requires the deliberate gesture before it releases
            // the sealed keyring password, and a greeter that just says "Password:"
            // gives the user no way to know that. Shown only on the interactive
            // greeter probe (`unseal` without `wait`): in `wait` mode KDE runs us as
            // a parallel biometric device where an unsolicited message competes with
            // the password field.
            //
            // The instruction names the gesture the daemon will actually accept,
            // from the same `consent_gesture` parse the engine gates on: telling a
            // `closure`-only user to nod would cost them the whole watch window and
            // then the password.
            //
            // Reading a root-only setting here is best-effort by design. Greeter and
            // lock stacks run as root, so the read normally succeeds; a non-root PAM
            // caller (a custom locker, `pamtester`) sees an unreadable file, which
            // fails secure to ON and at worst over-instructs. It cannot obtain the
            // credential either way, since the daemon refuses a non-root
            // UnsealPassword.
            if unseal && !wait && irlume_common::config::credential_release_gesture_required() {
                let how = irlume_common::config::consent_gesture_mode()
                    .instruction("unlock your keyring");
                let _ = pamh.conv(
                    Some(&format!("irlume: {how}")),
                    pamsm::PamMsgStyle::TEXT_INFO,
                );
            }

            // In `wait` mode, retry until a match or the budget runs out; otherwise
            // a single attempt. Every non-SUCCESS path returns PAM_IGNORE so the
            // stack cascades to the password (NIST: a fallback must exist), with ONE
            // deliberate exception handled just below: a polkit shake-decline returns
            // ABORT to close the dialog, because the user explicitly declined and no
            // fallback is wanted for THAT attempt (a timeout or no-match still
            // IGNOREs, so the password box still appears when the user did not shake).
            let deadline = Instant::now() + WAIT_BUDGET;
            loop {
                let (mut attempt, mut delivered) = if unseal {
                    try_unseal(&pamh, &user)
                } else {
                    (try_verify(&pamh, &user), Released::Failed)
                };
                // GDM and cosmic-greeter each drive BOTH the cold greeter and the
                // live lock screen through one service. Unsealing is refused on the
                // convenience tier (and on an un-armed keyring); a warm screen unlock
                // only needs identity, so fall back to a plain verify before giving up
                // to the password. `try_verify` re-applies biopolicy in the daemon, so
                // a cold login on a convenience tier still returns Deny here: the
                // fallback only rescues the identity-only warm-unlock case.
                if (facefirst || ondemand) && unseal && attempt != PamError::SUCCESS {
                    attempt = try_verify(&pamh, &user);
                    delivered = Released::Failed; // identity only, nothing released
                }
                // A polkit shake-decline is terminal: try_verify returned ABORT, so
                // abort the whole PAM stack instead of cascading to the password. The
                // attempt then fails with no password prompt, and the polkit agent
                // decides what to show (polkit-kde re-prompts and closes after its own
                // retry count; see POLKIT_VERIFY_STANZA in irlume-cli). Never retried,
                // even in `wait` mode: the user said no. Only a shake on a polkit
                // dialog reaches this; every other non-SUCCESS falls to IGNORE below.
                if attempt == PamError::ABORT {
                    return PamError::ABORT;
                }
                if attempt == PamError::SUCCESS {
                    // `kr` + a COLD login that put the login PASSWORD in
                    // `PAM_AUTHTOK` → IGNORE, so the `sufficient` control
                    // CONTINUES and pam_unix + pam_gnome_keyring authenticate
                    // and unlock from it. Every other success short-circuits:
                    // warm lock, nothing released, no `kr`, and every non-
                    // password delivery. A wallet key or keyring token left
                    // nothing pam_unix could accept, so continuing would turn a
                    // verified face into a password prompt; those kinds unlock
                    // through their own channels (the ksecretd pipe, the
                    // session helper) after this SUCCESS ends the auth phase.
                    if kr
                        && delivered == Released::AuthtokSet
                        && !irlume_common::platform::user_has_live_session(&user)
                    {
                        return PamError::IGNORE;
                    }
                    return PamError::SUCCESS;
                }
                if !wait || Instant::now() >= deadline {
                    return PamError::IGNORE;
                }
                std::thread::sleep(WAIT_RETRY_GAP);
            }
        })
    }

    fn setcred(_pamh: Pam, _flags: PamFlags, _args: Vec<String>) -> PamError {
        firewall(|| PamError::SUCCESS)
    }

    /// `reseal` SESSION line: the actual self-heal. Reached ONLY after auth +
    /// account succeeded, so the password the `reseal` AUTH line stashed is one
    /// the system accepted. Hand it to the daemon, which re-binds the TPM-sealed
    /// password to today's PCRs iff it is armed and has gone stale (PCR move or a
    /// changed password). Best-effort and always IGNORE: a session must never
    /// fail because of this, and other modes (unseal/verify/wait) wire no session
    /// line so they fall straight through.
    fn open_session(pamh: Pam, _flags: PamFlags, args: Vec<String>) -> PamError {
        firewall(move || {
            if args.iter().any(|a| a == "reseal") {
                if let Ok(Some(u)) = pamh.get_user(None) {
                    let user = u.to_string_lossy().into_owned();
                    // Reseal first: on a typed-password login after PCR drift
                    // it repairs the token envelope from its password wrap, so
                    // the delivery below can then unseal what a moment ago
                    // could not be unsealed.
                    try_reseal_session(&pamh, &user);
                    deliver_gnome_token(&pamh, &user);
                }
            }
            PamError::IGNORE
        })
    }

    fn close_session(_pamh: Pam, _flags: PamFlags, _args: Vec<String>) -> PamError {
        firewall(|| PamError::IGNORE)
    }
}

/// AUTH-phase half of `reseal`: copy the current PAM_AUTHTOK into PAM
/// transaction data for the SESSION half to pick up. Pure read + stash; no
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
        // took a path that never set a token); nothing to heal.
        _ => return,
    };
    let _ = request(&Request::ResealPassword {
        user: user.to_string(),
        password: pw,
    });
}

/// SESSION-phase delivery of a GNOME keyring token (#250): the keyring is
/// keyed to a random token only the TPM (or a password login's reseal) can
/// produce, so EVERY session open on a token-armed account must send it to the
/// keyring daemon's control socket; the typed password `pam_gnome_keyring`
/// stashed, when there is one, no longer opens anything.
///
/// The token normally arrives in the auth-phase stash (face or fingerprint
/// release). Without one — a typed-password login, or a topology where auth
/// ran in a different PAM transaction — ask the daemon: `have_password: true`
/// makes that free for password-armed users (no TPM touched), so the extra
/// round trip costs only token users, only on their stash-less logins.
/// Best-effort and silent like everything else in the session phase.
fn deliver_gnome_token(pamh: &Pam, user: &str) {
    let token = match pamh.retrieve_bytes(GKR_TOKEN_STASH_KEY) {
        Ok(bytes) if !bytes.is_empty() => SecretBytes::new(bytes),
        _ => {
            let service = pamh
                .get_service()
                .ok()
                .flatten()
                .and_then(|c| c.to_str().ok().map(str::to_string));
            // `true` is accurate here, not a convenient lie. The flag drives
            // exactly one decision: whether a PASSWORD-keyed keyring is
            // already served. By the session phase it always is, either
            // because the user typed a password or because the auth phase
            // released the sealed one into `PAM_AUTHTOK`; and if neither
            // happened, nothing can open that keyring anyway. Passing `false`
            // instead would make the daemon unseal a login password on every
            // session open, which this hook then discards, spending a TPM
            // round trip (seconds on a discrete TPM) per login for nothing.
            match request(&Request::UnsealKeyring {
                user: user.to_string(),
                service,
                have_password: true,
            }) {
                // Only a token belongs on the control socket. A password or a
                // wallet key reaching here would mean the user is armed for a
                // different backend, and this session hook has no business
                // delivering it.
                Ok(Response::PasswordUnsealed {
                    secret,
                    kind: irlume_common::KeyringSecretKind::GnomeKeyringToken,
                }) => secret,
                _ => return,
            }
        }
    };
    let _ = hand_token_to_keyring_daemon(user, &token);
}

/// Resolve a helper binary, ignoring the environment override under
/// secure execution.
///
/// The same rule `socket_path` already follows, and for the same reason: this
/// module is linked into PAM stacks that can be entered setuid-root (notably
/// `/etc/pam.d/sudo` under `--with-sudo`), which inherit the invoking user's
/// environment. These two helpers are spawned AS ROOT with a TPM-released
/// secret written to their stdin, so a plain `env::var` there would hand an
/// attacker root execution and the credential together. `secure_getenv`
/// returns NULL under AT_SECURE, so the compiled path wins in exactly those
/// contexts while the daemon and the test harness keep the override.
///
/// The shipped wiring does not put `unseal` in a setuid stack today, so this
/// closes a latent hole rather than a live one.
fn secure_helper_path(var: &str, compiled: &str) -> String {
    irlume_common::client::secure_env(var)
        .and_then(|v| v.into_string().ok())
        .filter(|v| !v.trim().is_empty())
        .unwrap_or_else(|| compiled.to_string())
}

/// Spawn the unlock helper with the token on stdin. The helper drops to the
/// target user before touching their runtime directory (the daemon's control
/// socket authenticates the peer uid, and root pathname work inside a
/// user-owned directory is the CVE-2018-10380 shape irlume-kwallet-init
/// already refuses to repeat).
fn hand_token_to_keyring_daemon(user: &str, token: &irlume_common::SecretBytes) -> bool {
    use std::io::Write;
    use std::process::{Command, Stdio};

    let helper = secure_helper_path("IRLUME_GKR_UNLOCK", irlume_common::GKR_UNLOCK_PATH);
    if !std::path::Path::new(&helper).is_file() {
        return false;
    }
    let mut child = match Command::new(&helper)
        .arg(user)
        .stdin(Stdio::piped())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
    {
        Ok(c) => c,
        Err(_) => return false,
    };
    if let Some(mut sin) = child.stdin.take() {
        if sin.write_all(token.expose()).is_err() {
            kill_bounded(&mut child);
            return false;
        }
        // EOF tells the helper the token is complete.
        drop(sin);
    }
    // Bounded, because this is the PAM session phase and the login blocks on
    // it. The helper has its own deadlines on the socket, but a wedged or
    // stopped child would otherwise hang the login here; the helper's own
    // ceiling plus a margin is the budget, and a child still running past it
    // is killed rather than waited on.
    wait_bounded(&mut child, HELPER_BUDGET)
}

/// Ceiling on the keyring helpers. The GNOME unlock helper's own socket
/// deadlines are 10s, so this is that plus room to start and exit; the KDE
/// helper forks and execs the wallet daemon and normally exits in
/// milliseconds, so the same ceiling is generous there.
const HELPER_BUDGET: Duration = Duration::from_secs(15);

/// Reap `child`, giving up (and killing it) after `budget`.
fn wait_bounded(child: &mut std::process::Child, budget: Duration) -> bool {
    reap_by(child, Instant::now() + budget).is_some_and(|status| status.success())
}

/// Reap `child`, giving up (and killing it) at `deadline`.
///
/// `Child::wait` has no timeout, and polling `try_wait` is the only way to put
/// a ceiling on it without another thread. The poll interval is coarse on
/// purpose: this runs once per login and the common case exits immediately.
fn reap_by(child: &mut std::process::Child, deadline: Instant) -> Option<std::process::ExitStatus> {
    loop {
        match child.try_wait() {
            Ok(Some(status)) => return Some(status),
            Ok(None) => {
                if Instant::now() >= deadline {
                    kill_bounded(child);
                    return None;
                }
                std::thread::sleep(Duration::from_millis(25));
            }
            Err(_) => {
                kill_bounded(child);
                return None;
            }
        }
    }
}

/// Request the child's termination and reap it if it dies promptly, never
/// waiting without a bound.
///
/// `kill` only queues SIGKILL. A child parked in an uninterruptible kernel
/// sleep (a wedged filesystem, a dead device) does not die until that sleep
/// resolves, and `Child::wait` here would block straight through the deadline
/// this module just enforced, hanging the login the deadline exists to
/// protect. The short poll reaps the common case, where a killed child exits
/// within a few scheduler ticks; a child that outlives it is left unreaped
/// rather than bought with a hung login, and init collects it once the login
/// process exits.
fn kill_bounded(child: &mut std::process::Child) {
    let _ = child.kill();
    let reap_deadline = Instant::now() + Duration::from_millis(200);
    loop {
        match child.try_wait() {
            Ok(Some(_)) | Err(_) => return,
            Ok(None) => {
                if Instant::now() >= reap_deadline {
                    return;
                }
                std::thread::sleep(Duration::from_millis(10));
            }
        }
    }
}

/// Cap on what the kwallet helper may print. Its whole output is one socket
/// path, far below this; a helper past the cap is misbehaving and gets killed
/// rather than read further.
const HELPER_STDOUT_MAX: usize = 4096;

/// Read `child`'s stdout to completion while reaping it, giving up (and
/// killing it) after `budget`.
///
/// `wait_with_output` would be unbounded twice over: the wait has no deadline,
/// and the read returns only when every holder of the pipe's write end has
/// closed it. One holder is outside our control: the helper points the wallet
/// daemon's stdio at /dev/null before exec, but if its open of /dev/null
/// fails, the daemon inherits the pipe and outlives the login. So the deadline
/// has to sit on the read itself: a non-blocking pipe polled alongside
/// `try_wait`, which also stops trusting the helper to ever exit.
///
/// `None` means the deadline expired, the output cap was hit, or the pipe
/// broke; the child is killed in every such case so nothing is left holding
/// the login open. `Some` carries the exit status and whatever stdout the
/// child produced.
fn read_stdout_bounded(
    child: &mut std::process::Child,
    budget: Duration,
) -> Option<(std::process::ExitStatus, Vec<u8>)> {
    use std::io::Read;
    use std::os::fd::AsRawFd;

    let kill_and_fail = |child: &mut std::process::Child| {
        kill_bounded(child);
        None
    };
    let Some(mut stdout) = child.stdout.take() else {
        return kill_and_fail(child);
    };
    let fd = stdout.as_raw_fd();
    // SAFETY: fcntl on an fd this process owns; F_GETFL/F_SETFL touch no memory.
    let flags = unsafe { libc::fcntl(fd, libc::F_GETFL) };
    #[expect(clippy::undocumented_unsafe_blocks, reason = "doc backlog")]
    if flags < 0 || unsafe { libc::fcntl(fd, libc::F_SETFL, flags | libc::O_NONBLOCK) } < 0 {
        return kill_and_fail(child);
    }

    let deadline = Instant::now() + budget;
    let mut out = Vec::new();
    let mut chunk = [0u8; 256];
    let mut exited = None;
    loop {
        match stdout.read(&mut chunk) {
            // EOF: every write end is closed, nothing more can arrive.
            Ok(0) => break,
            Ok(n) => {
                out.extend_from_slice(&chunk[..n]);
                if out.len() > HELPER_STDOUT_MAX {
                    return kill_and_fail(child);
                }
            }
            Err(e) if e.kind() == std::io::ErrorKind::Interrupted => {}
            Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                if exited.is_some() {
                    // The child is gone and the pipe is drained. Anything it
                    // wrote landed before it exited and was read above; only a
                    // leaked write end could still delay the EOF, and waiting
                    // for that would hang until the wallet daemon dies. What is
                    // in hand is everything the helper said.
                    break;
                }
                match child.try_wait() {
                    // Exited between the read and now: go around once more to
                    // drain what it wrote just before exiting.
                    Ok(Some(status)) => exited = Some(status),
                    Ok(None) => {
                        if Instant::now() >= deadline {
                            return kill_and_fail(child);
                        }
                        std::thread::sleep(Duration::from_millis(25));
                    }
                    Err(_) => return kill_and_fail(child),
                }
            }
            Err(_) => return kill_and_fail(child),
        }
    }
    match exited {
        Some(status) => Some((status, out)),
        // EOF arrived before the exit was observed: the helper is on its way
        // out, so reap it under what remains of the budget.
        None => reap_by(child, deadline).map(|status| (status, out)),
    }
}

/// One verify attempt (sudo / polkit / in-session unlock): no password released.
/// Returns `SUCCESS` on a live match; `ABORT` on a DELIBERATE head-shake decline
/// at a polkit consent dialog, so the whole stack aborts and the agent closes its
/// window; and `IGNORE` on anything else so the password fallback survives. Passes
/// the PAM service so the daemon can apply tier×operation-class gating (an RGB-only
/// convenience device honours only a screen-unlock service).
fn try_verify(pamh: &Pam, user: &str) -> PamError {
    let service = pamh
        .get_service()
        .ok()
        .flatten()
        .map(|s| s.to_string_lossy().into_owned());
    // A shake aborts the stack ONLY on a polkit consent dialog. Scoped HERE, not
    // in the daemon: the daemon reports the shake as a fact (`declined_by_gesture`);
    // the PAM layer decides what each surface does with it. This is the SAME
    // predicate the shake hint keys on (`wants_consent_instruction`, both = the
    // AppConsent class), so the dialog only tells the user "shake to decline
    // (closes the window)" where a shake actually closes it. On the greeter, lock
    // screen, and sudo a shake stays a soft IGNORE and the password fallback lives.
    let is_polkit_consent = service
        .as_deref()
        .and_then(irlume_common::pam_service::classify)
        .is_some_and(irlume_common::pam_service::ServiceKind::wants_consent_instruction);
    match request(&Request::Authenticate {
        user: user.to_string(),
        service,
    }) {
        Ok(Response::AuthResult {
            granted: true,
            live: true,
            ..
        }) => PamError::SUCCESS,
        // A deliberate head-shake on a polkit dialog. Abort so the password module
        // never prompts and the agent, seeing a total auth failure, closes its
        // window (polkit ends the attempt on any non-success and hands one
        // completed(FALSE) to the desktop agent; on this machine polkit-kde closes
        // rather than re-prompts). Fail-safe: this branch can only DENY, never grant.
        Ok(Response::AuthResult {
            granted: false,
            declined_by_gesture: true,
            ..
        }) if is_polkit_consent => PamError::ABORT,
        _ => PamError::IGNORE,
    }
}

/// One unseal attempt (login / cold-boot lock screen): release the sealed
/// secret and deliver it by kind. `IGNORE` on decline/error so the password
/// fallback runs. The second value reports HOW a success delivered, for the
/// `kr` decision at the call site.
fn try_unseal(pamh: &Pam, user: &str) -> (PamError, Released) {
    // Pass the PAM service name so the daemon can apply opt-in biopolicy
    // operation-class gating (e.g. refuse credential release to a remote service).
    let service = pamh
        .get_service()
        .ok()
        .flatten()
        .and_then(|c| c.to_str().ok().map(str::to_string));
    match request(&Request::UnsealPassword {
        user: user.to_string(),
        service,
    }) {
        Ok(Response::PasswordUnsealed { secret, kind }) => {
            let delivered = release_secret(pamh, user, &secret, kind);
            (code_for(delivered), delivered)
        }
        _ => (PamError::IGNORE, Released::Failed),
    }
}

/// The PAM code a delivery outcome earns.
///
/// Exhaustive with no catch-all (#365). The arm this replaces was
/// `delivered => PamError::SUCCESS`, which enumerated exactly one way to fail
/// and read every other variant, including any added later, as "the secret
/// reached its consumer". On a `kr` cold-login stack that answer short-circuits
/// `auth sufficient`, so `pam_unix` never runs and nothing puts a password in
/// `PAM_AUTHTOK`: the user is logged in with a keyring nothing can open, and no
/// diagnostic anywhere says why. A new variant now fails to compile until
/// someone states which of the two it is.
fn code_for(delivered: Released) -> PamError {
    match delivered {
        Released::AuthtokSet | Released::WalletStarted | Released::TokenStashed => {
            PamError::SUCCESS
        }
        Released::Failed => PamError::IGNORE,
    }
}

/// How a released secret was delivered, which the `kr` cold-login decision
/// routes on: only [`Released::AuthtokSet`] leaves something `pam_unix` can
/// authenticate with, so only it may continue the stack.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Released {
    /// The login password is in `PAM_AUTHTOK`.
    AuthtokSet,
    /// The KDE wallet daemon was started with the wallet key.
    WalletStarted,
    /// A GNOME keyring token was stashed for `open_session` to deliver.
    TokenStashed,
    Failed,
}

/// Deliver a released keyring secret to whatever actually consumes it.
///
/// The kinds are not interchangeable. A login password becomes `PAM_AUTHTOK`,
/// which `pam_gnome_keyring` reads. A KDE wallet key would be meaningless as an
/// `AUTHTOK`: `pam_kwallet5` would run PBKDF2 over it a second time and hand
/// `ksecretd` the wrong bytes; it goes to `ksecretd` on its startup pipe. A
/// GNOME keyring token is not the Unix password, so it must never sit where
/// `pam_unix` might read it; it is stashed in PAM data and `open_session`
/// sends it to the keyring daemon's control socket via the unlock helper.
fn release_secret(
    pamh: &Pam,
    user: &str,
    secret: &irlume_common::SecretBytes,
    kind: irlume_common::KeyringSecretKind,
) -> Released {
    use irlume_common::KeyringSecretKind as K;
    match kind {
        K::LoginPassword => {
            // CString copies the bytes; PAM then copies them into its own store,
            // after which we wipe our copy so the plaintext password does not
            // linger on this heap. A login password cannot contain a NUL, so
            // construction only fails on a malformed secret; treat as decline.
            match CString::new(secret.expose()) {
                Ok(tok) => {
                    let set = pamh.set_authtok(&tok);
                    zeroize::Zeroize::zeroize(&mut tok.into_bytes_with_nul());
                    if set.is_ok() {
                        Released::AuthtokSet
                    } else {
                        Released::Failed
                    }
                }
                Err(_) => Released::Failed,
            }
        }
        K::KdeWalletKey => {
            if hand_key_to_wallet_daemon(pamh, user, secret.expose()) {
                Released::WalletStarted
            } else {
                Released::Failed
            }
        }
        K::GnomeKeyringToken => {
            if pamh
                .send_bytes(GKR_TOKEN_STASH_KEY, secret.expose().to_vec(), None)
                .is_ok()
            {
                Released::TokenStashed
            } else {
                Released::Failed
            }
        }
    }
}

/// Start the KDE wallet daemon with `key`, via `irlume-kwallet-init`.
///
/// The key goes on the helper's stdin, never in argv, which is world-readable
/// through `/proc`. The helper prints the socket it created, and that path is
/// exported into the PAM environment under the name Plasma's
/// `plasma-kwallet-pam.service` reads, so Plasma delivers the session
/// environment to our daemon with no change on its side.
fn hand_key_to_wallet_daemon(pamh: &Pam, user: &str, key: &[u8]) -> bool {
    use std::io::Write;
    use std::process::{Command, Stdio};

    let helper = secure_helper_path("IRLUME_KWALLET_INIT", irlume_common::KWALLET_INIT_PATH);
    if !std::path::Path::new(&helper).is_file() {
        return false;
    }
    let mut child = match Command::new(&helper)
        .arg(user)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
    {
        Ok(c) => c,
        Err(_) => return false,
    };
    if let Some(mut sin) = child.stdin.take() {
        if sin.write_all(key).is_err() {
            kill_bounded(&mut child);
            return false;
        }
        // Dropping the handle closes the pipe; the helper reads a fixed length
        // and would otherwise sit waiting for more.
        drop(sin);
    }
    // Bounded, for the same reason as the GNOME helper above: this is the PAM
    // session phase and the login blocks on it. `wait_with_output` would wait
    // and read without a ceiling, and the read is the riskier half here, so
    // both carry the deadline (#257).
    let Some((status, stdout)) = read_stdout_bounded(&mut child, HELPER_BUDGET) else {
        return false;
    };
    if !status.success() {
        return false;
    }
    let sock = String::from_utf8_lossy(&stdout).trim().to_string();
    if sock.is_empty() {
        return false;
    }
    // This variable does two jobs, and both are load-bearing.
    //
    // Plasma's plasma-kwallet-pam.service only connects to the socket when it
    // is set, and until something connects, the wallet daemon sits in
    // waitForEnvironment() with the wallet still shut.
    //
    // It is also the interlock with pam_kwallet5. Both its pam_sm_authenticate
    // and its pam_sm_open_session begin by checking this exact variable and
    // returning early with "we were already executed" when it is present. So
    // setting it stops pam_kwallet5 launching a second wallet daemon, and stops
    // it calling prompt_for_password() because a face login left PAM_AUTHTOK
    // empty. No change to the PAM stack is needed for either.
    let entry = format!("{}={sock}", irlume_common::kwallet_wire::LOGIN_ENV);
    pamh.putenv(&entry).is_ok()
}

/// Round-trip one request to `irlumed` and return its reply. Delegates to the
/// shared client (bounded connect timeout so a stalled daemon never hangs the
/// auth prompt; wire buffers zeroized). The 25s read budget covers a full
/// camera capture + liveness + match before the TPM unseal.
fn request(req: &Request) -> std::io::Result<Response> {
    irlume_common::client::request_with_timeout(req, Duration::from_secs(25))
}

pam_module!(IrlumePam);

#[cfg(test)]
mod tests {

    /// Only a delivery that actually reached a consumer may continue the stack.
    ///
    /// The catch-all this replaced answered SUCCESS for anything that was not
    /// `Failed`, so a variant added later would silently short-circuit
    /// `auth sufficient` and leave the login with no password in PAM_AUTHTOK
    /// (#365). Exhaustiveness is the compiler's job now; this pins what each
    /// existing variant MEANS, which the compiler cannot.
    #[test]
    fn only_a_real_delivery_continues_the_stack() {
        use super::{code_for, Released};
        for delivered in [
            Released::AuthtokSet,
            Released::WalletStarted,
            Released::TokenStashed,
        ] {
            assert_eq!(
                code_for(delivered),
                pamsm::PamError::SUCCESS,
                "{delivered:?} did reach its consumer"
            );
        }
        assert_eq!(
            code_for(Released::Failed),
            pamsm::PamError::IGNORE,
            "a failed release must cascade to the password, never grant"
        );
    }
    use super::*;

    #[test]
    fn firewall_passes_normal_returns_through() {
        assert_eq!(firewall(|| PamError::SUCCESS), PamError::SUCCESS);
        assert_eq!(firewall(|| PamError::IGNORE), PamError::IGNORE);
    }

    #[test]
    fn remote_desktop_services_are_denied_local_greeters_are_not() {
        // Remote-desktop / remote-shell services stand down (face must not fire
        // for a session the camera-side person isn't driving).
        for svc in [
            "xrdp",
            "xrdp-sesman",
            "tigervnc",
            "x11vnc",
            "vncserver",
            "xpra",
            "nx",
            "nxagent",
            "sshd",
            "XRDP-SESMAN", // case-insensitive
        ] {
            assert!(is_remote_desktop_service(svc), "{svc} must be remote");
        }
        // Real local greeters / console / sudo must NOT be classified remote, or
        // face login would never engage there.
        for svc in [
            "gdm-password",
            "sddm",
            "lightdm",
            "plasmalogin",
            "cosmic-greeter",
            "greetd",
            "kde",
            "login",
            "sudo",
            "polkit-1",
        ] {
            assert!(!is_remote_desktop_service(svc), "{svc} must be local");
        }
    }

    #[test]
    fn firewall_maps_a_panic_to_ignore() {
        // A panic must become IGNORE (password fallback), never unwind toward
        // the pam_module! extern "C" shims: since Rust 1.81 that aborts the
        // calling process, i.e. kills sudo or the greeter mid-auth.
        let prev = std::panic::take_hook();
        std::panic::set_hook(Box::new(|_| {})); // keep the test log clean
        let got = firewall(|| panic!("boom"));
        std::panic::set_hook(prev);
        assert_eq!(got, PamError::IGNORE);
    }

    /// Spawn `sh -c script` with stdout piped, the way the kwallet helper is
    /// spawned.
    fn sh(script: &str) -> std::process::Child {
        std::process::Command::new("/bin/sh")
            .args(["-c", script])
            .stdin(std::process::Stdio::null())
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::null())
            .spawn()
            .expect("spawn /bin/sh")
    }

    #[test]
    fn bounded_read_returns_the_helpers_output_and_status() {
        let mut child = sh("printf '/run/user/1000/kwallet5.socket\\n'");
        let (status, out) =
            read_stdout_bounded(&mut child, Duration::from_secs(10)).expect("child exited");
        assert!(status.success());
        assert_eq!(
            String::from_utf8_lossy(&out).trim(),
            "/run/user/1000/kwallet5.socket"
        );
    }

    #[test]
    fn bounded_read_reports_a_nonzero_exit() {
        let mut child = sh("exit 3");
        let (status, _) =
            read_stdout_bounded(&mut child, Duration::from_secs(10)).expect("child exited");
        assert!(!status.success());
    }

    #[test]
    fn a_wedged_helper_is_killed_at_the_deadline() {
        // The wedge #257 describes: a child that produces nothing and never
        // exits. The old `wait_with_output` would sit here for the life of the
        // child, holding the login open.
        let started = Instant::now();
        let mut child = sh("sleep 30");
        let got = read_stdout_bounded(&mut child, Duration::from_millis(300));
        assert!(got.is_none(), "a wedged child must read as failure");
        assert!(
            started.elapsed() < Duration::from_secs(5),
            "the deadline did not bound the wait: {:?}",
            started.elapsed()
        );
        // Killed and reaped, not abandoned: a leftover child would hold the
        // stdin pipe (and the key on it) alive.
        assert!(matches!(child.try_wait(), Ok(Some(_))));
    }

    #[test]
    fn a_leaked_write_end_does_not_hold_the_login_after_exit() {
        // The helper's grandchild (the exec'd wallet daemon) inherits our pipe
        // when the helper's /dev/null redirect fails. Reading to EOF would then
        // block until the daemon dies; the bounded read must return with what
        // the helper printed once the helper itself is gone.
        let started = Instant::now();
        let mut child = sh("printf 'sockpath\\n'; sleep 30 & exit 0");
        let (status, out) =
            read_stdout_bounded(&mut child, Duration::from_secs(10)).expect("helper exited");
        assert!(status.success());
        assert_eq!(String::from_utf8_lossy(&out).trim(), "sockpath");
        assert!(
            started.elapsed() < Duration::from_secs(5),
            "waited on the leaked write end: {:?}",
            started.elapsed()
        );
    }

    #[test]
    fn a_helper_spewing_output_is_killed_at_the_cap() {
        // `yes` never exits and never stops writing, so neither the deadline
        // branch nor EOF would end this; only the output cap can.
        let started = Instant::now();
        let mut child = sh("yes x");
        let got = read_stdout_bounded(&mut child, Duration::from_secs(10));
        assert!(got.is_none(), "output past the cap must read as failure");
        assert!(started.elapsed() < Duration::from_secs(5));
        assert!(matches!(child.try_wait(), Ok(Some(_))));
    }
}

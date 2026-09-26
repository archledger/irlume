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
//!     Shared privileged services first offer one hidden field through PAM:
//!     `yes` selects one face attempt, while any other non-empty value remains
//!     the authentication token for the downstream password provider.
//!   * `unseal` (`auth sufficient pam_irlume.so unseal`): VERIFY + KEYRING
//!     UNLOCK. Sends `UnsealPassword`; on a live match the daemon releases the
//!     TPM-sealed login password, which we set as `PAM_AUTHTOK` so a downstream
//!     `pam_kwallet5` / `pam_gnome_keyring` unlocks the wallet. Use for login
//!     (SDDM/GDM) and the lock screen after a cold boot.
//!
//! Further module arguments (combinable with either mode): `wait` keeps the
//! module retrying for ~20s instead of doing a single capture. This is what the
//! KDE lock screen needs: kscreenlocker starts the non-interactive auth stack
//! the moment the screen appears, so the window is what lets the user sit back
//! down and be recognized without touching a key. A one-shot capture fires long
//! before they return and is useless there. `reseal` re-seals the keyring
//! secret under a new PAM-verified password, `keyring`/`kr` route a keyring
//! (not login) secret, `facefirst` orders face before the password provider,
//! and `ondemand` restricts the module to explicitly requested attempts (see
//! the per-argument docs in `parse_module_args` and the wiring recipes in
//! irlume-cli's `pamwire`).
//!
//! Per NIST SP 800-63B-4, face is one factor and a non-biometric fallback MUST
//! always exist: on any decline/timeout we return `PAM_IGNORE` so the stack
//! cleanly cascades to the password module (never `AUTH_ERR`, which would just
//! log a failure; the password is always the floor).

use irlume_common::pam_service::ServiceKind;
use irlume_common::{IntentAttestation, Request, Response, SecretBytes};
use pamsm::{pam_module, Pam, PamError, PamFlags, PamLibExt, PamServiceModule};
use std::ffi::{CStr, CString};
use std::time::{Duration, Instant};

/// How long `wait` keeps retrying before giving up to the password fallback.
const WAIT_BUDGET: Duration = Duration::from_secs(20);
/// Pause between attempts in `wait` mode: lets the daemon release the camera
/// (avoids back-to-back EBUSY) and keeps us from busy-looping.
const WAIT_RETRY_GAP: Duration = Duration::from_millis(400);
const FACE_INTENT_INFO: &str = "Type yes to use face authentication";
const COSMIC_FACE_PROMPT: &str = "Password or yes for face: ";

#[derive(Clone, Copy, PartialEq, Eq)]
enum IntentInput {
    Confirmed,
    Empty,
    Password,
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum IntentConfirmation {
    Confirmed,
    Fallback,
    Abort,
}

fn classify_intent_input(response: Option<&[u8]>) -> IntentInput {
    let Some(response) = response else {
        return IntentInput::Empty;
    };
    if response.is_empty() {
        return IntentInput::Empty;
    }
    if response.len() <= 16
        && response.is_ascii()
        && std::str::from_utf8(response).is_ok_and(|text| text.trim().eq_ignore_ascii_case("yes"))
    {
        return IntentInput::Confirmed;
    }
    IntentInput::Password
}

fn resolve_intent_input(
    input: IntentInput,
    clear: impl FnOnce() -> pamsm::PamResult<()>,
) -> IntentConfirmation {
    match input {
        IntentInput::Password => IntentConfirmation::Fallback,
        IntentInput::Empty => match clear() {
            Ok(()) => IntentConfirmation::Fallback,
            Err(_) => IntentConfirmation::Abort,
        },
        IntentInput::Confirmed => match clear() {
            Ok(()) => IntentConfirmation::Confirmed,
            Err(_) => IntentConfirmation::Abort,
        },
    }
}

fn confirm_face_intent_with<'a>(
    service: ServiceKind,
    show_info: impl FnOnce() -> pamsm::PamResult<()>,
    get_token: impl FnOnce() -> pamsm::PamResult<Option<&'a CStr>>,
    clear: impl FnOnce() -> pamsm::PamResult<()>,
) -> IntentConfirmation {
    if !service.requires_face_intent_confirmation() || show_info().is_err() {
        return IntentConfirmation::Fallback;
    }
    let Ok(Some(token)) = get_token() else {
        return IntentConfirmation::Fallback;
    };
    resolve_intent_input(classify_intent_input(Some(token.to_bytes())), clear)
}

fn confirm_face_intent(pamh: &Pam, service: ServiceKind) -> IntentConfirmation {
    confirm_face_intent_with(
        service,
        || pamh.info(FACE_INTENT_INFO),
        || pamh.get_authtok(None),
        || pamh.clear_authtok(),
    )
}

/// COSMIC discards empty submissions before answering PAM. Ask for a fresh,
/// nonempty choice in its hidden prompt; an earlier module's token is never
/// consent, even when that password happens to be `yes`.
fn confirm_cosmic_face(pamh: &Pam) -> IntentConfirmation {
    match pamh.get_cached_authtok() {
        Ok(Some(token)) if !token.to_bytes().is_empty() => return IntentConfirmation::Fallback,
        Ok(Some(_)) => {
            if pamh.clear_authtok().is_err() {
                return IntentConfirmation::Abort;
            }
        }
        Ok(None) => {}
        Err(_) => return IntentConfirmation::Fallback,
    }
    let Ok(Some(token)) = pamh.get_authtok(Some(COSMIC_FACE_PROMPT)) else {
        return IntentConfirmation::Fallback;
    };
    resolve_intent_input(classify_intent_input(Some(token.to_bytes())), || {
        pamh.clear_authtok()
    })
}

/// PAM-data key under which the `reseal` AUTH line stashes the typed password for
/// the `reseal` SESSION line to pick up. Namespaced to this module.
const RESEAL_STASH_KEY: &str = "pam_irlume_reseal_authtok";

/// PAM-data key for a released GNOME keyring token, carried from the auth
/// phase to `open_session`, which hands it to the unlock helper and leaves
/// the key set but empty, so a handle delivers once. A token never
/// rides `PAM_AUTHTOK`: on a Debian-style `kr` stack `pam_unix` would consume
/// it as the Unix password and fail the login it was meant to decorate.
const GKR_TOKEN_STASH_KEY: &str = "pam_irlume_gkr_token";

/// PAM-data key for a released KDE wallet key, carried from the auth phase to
/// `open_session` only on the fingerprint `keyring` path, and only when
/// `irlume-kwallet-init` reports the session is not ready yet (a cold-boot
/// first login). Delivered from the `reseal` session line irlume wires after
/// the include that runs `pam_systemd`, so `/run/user/<uid>` exists there. A
/// stack with the `keyring` auth line but no `reseal` session line (a
/// hand-written one) never picks up the stash, so its wallet stays locked
/// after a cold boot. The face `unseal` path never defers: it decides the
/// login outcome, so a stack without the `reseal` line would turn a stash
/// into a face login with a locked wallet.
const KWALLET_KEY_STASH_KEY: &str = "pam_irlume_kwallet_key";

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
        let svc = svc.to_string_lossy();
        if is_remote_desktop_service(&svc) {
            return true;
        }
        // polkit's agent helper carries no remote marker: it clears its
        // environment (or starts fresh from a socket), and polkit sets no
        // PAM_RHOST. An administrator in an SSH session who runs pkexec,
        // run0 or systemctl answers the prompt at pkttyagent, so the agent
        // that asked is what says where the requester is.
        if irlume_common::pam_service::classify(&svc) == Some(ServiceKind::AppConsent)
            && !consent_requester_is_local()
        {
            return true;
        }
    }
    // RESIDUAL (docs/THREAT_MODEL.md, "Remote sessions"): a deny-list by service name
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
///
/// The shared service table's remote rows count too (`remote` for rlogin and
/// telnet-style daemons, `cockpit` for the web console), so the module and the
/// daemon's classifier cannot disagree about a name both know. A web console
/// behind a local reverse proxy reports a loopback PAM_RHOST, so only the name
/// catches it.
fn is_remote_desktop_service(service: &str) -> bool {
    if irlume_common::pam_service::classify(service) == Some(ServiceKind::Remote) {
        return true;
    }
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

/// Where a process sits in logind's view, read from its cgroup path.
#[derive(Debug, PartialEq, Eq)]
enum CgroupOwner {
    /// A process in a login session's scope (`session-<id>.scope`), of the
    /// user whose slice holds it.
    Session { id: String, uid: u32 },
    /// A process the user's service manager started (`user@<uid>.service`),
    /// which belongs to no session. logind names the user's display session
    /// for it, as polkit itself does for such a subject.
    UserManager(u32),
}

/// The owner of a process from its `/proc/<pid>/cgroup` text: the unified
/// hierarchy's line (`0::`), else systemd's legacy one (`name=systemd`).
/// `None` for anything else, such as a system service.
fn cgroup_owner(text: &str) -> Option<CgroupOwner> {
    text.lines()
        .filter_map(|line| {
            let mut fields = line.splitn(3, ':');
            let (_, controllers, path) = (fields.next()?, fields.next()?, fields.next()?);
            (controllers.is_empty() || controllers == "name=systemd").then_some(path)
        })
        .find_map(owner_of_path)
}

/// The owner of a cgroup path, read only where logind and the system
/// manager place things: `/user.slice/user-<uid>.slice/session-<id>.scope`
/// for a session (a scope with no children), and
/// `/user.slice/user-<uid>.slice/user@<uid>.service/...` for the user's
/// service manager. A scope the user creates themselves (`systemd-run
/// --user --scope`) lives below their service manager whatever it is named,
/// so it reads as the service manager, never as a session.
fn owner_of_path(path: &str) -> Option<CgroupOwner> {
    let mut parts = path.split('/').filter(|part| !part.is_empty());
    if parts.next()? != "user.slice" {
        return None;
    }
    let uid: u32 = parts
        .next()?
        .strip_prefix("user-")?
        .strip_suffix(".slice")?
        .parse()
        .ok()?;
    let unit = parts.next()?;
    if let Some(id) = unit
        .strip_prefix("session-")
        .and_then(|u| u.strip_suffix(".scope"))
    {
        return (parts.next().is_none() && logind_id(id)).then(|| CgroupOwner::Session {
            id: id.to_string(),
            uid,
        });
    }
    let manager: u32 = unit
        .strip_prefix("user@")?
        .strip_suffix(".service")?
        .parse()
        .ok()?;
    (manager == uid).then_some(CgroupOwner::UserManager(uid))
}

/// Whether `id` can be a logind session id, which becomes a file name.
fn logind_id(id: &str) -> bool {
    !id.is_empty() && id.bytes().all(|b| b.is_ascii_alphanumeric())
}

/// The value of `key` in one of logind's `KEY=value` state files.
fn logind_value<'a>(text: &'a str, key: &str) -> Option<&'a str> {
    text.lines().find_map(|line| {
        line.strip_prefix(key)
            .and_then(|rest| rest.strip_prefix('='))
            .map(str::trim)
    })
}

/// The process that asked polkit's agent helper for this authentication: the
/// agent at the other end of its standard input when that is a socket (the
/// socket-activated helper), else its parent (the setuid helper the agent
/// spawns). `None` when neither names a process other than init.
fn requesting_agent_pid() -> Option<u32> {
    let mut cred = libc::ucred {
        pid: 0,
        uid: 0,
        gid: 0,
    };
    let mut len = std::mem::size_of::<libc::ucred>() as libc::socklen_t;
    // SAFETY: `cred` and `len` are valid for writes of the sizes passed, and
    // `getsockopt` writes at most `len` bytes. Standard input may be closed or
    // not a socket; the call then fails and nothing is read from `cred`.
    let peer = unsafe {
        libc::getsockopt(
            0,
            libc::SOL_SOCKET,
            libc::SO_PEERCRED,
            std::ptr::addr_of_mut!(cred).cast(),
            &mut len,
        )
    } == 0;
    let pid = if peer {
        u32::try_from(cred.pid).ok()?
    } else {
        std::os::unix::process::parent_id()
    };
    (pid > 1).then_some(pid)
}

/// Whether the agent behind a consent prompt is in a local login session.
/// False when the session is remote, and also when the agent, its session or
/// the session's remoteness cannot be established: the prompt then goes to
/// the password, never to the camera.
fn consent_requester_is_local() -> bool {
    let proc_dir = irlume_common::client::secure_env("IRLUME_PROC_DIR").map_or_else(
        || std::path::PathBuf::from("/proc"),
        std::path::PathBuf::from,
    );
    let logind_dir = irlume_common::client::secure_env("IRLUME_LOGIND_DIR").map_or_else(
        || std::path::PathBuf::from("/run/systemd"),
        std::path::PathBuf::from,
    );
    let Some(pid) = requesting_agent_pid() else {
        return false;
    };
    let Ok(cgroup) = std::fs::read_to_string(proc_dir.join(pid.to_string()).join("cgroup")) else {
        return false;
    };
    let (session, uid) = match cgroup_owner(&cgroup) {
        Some(CgroupOwner::Session { id, uid }) => (id, uid),
        Some(CgroupOwner::UserManager(uid)) => {
            let Ok(user) = std::fs::read_to_string(logind_dir.join("users").join(uid.to_string()))
            else {
                return false;
            };
            match logind_value(&user, "DISPLAY") {
                Some(id) if logind_id(id) => (id.to_string(), uid),
                _ => return false,
            }
        }
        None => return false,
    };
    // The session must be the agent's user's, and say it is local.
    std::fs::read_to_string(logind_dir.join("sessions").join(session)).is_ok_and(|text| {
        logind_value(&text, "UID") == Some(uid.to_string().as_str())
            && logind_value(&text, "REMOTE") == Some("0")
    })
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
                //
                // A wallet daemon that an earlier irlume line started in this
                // login (a warm face `unseal` ahead of this line) counts too.
                // In the auth phase only such a start sets
                // `PAM_KWALLET5_LOGIN`, and with the flag set the daemon
                // answers KeyringUnlockNotNeeded for a wallet key without a
                // second TPM unseal, instead of sending the key into this
                // process again. A GNOME token is still released.
                let have_password = matches!(
                    pamh.get_cached_authtok(),
                    Ok(Some(tok)) if !tok.to_bytes().is_empty()
                ) || kwallet_login_set(&pamh);
                let service = pamh
                    .get_service()
                    .ok()
                    .flatten()
                    .and_then(|c| c.to_str().ok().map(str::to_string));
                // Marked as the auth phase: irlumed releases nothing to it
                // while the account has a live local desktop, which is what
                // a lock-screen unlock of that desktop is.
                if let Ok(Response::PasswordUnsealed { secret, kind }) =
                    request(&Request::UnsealKeyring {
                        user: user.clone(),
                        service,
                        have_password,
                        auth_phase: true,
                    })
                {
                    // Routed by kind, not assumed: on KDE this starts the
                    // wallet daemon, or stashes the key for `open_session`
                    // when the session is not ready yet; a GNOME token is
                    // always stashed for the session helper; and only a login
                    // password becomes an AUTHTOK. Best-effort either way;
                    // the IGNORE below never becomes a failed login.
                    if kind == irlume_common::KeyringSecretKind::KdeWalletKey {
                        // On a cold-boot first login `/run/user/<uid>` does
                        // not exist yet: stash the key rather than lose it,
                        // so `open_session`'s `reseal` line can start the
                        // daemon once the session (and that directory)
                        // exist. Only this line defers: its result decides
                        // nothing, so a stash no session line picks up
                        // changes nothing. The `unseal` path goes through
                        // `release_secret`, which never stashes a wallet key.
                        if matches!(
                            hand_key_to_wallet_daemon(&pamh, &user, secret.expose()),
                            WalletHandoff::NotReady
                        ) {
                            let _ = pamh.send_secret(
                                KWALLET_KEY_STASH_KEY,
                                pamsm::PamSecretBytes::new(secret.expose().to_vec()),
                            );
                        }
                    } else {
                        let _ = release_secret(&pamh, &user, &secret, kind);
                    }
                }
                return PamError::IGNORE;
            }
            // `facefirst` (GNOME/GDM wiring): GDM's PAM conversation BLOCKS on the
            // active password probe until the user types (unlike plasmalogin/SDDM,
            // which answer instantly from the buffered field), so skip the probe and
            // scan right away; a typed password still wins via the modules after us.
            let facefirst = args.iter().any(|a| a == "facefirst");

            // `ondemand`: explicit input selects face, with the warm
            // unseal→verify fallback for shared login/lock services. COSMIC needs
            // a nonempty `yes` choice because its frontend drops empty input;
            // other on-demand frontends keep their empty-Enter selection.
            let ondemand = args.iter().any(|a| a == "ondemand");

            // `reseal` AUTH line (placed AFTER password-auth): STASH ONLY. We copy the
            // current PAM_AUTHTOK into PAM transaction data so the matching `reseal`
            // SESSION line can re-bind it later. We deliberately do NOT contact the
            // daemon or touch the TPM here, because this auth line runs even after a
            // FAILED password attempt; acting on the token here is exactly the bug
            // that let a typo overwrite the good seal. The mutation happens in
            // open_session, which PAM only runs once auth has SUCCEEDED. That success
            // can come from another factor after a mistyped password, so irlumed also
            // checks the token against the login hash where it can read one. Always
            // IGNORE.
            if reseal {
                stash_authtok(&pamh);
                return PamError::IGNORE;
            }

            let service = pamh
                .get_service()
                .ok()
                .flatten()
                .and_then(|value| value.to_str().ok().map(str::to_string));
            let cosmic_choice = unseal
                && ondemand
                && !wait
                && !facefirst
                && service.as_deref() == Some("cosmic-greeter");
            if cosmic_choice {
                match confirm_cosmic_face(&pamh) {
                    IntentConfirmation::Confirmed => {}
                    IntentConfirmation::Fallback => return PamError::IGNORE,
                    IntentConfirmation::Abort => return PamError::ABORT,
                }
            }

            // Except for COSMIC's consumed explicit choice above, if the user
            // has typed a password, defer to it; don't power up the
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
            //    NOT actively prompt here: a dedicated biometric transaction must
            //    leave password input to the frontend's password transaction.
            //    Cancellation depends on that frontend's worker lifecycle; a queued
            //    PAM conversation cancellation may not interrupt our synchronous
            //    daemon request (see docs/DESKTOP-AUTH.md).
            //    A privileged one-shot service offers its explicit
            //    face-intent choice only after this password-first check, then obtains
            //    the ordinary PAM token so a non-`yes` password is not asked twice.
            let typed = if cosmic_choice {
                None // The explicit face-selection token was already consumed.
            } else if unseal && !wait && !facefirst {
                match pamh.get_authtok(Some("Password: ")) {
                    Ok(Some(token)) => Some(token),
                    // Only an explicitly returned empty token chooses face.
                    // Cancellation/EOF or a missing token is not empty input:
                    // leave the stack before any daemon or credential request.
                    Ok(None) | Err(_) => return PamError::IGNORE,
                }
            } else {
                pamh.get_cached_authtok().ok().flatten()
            };
            if let Some(tok) = typed {
                if !tok.to_bytes().is_empty() {
                    return PamError::IGNORE;
                }
                // The active probe caches even an empty answer. It selected
                // face, not an empty Unix password: consume it so a timeout or
                // refusal lets the next provider ask for a fresh password.
                if unseal && !wait && !facefirst && pamh.clear_authtok().is_err() {
                    return PamError::IGNORE;
                }
            }

            let service_kind = service
                .as_deref()
                .and_then(irlume_common::pam_service::classify);
            let intent_confirmation = match service_kind {
                Some(kind) if kind.requires_face_intent_confirmation() => {
                    // A single response cannot authorize a retry loop or the
                    // structurally different credential-release request.
                    if wait || unseal {
                        return PamError::IGNORE;
                    }
                    // The machine's owner can put privileged services on the
                    // same footing as screen unlock, where the PAM wiring is
                    // itself the consent. Off by default; the daemon checks the
                    // same key before it honours the waiver.
                    if !irlume_common::config::privileged_face_consent_required() {
                        Some(IntentAttestation::PolicyWaived)
                    } else {
                        match confirm_face_intent(&pamh, kind) {
                            IntentConfirmation::Confirmed => {
                                Some(IntentAttestation::PamConversation)
                            }
                            IntentConfirmation::Fallback => return PamError::IGNORE,
                            IntentConfirmation::Abort => return PamError::ABORT,
                        }
                    }
                }
                _ => None,
            };

            // In `wait` mode, retry until a match or the budget runs out; otherwise
            // a single attempt. Every non-SUCCESS path returns PAM_IGNORE so the
            // stack cascades to the password (NIST: a fallback must exist), with ONE
            // deliberate exception handled just below: a polkit shake-decline returns
            // ABORT to close the dialog, because the user explicitly declined and no
            // fallback is wanted for THAT attempt (a timeout or no-match still
            // IGNOREs, so the password box still appears when the user did not decline).
            let deadline = Instant::now() + WAIT_BUDGET;
            loop {
                let (attempt, delivered) = if unseal {
                    match try_unseal(&pamh, &user) {
                        UnsealAttempt::Delivered(delivered) => (code_for(delivered), delivered),
                        // Shared login/lock services may need identity only when
                        // release was refused BEFORE any face attempt. A denial,
                        // transport error or failed delivery must not buy a new
                        // scan and deadline. Verify rechecks daemon policy.
                        UnsealAttempt::Unavailable if facefirst || ondemand => {
                            (try_verify(&pamh, &user, None), Released::Failed)
                        }
                        UnsealAttempt::Unavailable | UnsealAttempt::Failed => {
                            (PamError::IGNORE, Released::Failed)
                        }
                    }
                } else {
                    (
                        try_verify(&pamh, &user, intent_confirmation),
                        Released::Failed,
                    )
                };
                // A polkit decline is terminal (legacy daemons produced it from a
                // head shake; current daemons from an explicit cancel):
                // try_verify returned ABORT, so
                // abort the whole PAM stack instead of cascading to the password. The
                // attempt then fails with no password prompt, and the polkit agent
                // decides what to show (polkit-kde re-prompts and closes after its own
                // retry count; see POLKIT_VERIFY_STANZA in irlume-cli). Never retried,
                // even in `wait` mode: the user said no. Only an explicit decline on a
                // polkit dialog reaches this; every other non-SUCCESS falls to IGNORE below.
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

    /// `reseal` SESSION line: the actual self-heal, plus the two deferred
    /// deliveries auth stashed. Reached ONLY after auth + account succeeded, so
    /// the password the `reseal` AUTH line stashed is one the system accepted.
    /// Hand it to the daemon, which re-binds the TPM-sealed password to today's
    /// PCRs iff it is armed and has gone stale (PCR move or a changed
    /// password). Then deliver a stashed GNOME keyring token and a stashed KDE
    /// wallet key, both of which need this session phase to exist because
    /// `/run/user/<uid>` (the GNOME keyring control socket's directory, and the
    /// one `irlume-kwallet-init` requires) is not guaranteed to exist until
    /// logind opens the session. Best-effort and always IGNORE: a session must
    /// never fail because of this, and other modes (unseal/verify/wait) wire no
    /// session line so they fall straight through.
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
                    deliver_kde_wallet_key(&pamh, &user);
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
            // The stash itself is zeroizing on the PAM side now; the copy
            // taken in the session phase is wrapped in SecretBytes as well.
            let _ = pamh.send_secret(RESEAL_STASH_KEY, pamsm::PamSecretBytes::new(bytes.to_vec()));
        }
    }
}

/// SESSION-phase half of `reseal`: retrieve the stashed password and ask the
/// daemon to re-seal it if the envelope is armed and stale (the daemon checks
/// it against the login hash where it can read one).
/// Best-effort and silent: a login session must never fail because of this.
fn try_reseal_session(pamh: &Pam, user: &str) {
    // SAFETY: the key was registered by `stash_authtok` in this same PAM
    // transaction and is not replaced while the borrow is live; the borrow
    // ends inside the first match arm, before `SecretBytes` copies it.
    let pw = match unsafe { pamh.get_secret(RESEAL_STASH_KEY) } {
        Ok(stash) if !stash.is_empty() => SecretBytes::new(stash.expose().to_vec()),
        // No stash (e.g. a pure face login that submitted a blank field, or auth
        // took a path that never set a token); nothing to heal.
        _ => return,
    };
    let wallet_salt = match irlume_common::client::read_wallet_salt(user) {
        Ok(salt) => salt,
        Err(_) => return,
    };
    let _ = request(&Request::ResealPassword {
        user: user.to_string(),
        password: pw,
        wallet_salt,
        wallet_salt_checked: true,
    });
}

/// SESSION-phase delivery of a GNOME keyring token (#250): the keyring is
/// keyed to a random token only the TPM (or a password login's reseal) can
/// produce, so EVERY session open on a token-armed account must send it to the
/// keyring daemon's control socket; the typed password `pam_gnome_keyring`
/// stashed, when there is one, no longer opens anything.
///
/// The token normally arrives in the auth-phase stash (face or fingerprint
/// release). Without one (a typed-password login, or a topology where auth
/// ran in a different PAM transaction) ask the daemon: `have_password: true`
/// makes that free for password-armed users (no TPM touched), so the extra
/// round trip costs only token users, only on their stash-less logins.
///
/// gnome-keyring may not accept the token yet at this point: a
/// `pam_gnome_keyring --login` daemon refuses it until the session's first
/// Secret Service client initializes it, after this phase has returned. The
/// helper therefore hands the token to a detached waiter of its own and
/// returns within about a second; the waiter delivers it later and logs the
/// outcome to the journal. Each handle delivers at most once: the stash is
/// emptied first, on both paths, so a second `open_session` on this handle
/// neither asks the daemon again nor starts a second waiter. Best-effort like
/// everything else in the session phase: nothing reaches the prompt and the
/// session opens either way, but a failed hand-off to the helper writes one
/// journal warning ([`hand_token_to_keyring_daemon`]).
fn deliver_gnome_token(pamh: &Pam, user: &str) {
    // SAFETY: the key was registered by this module in the same PAM
    // transaction and is not replaced while the borrow is live; the borrow
    // ends inside the match arms, before `SecretBytes` copies it.
    let stashed = match unsafe { pamh.get_secret(GKR_TOKEN_STASH_KEY) } {
        Ok(stash) if !stash.is_empty() => Some(SecretBytes::new(stash.expose().to_vec())),
        // Emptied below by an earlier `open_session` on this handle: the
        // token was handed on already.
        Ok(_) => return,
        Err(_) => None,
    };
    // Empty the stash before anything else can fail. The replacement also
    // wipes the stashed copy.
    let _ = pamh.send_secret(GKR_TOKEN_STASH_KEY, pamsm::PamSecretBytes::new(Vec::new()));
    let token = match stashed {
        Some(token) => token,
        None => {
            let service = pamh
                .get_service()
                .ok()
                .flatten()
                .and_then(|c| c.to_str().ok().map(str::to_string));
            // `true` is accurate here, not a convenient lie. The flag drives
            // exactly one decision: whether a password-derived keyring secret is
            // already served. By the session phase it always is, either
            // because the user typed a password or because the auth phase
            // released the sealed one into `PAM_AUTHTOK`; and if neither
            // happened, nothing can open that keyring anyway. Passing `false`
            // instead would make the daemon unseal a login password on every
            // session open, which this hook then discards, spending a TPM
            // round trip (seconds on a discrete TPM) per login for nothing.
            // KDE wallet keys are password-derived too. This GNOME-only hook
            // cannot deliver one, so the daemon must skip them here as well.
            match request(&Request::UnsealKeyring {
                user: user.to_string(),
                service,
                have_password: true,
                // This session is being opened, so it is a login, not a
                // lock-screen unlock of a running desktop, although logind
                // lists it as live already.
                auth_phase: false,
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
    let _ = hand_token_to_keyring_daemon(pamh, user, &token);
}

/// SESSION-phase delivery of a KDE wallet key deferred by the auth phase: the
/// fingerprint `keyring` path stashes only when `irlume-kwallet-init` reported
/// the session was not ready yet (a cold-boot first login), because
/// `/run/user/<uid>` did not exist there. The face `unseal` path never
/// defers. A warm login starts the daemon straight from auth and leaves no
/// stash, so this is a no-op then. A stash is delivered at most once, and not
/// at all when `PAM_KWALLET5_LOGIN` already names a running daemon (see
/// [`hand_key_to_wallet_daemon`]). No daemon fallback here, unlike the GNOME
/// token: a stash-less KDE login either already has a typed password driving
/// `pam_kwallet5` normally, or auth already started the daemon, or the helper
/// failed outright, or the stash could not be written, or nothing was
/// released at all.
fn deliver_kde_wallet_key(pamh: &Pam, user: &str) {
    // SAFETY: the key was registered by this module in the same PAM
    // transaction and is not replaced while the borrow is live; the borrow
    // ends inside the match arm, before `SecretBytes` copies it.
    let key = match unsafe { pamh.get_secret(KWALLET_KEY_STASH_KEY) } {
        Ok(stash) if !stash.is_empty() => SecretBytes::new(stash.expose().to_vec()),
        _ => return,
    };
    // Overwrite the stash with an empty value, which the check above reads
    // as absent, so a second `open_session` on this handle cannot start
    // another daemon with the same key. The replacement also wipes the
    // stashed copy.
    let _ = pamh.send_secret(
        KWALLET_KEY_STASH_KEY,
        pamsm::PamSecretBytes::new(Vec::new()),
    );
    let _ = hand_key_to_wallet_daemon(pamh, user, key.expose());
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
/// already refuses to repeat). It then forks a detached waiter, which
/// delivers the token at once if gnome-keyring is already initialized and
/// otherwise waits for it, and exits at the waiter's first report or after
/// one second, whichever comes first. Only the helper process itself is
/// waited for, never the waiter.
///
/// Exit status 0 means the token was delivered or handed to the waiter,
/// which logs its own outcome under `irlume-gkr-unlock`; that returns `true`
/// and writes nothing here. Anything else writes one warning through
/// `pam_syslog` ([`log_hand_off_failure`]): the helper is missing, cannot be
/// started, closes its input early, exits non-zero (1 is a refusal or an
/// error before the hand-off, or a waiter that failed or died within its
/// first second), ends on a signal, is killed at [`HELPER_BUDGET`], or cannot
/// be waited for. The helper's own stderr goes to /dev/null, so for an error
/// before the hand-off that line is the only trace of a token that never
/// reached the keyring.
fn hand_token_to_keyring_daemon(
    pamh: &Pam,
    user: &str,
    token: &irlume_common::SecretBytes,
) -> bool {
    use std::io::Write;
    use std::os::unix::process::ExitStatusExt as _;
    use std::process::{Command, Stdio};

    let helper = secure_helper_path("IRLUME_GKR_UNLOCK", irlume_common::GKR_UNLOCK_PATH);
    if !std::path::Path::new(&helper).is_file() {
        log_hand_off_failure(pamh, HandOffFailure::Missing);
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
        Err(_) => {
            log_hand_off_failure(pamh, HandOffFailure::Spawn);
            return false;
        }
    };
    if let Some(mut sin) = child.stdin.take() {
        if sin.write_all(token.expose()).is_err() {
            kill_bounded(&mut child);
            log_hand_off_failure(pamh, HandOffFailure::Input);
            return false;
        }
        // EOF tells the helper the token is complete.
        drop(sin);
    }
    // Bounded, because this is the PAM session phase and the login blocks on
    // it. The helper normally exits within a second, but a wedged or stopped
    // child would otherwise hang the login here; a child still running past
    // the budget is killed rather than waited on. `reap_by` also gives up
    // when the status cannot be read, which the deadline check tells apart.
    let deadline = Instant::now() + HELPER_BUDGET;
    let failure = match reap_by(&mut child, deadline) {
        Some(status) if status.success() => return true,
        Some(status) => match (status.code(), status.signal()) {
            (Some(code), _) => HandOffFailure::Exit(code),
            (None, Some(signal)) => HandOffFailure::Signal(signal),
            (None, None) => HandOffFailure::Unknown,
        },
        None if Instant::now() >= deadline => HandOffFailure::TimedOut,
        None => HandOffFailure::Unknown,
    };
    log_hand_off_failure(pamh, failure);
    false
}

/// Why [`hand_token_to_keyring_daemon`] failed. It holds no secret: only the
/// step that failed and the helper's exit code or signal number, so nothing
/// logged from it can carry the token, its length or a password.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum HandOffFailure {
    /// The helper path does not name a regular file.
    Missing,
    /// The helper could not be started.
    Spawn,
    /// The helper closed its input before taking the whole token.
    Input,
    /// The helper exited with this non-zero code.
    Exit(i32),
    /// The helper was ended by this signal.
    Signal(i32),
    /// The helper was still running at [`HELPER_BUDGET`] and was killed.
    TimedOut,
    /// Waiting for the helper failed, so its exit status is unknown.
    Unknown,
}

impl HandOffFailure {
    /// The journal text: fixed wording plus at most one number.
    fn message(self) -> String {
        const HELPER: &str = "irlume-gkr-unlock";
        let what = match self {
            HandOffFailure::Missing => format!("{HELPER} not found"),
            HandOffFailure::Spawn => format!("{HELPER} could not be started"),
            HandOffFailure::Input => format!("{HELPER} closed its input early"),
            HandOffFailure::Exit(code) => format!("{HELPER} exited with code {code}"),
            HandOffFailure::Signal(signal) => format!("{HELPER} was ended by signal {signal}"),
            HandOffFailure::TimedOut => format!(
                "{HELPER} was still running after {} s and was killed",
                HELPER_BUDGET.as_secs()
            ),
            HandOffFailure::Unknown => format!("{HELPER} could not be waited for"),
        };
        format!("GNOME keyring token hand-off failed: {what}")
    }
}

/// Write `failure` to the journal as one warning.
///
/// `pam_syslog` logs under `LOG_AUTHPRIV` with the standard
/// `pam_irlume(<service>:session):` prefix and never calls `openlog`, so the
/// host process's own syslog identity and facility stay as they were. Taking
/// a [`HandOffFailure`] instead of text keeps secrets out by construction.
fn log_hand_off_failure(pamh: &Pam, failure: HandOffFailure) {
    let _ = pamh.syslog(pamsm::LogLvl::WARNING, &failure.message());
}

/// Ceiling on the keyring helpers, not their expected time. The GNOME unlock
/// helper returns within about a second: the process waited for here never
/// touches the control socket and waits at most one second for its detached
/// waiter's first report, so this covers a slow user lookup (NSS) and room
/// to start and exit; the KDE helper forks and execs the wallet daemon and normally exits
/// in milliseconds, so the same ceiling is generous there.
const HELPER_BUDGET: Duration = Duration::from_secs(15);

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

/// #616 step 3: action wording for a failed attempt's situation, mapped
/// from the daemon-reported stable vocabulary. Usability situations tell
/// the person what to DO; attack-shaped situations (`spoof`, `glint
/// below`, `below score`), `declined`, `other`, and unknown or empty
/// labels return `None` and stay SILENT at the prompt: wording that names
/// the cue that fired is a free oracle for a presentation attacker tuning
/// a spoof, and no threshold value ever reaches a prompt surface (the
/// numbers live in the journal and the diagnostic trace, root-visible).
fn situation_prompt(situation: &str) -> Option<&'static str> {
    match situation {
        "timed out" => Some("authentication timed out; use your password"),
        "unavailable" => Some("face authentication unavailable; use your password"),
        "no face" => Some("look at the camera"),
        "too far" => Some("come closer"),
        "off-center" => Some("center your face in the frame"),
        "looking away" => Some("look directly at the camera"),
        "too dark" => Some("it is too dark to see your face; add light"),
        "IR source" => {
            Some("an IR-bright source is overwhelming the camera; reposition or use your password")
        }
        _ => None,
    }
}

/// One verify attempt (sudo / polkit / in-session unlock): no password released.
/// Returns `SUCCESS` on a live match; `ABORT` on a DELIBERATE decline
/// at a polkit consent dialog (legacy head-shake daemon, or an explicit cancel),
/// so the whole stack aborts and the agent closes its
/// window; and `IGNORE` on anything else so the password fallback survives. Passes
/// the PAM service so the daemon can apply tier×operation-class gating (an RGB-only
/// convenience device honours only a screen-unlock service).
///
/// #616 step 3: a denial whose situation is usability-shaped also puts ONE
/// action-oriented line at the prompt via [`situation_prompt`] before the
/// password fallback.
fn try_verify(pamh: &Pam, user: &str, intent_confirmation: Option<IntentAttestation>) -> PamError {
    let service = pamh
        .get_service()
        .ok()
        .flatten()
        .map(|s| s.to_string_lossy().into_owned());
    let is_polkit_consent = service
        .as_deref()
        .and_then(irlume_common::pam_service::classify)
        .is_some_and(irlume_common::pam_service::ServiceKind::wants_consent_instruction);
    match request(&Request::Authenticate {
        structured_errors: false,
        user: user.to_string(),
        service,
        intent_confirmation,
    }) {
        Ok(Response::AuthResult {
            granted: true,
            live: true,
            ..
        }) => PamError::SUCCESS,
        // Honor legacy daemons' explicit cancellation as deny-only compatibility.
        Ok(Response::AuthResult {
            granted: false,
            declined_by_gesture: true,
            ..
        }) if is_polkit_consent => PamError::ABORT,
        // #616 step 3: a usability situation gets ONE best-effort action
        // line at the prompt (some agents never display module info text;
        // the XFCE lesson), numbers-free by construction. Attack-shaped
        // situations map to nothing and stay silent: wording that names the
        // cue that fired is a free oracle for a presentation attacker
        // tuning a spoof, and no threshold value ever reaches a prompt
        // surface (the numbers live in the journal and trace, root-visible).
        Ok(Response::AuthResult {
            granted: false,
            situation,
            ..
        }) => {
            if let Some(action) = situation_prompt(&situation) {
                let _ = pamh.info(&format!("irlume: {action}"));
            }
            PamError::IGNORE
        }
        _ => PamError::IGNORE,
    }
}

/// One unseal attempt: only an explicit pre-authentication refusal permits
/// identity-only fallback.
/// Unknown replies and legacy daemon errors fail closed to the password.
enum UnsealAttempt {
    Delivered(Released),
    Unavailable,
    Failed,
}

/// Release and deliver a secret by kind, preserving pre-auth refusal separately
/// from failed authentication or delivery. Never log the secret.
fn try_unseal(pamh: &Pam, user: &str) -> UnsealAttempt {
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
            UnsealAttempt::Delivered(release_secret(pamh, user, &secret, kind))
        }
        Ok(Response::UnsealUnavailable { .. }) => UnsealAttempt::Unavailable,
        _ => UnsealAttempt::Failed,
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
            // PAM copies the token into its own store; the copy made here is
            // wiped when `tok` drops. A login password cannot contain a NUL,
            // so one that does is a malformed secret; treat it as a decline.
            // Keep the conversion in `secret_cstring`: its test covers both
            // paths.
            let Some(tok) = secret_cstring(secret.expose()) else {
                return Released::Failed;
            };
            if pamh.set_authtok(&tok).is_ok() {
                Released::AuthtokSet
            } else {
                Released::Failed
            }
        }
        K::KdeWalletKey => match hand_key_to_wallet_daemon(pamh, user, secret.expose()) {
            WalletHandoff::Started => Released::WalletStarted,
            // Never stashed here: the face `unseal` path's result decides the
            // login, and a stack without a `reseal` session line (the NixOS
            // module) would turn a stash into a face login with a locked
            // wallet. A session that is not ready yet falls to the password
            // like any other failure. Only the fingerprint `keyring` line,
            // whose result decides nothing, defers the key to `open_session`.
            WalletHandoff::NotReady | WalletHandoff::Failed => Released::Failed,
        },
        K::GnomeKeyringToken => {
            if pamh
                .send_secret(
                    GKR_TOKEN_STASH_KEY,
                    pamsm::PamSecretBytes::new(secret.expose().to_vec()),
                )
                .is_ok()
            {
                Released::TokenStashed
            } else {
                Released::Failed
            }
        }
    }
}

/// A released secret as the C string `set_authtok` takes, wiped when dropped.
///
/// `CString::new` copies the secret into one new buffer, which the result
/// owns and zeroizes on drop. A secret with an interior NUL cannot be a C
/// string: `CString::new` then returns that copy inside its `NulError`, so it
/// is taken back with `into_vec` straight into `Zeroizing`, which wipes it
/// when it drops here (also on unwind), and the result is `None`.
fn secret_cstring(secret: &[u8]) -> Option<zeroize::Zeroizing<CString>> {
    match CString::new(secret) {
        Ok(tok) => Some(zeroize::Zeroizing::new(tok)),
        Err(rejected) => {
            drop(zeroize::Zeroizing::new(rejected.into_vec()));
            None
        }
    }
}

/// The outcome of one `irlume-kwallet-init` attempt.
enum WalletHandoff {
    /// The daemon is running; `PAM_KWALLET5_LOGIN` names its socket.
    Started,
    /// `/run/user/<uid>` did not exist yet ([`SESSION_NOT_READY_EXIT`]). Only
    /// meaningful from the auth phase; retrying later (`open_session`) may
    /// succeed once the session exists.
    ///
    /// [`SESSION_NOT_READY_EXIT`]: irlume_common::kwallet_wire::SESSION_NOT_READY_EXIT
    NotReady,
    /// Anything else: missing helper, spawn failure, a non-zero exit that is
    /// not the not-ready status, or a malformed reply. Also a daemon already
    /// named in `PAM_KWALLET5_LOGIN`, which this attempt leaves alone.
    Failed,
}

/// Whether `PAM_KWALLET5_LOGIN` in the PAM environment already names a wallet
/// daemon for this login: the variable `pam_kwallet5` checks before it starts
/// one, and the one [`hand_key_to_wallet_daemon`] exports. `pam_kwallet5`
/// also falls back to the process environment, which a greeter does not
/// carry, so only the PAM environment is read here.
fn kwallet_login_set(pamh: &Pam) -> bool {
    matches!(
        pamh.getenv(irlume_common::kwallet_wire::LOGIN_ENV),
        Ok(Some(sock)) if !sock.to_bytes().is_empty()
    )
}

/// Attempt to start the KDE wallet daemon with `key`, via `irlume-kwallet-init`.
///
/// The key goes on the helper's stdin, never in argv, which is world-readable
/// through `/proc`. On success the helper prints the socket it created, and
/// that path is exported into the PAM environment under the name Plasma's
/// `plasma-kwallet-pam.service` reads, so Plasma delivers the session
/// environment to our daemon with no change on its side. When that variable
/// is already set in the PAM environment, this stands down, as `pam_kwallet5`
/// does on the same variable (see [`kwallet_login_set`]).
fn hand_key_to_wallet_daemon(pamh: &Pam, user: &str, key: &[u8]) -> WalletHandoff {
    use std::io::Write;
    use std::process::{Command, Stdio};

    // pam_kwallet5's own interlock, honoured here too. A set variable means a
    // wallet daemon already runs for this login: pam_kwallet5's session hook
    // started it, which runs before irlume's `reseal` session line on the
    // Arch include layout, or an earlier irlume line did. For the latter the
    // `keyring` line already tells irlumed a wallet runs, so a warm face
    // `unseal` ahead of it normally gets no second key; this check is the
    // defence in depth for an irlumed that releases one anyway (one older
    // than `have_password`, or a concurrent re-arm). A second helper would
    // unlink that daemon's socket and leave it orphaned with the key in
    // memory. Nothing is delivered, so on the face `unseal` path this is a
    // failure like any other.
    if kwallet_login_set(pamh) {
        return WalletHandoff::Failed;
    }
    let helper = secure_helper_path("IRLUME_KWALLET_INIT", irlume_common::KWALLET_INIT_PATH);
    if !std::path::Path::new(&helper).is_file() {
        return WalletHandoff::Failed;
    }
    let mut child = match Command::new(&helper)
        .arg(user)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
    {
        Ok(c) => c,
        Err(_) => return WalletHandoff::Failed,
    };
    if let Some(mut sin) = child.stdin.take() {
        if sin.write_all(key).is_err() {
            kill_bounded(&mut child);
            return WalletHandoff::Failed;
        }
        // Dropping the handle closes the pipe; the helper reads a fixed length
        // and would otherwise sit waiting for more.
        drop(sin);
    }
    // Bounded, for the same reason as the GNOME helper above: this call can
    // run in the PAM auth phase, and the login blocks on it either way.
    // `wait_with_output` would wait and read without a ceiling, and the read
    // is the riskier half here, so both carry the deadline (#257).
    let Some((status, stdout)) = read_stdout_bounded(&mut child, HELPER_BUDGET) else {
        return WalletHandoff::Failed;
    };
    if !status.success() {
        if status.code() == Some(irlume_common::kwallet_wire::SESSION_NOT_READY_EXIT) {
            return WalletHandoff::NotReady;
        }
        return WalletHandoff::Failed;
    }
    let sock = String::from_utf8_lossy(&stdout).trim().to_string();
    if sock.is_empty() {
        return WalletHandoff::Failed;
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
    // setting it here stops pam_kwallet5's own hooks that run after this one
    // in the stack from launching a second wallet daemon or prompting for a
    // password a face or fingerprint login never had. On the deferred path
    // pam_kwallet5's auth hook has already run without this variable, and
    // what its session hook does depends on the stack order. Where irlume's
    // `reseal` session line comes first (the Fedora and Debian layouts), it
    // finds this variable and logs "we were already executed". Where
    // irlume's line runs after it (the Arch include layout, or an openSUSE
    // stack with pam_kwallet5 added to common-session, whose substack runs
    // before irlume's line; the stock openSUSE stack has no pam_kwallet5
    // line), it has already run: with no password from its own prompt it logs
    // "open_session called without kwallet5_key" and does nothing (observed
    // on plasma-login-manager 6.7.4 / kwallet-pam 6.7.5); with one, it started
    // its own daemon and set this variable, and the check at the top of this
    // function stood down.
    let entry = format!("{}={sock}", irlume_common::kwallet_wire::LOGIN_ENV);
    if pamh.putenv(&entry).is_ok() {
        WalletHandoff::Started
    } else {
        WalletHandoff::Failed
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

#[cfg(test)]
mod tests {

    /// The cgroup path names the session, or the user manager, of the agent
    /// behind a consent prompt; anything else (a system service, a malformed
    /// session id that would become a path) names no owner.
    #[test]
    fn cgroup_paths_name_the_session_or_the_user_manager() {
        use super::{cgroup_owner, CgroupOwner};
        assert_eq!(
            cgroup_owner("0::/user.slice/user-1000.slice/session-3.scope\n"),
            Some(CgroupOwner::Session {
                id: "3".into(),
                uid: 1000
            })
        );
        // A scope the user names like a session, below their own service
        // manager, is the service manager's.
        assert_eq!(
            cgroup_owner(
                "0::/user.slice/user-1000.slice/user@1000.service/app.slice/session-3.scope\n"
            ),
            Some(CgroupOwner::UserManager(1000))
        );
        assert_eq!(
            cgroup_owner(
                "0::/user.slice/user-1000.slice/user@1000.service/session.slice/org.gnome.Shell@wayland.service\n"
            ),
            Some(CgroupOwner::UserManager(1000))
        );
        // cgroup v1 (legacy or hybrid): systemd's named hierarchy.
        assert_eq!(
            cgroup_owner(
                "12:pids:/user.slice\n1:name=systemd:/user.slice/user-1000.slice/session-c2.scope\n"
            ),
            Some(CgroupOwner::Session {
                id: "c2".into(),
                uid: 1000
            })
        );
        for text in [
            "0::/system.slice/polkit-agent-helper@1.service\n",
            "0::/init.scope\n",
            "0::/user.slice/user-1000.slice/session-..%2f.scope\n",
            "12:pids:/user.slice/user-1000.slice/session-3.scope\n",
            // Not where logind puts a session, nor a matching service manager.
            "0::/system.slice/x.service/session-3.scope\n",
            "0::/user.slice/user-1000.slice/session-3.scope/sub\n",
            "0::/user.slice/user-1000.slice/user@1001.service/app.slice\n",
            "0::/session-3.scope\n",
            "",
        ] {
            assert_eq!(cgroup_owner(text), None, "{text:?}");
        }
    }

    #[test]
    fn logind_state_files_are_read_by_exact_key() {
        use super::logind_value;
        let session = "UID=1000\nREMOTE_HOST=example\nREMOTE=1\nTYPE=tty\n";
        assert_eq!(logind_value(session, "REMOTE"), Some("1"));
        assert_eq!(logind_value("NAME=a\nDISPLAY=2\n", "DISPLAY"), Some("2"));
        assert_eq!(logind_value("REMOTE_HOST=h\n", "REMOTE"), None);
    }

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

    /// Compile-only contract: the maintained pamsm fork must expose token
    /// clearing, response-free informational text, and zeroizing secret
    /// module-data storage without leaking the opaque raw PAM handle into
    /// this module. The function is coerced to a fn pointer and never runs;
    /// runtime behavior of these APIs is pinned by the pam_wrapper
    /// integration cases (see tests/pamwrap.rs).
    #[test]
    fn pamsm_exposes_safe_auth_token_clearing_and_zeroizing_secrets() {
        fn require_api(pam: &Pam) -> pamsm::PamResult<()> {
            pam.clear_authtok()?;
            pam.info("pamsm test info")?;
            pam.send_secret("pamsm.test.secret", pamsm::PamSecretBytes::new(Vec::new()))?;
            // SAFETY: compile-only; the key was registered above and the
            // borrow does not outlive the expression.
            let _secret = unsafe { pam.get_secret("pamsm.test.secret") }?;
            Ok(())
        }
        let _: fn(&Pam) -> pamsm::PamResult<()> = require_api;
    }

    /// The copy `secret_cstring` makes of a released password is zeroized
    /// before its memory is freed, on both paths: the C string handed to
    /// `set_authtok`, and the copy `CString::new` keeps inside the
    /// `NulError` it returns for a secret with an interior NUL.
    #[test]
    fn secret_cstring_wipes_its_copy_on_both_paths() {
        // Not at offset 0: dropping a `CString` clears its first byte, which
        // would hide a copy that was otherwise freed as is.
        const MARKER: &[u8] = b"irlume-wipe-check-5c1e";
        const SECRET: &[u8] = b"pw-irlume-wipe-check-5c1e";
        const WITH_NUL: &[u8] = b"pw-irlume-wipe-check-5c1e\0tail";

        // The check itself sees an unwiped copy freed as is.
        let unwiped = freed_blocks::count_unwiped(MARKER, || {
            drop(std::hint::black_box(SECRET.to_vec()));
        });
        assert_eq!(unwiped, 1, "the freed-block check is not installed");

        let unwiped = freed_blocks::count_unwiped(MARKER, || {
            let tok = secret_cstring(SECRET).expect("no interior NUL");
            assert_eq!(tok.as_bytes(), SECRET);
        });
        assert_eq!(unwiped, 0, "the C string was freed without a wipe");

        let unwiped = freed_blocks::count_unwiped(MARKER, || {
            assert!(secret_cstring(WITH_NUL).is_none());
        });
        assert_eq!(unwiped, 0, "the rejected copy was freed without a wipe");
    }

    #[test]
    fn firewall_passes_normal_returns_through() {
        assert_eq!(firewall(|| PamError::SUCCESS), PamError::SUCCESS);
        assert_eq!(firewall(|| PamError::IGNORE), PamError::IGNORE);
    }

    /// Only the existing bounded ASCII `yes` spellings are face intent. Empty
    /// input and password-shaped bytes take separate, camera-free branches.
    #[test]
    fn intent_input_separates_confirmation_empty_and_password() {
        for accepted in [
            b"yes".as_slice(),
            b" YES ",
            b"\tyEs\r\n",
            b"      yes       ",
        ] {
            assert!(matches!(
                classify_intent_input(Some(accepted)),
                IntentInput::Confirmed
            ));
        }
        assert!(matches!(classify_intent_input(None), IntentInput::Empty));
        assert!(matches!(
            classify_intent_input(Some(b"")),
            IntentInput::Empty
        ));
        for password in [
            b"no".as_slice(),
            b"long-local-credential-value",
            &[0xff, 0xfe],
            b"yes\0",
            b"yes             x",
            b"                 ",
        ] {
            assert!(matches!(
                classify_intent_input(Some(password)),
                IntentInput::Password
            ));
        }
    }

    #[test]
    fn empty_and_yes_require_successful_token_clearing() {
        for input in [IntentInput::Empty, IntentInput::Confirmed] {
            assert!(matches!(
                resolve_intent_input(input, || Err(PamError::SYSTEM_ERR)),
                IntentConfirmation::Abort
            ));
        }
        assert!(matches!(
            resolve_intent_input(IntentInput::Password, || panic!(
                "must not clear password input"
            )),
            IntentConfirmation::Fallback
        ));
    }

    #[test]
    fn conversation_errors_never_confirm_or_clear() {
        let token = CString::new("yes").unwrap();
        let kind = ServiceKind::Elevation;
        assert!(matches!(
            confirm_face_intent_with(
                kind,
                || Err(PamError::CONV_ERR),
                || Ok(Some(token.as_c_str())),
                || panic!("must not clear after info error"),
            ),
            IntentConfirmation::Fallback
        ));
        assert!(matches!(
            confirm_face_intent_with(
                kind,
                || Ok(()),
                || Err(PamError::CONV_ERR),
                || panic!("must not clear after token error"),
            ),
            IntentConfirmation::Fallback
        ));
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
            // The shared table's remote rows.
            "remote",
            "cockpit",
            " Cockpit ",
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

    /// #616 step 3: usability situations get one action-oriented line at the
    /// prompt; attack-shaped situations stay SILENT (wording that names the
    /// cue that fired is a free oracle for a presentation attacker tuning a
    /// spoof). Hand-written expectations: the table IS the contract.
    #[test]
    fn usability_situations_get_action_wording_attack_signals_stay_silent() {
        use super::situation_prompt;
        assert_eq!(situation_prompt("no face"), Some("look at the camera"));
        assert_eq!(
            situation_prompt("timed out"),
            Some("authentication timed out; use your password")
        );
        assert_eq!(situation_prompt("too far"), Some("come closer"));
        assert_eq!(
            situation_prompt("off-center"),
            Some("center your face in the frame")
        );
        assert_eq!(
            situation_prompt("looking away"),
            Some("look directly at the camera")
        );
        assert_eq!(
            situation_prompt("too dark"),
            Some("it is too dark to see your face; add light")
        );
        for silent in [
            "spoof",
            "glint below",
            "below score",
            "declined",
            "other",
            "",
            "too farfetched",
        ] {
            assert_eq!(
                situation_prompt(silent),
                None,
                "{silent:?} must stay silent at the prompt"
            );
        }
    }

    #[test]
    #[allow(non_snake_case)]
    fn IR_source_situation_gets_action_wording() {
        use super::situation_prompt;
        assert_eq!(
            situation_prompt("IR source"),
            Some("an IR-bright source is overwhelming the camera; reposition or use your password")
        );
    }

    /// The #616 step 3 split: rich numbers live in the journal and the
    /// diagnostic trace, NEVER at a prompt surface. No mapped wording may
    /// carry a digit, so no threshold value can leak through a label.
    #[test]
    fn runtime_unavailable_prompts_password_fallback() {
        assert_eq!(
            super::situation_prompt("unavailable"),
            Some("face authentication unavailable; use your password")
        );
    }

    #[test]
    fn no_situation_prompt_wording_ever_carries_a_number() {
        use super::situation_prompt;
        for label in [
            "timed out",
            "unavailable",
            "no face",
            "too far",
            "off-center",
            "looking away",
            "too dark",
            "IR source",
        ] {
            if let Some(text) = situation_prompt(label) {
                assert!(
                    !text.bytes().any(|b| b.is_ascii_digit()),
                    "prompt wording must carry no numbers: {text}"
                );
            }
        }
    }

    /// #616 step 3 wiring: `try_verify` turns the daemon's situation label
    /// into ONE best-effort info line before cascading to the password.
    /// Pinned against the source the way the auth crate pins its seams: no
    /// camera-less test can drive a full reply through the PAM stack.
    #[test]
    fn try_verify_prompts_one_action_line_from_the_reply_situation() {
        let src = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("src/lib.rs");
        let text = std::fs::read_to_string(&src).expect("read irlume-pam/src/lib.rs");
        let fn_start = text.find("fn try_verify(").expect("try_verify exists");
        let fn_end = text[fn_start..]
            .find("\n/// One unseal attempt")
            .map(|offset| fn_start + offset)
            .expect("the unseal helper follows try_verify");
        let body = &text[fn_start..fn_end];
        // Assembled from pieces so this test's own source cannot satisfy the
        // needle it searches for (the auth crate's tripwire idiom).
        let info_call = ["pamh.info(&format!(\"irlume: {", "action}\"))"].concat();
        let arm = body
            .find("situation,")
            .expect("try_verify binds the reply's situation");
        let consult = body[arm..]
            .find("situation_prompt(&situation)")
            .expect("the situation is mapped through the prompt table");
        let emit = body[arm..]
            .find(&info_call)
            .expect("the action line is emitted once, best-effort");
        assert!(
            consult < emit,
            "the mapping is consulted before the emission"
        );
        // And the mapping is best-effort: an info failure never changes the
        // return code (the emission's result is discarded).
        assert!(
            body[arm..].contains("let _ = "),
            "the info emission must be best-effort"
        );
    }

    /// The journal lines for a failed GNOME keyring token hand-off are fixed
    /// text plus at most one number (an exit code, a signal or the budget),
    /// never anything derived from the token. Hand-written expectations: the
    /// table is the contract.
    #[test]
    fn keyring_hand_off_failures_log_fixed_text_and_at_most_one_number() {
        use super::HandOffFailure;
        let prefix = "GNOME keyring token hand-off failed: irlume-gkr-unlock ";
        for (failure, rest) in [
            (HandOffFailure::Missing, "not found"),
            (HandOffFailure::Spawn, "could not be started"),
            (HandOffFailure::Input, "closed its input early"),
            (HandOffFailure::Exit(1), "exited with code 1"),
            (HandOffFailure::Exit(-3), "exited with code -3"),
            (HandOffFailure::Signal(9), "was ended by signal 9"),
            (
                HandOffFailure::TimedOut,
                "was still running after 15 s and was killed",
            ),
            (HandOffFailure::Unknown, "could not be waited for"),
        ] {
            assert_eq!(failure.message(), format!("{prefix}{rest}"), "{failure:?}");
        }
    }

    /// The allocator of this test binary, which can find a secret in freed
    /// memory.
    ///
    /// It zero-fills every block it hands out. While [`count_unwiped`] runs
    /// on a thread, each block that thread frees is read as bytes and
    /// searched for a marker first; other threads and other times forward to
    /// `System` unchanged. Use `count_unwiped` only around code that frees
    /// byte buffers (`Vec<u8>`, `CString`): a typed write can leave padding
    /// bytes uninitialized, and those must not be read as `u8`.
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

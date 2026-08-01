// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright the irlume contributors.

//! Stack rewrites: given the text of a PAM file, return the text irlume wants
//! it to have.
//!
//! Every function here is `&str -> (String, bool)` with no I/O, which is what
//! lets the upstream greeter files be checked in as fixtures and compared
//! byte-for-byte. Deciding WHICH files to rewrite, and writing them safely,
//! belongs to the parent module.

use super::grammar::*;
use super::stanzas::*;

/// What a wired greeter stack does with the password irlume releases.
///
/// irlume's job ends at setting `PAM_AUTHTOK`. Turning that token into an OPEN
/// wallet is another module's work, and if that module is absent (or sits above
/// our line, where it runs before the token exists) the login succeeds by face
/// and the wallet stays locked — which surfaces to the user as KWallet
/// prompting for its password anyway. Nothing checked for this, so the failure
/// was indistinguishable from "wired ✓".
pub(super) struct KeyringHandoff {
    /// A module carrying BOTH halves: an `auth` line below ours (so it observes
    /// the token) and a `session` line of its own. That is a hand-off that
    /// actually opens a wallet.
    ///
    /// The two halves are paired PER MODULE rather than counted separately,
    /// because upstream stacks list several consumers side by side: Fedora's
    /// `plasmalogin` ships `pam_gnome_keyring.so`, `pam_kwallet5.so` AND
    /// `pam_kwallet.so`. Counting "some auth line" and "some session line"
    /// independently would call a stack complete when one module read the token
    /// and a different one started a daemon that never received it.
    pub(super) complete: Option<&'static str>,
    /// Modules with an auth line below ours but no session line of their own.
    /// `pam_kwallet.c` stashes the key with `pam_set_data` in
    /// `pam_sm_authenticate` and only `pam_sm_open_session` acts on it, so this
    /// half alone derives a key and then drops it.
    pub(super) auth_only: Vec<&'static str>,
}

/// Locate the keyring hand-off in a wired stack. `None` when this stack
/// releases no credential at all (no `unseal` line), which is how the plain
/// verify surfaces — sudo and polkit — opt out of being judged against a wallet
/// they were never meant to open. The lock screen opts out a level up instead:
/// `report_keyring_handoff` walks only `GREETERS`, because a warm screen unlock
/// runs against a wallet the login already opened.
pub(super) fn keyring_handoff(content: &str) -> Option<KeyringHandoff> {
    let lines: Vec<&str> = content.lines().collect();
    let unseal_at = lines.iter().position(|l| {
        let t = l.trim_start();
        !t.starts_with('#') && t.contains(MODULE) && t.contains("unseal")
    })?;
    let consumer_in = |l: &str| -> Option<&'static str> {
        let t = l.trim_start();
        if t.starts_with('#') {
            return None;
        }
        KEYRING_CONSUMERS.iter().copied().find(|m| t.contains(m))
    };
    // A given module's session line may sit anywhere in the session phase, so
    // that half is searched across the whole file; only the AUTH half is
    // order-sensitive.
    let has_session_line = |module: &str| {
        lines.iter().any(|l| {
            let t = l.trim_start();
            if t.starts_with('#') {
                return false;
            }
            let phase = t.strip_prefix('-').unwrap_or(t);
            phase.split_whitespace().next() == Some("session") && t.contains(module)
        })
    };
    // Only lines BELOW ours can see the token we set, so the search starts past
    // the unseal line rather than scanning the whole file.
    let mut complete = None;
    let mut auth_only: Vec<&'static str> = Vec::new();
    for module in lines
        .iter()
        .skip(unseal_at + 1)
        .filter(|l| is_auth_directive(l))
        .filter_map(|l| consumer_in(l))
    {
        if has_session_line(module) {
            complete = complete.or(Some(module));
        } else if !auth_only.contains(&module) {
            auth_only.push(module);
        }
    }
    Some(KeyringHandoff {
        complete,
        auth_only,
    })
}

/// Insert irlume's greeter block: `unseal` before the password substack, a
/// `pam_permit` landing + `reseal` after it, and a `session reseal` after the
/// session substack. Idempotent; falls back to the first `auth` line if there's
/// no password substack.
/// Wire a display-manager greeter. `face` adds the face-first login lines
/// (Secure-tier credential release); `keyring` adds the post-auth keyring-unseal
/// line (fingerprint keyring unlock; needed in gdm-password too, since GDM's
/// SESSION keyring unlock runs through gdm-password even on a fingerprint login).
/// Reseal (self-heal of the sealed password) rides along whenever either is set.
pub(super) fn wire_greeter_impl(
    content: &str,
    face: bool,
    keyring: bool,
    ondemand: bool,
) -> (String, bool) {
    if !face && !keyring {
        return (content.to_string(), false);
    }
    if content_has_module(content) {
        return (content.to_string(), false);
    }
    let lines: Vec<&str> = content.lines().collect();
    // Debian/Ubuntu layout: face-first `sufficient` before the password path;
    // keyring-unseal after it (runs on any auth success, incl. a fingerprint via
    // common-auth's pam_fprintd). Most greeters `@include common-auth` directly;
    // greetd instead `@include login` (which itself pulls in common-auth) and adds
    // its own keyring modules after; inserting the face line before that include
    // works identically (face IGNORE on cold login → the include's pam_unix +
    // greetd's pam_gnome_keyring run with the unsealed AUTHTOK → keyring unlocks).
    if let Some(inc_at) = lines.iter().position(|l| is_include_auth_layout(l)) {
        let mut out = Vec::with_capacity(lines.len() + 4);
        for (i, l) in lines.iter().enumerate() {
            if i == inc_at {
                if face {
                    out.push(include_greeter_line(
                        if ondemand { "ondemand" } else { "facefirst" },
                        true,
                    ));
                }
                out.push((*l).to_string());
                if keyring {
                    out.push(KEYRING_UNSEAL.to_string());
                }
                out.push(RESEAL_AUTH.to_string());
            } else if l.trim_start().starts_with("@include common-session") {
                out.push((*l).to_string());
                out.push(RESEAL_SESSION.to_string());
            } else {
                out.push((*l).to_string());
            }
        }
        if !out.iter().any(|l| l == RESEAL_SESSION) {
            out.push(RESEAL_SESSION.to_string());
        }
        return (format!("{}\n", out.join("\n")), true);
    }
    let auth_at = find_auth_anchor(&lines);
    let sess_at = lines.iter().position(|l| is_passwd_substack(l, "session"));
    let Some(auth_at) = auth_at else {
        return (content.to_string(), false);
    };
    let mut out = Vec::with_capacity(lines.len() + 5);
    for (i, l) in lines.iter().enumerate() {
        if i == auth_at {
            if face {
                out.push(
                    if ondemand {
                        GREETER_UNSEAL_COSMIC_JUMP
                    } else {
                        GREETER_UNSEAL_FACEFIRST_JUMP
                    }
                    .to_string(),
                );
                out.push((*l).to_string());
                out.push(PERMIT_LANDING.to_string());
            } else {
                out.push((*l).to_string());
            }
            if keyring {
                out.push(KEYRING_UNSEAL.to_string());
            }
            out.push(RESEAL_AUTH.to_string());
        } else if Some(i) == sess_at {
            out.push((*l).to_string());
            out.push(RESEAL_SESSION.to_string());
        } else {
            out.push((*l).to_string());
        }
    }
    if sess_at.is_none() {
        out.push(RESEAL_SESSION.to_string()); // harmless optional session line
    }
    (format!("{}\n", out.join("\n")), true)
}

/// Wire the KDE lock (`kde`) with the consent-driven on-demand face block: face
/// engages only on an empty-field Enter, verifies identity for the unlock, and
/// otherwise falls through to the password. Same `ondemand` mode as
/// cosmic-greeter, applied to KDE's submit-driven lock service. No reseal (a
/// screen unlock releases no credential). Handles both the Debian `@include`
/// and the Fedora `substack` layouts.
pub(super) fn wire_lock(content: &str) -> (String, bool) {
    if content_has_module(content) {
        return (content.to_string(), false);
    }
    let lines: Vec<&str> = content.lines().collect();
    // Include layout (Debian `@include common-auth`, Arch `auth include
    // system-local-login`) → face-first `sufficient` before it. A warm lock so
    // no keyring-continue arg; on face success the module returns SUCCESS and
    // `sufficient` grants the unlock.
    if let Some(inc_at) = lines.iter().position(|l| is_include_auth_layout(l)) {
        let mut out = Vec::with_capacity(lines.len() + 1);
        for (i, l) in lines.iter().enumerate() {
            if i == inc_at {
                out.push(include_greeter_line("ondemand", false));
            }
            out.push((*l).to_string());
        }
        return (format!("{}\n", out.join("\n")), true);
    }
    // Fedora `substack password-auth` layout → jump stanza + permit landing.
    let auth_at = find_auth_anchor(&lines);
    let Some(auth_at) = auth_at else {
        return (content.to_string(), false);
    };
    let mut out = Vec::with_capacity(lines.len() + 2);
    for (i, l) in lines.iter().enumerate() {
        if i == auth_at {
            out.push(GREETER_UNSEAL_COSMIC_JUMP.to_string());
            out.push((*l).to_string());
            out.push(PERMIT_LANDING.to_string());
        } else {
            out.push((*l).to_string());
        }
    }
    (format!("{}\n", out.join("\n")), true)
}

/// Wire the `keyring` unseal line into a fingerprint login service
/// (`gdm-fingerprint`): insert it right after the `pam_fprintd.so` auth line so
/// the sealed password is set before pam_gnome_keyring's auth line runs.
pub(super) fn wire_fp_keyring(content: &str) -> (String, bool) {
    if content.lines().any(|l| {
        let t = l.trim_start();
        !t.starts_with('#') && t.contains("pam_irlume.so") && t.contains("keyring")
    }) {
        return (content.to_string(), false); // already wired
    }
    let lines: Vec<&str> = content.lines().collect();
    let Some(fp_at) = lines.iter().position(|l| is_fingerprint_auth(l)) else {
        return (content.to_string(), false);
    };
    // Does anything in this stack already read the token we are about to set?
    // GDM's own `gdm-fingerprint` does not, so the unseal line alone would
    // release a password into a stack with no consumer.
    let has_consumer = lines.iter().any(|l| {
        let t = l.trim_start();
        !t.starts_with('#') && KEYRING_CONSUMERS.iter().any(|m| t.contains(m))
    });
    let mut out = Vec::with_capacity(lines.len() + 3);
    for (i, l) in lines.iter().enumerate() {
        out.push((*l).to_string());
        if i == fp_at {
            out.push(KEYRING_UNSEAL.to_string());
            if !has_consumer {
                out.push(FP_GKR_AUTH.to_string());
            }
        }
    }
    if !has_consumer {
        // Appended last: gnome-keyring's session half wants to run once the
        // session is otherwise set up, and it is the half that actually starts
        // the daemon and unlocks with the stashed key.
        out.push(FP_GKR_SESSION.to_string());
    }
    (format!("{}\n", out.join("\n")), true)
}

/// Wire a single-stanza verify service (`sudo`, `polkit-1`): the stanza goes
/// ABOVE the first auth-phase line, whether that is Fedora's `auth include
/// system-auth` or Debian/Ubuntu's `@include common-auth`. An anchor that only
/// matched a literal `auth` token missed the include layout entirely and the
/// stanza got appended at EOF, i.e. AFTER the password modules, where it is dead:
/// a wrong password already hit common-auth's pam_deny, a right one already
/// granted via pam_unix. No anchor at all → no wiring: appending to a file with
/// no auth phase would leave pam_irlume as the only auth module, and its IGNORE
/// on a failed face would then fail the whole prompt instead of falling back to
/// the password.
pub(super) fn wire_verify_service(content: &str) -> (String, bool) {
    if content_has_module(content) {
        return (content.to_string(), false);
    }
    let lines: Vec<&str> = content.lines().collect();
    let anchor = lines
        .iter()
        .position(|l| is_include_auth_layout(l) || is_auth_directive(l));
    let Some(anchor) = anchor else {
        return (content.to_string(), false);
    };
    let mut out = Vec::with_capacity(lines.len() + 1);
    for (i, l) in lines.iter().enumerate() {
        if i == anchor {
            out.push(VERIFY_STANZA.to_string());
        }
        out.push((*l).to_string());
    }
    (format!("{}\n", out.join("\n")), true)
}

/// Remove every irlume line AND the pam_permit landing we added (used only when
/// no backup exists; the backup-restore path is preferred).
pub(super) fn unwire_lines(content: &str) -> (String, bool) {
    // Strip every pam_irlume line, plus ONLY the pam_permit landing WE tagged
    // (`# irlume-landing`), never a foreign pam_permit.so.
    let mut changed = false;
    let kept: Vec<&str> = content
        .lines()
        .filter(|l| {
            let t = l.trim_start();
            if t.starts_with('#') {
                return true;
            }
            let drop = t.contains(MODULE)
                || (t.contains("pam_permit.so") && l.contains("# irlume-landing"))
                // Only the gnome-keyring lines WE tagged; a distro-shipped
                // keyring line carries no tag and must survive unwiring.
                || (t.contains("pam_gnome_keyring.so") && l.contains(KEYRING_TAG));
            if drop {
                changed = true;
            }
            !drop
        })
        .collect();
    (format!("{}\n", kept.join("\n")), changed)
}

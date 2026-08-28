// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright the irlume contributors.

//! What irlume tells the user about a machine's wiring: the `login status`
//! report, the per-surface facts the machine API serialises, and the warning
//! that a released password has nothing downstream to unlock a wallet with.
//!
//! Read-only. Nothing here writes a PAM file, which is why it is safe for the
//! human report and `login status --json` to derive from one pass over the same
//! facts and merely word them differently.

use super::*;

/// Short label from an /etc/pam.d path (e.g. "/etc/pam.d/gdm-password" → "gdm-password").
pub(super) fn label_of(etc: &str) -> String {
    service_name(etc).to_string()
}

/// One PAM surface irlume knows how to wire, as facts rather than a rendered
/// row. The human report prints these and `login status --json` serializes
/// them, so a single pass feeds both and the two cannot disagree about what is
/// wired; they can only differ in how they word it.
pub(crate) struct SurfaceFact {
    /// The PAM service name (`plasmalogin`, `kde`, `sudo`, …). Stable public id.
    pub(crate) id: &'static str,
    pub(crate) role: &'static str,
    /// The /etc path, for the human report only. Machine output publishes the
    /// service name instead, in keeping with the no-paths rule.
    pub(crate) path: &'static str,
    /// Whether this service exists here at all: a real /etc file, or a vendor
    /// copy an /etc override would be materialized from.
    pub(crate) present: bool,
    pub(crate) wired: bool,
    /// How face fires here when wired: `face-first`, `on-demand`, `keyring`
    /// (the fingerprint keyring-unlock line, which is not a face factor) or
    /// `verify` (the plain sudo/polkit stanza). `None` when not wired.
    pub(crate) mode: Option<&'static str>,
}

pub(super) fn surface_fact(
    etc: &'static str,
    vendor: Option<&'static str>,
    role: &'static str,
) -> SurfaceFact {
    let path = service_present(&Svc { etc, vendor });
    let content = path
        .as_ref()
        .and_then(|p| std::fs::read_to_string(p).ok())
        .unwrap_or_default();
    let wired = content_has_module(&content);
    let mode = wiring_mode(role, &content);
    SurfaceFact {
        id: service_name(etc),
        role,
        path: etc,
        present: path.is_some(),
        wired,
        mode,
    }
}

/// Name HOW face fires on a wired service, from its content. Pure: the same
/// decision feeds the human report, `login status --json`, and the TUI.
/// `verify` is the plain consent line (sudo, polkit, and the Omarchy lock,
/// whose polkit-recipe line carries no `unseal`); a keyring-only line is the
/// fingerprint unlock rather than face at all, and locks never carry one.
fn wiring_mode(role: &str, content: &str) -> Option<&'static str> {
    if !content_has_module(content) {
        return None;
    }
    if role == ROLE_SUDO
        || role == ROLE_POLKIT
        || (role == ROLE_LOCK && !content.contains("unseal"))
    {
        return Some("verify");
    }
    if !content.contains("unseal") {
        return Some("keyring");
    }
    if content.contains("ondemand") {
        return Some("on-demand");
    }
    Some("face-first")
}

/// Every surface irlume can wire, present or not, in the order the human report
/// prints them. Absent services are kept in the list with `present: false`: a
/// consumer must be able to read an id it knows and cannot find as "this engine
/// does not wire that service" rather than as "not wired here".
pub(crate) fn surface_facts() -> Vec<SurfaceFact> {
    surface_facts_with(
        irlume_common::platform::omarchy_present(),
        std::path::Path::new("/etc/pam.d/cinnamon-screensaver").exists(),
    )
}

/// Testable core of [`surface_facts`]: the lock row follows the SAME dynamic
/// lock surface the wiring uses, so what `login status` reports can never
/// drift from what `login enable` wires (#584/#585 made the lock surface
/// environment-aware; the report had kept the static KDE row, which is why
/// no desktop ever saw its lock listed).
fn surface_facts_with(omarchy: bool, cinnamon: bool) -> Vec<SurfaceFact> {
    let mut out: Vec<SurfaceFact> = GREETERS
        .iter()
        .map(|s| surface_fact(s.etc, s.vendor, ROLE_LOGIN))
        .chain(
            FP_GREETERS
                .iter()
                .map(|s| surface_fact(s.etc, s.vendor, ROLE_LOGIN_FP)),
        )
        .collect();
    let (lock_svc, _) = lock_surface_for(omarchy, cinnamon);
    out.push(surface_fact(lock_svc.etc, lock_svc.vendor, ROLE_LOCK));
    out.push(surface_fact(SUDO, None, ROLE_SUDO));
    out.push(surface_fact(POLKIT.etc, POLKIT.vendor, ROLE_POLKIT));
    out
}

/// Print a warning for every wired greeter that releases the login password
/// with nothing downstream to open the wallet. Advisory only: it never changes
/// a stack and never fails a command, because a missing wallet module is the
/// user's package/desktop choice, not a broken irlume wiring.
/// One wired greeter whose released password nothing turns into an open
/// wallet: either a module read it with no session half (`auth_only`), or no
/// keyring module reads it at all (`auth_only: None`).
#[derive(Clone, Copy)]
pub(crate) struct HandoffWarning {
    /// The `/etc/pam.d` path of the affected greeter.
    pub(crate) service: &'static str,
    /// The module holding only the auth half, when one does.
    pub(crate) auth_only: Option<&'static str>,
}

/// The keyring hand-off findings as DATA, shared by the printed report below
/// and the TUI's PAM screen. One walk feeding both surfaces: two copies of
/// this logic disagreeing is how an advisory lies in exactly one place.
pub(crate) fn keyring_handoff_warnings() -> Vec<HandoffWarning> {
    let mut out = Vec::new();
    for s in GREETERS {
        let Some(path) = service_present(s) else {
            continue;
        };
        let Ok(content) = std::fs::read_to_string(&path) else {
            continue;
        };
        if !content_has_module(&content) {
            continue;
        }
        let Some(handoff) = keyring_handoff(&content, service_name(s.etc)) else {
            continue;
        };
        // A single complete module is enough: the wallet opens. Only when none
        // is complete does the stack need explaining.
        if handoff.complete.is_some() {
            continue;
        }
        out.push(HandoffWarning {
            service: s.etc,
            auth_only: handoff.auth_only.first().copied(),
        });
    }
    out
}

pub(super) fn report_keyring_handoff() {
    for w in keyring_handoff_warnings() {
        match w.auth_only {
            Some(m) => println!(
                "  ⚠ {}: {m} reads the released password but has no session line, so the\n     \
                 wallet daemon is never started with the key. Your wallet will still prompt.",
                w.service
            ),
            None => println!(
                "  ⚠ {}: a face or fingerprint login releases your login password, but no\n     \
                 keyring module reads it afterwards, so KWallet/the login keyring will\n     \
                 still prompt. Install kwallet-pam (KDE) or gnome-keyring (GNOME); if it\n     \
                 is already installed, its auth line must sit BELOW the pam_irlume line.",
                w.service
            ),
        }
    }
}

/// The active login manager and the PAM services it consults.
pub(crate) struct LoginManagerFact {
    /// `None` when no login manager could be found at all: a headless host. A
    /// greeter that registers no `display-manager.service` is still found when
    /// it is one of [`WANTS_ONLY_DMS`]. Not the same as "no face login".
    pub(crate) name: Option<String>,
    /// Whether irlume can wire face login here. False covers both a login
    /// manager it has no mapping for and one whose mapped service it has no
    /// recipe for; either way `login enable` cannot target it.
    pub(crate) recognized: bool,
    /// The greeter service, plus the separate fingerprint service on the login
    /// managers that have one (GDM). Empty when unrecognized.
    pub(crate) services: Vec<&'static str>,
}

pub(crate) fn login_manager_fact() -> LoginManagerFact {
    let Some(dm) = active_display_manager() else {
        return LoginManagerFact {
            name: None,
            recognized: false,
            services: Vec::new(),
        };
    };
    let (greeter, fp) = dm_pam_services(&dm);
    // Named is not the same as wirable, so a service irlume cannot write must
    // not be published as one it consults.
    let recognized = dm_wirable(&dm);
    LoginManagerFact {
        name: Some(dm),
        recognized,
        services: if recognized {
            std::iter::once(greeter).chain(fp).collect()
        } else {
            Vec::new()
        },
    }
}

/// Structured wiring status for the TUI: `(label, present, wired)` per service
/// plus a trailing SELinux row. Mirrors what `status()` prints, lock surface
/// included: the same dynamic chooser the wiring uses (#587's lesson).
pub(crate) fn status_report() -> Vec<(String, bool, bool)> {
    let (lock_svc, _) = lock_surface();
    let mut out = Vec::new();
    for s in GREETERS
        .iter()
        .chain(FP_GREETERS.iter())
        .chain(std::iter::once(lock_svc))
    {
        match service_present(s) {
            Some(p) => out.push((label_of(s.etc), true, file_has_module(&p))),
            None => out.push((label_of(s.etc), false, false)),
        }
    }
    let sudo = Path::new(SUDO);
    out.push((
        "sudo".into(),
        sudo.exists(),
        sudo.exists() && file_has_module(sudo),
    ));
    match service_present(&POLKIT) {
        Some(p) => out.push(("polkit (apps)".into(), true, file_has_module(&p))),
        None => out.push(("polkit (apps)".into(), false, false)),
    }
    out
}

pub(super) fn status() -> ExitCode {
    println!("[login] wiring status (face auth in PAM):");
    if let Some(dm) = active_display_manager() {
        let (greeter, fp) = dm_pam_services(&dm);
        match fp {
            Some(fp) => println!("  active login manager: {dm}  (uses {greeter} + {fp})"),
            None => println!("  active login manager: {dm}  (uses {greeter})"),
        }
    }
    let mut any = false;
    let mut any_ondemand = false;
    for f in surface_facts() {
        if !f.present {
            continue;
        }
        let label = match (f.role, f.mode) {
            (ROLE_SUDO, Some(_)) => "● wired (sudo)",
            (ROLE_SUDO, None) => "○ not wired (sudo)",
            (ROLE_POLKIT, Some(_)) => "● wired (polkit app prompts)",
            (ROLE_POLKIT, None) => "○ not wired (polkit app prompts)",
            (_, None) => "○ not wired",
            (_, Some("on-demand")) => {
                any_ondemand = true;
                "● wired (face on-demand)"
            }
            (_, Some("face-first")) => "● wired (face-first)",
            // keyring-only line
            (_, Some(_)) => "● wired",
        };
        // face-sudo alone does not make the login screen work, so it does not
        // silence the "enable with" hint below.
        any |= f.wired && f.role != ROLE_SUDO && f.role != ROLE_POLKIT;
        println!("  {:<34} {}", f.path, label);
    }
    if any_ondemand {
        println!("  on-demand: {ONDEMAND_HINT}");
    }
    // A greeter can be correctly wired and still leave the wallet locked, so
    // this is reported next to the wiring rather than left to `doctor`: it is
    // the difference between "face logs me in" and "face logs me in AND my
    // wallet is open", which is what the keyring path exists for.
    report_keyring_handoff();
    println!(
        "[login] SELinux module: {}",
        match selinux_loaded() {
            Some(true) => "loaded",
            Some(false) => "not loaded",
            None => "unknown (run as root to check)",
        }
    );
    if !any {
        println!(
            "  → enable with:  sudo irlume login enable --apply   (add --with-sudo for face-sudo, \
             --with-polkit for app prompts like Bitwarden)"
        );
    }
    ExitCode::SUCCESS
}

#[cfg(test)]
mod tests {
    use super::*;

    /// #584/#585 made the lock surface environment-aware; the status report
    /// must follow the SAME surface the wiring writes, or `login status`
    /// silently omits a wired lock (which is exactly what shipped: no desktop
    /// ever saw a lock row). The lock row's path tracks the chosen surface,
    /// including the Omarchy-beats-Cinnamon precedence.
    #[test]
    fn wiring_mode_names_each_shape_correctly() {
        // The Omarchy lock's polkit-recipe line: a consent keyword, not
        // keyring, not on-demand.
        let omarchy_lock = "auth       [success=done new_authtok_reqd=done abort=die default=ignore]   pam_irlume.so\n@include common-auth\n";
        assert_eq!(wiring_mode(ROLE_LOCK, omarchy_lock), Some("verify"));
        // The KDE/Cinnamon on-demand line.
        let ondemand =
            "auth       sufficient   pam_irlume.so unseal ondemand\n@include common-auth\n";
        assert_eq!(wiring_mode(ROLE_LOCK, ondemand), Some("on-demand"));
        // A keyring-only line on a greeter is the fingerprint unlock
        // (stanzas.rs KEYRING_UNSEAL's exact shape, no `unseal` token).
        let keyring = "auth       optional                     pam_irlume.so keyring\n";
        assert_eq!(wiring_mode(ROLE_LOGIN_FP, keyring), Some("keyring"));
        // Nothing wired says nothing.
        assert_eq!(wiring_mode(ROLE_LOCK, "#%PAM-1.0\n"), None);
    }

    #[test]
    fn surface_facts_lock_row_follows_the_dynamic_lock_surface() {
        let lock_row = |omarchy: bool, cinnamon: bool| {
            surface_facts_with(omarchy, cinnamon)
                .into_iter()
                .find(|f| f.role == ROLE_LOCK)
                .expect("exactly one lock row")
        };
        assert_eq!(
            lock_row(true, true).id,
            "omarchy-lock-password",
            "omarchy wins when both signals exist"
        );
        assert_eq!(
            lock_row(false, true).id,
            "cinnamon-screensaver",
            "Cinnamon's lock is reported when its service file exists"
        );
        assert_eq!(
            lock_row(false, false).id,
            "kde",
            "KDE remains the default lock row"
        );
    }
}

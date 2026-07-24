//! Secret Service (login keyring) diagnostics for `irlume doctor`.
//!
//! Bitwarden's biometric unlock, and any app that stores secrets, needs a
//! Secret Service provider (GNOME Keyring or KWallet) running on the session
//! bus with the login collection unlocked. When face login releases the
//! TPM-sealed password through PAM, `pam_gnome_keyring` / `pam_kwallet5` unlock
//! that collection automatically; if the collection is still locked after a
//! face login, the keyring password did not match the login password (a stale
//! `irlume keyring arm`) and secrets fall back to a manual unlock prompt.
//!
//! This probe shells out to `busctl --user` rather than linking a D-Bus client,
//! matching how irlume-fingerprint talks to fprintd. It only inspects the
//! caller's own session bus, so it is meaningful only for the current user.

use std::path::PathBuf;
use std::process::Command;

/// The default (login) collection alias every Secret Service provider exposes.
const DEFAULT_COLLECTION: &str = "/org/freedesktop/secrets/aliases/default";
const SECRETS_BUS: &str = "org.freedesktop.secrets";

/// Locale-pinned `busctl --user`, or `None` when busctl is not installed.
fn busctl_user() -> Option<Command> {
    let path = which_busctl()?;
    let mut c = Command::new(path);
    c.env("LC_ALL", "C").env("LANG", "C").arg("--user");
    Some(c)
}

/// Resolve `busctl` on PATH without assuming a fixed location (it lives in
/// /usr/bin on most distros but /bin elsewhere).
fn which_busctl() -> Option<PathBuf> {
    let path = std::env::var_os("PATH")?;
    std::env::split_paths(&path)
        .map(|d| d.join("busctl"))
        .find(|p| p.exists())
}

/// Whether the current process has a session bus to talk to at all. Under
/// `sudo irlume doctor` there is none, so the probe stays silent instead of
/// reporting a misleading "keyring unavailable".
fn have_session_bus() -> bool {
    std::env::var_os("DBUS_SESSION_BUS_ADDRESS").is_some()
        || std::env::var_os("XDG_RUNTIME_DIR")
            .is_some_and(|r| std::path::Path::new(&r).join("bus").exists())
}

/// Lock state of the login keyring collection.
enum Collection {
    /// A provider answered; the login collection is unlocked (`false`) or
    /// locked (`true`).
    Present { locked: bool },
    /// No provider owns `org.freedesktop.secrets` on this bus.
    NoProvider,
}

/// The process backing `org.freedesktop.secrets`, as a friendly name. KDE
/// Plasma 6 uses `ksecretd` (launched by pam_kwallet5 with `--pam-login`);
/// older KDE uses `kwalletd6`/`kwalletd5`; GNOME uses `gnome-keyring-daemon`.
/// Knowing which one lets the doctor line name the PAM module that unlocks it.
fn provider_name() -> Option<String> {
    let mut cmd = busctl_user()?;
    let out = cmd.args(["status", SECRETS_BUS]).output().ok()?;
    if !out.status.success() {
        return None;
    }
    // `busctl status` prints a `Comm=<exe>` line for the owning process.
    String::from_utf8_lossy(&out.stdout)
        .lines()
        .find_map(|l| l.trim().strip_prefix("Comm="))
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
}

/// Map a provider process name to the PAM module that unlocks it from the
/// face-released password, for a precise doctor hint. `None` for an unknown
/// provider (still a valid Secret Service, just not one we have advice for).
fn unlock_module_for(provider: &str) -> Option<&'static str> {
    match provider {
        "ksecretd" | "kwalletd6" | "kwalletd5" => Some("pam_kwallet5"),
        "gnome-keyring-d" | "gnome-keyring-daemon" => Some("pam_gnome_keyring"),
        _ => None,
    }
}

/// Query the default collection's `Locked` property. A successful reply means a
/// provider is running (the query D-Bus-activates it if it is merely
/// registered); a failure means no provider is installed or reachable.
fn query_collection() -> Collection {
    let Some(mut cmd) = busctl_user() else {
        return Collection::NoProvider;
    };
    let out = cmd
        .args([
            "get-property",
            SECRETS_BUS,
            DEFAULT_COLLECTION,
            "org.freedesktop.Secret.Collection",
            "Locked",
        ])
        .output();
    match out {
        Ok(o) if o.status.success() => match parse_locked(&String::from_utf8_lossy(&o.stdout)) {
            Some(locked) => Collection::Present { locked },
            None => Collection::NoProvider,
        },
        _ => Collection::NoProvider,
    }
}

/// Parse a `busctl get-property … Locked` reply. The wire form is `b true` or
/// `b false`; anything else (empty, malformed) yields `None`.
fn parse_locked(reply: &str) -> Option<bool> {
    let mut it = reply.split_whitespace();
    if it.next()? != "b" {
        return None;
    }
    match it.next()? {
        "true" => Some(true),
        "false" => Some(false),
        _ => None,
    }
}

/// Print one doctor line about the login keyring, or nothing when there is no
/// session bus to inspect (e.g. under sudo). Only call for the current user.
/// For the TUI Repair check: `Some(true)` when a Secret Service provider is up
/// but the login collection is LOCKED (apps like Bitwarden can't read secrets),
/// `Some(false)` when unlocked, `None` when there's no session bus or provider
/// to judge (so Repair stays quiet rather than warning on a headless/no-wallet
/// box). Only meaningful run as the user (a session bus), like the report.
pub(crate) fn login_keyring_locked() -> Option<bool> {
    if !have_session_bus() {
        return None;
    }
    match query_collection() {
        Collection::Present { locked } => Some(locked),
        Collection::NoProvider => None,
    }
}

pub fn report_keyring_status() {
    if !have_session_bus() {
        return;
    }
    // Name the provider (ksecretd on Plasma 6, kwalletd, gnome-keyring) so the
    // hint points at the exact PAM module carrying the face-released password.
    let provider = provider_name();
    let via = provider
        .as_deref()
        .and_then(unlock_module_for)
        .map(|m| format!("via {m}"))
        .unwrap_or_else(|| "via pam_gnome_keyring/pam_kwallet5".to_string());
    let who = provider
        .as_deref()
        .map(|p| format!(" [{p}]"))
        .unwrap_or_default();
    match query_collection() {
        Collection::Present { locked: false } => println!(
            "[doctor] login keyring{who}: unlocked ✓ (Secret Service apps like Bitwarden \
             can read secrets after a face login)"
        ),
        Collection::Present { locked: true } => println!(
            "[doctor] login keyring{who}: LOCKED. A face login should unlock it {via}.\n     \
             If it stays locked, the sealed keyring password is stale; re-run: \
             sudo irlume keyring arm"
        ),
        Collection::NoProvider => println!(
            "[doctor] login keyring: no Secret Service provider running \
             (GNOME Keyring / KWallet).\n     \
             Bitwarden and other secret-storing apps need one; your desktop \
             normally starts it at login."
        ),
    }
}

#[cfg(test)]
mod tests {
    use super::{parse_locked, unlock_module_for};

    #[test]
    fn parse_locked_reads_the_busctl_boolean_reply() {
        assert_eq!(parse_locked("b true\n"), Some(true));
        assert_eq!(parse_locked("b false\n"), Some(false));
        // A missing or malformed reply is not a false "unlocked" signal.
        assert_eq!(parse_locked(""), None);
        assert_eq!(parse_locked("b"), None);
        assert_eq!(parse_locked("s \"oops\""), None);
    }

    #[test]
    fn unlock_module_maps_known_secret_service_providers() {
        // Plasma 6 (ksecretd) and older KWallet both unlock via pam_kwallet5.
        assert_eq!(unlock_module_for("ksecretd"), Some("pam_kwallet5"));
        assert_eq!(unlock_module_for("kwalletd6"), Some("pam_kwallet5"));
        assert_eq!(
            unlock_module_for("gnome-keyring-d"),
            Some("pam_gnome_keyring")
        );
        // An unknown provider yields no hint rather than a wrong one.
        assert_eq!(unlock_module_for("keepassxc"), None);
    }
}

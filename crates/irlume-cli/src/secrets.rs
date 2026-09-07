//! Secret Service (login keyring) diagnostics for `irlume doctor`.
//!
//! Bitwarden's biometric unlock, and any app that stores secrets, needs a
//! Secret Service provider (GNOME Keyring or KWallet) running on the session
//! bus with a default collection unlocked. The provider can be running without
//! a default collection, or applications can reach a different provider from
//! the wallet Irlume unlocks. Report those states separately from a locked
//! wallet; none alone proves that the sealed credential is stale.
//!
//! This probe shells out to `busctl --user` rather than linking a D-Bus client,
//! matching how irlume-fingerprint talks to fprintd. It only inspects the
//! caller's own session bus, so it is meaningful only for the current user.

use crate::dout;
use std::path::PathBuf;
use std::process::Command;

/// The service can exist without a default collection (ReadAlias returns `/`).
const SECRETS_PATH: &str = "/org/freedesktop/secrets";
const SECRETS_BUS: &str = "org.freedesktop.secrets";

/// Locale-pinned `busctl --user`, or `None` when busctl is not installed.
fn busctl_user() -> Option<Command> {
    let path = which_busctl()?;
    let mut c = Command::new(path);
    c.env("LC_ALL", "C")
        .env("LANG", "C")
        .args(["--user", "--timeout=3", "--auto-start=no"]);
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
    /// A provider answered ReadAlias, but has no default collection.
    MissingDefault,
    /// The bus, provider, or reply could not be checked reliably.
    Unavailable,
}

/// Actionable state shared by doctor and the TUI Repair page.
#[derive(Clone, Copy)]
pub(crate) enum LoginKeyringProblem {
    Locked,
    MissingDefault,
}

impl LoginKeyringProblem {
    pub(crate) fn description(self) -> &'static str {
        match self {
            Self::Locked => "the default wallet is locked; apps cannot read its secrets yet",
            Self::MissingDefault => "the running Secret Service provider has no default collection; apps may ask to create a keyring",
        }
    }

    pub(crate) fn advice(self) -> &'static str {
        match self {
            Self::Locked => "Unlock the existing wallet and check `irlume keyring status` before re-arming.",
            Self::MissingDefault => "Check your desktop's preferred Secret Service provider and select an existing default wallet before arming Irlume.",
        }
    }
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

/// Read provider ownership and the default collection without activating a
/// provider or prompting. A missing alias is not a missing provider. Errors
/// remain unknown, including a provider that disappears between these reads.
fn query_collection() -> Collection {
    match busctl_output(&[
        "call",
        "org.freedesktop.DBus",
        "/org/freedesktop/DBus",
        "org.freedesktop.DBus",
        "NameHasOwner",
        "s",
        SECRETS_BUS,
    ])
    .as_deref()
    .and_then(parse_locked)
    {
        Some(false) => return Collection::NoProvider,
        Some(true) => {}
        None => return Collection::Unavailable,
    }
    let alias = busctl_output(&[
        "call",
        SECRETS_BUS,
        SECRETS_PATH,
        "org.freedesktop.Secret.Service",
        "ReadAlias",
        "s",
        "default",
    ]);
    let Some(path) = alias.as_deref().and_then(parse_collection_path) else {
        return Collection::Unavailable;
    };
    if path == "/" {
        return Collection::MissingDefault;
    }
    match busctl_output(&[
        "get-property",
        SECRETS_BUS,
        &path,
        "org.freedesktop.Secret.Collection",
        "Locked",
    ])
    .as_deref()
    .and_then(parse_locked)
    {
        Some(locked) => Collection::Present { locked },
        None => Collection::Unavailable,
    }
}

fn busctl_output(args: &[&str]) -> Option<String> {
    let out = busctl_user()?.args(args).output().ok()?;
    out.status
        .success()
        .then(|| String::from_utf8_lossy(&out.stdout).into_owned())
}

fn parse_collection_path(reply: &str) -> Option<String> {
    let path: String = serde_json::from_str(reply.trim().strip_prefix("o ")?).ok()?;
    let valid = path == "/"
        || path.strip_prefix('/').is_some_and(|rest| {
            rest.split('/').all(|part| {
                !part.is_empty() && part.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'_')
            })
        });
    valid.then_some(path)
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

/// Read actionable default-keyring state for the TUI without treating a
/// missing collection as an absent provider. No session bus means no verdict.
pub(crate) fn login_keyring_problem() -> Option<LoginKeyringProblem> {
    if !have_session_bus() {
        return None;
    }
    match query_collection() {
        Collection::Present { locked: true } => Some(LoginKeyringProblem::Locked),
        Collection::MissingDefault => Some(LoginKeyringProblem::MissingDefault),
        _ => None,
    }
}

pub fn report_keyring_status(report: &mut crate::doctor_report::Report) {
    use crate::doctor_report::State;
    if !have_session_bus() {
        // No session bus, e.g. under `sudo irlume doctor`. The human report stays
        // silent, but the machine one must still carry the check: a consumer that
        // found this id missing could not tell "not checked here" from "checked
        // and fine", which is the failure this whole array exists to avoid.
        report.check("keyring-secrets", State::Unknown);
        return;
    }
    let collection = query_collection();
    let provider = provider_name();
    let via = provider
        .as_deref()
        .and_then(unlock_module_for)
        .map(|m| format!("via {m}"))
        .unwrap_or_else(|| "via your desktop's PAM keyring module".to_string());
    let who = provider
        .as_deref()
        .map(|p| format!(" [{p}]"))
        .unwrap_or_default();
    let (state, message) = match collection {
        Collection::Present { locked: false } => (State::Pass,
            format!("login keyring{who}: unlocked ✓ (Secret Service apps can read secrets)")),
        Collection::Present { locked: true } => (State::Warn,
            format!("login keyring{who}: {}. Login normally unlocks it {via}.\n     {}",
                LoginKeyringProblem::Locked.description(), LoginKeyringProblem::Locked.advice())),
        Collection::MissingDefault => (State::Warn,
            format!("login keyring{who}: {}.\n     {}",
                LoginKeyringProblem::MissingDefault.description(), LoginKeyringProblem::MissingDefault.advice())),
        Collection::NoProvider => (State::Info,
            "login keyring: no Secret Service provider running (GNOME Keyring / KWallet). Your desktop normally starts it at login.".to_string()),
        Collection::Unavailable => (State::Unknown,
            "login keyring: could not determine the default collection's state; check the session bus and Secret Service provider.".to_string()),
    };
    // One observation supplies both outputs, including the actionable reason.
    report.check_detail("keyring-secrets", state, &message);
    dout!(report, "[doctor] {message}");
}

#[cfg(test)]
mod tests {
    use super::{parse_locked, unlock_module_for};

    // Run the real probe/report in a child process so fixture PATH and bus
    // environment cannot race unrelated unit tests or touch the user's bus.
    #[test]
    fn doctor_reports_secret_service_states() {
        use std::os::unix::fs::PermissionsExt;
        let dir =
            std::env::temp_dir().join(format!("irlume-secrets-test-{}", rand::random::<u64>()));
        std::fs::create_dir(&dir).unwrap();
        struct Cleanup(std::path::PathBuf);
        impl Drop for Cleanup {
            fn drop(&mut self) {
                let _ = std::fs::remove_dir_all(&self.0);
            }
        }
        let _cleanup = Cleanup(dir.clone());
        let busctl = dir.join("busctl");
        std::fs::write(
            &busctl,
            r#"#!/bin/sh
no_activation=0
for arg do
  if [ "$arg" = "--auto-start=no" ]; then no_activation=1; fi
done
[ "$no_activation" = 1 ] || exit 65
case "$*" in
  *"status org.freedesktop.secrets") printf 'Comm=gnome-keyring-d\n' ;;
  *"NameHasOwner s org.freedesktop.secrets")
    case "$IRLUME_TEST_SECRET_STATE" in
      no-provider) printf 'b false\n' ;;
      unavailable) exit 1 ;;
      *) printf 'b true\n' ;;
    esac ;;
  *"ReadAlias s default")
    case "$IRLUME_TEST_SECRET_STATE" in
      missing) printf 'o "/"\n' ;;
      unavailable) exit 1 ;;
      malformed-alias) printf 's "wrong type"\n' ;;
      *) printf 'o "/org/freedesktop/secrets/collection/login"\n' ;;
    esac ;;
  *"org.freedesktop.Secret.Collection Locked")
    case "$IRLUME_TEST_SECRET_STATE" in
      locked) printf 'b true\n' ;;
      unlocked) printf 'b false\n' ;;
      malformed-lock) printf 's "false"\n' ;;
      *) exit 1 ;;
    esac ;;
  *) exit 64 ;;
esac
"#,
        )
        .unwrap();
        std::fs::set_permissions(&busctl, std::fs::Permissions::from_mode(0o700)).unwrap();
        for (scenario, want) in [
            ("missing", "warn"),
            ("locked", "warn"),
            ("unlocked", "pass"),
            ("no-provider", "info"),
            ("unavailable", "unknown"),
            ("malformed-alias", "unknown"),
            ("malformed-lock", "unknown"),
        ] {
            let output = std::process::Command::new(std::env::current_exe().unwrap())
                .args([
                    "--exact",
                    "secrets::tests::secret_service_fixture_child",
                    "--nocapture",
                ])
                .env("PATH", &dir)
                .env(
                    "DBUS_SESSION_BUS_ADDRESS",
                    "unix:path=/nonexistent-irlume-test-bus",
                )
                .env("IRLUME_TEST_SECRET_STATE", scenario)
                .output()
                .unwrap();
            assert!(
                output.status.success(),
                "{scenario}: {}",
                String::from_utf8_lossy(&output.stderr)
            );
            let stdout = String::from_utf8(output.stdout).unwrap();
            let json = stdout
                .lines()
                .find_map(|line| line.split_once("IRLUME_FIXTURE_RESULT=").map(|(_, v)| v))
                .expect(&stdout);
            let checks: serde_json::Value = serde_json::from_str(json).unwrap();
            assert_eq!(checks["checks"][0]["id"], "keyring-secrets");
            assert_eq!(checks["checks"][0]["state"], want, "{scenario}");
            assert!(
                !checks["checks"][0]["detail"]
                    .as_str()
                    .unwrap()
                    .contains("[doctor]"),
                "human report prefix leaked into machine detail: {scenario}"
            );
            let problem = &checks["problem"];
            if matches!(scenario, "missing" | "locked") {
                let description = problem["description"].as_str().unwrap();
                let detail = checks["checks"][0]["detail"].as_str().unwrap();
                assert!(detail.contains(description), "doctor and TUI must agree");
                if scenario == "missing" {
                    assert!(description.contains("no default collection"));
                    assert!(!problem["advice"].as_str().unwrap().contains("keyring arm"));
                } else {
                    assert!(description.contains("locked"));
                }
            } else {
                assert!(
                    problem.is_null(),
                    "{scenario} is not a confirmed wallet problem"
                );
            }
        }
    }

    #[test]
    fn secret_service_fixture_child() {
        if std::env::var_os("IRLUME_TEST_SECRET_STATE").is_none() {
            return;
        }
        let mut report = crate::doctor_report::Report::new(crate::doctor_report::Mode::Collect);
        super::report_keyring_status(&mut report);
        let problem = super::login_keyring_problem().map(|problem| {
            serde_json::json!({
                "description": problem.description(), "advice": problem.advice(),
            })
        });
        println!(
            "IRLUME_FIXTURE_RESULT={}",
            serde_json::json!({
                "checks": report.into_checks(), "problem": problem,
            })
        );
    }

    #[test]
    fn collection_path_requires_an_object_path_reply() {
        assert_eq!(super::parse_collection_path("o \"/\"\n"), Some("/".into()));
        assert_eq!(
            super::parse_collection_path("o \"/org/freedesktop/secrets/collection/login\""),
            Some("/org/freedesktop/secrets/collection/login".into())
        );
        for malformed in [
            "",
            "s \"/\"",
            "o \"relative\"",
            "o \"/bad-path\"",
            "o \"/bad//path\"",
            "o \"/bad/\"",
            "o \"/\" trailing",
        ] {
            assert_eq!(super::parse_collection_path(malformed), None, "{malformed}");
        }
    }

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

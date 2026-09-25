// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright the irlume contributors.

//! NixOS: the system configuration owns PAM, and irlume seals only the login
//! password there.
//!
//! On NixOS `/etc/pam.d` is generated from the system configuration, and
//! irlume's rules come from `services.irlume.pam.services` in the flake's
//! module (`nix/module.nix`). The imperative `irlume login` changes have
//! nothing there they may edit: the next switch regenerates every stack.
//!
//! The module's rules were written for a sealed login password: one auth rule
//! per service, and no session-phase `reseal` rule, which a KDE wallet key or
//! a GNOME keyring token needs. Until the module adds those rules, the keyring
//! arm paths refuse the other two kinds (docs/NIXOS.md).

use irlume_common::{KeyringSecretKind, Request, Response, WalletSalt};
use std::path::{Path, PathBuf};

/// Why `irlume login enable` and `disable` change nothing on NixOS.
pub(crate) const LOGIN_REFUSAL: &str = "[login] refusing: on NixOS the system configuration owns \
     the PAM stacks, so irlume does not edit them. Add or remove services under \
     `services.irlume.pam.services` and rebuild (docs/NIXOS.md). Nothing was changed.";

/// Why `irlume login reconcile` has nothing to do on NixOS.
pub(crate) const RECONCILE_NOTICE: &str = "[login] reconcile: nothing to do on NixOS: the system \
     configuration owns the PAM stacks, and `services.irlume.pam.services` sets irlume's rules \
     (docs/NIXOS.md).";

/// What the hints that elsewhere name `sudo irlume login enable --apply` say
/// on NixOS.
pub(crate) const PAM_POINTER: &str = "on NixOS the system configuration owns the PAM stacks: set \
     irlume's services under `services.irlume.pam.services` and rebuild (docs/NIXOS.md)";

/// Whether os-release text describes NixOS: its `ID` is `nixos`. An `ID`
/// that is empty or quoted on one side only names no distribution.
fn is_nixos(os_release: &str) -> bool {
    crate::os_release::field(os_release, "ID") == Some(Ok("nixos"))
}

/// Whether this host runs NixOS, from the os-release file
/// [`crate::os_release::read_host`] reads (the one the upgrade notices read
/// too). A file that cannot be read names no distribution, so it is not
/// NixOS.
pub(crate) fn host_is_nixos() -> bool {
    crate::os_release::read_host().is_ok_and(|text| is_nixos(&text))
}

/// How a keyring arm or reseal on this host picks what to seal.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum SealKind {
    /// Off NixOS: irlumed picks the kind from what the account has.
    DaemonDecides,
    /// On NixOS: the login password, asked for by name, so irlumed cannot
    /// resolve the arm to a kind the module does not deliver.
    LoginPassword,
}

/// The `kind` and `wallet_salt` fields of a `SealPassword` request.
pub(crate) type SealFields = (Option<KeyringSecretKind>, Option<WalletSalt>);

impl SealKind {
    /// The `kind` and `wallet_salt` of the `SealPassword` request. Off NixOS
    /// the wallet salt is read as every arm path read it; a forced login
    /// password carries none, as irlumed requires.
    ///
    /// # Errors
    /// The wallet salt lookup failed.
    pub(crate) fn request_fields(self, user: &str) -> std::io::Result<SealFields> {
        match self {
            Self::DaemonDecides => Ok((None, irlume_common::client::read_wallet_salt(user)?)),
            Self::LoginPassword => Ok((Some(KeyringSecretKind::LoginPassword), None)),
        }
    }
}

/// Decide how this host arms `user`. Off NixOS this reads nothing. On NixOS
/// it asks irlumed what is armed and reads the account's KDE wallet salt and
/// GNOME login keyring, then refuses an account that has or would get a KDE
/// wallet key or a GNOME keyring token, or that has a sealed secret irlumed
/// cannot read.
///
/// # Errors
/// On NixOS: the refusal, a failed question to irlumed or a failed wallet
/// salt lookup, as a sentence for the caller to prefix.
pub(crate) fn seal_kind(user: &str) -> Result<SealKind, String> {
    if !host_is_nixos() {
        return Ok(SealKind::DaemonDecides);
    }
    let armed = armed_kind(
        user,
        crate::daemon_request(&Request::KeyringMetadata {
            user: user.to_string(),
        }),
    )?;
    let salt = irlume_common::client::read_wallet_salt(user)
        .map_err(|e| format!("could not check which wallet this account uses: {e}"))?;
    nixos_seal_kind(armed, home_for_name(user).as_deref(), salt.is_some())
}

/// What irlumed's `KeyringMetadata` reply says is armed for `user`: `None`
/// for nothing, else the kind. An arm irlumed cannot name the kind of is an
/// envelope it cannot read. irlumed refuses every arm over one, since it may
/// hold the only copy of a GNOME keyring token; this refuses it before the
/// password prompt, with the same advice to keep the file. A failed question
/// is refused too: on NixOS the CLI and irlumed come from one package, so
/// there is no older daemon to allow for.
fn armed_kind(
    user: &str,
    reply: Result<Response, String>,
) -> Result<Option<KeyringSecretKind>, String> {
    match reply {
        Ok(Response::KeyringInfo { armed: false, .. }) => Ok(None),
        Ok(Response::KeyringInfo {
            kind: Some(kind), ..
        }) => Ok(Some(kind)),
        Ok(Response::KeyringInfo { kind: None, .. }) => Err(format!(
            "refusing: this account has a sealed secret irlumed cannot read, and it may hold \
             the only copy of a GNOME keyring token, so irlume does not arm over it. Nothing \
             was sealed. Keep {} as it is: if a newer irlume wrote it, that version can still \
             read it.",
            irlume_core::keyring::envelope_path(user).display()
        )),
        Ok(Response::Error(e)) | Err(e) => Err(format!(
            "could not ask irlumed what this account has armed: {e}"
        )),
        Ok(other) => Err(format!(
            "could not ask irlumed what this account has armed: unexpected response {other:?}"
        )),
    }
}

/// Why the login password is the one kind sealed on NixOS.
const WRITTEN_FOR: &str = "the kind the NixOS module's PAM rules were written for";

/// The remedy for an existing arm the NixOS paths refuse.
const FORGET: &str = "`irlume keyring forget` removes the existing arm";

/// The kind irlumed picks for an account whose home is `home` (`None`: not
/// found), given whether the account-scoped helper found a KDE wallet salt.
/// The same rule as irlumed's `SealPassword` arm, which calls the same
/// `detect_kind` and treats an account without a home the same way.
fn expected_kind(home: Option<&Path>, has_kde_salt: bool) -> KeyringSecretKind {
    use irlume_core::envelope::SecretKind;
    let kind = match home {
        Some(home) => irlume_core::kwallet::detect_kind(home, has_kde_salt),
        None if has_kde_salt => SecretKind::KdeWalletKey,
        None => SecretKind::LoginPassword,
    };
    match kind {
        SecretKind::LoginPassword => KeyringSecretKind::LoginPassword,
        SecretKind::KdeWalletKey => KeyringSecretKind::KdeWalletKey,
        SecretKind::GnomeKeyringToken => KeyringSecretKind::GnomeKeyringToken,
    }
}

/// The NixOS decision, pure. `armed` is the kind already sealed for the
/// account: a login password stays one, a KDE wallet key or GNOME keyring
/// token is refused. With nothing armed, the kind a first arm would get
/// decides.
fn nixos_seal_kind(
    armed: Option<KeyringSecretKind>,
    home: Option<&Path>,
    has_kde_salt: bool,
) -> Result<SealKind, String> {
    let kind = armed.unwrap_or_else(|| expected_kind(home, has_kde_salt));
    let what = match kind {
        KeyringSecretKind::LoginPassword => return Ok(SealKind::LoginPassword),
        KeyringSecretKind::KdeWalletKey => "a KDE wallet key",
        KeyringSecretKind::GnomeKeyringToken => "a GNOME keyring token",
    };
    // Only an existing arm has anything for `forget` to remove.
    let (has, remedy) = match armed {
        Some(_) => ("has", format!("; {FORGET}")),
        None => ("would get", String::new()),
    };
    Err(format!(
        "refusing: this account {has} {what}, and on NixOS irlume seals only the login \
         password, {WRITTEN_FOR}. Nothing was sealed{remedy} (docs/NIXOS.md, \
         \"Keyring unlock\")."
    ))
}

/// Resolve a user name to its home directory via NSS (`getpwnam_r`). `None`
/// if the account is absent or names no home.
fn home_for_name(name: &str) -> Option<PathBuf> {
    let name = std::ffi::CString::new(name).ok()?;
    // SAFETY: `passwd` is a plain C struct of integers and pointers, for
    // which all-zero bytes are a valid value; getpwnam_r fills it in.
    let mut entry: libc::passwd = unsafe { std::mem::zeroed() };
    let mut buf = vec![0 as libc::c_char; 16 * 1024];
    let mut result: *mut libc::passwd = std::ptr::null_mut();
    // SAFETY: every pointer is valid for the call and `buf.len()` is the
    // buffer's real size. On success `result` points at `entry`, whose
    // strings point into `buf`, which outlives every read below.
    let rc = unsafe {
        libc::getpwnam_r(
            name.as_ptr(),
            &mut entry,
            buf.as_mut_ptr(),
            buf.len(),
            &mut result,
        )
    };
    if rc != 0 || result.is_null() || entry.pw_dir.is_null() {
        return None;
    }
    // SAFETY: `pw_dir` is non-null and points at a NUL-terminated string in
    // `buf`, which is still alive.
    let dir = unsafe { std::ffi::CStr::from_ptr(entry.pw_dir) };
    let dir = dir.to_str().ok()?;
    (!dir.is_empty()).then(|| PathBuf::from(dir))
}

#[cfg(test)]
mod tests {
    use super::*;
    use KeyringSecretKind as K;

    #[test]
    fn only_an_os_release_id_of_nixos_is_nixos() {
        for (text, nixos) in [
            ("NAME=NixOS\nID=nixos\nVERSION_ID=\"25.11\"\n", true),
            ("ID=\"nixos\"\n", true),
            ("ID='nixos'\n", true),
            ("  ID=nixos  \n", true),
            ("ID=fedora\nID=nixos\n", true),
            ("ID=nixos\nID=fedora\n", false),
            ("NAME=\"Fedora Linux\"\nID=fedora\nVERSION_ID=44\n", false),
            ("ID=debian\nID_LIKE=nixos\n", false),
            ("# ID=nixos\nID=arch\n", false),
            ("VARIANT_ID=nixos\n", false),
            // Empty or unbalanced: no distribution, as the upgrade notices
            // read it.
            ("ID=\n", false),
            ("ID=\"nixos\n", false),
            ("ID=nixos\nID=\"\n", false),
            ("", false),
        ] {
            assert_eq!(is_nixos(text), nixos, "{text:?}");
        }
    }

    #[test]
    fn the_host_reading_follows_the_override_and_an_unreadable_file_is_not_nixos() {
        use crate::os_release::OS_RELEASE_ENV;
        let _guard = crate::testenv::ENV_LOCK
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        let old = std::env::var_os(OS_RELEASE_ENV);
        let dir = std::env::temp_dir().join(format!("irlume-nixos-host-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let file = dir.join("os-release");
        let mut seen = Vec::new();
        for text in ["NAME=NixOS\nID=nixos\n", "ID=fedora\n"] {
            std::fs::write(&file, text).unwrap();
            std::env::set_var(OS_RELEASE_ENV, &file);
            seen.push(host_is_nixos());
        }
        std::env::set_var(OS_RELEASE_ENV, dir.join("absent"));
        seen.push(host_is_nixos());
        match old {
            Some(value) => std::env::set_var(OS_RELEASE_ENV, value),
            None => std::env::remove_var(OS_RELEASE_ENV),
        }
        let _ = std::fs::remove_dir_all(&dir);
        assert_eq!(seen, [true, false, false]);
    }

    /// A first arm follows irlumed's kind detection; an existing arm keeps a
    /// login password and refuses the other two kinds.
    #[test]
    fn nixos_arms_only_the_login_password() {
        let root = std::env::temp_dir().join(format!("irlume-nixos-kind-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        let plain = root.join("plain");
        let gnome = root.join("gnome");
        std::fs::create_dir_all(&plain).unwrap();
        std::fs::create_dir_all(gnome.join(".local/share/keyrings")).unwrap();
        std::fs::write(gnome.join(".local/share/keyrings/login.keyring"), b"").unwrap();
        // One reading: what is armed, the home, whether a KDE wallet salt
        // exists, and the decision (a refusal by a fragment of its text).
        // `forget` is named only when there is an arm for it to remove.
        fn check(armed: Option<K>, home: Option<&Path>, salt: bool, want: Result<SealKind, &str>) {
            let got = nixos_seal_kind(armed, home, salt);
            match (want, &got) {
                (Ok(want), Ok(got)) => assert_eq!(*got, want),
                (Err(fragment), Err(refusal)) => {
                    for needle in [fragment, "docs/NIXOS.md", "Nothing was sealed"] {
                        assert!(refusal.contains(needle), "{needle:?} not in {refusal}");
                    }
                    assert_eq!(
                        refusal.contains("irlume keyring forget"),
                        armed.is_some(),
                        "{refusal}"
                    );
                }
                _ => panic!("{armed:?} {home:?} salt={salt}: {got:?}"),
            }
        }
        let lp = Ok(SealKind::LoginPassword);
        let (plain, gnome) = (Some(plain.as_path()), Some(gnome.as_path()));
        // First arms follow irlumed's detection.
        check(None, None, false, lp);
        check(None, None, true, Err("would get a KDE wallet key"));
        check(None, plain, false, lp);
        check(None, plain, true, Err("would get a KDE wallet key"));
        check(None, gnome, false, Err("would get a GNOME keyring token"));
        // Both backends: irlumed seals the login password.
        check(None, gnome, true, lp);
        // Re-arms and reseals go by what is armed.
        check(Some(K::LoginPassword), plain, true, lp);
        check(Some(K::LoginPassword), gnome, false, lp);
        check(
            Some(K::KdeWalletKey),
            gnome,
            true,
            Err("has a KDE wallet key"),
        );
        check(
            Some(K::KdeWalletKey),
            None,
            false,
            Err("has a KDE wallet key"),
        );
        check(
            Some(K::GnomeKeyringToken),
            None,
            false,
            Err("has a GNOME keyring token"),
        );
        let _ = std::fs::remove_dir_all(&root);
    }

    /// irlumed's answer about what is armed: nothing, a named kind, an
    /// envelope it cannot read (refused with irlumed's own advice to keep the
    /// file), or no answer (refused).
    #[test]
    fn an_arm_irlumed_cannot_describe_is_refused() {
        let info = |armed: bool, kind: Option<K>| {
            Ok(Response::KeyringInfo {
                armed,
                policy: None,
                pcrs: Vec::new(),
                drifted: None,
                kind,
            })
        };
        assert_eq!(armed_kind("alice", info(false, None)), Ok(None));
        for kind in [K::LoginPassword, K::KdeWalletKey, K::GnomeKeyringToken] {
            assert_eq!(armed_kind("alice", info(true, Some(kind))), Ok(Some(kind)));
        }
        let unknown =
            armed_kind("alice", info(true, None)).expect_err("an unreadable arm is refused");
        for needle in [
            "a sealed secret irlumed cannot read",
            "Nothing was sealed",
            "alice.json as it is: if a newer irlume wrote it",
        ] {
            assert!(unknown.contains(needle), "{needle:?} not in {unknown}");
        }
        // `forget` refuses an arm it cannot identify, and with `--force`
        // deletes the file irlumed says to keep, so it is not offered here.
        assert!(!unknown.contains("irlume keyring forget"), "{unknown}");
        for reply in [
            Ok(Response::Error("bad request".into())),
            Err("irlumed is not running".into()),
            Ok(Response::Pong),
        ] {
            let refusal = armed_kind("alice", reply).expect_err("no answer is no permission");
            assert!(
                refusal.starts_with("could not ask irlumed what this account has armed"),
                "{refusal}"
            );
        }
    }

    #[test]
    fn a_forced_login_password_carries_no_wallet_salt() {
        // No helper runs for a forced kind, so this needs no sandbox.
        let fields = SealKind::LoginPassword
            .request_fields("irlume-no-such-account")
            .expect("a forced kind reads nothing");
        assert!(matches!(fields, (Some(K::LoginPassword), None)));
    }

    #[test]
    fn home_lookup_resolves_root_and_rejects_absent_names() {
        assert!(home_for_name("root").is_some_and(|home| home.is_absolute()));
        assert_eq!(home_for_name("irlume-no-such-account"), None);
        assert_eq!(home_for_name("bad\0name"), None);
        assert_eq!(home_for_name(""), None);
    }
}

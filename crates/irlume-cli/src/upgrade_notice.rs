// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright the irlume contributors.

//! Distribution upgrades a GNOME keyring token does not carry over.
//!
//! A token arm (#250) keys the login keyring to a random secret irlume
//! releases at login. A release whose login screen hands the login keyring to
//! another provider migrates it with the login password, which no longer opens
//! a token-keyed keyring. The step is to re-key back with
//! `irlume keyring forget` before the upgrade; `doctor`, `keyring arm`,
//! `keyring status` and the TUI say so on a release listed here. The list is
//! data, so the next such release is one more row.

use irlume_common::{KeyringSecretKind, Response};

/// An installed release whose next upgrade a GNOME keyring token does not
/// survive.
#[derive(Debug, PartialEq, Eq)]
pub(crate) struct TokenUpgradeNotice {
    /// os-release `ID` of the installed system.
    pub(crate) id: &'static str,
    /// os-release `VERSION_ID` of the installed system.
    pub(crate) version_id: &'static str,
    /// The installed release, as its users name it.
    pub(crate) release: &'static str,
    /// The release the upgrade goes to, as its users name it.
    pub(crate) next_release: &'static str,
    /// Why the token does not carry over, in one sentence.
    pub(crate) reason: &'static str,
}

const FEDORA_45_OO7: &str = "On Fedora 45 the login screen unlocks the login keyring through \
                             oo7, which migrates it with the login password, so a keyring \
                             keyed to an irlume token does not carry over.";

/// Every release with a pending notice, matched on `ID` and `VERSION_ID`
/// exactly (a derivative has its own `ID`). Fedora 43 is listed because
/// Fedora upgrades may skip one release.
pub(crate) const TOKEN_UPGRADE_NOTICES: &[TokenUpgradeNotice] = &[
    TokenUpgradeNotice {
        id: "fedora",
        version_id: "43",
        release: "Fedora 43",
        next_release: "Fedora 45",
        reason: FEDORA_45_OO7,
    },
    TokenUpgradeNotice {
        id: "fedora",
        version_id: "44",
        release: "Fedora 44",
        next_release: "Fedora 45",
        reason: FEDORA_45_OO7,
    },
];

impl TokenUpgradeNotice {
    /// The reason and what to do for `user`, as one paragraph. `forget`
    /// re-keys the keyring through its owner's own session, so the step names
    /// the account and where to run it. It does not send the user to `irlume
    /// keyring arm` on the next release: this build's kind detection would pick
    /// a token there again.
    pub(crate) fn advice(&self, user: &str) -> String {
        format!(
            "{} Before upgrading to {next}, log in as {user} and run \
             `irlume keyring forget` in that graphical session (it re-keys the login \
             keyring back to the password). Do not arm again on {next} until an irlume \
             update supports its keyring; until then the password opens it as usual.",
            self.reason,
            next = self.next_release
        )
    }
}

/// Whether the daemon's answer to `KeyringInfo` or `KeyringMetadata` shows a
/// GNOME keyring token armed. `None` when it does not say: no answer, an error, another reply, or
/// an armed secret whose kind an older daemon does not report.
pub(crate) fn token_armed(answer: &Result<Response, String>) -> Option<bool> {
    match answer {
        Ok(Response::KeyringInfo { armed: false, .. }) => Some(false),
        Ok(Response::KeyringInfo {
            kind: Some(kind), ..
        }) => Some(*kind == KeyringSecretKind::GnomeKeyringToken),
        _ => None,
    }
}

/// The notice for the release `os_release` describes, if one is listed.
/// `Err` when it names no `ID` or no `VERSION_ID`, or gives one malformed:
/// the release is then unknown, not merely unlisted.
pub(crate) fn token_upgrade_notice(
    os_release: &str,
) -> Result<Option<&'static TokenUpgradeNotice>, &'static str> {
    let field = |key: &str| match crate::os_release::field(os_release, key) {
        Some(Ok(value)) => Ok(value),
        Some(Err(())) => Err("os-release gives an empty or unbalanced ID or VERSION_ID"),
        None => Err("os-release names no ID or no VERSION_ID"),
    };
    let id = field("ID")?;
    let version_id = field("VERSION_ID")?;
    Ok(TOKEN_UPGRADE_NOTICES
        .iter()
        .find(|notice| notice.id == id && notice.version_id == version_id))
}

/// [`token_upgrade_notice`] for this host's os-release
/// ([`crate::os_release::read_host`]). `Err` when no such file can be read,
/// so a caller can tell "this release needs no notice" from "the release
/// could not be determined".
pub(crate) fn host_token_upgrade_notice_checked(
) -> std::io::Result<Option<&'static TokenUpgradeNotice>> {
    let text = crate::os_release::read_host()?;
    token_upgrade_notice(&text)
        .map_err(|why| std::io::Error::new(std::io::ErrorKind::InvalidData, why))
}

/// [`host_token_upgrade_notice_checked`] where an unreadable release simply
/// gives no notice: for the arm and status paths, which only add advice.
pub(crate) fn host_token_upgrade_notice() -> Option<&'static TokenUpgradeNotice> {
    host_token_upgrade_notice_checked().ok().flatten()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::os_release::OS_RELEASE_ENV;

    #[test]
    fn an_unreadable_release_is_an_error_not_an_unlisted_release() {
        let _guard = crate::testenv::ENV_LOCK
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        let old = std::env::var_os(OS_RELEASE_ENV);
        let dir = std::env::temp_dir().join(format!("irlume-os-release-{}", std::process::id()));
        std::env::set_var(OS_RELEASE_ENV, dir.join("missing"));
        assert!(host_token_upgrade_notice_checked().is_err());
        assert!(host_token_upgrade_notice().is_none());
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(dir.join("debian"), "ID=debian\nVERSION_ID=13\n").unwrap();
        std::env::set_var(OS_RELEASE_ENV, dir.join("debian"));
        assert!(matches!(host_token_upgrade_notice_checked(), Ok(None)));
        std::fs::write(dir.join("partial"), "ID=fedora\n").unwrap();
        std::env::set_var(OS_RELEASE_ENV, dir.join("partial"));
        assert!(host_token_upgrade_notice_checked().is_err());
        // Restore, not remove: a run with the override set (a simulated
        // NixOS host) keeps it for the tests after this one.
        match old {
            Some(value) => std::env::set_var(OS_RELEASE_ENV, value),
            None => std::env::remove_var(OS_RELEASE_ENV),
        }
        let _ = std::fs::remove_dir_all(&dir);
    }

    const FEDORA_44: &str = "NAME=\"Fedora Linux\"\nVERSION=\"44 (Workstation Edition)\"\n\
                             ID=fedora\nVERSION_ID=44\nPLATFORM_ID=\"platform:f44\"\n\
                             VARIANT_ID=workstation\n";

    #[test]
    fn fedora_43_and_44_are_listed_and_other_releases_are_not() {
        let notice = token_upgrade_notice(FEDORA_44)
            .unwrap()
            .expect("Fedora 44 is listed");
        assert_eq!(notice.release, "Fedora 44");
        assert_eq!(notice.next_release, "Fedora 45");
        // Quoting and field order do not matter.
        assert_eq!(
            token_upgrade_notice("VERSION_ID=\"44\"\nID='fedora'\n").unwrap(),
            Some(notice)
        );
        let notice = token_upgrade_notice("ID=fedora\nVERSION_ID=43\n")
            .unwrap()
            .expect("Fedora 43");
        assert_eq!(notice.release, "Fedora 43");
        assert_eq!(notice.next_release, "Fedora 45");
        for other in [
            "ID=fedora\nVERSION_ID=42\n",
            "ID=fedora\nVERSION_ID=45\n",
            // A derivative carries its own ID even when it is like Fedora.
            "ID=nobara\nID_LIKE=\"rhel centos fedora\"\nVERSION_ID=44\n",
            "ID=debian\nVERSION_ID=\"13\"\n",
        ] {
            assert_eq!(token_upgrade_notice(other), Ok(None), "{other:?}");
        }
        // Without both keys, or with either malformed, the release is
        // unknown, not unlisted.
        for incomplete in [
            "ID=fedora\n",
            "VERSION_ID=44\n",
            "",
            "ID=\nVERSION_ID=44\n",
            "ID=\"\"\nVERSION_ID=44\n",
            "ID=\"fedora\nVERSION_ID=44\n",
            "ID=fedora\nVERSION_ID=44'\n",
            "ID=fedora\nVERSION_ID=\"\n",
        ] {
            assert!(token_upgrade_notice(incomplete).is_err(), "{incomplete:?}");
        }
    }

    #[test]
    fn every_notice_gives_the_forget_step_and_no_rearm() {
        for notice in TOKEN_UPGRADE_NOTICES {
            let advice = notice.advice("alice");
            assert!(
                advice.contains(&format!("Before upgrading to {}", notice.next_release))
                    && advice.contains("log in as alice")
                    && advice.contains("irlume keyring forget"),
                "{advice}"
            );
            // A re-arm on the next release would pick a token again.
            assert!(!advice.contains("irlume keyring arm"), "{advice}");
            assert!(!advice.contains('\u{2014}'), "{advice}");
        }
    }

    #[test]
    fn only_a_reported_token_arm_counts_and_anything_unreported_is_unknown() {
        let info = |armed: bool, kind: Option<KeyringSecretKind>| {
            Ok(Response::KeyringInfo {
                armed,
                policy: None,
                pcrs: Vec::new(),
                drifted: None,
                kind,
            })
        };
        use KeyringSecretKind as K;
        assert_eq!(
            token_armed(&info(true, Some(K::GnomeKeyringToken))),
            Some(true)
        );
        for kind in [K::LoginPassword, K::KdeWalletKey] {
            assert_eq!(
                token_armed(&info(true, Some(kind))),
                Some(false),
                "{kind:?}"
            );
        }
        // Nothing armed, whatever the kind field says.
        assert_eq!(token_armed(&info(false, None)), Some(false));
        assert_eq!(
            token_armed(&info(false, Some(K::GnomeKeyringToken))),
            Some(false)
        );
        // Armed with a kind an older daemon does not report.
        assert_eq!(token_armed(&info(true, None)), None);
        assert_eq!(token_armed(&Ok(Response::HasPassword(true))), None);
        assert_eq!(
            token_armed(&Ok(Response::Error("bad request".into()))),
            None
        );
        assert_eq!(token_armed(&Err("connect: no such file".into())), None);
    }
}

// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright the irlume contributors.

//! Guidance for a keyring secret sealed under the literal PCR 7 policy
//! (Tier 3) where irlume's state directory is not on encrypted storage.
//!
//! The literal PCR 7 policy binds the Secure Boot state only: another
//! operating system signed with the same keys reproduces it. `keyring arm`
//! and `doctor`'s `pcrlock` check name the remedies when the state directory
//! is not on encrypted storage, or when that cannot be established
//! (docs/SECURITY_AT_REST.md, layer 3).

use irlume_common::storage_encryption::StorageEncryption;
use irlume_common::Response;
use std::path::Path;

/// Whether `policy`, as the daemon names an envelope's policy
/// (`PolicyKind::describe`), is the literal PCR policy (Tier 3).
pub(crate) fn is_literal_pcr_policy(policy: &str) -> bool {
    policy == irlume_core::envelope::PolicyKind::PcrLiteral.describe()
}

/// The policy of the keyring secret armed, from a `KeyringMetadata` or
/// `KeyringInfo` reply; `None` when nothing is armed, the daemon did not
/// answer or it did not name the policy.
fn armed_policy(reply: &Result<Response, String>) -> Option<&str> {
    match reply {
        Ok(Response::KeyringInfo {
            armed: true,
            policy: Some(policy),
            ..
        }) => Some(policy),
        _ => None,
    }
}

/// The guidance for a keyring secret sealed under the literal PCR policy,
/// given what the probe found for `state_dir`; `None` when it is on
/// encrypted storage.
fn literal_seal_advice(storage: StorageEncryption, state_dir: &Path) -> Option<String> {
    let dir = state_dir.display();
    let storage = match storage {
        StorageEncryption::Encrypted => return None,
        StorageEncryption::NotEncrypted => format!("{dir} is not on encrypted storage"),
        StorageEncryption::Unknown => {
            format!("irlume could not confirm that {dir} is on encrypted storage")
        }
    };
    Some(format!(
        "The keyring secret is sealed under the literal PCR 7 policy (Tier 3), which binds \
         the Secure Boot state only: another operating system signed with the same keys \
         reproduces it, and {storage}. Prefer a pcrlock policy (Tier 2: provision one \
         with `systemd-pcrlock make-policy` where none is, then run `irlume keyring arm` \
         again) or full-disk encryption unlocked by a passphrase \
         (docs/SECURITY_AT_REST.md)."
    ))
}

/// The guidance for the keyring secret a `KeyringMetadata` reply describes.
/// `probe` answers for `state_dir` and runs only for a secret armed under
/// the literal PCR policy.
pub(crate) fn advice_for(
    reply: &Result<Response, String>,
    state_dir: &Path,
    probe: impl FnOnce(&Path) -> StorageEncryption,
) -> Option<String> {
    let policy = armed_policy(reply)?;
    if !is_literal_pcr_policy(policy) {
        return None;
    }
    literal_seal_advice(probe(state_dir), state_dir)
}

/// [`advice_for`] against irlume's state directory and this system's
/// storage.
pub(crate) fn state_dir_advice_for(reply: &Result<Response, String>) -> Option<String> {
    advice_for(
        reply,
        &irlume_common::state_dir(),
        irlume_common::storage_encryption::path_encryption,
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use irlume_core::envelope::PolicyKind;
    use std::cell::Cell;

    fn armed(policy: Option<String>) -> Result<Response, String> {
        Ok(Response::KeyringInfo {
            armed: true,
            policy,
            pcrs: vec![7],
            drifted: None,
            kind: None,
        })
    }

    const DIR: &str = "/var/lib/irlume";

    #[test]
    fn only_the_literal_policy_label_is_tier_3() {
        assert!(is_literal_pcr_policy("literal PolicyPCR (Tier 3)"));
        assert!(is_literal_pcr_policy(&PolicyKind::PcrLiteral.describe()));
        assert!(!is_literal_pcr_policy(
            &PolicyKind::PcrlockNv { nv_index: 0x1a2b }.describe()
        ));
        assert!(!is_literal_pcr_policy(
            &PolicyKind::Authorized {
                pubkey_pem: String::new(),
                policy_ref: Vec::new(),
            }
            .describe()
        ));
        assert!(!is_literal_pcr_policy(""));
    }

    #[test]
    fn a_tier_3_secret_off_encrypted_storage_gets_the_advice() {
        let reply = armed(Some(PolicyKind::PcrLiteral.describe()));
        let advice = advice_for(&reply, Path::new(DIR), |_| StorageEncryption::NotEncrypted)
            .expect("advice");
        assert!(advice.contains("literal PCR 7 policy (Tier 3)"), "{advice}");
        assert!(advice.contains("another operating system signed with the same keys"));
        assert!(advice.contains("/var/lib/irlume is not on encrypted storage"));
        assert!(advice.contains("pcrlock policy (Tier 2"));
        assert!(advice.contains("`systemd-pcrlock make-policy`"));
        assert!(advice.contains("full-disk encryption unlocked by a passphrase"));
        assert!(!advice.contains('\u{2014}'), "no em dash: {advice}");

        let unknown =
            advice_for(&reply, Path::new(DIR), |_| StorageEncryption::Unknown).expect("advice");
        assert!(
            unknown
                .contains("irlume could not confirm that /var/lib/irlume is on encrypted storage"),
            "{unknown}"
        );
    }

    #[test]
    fn encrypted_storage_or_a_stronger_policy_gets_none() {
        let reply = armed(Some(PolicyKind::PcrLiteral.describe()));
        assert_eq!(
            advice_for(&reply, Path::new(DIR), |_| StorageEncryption::Encrypted),
            None
        );
        let probed = Cell::new(false);
        let pcrlock = armed(Some(PolicyKind::PcrlockNv { nv_index: 0x1a2b }.describe()));
        assert_eq!(
            advice_for(&pcrlock, Path::new(DIR), |_| {
                probed.set(true);
                StorageEncryption::NotEncrypted
            }),
            None
        );
        assert!(!probed.get(), "only a Tier 3 secret probes the storage");
    }

    #[test]
    fn nothing_armed_or_no_answer_gets_none() {
        let never = |_: &Path| -> StorageEncryption { panic!("must not probe") };
        let not_armed = Ok(Response::KeyringInfo {
            armed: false,
            policy: None,
            pcrs: Vec::new(),
            drifted: None,
            kind: None,
        });
        assert_eq!(advice_for(&not_armed, Path::new(DIR), never), None);
        // An armed envelope the daemon could not load names no policy.
        assert_eq!(advice_for(&armed(None), Path::new(DIR), never), None);
        let down: Result<Response, String> = Err("irlumed is not running".to_string());
        assert_eq!(advice_for(&down, Path::new(DIR), never), None);
        let old = Ok(Response::Error("bad request".to_string()));
        assert_eq!(advice_for(&old, Path::new(DIR), never), None);
    }

    #[test]
    fn the_probe_is_asked_about_the_state_directory() {
        let reply = armed(Some(PolicyKind::PcrLiteral.describe()));
        let dir = Path::new("/srv/irlume-state");
        let advice = advice_for(&reply, dir, |asked| {
            assert_eq!(asked, dir);
            StorageEncryption::NotEncrypted
        })
        .expect("advice");
        assert!(advice.contains("/srv/irlume-state is not on encrypted storage"));
    }
}

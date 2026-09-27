// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright the irlume contributors.

//! Guidance for a keyring secret sealed under the literal PCR 7 policy
//! (Tier 3).
//!
//! The literal PCR 7 policy binds the Secure Boot state only: another
//! operating system signed with the same keys reproduces it. `keyring arm`
//! and `doctor`'s `pcrlock` check name the remedies (docs/SECURITY_AT_REST.md,
//! layer 3). Where the state directory is not on encrypted storage, or that
//! cannot be established, it is a warning. Where it is on dm-crypt, the
//! guidance still shows, as information: the storage alone cannot tell
//! whether that volume asks for a passphrase or PIN or unlocks from the TPM
//! or a key file, and only the first protects these secrets.

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

/// Guidance for a keyring secret sealed under the literal PCR policy.
#[derive(Debug, PartialEq, Eq)]
pub(crate) struct SealAdvice {
    /// The text shown after `keyring arm` and as the doctor detail.
    pub(crate) text: String,
    /// A warning: the state directory is not on encrypted storage, or that
    /// could not be established. Otherwise information: it is on dm-crypt,
    /// whose unlock method the storage does not show.
    pub(crate) warn: bool,
}

/// The guidance for a keyring secret sealed under the literal PCR policy,
/// given what the probe found for `state_dir`.
fn literal_seal_advice(storage: StorageEncryption, state_dir: &Path) -> SealAdvice {
    let dir = state_dir.display();
    let (storage, warn) = match storage {
        StorageEncryption::Encrypted => (
            format!(
                "{dir} is on encrypted storage, which protects it only if that volume asks \
                 for a passphrase or PIN to unlock rather than unlocking from the TPM or a \
                 key file alone"
            ),
            false,
        ),
        StorageEncryption::NotEncrypted => (format!("{dir} is not on encrypted storage"), true),
        StorageEncryption::Unknown => (
            format!("irlume could not confirm that {dir} is on encrypted storage"),
            true,
        ),
    };
    SealAdvice {
        text: format!(
            "The keyring secret is sealed under the literal PCR 7 policy (Tier 3), which binds \
             the Secure Boot state only: another operating system signed with the same keys \
             reproduces it, and {storage}. Prefer a pcrlock policy (Tier 2: provision one \
             with `systemd-pcrlock make-policy` where none is, then run `irlume keyring arm` \
             again) or full-disk encryption unlocked by a passphrase \
             (docs/SECURITY_AT_REST.md)."
        ),
        warn,
    }
}

/// The guidance for the keyring secret a `KeyringMetadata` reply describes.
/// `probe` answers for `state_dir` and runs only for a secret armed under
/// the literal PCR policy.
pub(crate) fn advice_for(
    reply: &Result<Response, String>,
    state_dir: &Path,
    probe: impl FnOnce(&Path) -> StorageEncryption,
) -> Option<SealAdvice> {
    let policy = armed_policy(reply)?;
    if !is_literal_pcr_policy(policy) {
        return None;
    }
    Some(literal_seal_advice(probe(state_dir), state_dir))
}

/// [`advice_for`] against irlume's state directory and this system's
/// storage.
pub(crate) fn state_dir_advice_for(reply: &Result<Response, String>) -> Option<SealAdvice> {
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
        assert!(advice.warn);
        let advice = advice.text;
        assert!(advice.contains("literal PCR 7 policy (Tier 3)"), "{advice}");
        assert!(advice.contains("another operating system signed with the same keys"));
        assert!(advice.contains("/var/lib/irlume is not on encrypted storage"));
        assert!(advice.contains("pcrlock policy (Tier 2"));
        assert!(advice.contains("`systemd-pcrlock make-policy`"));
        assert!(advice.contains("full-disk encryption unlocked by a passphrase"));
        assert!(!advice.contains('\u{2014}'), "no em dash: {advice}");

        let unknown =
            advice_for(&reply, Path::new(DIR), |_| StorageEncryption::Unknown).expect("advice");
        assert!(unknown.warn);
        assert!(
            unknown
                .text
                .contains("irlume could not confirm that /var/lib/irlume is on encrypted storage"),
            "{}",
            unknown.text
        );
    }

    #[test]
    fn encrypted_storage_informs_and_a_stronger_policy_gets_none() {
        // dm-crypt does not show whether the volume asks for a passphrase or
        // unlocks from the TPM or a key file, so the guidance stays, as
        // information naming that condition.
        let reply = armed(Some(PolicyKind::PcrLiteral.describe()));
        let encrypted = advice_for(&reply, Path::new(DIR), |_| StorageEncryption::Encrypted)
            .expect("advice on encrypted storage");
        assert!(!encrypted.warn);
        assert!(
            encrypted.text.contains(
                "/var/lib/irlume is on encrypted storage, which protects it only if that \
                 volume asks for a passphrase or PIN to unlock"
            ),
            "{}",
            encrypted.text
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
        assert!(advice
            .text
            .contains("/srv/irlume-state is not on encrypted storage"));
    }
}

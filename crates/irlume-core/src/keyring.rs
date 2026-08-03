// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright the irlume contributors.

//! TPM-sealed login password for keyring/wallet unlock.
//!
//! After a face login there is no typed password for `pam_gnome_keyring` /
//! `pam_kwallet` to unlock the wallet with. We bridge that gap: at setup the
//! user's login password is sealed in the TPM ([`tpm`]), and on a successful
//! live face match `irlumed` unseals it and hands it to the PAM module, which
//! sets it as `PAM_AUTHTOK` so the downstream keyring module unlocks the wallet.
//!
//! The sealed envelope is stored ROOT-ONLY under `/var/lib/irlume/keyring`
//! (override `IRLUME_KEYRING_DIR`), deliberately NOT in the user's home (where
//! the templates live), so the wrapped login secret is never under user control.
//! It is TPM-wrapped regardless, but defence in depth.

use crate::envelope::{SealedEnvelope, SecretKind};
use crate::tpm;
use irlume_common::{Error, Result};
use std::path::PathBuf;
use zeroize::Zeroizing;

/// Root-only directory for sealed-password envelopes.
fn keyring_dir() -> PathBuf {
    std::env::var("IRLUME_KEYRING_DIR")
        .map(PathBuf::from)
        .unwrap_or_else(|_| PathBuf::from(irlume_common::STATE_DIR).join("keyring"))
}

pub fn envelope_path(user: &str) -> PathBuf {
    keyring_dir().join(format!("{user}.json"))
}

/// Seal `password` for `user` so a later face login can release it. Overwrites
/// any existing sealed password (re-arming, e.g. after a password change).
pub fn seal_password(user: &str, password: &[u8]) -> Result<()> {
    seal_secret(user, password, SecretKind::LoginPassword)
}

/// Seal `secret` for `user`, recording what it is.
///
/// The kind is stamped here rather than in [`tpm::seal`], which wraps bytes and
/// has no business knowing what they mean.
pub fn seal_secret(user: &str, secret: &[u8], kind: SecretKind) -> Result<()> {
    if secret.is_empty() {
        return Err(Error::Protocol(format!(
            "refusing to seal an empty {}",
            kind.describe()
        )));
    }
    if kind == SecretKind::KdeWalletKey && secret.len() != crate::kwallet::KEY_LEN {
        // ksecretd reads exactly KEY_LEN bytes off the pipe. Sealing any other
        // length produces an envelope that can never open the wallet, and the
        // failure would not show up until a login.
        return Err(Error::Protocol(format!(
            "a KDE wallet key must be exactly {} bytes, got {}",
            crate::kwallet::KEY_LEN,
            secret.len()
        )));
    }
    let mut env = tpm::seal(secret)?;
    env.secret = kind;
    env.save(&envelope_path(user))
}

/// Derive the secret of `kind` that `user` should have sealed, from their
/// VERIFIED login password.
///
/// For [`SecretKind::KdeWalletKey`] this is PBKDF2 over the wallet salt in
/// `home`, matching what `pam_kwallet5` computes. Note what that implies after
/// a password change: the wallet is still keyed to the OLD derived key until
/// the user re-keys it in KWallet, so deriving from the new password yields a
/// key that does not open it. That is not a regression we introduce; it is
/// exactly what `pam_kwallet5` does with the new password, and the user fixes
/// it the same way, by changing the wallet password.
pub fn derive_secret(
    kind: SecretKind,
    password: &[u8],
    home: &std::path::Path,
) -> Result<Zeroizing<Vec<u8>>> {
    match kind {
        SecretKind::LoginPassword => Ok(Zeroizing::new(password.to_vec())),
        SecretKind::KdeWalletKey => crate::kwallet::derive_for_home(password, home),
    }
}

/// What kind of secret `user` currently has armed, if any.
pub fn sealed_kind(user: &str) -> Option<SecretKind> {
    SealedEnvelope::load(&envelope_path(user))
        .ok()
        .map(|e| e.secret)
}

/// Release `user`'s sealed password from the TPM. Fails if none is armed or if
/// the bound PCR policy is no longer satisfied (e.g. Secure Boot config changed);
/// the caller then falls back to the typed password and the wallet stays
/// locked until the user re-arms.
pub fn unseal_password(user: &str) -> Result<Zeroizing<Vec<u8>>> {
    let path = envelope_path(user);
    if !path.exists() {
        return Err(Error::Policy(format!(
            "no sealed password for '{user}': run `irlume keyring arm`"
        )));
    }
    let env = SealedEnvelope::load(&path)?;
    tpm::unseal(&env)
}

/// Outcome of [`reseal_password`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Reseal {
    /// No sealed password is armed for this user; nothing was done. We never
    /// auto-arm from the login hook; arming stays an explicit `keyring arm`.
    NotArmed,
    /// The existing envelope already unseals to this exact password under the
    /// current PCR policy; left untouched (the steady-state on every login).
    Unchanged,
    /// The envelope was re-sealed against the current PCR policy. Either it no
    /// longer unsealed (PCRs moved: dbx/Secure Boot update) or the password
    /// differed (the user changed it). This is the self-heal.
    Resealed,
    /// The password and PCR policy were unchanged, but a stronger sealing tier
    /// became available (e.g. signed-PCR started working), so the envelope was
    /// re-sealed to that tier. Lets an existing arm climb to Tier 1 on the next
    /// login with no `keyring arm` from the user.
    Upgraded,
}

/// Self-heal: re-seal `user`'s login password against the *current* PCR policy,
/// but only when it's both armed and actually stale.
///
/// SAFETY CONTRACT: the caller MUST pass only a password that has been
/// VERIFIED correct (i.e. `pam_unix` accepted it). This function cannot tell a
/// genuine new password from a typo on its own; that guarantee comes from
/// WHERE it is called: the PAM **session** phase, which only runs after
/// authentication has already succeeded. (An earlier version called it from an
/// `optional` auth line that also ran after a FAILED password attempt, which let
/// a typo overwrite the good seal; that path has been deleted. Never call this
/// anywhere auth success is not already established.)
///
/// Given a verified password it writes nothing in the common case:
///   * not armed            -> `NotArmed` (never auto-arm)
///   * unseals to same `pw` -> `Unchanged` (PCRs still match, password same)
///   * unseal fails OR diff  -> reseal, `Resealed`
///
/// The "unseal fails" branch is what fixes a dbx/Secure-Boot update: the old
/// envelope's PCR7 policy no longer satisfies, so we rebind to today's PCRs
/// using the password the user just proved (via a successful login) they know.
pub fn reseal_password(user: &str, password: &[u8], home: &std::path::Path) -> Result<Reseal> {
    if password.is_empty() {
        return Err(Error::Protocol(
            "refusing to reseal an empty password".into(),
        ));
    }
    if !has_sealed_password(user) {
        return Ok(Reseal::NotArmed);
    }
    // Reseal whatever kind is already armed. Deriving the wrong kind here would
    // quietly replace a working envelope with one that opens nothing, and the
    // damage would not show up until the next login.
    let kind = sealed_kind(user).unwrap_or_default();
    let secret = match derive_secret(kind, password, home) {
        Ok(s) => s,
        // A KDE wallet key cannot be derived without the salt. Leaving the
        // existing envelope alone is the safe outcome: it may still be valid,
        // and overwriting it on a machine where the salt has gone missing would
        // destroy a working arm.
        Err(e) => {
            return Err(Error::Policy(format!(
                "cannot reseal the {} for '{user}': {e}",
                kind.describe()
            )))
        }
    };
    let password = secret.as_slice();
    // If the current envelope still unseals to the same secret, there is nothing
    // to reseal for correctness; don't churn the TPM on every single login.
    if let Ok(current) = unseal_password(user) {
        if current.as_slice() == password {
            // One exception: if a strictly stronger sealing tier became
            // available since this envelope was written (e.g. signed-PCR now
            // works), climb to it. This is how an existing arm reaches Tier 1
            // after a fix/config change without the user re-arming. Only fires
            // when an upgrade is actually possible, and only adopts the new
            // envelope if the ladder genuinely produced a stronger tier (it
            // round-trip-verifies internally), so a machine already at its best
            // tier writes nothing.
            if let Ok(env) = SealedEnvelope::load(&envelope_path(user)) {
                if tpm::stronger_tier_available_than(&env.policy) {
                    let mut candidate = tpm::seal(password)?;
                    // Carry the kind across the upgrade. tpm::seal defaults it,
                    // so without this a tier climb would rewrite a wallet-key
                    // envelope as a login-password one and the next login would
                    // hand 56 bytes of key to pam_gnome_keyring as an AUTHTOK.
                    candidate.secret = kind;
                    if candidate.policy.strength_rank() > env.policy.strength_rank() {
                        candidate.save(&envelope_path(user))?;
                        return Ok(Reseal::Upgraded);
                    }
                }
            }
            return Ok(Reseal::Unchanged);
        }
    }
    seal_secret(user, password, kind)?;
    Ok(Reseal::Resealed)
}

/// Whether `user` has a sealed password armed.
pub fn has_sealed_password(user: &str) -> bool {
    envelope_path(user).exists()
}

/// Erase `user`'s sealed password (disarms keyring unlock). Idempotent.
pub fn forget_password(user: &str) -> Result<()> {
    let path = envelope_path(user);
    if path.exists() {
        std::fs::remove_file(&path).map_err(|e| Error::Io(e.to_string()))?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn envelope_path_under_keyring_dir() {
        let _g = crate::testenv::ENV_LOCK.lock().unwrap();
        std::env::set_var("IRLUME_KEYRING_DIR", "/tmp/irlume-kr-test");
        assert_eq!(
            envelope_path("alice"),
            PathBuf::from("/tmp/irlume-kr-test/alice.json")
        );
        std::env::remove_var("IRLUME_KEYRING_DIR");
    }

    /// Full arm → unseal round-trip through the keyring layer on the real TPM.
    /// Ignored: needs /dev/tpmrm0.
    #[test]
    #[ignore = "requires a TPM: real /dev/tpmrm0, or swtpm via IRLUME_TCTI (CI does this)"]
    fn arm_and_unseal_roundtrip() {
        let _g = crate::testenv::ENV_LOCK.lock().unwrap();
        let dir = "/tmp/irlume-kr-rt";
        std::env::set_var("IRLUME_KEYRING_DIR", dir);
        let _ = std::fs::remove_dir_all(dir);
        let pw = b"correct horse battery staple";
        seal_password("tester", pw).expect("seal");
        assert!(has_sealed_password("tester"));
        let got = unseal_password("tester").expect("unseal");
        assert_eq!(&*got, pw);
        forget_password("tester").expect("forget");
        assert!(!has_sealed_password("tester"));
        std::env::remove_var("IRLUME_KEYRING_DIR");
    }

    /// On signed-UKI hardware, an envelope armed under a weaker tier auto-upgrades
    /// to Tier-1 on the next login-time reseal, with no `keyring arm` from the
    /// user. This is the migration path after signed-PCR started working.
    #[test]
    #[ignore = "requires a real TPM + fresh systemd signed-PCR artifacts (UKI/systemd-boot)"]
    fn reseal_auto_upgrades_weaker_tier_to_signed() {
        use crate::envelope::{PolicyKind, SealedEnvelope};
        let _g = crate::testenv::ENV_LOCK.lock().unwrap();
        let dir = "/tmp/irlume-kr-upgrade";
        std::env::set_var("IRLUME_KEYRING_DIR", dir);
        let _ = std::fs::remove_dir_all(dir);
        let pw = b"correct horse battery staple";
        // Simulate an "old" arm under the weakest tier (literal PCR 7).
        tpm::seal_with_pcrs(pw, &[7])
            .unwrap()
            .save(&envelope_path("tester"))
            .unwrap();
        assert_eq!(
            SealedEnvelope::load(&envelope_path("tester"))
                .unwrap()
                .policy
                .strength_rank(),
            1,
            "precondition: sealed at Tier 3 (literal)"
        );
        // A login-time reseal with the same verified password upgrades the tier.
        assert_eq!(
            // A login-password envelope never reads `home`: derive_secret
            // returns the password unchanged.
            reseal_password("tester", pw, std::path::Path::new("/nonexistent")).unwrap(),
            Reseal::Upgraded
        );
        let env = SealedEnvelope::load(&envelope_path("tester")).unwrap();
        assert!(
            matches!(env.policy, PolicyKind::Authorized { .. }),
            "should climb to Tier 1, got {:?}",
            env.policy
        );
        assert_eq!(&*unseal_password("tester").unwrap(), pw, "still unseals");
        forget_password("tester").unwrap();
        std::env::remove_var("IRLUME_KEYRING_DIR");
    }

    #[test]
    fn a_wallet_key_must_be_exactly_the_length_ksecretd_reads() {
        // Caught before the TPM is involved, because a wrong-length seal is only
        // discoverable at a login otherwise: ksecretd blocks on a short key and
        // truncates a long one, and neither says anything.
        let _g = crate::testenv::ENV_LOCK.lock().unwrap();
        std::env::set_var("IRLUME_KEYRING_DIR", "/tmp/irlume-kr-len");
        for bad in [crate::kwallet::KEY_LEN - 1, crate::kwallet::KEY_LEN + 1] {
            assert!(
                seal_secret("lentest", &vec![7u8; bad], SecretKind::KdeWalletKey).is_err(),
                "{bad} bytes was accepted as a wallet key"
            );
        }
        std::env::remove_var("IRLUME_KEYRING_DIR");
    }

    /// A wallet-key envelope must stay a wallet-key envelope across every path
    /// that rewrites it. Both rewrite sites in `reseal_password` build a fresh
    /// envelope via `tpm::seal`, which defaults the kind, so a missed stamp
    /// downgrades the envelope to `LoginPassword` and the next login hands 56
    /// bytes of raw key to `pam_gnome_keyring` as an `AUTHTOK`.
    #[test]
    #[ignore = "requires a TPM: real /dev/tpmrm0, or swtpm via IRLUME_TCTI (CI does this)"]
    fn resealing_preserves_the_secret_kind() {
        let _g = crate::testenv::ENV_LOCK.lock().unwrap();
        let dir = "/tmp/irlume-kr-kind";
        std::env::set_var("IRLUME_KEYRING_DIR", dir);
        let _ = std::fs::remove_dir_all(dir);

        // A home with a real salt, so the wallet key can actually be derived.
        let home = std::path::PathBuf::from("/tmp/irlume-kr-kind-home");
        let _ = std::fs::remove_dir_all(&home);
        std::fs::create_dir_all(crate::kwallet::salt_path(&home).parent().unwrap()).unwrap();
        std::fs::write(crate::kwallet::salt_path(&home), [0x33u8; crate::kwallet::SALT_LEN])
            .unwrap();

        let pw = b"a-login-password";
        let key = crate::kwallet::derive_for_home(pw, &home).expect("derive");

        // Seed at the WEAKEST tier on purpose. Sealing normally lands on this
        // machine's best tier, so the reseal returns Unchanged and the tier-climb
        // rewrite never runs: the assertion below then passes without observing
        // the path it names. Verified by breaking the stamp, which went unnoticed
        // until this seeding was added.
        let mut weak = tpm::seal_with_pcrs(&key, &[7]).expect("seal at Tier 3");
        weak.secret = SecretKind::KdeWalletKey;
        weak.save(&envelope_path("kindtest")).expect("arm");
        assert_eq!(sealed_kind("kindtest"), Some(SecretKind::KdeWalletKey));

        // Same password, weaker tier on disk -> the tier-climb rewrite.
        let first = reseal_password("kindtest", pw, &home).expect("reseal");
        assert_eq!(
            first,
            Reseal::Upgraded,
            "expected the tier-climb rewrite; without it this test cannot see \
             whether that path preserves the kind"
        );
        assert_eq!(
            sealed_kind("kindtest"),
            Some(SecretKind::KdeWalletKey),
            "the {first:?} path dropped the secret kind"
        );

        // A changed password takes the Resealed path, which rebuilds the
        // envelope from scratch.
        assert_eq!(
            reseal_password("kindtest", b"a-different-password", &home).unwrap(),
            Reseal::Resealed
        );
        assert_eq!(
            sealed_kind("kindtest"),
            Some(SecretKind::KdeWalletKey),
            "the Resealed path dropped the secret kind"
        );
        // And it holds the key derived from the NEW password, not the password.
        let expect = crate::kwallet::derive_for_home(b"a-different-password", &home).unwrap();
        assert_eq!(&*unseal_password("kindtest").unwrap(), &*expect);

        forget_password("kindtest").unwrap();
        let _ = std::fs::remove_dir_all(&home);
        std::env::remove_var("IRLUME_KEYRING_DIR");
    }

    /// reseal: NotArmed when nothing sealed, Unchanged when same pw still
    /// unseals, Resealed when the password differs. The PCR-moved -> Resealed
    /// branch can't be exercised without changing PCRs, but the differ branch
    /// hits the same reseal path. (Callers gate this on a verified password via
    /// the PAM session phase; see the SAFETY CONTRACT on `reseal_password`.)
    #[test]
    #[ignore = "requires a TPM: real /dev/tpmrm0, or swtpm via IRLUME_TCTI (CI does this)"]
    fn reseal_only_when_stale() {
        let _g = crate::testenv::ENV_LOCK.lock().unwrap();
        let dir = "/tmp/irlume-kr-reseal";
        std::env::set_var("IRLUME_KEYRING_DIR", dir);
        let _ = std::fs::remove_dir_all(dir);
        // Unused for login-password envelopes; see the note in the tier test.
        let home = std::path::Path::new("/nonexistent");

        // Not armed -> nothing happens.
        assert_eq!(
            reseal_password("rt", b"whatever", home).unwrap(),
            Reseal::NotArmed
        );

        seal_password("rt", b"first-password").expect("arm");
        // Same password still unseals under current PCRs -> no rewrite.
        assert_eq!(
            reseal_password("rt", b"first-password", home).unwrap(),
            Reseal::Unchanged
        );
        // Different password (simulates a password change) -> reseal.
        assert_eq!(
            reseal_password("rt", b"second-password", home).unwrap(),
            Reseal::Resealed
        );
        // And it now unseals to the new one.
        assert_eq!(&*unseal_password("rt").unwrap(), b"second-password");

        forget_password("rt").expect("forget");
        std::env::remove_var("IRLUME_KEYRING_DIR");
    }
}

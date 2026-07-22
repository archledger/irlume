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

use crate::envelope::SealedEnvelope;
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
    if password.is_empty() {
        return Err(Error::Protocol("refusing to seal an empty password".into()));
    }
    let env = tpm::seal(password)?;
    env.save(&envelope_path(user))
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
pub fn reseal_password(user: &str, password: &[u8]) -> Result<Reseal> {
    if password.is_empty() {
        return Err(Error::Protocol(
            "refusing to reseal an empty password".into(),
        ));
    }
    if !has_sealed_password(user) {
        return Ok(Reseal::NotArmed);
    }
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
                    let candidate = tpm::seal(password)?;
                    if candidate.policy.strength_rank() > env.policy.strength_rank() {
                        candidate.save(&envelope_path(user))?;
                        return Ok(Reseal::Upgraded);
                    }
                }
            }
            return Ok(Reseal::Unchanged);
        }
    }
    seal_password(user, password)?;
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
        assert_eq!(reseal_password("tester", pw).unwrap(), Reseal::Upgraded);
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

        // Not armed -> nothing happens.
        assert_eq!(
            reseal_password("rt", b"whatever").unwrap(),
            Reseal::NotArmed
        );

        seal_password("rt", b"first-password").expect("arm");
        // Same password still unseals under current PCRs -> no rewrite.
        assert_eq!(
            reseal_password("rt", b"first-password").unwrap(),
            Reseal::Unchanged
        );
        // Different password (simulates a password change) -> reseal.
        assert_eq!(
            reseal_password("rt", b"second-password").unwrap(),
            Reseal::Resealed
        );
        // And it now unseals to the new one.
        assert_eq!(&*unseal_password("rt").unwrap(), b"second-password");

        forget_password("rt").expect("forget");
        std::env::remove_var("IRLUME_KEYRING_DIR");
    }
}

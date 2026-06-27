//! TPM-sealed login password for keyring/wallet unlock.
//!
//! After a face login there is no typed password for `pam_gnome_keyring` /
//! `pam_kwallet` to unlock the wallet with. We bridge that gap: at setup the
//! user's login password is sealed in the TPM ([`tpm`]), and on a successful
//! live face match `irlumed` unseals it and hands it to the PAM module, which
//! sets it as `PAM_AUTHTOK` so the downstream keyring module unlocks the wallet.
//!
//! The sealed envelope is stored ROOT-ONLY under `/var/lib/irlume/keyring`
//! (override `IRLUME_KEYRING_DIR`) — deliberately NOT in the user's home (where
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
/// the bound PCR policy is no longer satisfied (e.g. Secure Boot config changed)
/// — the caller then falls back to the typed password and the wallet stays
/// locked until the user re-arms.
pub fn unseal_password(user: &str) -> Result<Zeroizing<Vec<u8>>> {
    let path = envelope_path(user);
    if !path.exists() {
        return Err(Error::Policy(format!(
            "no sealed password for '{user}' — run `irlume keyring arm`"
        )));
    }
    let env = SealedEnvelope::load(&path)?;
    tpm::unseal(&env)
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
    #[ignore = "requires real TPM (/dev/tpmrm0)"]
    fn arm_and_unseal_roundtrip() {
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
}

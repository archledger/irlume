// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright the irlume contributors.

//! The KDE wallet key: what `ksecretd` actually accepts, and how to derive it.
//!
//! KDE's secret store never sees the login password. `pam_kwallet5` runs the
//! password through PBKDF2 and hands `ksecretd` the resulting bytes over a
//! pipe; `ksecretd`'s `waitForHash()` reads exactly [`KEY_LEN`] of them and
//! opens the wallet with that. The password is only the KDF input, and it is
//! discarded before the daemon is reached.
//!
//! That is why this module exists. Sealing the derived key instead of the login
//! password removes the password from the sealed envelope entirely, with no
//! wallet re-key and no migration of the wallet itself: the wallet stays keyed
//! to the same bytes it always was, and a typed password still opens it through
//! the normal `pam_kwallet5` path because the KDF input is unchanged. A leaked
//! envelope then yields a wallet key, which is useless anywhere else, instead of
//! a Unix password that is not.
//!
//! GNOME has no equivalent. `pam_gnome_keyring` passes the password string
//! itself and `gkd_login_unlock()` builds the credential from that string, so
//! there is no derived intermediate for us to seal in its place. See #250.
//!
//! Every constant here is a wire-format constant shared with software we do not
//! ship. Changing one silently produces a key that `ksecretd` rejects, so each
//! cites its source.

use irlume_common::{Error, Result};
use std::path::{Path, PathBuf};
use zeroize::Zeroizing;

// The wire constants live in irlume-common so the handoff helper can use them
// without this crate's TPM and inference dependencies, and so both sides of the
// handoff read one definition.
pub use irlume_common::kwallet_wire::{ITERATIONS, KEY_LEN, SALT_LEN};

/// Path of the salt `pam_kwallet5` derives against, relative to `$HOME`.
///
/// Still `kwalletd` on disk even though the daemon that reads it is now
/// `ksecretd`; KWallet became a compatibility shim over the Secret Service and
/// the storage location did not move.
const SALT_RELPATH: &str = ".local/share/kwalletd/kdewallet.salt";

/// Absolute path of `home`'s wallet salt file.
pub fn salt_path(home: &Path) -> PathBuf {
    home.join(SALT_RELPATH)
}

/// Read `home`'s wallet salt.
///
/// Deliberately does NOT create a missing salt, unlike `pam_kwallet5`, which
/// creates one on first login. Absent salt means this user has no KDE wallet
/// yet, and inventing one here would derive a key that opens nothing while
/// looking like a successful arm.
pub fn read_salt(home: &Path) -> Result<Zeroizing<Vec<u8>>> {
    let path = salt_path(home);
    let raw = std::fs::read(&path).map_err(|e| {
        Error::Policy(format!(
            "no KDE wallet salt at {}: {e}. Log into a Plasma session once so \
             the wallet exists, then arm again",
            path.display()
        ))
    })?;
    if raw.len() < SALT_LEN {
        return Err(Error::Policy(format!(
            "wallet salt at {} is {} bytes, expected at least {SALT_LEN}",
            path.display(),
            raw.len()
        )));
    }
    // pam_kwallet5 reads SALT_LEN and derives over exactly that, so a longer
    // file must be truncated rather than passed through, or we derive a
    // different key from the same file it used.
    Ok(Zeroizing::new(raw[..SALT_LEN].to_vec()))
}

/// Derive the wallet key `ksecretd` expects from `secret` and `salt`.
///
/// PBKDF2-HMAC-SHA512, [`ITERATIONS`] rounds, [`KEY_LEN`] output. This is
/// `kwallet_hash()` in `pam_kwallet.c`, which calls `gcry_kdf_derive` with
/// `GCRY_KDF_PBKDF2` and `GCRY_MD_SHA512`.
pub fn derive_key(secret: &[u8], salt: &[u8]) -> Result<Zeroizing<Vec<u8>>> {
    if salt.len() != SALT_LEN {
        return Err(Error::Protocol(format!(
            "wallet salt must be exactly {SALT_LEN} bytes, got {}",
            salt.len()
        )));
    }
    let mut out = Zeroizing::new(vec![0u8; KEY_LEN]);
    pbkdf2::pbkdf2_hmac::<sha2::Sha512>(secret, salt, ITERATIONS, &mut out);
    Ok(out)
}

/// Derive `home`'s wallet key from the login password.
pub fn derive_for_home(password: &[u8], home: &Path) -> Result<Zeroizing<Vec<u8>>> {
    let salt = read_salt(home)?;
    derive_key(password, &salt)
}

/// Which secret to seal for a user, judged by what they actually have.
///
/// A KDE wallet key only makes sense where there is a KDE wallet, and it must
/// not be chosen on a machine that also runs gnome-keyring: that backend takes
/// the password string itself, so sealing a wallet key there would leave the
/// GNOME login keyring locked with nothing to unlock it.
///
/// The conservative direction is [`crate::envelope::SecretKind::LoginPassword`],
/// the behaviour before #250, so anything ambiguous resolves to it.
pub fn detect_kind(home: &Path) -> crate::envelope::SecretKind {
    use crate::envelope::SecretKind;
    let has_kde = salt_path(home).exists();
    // gnome-keyring's login keyring, the thing that would break.
    let has_gnome = home.join(".local/share/keyrings/login.keyring").exists();
    if has_kde && !has_gnome {
        SecretKind::KdeWalletKey
    } else {
        SecretKind::LoginPassword
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn derived_key_is_the_length_ksecretd_reads() {
        let salt = vec![0x5a; SALT_LEN];
        let key = derive_key(b"hunter2", &salt).expect("derive");
        assert_eq!(
            key.len(),
            KEY_LEN,
            "ksecretd's waitForHash() reads exactly {KEY_LEN} bytes; a shorter \
             key leaves it blocking and a longer one silently truncates"
        );
    }

    #[test]
    fn a_wrong_length_salt_is_refused_rather_than_padded() {
        // Silently accepting a short salt would derive a key that opens nothing,
        // which surfaces as a wallet prompt at login with no error anywhere.
        assert!(derive_key(b"hunter2", &[0x5a; SALT_LEN - 1]).is_err());
        assert!(derive_key(b"hunter2", &[0x5a; SALT_LEN + 1]).is_err());
    }

    #[test]
    fn the_same_password_and_salt_give_the_same_key() {
        let salt = vec![0x11; SALT_LEN];
        assert_eq!(
            derive_key(b"pw", &salt).unwrap().to_vec(),
            derive_key(b"pw", &salt).unwrap().to_vec()
        );
    }

    #[test]
    fn a_different_salt_gives_a_different_key() {
        // The salt is per-user and regenerated when a home directory is reset,
        // which is the case that would otherwise produce a stale sealed key.
        let a = derive_key(b"pw", &[0x11; SALT_LEN]).unwrap().to_vec();
        let b = derive_key(b"pw", &[0x22; SALT_LEN]).unwrap().to_vec();
        assert_ne!(a, b);
    }

    /// The derivation must agree with the one `pam_kwallet5` performs, byte for
    /// byte, or the sealed key opens nothing.
    ///
    /// This vector was produced independently of this code, from libgcrypt's own
    /// PBKDF2 via Python's `hashlib.pbkdf2_hmac("sha512", ...)`, using the same
    /// parameters `kwallet_hash()` passes to `gcry_kdf_derive`. It pins the
    /// three constants that have no in-tree definition to check against.
    #[test]
    fn derivation_matches_an_independently_computed_vector() {
        let salt: Vec<u8> = (0..SALT_LEN as u8).collect();
        let key = derive_key(b"kw-orig-pass-5518", &salt).expect("derive");
        assert_eq!(
            hex(&key),
            "f96e0dc4f5b8558f05adbad5ecb040b9cc16573cd2395e0162f0e2597ee3946c\
             e596adeff3a0956bd442250e7149e1cec92269cf93057462",
            "PBKDF2-HMAC-SHA512 / {ITERATIONS} rounds / {KEY_LEN} bytes"
        );
    }

    fn hex(b: &[u8]) -> String {
        b.iter().map(|x| format!("{x:02x}")).collect()
    }

    /// Detection has to be conservative in both directions: no KDE wallet means
    /// there is nothing a wallet key could open, and a machine running both
    /// backends must keep the password, or its GNOME login keyring is stranded.
    #[test]
    fn detect_kind_only_picks_the_wallet_key_on_a_kde_only_home() {
        use crate::envelope::SecretKind;
        let base = std::env::temp_dir().join(format!("irlume-detect-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&base);

        let mk = |name: &str, kde: bool, gnome: bool| {
            let h = base.join(name);
            if kde {
                std::fs::create_dir_all(salt_path(&h).parent().unwrap()).unwrap();
                std::fs::write(salt_path(&h), [0u8; SALT_LEN]).unwrap();
            }
            if gnome {
                let g = h.join(".local/share/keyrings");
                std::fs::create_dir_all(&g).unwrap();
                std::fs::write(g.join("login.keyring"), b"x").unwrap();
            }
            std::fs::create_dir_all(&h).unwrap();
            h
        };

        assert_eq!(
            detect_kind(&mk("neither", false, false)),
            SecretKind::LoginPassword
        );
        assert_eq!(
            detect_kind(&mk("gnome", false, true)),
            SecretKind::LoginPassword
        );
        assert_eq!(
            detect_kind(&mk("both", true, true)),
            SecretKind::LoginPassword
        );
        assert_eq!(
            detect_kind(&mk("kde", true, false)),
            SecretKind::KdeWalletKey
        );
        let _ = std::fs::remove_dir_all(&base);
    }

    #[test]
    fn a_missing_salt_is_an_error_rather_than_a_freshly_invented_one() {
        // pam_kwallet5 creates a missing salt; we must not. No salt means no
        // wallet, and a key derived against an invented salt opens nothing
        // while `keyring arm` reports success.
        let dir = std::env::temp_dir().join(format!("irlume-kwallet-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).expect("mkdir");
        let err = read_salt(&dir).expect_err("a missing salt must not be invented");
        assert!(
            !salt_path(&dir).exists(),
            "read_salt created {} instead of failing",
            salt_path(&dir).display()
        );
        assert!(
            format!("{err}").contains("Plasma"),
            "the error should tell the user how to get a wallet, got: {err}"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn a_salt_file_longer_than_the_derivation_uses_is_truncated_not_hashed_whole() {
        // pam_kwallet5 reads SALT_LEN bytes and derives over exactly those. If we
        // hashed a longer file whole we would get a different key from the same
        // file it used, and the wallet would never open.
        let dir = std::env::temp_dir().join(format!("irlume-kwallet-long-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(salt_path(&dir).parent().unwrap()).expect("mkdir");
        let mut long = vec![0x7u8; SALT_LEN];
        long.extend_from_slice(b"trailing bytes pam_kwallet5 never reads");
        std::fs::write(salt_path(&dir), &long).expect("write salt");

        let via_file = derive_for_home(b"pw", &dir).expect("derive");
        let via_prefix = derive_key(b"pw", &long[..SALT_LEN]).expect("derive");
        assert_eq!(via_file.to_vec(), via_prefix.to_vec());
        let _ = std::fs::remove_dir_all(&dir);
    }
}

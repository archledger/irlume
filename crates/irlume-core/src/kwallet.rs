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
use std::path::Path;
use zeroize::Zeroizing;

// The wire constants live in irlume-common so the handoff helper can use them
// without this crate's TPM and inference dependencies, and so both sides of the
// handoff read one definition.
pub use irlume_common::kwallet_wire::{ITERATIONS, KEY_LEN, SALT_LEN};

/// Derive the wallet key `ksecretd` expects from `secret` and `salt`.
///
/// PBKDF2-HMAC-SHA512, [`ITERATIONS`] rounds, [`KEY_LEN`] output. This is
/// `kwallet_hash()` in `pam_kwallet.c`, which calls `gcry_kdf_derive` with
/// `GCRY_KDF_PBKDF2` and `GCRY_MD_SHA512`.
#[expect(clippy::missing_errors_doc, reason = "doc backlog")]
pub fn derive_key(secret: &[u8], salt: &[u8]) -> Result<Zeroizing<Vec<u8>>> {
    if salt.len() != SALT_LEN {
        return Err(Error::Protocol(format!(
            "wallet salt must be exactly {SALT_LEN} bytes, got {}",
            salt.len()
        )));
    }
    let mut out = Zeroizing::new(vec![0u8; KEY_LEN]);
    // Protect the allocation before PBKDF2 writes the derived secret into it;
    // locking only after the KDF would leave the most sensitive window open.
    irlume_common::memlock::lock_slice(&out);
    pbkdf2::pbkdf2_hmac::<sha2::Sha512>(secret, salt, ITERATIONS, &mut out);
    Ok(out)
}

/// Which secret to seal for a user, combining the caller's account-scoped KDE
/// salt result with the GNOME keyring visible below `home`.
///
/// A KDE wallet key only makes sense where there is a KDE wallet. A GNOME
/// keyring token only makes sense where there is a GNOME login keyring to
/// re-key to it, and not where a KDE wallet also exists: the wallet key is
/// derived from the password, so a token arm would leave the KDE wallet with
/// nothing to open it.
///
/// The conservative direction is [`crate::envelope::SecretKind::LoginPassword`],
/// the behaviour before #250, so anything ambiguous (both backends, neither)
/// resolves to it. A home with neither also lands there deliberately: a token
/// arm on a fresh account would have no keyring to re-key, and the envelope it
/// wrote would unlock nothing.
pub fn detect_kind(home: &Path, has_kde_salt: bool) -> crate::envelope::SecretKind {
    use crate::envelope::SecretKind;
    // gnome-keyring's login keyring: what a token re-keys, and what a wallet
    // key arm would break.
    let has_gnome = home.join(".local/share/keyrings/login.keyring").exists();
    match (has_kde_salt, has_gnome) {
        (true, false) => SecretKind::KdeWalletKey,
        (false, true) => SecretKind::GnomeKeyringToken,
        _ => SecretKind::LoginPassword,
    }
}

#[cfg(test)]
mod tests {

    fn locked_kb_of(addr: usize) -> Option<u64> {
        let smaps = std::fs::read_to_string("/proc/self/smaps").ok()?;
        let mut in_range = false;
        for line in smaps.lines() {
            if let Some((range, _)) = line.split_once(' ') {
                if let Some((start, end)) = range.split_once('-') {
                    if let (Ok(start), Ok(end)) = (
                        usize::from_str_radix(start, 16),
                        usize::from_str_radix(end, 16),
                    ) {
                        in_range = start <= addr && addr < end;
                        continue;
                    }
                }
            }
            if in_range {
                if let Some(rest) = line.strip_prefix("Locked:") {
                    return rest.trim().trim_end_matches("kB").trim().parse().ok();
                }
            }
        }
        None
    }

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
    fn derived_wallet_key_is_memlocked() {
        let key = derive_key(b"synthetic password", &[0x5a; SALT_LEN]).expect("derive");
        let key_locked = locked_kb_of(key.as_ptr() as usize).unwrap_or(0);

        // Control: stand down when best-effort mlock is unavailable in this
        // environment, rather than changing the authentication contract.
        let control = irlume_common::SecretBytes::new(vec![0x71; 16 * 1024]);
        let control_mid = control.expose().as_ptr() as usize + 8 * 1024;
        match locked_kb_of(control_mid) {
            Some(kb) if kb > 0 => {}
            _ => {
                eprintln!("skipping: environment cannot mlock (RLIMIT_MEMLOCK?)");
                return;
            }
        }

        assert!(
            key_locked > 0,
            "PBKDF2 output must be protected while and after it is derived"
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

    /// Detection has to be conservative in every ambiguous direction: a home
    /// with neither backend has nothing to unlock, and a machine running both
    /// backends must keep the password, or whichever backend the arm did not
    /// pick is stranded. Only an unambiguous single-backend home gets that
    /// backend's dedicated secret.
    #[test]
    fn detect_kind_only_picks_the_wallet_key_on_a_kde_only_home() {
        use crate::envelope::SecretKind;
        let base = std::env::temp_dir().join(format!("irlume-detect-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&base);

        let mk = |name: &str, gnome: bool| {
            let h = base.join(name);
            if gnome {
                let g = h.join(".local/share/keyrings");
                std::fs::create_dir_all(&g).unwrap();
                std::fs::write(g.join("login.keyring"), b"x").unwrap();
            }
            std::fs::create_dir_all(&h).unwrap();
            h
        };

        assert_eq!(
            detect_kind(&mk("neither", false), false),
            SecretKind::LoginPassword
        );
        assert_eq!(
            detect_kind(&mk("gnome", true), false),
            SecretKind::GnomeKeyringToken
        );
        assert_eq!(
            detect_kind(&mk("both", true), true),
            SecretKind::LoginPassword
        );
        assert_eq!(
            detect_kind(&mk("kde", false), true),
            SecretKind::KdeWalletKey
        );
        let _ = std::fs::remove_dir_all(&base);
    }
}

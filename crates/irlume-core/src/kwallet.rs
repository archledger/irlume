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

/// The most this file can be and still be a wallet salt. A real one is
/// [`SALT_LEN`] bytes; the headroom is for a future format, not for a payload.
const MAX_SALT_BYTES: u64 = 4096;

/// Read a REGULAR file of at most `max` bytes, without blocking and without
/// following a symlink at the final component.
///
/// This path lives inside the user's own home, so its contents and its type are
/// theirs to choose, and the daemon reads it as root on the worker thread. A
/// plain `fs::read` here was a wedge: `mkfifo`ing the salt path blocks in
/// `open(2)` until a writer appears, which stalls the camera worker forever
/// while the connection threads keep answering Ping, so the daemon looks
/// healthy while every capture and mutation is dead. The systemd watchdog then
/// kills and restarts it, and the file is still a FIFO, so it happens again.
/// Pointing it at /dev/zero gives unbounded allocation instead.
///
/// `O_NONBLOCK` makes opening a FIFO return instead of waiting, `O_NOFOLLOW`
/// stops a symlink redirecting the final component elsewhere, and the fstat
/// rejects anything that is not a regular file, which covers FIFOs, devices,
/// and directories together. The size cap bounds the allocation.
fn read_regular_file_capped(path: &Path, max: u64) -> std::io::Result<Vec<u8>> {
    use std::io::Read as _;
    use std::os::unix::fs::{FileTypeExt as _, OpenOptionsExt as _};

    let file = std::fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NONBLOCK | libc::O_NOFOLLOW)
        .open(path)?;
    let meta = file.metadata()?;
    let ft = meta.file_type();
    if !ft.is_file() {
        let what = if ft.is_fifo() {
            "a FIFO"
        } else if ft.is_char_device() || ft.is_block_device() {
            "a device"
        } else if ft.is_dir() {
            "a directory"
        } else if ft.is_socket() {
            "a socket"
        } else {
            "not a regular file"
        };
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            format!("{} is {what}, not a regular file", path.display()),
        ));
    }
    if meta.len() > max {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            format!(
                "{} is {} bytes, over the {max}-byte limit",
                path.display(),
                meta.len()
            ),
        ));
    }
    let mut buf = Vec::with_capacity(meta.len() as usize);
    // Cap the read as well as the stat: the file can grow between the two.
    file.take(max).read_to_end(&mut buf)?;
    Ok(buf)
}

/// Read `home`'s wallet salt.
///
/// Deliberately does NOT create a missing salt, unlike `pam_kwallet5`, which
/// creates one on first login. Absent salt means this user has no KDE wallet
/// yet, and inventing one here would derive a key that opens nothing while
/// looking like a successful arm.
#[expect(clippy::missing_errors_doc, reason = "doc backlog")]
pub fn read_salt(home: &Path) -> Result<Zeroizing<Vec<u8>>> {
    let path = salt_path(home);
    let raw = read_regular_file_capped(&path, MAX_SALT_BYTES).map_err(|e| {
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
#[expect(clippy::missing_errors_doc, reason = "doc backlog")]
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
#[expect(clippy::missing_errors_doc, reason = "doc backlog")]
pub fn derive_for_home(password: &[u8], home: &Path) -> Result<Zeroizing<Vec<u8>>> {
    let salt = read_salt(home)?;
    derive_key(password, &salt)
}

/// Which secret to seal for a user, judged by what they actually have.
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
pub fn detect_kind(home: &Path) -> crate::envelope::SecretKind {
    use crate::envelope::SecretKind;
    let has_kde = salt_path(home).exists();
    // gnome-keyring's login keyring: what a token re-keys, and what a wallet
    // key arm would break.
    let has_gnome = home.join(".local/share/keyrings/login.keyring").exists();
    match (has_kde, has_gnome) {
        (true, false) => SecretKind::KdeWalletKey,
        (false, true) => SecretKind::GnomeKeyringToken,
        _ => SecretKind::LoginPassword,
    }
}

#[cfg(test)]
mod tests {

    /// The salt path lives in the user's own home, so its TYPE is theirs to
    /// choose. `fs::read` on a FIFO blocks in `open(2)` until a writer appears,
    /// which stalls the daemon's camera worker forever while the connection
    /// threads keep answering Ping: the daemon looks healthy while every capture
    /// is dead, the watchdog kills it, and the FIFO is still there on restart.
    #[test]
    fn a_non_regular_salt_is_refused_instead_of_blocking() {
        let dir = std::path::PathBuf::from(crate::test_tmp_dir("kwallet-fifo"))
            .join(".local/share/kwalletd");
        let _ = std::fs::remove_dir_all(dir.parent().unwrap().parent().unwrap());
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("kdewallet.salt");
        let c = std::ffi::CString::new(path.to_str().unwrap()).unwrap();
        assert_eq!(
            // SAFETY: `c` is a live CString that outlives this call, so the pointer is
            // a valid NUL-terminated path for the duration of mkfifo.
            unsafe { libc::mkfifo(c.as_ptr(), 0o600) },
            0,
            "mkfifo failed"
        );

        let home = dir.parent().unwrap().parent().unwrap().parent().unwrap();
        // Must RETURN. Before the fix this call never came back.
        let err = read_salt(home).expect_err("a FIFO must not be read as a salt");
        let msg = format!("{err}");
        assert!(
            msg.contains("FIFO"),
            "the refusal must name what it found: {msg}"
        );

        // A real salt still reads.
        std::fs::remove_file(&path).unwrap();
        std::fs::write(&path, vec![7u8; SALT_LEN]).unwrap();
        assert_eq!(read_salt(home).unwrap().len(), SALT_LEN);

        // And an implausibly large one is refused rather than allocated.
        std::fs::write(&path, vec![0u8; (MAX_SALT_BYTES + 1) as usize]).unwrap();
        assert!(
            read_salt(home).is_err(),
            "an oversized salt must be refused"
        );
        let _ = std::fs::remove_dir_all(home);
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
            SecretKind::GnomeKeyringToken
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

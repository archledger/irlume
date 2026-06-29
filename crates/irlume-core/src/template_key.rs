//! Per-user template key: the AES-256-GCM key that [`crate::storage`] uses to
//! encrypt enrolled face templates at rest.
//!
//! The key is 32 random bytes, **TPM-sealed** (so `irlumed` can decrypt the
//! templates headlessly at the login greeter, no user interaction) and stored
//! root-only under `/var/lib/irlume/template-keys/<user>.json`. The same key may
//! also be **recovery-wrapped** under an Argon2id passphrase
//! ([`crate::recovery`]) and stored under `/var/lib/irlume/recovery/<user>.json`
//! — the manual backstop for when the TPM seal can no longer be satisfied
//! (Secure Boot off, TPM cleared, dbx/firmware PCR move, disk moved machines).
//!
//! Reliability note: like the keyring seal, the TPM-sealed key inherits PCR
//! fragility — after a dbx/firmware update the seal may stop unsealing, and face
//! auth then falls back to the password until `irlume recovery restore` (or a
//! re-enroll) re-binds the key to the current PCRs. Encrypting templates is the
//! security/reliability trade the operator opted into.

use crate::recovery::RecoveryEnvelope;
use crate::tpm;
use crate::{crypto, envelope::SealedEnvelope};
use irlume_common::{Error, Result};
use std::path::{Path, PathBuf};
use zeroize::Zeroizing;

fn key_dir() -> PathBuf {
    std::env::var("IRLUME_TEMPLATE_KEY_DIR")
        .map(PathBuf::from)
        .unwrap_or_else(|_| PathBuf::from(irlume_common::STATE_DIR).join("template-keys"))
}

fn recovery_dir() -> PathBuf {
    std::env::var("IRLUME_RECOVERY_DIR")
        .map(PathBuf::from)
        .unwrap_or_else(|_| PathBuf::from(irlume_common::STATE_DIR).join("recovery"))
}

pub fn key_path(user: &str) -> PathBuf {
    key_dir().join(format!("{user}.json"))
}

pub fn recovery_path(user: &str) -> PathBuf {
    recovery_dir().join(format!("{user}.json"))
}

/// Whether a TPM is present. When false, [`crate::storage`] keeps templates as
/// root-only plaintext (dev boxes / no-TPM hosts) instead of failing.
pub fn tpm_available() -> bool {
    Path::new("/dev/tpmrm0").exists() || Path::new("/dev/tpm0").exists()
}

/// Whether a sealed template key exists for `user`.
pub fn has_key(user: &str) -> bool {
    key_path(user).exists()
}

/// Whether a recovery envelope exists for `user`.
pub fn has_recovery(user: &str) -> bool {
    recovery_path(user).exists()
}

/// The template key for `user`, generating and TPM-sealing a fresh one if none
/// exists. Used on the write path ([`crate::storage::save`]).
pub fn ensure_key(user: &str) -> Result<Zeroizing<Vec<u8>>> {
    if has_key(user) {
        return load_key(user);
    }
    let key = crypto::generate_key();
    reseal_key(user, &key)?;
    Ok(key)
}

/// Unseal the existing template key for `user`. Errors if none is sealed (the
/// caller must NOT generate one here — that would orphan already-encrypted data).
pub fn load_key(user: &str) -> Result<Zeroizing<Vec<u8>>> {
    let path = key_path(user);
    if !path.exists() {
        return Err(Error::Policy(format!("no template key sealed for '{user}'")));
    }
    let env = SealedEnvelope::load(&path)?;
    tpm::unseal(&env)
}

/// (Re-)seal `key` for `user` against the current TPM PCR policy and persist it.
/// Used at first enrollment and by recovery-restore to re-bind after a PCR move.
pub fn reseal_key(user: &str, key: &[u8]) -> Result<()> {
    if key.len() != crypto::KEY_LEN {
        return Err(Error::Policy(format!(
            "template key must be {} bytes",
            crypto::KEY_LEN
        )));
    }
    let dir = key_dir();
    std::fs::create_dir_all(&dir).map_err(|e| Error::Io(e.to_string()))?;
    let env = tpm::seal(key)?;
    env.save(&key_path(user))?;
    set_0600(&key_path(user));
    Ok(())
}

/// Erase `user`'s sealed template key (e.g. when their enrollment is deleted).
/// Idempotent. Does NOT touch the recovery envelope.
pub fn forget_key(user: &str) -> Result<()> {
    let path = key_path(user);
    if path.exists() {
        std::fs::remove_file(&path).map_err(|e| Error::Io(e.to_string()))?;
    }
    Ok(())
}

// --- recovery passphrase backstop ------------------------------------------

/// Create (or replace) `user`'s recovery envelope: wrap the live template key
/// under `passphrase`. Requires a sealed template key to already exist.
pub fn setup_recovery(user: &str, passphrase: &[u8]) -> Result<()> {
    let key = load_key(user)?;
    let env = crate::recovery::wrap(passphrase, &key)?;
    save_recovery(user, &env)
}

/// Restore `user`'s template key from the recovery envelope using `passphrase`,
/// and re-seal it against the *current* TPM PCRs (healing a PCR move / TPM
/// clear / disk move). Errors on a wrong passphrase or a missing envelope.
pub fn restore_from_recovery(user: &str, passphrase: &[u8]) -> Result<()> {
    let path = recovery_path(user);
    if !path.exists() {
        return Err(Error::Policy(format!(
            "no recovery passphrase set for '{user}' — run `irlume recovery setup`"
        )));
    }
    let env = load_recovery(user)?;
    let key = crate::recovery::unwrap(passphrase, &env)?;
    reseal_key(user, &key)
}

/// Erase `user`'s recovery envelope. Idempotent.
pub fn forget_recovery(user: &str) -> Result<()> {
    let path = recovery_path(user);
    if path.exists() {
        std::fs::remove_file(&path).map_err(|e| Error::Io(e.to_string()))?;
    }
    Ok(())
}

fn save_recovery(user: &str, env: &RecoveryEnvelope) -> Result<()> {
    let dir = recovery_dir();
    std::fs::create_dir_all(&dir).map_err(|e| Error::Io(e.to_string()))?;
    let json = serde_json::to_vec_pretty(env).map_err(|e| Error::Protocol(e.to_string()))?;
    let path = recovery_path(user);
    std::fs::write(&path, json).map_err(|e| Error::Io(e.to_string()))?;
    set_0600(&path);
    Ok(())
}

fn load_recovery(user: &str) -> Result<RecoveryEnvelope> {
    let data = std::fs::read(recovery_path(user)).map_err(|e| Error::Io(e.to_string()))?;
    serde_json::from_slice(&data).map_err(|e| Error::Protocol(e.to_string()))
}

#[cfg(unix)]
fn set_0600(path: &Path) {
    use std::os::unix::fs::PermissionsExt;
    let _ = std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600));
}
#[cfg(not(unix))]
fn set_0600(_path: &Path) {}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex;

    // The override env vars are process-global; serialize the tests that mutate
    // them so parallel `cargo test` runs don't clobber each other.
    static ENV_LOCK: Mutex<()> = Mutex::new(());

    #[test]
    fn paths_under_override_dirs() {
        let _g = ENV_LOCK.lock().unwrap();
        std::env::set_var("IRLUME_TEMPLATE_KEY_DIR", "/tmp/irlume-tk");
        std::env::set_var("IRLUME_RECOVERY_DIR", "/tmp/irlume-rec");
        assert_eq!(key_path("bob"), PathBuf::from("/tmp/irlume-tk/bob.json"));
        assert_eq!(recovery_path("bob"), PathBuf::from("/tmp/irlume-rec/bob.json"));
        std::env::remove_var("IRLUME_TEMPLATE_KEY_DIR");
        std::env::remove_var("IRLUME_RECOVERY_DIR");
    }

    /// Recovery round-trip WITHOUT a TPM: seed a key file via wrap math directly
    /// to exercise setup/restore plumbing minus the TPM seal. The TPM-backed
    /// `load_key`/`reseal_key` path is covered by an ignored test.
    #[test]
    fn recovery_envelope_save_load_round_trip() {
        let _g = ENV_LOCK.lock().unwrap();
        std::env::set_var("IRLUME_RECOVERY_DIR", "/tmp/irlume-rec-rt");
        let _ = std::fs::remove_dir_all("/tmp/irlume-rec-rt");
        let key = crypto::generate_key();
        let env = crate::recovery::wrap(b"pass-phrase-here", &key).unwrap();
        save_recovery("rt", &env).unwrap();
        assert!(has_recovery("rt"));
        let loaded = load_recovery("rt").unwrap();
        let got = crate::recovery::unwrap(b"pass-phrase-here", &loaded).unwrap();
        assert_eq!(&*got, &*key);
        forget_recovery("rt").unwrap();
        assert!(!has_recovery("rt"));
        std::env::remove_var("IRLUME_RECOVERY_DIR");
    }

    /// Full TPM-backed lifecycle: seal a key, recovery-wrap it, simulate a PCR
    /// move by forgetting the seal, then restore from the passphrase.
    #[test]
    #[ignore = "requires real TPM (/dev/tpmrm0)"]
    fn tpm_key_and_recovery_lifecycle() {
        let _g = ENV_LOCK.lock().unwrap();
        std::env::set_var("IRLUME_TEMPLATE_KEY_DIR", "/tmp/irlume-tk-rt");
        std::env::set_var("IRLUME_RECOVERY_DIR", "/tmp/irlume-rec-tpm");
        let _ = std::fs::remove_dir_all("/tmp/irlume-tk-rt");
        let _ = std::fs::remove_dir_all("/tmp/irlume-rec-tpm");

        let k1 = ensure_key("rt").unwrap();
        assert!(has_key("rt"));
        // Stable across calls.
        assert_eq!(&*load_key("rt").unwrap(), &*k1);

        setup_recovery("rt", b"my recovery passphrase").unwrap();
        assert!(has_recovery("rt"));

        // Simulate seal loss (dbx move / TPM clear) and restore.
        forget_key("rt").unwrap();
        assert!(!has_key("rt"));
        restore_from_recovery("rt", b"my recovery passphrase").unwrap();
        assert!(has_key("rt"));
        assert_eq!(&*load_key("rt").unwrap(), &*k1, "restored key must match original");

        forget_key("rt").unwrap();
        forget_recovery("rt").unwrap();
        std::env::remove_var("IRLUME_TEMPLATE_KEY_DIR");
        std::env::remove_var("IRLUME_RECOVERY_DIR");
    }
}

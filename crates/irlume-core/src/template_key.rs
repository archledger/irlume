// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright the irlume contributors.

//! Per-user template key: the AES-256-GCM key that [`crate::storage`] uses to
//! encrypt enrolled face templates at rest.
//!
//! The key is 32 random bytes, **TPM-sealed** (so `irlumed` can decrypt the
//! templates headlessly at the login greeter, no user interaction) and stored
//! root-only under `/var/lib/irlume/template-keys/<user>.json`. The same key may
//! also be **recovery-wrapped** under an Argon2id passphrase
//! ([`crate::recovery`]) and stored under `/var/lib/irlume/recovery/<user>.json`,
//! the manual backstop for when the TPM seal can no longer be satisfied
//! (Secure Boot off, TPM cleared, dbx/firmware PCR move, disk moved machines).
//!
//! Reliability note: like the keyring seal, the TPM-sealed key inherits PCR
//! fragility: after a dbx/firmware update the seal may stop unsealing, and face
//! auth then falls back to the password until `irlume recovery restore` (or a
//! re-enroll) re-binds the key to the current PCRs. Encrypting templates is the
//! security/reliability trade the operator opted into.

use crate::recovery::RecoveryEnvelope;
use crate::tpm;
use crate::{crypto, envelope::SealedEnvelope};
use irlume_common::{Error, Result};
use std::fs::OpenOptions;
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

fn device_accessible(path: &Path) -> bool {
    OpenOptions::new().read(true).write(true).open(path).is_ok()
}

/// Whether this process can use a TPM. Device-node presence alone is not
/// enough: an unprivileged process may see `/dev/tpmrm0` without having access
/// to it. When false, [`crate::storage`] keeps templates as root-only plaintext
/// (dev boxes / no-TPM hosts) instead of failing every profile write.
pub fn tpm_available() -> bool {
    if std::env::var_os("IRLUME_TCTI").is_some_and(|value| !value.is_empty()) {
        return true;
    }
    device_accessible(Path::new("/dev/tpmrm0")) || device_accessible(Path::new("/dev/tpm0"))
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
/// caller must NOT generate one here; that would orphan already-encrypted data).
pub fn load_key(user: &str) -> Result<Zeroizing<Vec<u8>>> {
    let path = key_path(user);
    if !path.exists() {
        return Err(Error::Policy(format!(
            "no template key sealed for '{user}'"
        )));
    }
    let env = SealedEnvelope::load(&path)?;
    let key = tpm::unseal(&env)?;
    // Best-effort tier auto-upgrade (mirrors keyring::reseal_password): if a
    // strictly stronger sealing tier became available since this key was sealed
    // (e.g. signed-PCR started working), re-seal the key to it so an existing
    // enrollment reaches Tier 1 with no re-enroll. The check short-circuits to a
    // no-op once the envelope is already at the best tier, so there is no steady
    // per-match cost. Never fail the load on it: the key unsealed fine and the
    // weaker envelope stays usable.
    if tpm::stronger_tier_available_than(&env.policy) {
        if let Ok(candidate) = tpm::seal(&key) {
            if candidate.policy.strength_rank() > env.policy.strength_rank()
                && candidate.save(&path).is_ok()
            {
                set_0600(&path);
            }
        }
    }
    Ok(key)
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
            "no recovery passphrase set for '{user}'; run `irlume recovery setup`"
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
    // Atomic: replacing a recovery envelope must not corrupt the existing one on
    // a failed write; it is the last-resort backstop after a TPM seal breaks.
    irlume_common::write_0600_atomic(&path, &json).map_err(|e| Error::Io(e.to_string()))
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
    // The override env vars are process-global; the crate-wide lock stops
    // cross-module races too (keyring tests mutate their own override).
    use crate::testenv::ENV_LOCK;

    #[test]
    fn paths_under_override_dirs() {
        let _g = ENV_LOCK.lock().unwrap();
        std::env::set_var("IRLUME_TEMPLATE_KEY_DIR", "/tmp/irlume-tk");
        std::env::set_var("IRLUME_RECOVERY_DIR", "/tmp/irlume-rec");
        assert_eq!(key_path("bob"), PathBuf::from("/tmp/irlume-tk/bob.json"));
        assert_eq!(
            recovery_path("bob"),
            PathBuf::from("/tmp/irlume-rec/bob.json")
        );
        std::env::remove_var("IRLUME_TEMPLATE_KEY_DIR");
        std::env::remove_var("IRLUME_RECOVERY_DIR");
    }

    #[test]
    fn device_probe_requires_an_openable_read_write_target() {
        let dir = PathBuf::from(crate::test_tmp_dir("tpm-access"));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let target = dir.join("device");
        std::fs::write(&target, b"probe").unwrap();

        assert!(device_accessible(&target));
        assert!(!device_accessible(&dir.join("missing")));

        let _ = std::fs::remove_dir_all(dir);
    }

    /// Recovery round-trip WITHOUT a TPM: seed a key file via wrap math directly
    /// to exercise setup/restore plumbing minus the TPM seal. The TPM-backed
    /// `load_key`/`reseal_key` path is covered by an ignored test.
    #[test]
    fn recovery_envelope_save_load_round_trip() {
        let _g = ENV_LOCK.lock().unwrap();
        let dir = crate::test_tmp_dir("rec-rt");
        std::env::set_var("IRLUME_RECOVERY_DIR", &dir);
        let _ = std::fs::remove_dir_all(&dir);
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
    #[ignore = "requires a TPM: real /dev/tpmrm0, or swtpm via IRLUME_TCTI (CI does this)"]
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
        assert_eq!(
            &*load_key("rt").unwrap(),
            &*k1,
            "restored key must match original"
        );

        forget_key("rt").unwrap();
        forget_recovery("rt").unwrap();
        std::env::remove_var("IRLUME_TEMPLATE_KEY_DIR");
        std::env::remove_var("IRLUME_RECOVERY_DIR");
    }

    /// A wrong recovery passphrase must fail the restore WITHOUT materialising a
    /// key file: a bogus key would let the daemon "unseal" garbage and silently
    /// destroy the encrypted templates. No TPM needed (unwrap fails before the
    /// re-seal), so this seeds the envelope directly via save_recovery.
    #[test]
    fn recovery_restore_rejects_wrong_passphrase() {
        let _g = ENV_LOCK.lock().unwrap();
        let rec = crate::test_tmp_dir("rec-wrongpass");
        let tk = crate::test_tmp_dir("tk-wrongpass");
        let _ = std::fs::remove_dir_all(&rec);
        let _ = std::fs::remove_dir_all(&tk);
        std::env::set_var("IRLUME_RECOVERY_DIR", &rec);
        std::env::set_var("IRLUME_TEMPLATE_KEY_DIR", &tk);

        let key = crypto::generate_key();
        let env = crate::recovery::wrap(b"correct horse battery", &key).unwrap();
        save_recovery("rt", &env).unwrap();

        let err = restore_from_recovery("rt", b"wrong passphrase").unwrap_err();
        // GCM auth failure surfaces as a decrypt error (Error::Policy), not a panic.
        let msg = format!("{err}");
        assert!(msg.contains("wrong recovery passphrase"), "got: {msg}");
        assert!(
            !has_key("rt"),
            "a failed restore must not create a key file"
        );

        forget_recovery("rt").unwrap();
        std::env::remove_var("IRLUME_RECOVERY_DIR");
        std::env::remove_var("IRLUME_TEMPLATE_KEY_DIR");
    }

    /// Restore with no envelope on disk errors with the guidance message rather
    /// than a bare not-found, so the greeter/CLI can tell the user what to do.
    #[test]
    fn recovery_restore_errors_without_envelope() {
        let _g = ENV_LOCK.lock().unwrap();
        let rec = crate::test_tmp_dir("rec-none");
        let _ = std::fs::remove_dir_all(&rec);
        std::env::set_var("IRLUME_RECOVERY_DIR", &rec);

        let err = restore_from_recovery("nobody", b"whatever").unwrap_err();
        let msg = format!("{err}");
        assert!(msg.contains("no recovery passphrase set"), "got: {msg}");

        std::env::remove_var("IRLUME_RECOVERY_DIR");
    }

    /// A truncated / hand-edited recovery file must error out of the JSON parse,
    /// never panic: a corrupt backstop should degrade to "use your password",
    /// not crash the daemon mid-login.
    #[test]
    fn recovery_restore_rejects_corrupt_envelope() {
        let _g = ENV_LOCK.lock().unwrap();
        let rec = crate::test_tmp_dir("rec-corrupt");
        let _ = std::fs::remove_dir_all(&rec);
        std::fs::create_dir_all(&rec).unwrap();
        std::env::set_var("IRLUME_RECOVERY_DIR", &rec);

        std::fs::write(recovery_path("rt"), b"{ not valid json ").unwrap();
        let err = restore_from_recovery("rt", b"x").unwrap_err();
        assert!(matches!(err, Error::Protocol(_)), "got {err:?}");

        std::env::remove_var("IRLUME_RECOVERY_DIR");
    }

    /// The core recovery promise on real hardware: if the sealed key on disk can
    /// no longer be unsealed (here a bit-flip in the TPM-sealed private blob,
    /// standing in for a PCR move / dbx update), load_key FAILS (auth falls back
    /// to the password) and `recovery restore` heals it back to the ORIGINAL key
    /// so already-encrypted templates decrypt again.
    #[test]
    #[ignore = "requires a TPM: real /dev/tpmrm0, or swtpm via IRLUME_TCTI (CI does this)"]
    fn tpm_tampered_seal_falls_back_then_recovery_heals() {
        let _g = ENV_LOCK.lock().unwrap();
        let tk = "/tmp/irlume-tk-tamper";
        let rec = "/tmp/irlume-rec-tamper";
        std::env::set_var("IRLUME_TEMPLATE_KEY_DIR", tk);
        std::env::set_var("IRLUME_RECOVERY_DIR", rec);
        let _ = std::fs::remove_dir_all(tk);
        let _ = std::fs::remove_dir_all(rec);

        let original = ensure_key("rt").unwrap();
        setup_recovery("rt", b"my recovery passphrase").unwrap();

        // Corrupt the sealed private blob so the TPM can no longer unseal it.
        let mut env = SealedEnvelope::load(&key_path("rt")).unwrap();
        assert!(!env.private.is_empty());
        env.private[0] ^= 0xff;
        env.save(&key_path("rt")).unwrap();
        assert!(load_key("rt").is_err(), "a tampered seal must not unseal");

        // Recovery heals it: unwrap under the passphrase, re-seal to current PCRs.
        restore_from_recovery("rt", b"my recovery passphrase").unwrap();
        assert_eq!(
            &*load_key("rt").unwrap(),
            &*original,
            "recovered key must match the original that encrypted the templates"
        );

        forget_key("rt").unwrap();
        forget_recovery("rt").unwrap();
        std::env::remove_var("IRLUME_TEMPLATE_KEY_DIR");
        std::env::remove_var("IRLUME_RECOVERY_DIR");
    }

    /// On signed-UKI hardware, a template key sealed under a weaker tier
    /// auto-upgrades to Tier 1 the next time it is loaded (i.e. the next face
    /// match), with no re-enroll. Companion to the keyring reseal upgrade.
    #[test]
    #[ignore = "requires a real TPM + fresh systemd signed-PCR artifacts (UKI/systemd-boot)"]
    fn load_key_auto_upgrades_weaker_tier_to_signed() {
        use crate::crypto;
        use crate::envelope::PolicyKind;
        let _g = ENV_LOCK.lock().unwrap();
        std::env::set_var("IRLUME_TEMPLATE_KEY_DIR", "/tmp/irlume-tk-upg");
        let _ = std::fs::remove_dir_all("/tmp/irlume-tk-upg");
        std::fs::create_dir_all("/tmp/irlume-tk-upg").unwrap();

        let key = crypto::generate_key();
        // Simulate an "old" seal under the weakest tier (literal PCR 7).
        crate::tpm::seal_with_pcrs(&key, &[7])
            .unwrap()
            .save(&key_path("rt"))
            .unwrap();
        assert_eq!(
            SealedEnvelope::load(&key_path("rt"))
                .unwrap()
                .policy
                .strength_rank(),
            1,
            "precondition: sealed at Tier 3"
        );
        // A load (what every match does) returns the key AND upgrades the tier.
        assert_eq!(&*load_key("rt").unwrap(), &*key);
        let env = SealedEnvelope::load(&key_path("rt")).unwrap();
        assert!(
            matches!(env.policy, PolicyKind::Authorized { .. }),
            "should climb to Tier 1, got {:?}",
            env.policy
        );
        assert_eq!(
            &*load_key("rt").unwrap(),
            &*key,
            "still loads after upgrade"
        );
        forget_key("rt").unwrap();
        std::env::remove_var("IRLUME_TEMPLATE_KEY_DIR");
    }
}

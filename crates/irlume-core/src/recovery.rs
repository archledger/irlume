//! Dedicated recovery passphrase for the per-user template key.
//!
//! This is the deliberate, manual backstop for the cases TPM-sealing cannot
//! cover — Secure Boot turned off, the TPM cleared, a dbx/firmware update that
//! moves the PCRs, or the disk moved to another machine. It is **separate from
//! the login/keyring password** (by design: a user may not want their face
//! template recoverable with the same secret that unlocks their account), and
//! behaves like a BitLocker / LUKS recovery key.
//!
//! The 32-byte template key (see [`crate::template_key`]) is wrapped with a key
//! derived from the passphrase via Argon2id (memory-hard, so an offline attacker
//! holding the on-disk envelope still faces an expensive brute force), then
//! sealed with AES-256-GCM ([`crate::crypto`]). The passphrase itself is never
//! stored.
//!
//! On-disk format (`recovery/<user>.json`):
//! ```json
//! {
//!   "version": 1, "kdf": "argon2id",
//!   "salt": "<base64, 16 bytes>",
//!   "m_cost": 19456, "t_cost": 2, "p_cost": 1,
//!   "wrapped": "<base64: 12-byte nonce ‖ AES-256-GCM ciphertext+tag>"
//! }
//! ```

use crate::crypto;
use argon2::{Algorithm, Argon2, Params, Version};
use base64::{engine::general_purpose::STANDARD, Engine};
use irlume_common::{Error, Result};
use rand::RngCore;
use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

const SALT_LEN: usize = 16;
// OWASP-recommended Argon2id baseline: 19 MiB, 2 passes, 1 lane. Plenty for a
// rarely-used recovery path; tunable per-envelope via the stored cost fields.
const M_COST: u32 = 19_456;
const T_COST: u32 = 2;
const P_COST: u32 = 1;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RecoveryEnvelope {
    pub version: u32,
    pub kdf: String,
    pub salt: String,
    pub m_cost: u32,
    pub t_cost: u32,
    pub p_cost: u32,
    pub wrapped: String,
}

fn derive_key(
    passphrase: &[u8],
    salt: &[u8],
    m: u32,
    t: u32,
    p: u32,
) -> Result<Zeroizing<Vec<u8>>> {
    let params = Params::new(m, t, p, Some(crypto::KEY_LEN))
        .map_err(|e| Error::Policy(format!("argon2 params: {e}")))?;
    let a2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);
    let mut out = Zeroizing::new(vec![0u8; crypto::KEY_LEN]);
    a2.hash_password_into(passphrase, salt, &mut out)
        .map_err(|e| Error::Policy(format!("argon2 derive: {e}")))?;
    irlume_common::memlock::lock_slice(&out);
    Ok(out)
}

/// Wrap `template_key` under a fresh Argon2id-derived key from `passphrase`.
pub fn wrap(passphrase: &[u8], template_key: &[u8]) -> Result<RecoveryEnvelope> {
    if passphrase.is_empty() {
        return Err(Error::Policy("empty recovery passphrase".into()));
    }
    let mut salt = [0u8; SALT_LEN];
    rand::thread_rng().fill_bytes(&mut salt);
    let dk = derive_key(passphrase, &salt, M_COST, T_COST, P_COST)?;
    let wrapped = crypto::encrypt(&dk, template_key)?;
    Ok(RecoveryEnvelope {
        version: 1,
        kdf: "argon2id".into(),
        salt: STANDARD.encode(salt),
        m_cost: M_COST,
        t_cost: T_COST,
        p_cost: P_COST,
        wrapped: STANDARD.encode(wrapped),
    })
}

/// Recover the template key from a recovery envelope and passphrase. Returns a
/// generic error on a wrong passphrase (AES-GCM tag mismatch) — indistinguishable
/// from tampering, by design.
pub fn unwrap(passphrase: &[u8], env: &RecoveryEnvelope) -> Result<Zeroizing<Vec<u8>>> {
    if env.kdf != "argon2id" {
        return Err(Error::Policy(format!(
            "unsupported recovery KDF: {}",
            env.kdf
        )));
    }
    let salt = STANDARD
        .decode(&env.salt)
        .map_err(|e| Error::Protocol(format!("bad recovery salt: {e}")))?;
    let wrapped = STANDARD
        .decode(&env.wrapped)
        .map_err(|e| Error::Protocol(format!("bad recovery blob: {e}")))?;
    let dk = derive_key(passphrase, &salt, env.m_cost, env.t_cost, env.p_cost)?;
    crypto::decrypt(&dk, &wrapped).map_err(|_| Error::Policy("wrong recovery passphrase".into()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn wrap_unwrap_round_trip() {
        let key = crypto::generate_key();
        let env = wrap(b"correct horse battery staple", &key).unwrap();
        let got = unwrap(b"correct horse battery staple", &env).unwrap();
        assert_eq!(&*got, &*key);
    }

    #[test]
    fn wrong_passphrase_fails() {
        let key = crypto::generate_key();
        let env = wrap(b"right-passphrase", &key).unwrap();
        assert!(unwrap(b"wrong-passphrase", &env).is_err());
    }

    #[test]
    fn empty_passphrase_rejected() {
        let key = crypto::generate_key();
        assert!(wrap(b"", &key).is_err());
    }

    #[test]
    fn distinct_salts_across_wraps() {
        let key = crypto::generate_key();
        let a = wrap(b"same-pass", &key).unwrap();
        let b = wrap(b"same-pass", &key).unwrap();
        assert_ne!(a.salt, b.salt, "each wrap must use a fresh salt");
        assert_ne!(a.wrapped, b.wrapped);
    }
}

// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright the irlume contributors.

//! AES-256-GCM encryption for face-template storage at rest.
//!
//! Blob format: `[12-byte nonce][ciphertext + 16-byte GCM tag]`. The nonce is
//! random per write; the GCM tag is appended by `aes-gcm` and verified on
//! decrypt, so any tampering with the ciphertext or tag is caught.
//!
//! Keys are 32 bytes from [`generate_key`], intended to be TPM-sealed (see
//! [`crate::template_key`]) and, optionally, recovery-wrapped under an Argon2id
//! passphrase (see [`crate::recovery`]).

use aes_gcm::aead::{Aead, KeyInit};
use aes_gcm::{Aes256Gcm, Nonce};
use irlume_common::{Error, Result};
use rand::Rng;
use zeroize::Zeroizing;

pub const KEY_LEN: usize = 32;
const NONCE_LEN: usize = 12;
/// Minimum valid blob: nonce + the 16-byte GCM tag (empty plaintext).
const TAG_LEN: usize = 16;

/// A fresh random 256-bit key, zeroized on drop.
pub fn generate_key() -> Zeroizing<Vec<u8>> {
    let mut key = Zeroizing::new(vec![0u8; KEY_LEN]);
    rand::rng().fill_bytes(&mut key);
    irlume_common::memlock::lock_slice(&key);
    key
}

/// Encrypt `plaintext` under `key`, returning `nonce ‖ ciphertext+tag`.
pub fn encrypt(key: &[u8], plaintext: &[u8]) -> Result<Vec<u8>> {
    if key.len() != KEY_LEN {
        return Err(Error::Policy(format!(
            "key must be {KEY_LEN} bytes, got {}",
            key.len()
        )));
    }
    let cipher =
        Aes256Gcm::new_from_slice(key).map_err(|e| Error::Tpm(format!("aes init: {e}")))?;

    let mut nonce_bytes = [0u8; NONCE_LEN];
    rand::rng().fill_bytes(&mut nonce_bytes);
    let nonce = Nonce::from(nonce_bytes);

    let ct = cipher
        .encrypt(&nonce, plaintext)
        .map_err(|e| Error::Tpm(format!("aes encrypt: {e}")))?;

    let mut out = Vec::with_capacity(NONCE_LEN + ct.len());
    out.extend_from_slice(&nonce_bytes);
    out.extend_from_slice(&ct);
    Ok(out)
}

/// Decrypt a `nonce ‖ ciphertext+tag` blob under `key`. A wrong key or tampered
/// data fails the GCM tag check and returns a generic error (indistinguishable
/// by design).
pub fn decrypt(key: &[u8], blob: &[u8]) -> Result<Zeroizing<Vec<u8>>> {
    if key.len() != KEY_LEN {
        return Err(Error::Policy(format!(
            "key must be {KEY_LEN} bytes, got {}",
            key.len()
        )));
    }
    if blob.len() < NONCE_LEN + TAG_LEN {
        return Err(Error::Policy("encrypted blob too short".into()));
    }
    let (nonce_bytes, ct) = blob.split_at(NONCE_LEN);
    // Length is guaranteed by the split above; try_from replaces the
    // deprecated from_slice in aes-gcm 0.11.
    let nonce = Nonce::try_from(nonce_bytes)
        .map_err(|_| Error::Policy("encrypted blob has malformed nonce".into()))?;

    let cipher =
        Aes256Gcm::new_from_slice(key).map_err(|e| Error::Tpm(format!("aes init: {e}")))?;

    let plain = cipher
        .decrypt(&nonce, ct)
        .map_err(|_| Error::Policy("decryption failed (wrong key or tampered data)".into()))?;
    irlume_common::memlock::lock_slice(&plain);
    Ok(Zeroizing::new(plain))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trip() {
        let key = generate_key();
        let msg = b"hello face embeddings";
        let enc = encrypt(&key, msg).unwrap();
        let dec = decrypt(&key, &enc).unwrap();
        assert_eq!(&*dec, msg);
    }

    #[test]
    fn wrong_key_fails() {
        let enc = encrypt(&generate_key(), b"secret").unwrap();
        assert!(decrypt(&generate_key(), &enc).is_err());
    }

    #[test]
    fn tampered_ciphertext_fails() {
        let key = generate_key();
        let mut enc = encrypt(&key, b"secret").unwrap();
        let last = enc.len() - 1;
        enc[last] ^= 0xFF;
        assert!(decrypt(&key, &enc).is_err());
    }

    #[test]
    fn distinct_nonces_across_encryptions() {
        let key = generate_key();
        let a = encrypt(&key, b"same plaintext").unwrap();
        let b = encrypt(&key, b"same plaintext").unwrap();
        assert_ne!(
            a[..NONCE_LEN],
            b[..NONCE_LEN],
            "each encrypt must use a fresh nonce"
        );
        assert_ne!(a, b);
    }

    #[test]
    fn wrong_key_length_rejected() {
        assert!(encrypt(&[0u8; 16], b"x").is_err());
        assert!(decrypt(&[0u8; 16], &[0u8; 40]).is_err());
    }

    fn unhex(s: &str) -> Vec<u8> {
        (0..s.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
            .collect()
    }

    /// NIST CAVP known-answer test (gcmEncryptExtIV256.rsp, AES-256-GCM,
    /// 96-bit IV, no AAD) hand-assembled into this module's on-disk layout
    /// `nonce ‖ ciphertext ‖ tag`. Pins BOTH the algorithm and the blob layout:
    /// an aes-gcm upgrade that changes either fails here instead of silently
    /// orphaning every encrypted enrollment on disk.
    #[test]
    fn nist_cavp_vector_decrypts_through_the_blob_layout() {
        let key = unhex("31bdadd96698c204aa9ce1448ea94ae1fb4a9a0b3c9d773b51bb1822666b8f22");
        let mut blob = unhex("0d18e06c7c725ac9e362e1ce"); // nonce
        blob.extend(unhex("fa4362189661d163fcd6a56d8bf0405a")); // ciphertext
        blob.extend(unhex("d636ac1bbedd5cc3ee727dc2ab4a9489")); // tag
        let plain = decrypt(&key, &blob).expect("NIST vector must decrypt");
        assert_eq!(
            &*plain,
            &unhex("2db5168e932556f8089a0622981d017d")[..],
            "AES-256-GCM output no longer matches the NIST CAVP vector"
        );
    }

    /// The wire layout is load-bearing: nonce is the first 12 bytes, the GCM tag
    /// the last 16, and the total overhead is exactly 28 bytes. A dependency
    /// change that alters framing must trip this before it ships.
    #[test]
    fn blob_layout_overhead_is_stable() {
        let key = generate_key();
        let enc = encrypt(&key, b"x").unwrap();
        assert_eq!(enc.len(), NONCE_LEN + 1 + TAG_LEN);
    }
}

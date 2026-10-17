// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright the irlume contributors.

//! TPM2_MakeCredential in software (ADR-0036 section 2.4).
//!
//! The same-TPM test sends a credential to the TPM's endorsement key (EK),
//! bound to the Name of irlume's storage key, and asks the TPM to release it
//! with TPM2_ActivateCredential. The credential is made here, not by the
//! TPM's own TPM2_MakeCredential, which would show the secret to the very TPM
//! under test. TPM 2.0 Library Part 1 v185 clause 21 defines it:
//!
//! 1. a seed, shared with the EK by its labeled KEM (clause 8.4.5.2): for
//!    RSA, a random secret of the nameAlg's digest size, RSA-OAEP encrypted
//!    with the nameAlg and the label `IDENTITY\0` (43.10); for ECC, KDFe over
//!    the ECDH secret of an ephemeral key (44.7);
//! 2. `symKey = KDFa(nameAlg, seed, "STORAGE", Name, -, symmetric bits)`;
//! 3. `encIdentity = CFB(symKey, IV = 0, TPM2B_DIGEST(credential))`;
//! 4. `HMACkey = KDFa(nameAlg, seed, "INTEGRITY", -, -, digest bits)`;
//! 5. `integrityHMAC = HMAC(HMACkey, encIdentity || Name)`.
//!
//! Only public-key operations run here: RSA-OAEP encryption to the EK and
//! ECDH with a fresh ephemeral key.

use aes::{Aes128, Aes256};
use cfb_mode::cipher::KeyIvInit;
use hmac::{Hmac, KeyInit, Mac};
use p256::elliptic_curve::sec1::ToSec1Point;
use p256::elliptic_curve::Generate;
use rand::CryptoRng;
use rsa::{BoxedUint, Oaep, RsaPublicKey};
use sha2::{Digest, Sha256, Sha384, Sha512};
use zeroize::Zeroizing;

use crate::ek_cert::{EccCurve, EkPublicKey};

/// The KEM label for credential protection: "IDENTITY" and its terminating
/// zero octet, nine octets (Part 1 clause 3).
const IDENTITY: &[u8] = b"IDENTITY\0";
const STORAGE: &[u8] = b"STORAGE\0";
const INTEGRITY: &[u8] = b"INTEGRITY\0";
/// The RSA public exponent an EK public area states as 0 (Part 2 12.2.3.4).
const DEFAULT_RSA_EXPONENT: u32 = 65_537;

/// An EK's nameAlg: the hash for the KEM, both KDFs and the HMAC.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NameAlg {
    Sha256,
    Sha384,
    Sha512,
}

impl NameAlg {
    /// The nameAlg a TPM_ALG_ID names, if irlume supports it.
    #[must_use]
    pub fn from_tpm_alg(id: u16) -> Option<Self> {
        match id {
            0x000B => Some(Self::Sha256),
            0x000C => Some(Self::Sha384),
            0x000D => Some(Self::Sha512),
            _ => None,
        }
    }

    /// The digest size in octets.
    #[must_use]
    pub fn digest_len(self) -> usize {
        match self {
            Self::Sha256 => 32,
            Self::Sha384 => 48,
            Self::Sha512 => 64,
        }
    }

    fn hash(self, parts: &[&[u8]]) -> Vec<u8> {
        fn run<D: Digest>(parts: &[&[u8]]) -> Vec<u8> {
            let mut digest = D::new();
            for part in parts {
                digest.update(part);
            }
            digest.finalize().to_vec()
        }
        match self {
            Self::Sha256 => run::<Sha256>(parts),
            Self::Sha384 => run::<Sha384>(parts),
            Self::Sha512 => run::<Sha512>(parts),
        }
    }

    fn hmac(self, key: &[u8], parts: &[&[u8]]) -> Vec<u8> {
        fn run<M: Mac + KeyInit>(key: &[u8], parts: &[&[u8]]) -> Vec<u8> {
            let mut mac =
                <M as KeyInit>::new_from_slice(key).expect("HMAC takes a key of any length");
            for part in parts {
                mac.update(part);
            }
            mac.finalize().into_bytes().to_vec()
        }
        match self {
            Self::Sha256 => run::<Hmac<Sha256>>(key, parts),
            Self::Sha384 => run::<Hmac<Sha384>>(key, parts),
            Self::Sha512 => run::<Hmac<Sha512>>(key, parts),
        }
    }
}

/// KDFa (Part 1 8.4.10.2): counter-mode HMAC over `[i] || label || 00 ||
/// contextU || contextV || [bits]`, the zero octet added only when the label
/// is empty or does not already end in one. `bits` must be a multiple of 8.
pub(crate) fn kdfa(
    alg: NameAlg,
    key: &[u8],
    label: &[u8],
    context_u: &[u8],
    context_v: &[u8],
    bits: u32,
) -> Vec<u8> {
    debug_assert_eq!(bits % 8, 0, "irlume derives whole octets only");
    let wanted = (bits / 8) as usize;
    let terminator: &[u8] = if label.last() == Some(&0) { &[] } else { &[0] };
    let mut out = Vec::with_capacity(wanted + alg.digest_len());
    let mut counter: u32 = 1;
    while out.len() < wanted {
        out.extend(alg.hmac(
            key,
            &[
                &counter.to_be_bytes(),
                label,
                terminator,
                context_u,
                context_v,
                &bits.to_be_bytes(),
            ],
        ));
        counter += 1;
    }
    out.truncate(wanted);
    out
}

/// KDFe (Part 1 8.4.10.3): `H([i] || Z || Use || PartyUInfo || PartyVInfo)`,
/// Use hashed exactly as given (the caller's label carries its own zero
/// octet, as the TCG reference code expects). `bits` must be a multiple of 8.
pub(crate) fn kdfe(
    alg: NameAlg,
    z: &[u8],
    label: &[u8],
    party_u: &[u8],
    party_v: &[u8],
    bits: u32,
) -> Vec<u8> {
    debug_assert_eq!(bits % 8, 0, "irlume derives whole octets only");
    let wanted = (bits / 8) as usize;
    let mut out = Vec::with_capacity(wanted + alg.digest_len());
    let mut counter: u32 = 1;
    while out.len() < wanted {
        out.extend(alg.hash(&[&counter.to_be_bytes(), z, label, party_u, party_v]));
        counter += 1;
    }
    out.truncate(wanted);
    out
}

/// Why a credential cannot be made for this EK.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum CredentialError {
    /// The EK's symmetric algorithm is not AES-128 or AES-256 in CFB mode.
    #[error("the EK's symmetric key is not AES-128 or AES-256 ({0} bits)")]
    Symmetric(u16),
    /// The credential is longer than the nameAlg's digest, which TPMs need
    /// not accept (Part 3 12.5).
    #[error("a credential longer than the EK's digest ({0} octets)")]
    CredentialLength(usize),
    /// The object Name is empty.
    #[error("no object Name to bind the credential to")]
    NoName,
    /// The EK's public key is not one irlume can encrypt to.
    #[error("the EK's public key is not usable: {0}")]
    Key(&'static str),
}

/// A credential for TPM2_ActivateCredential.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Credential {
    /// The TPM2B_ID_OBJECT's `credential` octets, without its own size:
    /// `TPM2B_DIGEST(integrityHMAC) || encIdentity`.
    pub id_object: Vec<u8>,
    /// The TPM2B_ENCRYPTED_SECRET's `secret` octets, without its own size:
    /// the OAEP ciphertext (RSA) or the marshaled ephemeral TPMS_ECC_POINT
    /// (ECC).
    pub encrypted_secret: Vec<u8>,
}

/// The EK a credential is made for, as its public area states it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EkTarget<'a> {
    pub name_alg: NameAlg,
    /// `parameters.symmetric.keyBits.sym`: 128 or 256 (AES, CFB).
    pub symmetric_bits: u16,
    /// The public key. For ECC, `x` is used exactly as the public area holds
    /// it, as the TPM uses it in KDFe.
    pub key: &'a EkPublicKey,
}

/// Make a credential for `object_name` (the activate object's Name, the
/// TPM2B_NAME's octets: nameAlg then digest) that the TPM holding `ek` will
/// release as `credential`.
///
/// # Errors
///
/// [`CredentialError`] when the EK's symmetric algorithm or key is not one
/// irlume supports, the credential is longer than the nameAlg's digest, or
/// the Name is empty.
pub fn make_credential<R: CryptoRng + ?Sized>(
    ek: &EkTarget<'_>,
    object_name: &[u8],
    credential: &[u8],
    rng: &mut R,
) -> Result<Credential, CredentialError> {
    check_protection(ek, object_name, credential)?;
    let (seed, encrypted_secret) = match ek.key {
        EkPublicKey::Rsa { modulus, exponent } => {
            let mut seed = Zeroizing::new(vec![0u8; ek.name_alg.digest_len()]);
            rng.fill_bytes(&mut seed);
            let encrypted = rsa_encrypt_seed(ek.name_alg, modulus, *exponent, &seed, rng)?;
            (seed, encrypted)
        }
        EkPublicKey::Ecc { curve, x, y } => {
            let ephemeral = EphemeralKey::random(*curve, rng);
            ecc_seed(ek.name_alg, *curve, x, y, &ephemeral)?
        }
    };
    Ok(Credential {
        id_object: protect(ek, &seed, object_name, credential),
        encrypted_secret,
    })
}

fn check_protection(
    ek: &EkTarget<'_>,
    object_name: &[u8],
    credential: &[u8],
) -> Result<(), CredentialError> {
    if !matches!(ek.symmetric_bits, 128 | 256) {
        return Err(CredentialError::Symmetric(ek.symmetric_bits));
    }
    if credential.len() > ek.name_alg.digest_len() {
        return Err(CredentialError::CredentialLength(credential.len()));
    }
    if object_name.is_empty() {
        return Err(CredentialError::NoName);
    }
    Ok(())
}

/// Steps 2 to 5: the TPMS_ID_OBJECT from the shared seed.
fn protect(ek: &EkTarget<'_>, seed: &[u8], object_name: &[u8], credential: &[u8]) -> Vec<u8> {
    let alg = ek.name_alg;
    let sym_key = Zeroizing::new(kdfa(
        alg,
        seed,
        STORAGE,
        object_name,
        &[],
        u32::from(ek.symmetric_bits),
    ));
    // The whole TPM2B_DIGEST is encrypted, its size included (Part 1 21.4).
    let mut enc_identity = u16::try_from(credential.len())
        .expect("check_protection bounds the credential")
        .to_be_bytes()
        .to_vec();
    enc_identity.extend_from_slice(credential);
    let iv = [0u8; 16];
    match ek.symmetric_bits {
        128 => cfb_mode::Encryptor::<Aes128>::new_from_slices(&sym_key, &iv)
            .expect("KDFa derived 16 octets")
            .encrypt(&mut enc_identity),
        _ => cfb_mode::Encryptor::<Aes256>::new_from_slices(&sym_key, &iv)
            .expect("KDFa derived 32 octets")
            .encrypt(&mut enc_identity),
    }
    let digest_bits = u32::try_from(alg.digest_len() * 8).expect("a digest's bit count fits");
    let hmac_key = Zeroizing::new(kdfa(alg, seed, INTEGRITY, &[], &[], digest_bits));
    let integrity = alg.hmac(&hmac_key, &[&enc_identity, object_name]);
    let mut id_object = u16::try_from(integrity.len())
        .expect("a digest's size fits")
        .to_be_bytes()
        .to_vec();
    id_object.extend(integrity);
    id_object.extend(enc_identity);
    id_object
}

/// RSA labeled KEM (Part 1 43.10): OAEP with the nameAlg for both the hash
/// and MGF1, and the label `IDENTITY\0`.
fn rsa_encrypt_seed<R: CryptoRng + ?Sized>(
    alg: NameAlg,
    modulus: &[u8],
    exponent: u32,
    seed: &[u8],
    rng: &mut R,
) -> Result<Vec<u8>, CredentialError> {
    let exponent = if exponent == 0 {
        DEFAULT_RSA_EXPONENT
    } else {
        exponent
    };
    let key = RsaPublicKey::new(
        BoxedUint::from_be_slice_vartime(modulus),
        BoxedUint::from(u64::from(exponent)),
    )
    .map_err(|_| CredentialError::Key("an RSA modulus or exponent rsa rejects"))?;
    let encrypted = match alg {
        NameAlg::Sha256 => key.encrypt(rng, Oaep::<Sha256>::new_with_label(IDENTITY), seed),
        NameAlg::Sha384 => key.encrypt(rng, Oaep::<Sha384>::new_with_label(IDENTITY), seed),
        NameAlg::Sha512 => key.encrypt(rng, Oaep::<Sha512>::new_with_label(IDENTITY), seed),
    };
    encrypted.map_err(|_| CredentialError::Key("an RSA key too small for OAEP with this hash"))
}

/// An ephemeral ECC key for the ECC labeled KEM.
enum EphemeralKey {
    P256(p256::SecretKey),
    P384(p384::SecretKey),
    P521(p521::SecretKey),
}

impl EphemeralKey {
    fn random<R: CryptoRng + ?Sized>(curve: EccCurve, rng: &mut R) -> Self {
        match curve {
            EccCurve::NistP256 => Self::P256(p256::SecretKey::generate_from_rng(rng)),
            EccCurve::NistP384 => Self::P384(p384::SecretKey::generate_from_rng(rng)),
            EccCurve::NistP521 => Self::P521(p521::SecretKey::generate_from_rng(rng)),
        }
    }
}

/// ECC labeled KEM (Part 1 44.7): Z is the x-coordinate of the ephemeral
/// key times the EK's point, `seed = KDFe(nameAlg, Z, "IDENTITY",
/// ephemeral.x, EK.x, digest bits)`, and the encrypted secret is the
/// ephemeral public point, both coordinates padded to the field size and
/// hashed exactly as sent (44.5).
fn ecc_seed(
    alg: NameAlg,
    curve: EccCurve,
    x: &[u8],
    y: &[u8],
    ephemeral: &EphemeralKey,
) -> Result<(Zeroizing<Vec<u8>>, Vec<u8>), CredentialError> {
    let exchange = ecc_exchange(curve, x, y, ephemeral)?;
    let digest_bits = u32::try_from(alg.digest_len() * 8).expect("a digest's bit count fits");
    let seed = Zeroizing::new(kdfe(
        alg,
        &exchange.z,
        IDENTITY,
        &exchange.ephemeral_x,
        x,
        digest_bits,
    ));
    Ok((seed, exchange.secret()))
}

/// The ECDH half of the ECC labeled KEM.
struct Exchange {
    /// The shared point's x-coordinate, padded to the field size.
    z: Zeroizing<Vec<u8>>,
    /// The ephemeral public point's coordinates, padded to the field size.
    ephemeral_x: Vec<u8>,
    ephemeral_y: Vec<u8>,
}

impl Exchange {
    /// The marshaled TPMS_ECC_POINT the TPM receives as the secret.
    fn secret(&self) -> Vec<u8> {
        let mut secret = Vec::with_capacity(4 + self.ephemeral_x.len() + self.ephemeral_y.len());
        for coordinate in [&self.ephemeral_x, &self.ephemeral_y] {
            secret.extend_from_slice(
                &u16::try_from(coordinate.len())
                    .expect("a field size fits")
                    .to_be_bytes(),
            );
            secret.extend_from_slice(coordinate);
        }
        secret
    }
}

fn ecc_exchange(
    curve: EccCurve,
    x: &[u8],
    y: &[u8],
    ephemeral: &EphemeralKey,
) -> Result<Exchange, CredentialError> {
    let field = match curve {
        EccCurve::NistP256 => 32,
        EccCurve::NistP384 => 48,
        EccCurve::NistP521 => 66,
    };
    if x.len() > field || y.len() > field {
        return Err(CredentialError::Key(
            "an ECC coordinate longer than its field",
        ));
    }
    let mut point = vec![0x04];
    point.extend(std::iter::repeat_n(0, field - x.len()));
    point.extend_from_slice(x);
    point.extend(std::iter::repeat_n(0, field - y.len()));
    point.extend_from_slice(y);
    let off_curve = |_| CredentialError::Key("an ECC point that is not on its curve");
    macro_rules! exchange {
        ($curve:ident, $secret:expr) => {{
            let ek = $curve::PublicKey::from_sec1_bytes(&point).map_err(off_curve)?;
            let shared = $curve::ecdh::diffie_hellman($secret.to_nonzero_scalar(), ek.as_affine());
            let public = $secret.public_key().to_sec1_point(false);
            let public = public.as_bytes();
            Exchange {
                z: Zeroizing::new(shared.raw_secret_bytes().to_vec()),
                ephemeral_x: public[1..1 + field].to_vec(),
                ephemeral_y: public[1 + field..].to_vec(),
            }
        }};
    }
    Ok(match (curve, ephemeral) {
        (EccCurve::NistP256, EphemeralKey::P256(secret)) => exchange!(p256, secret),
        (EccCurve::NistP384, EphemeralKey::P384(secret)) => exchange!(p384, secret),
        (EccCurve::NistP521, EphemeralKey::P521(secret)) => exchange!(p521, secret),
        _ => return Err(CredentialError::Key("an ephemeral key on another curve")),
    })
}

#[cfg(test)]
mod tests;

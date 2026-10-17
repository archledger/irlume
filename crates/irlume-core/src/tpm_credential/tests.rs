// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright the irlume contributors.

//! Known-answer tests from the TCG reference code, tpm2-pytss, go-tpm and
//! two credentials swtpm activated, then round trips through a software
//! ActivateCredential for every EK shape irlume supports.

use std::convert::Infallible;

use p256::elliptic_curve::sec1::ToSec1Point;
use p256::elliptic_curve::Generate;
use rand::{Rng, TryCryptoRng, TryRng};
use rsa::traits::PublicKeyParts;
use rsa::RsaPrivateKey;

use super::*;

fn hex(text: &str) -> Vec<u8> {
    assert_eq!(text.len() % 2, 0, "{text}");
    (0..text.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&text[i..i + 2], 16).unwrap())
        .collect()
}

fn vectors() -> serde_json::Value {
    serde_json::from_str(include_str!("vectors.json")).unwrap()
}

fn field<'a>(vector: &'a serde_json::Value, name: &str) -> &'a str {
    vector[name]
        .as_str()
        .unwrap_or_else(|| panic!("{name} in {vector}"))
}

/// Hands out fixed octets, then fails the test if asked for more.
struct FixedRng(Vec<u8>);

impl TryRng for FixedRng {
    type Error = Infallible;

    fn try_next_u32(&mut self) -> Result<u32, Infallible> {
        let mut bytes = [0; 4];
        self.try_fill_bytes(&mut bytes)?;
        Ok(u32::from_le_bytes(bytes))
    }

    fn try_next_u64(&mut self) -> Result<u64, Infallible> {
        let mut bytes = [0; 8];
        self.try_fill_bytes(&mut bytes)?;
        Ok(u64::from_le_bytes(bytes))
    }

    fn try_fill_bytes(&mut self, dst: &mut [u8]) -> Result<(), Infallible> {
        assert!(dst.len() <= self.0.len(), "the fixed RNG ran out");
        let rest = self.0.split_off(dst.len());
        dst.copy_from_slice(&self.0);
        self.0 = rest;
        Ok(())
    }
}

impl TryCryptoRng for FixedRng {}

/// What the vectors need from a marshaled TPMT_PUBLIC.
struct ParsedPublic {
    name_alg: NameAlg,
    symmetric: EkSymmetric,
    key: EkPublicKey,
}

fn parse_public(bytes: &[u8]) -> ParsedPublic {
    let mut at = 0;
    let u16_at = |at: &mut usize| {
        let value = u16::from_be_bytes([bytes[*at], bytes[*at + 1]]);
        *at += 2;
        value
    };
    let kind = u16_at(&mut at);
    let name_alg = NameAlg::from_tpm_alg(u16_at(&mut at)).unwrap();
    at += 4; // objectAttributes
    let policy = usize::from(u16_at(&mut at));
    at += policy;
    let symmetric_alg = u16_at(&mut at);
    let mut symmetric = EkSymmetric::Aes128Cfb;
    if symmetric_alg != 0x0010 {
        assert_eq!(symmetric_alg, 0x0006, "AES");
        symmetric = match u16_at(&mut at) {
            128 => EkSymmetric::Aes128Cfb,
            256 => EkSymmetric::Aes256Cfb,
            other => panic!("AES-{other}"),
        };
        assert_eq!(u16_at(&mut at), 0x0043, "CFB");
    }
    let scheme = u16_at(&mut at);
    if scheme != 0x0010 {
        at += 2; // scheme hash
    }
    let sized = |at: &mut usize| {
        let len = usize::from(u16::from_be_bytes([bytes[*at], bytes[*at + 1]]));
        *at += 2;
        let value = bytes[*at..*at + len].to_vec();
        *at += len;
        value
    };
    let key = match kind {
        0x0001 => {
            at += 2; // keyBits
            let exponent = u32::from_be_bytes(bytes[at..at + 4].try_into().unwrap());
            at += 4;
            EkPublicKey::Rsa {
                modulus: sized(&mut at),
                exponent,
            }
        }
        0x0023 => {
            let curve = match u16::from_be_bytes([bytes[at], bytes[at + 1]]) {
                0x0003 => EccCurve::NistP256,
                0x0004 => EccCurve::NistP384,
                0x0005 => EccCurve::NistP521,
                other => panic!("curve {other:#x}"),
            };
            at += 2;
            let kdf = u16::from_be_bytes([bytes[at], bytes[at + 1]]);
            at += 2;
            if kdf != 0x0010 {
                at += 2;
            }
            let x = sized(&mut at);
            let y = sized(&mut at);
            EkPublicKey::Ecc { curve, x, y }
        }
        other => panic!("type {other:#x}"),
    };
    ParsedPublic {
        name_alg,
        symmetric,
        key,
    }
}

fn ephemeral(curve: EccCurve, private: &[u8]) -> EphemeralKey {
    match curve {
        EccCurve::NistP256 => EphemeralKey::P256(p256::SecretKey::from_slice(private).unwrap()),
        EccCurve::NistP384 => EphemeralKey::P384(p384::SecretKey::from_slice(private).unwrap()),
        EccCurve::NistP521 => EphemeralKey::P521(p521::SecretKey::from_slice(private).unwrap()),
    }
}

// --- known answers ----------------------------------------------------------

#[test]
fn kdfa_matches_the_tcg_reference_self_test() {
    // TCG TPM reference code V184, include/private/KdfTestData.h: the label
    // carries its own zero octet, so none is added.
    let key = hex("271FA08BBDC5060EC3DFA928FF9B73123A12DA0C");
    // "KDFSELFTESTLABEL" and its zero octet, 17 octets.
    let label = hex("4B44465345 4C4654455354 4C4142454C00"
        .replace(' ', "")
        .as_str());
    let (u, v) = (hex("CE244F395DCA7391"), hex("DA504031DDF12E83"));
    for (alg, expected) in [
        (NameAlg::Sha256, "bb0259e1c8ba607e6a2cd704b69a902e9ade84c4"),
        (NameAlg::Sha384, "1dce70c9113eb2dba47bd9cfc72bf46f45b09312"),
        (NameAlg::Sha512, "8be2c1b85b78569b9fa759f5857c56d684810fd3"),
    ] {
        assert_eq!(
            *kdfa(alg, &key, &label, &u, &v, 160),
            hex(expected),
            "{alg:?}"
        );
    }
}

#[test]
fn kdfa_and_kdfe_match_tpm2_pytss() {
    // tpm2-pytss test/test_crypto.py, master 1804b6517f3e: KDFa's label has
    // no zero octet (one is added); KDFe's Use is hashed as given.
    assert_eq!(
        *kdfa(NameAlg::Sha256, b"key data", b"label data", b"contextU data", b"contextV data", 2048),
        hex(concat!(
            "61e2b87b4066c094a3507408f5af015bce85748433f8b3032571e58478dc60814520f5a9e89fc8c99655be1b07d98f97",
            "2a7ef79b5899be86e71067249c55515497009a97fdf05dec2eed77b4f58a2f2918441357363f607b2166f5a7d93e45f7",
            "d636116a8a5a06e10a4a4a99b49e15eaedb09869cda56349345071aee80c36ba65b174e16b7594062ce6271bed6ef254",
            "f7bdb4fe757fac449ecb5b72484ef4673143b3d94d4cd23a06eab14998a7e2a0998b82b96eadb61c5aa83e21b981f903",
            "7788460a19b15ed88031d69d46f3c30591924cc1d0ae693b186ead3d762765a7cc36a7a22250429ffbadeb41008dee99",
            "10af41c3c9e6d7aa4965df2f3af3437b",
        ))
    );
    assert_eq!(
        *kdfe(
            NameAlg::Sha256,
            b"z data",
            b"use data",
            b"partyuinfo data",
            b"partyvinfo data",
            256
        ),
        hex("407c8b62921c85067ec56421145eb43401afa2ac28b9385433916d834ca9dc58")
    );
}

#[test]
fn kdfa_and_kdfe_match_go_tpm() {
    let vectors = vectors();
    let alg = |v: &serde_json::Value| {
        NameAlg::from_tpm_alg(u16::try_from(v["HashAlg"].as_u64().unwrap()).unwrap()).unwrap()
    };
    let bits = |v: &serde_json::Value| u32::try_from(v["Bits"].as_u64().unwrap()).unwrap();
    let kdfa_vectors = vectors["go_tpm_kdfa"].as_array().unwrap();
    assert_eq!(kdfa_vectors.len(), 10);
    for v in kdfa_vectors {
        // go-tpm adds the label's zero octet itself, as KDFa does.
        let got = kdfa(
            alg(v),
            &hex(field(v, "Key")),
            field(v, "Label").as_bytes(),
            &hex(field(v, "ContextU")),
            &hex(field(v, "ContextV")),
            bits(v),
        );
        assert_eq!(*got, hex(field(v, "Result")), "{}", field(v, "Name"));
    }
    let kdfe_vectors = vectors["go_tpm_kdfe"].as_array().unwrap();
    assert_eq!(kdfe_vectors.len(), 10);
    for v in kdfe_vectors {
        // KDFe hashes Use as given; go-tpm appends the zero octet.
        let mut label = field(v, "Label").as_bytes().to_vec();
        label.push(0);
        let got = kdfe(
            alg(v),
            &hex(field(v, "Z")),
            &label,
            &hex(field(v, "ContextU")),
            &hex(field(v, "ContextV")),
            bits(v),
        );
        assert_eq!(*got, hex(field(v, "Result")), "{}", field(v, "Name"));
    }
}

#[test]
fn the_rsa_kem_matches_go_tpm_vectors_a_tpm_activated() {
    let vectors = vectors();
    let rsa = vectors["go_tpm_rsa_kem"].as_array().unwrap();
    assert_eq!(
        rsa.len(),
        12,
        "RSA-2048, 3072 and 4096 with SHA-256, 384 and 512"
    );
    for v in rsa {
        let public = parse_public(&hex(field(v, "PublicKey")));
        let EkPublicKey::Rsa { modulus, exponent } = &public.key else {
            panic!("an RSA key")
        };
        let got = rsa_encrypt_seed(
            public.name_alg,
            modulus,
            *exponent,
            &hex(field(v, "Secret")),
            &mut FixedRng(hex(field(v, "OAEPSalt"))),
        )
        .unwrap();
        assert_eq!(got, hex(field(v, "Ciphertext")), "{}", field(v, "Name"));
    }
}

#[test]
fn the_ecc_kem_matches_go_tpm_vectors_a_tpm_activated() {
    let vectors = vectors();
    let ecc = vectors["go_tpm_ecc_kem"].as_array().unwrap();
    assert_eq!(ecc.len(), 11, "P-256 and P-521 with SHA-256, 384 and 512");
    for v in ecc {
        let public = parse_public(&hex(field(v, "PublicKey")));
        let EkPublicKey::Ecc { curve, x, y } = &public.key else {
            panic!("an ECC key")
        };
        let exchange = ecc_exchange(
            *curve,
            x,
            y,
            &ephemeral(*curve, &hex(field(v, "EphemeralPrivate"))),
        )
        .unwrap();
        let secret = hex(field(v, "Secret"));
        let bits = u32::try_from(secret.len() * 8).unwrap();
        let seed = kdfe(
            public.name_alg,
            &exchange.z,
            IDENTITY,
            &exchange.ephemeral_x,
            x,
            bits,
        );
        assert_eq!(*seed, secret, "{}", field(v, "Name"));
        assert_eq!(
            exchange.secret(),
            hex(field(v, "Ciphertext")),
            "{}",
            field(v, "Name")
        );
    }
}

#[test]
fn full_credentials_match_two_that_swtpm_activated() {
    let vectors = vectors();
    let credential = hex("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f");

    let rsa = &vectors["swtpm_make_credential"]["rsa_L1"];
    let public = parse_public(&hex(field(rsa, "ek_tpmt_public")));
    let ek = EkTarget {
        name_alg: public.name_alg,
        symmetric: public.symmetric,
        key: &public.key,
    };
    let mut rng = FixedRng([hex(field(rsa, "seed")), hex(field(rsa, "oaep_seed"))].concat());
    let made =
        make_credential(&ek, &hex(field(rsa, "object_name")), &credential, &mut rng).unwrap();
    assert_eq!(made.id_object, hex(field(rsa, "id_object")));
    assert_eq!(made.encrypted_secret, hex(field(rsa, "encrypted_secret")));

    let ecc = &vectors["swtpm_make_credential"]["ecc_L2"];
    let public = parse_public(&hex(field(ecc, "ek_tpmt_public")));
    let ek = EkTarget {
        name_alg: public.name_alg,
        symmetric: public.symmetric,
        key: &public.key,
    };
    let EkPublicKey::Ecc { curve, x, y } = &public.key else {
        panic!("an ECC key")
    };
    let key = ephemeral(*curve, &hex(field(ecc, "ephemeral_private")));
    let (seed, secret) = ecc_seed(ek.name_alg, *curve, x, y, &key).unwrap();
    assert_eq!(*seed, hex(field(ecc, "seed")));
    assert_eq!(secret, hex(field(ecc, "encrypted_secret")));
    let name = hex(field(ecc, "object_name"));
    assert_eq!(
        protect(&ek, &seed, &name, &credential),
        hex(field(ecc, "id_object"))
    );
    assert_eq!(
        *kdfa(ek.name_alg, &seed, STORAGE, &name, &[], 128),
        hex(field(ecc, "sym_key"))
    );
}

// --- round trips through a software ActivateCredential -----------------------

enum PrivateEk {
    Rsa(RsaPrivateKey),
    P256(p256::SecretKey),
    P384(p384::SecretKey),
    P521(p521::SecretKey),
}

impl PrivateEk {
    fn public(&self) -> EkPublicKey {
        match self {
            Self::Rsa(key) => EkPublicKey::Rsa {
                modulus: key.n_bytes().to_vec(),
                exponent: 0,
            },
            Self::P256(key) => ecc_public(
                EccCurve::NistP256,
                key.public_key().to_sec1_point(false).as_bytes(),
            ),
            Self::P384(key) => ecc_public(
                EccCurve::NistP384,
                key.public_key().to_sec1_point(false).as_bytes(),
            ),
            Self::P521(key) => ecc_public(
                EccCurve::NistP521,
                key.public_key().to_sec1_point(false).as_bytes(),
            ),
        }
    }
}

fn ecc_public(curve: EccCurve, point: &[u8]) -> EkPublicKey {
    let field = (point.len() - 1) / 2;
    EkPublicKey::Ecc {
        curve,
        x: point[1..1 + field].to_vec(),
        y: point[1 + field..].to_vec(),
    }
}

/// What a TPM does in TPM2_ActivateCredential: recover the seed, check the
/// HMAC over encIdentity and the Name, then decrypt the credential.
fn activate(
    ek: &EkTarget<'_>,
    private: &PrivateEk,
    name: &[u8],
    made: &Credential,
) -> Option<Vec<u8>> {
    let alg = ek.name_alg;
    let digest_bits = u32::try_from(alg.digest_len() * 8).unwrap();
    let seed = match private {
        PrivateEk::Rsa(key) => match alg {
            NameAlg::Sha256 => key.decrypt(
                Oaep::<Sha256>::new_with_label(IDENTITY),
                &made.encrypted_secret,
            ),
            NameAlg::Sha384 => key.decrypt(
                Oaep::<Sha384>::new_with_label(IDENTITY),
                &made.encrypted_secret,
            ),
            NameAlg::Sha512 => key.decrypt(
                Oaep::<Sha512>::new_with_label(IDENTITY),
                &made.encrypted_secret,
            ),
        }
        .ok()?,
        _ => {
            let secret = &made.encrypted_secret;
            let x_len = usize::from(u16::from_be_bytes([secret[0], secret[1]]));
            let x = &secret[2..2 + x_len];
            let y = &secret[4 + x_len..];
            let point = [&[0x04][..], x, y].concat();
            let EkPublicKey::Ecc { x: ek_x, .. } = ek.key else {
                return None;
            };
            let z = match private {
                PrivateEk::P256(key) => p256::ecdh::diffie_hellman(
                    key.to_nonzero_scalar(),
                    p256::PublicKey::from_sec1_bytes(&point).ok()?.as_affine(),
                )
                .raw_secret_bytes()
                .to_vec(),
                PrivateEk::P384(key) => p384::ecdh::diffie_hellman(
                    key.to_nonzero_scalar(),
                    p384::PublicKey::from_sec1_bytes(&point).ok()?.as_affine(),
                )
                .raw_secret_bytes()
                .to_vec(),
                PrivateEk::P521(key) => p521::ecdh::diffie_hellman(
                    key.to_nonzero_scalar(),
                    p521::PublicKey::from_sec1_bytes(&point).ok()?.as_affine(),
                )
                .raw_secret_bytes()
                .to_vec(),
                PrivateEk::Rsa(_) => unreachable!(),
            };
            kdfe(alg, &z, IDENTITY, x, ek_x, digest_bits).to_vec()
        }
    };
    let blob = &made.id_object;
    let hmac_len = usize::from(u16::from_be_bytes([blob[0], blob[1]]));
    let (integrity, enc_identity) = blob[2..].split_at(hmac_len);
    let hmac_key = kdfa(alg, &seed, INTEGRITY, &[], &[], digest_bits);
    let mut expected = Vec::new();
    alg.hmac_into(&hmac_key, &[enc_identity, name], &mut expected);
    if expected != integrity {
        return None;
    }
    let sym_key = kdfa(alg, &seed, STORAGE, name, &[], ek.symmetric.key_bits());
    let mut plain = enc_identity.to_vec();
    match ek.symmetric {
        EkSymmetric::Aes128Cfb => {
            cfb_mode::Decryptor::<Aes128>::new_from_slices(&sym_key, &[0; 16])
                .unwrap()
                .decrypt(&mut plain)
        }
        EkSymmetric::Aes256Cfb => {
            cfb_mode::Decryptor::<Aes256>::new_from_slices(&sym_key, &[0; 16])
                .unwrap()
                .decrypt(&mut plain)
        }
    }
    let len = usize::from(u16::from_be_bytes([plain[0], plain[1]]));
    (plain.len() == 2 + len).then(|| plain[2..].to_vec())
}

#[test]
fn a_credential_round_trips_for_every_ek_shape_irlume_supports() {
    let mut rng = rand::rng();
    let rsa = RsaPrivateKey::new(&mut rng, 2048).unwrap();
    let shapes = [
        // L-1, H-1; H-6 and H-7 use the same code with SHA-384 and AES-256.
        (
            NameAlg::Sha256,
            EkSymmetric::Aes128Cfb,
            PrivateEk::Rsa(rsa.clone()),
        ),
        (NameAlg::Sha384, EkSymmetric::Aes256Cfb, PrivateEk::Rsa(rsa)),
        // L-2, H-2, H-3, H-4.
        (
            NameAlg::Sha256,
            EkSymmetric::Aes128Cfb,
            PrivateEk::P256(p256::SecretKey::generate_from_rng(&mut rng)),
        ),
        (
            NameAlg::Sha384,
            EkSymmetric::Aes256Cfb,
            PrivateEk::P384(p384::SecretKey::generate_from_rng(&mut rng)),
        ),
        (
            NameAlg::Sha512,
            EkSymmetric::Aes256Cfb,
            PrivateEk::P521(p521::SecretKey::generate_from_rng(&mut rng)),
        ),
    ];
    let name = hex("000bf3a3a57f799498275f749e526f667c3cf4bf89fa09bebeb80b94d550486424c0");
    let other_name = hex("000b0000000000000000000000000000000000000000000000000000000000000000");
    for (name_alg, symmetric, private) in &shapes {
        let key = private.public();
        let ek = EkTarget {
            name_alg: *name_alg,
            symmetric: *symmetric,
            key: &key,
        };
        let mut credential = vec![0u8; name_alg.digest_len()];
        rng.fill_bytes(&mut credential);
        let made = make_credential(&ek, &name, &credential, &mut rng).unwrap();
        assert_eq!(
            activate(&ek, private, &name, &made),
            Some(credential.clone()),
            "{name_alg:?}"
        );
        // Bound to the Name: another object's Name fails the HMAC, the
        // TPM_RC_INTEGRITY case.
        assert_eq!(
            activate(&ek, private, &other_name, &made),
            None,
            "{name_alg:?}"
        );
        // A fresh credential uses a fresh seed.
        let again = make_credential(&ek, &name, &credential, &mut rng).unwrap();
        assert_ne!(again.encrypted_secret, made.encrypted_secret);
    }
}

#[test]
fn credentials_irlume_cannot_make_are_refused() {
    let point = p256::SecretKey::generate_from_rng(&mut rand::rng()).public_key();
    let key = ecc_public(EccCurve::NistP256, point.to_sec1_point(false).as_bytes());
    let ek = EkTarget {
        name_alg: NameAlg::Sha256,
        symmetric: EkSymmetric::Aes128Cfb,
        key: &key,
    };
    let name = [0x00, 0x0b, 1, 2, 3];
    let mut rng = rand::rng();
    assert_eq!(
        make_credential(&ek, &name, &[1; 33], &mut rng),
        Err(CredentialError::CredentialLength(33))
    );
    assert_eq!(
        make_credential(&ek, &[], &[1; 32], &mut rng),
        Err(CredentialError::NoName)
    );
    let off_curve = EkPublicKey::Ecc {
        curve: EccCurve::NistP256,
        x: vec![0x11; 32],
        y: vec![0x22; 32],
    };
    let ek = EkTarget {
        name_alg: NameAlg::Sha256,
        symmetric: EkSymmetric::Aes128Cfb,
        key: &off_curve,
    };
    assert!(matches!(
        make_credential(&ek, &name, &[1; 32], &mut rng),
        Err(CredentialError::Key(_))
    ));
}

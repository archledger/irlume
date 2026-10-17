// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright the irlume contributors.

//! Test-only certificates: a small DER builder, test CAs and EK
//! certificates with full control over every field, for the ek_cert tests
//! and the swtpm tests of the endorsement check.

use std::sync::OnceLock;

use der::flagset::FlagSet;
use p256::ecdsa::signature::hazmat::PrehashSigner;
use rsa::traits::PublicKeyParts;
use rsa::RsaPrivateKey;

use super::*;

// --- DER building -----------------------------------------------------------

pub(crate) fn tlv(tag: u8, content: &[u8]) -> Vec<u8> {
    let mut out = vec![tag];
    let len = content.len();
    if len < 0x80 {
        out.push(len as u8);
    } else {
        let bytes = len.to_be_bytes();
        let skip = bytes.iter().take_while(|b| **b == 0).count();
        out.push(0x80 | (bytes.len() - skip) as u8);
        out.extend_from_slice(&bytes[skip..]);
    }
    out.extend_from_slice(content);
    out
}

pub(crate) fn seq(parts: &[Vec<u8>]) -> Vec<u8> {
    tlv(0x30, &parts.concat())
}

pub(crate) fn set(parts: &[Vec<u8>]) -> Vec<u8> {
    tlv(0x31, &parts.concat())
}

pub(crate) fn oid_der(id: &str) -> Vec<u8> {
    ObjectIdentifier::new(id).unwrap().to_der().unwrap()
}

/// A positive INTEGER from big-endian magnitude bytes.
pub(crate) fn int(magnitude: &[u8]) -> Vec<u8> {
    let skip = magnitude
        .iter()
        .take_while(|b| **b == 0)
        .count()
        .min(magnitude.len().saturating_sub(1));
    let magnitude = &magnitude[skip..];
    let mut content = Vec::new();
    if magnitude.first().is_some_and(|b| b & 0x80 != 0) {
        content.push(0);
    }
    content.extend_from_slice(magnitude);
    tlv(0x02, &content)
}

pub(crate) fn utf8(text: &str) -> Vec<u8> {
    tlv(0x0c, text.as_bytes())
}

pub(crate) fn octet(bytes: &[u8]) -> Vec<u8> {
    tlv(0x04, bytes)
}

pub(crate) fn bit_string(bytes: &[u8]) -> Vec<u8> {
    let mut content = vec![0];
    content.extend_from_slice(bytes);
    tlv(0x03, &content)
}

pub(crate) fn null() -> Vec<u8> {
    vec![0x05, 0x00]
}

pub(crate) fn explicit(n: u8, content: &[u8]) -> Vec<u8> {
    tlv(0xa0 | n, content)
}

pub(crate) fn utc_time(text: &str) -> Vec<u8> {
    tlv(0x17, text.as_bytes())
}

pub(crate) fn name(cn: &str) -> Vec<u8> {
    seq(&[set(&[seq(&[oid_der("2.5.4.3"), utf8(cn)])])])
}

// --- keys -------------------------------------------------------------------

#[derive(Clone)]
pub(crate) enum Key {
    P256(p256::ecdsa::SigningKey),
    P384(p384::ecdsa::SigningKey),
    P521(p521::ecdsa::SigningKey),
    Rsa(RsaPrivateKey),
}

impl Key {
    pub(crate) fn p256(seed: u8) -> Self {
        Self::P256(p256::ecdsa::SigningKey::from_slice(&Sha256::digest([seed])).unwrap())
    }

    pub(crate) fn p384(seed: u8) -> Self {
        Self::P384(p384::ecdsa::SigningKey::from_slice(&Sha384::digest([seed])).unwrap())
    }

    pub(crate) fn p521(seed: u8) -> Self {
        let mut scalar = vec![0, 0];
        scalar.extend_from_slice(&Sha512::digest([seed]));
        Self::P521(p521::ecdsa::SigningKey::from_slice(&scalar).unwrap())
    }

    /// One of three RSA-2048 keys, generated once per test run.
    pub(crate) fn rsa(i: usize) -> Self {
        static KEYS: OnceLock<Vec<RsaPrivateKey>> = OnceLock::new();
        let keys = KEYS.get_or_init(|| {
            let mut rng = rand::rng();
            (0..3)
                .map(|_| RsaPrivateKey::new(&mut rng, 2048).unwrap())
                .collect()
        });
        Self::Rsa(keys[i].clone())
    }

    pub(crate) fn spki(&self) -> Vec<u8> {
        let ec = |curve: &str, point: &[u8]| {
            seq(&[
                seq(&[oid_der("1.2.840.10045.2.1"), oid_der(curve)]),
                bit_string(point),
            ])
        };
        match self {
            Self::P256(k) => ec(
                "1.2.840.10045.3.1.7",
                k.verifying_key().to_sec1_point(false).as_bytes(),
            ),
            Self::P384(k) => ec(
                "1.3.132.0.34",
                k.verifying_key().to_sec1_point(false).as_bytes(),
            ),
            Self::P521(k) => ec(
                "1.3.132.0.35",
                k.verifying_key().to_sec1_point(false).as_bytes(),
            ),
            Self::Rsa(k) => seq(&[
                seq(&[oid_der("1.2.840.113549.1.1.1"), null()]),
                bit_string(&seq(&[int(&k.n_bytes()), int(&k.e_bytes())])),
            ]),
        }
    }

    pub(crate) fn key_id(&self) -> Vec<u8> {
        Sha256::digest(self.spki())[..20].to_vec()
    }

    /// The signature algorithm this key signs with by default.
    pub(crate) fn default_alg(&self) -> Vec<u8> {
        match self {
            Self::P256(_) => ecdsa_alg("1.2.840.10045.4.3.2"),
            Self::P384(_) => ecdsa_alg("1.2.840.10045.4.3.3"),
            Self::P521(_) => ecdsa_alg("1.2.840.10045.4.3.4"),
            Self::Rsa(_) => rsa_alg("1.2.840.113549.1.1.11"),
        }
    }

    pub(crate) fn sign(&self, alg: &[u8], tbs: &[u8]) -> Vec<u8> {
        let alg = AlgorithmIdentifierOwned::from_der(alg).unwrap();
        let Ok(scheme) = scheme(&alg) else {
            // An algorithm irlume refuses: any bytes will do.
            return vec![0x5a; 64];
        };
        match (self, scheme) {
            (Self::P256(k), Scheme::Ecdsa(h)) => {
                let sig: p256::ecdsa::Signature = k.sign_prehash(&h.digest(tbs)).unwrap();
                sig.to_der().as_bytes().to_vec()
            }
            (Self::P384(k), Scheme::Ecdsa(h)) => {
                let sig: p384::ecdsa::Signature = k.sign_prehash(&h.digest(tbs)).unwrap();
                sig.to_der().as_bytes().to_vec()
            }
            (Self::P521(k), Scheme::Ecdsa(h)) => {
                let sig: p521::ecdsa::Signature = k.sign_prehash(&h.digest(tbs)).unwrap();
                sig.to_der().as_bytes().to_vec()
            }
            (Self::Rsa(k), Scheme::RsaPkcs1(h)) => {
                let padding = match h {
                    HashAlg::Sha256 => Pkcs1v15Sign::new::<Sha256>(),
                    HashAlg::Sha384 => Pkcs1v15Sign::new::<Sha384>(),
                    HashAlg::Sha512 => Pkcs1v15Sign::new::<Sha512>(),
                };
                k.sign(padding, &h.digest(tbs)).unwrap()
            }
            (Self::Rsa(k), Scheme::RsaPss(HashAlg::Sha256, salt)) => k
                .sign_with_rng(
                    &mut rand::rng(),
                    Pss::<Sha256>::new_with_salt(salt),
                    &HashAlg::Sha256.digest(tbs),
                )
                .unwrap(),
            _ => panic!("the test asked a key to sign with a scheme it cannot use"),
        }
    }
}

pub(crate) fn rsa_alg(id: &str) -> Vec<u8> {
    seq(&[oid_der(id), null()])
}

pub(crate) fn ecdsa_alg(id: &str) -> Vec<u8> {
    seq(&[oid_der(id)])
}

pub(crate) fn pss_sha256_alg(salt: u8) -> Vec<u8> {
    let sha256 = seq(&[oid_der("2.16.840.1.101.3.4.2.1"), null()]);
    seq(&[
        oid_der("1.2.840.113549.1.1.10"),
        seq(&[
            explicit(0, &sha256),
            explicit(1, &seq(&[oid_der("1.2.840.113549.1.1.8"), sha256.clone()])),
            explicit(2, &int(&[salt])),
        ]),
    ])
}

// --- certificates -----------------------------------------------------------

/// Extensions as (OID, critical, value), editable before encoding.
#[derive(Clone, Default)]
pub(crate) struct Exts(pub(crate) Vec<(&'static str, bool, Vec<u8>)>);

impl Exts {
    pub(crate) fn set(&mut self, id: &'static str, critical: bool, value: Vec<u8>) -> &mut Self {
        self.remove(id);
        self.0.push((id, critical, value));
        self
    }

    pub(crate) fn remove(&mut self, id: &str) -> &mut Self {
        self.0.retain(|(e, _, _)| *e != id);
        self
    }

    pub(crate) fn encode(&self) -> Vec<u8> {
        seq(&self
            .0
            .iter()
            .map(|(id, critical, value)| {
                let mut parts = vec![oid_der(id)];
                if *critical {
                    parts.push(vec![0x01, 0x01, 0xff]);
                }
                parts.push(octet(value));
                seq(&parts)
            })
            .collect::<Vec<_>>())
    }
}

pub(crate) const BC: &str = "2.5.29.19";
pub(crate) const KU: &str = "2.5.29.15";
pub(crate) const EKU: &str = "2.5.29.37";
pub(crate) const SAN: &str = "2.5.29.17";
pub(crate) const SKI: &str = "2.5.29.14";
pub(crate) const AKI: &str = "2.5.29.35";
pub(crate) const EK_CERTIFICATE: &str = "2.23.133.8.1";

pub(crate) fn bc(ca: bool, path_len: Option<u8>) -> Vec<u8> {
    BasicConstraints {
        ca,
        path_len_constraint: path_len,
    }
    .to_der()
    .unwrap()
}

pub(crate) fn ku(flags: impl Into<FlagSet<KeyUsages>>) -> Vec<u8> {
    KeyUsage(flags.into()).to_der().unwrap()
}

pub(crate) fn eku(ids: &[&str]) -> Vec<u8> {
    ExtendedKeyUsage(
        ids.iter()
            .map(|id| ObjectIdentifier::new(id).unwrap())
            .collect(),
    )
    .to_der()
    .unwrap()
}

pub(crate) fn aki(id: &[u8]) -> Vec<u8> {
    seq(&[tlv(0x80, id)])
}

pub(crate) fn tpm_san(
    manufacturer: Option<&str>,
    model: Option<&str>,
    version: Option<&str>,
) -> Vec<u8> {
    let rdns: Vec<Vec<u8>> = [
        ("2.23.133.2.1", manufacturer),
        ("2.23.133.2.2", model),
        ("2.23.133.2.3", version),
    ]
    .iter()
    .filter_map(|(id, value)| value.map(|v| set(&[seq(&[oid_der(id), utf8(v)])])))
    .collect();
    seq(&[tlv(0xa4, &seq(&rdns))])
}

/// What one certificate says, before it is signed.
#[derive(Clone)]
pub(crate) struct Spec {
    pub(crate) subject: Vec<u8>,
    pub(crate) key: Key,
    pub(crate) exts: Exts,
    pub(crate) not_before: &'static str,
    pub(crate) not_after: &'static str,
    pub(crate) version3: bool,
    /// A SubjectPublicKeyInfo to certify in place of `key`'s: an EK the
    /// test has no private key for.
    pub(crate) spki: Option<Vec<u8>>,
}

/// A signed CA certificate, kept with what its children need.
#[derive(Clone)]
pub(crate) struct Ca {
    pub(crate) der: Vec<u8>,
    pub(crate) name: Vec<u8>,
    pub(crate) key: Key,
}

pub(crate) fn issue(
    spec: &Spec,
    issuer_name: &[u8],
    issuer_key: &Key,
    alg: Option<Vec<u8>>,
) -> Vec<u8> {
    let alg = alg.unwrap_or_else(|| issuer_key.default_alg());
    let mut fields = Vec::new();
    if spec.version3 {
        fields.push(explicit(0, &int(&[2])));
    }
    fields.push(int(&Sha256::digest(&spec.subject)[..8]));
    fields.push(alg.clone());
    fields.push(issuer_name.to_vec());
    fields.push(seq(&[utc_time(spec.not_before), utc_time(spec.not_after)]));
    fields.push(spec.subject.clone());
    fields.push(spec.spki.clone().unwrap_or_else(|| spec.key.spki()));
    if !spec.exts.0.is_empty() {
        fields.push(explicit(3, &spec.exts.encode()));
    }
    let tbs = seq(&fields);
    let signature = issuer_key.sign(&alg, &tbs);
    seq(&[tbs, alg, bit_string(&signature)])
}

pub(crate) fn ca_spec(cn: &str, key: Key, issuer_key: Option<&Key>) -> Spec {
    let mut exts = Exts::default();
    exts.set(BC, true, bc(true, None))
        .set(KU, true, ku(KeyUsages::KeyCertSign | KeyUsages::CRLSign))
        .set(SKI, false, octet(&key.key_id()));
    if let Some(issuer_key) = issuer_key {
        exts.set(AKI, false, aki(&issuer_key.key_id()));
    }
    Spec {
        subject: name(cn),
        key,
        exts,
        not_before: "150101000000Z",
        not_after: "450101000000Z",
        version3: true,
        spki: None,
    }
}

pub(crate) fn root(cn: &str, key: Key) -> Ca {
    let spec = ca_spec(cn, key.clone(), None);
    Ca {
        der: issue(&spec, &spec.subject, &key, None),
        name: spec.subject,
        key,
    }
}

pub(crate) fn intermediate_with(
    cn: &str,
    key: Key,
    issuer: &Ca,
    edit: impl FnOnce(&mut Spec),
) -> Ca {
    let mut spec = ca_spec(cn, key.clone(), Some(&issuer.key));
    edit(&mut spec);
    Ca {
        der: issue(&spec, &issuer.name, &issuer.key, None),
        name: spec.subject,
        key,
    }
}

pub(crate) fn intermediate(cn: &str, key: Key, issuer: &Ca) -> Ca {
    intermediate_with(cn, key, issuer, |_| {})
}

pub(crate) fn ek_spec(key: Key, issuer: &Ca) -> Spec {
    let usage = match key {
        Key::Rsa(_) => KeyUsages::KeyEncipherment,
        _ => KeyUsages::KeyAgreement,
    };
    let mut exts = Exts::default();
    exts.set(
        SAN,
        true,
        tpm_san(
            Some("id:53544D20"),
            Some("ST33HTPHAHD4"),
            Some("id:00490004"),
        ),
    )
    .set(BC, true, bc(false, None))
    .set(KU, true, ku(usage))
    .set(EKU, false, eku(&[EK_CERTIFICATE]))
    .set(AKI, false, aki(&issuer.key.key_id()));
    Spec {
        subject: seq(&[]),
        key,
        exts,
        not_before: "250101000000Z",
        not_after: "450101000000Z",
        version3: true,
        spki: None,
    }
}

pub(crate) fn ek_with(key: Key, issuer: &Ca, edit: impl FnOnce(&mut Spec)) -> Vec<u8> {
    let mut spec = ek_spec(key, issuer);
    edit(&mut spec);
    issue(&spec, &issuer.name, &issuer.key, None)
}

pub(crate) fn ek(key: Key, issuer: &Ca) -> Vec<u8> {
    ek_with(key, issuer, |_| {})
}

pub(crate) fn anchors(roots: &[&Ca], intermediates: &[&Ca]) -> Anchors {
    let roots: Vec<&[u8]> = roots.iter().map(|c| c.der.as_slice()).collect();
    let intermediates: Vec<&[u8]> = intermediates.iter().map(|c| c.der.as_slice()).collect();
    Anchors::from_der(&roots, &intermediates).unwrap()
}

/// The SubjectPublicKeyInfo of an EK public key, as an EK certificate
/// carries it.
pub(crate) fn spki_of(key: &EkPublicKey) -> Vec<u8> {
    match key {
        EkPublicKey::Rsa { modulus, exponent } => seq(&[
            seq(&[oid_der("1.2.840.113549.1.1.1"), null()]),
            bit_string(&seq(&[int(modulus), int(&exponent.to_be_bytes())])),
        ]),
        EkPublicKey::Ecc { curve, x, y } => {
            let curve = match curve {
                EccCurve::NistP256 => "1.2.840.10045.3.1.7",
                EccCurve::NistP384 => "1.3.132.0.34",
                EccCurve::NistP521 => "1.3.132.0.35",
            };
            let point = [&[0x04][..], x, y].concat();
            seq(&[
                seq(&[oid_der("1.2.840.10045.2.1"), oid_der(curve)]),
                bit_string(&point),
            ])
        }
    }
}

/// An EK certificate for `ek` under `issuer`, naming manufacturer
/// `manufacturer` (a TCG vendor ID) in its subject alternative name.
pub(crate) fn ek_certificate_for(ek: &EkPublicKey, issuer: &Ca, manufacturer: u32) -> Vec<u8> {
    let usage = match ek {
        EkPublicKey::Rsa { .. } => KeyUsages::KeyEncipherment,
        EkPublicKey::Ecc { .. } => KeyUsages::KeyAgreement,
    };
    ek_with(Key::p256(99), issuer, |spec| {
        spec.spki = Some(spki_of(ek));
        let id = format!("id:{manufacturer:08X}");
        spec.exts
            .set(
                SAN,
                true,
                tpm_san(Some(&id), Some("swtpm"), Some("id:20240125")),
            )
            .set(KU, true, ku(usage));
    })
}

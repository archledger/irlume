// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright the irlume contributors.

//! TPM endorsement key (EK) certificates: where their bytes stop in an NV
//! index, and whether one chains to a TPM vendor's root (ADR-0036 sections
//! 2.1, 2.3, 5 and 6).
//!
//! Everything here is software and offline. [`Anchors::shipped`] is the vendor
//! root and intermediate CA certificates irlume curates in
//! `crates/irlume-core/tpm-ek-anchors/` (refreshed by
//! `scripts/update-tpm-ek-anchors.py`) and embeds at build time; nothing is
//! read from disk or the network at run time.
//!
//! [`EkCertificate::verify`] answers in three ways, which the doctor check
//! maps to its states:
//! - [`ChainVerdict::Verified`]: the certificate is an EK certificate by the
//!   TCG EK Credential Profile and every signature on a path to a pinned root
//!   verifies (`pass`, once irlumed has also matched the EK and run the
//!   same-TPM test).
//! - [`ChainVerdict::Refused`]: on a path that reaches a pinned root, a
//!   signature, a CA constraint or the EK certificate profile fails (`warn`).
//! - [`ChainVerdict::Unverifiable`]: no path can be judged, for instance the
//!   issuer is not in irlume's list or a signature uses SHA-1 (`unknown`,
//!   which never means "not genuine").
//!
//! Validity periods are reported, not enforced: genuine TPMs outlive their
//! certificates. Revocation is not checked: it needs the network.
//!
//! Strings taken from a certificate (CA names, the TPM model and version) are
//! untrusted. They are bounded here; whoever prints them must still render
//! them as visible text.

use std::ops::Range;
use std::sync::OnceLock;

use der::asn1::{Ia5StringRef, ObjectIdentifier, PrintableStringRef, UintRef, Utf8StringRef};
use der::{Decode, Encode, Header, Reader, Sequence, SliceReader, Tag, Tagged};
use rsa::{BoxedUint, Pkcs1v15Sign, Pss, RsaPublicKey};
use sha2::{Digest, Sha256, Sha384, Sha512};
use spki::{AlgorithmIdentifierOwned, SubjectPublicKeyInfoOwned};
use x509_cert::certificate::Version;
use x509_cert::ext::pkix::name::GeneralName;
use x509_cert::ext::pkix::{
    AuthorityKeyIdentifier, BasicConstraints, CertificatePolicies, ExtendedKeyUsage, KeyUsage,
    KeyUsages, SubjectAltName, SubjectKeyIdentifier,
};
use x509_cert::name::Name;
use x509_cert::Certificate;

mod shipped;

/// The longest CA name kept, in characters.
const MAX_NAME_CHARS: usize = 160;
/// The longest TPM model or version string kept, in characters.
const MAX_ATTRIBUTE_CHARS: usize = 64;
/// At most this many certificates are taken from the joined chain indices.
const MAX_CHAIN_CERTIFICATES: usize = 64;
/// At most this many CA certificates between the EK certificate and the root.
const MAX_INTERMEDIATES: usize = 6;
/// At most this many candidate paths are judged per EK certificate.
const MAX_PATHS: usize = 32;
/// At most this many candidate issuers are tried per EK certificate. The
/// chain indices are untrusted, and same-named CAs that only issue each other
/// would otherwise make the search exponential.
const MAX_SEARCH_STEPS: usize = 2048;
/// The RSA modulus sizes accepted for a signature, in bits.
const MIN_RSA_BITS: usize = 2048;
const MAX_RSA_BITS: usize = 4096;

/// The PC Client header some TPMs put before the DER certificate in an EK
/// certificate index: `0x10 0x01 0x00`, then a two-byte big-endian length.
const PC_CLIENT_HEADER: [u8; 3] = [0x10, 0x01, 0x00];

mod oid {
    use der::asn1::ObjectIdentifier as Oid;

    pub const RSA_ENCRYPTION: Oid = Oid::new_unwrap("1.2.840.113549.1.1.1");
    pub const RSAES_OAEP: Oid = Oid::new_unwrap("1.2.840.113549.1.1.7");
    pub const MGF1: Oid = Oid::new_unwrap("1.2.840.113549.1.1.8");
    pub const RSASSA_PSS: Oid = Oid::new_unwrap("1.2.840.113549.1.1.10");
    pub const SHA256_WITH_RSA: Oid = Oid::new_unwrap("1.2.840.113549.1.1.11");
    pub const SHA384_WITH_RSA: Oid = Oid::new_unwrap("1.2.840.113549.1.1.12");
    pub const SHA512_WITH_RSA: Oid = Oid::new_unwrap("1.2.840.113549.1.1.13");
    pub const MD5_WITH_RSA: Oid = Oid::new_unwrap("1.2.840.113549.1.1.4");
    pub const SHA1_WITH_RSA: Oid = Oid::new_unwrap("1.2.840.113549.1.1.5");
    pub const SHA224_WITH_RSA: Oid = Oid::new_unwrap("1.2.840.113549.1.1.14");
    pub const EC_PUBLIC_KEY: Oid = Oid::new_unwrap("1.2.840.10045.2.1");
    pub const ECDSA_SHA1: Oid = Oid::new_unwrap("1.2.840.10045.4.1");
    pub const ECDSA_SHA224: Oid = Oid::new_unwrap("1.2.840.10045.4.3.1");
    pub const ECDSA_SHA256: Oid = Oid::new_unwrap("1.2.840.10045.4.3.2");
    pub const ECDSA_SHA384: Oid = Oid::new_unwrap("1.2.840.10045.4.3.3");
    pub const ECDSA_SHA512: Oid = Oid::new_unwrap("1.2.840.10045.4.3.4");
    pub const P256: Oid = Oid::new_unwrap("1.2.840.10045.3.1.7");
    pub const P384: Oid = Oid::new_unwrap("1.3.132.0.34");
    pub const P521: Oid = Oid::new_unwrap("1.3.132.0.35");
    pub const SHA256: Oid = Oid::new_unwrap("2.16.840.1.101.3.4.2.1");
    pub const SHA384: Oid = Oid::new_unwrap("2.16.840.1.101.3.4.2.2");
    pub const SHA512: Oid = Oid::new_unwrap("2.16.840.1.101.3.4.2.3");

    pub const SUBJECT_KEY_ID: Oid = Oid::new_unwrap("2.5.29.14");
    pub const KEY_USAGE: Oid = Oid::new_unwrap("2.5.29.15");
    pub const SUBJECT_ALT_NAME: Oid = Oid::new_unwrap("2.5.29.17");
    pub const BASIC_CONSTRAINTS: Oid = Oid::new_unwrap("2.5.29.19");
    pub const NAME_CONSTRAINTS: Oid = Oid::new_unwrap("2.5.29.30");
    pub const CERTIFICATE_POLICIES: Oid = Oid::new_unwrap("2.5.29.32");
    pub const POLICY_MAPPINGS: Oid = Oid::new_unwrap("2.5.29.33");
    pub const AUTHORITY_KEY_ID: Oid = Oid::new_unwrap("2.5.29.35");
    pub const POLICY_CONSTRAINTS: Oid = Oid::new_unwrap("2.5.29.36");
    pub const EXT_KEY_USAGE: Oid = Oid::new_unwrap("2.5.29.37");
    pub const INHIBIT_ANY_POLICY: Oid = Oid::new_unwrap("2.5.29.54");
    pub const ANY_EXTENDED_KEY_USAGE: Oid = Oid::new_unwrap("2.5.29.37.0");

    pub const TCG_KP_EK_CERTIFICATE: Oid = Oid::new_unwrap("2.23.133.8.1");
    pub const TPM_MANUFACTURER: Oid = Oid::new_unwrap("2.23.133.2.1");
    pub const TPM_MODEL: Oid = Oid::new_unwrap("2.23.133.2.2");
    pub const TPM_VERSION: Oid = Oid::new_unwrap("2.23.133.2.3");
}

/// Why bytes read from an EK certificate index are not a certificate.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum NvCertificateError {
    /// The PC Client header declares more bytes than the index holds.
    #[error(
        "the PC Client header declares {declared} bytes, the index holds {available} after it"
    )]
    HeaderOverrun { declared: usize, available: usize },
    /// The bytes do not start with a complete DER SEQUENCE.
    #[error("the index does not start with a DER certificate")]
    NotDer,
}

/// The DER certificate in an EK certificate NV index (ADR-0036 section 2.1).
///
/// The index may carry unspecified bytes after the certificate (TCG EK
/// Credential Profile 2.2.2.2.1), and some TPMs put the PC Client header
/// (`0x10 0x01 0x00` and a two-byte big-endian length) before it, as
/// go-attestation's `ParseEKCertificate` reads it. Returns exactly the first
/// DER value, within the header's length when there is a header.
///
/// # Errors
///
/// [`NvCertificateError::HeaderOverrun`] when the header declares more bytes
/// than follow it, [`NvCertificateError::NotDer`] when no complete DER
/// SEQUENCE starts the certificate bytes.
pub fn certificate_in_nv(index: &[u8]) -> Result<&[u8], NvCertificateError> {
    let body = match index {
        [a, b, c, hi, lo, rest @ ..] if [*a, *b, *c] == PC_CLIENT_HEADER => {
            let declared = usize::from(u16::from_be_bytes([*hi, *lo]));
            rest.get(..declared)
                .ok_or(NvCertificateError::HeaderOverrun {
                    declared,
                    available: rest.len(),
                })?
        }
        _ => index,
    };
    first_sequence(body).ok_or(NvCertificateError::NotDer)
}

/// Every complete DER certificate in the EK certificate chain indices
/// (0x01C00100 onward), given their contents joined in index order.
///
/// One index may hold several certificates and one certificate may continue
/// into the next index (Credential Profile 2.2.2.5.2), so the indices are
/// read as one concatenation. Reading stops at the first byte that does not
/// start a complete DER SEQUENCE, and after 64 certificates.
#[must_use]
pub fn chain_certificates(joined: &[u8]) -> Vec<&[u8]> {
    let mut found = Vec::new();
    let mut rest = joined;
    while found.len() < MAX_CHAIN_CERTIFICATES {
        let Some(certificate) = first_sequence(rest) else {
            break;
        };
        found.push(certificate);
        rest = &rest[certificate.len()..];
    }
    found
}

/// The first complete DER SEQUENCE in `bytes`, header included.
fn first_sequence(bytes: &[u8]) -> Option<&[u8]> {
    let mut reader = SliceReader::new(bytes).ok()?;
    if Header::peek(&reader).ok()?.tag() != Tag::Sequence {
        return None;
    }
    reader.tlv_bytes().ok()
}

/// A parsed certificate, kept with the exact bytes its issuer signed.
#[derive(Clone)]
struct Parsed {
    der: Vec<u8>,
    /// The tbsCertificate TLV within `der`. The signature covers these bytes,
    /// never a re-encoding: decoding sorts SET OF values, and some vendors'
    /// names are not in DER order.
    tbs: Range<usize>,
    cert: Certificate,
    /// The subject and issuer as RFC 5280 7.1 compares them.
    subject_canonical: CanonicalName,
    issuer_canonical: CanonicalName,
}

impl Parsed {
    fn new(der: &[u8]) -> Result<Self, CertificateError> {
        let cert = Certificate::from_der(der).map_err(|e| CertificateError(e.to_string()))?;
        let tbs = tbs_range(der).map_err(|e| CertificateError(e.to_string()))?;
        let subject_canonical = canonical_name(cert.tbs_certificate().subject());
        let issuer_canonical = canonical_name(cert.tbs_certificate().issuer());
        Ok(Self {
            der: der.to_vec(),
            tbs,
            cert,
            subject_canonical,
            issuer_canonical,
        })
    }

    fn tbs_bytes(&self) -> &[u8] {
        &self.der[self.tbs.clone()]
    }

    fn subject(&self) -> &Name {
        self.cert.tbs_certificate().subject()
    }

    fn issuer(&self) -> &Name {
        self.cert.tbs_certificate().issuer()
    }

    fn extension<'a, T: Decode<'a>>(&'a self, id: ObjectIdentifier) -> Option<(bool, T)> {
        let ext = self
            .cert
            .tbs_certificate()
            .extensions()?
            .iter()
            .find(|ext| ext.extn_id == id)?;
        T::from_der(ext.extn_value.as_bytes())
            .ok()
            .map(|value| (ext.critical, value))
    }

    fn subject_key_id(&self) -> Option<Vec<u8>> {
        self.extension::<SubjectKeyIdentifier>(oid::SUBJECT_KEY_ID)
            .map(|(_, ski)| ski.0.as_bytes().to_vec())
    }

    fn authority_key_id(&self) -> Option<Vec<u8>> {
        self.extension::<AuthorityKeyIdentifier>(oid::AUTHORITY_KEY_ID)
            .and_then(|(_, aki)| aki.key_identifier)
            .map(|id| id.as_bytes().to_vec())
    }

    fn self_issued(&self) -> bool {
        self.subject_canonical == self.issuer_canonical
    }

    fn not_before(&self) -> u64 {
        let validity = self.cert.tbs_certificate().validity();
        validity.not_before.to_unix_duration().as_secs()
    }

    fn not_after(&self) -> u64 {
        let validity = self.cert.tbs_certificate().validity();
        validity.not_after.to_unix_duration().as_secs()
    }

    /// The certificate's name for a report: its subject, or a fixed label for
    /// the EK certificate, whose subject is usually empty.
    fn label(&self, leaf: bool) -> String {
        if leaf {
            "the EK certificate".to_owned()
        } else {
            name_text(self.subject())
        }
    }
}

fn tbs_range(der: &[u8]) -> der::Result<Range<usize>> {
    let mut outer = SliceReader::new(der)?;
    let header = Header::decode(&mut outer)?;
    let start = usize::try_from(header.encoded_len()?)?;
    let tbs = SliceReader::new(&der[start..])?.tlv_bytes()?.len();
    Ok(start..start + tbs)
}

/// A name as RFC 5280 7.1 compares it: each RDN's attributes, sorted, with
/// directory strings compared as text after case folding and insignificant
/// space handling (RFC 4518, without its Unicode normalization). Vendors do
/// not always repeat a CA's name with the same string types: ST's ECC
/// Intermediate CA 02 names its issuer in UTF8String where that CA's own
/// subject uses PrintableString. A match only nominates an issuer; its key
/// must still verify the signature.
type CanonicalName = Vec<Vec<(ObjectIdentifier, CanonicalValue)>>;

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
enum CanonicalValue {
    Text(String),
    Other(Tag, Vec<u8>),
}

fn canonical_name(name: &Name) -> CanonicalName {
    name.iter_rdn()
        .map(|rdn| {
            let mut attributes: Vec<_> = rdn
                .iter()
                .map(|attribute| (attribute.oid, canonical_value(&attribute.value)))
                .collect();
            attributes.sort();
            attributes
        })
        .collect()
}

fn canonical_value(value: &der::Any) -> CanonicalValue {
    let bytes = value.value();
    let text = match value.tag() {
        Tag::Utf8String => std::str::from_utf8(bytes).ok().map(str::to_owned),
        Tag::PrintableString | Tag::Ia5String if bytes.is_ascii() => {
            Some(String::from_utf8_lossy(bytes).into_owned())
        }
        // T.61 is read as Latin-1, as most decoders do.
        Tag::TeletexString => Some(bytes.iter().map(|&b| char::from(b)).collect()),
        Tag::BmpString if bytes.len() % 2 == 0 => char::decode_utf16(
            bytes
                .chunks_exact(2)
                .map(|pair| u16::from_be_bytes([pair[0], pair[1]])),
        )
        .collect::<Result<String, _>>()
        .ok(),
        _ => None,
    };
    match text {
        Some(text) => CanonicalValue::Text(
            text.split_whitespace()
                .collect::<Vec<_>>()
                .join(" ")
                .to_lowercase(),
        ),
        None => CanonicalValue::Other(value.tag(), bytes.to_vec()),
    }
}

/// A name as RFC 4514 text, bounded.
fn name_text(name: &Name) -> String {
    bounded(name.to_string(), MAX_NAME_CHARS)
}

fn bounded(mut text: String, max_chars: usize) -> String {
    if let Some((cut, _)) = text.char_indices().nth(max_chars) {
        text.truncate(cut);
    }
    text
}

/// Bytes that are not one DER X.509 certificate irlume can parse.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("not a DER X.509 certificate: {0}")]
pub struct CertificateError(String);

/// What a vendor CA certificate is to irlume.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum AnchorRole {
    /// A self-signed vendor root: a trust anchor, by its name and key.
    Root,
    /// A vendor CA that must itself chain to a root: it helps find a path,
    /// it is not trusted by being listed.
    Intermediate,
}

/// One entry of the generated list in `ek_cert/shipped.rs`.
struct ShippedAnchor {
    role: AnchorRole,
    der: &'static [u8],
}

/// The vendor CA certificates a chain is judged against.
pub struct Anchors {
    roots: Vec<Parsed>,
    intermediates: Vec<Parsed>,
}

impl Anchors {
    /// The vendor roots and intermediates irlume ships (ADR-0036 section 5),
    /// parsed once.
    pub fn shipped() -> &'static Anchors {
        static SHIPPED: OnceLock<Anchors> = OnceLock::new();
        SHIPPED.get_or_init(|| {
            let mut anchors = Anchors {
                roots: Vec::new(),
                intermediates: Vec::new(),
            };
            // A shipped certificate that does not parse is left out; the
            // unit tests require every one to parse.
            for anchor in shipped::SHIPPED {
                if let Ok(parsed) = Parsed::new(anchor.der) {
                    match anchor.role {
                        AnchorRole::Root => anchors.roots.push(parsed),
                        AnchorRole::Intermediate => anchors.intermediates.push(parsed),
                    }
                }
            }
            anchors
        })
    }

    /// Anchors from DER certificates: `roots` are trusted by name and key,
    /// `intermediates` only help find a path to one of them. The swtpm tests
    /// use this to trust a test CA.
    ///
    /// # Errors
    ///
    /// [`CertificateError`] when any certificate does not parse.
    pub fn from_der(roots: &[&[u8]], intermediates: &[&[u8]]) -> Result<Self, CertificateError> {
        Ok(Self {
            roots: roots
                .iter()
                .map(|der| Parsed::new(der))
                .collect::<Result<_, _>>()?,
            intermediates: intermediates
                .iter()
                .map(|der| Parsed::new(der))
                .collect::<Result<_, _>>()?,
        })
    }

    /// How many roots there are.
    #[must_use]
    pub fn root_count(&self) -> usize {
        self.roots.len()
    }

    /// How many intermediates there are.
    #[must_use]
    pub fn intermediate_count(&self) -> usize {
        self.intermediates.len()
    }
}

/// An EK's public key as its certificate states it, for matching the key the
/// TPM derives (ADR-0036 section 2.2).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EkPublicKey {
    /// An RSA key: the modulus without leading zero bytes, and the exponent.
    Rsa { modulus: Vec<u8>, exponent: u32 },
    /// A NIST curve key: the point's affine coordinates, each the curve's
    /// field size.
    Ecc {
        curve: EccCurve,
        x: Vec<u8>,
        y: Vec<u8>,
    },
}

/// The curves irlume accepts for an EK.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EccCurve {
    NistP256,
    NistP384,
    NistP521,
}

impl EccCurve {
    fn from_oid(id: ObjectIdentifier) -> Option<Self> {
        match id {
            oid::P256 => Some(Self::NistP256),
            oid::P384 => Some(Self::NistP384),
            oid::P521 => Some(Self::NistP521),
            _ => None,
        }
    }

    fn field_bytes(self) -> usize {
        match self {
            Self::NistP256 => 32,
            Self::NistP384 => 48,
            Self::NistP521 => 66,
        }
    }
}

/// PKCS#1 RSAPublicKey: SEQUENCE { modulus INTEGER, publicExponent INTEGER }.
#[derive(Sequence)]
struct RsaPublicKeyDer<'a> {
    n: UintRef<'a>,
    e: UintRef<'a>,
}

/// The key in a SubjectPublicKeyInfo, when it is one irlume accepts.
fn spki_key(spki: &SubjectPublicKeyInfoOwned) -> Option<EkPublicKey> {
    let key_bytes = spki.subject_public_key.as_bytes()?;
    match spki.algorithm.oid {
        // An RSAES-OAEP key is an RSA key with its padding named: some older
        // EK certificates use it.
        oid::RSA_ENCRYPTION | oid::RSAES_OAEP => {
            let key = RsaPublicKeyDer::from_der(key_bytes).ok()?;
            let e = key.e.as_bytes();
            if e.is_empty() || e.len() > 4 {
                return None;
            }
            let mut exponent = [0u8; 4];
            exponent[4 - e.len()..].copy_from_slice(e);
            Some(EkPublicKey::Rsa {
                modulus: key.n.as_bytes().to_vec(),
                exponent: u32::from_be_bytes(exponent),
            })
        }
        oid::EC_PUBLIC_KEY => {
            let curve_oid = spki
                .algorithm
                .parameters
                .as_ref()?
                .decode_as::<ObjectIdentifier>()
                .ok()?;
            let curve = EccCurve::from_oid(curve_oid)?;
            let size = curve.field_bytes();
            match key_bytes {
                [0x04, point @ ..] if point.len() == 2 * size => Some(EkPublicKey::Ecc {
                    curve,
                    x: point[..size].to_vec(),
                    y: point[size..].to_vec(),
                }),
                _ => None,
            }
        }
        _ => None,
    }
}

/// Where a certificate on a verified path came from.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CertificateSource {
    /// The EK certificate itself.
    Leaf,
    /// The TPM's EK certificate chain indices.
    TpmChain,
    /// An intermediate in irlume's list.
    Listed,
    /// A root in irlume's list.
    Root,
}

/// One certificate on a verified path, EK certificate first.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ChainLink {
    /// The certificate's subject as RFC 4514 text, bounded; "the EK
    /// certificate" for the first link. Untrusted text.
    pub name: String,
    /// Validity start, in seconds since the Unix epoch.
    pub not_before: u64,
    /// Validity end, in seconds since the Unix epoch. Not enforced: a
    /// verified path may name an end date that has passed.
    pub not_after: u64,
    /// Where the certificate came from.
    pub source: CertificateSource,
}

/// The TPM a verified EK certificate describes, from its subject alternative
/// name (Credential Profile 3.1.2 and 3.2.9).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TpmIdentity {
    /// The TCG vendor ID, equal to the TPM's `TPM_PT_MANUFACTURER`.
    pub manufacturer: u32,
    /// The TPM part number, bounded. Untrusted text.
    pub model: String,
    /// The firmware version when the certificate was issued, as the
    /// certificate states it (normally `id:` and eight hex digits), bounded.
    /// Untrusted text.
    pub version: String,
}

impl TpmIdentity {
    /// The version as a `TPM_PT_FIRMWARE_VERSION_1` value, when the
    /// certificate states it in the profile's `id:XXXXXXXX` form.
    #[must_use]
    pub fn firmware_version_1(&self) -> Option<u32> {
        tcg_id(&self.version)
    }
}

/// A path that verifies to a pinned root.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifiedChain {
    /// The TPM the certificate names.
    pub tpm: TpmIdentity,
    /// The certificates from the EK certificate to the root.
    pub path: Vec<ChainLink>,
}

/// Why the EK certificate does not fit the EK Credential Profile (3.2).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LeafProblem {
    /// Not an X.509 v3 certificate.
    NotVersion3,
    /// Basic Constraints is missing or not critical.
    BasicConstraints,
    /// Basic Constraints says it is a CA.
    IsCa,
    /// Key Usage is missing or not critical.
    KeyUsageMissing,
    /// Key Usage lacks keyEncipherment (RSA) or keyAgreement (ECC).
    KeyUsageWrong,
    /// No subject alternative name, or none with a directory name.
    NoAlternativeName,
    /// The subject is empty and the subject alternative name not critical.
    AlternativeNameNotCritical,
    /// An attribute appears twice with different values.
    ConflictingAttributes,
    /// No TPM manufacturer attribute, or not in the `id:XXXXXXXX` form.
    NoManufacturer,
    /// The manufacturer differs from the TPM's `TPM_PT_MANUFACTURER`.
    ManufacturerDiffers { certificate: u32, tpm: u32 },
    /// No TPM model attribute.
    NoModel,
    /// No TPM firmware version attribute.
    NoVersion,
    /// An Extended Key Usage without tcg-kp-EKCertificate.
    Purpose,
}

/// Evidence against the certificate on a path to a pinned root: the doctor
/// check's `warn`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Refusal {
    /// A signature does not verify although the issuer's key identifier
    /// names the key that should have made it.
    Signature { certificate: String, issuer: String },
    /// A CA on the path is not marked CA:TRUE.
    NotACa { certificate: String },
    /// A CA on the path may not sign certificates (no keyCertSign).
    NoCertSign { certificate: String },
    /// A CA's path length constraint is exceeded.
    PathLength { certificate: String },
    /// A CA's Extended Key Usage excludes EK certificates.
    CaPurpose { certificate: String },
    /// The EK certificate is not an EK certificate by the profile.
    Leaf(LeafProblem),
}

/// Why no path can be judged: the doctor check's `unknown`, which never means
/// the TPM is not genuine.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Unverifiable {
    /// No CA in irlume's list or the TPM's chain indices issued it: a newer
    /// intermediate, or a manufacturer irlume does not know.
    IssuerNotListed { issuer: String },
    /// A signature uses an algorithm irlume does not accept, such as SHA-1.
    Algorithm {
        certificate: String,
        algorithm: String,
    },
    /// A critical extension irlume does not process (RFC 5280 4.2).
    CriticalExtension {
        certificate: String,
        extension: String,
    },
    /// Name or policy constraints, which irlume does not implement.
    Constraints { certificate: String },
    /// An extension irlume reads does not parse, or appears twice.
    Malformed {
        certificate: String,
        detail: &'static str,
    },
    /// The EK certificate's key is not RSA or NIST P-256, P-384 or P-521.
    LeafKey,
}

/// The result of judging one EK certificate.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ChainVerdict {
    Verified(VerifiedChain),
    Refused(Refusal),
    Unverifiable(Unverifiable),
}

/// A parsed EK certificate.
pub struct EkCertificate {
    leaf: Parsed,
    key: Option<EkPublicKey>,
}

impl EkCertificate {
    /// Parse exactly one DER certificate, as [`certificate_in_nv`] returns it.
    ///
    /// # Errors
    ///
    /// [`CertificateError`] when the bytes are not one DER X.509 certificate.
    pub fn from_der(der: &[u8]) -> Result<Self, CertificateError> {
        let leaf = Parsed::new(der)?;
        let key = spki_key(leaf.cert.tbs_certificate().subject_public_key_info());
        Ok(Self { leaf, key })
    }

    /// The public key the certificate certifies, when it is RSA or NIST
    /// P-256, P-384 or P-521.
    #[must_use]
    pub fn public_key(&self) -> Option<&EkPublicKey> {
        self.key.as_ref()
    }

    /// Judge the certificate against `anchors`, with `tpm_chain` the
    /// certificates from the TPM's chain indices ([`chain_certificates`]) and
    /// `tpm_manufacturer` the TPM's `TPM_PT_MANUFACTURER`.
    ///
    /// Every path from the certificate through the TPM's and the listed
    /// intermediates to a listed root is judged. One path that verifies is
    /// enough; otherwise a refusal on any path is reported before a reason a
    /// path could not be judged.
    #[must_use]
    pub fn verify(
        &self,
        tpm_chain: &[&[u8]],
        anchors: &Anchors,
        tpm_manufacturer: u32,
    ) -> ChainVerdict {
        let Some(key) = &self.key else {
            return ChainVerdict::Unverifiable(Unverifiable::LeafKey);
        };
        // A chain certificate irlume also lists is searched once, as listed.
        let listed = |der: &[u8]| {
            anchors
                .roots
                .iter()
                .chain(&anchors.intermediates)
                .any(|c| c.der == der)
        };
        let tpm_chain: Vec<Parsed> = tpm_chain
            .iter()
            .filter(|der| !listed(der))
            .filter_map(|der| Parsed::new(der).ok())
            .collect();
        // irlume's own certificates come first: the search tries candidates
        // in pool order at every level, so certificates from the untrusted
        // chain indices cannot use up the path or step budget before every
        // path through listed CAs has been found.
        let mut pool: Vec<(&Parsed, CertificateSource)> = Vec::new();
        pool.extend(
            anchors
                .intermediates
                .iter()
                .map(|c| (c, CertificateSource::Listed)),
        );
        pool.extend(anchors.roots.iter().map(|c| (c, CertificateSource::Root)));
        pool.extend(tpm_chain.iter().map(|c| (c, CertificateSource::TpmChain)));

        let mut search = PathSearch::new(&pool, &self.leaf);
        search.extend(&mut Vec::new(), &self.leaf);

        let mut refusal = None;
        let mut unverifiable = None;
        for path in &search.paths {
            let chain: Vec<(&Parsed, CertificateSource)> =
                std::iter::once((&self.leaf, CertificateSource::Leaf))
                    .chain(path.iter().map(|&i| pool[i]))
                    .collect();
            match judge_path(&chain, Some((key, tpm_manufacturer))) {
                PathResult::Verified(Some(tpm)) => {
                    return ChainVerdict::Verified(VerifiedChain {
                        tpm,
                        path: chain
                            .iter()
                            .enumerate()
                            .map(|(i, (cert, source))| ChainLink {
                                name: cert.label(i == 0),
                                not_before: cert.not_before(),
                                not_after: cert.not_after(),
                                source: *source,
                            })
                            .collect(),
                    });
                }
                // judge_path names the TPM whenever it is given a leaf.
                PathResult::Verified(None) => {}
                PathResult::Refused(r) => {
                    refusal.get_or_insert(r);
                }
                PathResult::Unverifiable(u) => {
                    unverifiable.get_or_insert(u);
                }
            }
        }
        if let Some(r) = refusal {
            return ChainVerdict::Refused(r);
        }
        ChainVerdict::Unverifiable(unverifiable.unwrap_or_else(|| {
            Unverifiable::IssuerNotListed {
                issuer: search
                    .missing_issuer
                    .unwrap_or_else(|| name_text(self.leaf.issuer())),
            }
        }))
    }
}

/// Depth-first search for paths from the EK certificate to a listed root.
struct PathSearch<'p, 'a> {
    pool: &'p [(&'a Parsed, CertificateSource)],
    leaf: &'a Parsed,
    /// Each path is pool indices from the EK certificate's issuer to a root.
    paths: Vec<Vec<usize>>,
    /// The first issuer name no certificate in the pool carries.
    missing_issuer: Option<String>,
    /// Candidate issuers left to try.
    steps_left: usize,
}

impl<'p, 'a> PathSearch<'p, 'a> {
    fn new(pool: &'p [(&'a Parsed, CertificateSource)], leaf: &'a Parsed) -> Self {
        Self {
            pool,
            leaf,
            paths: Vec::new(),
            missing_issuer: None,
            steps_left: MAX_SEARCH_STEPS,
        }
    }

    fn extend(&mut self, path: &mut Vec<usize>, child: &Parsed) {
        let pool = self.pool;
        let mut found = false;
        for (i, (candidate, source)) in pool.iter().enumerate() {
            if self.paths.len() >= MAX_PATHS || self.steps_left == 0 {
                return;
            }
            if candidate.subject_canonical != child.issuer_canonical
                || path.contains(&i)
                || candidate.der == child.der
                || candidate.der == self.leaf.der
                || !key_ids_agree(child, candidate)
            {
                continue;
            }
            found = true;
            self.steps_left -= 1;
            path.push(i);
            if *source == CertificateSource::Root {
                self.paths.push(path.clone());
            } else if path.len() <= MAX_INTERMEDIATES {
                self.extend(path, candidate);
            }
            path.pop();
        }
        if !found && self.missing_issuer.is_none() {
            self.missing_issuer = Some(name_text(child.issuer()));
        }
    }
}

/// A candidate can be the issuer unless both key identifiers are present and
/// differ: re-keyed CAs share a name, and the identifiers tell them apart.
fn key_ids_agree(child: &Parsed, issuer: &Parsed) -> bool {
    match (child.authority_key_id(), issuer.subject_key_id()) {
        (Some(aki), Some(ski)) => aki == ski,
        _ => true,
    }
}

enum PathResult {
    /// The TPM identity is present when the path starts at an EK certificate.
    Verified(Option<TpmIdentity>),
    Refused(Refusal),
    Unverifiable(Unverifiable),
}

/// Judge one path, `chain[0]` the certificate being judged and the last
/// entry a root. With `leaf`, `chain[0]` must also be an EK certificate for
/// that key and that TPM manufacturer.
fn judge_path(
    chain: &[(&Parsed, CertificateSource)],
    leaf: Option<(&EkPublicKey, u32)>,
) -> PathResult {
    let is_leaf = |i: usize| i == 0 && leaf.is_some();
    // The root is a trust anchor by its name and key: its own extensions are
    // not processed (RFC 5280 6.1.1).
    let below_root = &chain[..chain.len() - 1];

    // First what can make a path unjudgeable, so that a refusal is only ever
    // given on a path irlume can judge to its root.
    for (i, (cert, _)) in below_root.iter().enumerate() {
        if let Err(u) = check_extensions(cert, is_leaf(i)) {
            return PathResult::Unverifiable(u);
        }
    }
    let mut links = Vec::with_capacity(below_root.len());
    for (i, pair) in chain.windows(2).enumerate() {
        let (child, parent) = (pair[0].0, pair[1].0);
        match link_check(child, parent) {
            Ok(link) => links.push(link),
            Err(algorithm) => {
                return PathResult::Unverifiable(Unverifiable::Algorithm {
                    certificate: child.label(is_leaf(i)),
                    algorithm,
                })
            }
        }
    }
    for (i, (pair, link)) in chain.windows(2).zip(&links).enumerate() {
        let ((child, child_source), (parent, parent_source)) = (pair[0], pair[1]);
        if !link.verify(child) {
            // A failing signature is evidence only between certificates
            // irlume vouches for (the EK certificate, its listed CAs and
            // roots) with both key identifiers naming the key that failed.
            // Otherwise it only shows that this same-named CA did not sign
            // it; and a certificate from the chain indices, which any
            // process that can define NV indices may write, never turns a
            // path into evidence against the TPM.
            let from_tpm_chain = child_source == CertificateSource::TpmChain
                || parent_source == CertificateSource::TpmChain;
            if !from_tpm_chain
                && child.authority_key_id().is_some()
                && parent.subject_key_id().is_some()
            {
                return PathResult::Refused(Refusal::Signature {
                    certificate: child.label(is_leaf(i)),
                    issuer: name_text(parent.subject()),
                });
            }
            return PathResult::Unverifiable(Unverifiable::IssuerNotListed {
                issuer: name_text(child.issuer()),
            });
        }
    }
    let first_ca = usize::from(leaf.is_some());
    if let Err(r) = check_cas(&below_root[first_ca..]) {
        return PathResult::Refused(r);
    }
    match leaf {
        Some((key, manufacturer)) => match check_leaf(chain[0].0, key, manufacturer) {
            Ok(tpm) => PathResult::Verified(Some(tpm)),
            Err(problem) => PathResult::Refused(Refusal::Leaf(problem)),
        },
        None => PathResult::Verified(None),
    }
}

/// Every critical extension must be one irlume processes, the ones it reads
/// must parse, and none may repeat (RFC 5280 4.2).
fn check_extensions(cert: &Parsed, leaf: bool) -> Result<(), Unverifiable> {
    let certificate = || cert.label(leaf);
    let Some(extensions) = cert.cert.tbs_certificate().extensions() else {
        return Ok(());
    };
    let mut seen: Vec<ObjectIdentifier> = Vec::with_capacity(extensions.len());
    for ext in extensions.iter() {
        if seen.contains(&ext.extn_id) {
            return Err(Unverifiable::Malformed {
                certificate: certificate(),
                detail: "an extension appears twice",
            });
        }
        seen.push(ext.extn_id);
        let value = ext.extn_value.as_bytes();
        let parses = match ext.extn_id {
            // irlume implements neither name nor policy constraints, so a
            // path that carries them cannot be judged, critical or not.
            oid::NAME_CONSTRAINTS
            | oid::POLICY_CONSTRAINTS
            | oid::POLICY_MAPPINGS
            | oid::INHIBIT_ANY_POLICY => {
                return Err(Unverifiable::Constraints {
                    certificate: certificate(),
                })
            }
            oid::BASIC_CONSTRAINTS => BasicConstraints::from_der(value).is_ok(),
            oid::KEY_USAGE => KeyUsage::from_der(value).is_ok(),
            oid::EXT_KEY_USAGE => ExtendedKeyUsage::from_der(value).is_ok(),
            oid::SUBJECT_ALT_NAME => SubjectAltName::from_der(value).is_ok(),
            oid::SUBJECT_KEY_ID => SubjectKeyIdentifier::from_der(value).is_ok(),
            oid::AUTHORITY_KEY_ID => AuthorityKeyIdentifier::from_der(value).is_ok(),
            // Certificate policies are processed with irlume's initial
            // policy set anyPolicy and no explicit policy required (RFC 5280
            // 6.1.1): with no policy constraints or mappings on the path,
            // which are refused above, they cannot invalidate it.
            oid::CERTIFICATE_POLICIES => CertificatePolicies::from_der(value).is_ok(),
            _ if ext.critical => {
                return Err(Unverifiable::CriticalExtension {
                    certificate: certificate(),
                    extension: ext.extn_id.to_string(),
                })
            }
            _ => true,
        };
        if !parses {
            return Err(Unverifiable::Malformed {
                certificate: certificate(),
                detail: "an extension does not parse",
            });
        }
    }
    Ok(())
}

/// A hash irlume accepts in a signature.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum HashAlg {
    Sha256,
    Sha384,
    Sha512,
}

impl HashAlg {
    fn from_oid(id: ObjectIdentifier) -> Option<Self> {
        match id {
            oid::SHA256 => Some(Self::Sha256),
            oid::SHA384 => Some(Self::Sha384),
            oid::SHA512 => Some(Self::Sha512),
            _ => None,
        }
    }

    fn digest(self, data: &[u8]) -> Vec<u8> {
        match self {
            Self::Sha256 => Sha256::digest(data).to_vec(),
            Self::Sha384 => Sha384::digest(data).to_vec(),
            Self::Sha512 => Sha512::digest(data).to_vec(),
        }
    }

    fn len(self) -> usize {
        match self {
            Self::Sha256 => 32,
            Self::Sha384 => 48,
            Self::Sha512 => 64,
        }
    }
}

/// A signature scheme irlume accepts.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Scheme {
    RsaPkcs1(HashAlg),
    /// RSASSA-PSS with MGF1 over the same hash and this salt length.
    RsaPss(HashAlg, usize),
    Ecdsa(HashAlg),
}

/// RSASSA-PSS-params (RFC 4055 3.1); an absent field takes its default,
/// SHA-1, MGF1 with SHA-1, salt 20 and trailer 1.
#[derive(Sequence)]
struct PssParams {
    #[asn1(context_specific = "0", tag_mode = "EXPLICIT", optional = "true")]
    hash: Option<AlgorithmIdentifierOwned>,
    #[asn1(context_specific = "1", tag_mode = "EXPLICIT", optional = "true")]
    mask_gen: Option<AlgorithmIdentifierOwned>,
    #[asn1(context_specific = "2", tag_mode = "EXPLICIT", optional = "true")]
    salt_len: Option<u32>,
    #[asn1(context_specific = "3", tag_mode = "EXPLICIT", optional = "true")]
    trailer: Option<u32>,
}

/// The scheme an AlgorithmIdentifier names, or the name to report for one
/// irlume does not accept.
fn scheme(alg: &AlgorithmIdentifierOwned) -> Result<Scheme, String> {
    let params_null_or_absent = alg.parameters.as_ref().is_none_or(|p| p.is_null());
    let pkcs1 = |hash| {
        if params_null_or_absent {
            Ok(Scheme::RsaPkcs1(hash))
        } else {
            Err(format!("{} with parameters", alg.oid))
        }
    };
    let ecdsa = |hash| {
        if params_null_or_absent {
            Ok(Scheme::Ecdsa(hash))
        } else {
            Err(format!("{} with parameters", alg.oid))
        }
    };
    match alg.oid {
        oid::SHA256_WITH_RSA => pkcs1(HashAlg::Sha256),
        oid::SHA384_WITH_RSA => pkcs1(HashAlg::Sha384),
        oid::SHA512_WITH_RSA => pkcs1(HashAlg::Sha512),
        oid::ECDSA_SHA256 => ecdsa(HashAlg::Sha256),
        oid::ECDSA_SHA384 => ecdsa(HashAlg::Sha384),
        oid::ECDSA_SHA512 => ecdsa(HashAlg::Sha512),
        oid::RSASSA_PSS => {
            pss_scheme(alg).ok_or_else(|| "RSASSA-PSS with SHA-1 or unusual parameters".to_owned())
        }
        oid::SHA1_WITH_RSA => Err("sha1WithRSAEncryption".to_owned()),
        oid::MD5_WITH_RSA => Err("md5WithRSAEncryption".to_owned()),
        oid::SHA224_WITH_RSA => Err("sha224WithRSAEncryption".to_owned()),
        oid::ECDSA_SHA1 => Err("ecdsa-with-SHA1".to_owned()),
        oid::ECDSA_SHA224 => Err("ecdsa-with-SHA224".to_owned()),
        other => Err(other.to_string()),
    }
}

fn pss_scheme(alg: &AlgorithmIdentifierOwned) -> Option<Scheme> {
    let params: PssParams = alg.parameters.as_ref()?.decode_as().ok()?;
    let hash_id = params.hash?;
    if hash_id.parameters.as_ref().is_some_and(|p| !p.is_null()) {
        return None;
    }
    let hash = HashAlg::from_oid(hash_id.oid)?;
    let mask_gen = params.mask_gen?;
    if mask_gen.oid != oid::MGF1 {
        return None;
    }
    let mgf_hash: AlgorithmIdentifierOwned = mask_gen.parameters.as_ref()?.decode_as().ok()?;
    if HashAlg::from_oid(mgf_hash.oid) != Some(hash) {
        return None;
    }
    if params.trailer.is_some_and(|t| t != 1) {
        return None;
    }
    let salt = usize::try_from(params.salt_len.unwrap_or(20)).ok()?;
    Some(Scheme::RsaPss(hash, salt))
}

/// An issuer's key, ready to verify.
enum IssuerKey {
    Rsa(RsaPublicKey),
    P256(p256::ecdsa::VerifyingKey),
    P384(p384::ecdsa::VerifyingKey),
    P521(p521::ecdsa::VerifyingKey),
}

/// The key and scheme for one link, after checking irlume accepts both.
struct Link {
    key: IssuerKey,
    scheme: Scheme,
}

impl Link {
    fn verify(&self, child: &Parsed) -> bool {
        use p256::ecdsa::signature::hazmat::PrehashVerifier;

        let Some(signature) = child.cert.signature().as_bytes() else {
            return false;
        };
        let tbs = child.tbs_bytes();
        match (&self.key, self.scheme) {
            (IssuerKey::Rsa(key), Scheme::RsaPkcs1(hash)) => {
                let padding = match hash {
                    HashAlg::Sha256 => Pkcs1v15Sign::new::<Sha256>(),
                    HashAlg::Sha384 => Pkcs1v15Sign::new::<Sha384>(),
                    HashAlg::Sha512 => Pkcs1v15Sign::new::<Sha512>(),
                };
                key.verify(padding, &hash.digest(tbs), signature).is_ok()
            }
            (IssuerKey::Rsa(key), Scheme::RsaPss(hash, salt)) => {
                let hashed = hash.digest(tbs);
                match hash {
                    HashAlg::Sha256 => {
                        key.verify(Pss::<Sha256>::new_with_salt(salt), &hashed, signature)
                    }
                    HashAlg::Sha384 => {
                        key.verify(Pss::<Sha384>::new_with_salt(salt), &hashed, signature)
                    }
                    HashAlg::Sha512 => {
                        key.verify(Pss::<Sha512>::new_with_salt(salt), &hashed, signature)
                    }
                }
                .is_ok()
            }
            (IssuerKey::P256(key), Scheme::Ecdsa(hash)) => {
                p256::ecdsa::Signature::from_der(signature)
                    .is_ok_and(|sig| key.verify_prehash(&hash.digest(tbs), &sig).is_ok())
            }
            (IssuerKey::P384(key), Scheme::Ecdsa(hash)) => {
                p384::ecdsa::Signature::from_der(signature)
                    .is_ok_and(|sig| key.verify_prehash(&hash.digest(tbs), &sig).is_ok())
            }
            (IssuerKey::P521(key), Scheme::Ecdsa(hash)) => {
                p521::ecdsa::Signature::from_der(signature)
                    .is_ok_and(|sig| key.verify_prehash(&hash.digest(tbs), &sig).is_ok())
            }
            // link_check pairs keys and schemes; any other pair never verifies.
            _ => false,
        }
    }
}

/// Check that irlume accepts how `parent` signed `child`, and prepare the
/// key. Errs with the name of what it does not accept.
fn link_check(child: &Parsed, parent: &Parsed) -> Result<Link, String> {
    // RFC 5280 4.1.1.2: the outer and the signed algorithm must be the same.
    if child.cert.signature_algorithm() != child.cert.tbs_certificate().signature() {
        return Err("signature algorithm fields that differ".to_owned());
    }
    let scheme = scheme(child.cert.signature_algorithm())?;
    let spki = parent.cert.tbs_certificate().subject_public_key_info();
    let key = match (spki_key(spki), spki.algorithm.oid) {
        (Some(EkPublicKey::Rsa { modulus, exponent }), oid::RSA_ENCRYPTION) => {
            let bits = modulus.first().map_or(0, |b| {
                (modulus.len() - 1) * 8 + (8 - b.leading_zeros() as usize)
            });
            if !(MIN_RSA_BITS..=MAX_RSA_BITS).contains(&bits) {
                return Err(format!("RSA-{bits}"));
            }
            let key = RsaPublicKey::new_with_max_size(
                BoxedUint::from_be_slice_vartime(&modulus),
                BoxedUint::from(u64::from(exponent)),
                MAX_RSA_BITS,
            )
            .map_err(|_| format!("RSA-{bits} with an unusable modulus or exponent"))?;
            IssuerKey::Rsa(key)
        }
        (Some(EkPublicKey::Ecc { curve, x, y }), _) => {
            let mut point = Vec::with_capacity(1 + x.len() + y.len());
            point.push(0x04);
            point.extend_from_slice(&x);
            point.extend_from_slice(&y);
            let invalid = |_| "an ECC key that is not on its curve".to_owned();
            match curve {
                EccCurve::NistP256 => IssuerKey::P256(
                    p256::ecdsa::VerifyingKey::from_sec1_bytes(&point).map_err(invalid)?,
                ),
                EccCurve::NistP384 => IssuerKey::P384(
                    p384::ecdsa::VerifyingKey::from_sec1_bytes(&point).map_err(invalid)?,
                ),
                EccCurve::NistP521 => IssuerKey::P521(
                    p521::ecdsa::VerifyingKey::from_sec1_bytes(&point).map_err(invalid)?,
                ),
            }
        }
        _ => return Err(format!("an issuer key of type {}", spki.algorithm.oid)),
    };
    match (&key, scheme) {
        (IssuerKey::Rsa(_), Scheme::RsaPkcs1(_) | Scheme::RsaPss(..)) => {}
        // ECDSA takes the hash's leftmost bits up to the order's size; a
        // hash shorter than half the field (SHA-256 on P-521) is not used.
        (IssuerKey::P521(_), Scheme::Ecdsa(hash))
            if hash.len() * 2 < EccCurve::NistP521.field_bytes() =>
        {
            return Err("ecdsa on P-521 with a hash shorter than SHA-384".to_owned());
        }
        (IssuerKey::P256(_) | IssuerKey::P384(_) | IssuerKey::P521(_), Scheme::Ecdsa(_)) => {}
        _ => return Err("a signature algorithm that does not fit the issuer's key".to_owned()),
    }
    Ok(Link { key, scheme })
}

/// The CA constraints of RFC 5280 6.1.4 for the CAs below the root, given
/// top-most last (as on a path from the EK certificate up).
fn check_cas(cas: &[(&Parsed, CertificateSource)]) -> Result<(), Refusal> {
    let mut max_path_length = cas.len();
    for (ca, _) in cas.iter().rev() {
        let certificate = || name_text(ca.subject());
        match ca.extension::<BasicConstraints>(oid::BASIC_CONSTRAINTS) {
            Some((_, bc)) if bc.ca => {
                if !ca.self_issued() {
                    if max_path_length == 0 {
                        return Err(Refusal::PathLength {
                            certificate: certificate(),
                        });
                    }
                    max_path_length -= 1;
                }
                if let Some(limit) = bc.path_len_constraint {
                    max_path_length = max_path_length.min(usize::from(limit));
                }
            }
            _ => {
                return Err(Refusal::NotACa {
                    certificate: certificate(),
                })
            }
        }
        match ca.extension::<KeyUsage>(oid::KEY_USAGE) {
            Some((_, ku)) if ku.0.contains(KeyUsages::KeyCertSign) => {}
            _ => {
                return Err(Refusal::NoCertSign {
                    certificate: certificate(),
                })
            }
        }
        // An issuing CA's Extended Key Usage limits what it may issue
        // (Credential Profile 3.2.16, RFC 5280 4.2.1.12).
        if let Some((_, eku)) = ca.extension::<ExtendedKeyUsage>(oid::EXT_KEY_USAGE) {
            if !eku
                .0
                .iter()
                .any(|id| *id == oid::TCG_KP_EK_CERTIFICATE || *id == oid::ANY_EXTENDED_KEY_USAGE)
            {
                return Err(Refusal::CaPurpose {
                    certificate: certificate(),
                });
            }
        }
    }
    Ok(())
}

/// A TCG `id:` value: `id:` and eight hex digits (Credential Profile 3.1.2).
fn tcg_id(text: &str) -> Option<u32> {
    let hex = text.strip_prefix("id:")?;
    if hex.len() != 8 || !hex.bytes().all(|b| b.is_ascii_hexdigit()) {
        return None;
    }
    u32::from_str_radix(hex, 16).ok()
}

/// A directory string attribute value as text.
fn attribute_text(value: &der::Any) -> Option<String> {
    let text = match value.tag() {
        Tag::Utf8String => Utf8StringRef::try_from(value).ok()?.as_str().to_owned(),
        Tag::PrintableString => PrintableStringRef::try_from(value)
            .ok()?
            .as_str()
            .to_owned(),
        Tag::Ia5String => Ia5StringRef::try_from(value).ok()?.as_str().to_owned(),
        _ => return None,
    };
    Some(text)
}

/// The EK certificate profile (Credential Profile 3.2) for a storage EK.
fn check_leaf(
    cert: &Parsed,
    key: &EkPublicKey,
    tpm_manufacturer: u32,
) -> Result<TpmIdentity, LeafProblem> {
    let tbs = cert.cert.tbs_certificate();
    if tbs.version() != Version::V3 {
        return Err(LeafProblem::NotVersion3);
    }
    match cert.extension::<BasicConstraints>(oid::BASIC_CONSTRAINTS) {
        Some((true, bc)) if !bc.ca => {}
        Some((_, bc)) if bc.ca => return Err(LeafProblem::IsCa),
        _ => return Err(LeafProblem::BasicConstraints),
    }
    let needed = match key {
        EkPublicKey::Rsa { .. } => KeyUsages::KeyEncipherment,
        EkPublicKey::Ecc { .. } => KeyUsages::KeyAgreement,
    };
    match cert.extension::<KeyUsage>(oid::KEY_USAGE) {
        Some((true, ku)) if ku.0.contains(needed) => {}
        Some((true, _)) => return Err(LeafProblem::KeyUsageWrong),
        _ => return Err(LeafProblem::KeyUsageMissing),
    }
    if let Some((_, eku)) = cert.extension::<ExtendedKeyUsage>(oid::EXT_KEY_USAGE) {
        if !eku.0.contains(&oid::TCG_KP_EK_CERTIFICATE) {
            return Err(LeafProblem::Purpose);
        }
    }

    let Some((critical, san)) = cert.extension::<SubjectAltName>(oid::SUBJECT_ALT_NAME) else {
        return Err(LeafProblem::NoAlternativeName);
    };
    if tbs.subject().is_empty() && !critical {
        return Err(LeafProblem::AlternativeNameNotCritical);
    }
    let mut manufacturer = None;
    let mut model = None;
    let mut version = None;
    let mut directory_names = 0;
    for name in &san.0 {
        let GeneralName::DirectoryName(name) = name else {
            continue;
        };
        directory_names += 1;
        for attribute in name.iter() {
            let slot = match attribute.oid {
                oid::TPM_MANUFACTURER => &mut manufacturer,
                oid::TPM_MODEL => &mut model,
                oid::TPM_VERSION => &mut version,
                _ => continue,
            };
            let Some(text) = attribute_text(&attribute.value) else {
                continue;
            };
            match slot {
                Some(existing) if *existing != text => {
                    return Err(LeafProblem::ConflictingAttributes)
                }
                _ => *slot = Some(text),
            }
        }
    }
    if directory_names == 0 {
        return Err(LeafProblem::NoAlternativeName);
    }
    let manufacturer = manufacturer
        .as_deref()
        .and_then(tcg_id)
        .ok_or(LeafProblem::NoManufacturer)?;
    if manufacturer != tpm_manufacturer {
        return Err(LeafProblem::ManufacturerDiffers {
            certificate: manufacturer,
            tpm: tpm_manufacturer,
        });
    }
    let model = model
        .filter(|m| !m.is_empty())
        .ok_or(LeafProblem::NoModel)?;
    let version = version
        .filter(|v| !v.is_empty())
        .ok_or(LeafProblem::NoVersion)?;
    Ok(TpmIdentity {
        manufacturer,
        model: bounded(model, MAX_ATTRIBUTE_CHARS),
        version: bounded(version, MAX_ATTRIBUTE_CHARS),
    })
}

#[cfg(test)]
mod tests;

// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright the irlume contributors.

//! The `tpm-endorsement` check's TPM side (ADR-0036 sections 2 to 4).
//!
//! [`endorsement_report`] reads the endorsement hierarchy's state, the EK
//! certificate indices the TCG EK Credential Profile assigns (and no other
//! index), the EK certificate chain indices, then for each storage EK
//! certificate: verifies its chain in software ([`crate::ek_cert`]), finds
//! the EK it is for (a persistent one, or one derived from its template),
//! and runs the same-TPM test: a credential made in software
//! ([`crate::tpm_credential`]) for the Name of the storage key new seals go
//! under, which the TPM releases through TPM2_ActivateCredential only if it
//! holds both keys. Nothing is kept between calls, and nothing is persisted
//! or written.
//!
//! The caller's `before_command` runs before each TPM command irlume sends,
//! and once for deriving the original storage key, which ESYS wraps in a
//! session it starts and flushes; when it answers `false` the check stops
//! and reads `unknown` ("ran out of time"). Flushing what the check loaded
//! still runs after that, so an abandoned check leaves no object or session
//! in the TPM.

use irlume_common::tpm_endorsement::{
    CertificateAuthority, CertifiedTpm, EndorsementCertificate, EndorsementReport,
    EndorsementState, SkippedCertificate, SkippedKind,
};
use tss_esapi::attributes::NvIndexAttributes;
use tss_esapi::constants::response_code::{Tss2ResponseCode, Tss2ResponseCodeKind};
use tss_esapi::handles::AuthHandle;
use tss_esapi::interface_types::algorithm::SymmetricMode;
use tss_esapi::interface_types::ecc::EccCurve as TssCurve;
use tss_esapi::interface_types::key_bits::AesKeyBits;
use tss_esapi::structures::{
    EccParameter, EccPoint, EccScheme, EncryptedSecret, IdObject, KeyDerivationFunctionScheme,
    MaxNvBuffer, PublicEccParametersBuilder, PublicRsaParametersBuilder,
};

use super::*;
use crate::ek_cert::{
    self, Anchors, ChainVerdict, EkCertificate, EkPublicKey, LeafProblem, Refusal, Unverifiable,
};
use crate::tpm_credential::{self, EkSymmetric, EkTarget, NameAlg};

/// First and last handles of the range the profile reserves for EK
/// credentials (Credential Profile 2.2.2.8).
const EK_RANGE: (u32, u32) = (0x01C0_0000, 0x01C0_7FFF);
/// The EK certificate chain indices (Credential Profile 2.2.2.5.2).
const CHAIN_RANGE: (u32, u32) = (0x01C0_0100, 0x01C0_01FF);
/// Persistent handles for endorsement primary objects (TCG Registry of
/// Reserved TPM 2.0 Handles and Localities).
const EK_PERSISTENT: (u32, u32) = (0x8101_0000, 0x8101_FFFF);
/// At most this many storage EK certificates are judged (ADR-0036 section 4).
const MAX_JUDGED: usize = 4;
/// The longest NV index read: no EK certificate or chain index is near it.
const MAX_INDEX_BYTES: usize = 16 * 1024;

/// TPMA_PERMANENT.endorsementAuthSet.
const ENDORSEMENT_AUTH_SET: u32 = 1 << 1;
/// TPMA_PERMANENT.inLockout.
const IN_LOCKOUT: u32 = 1 << 9;
/// TPMA_STARTUP_CLEAR.ehEnable.
const EH_ENABLE: u32 = 1 << 2;

/// PolicyA: `TPM2_PolicySecret(TPM_RH_ENDORSEMENT)` (Credential Profile
/// A.2.2), for each nameAlg.
const POLICY_A_SHA256: &str = "837197674484b3f81a90cc8d46a5d724fd52d76e06520b64f2a1da1b331469aa";
const POLICY_A_SHA384: &str =
    "8bbf2266537c171cb56e403c4dc1d4b64f432611dc386e6f532050c3278c930e143e8bb1133824ccb431053871c6db53";
const POLICY_A_SHA512: &str = "1e3b76502c8a1425aa0b7b3fc646a1b0fae063b03b5368f9c4cddecaff0891dd682bac1a85d4d832b781ea451915de5fc5bf0dc4a1917cd42fa041e3f998e0ee";
/// PolicyC: `TPM2_PolicyAuthorizeNV` with the policy index of the nameAlg
/// (A.2.4).
const POLICY_C_SHA256: &str = "3767e2edd43ff45a3a7e1eaefcef78643dca964632e7aad82c673a30d8633fde";
const POLICY_C_SHA384: &str =
    "d6032ce61f2fb3c240eb3cf6a33237ef2b6a16f4293c22b455e261cffd217ad5b4947c2d73e63005eed2dc2b3593d165";
const POLICY_C_SHA512: &str = "589ee1e146544716e8deafe6db247b01b81e9f9c7dd16b814aa159138749105fba5388dd1dea702f35240c184933121e2c61b8f50d3ef91393a49a38c3f73fc8";
/// PolicyB: `TPM2_PolicyOR(PolicyA, PolicyC)` (A.2.5), the high-range
/// templates' authPolicy.
const POLICY_B_SHA256: &str = "ca3d0a99a2b93906f7a3342414efcfb3a385d44cd1fd459089d19b5071c0b7a0";
const POLICY_B_SHA384: &str =
    "b26e7d28d11a50bc53d882bcf5fd3a1a074148bb35d3b4e4cb1c0ad9bde419cacb47ba09699646150f9fc000f3f80e12";
const POLICY_B_SHA512: &str = "b8221ca69e8550a4914de3faa6a18c072cc01208073a928d5d66d59ef79e49a429c41a6b269571d57edb25fbdb1838425608b413cd616a5f6db5b6071af99bea";

fn hex(text: &str) -> Vec<u8> {
    (0..text.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&text[i..i + 2], 16).expect("a constant in hex"))
        .collect()
}

/// The EK policies for one nameAlg.
struct Policies {
    a: Vec<u8>,
    b: Vec<u8>,
    c: Vec<u8>,
}

fn policies(alg: NameAlg) -> Policies {
    let (a, b, c) = match alg {
        NameAlg::Sha256 => (POLICY_A_SHA256, POLICY_B_SHA256, POLICY_C_SHA256),
        NameAlg::Sha384 => (POLICY_A_SHA384, POLICY_B_SHA384, POLICY_C_SHA384),
        NameAlg::Sha512 => (POLICY_A_SHA512, POLICY_B_SHA512, POLICY_C_SHA512),
    };
    Policies {
        a: hex(a),
        b: hex(b),
        c: hex(c),
    }
}

/// A storage EK certificate index irlume judges, with its default template
/// (Credential Profile 2.2.2.4, 2.2.2.5.1, 5.3, 5.4).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Slot {
    /// L-1, RSA 2048, low range.
    L1,
    /// L-2, ECC NIST P-256, low range.
    L2,
    /// H-1, RSA 2048.
    H1,
    /// H-2, ECC NIST P-256.
    H2,
    /// H-3, ECC NIST P-384.
    H3,
    /// H-4, ECC NIST P-521.
    H4,
    /// H-6, RSA 3072.
    H6,
    /// H-7, RSA 4096.
    H7,
}

/// The judged certificate indices, low range first (ADR-0036 section 4).
const JUDGED: [(u32, Slot); 8] = [
    (0x01C0_0002, Slot::L1),
    (0x01C0_000A, Slot::L2),
    (0x01C0_0012, Slot::H1),
    (0x01C0_0014, Slot::H2),
    (0x01C0_0016, Slot::H3),
    (0x01C0_0018, Slot::H4),
    (0x01C0_001C, Slot::H6),
    (0x01C0_001E, Slot::H7),
];

/// What a populated certificate index outside [`JUDGED`] is, when the
/// profile assigns it to an EK irlume cannot test (ADR-0036 section 2.1).
/// The profile (2.6, "EK certificates for Signing EKs") lists the
/// firmware-limited signing EKs H-22 to H-25 (0x01C00056 to 0x01C0005C)
/// among the signing EKs; being signing keys is why the test cannot use
/// them. The firmware-limited storage EKs are H-18 to H-21.
fn skipped_kind(index: u32) -> Option<SkippedKind> {
    if index % 2 != 0 {
        return None;
    }
    match index {
        0x01C0_001A => Some(SkippedKind::Sm2),
        0x01C0_0032..=0x01C0_003E | 0x01C0_0050..=0x01C0_005C | 0x01C0_0070..=0x01C0_007A => {
            Some(SkippedKind::Signing)
        }
        0x01C0_0040..=0x01C0_0046 => Some(SkippedKind::FirmwareLimited),
        0x01C0_0060..=0x01C0_006A => Some(SkippedKind::MlKem),
        _ => None,
    }
}

impl Slot {
    fn label(self) -> &'static str {
        match self {
            Self::L1 | Self::H1 => "RSA 2048",
            Self::L2 | Self::H2 => "ECC NIST P-256",
            Self::H3 => "ECC NIST P-384",
            Self::H4 => "ECC NIST P-521",
            Self::H6 => "RSA 3072",
            Self::H7 => "RSA 4096",
        }
    }

    /// Whether `key` is of the algorithm and size this slot's EK has: a
    /// certificate for another key is not the certificate the profile
    /// stores here.
    fn holds(self, key: &EkPublicKey) -> bool {
        match (self, key) {
            (Self::L1 | Self::H1, EkPublicKey::Rsa { modulus, .. }) => rsa_bits(modulus) == 2048,
            (Self::H6, EkPublicKey::Rsa { modulus, .. }) => rsa_bits(modulus) == 3072,
            (Self::H7, EkPublicKey::Rsa { modulus, .. }) => rsa_bits(modulus) == 4096,
            (Self::L2 | Self::H2, EkPublicKey::Ecc { curve, .. }) => {
                *curve == ek_cert::EccCurve::NistP256
            }
            (Self::H3, EkPublicKey::Ecc { curve, .. }) => *curve == ek_cert::EccCurve::NistP384,
            (Self::H4, EkPublicKey::Ecc { curve, .. }) => *curve == ek_cert::EccCurve::NistP521,
            _ => false,
        }
    }

    fn low_range(self) -> bool {
        matches!(self, Self::L1 | Self::L2)
    }

    /// The EK Nonce index, low range only.
    fn nonce_index(self, certificate: u32) -> Option<u32> {
        self.low_range().then_some(certificate + 1)
    }

    /// The EK Template index: two after a low-range certificate, the next
    /// (odd) index in the high range.
    fn template_index(self, certificate: u32) -> u32 {
        if self.low_range() {
            certificate + 2
        } else {
            certificate + 1
        }
    }

    /// The default template (Credential Profile Tables 4, 5, 9 and 11).
    fn default_template(self) -> Result<Public> {
        let attributes = ObjectAttributesBuilder::new()
            .with_fixed_tpm(true)
            .with_fixed_parent(true)
            .with_sensitive_data_origin(true)
            .with_user_with_auth(!self.low_range())
            .with_admin_with_policy(true)
            .with_restricted(true)
            .with_decrypt(true)
            .build()
            .map_err(tpm_err)?;
        let (hash, policy, symmetric) = match self {
            Self::L1 | Self::L2 => (
                HashingAlgorithm::Sha256,
                hex(POLICY_A_SHA256),
                SymmetricDefinitionObject::AES_128_CFB,
            ),
            Self::H1 | Self::H2 => (
                HashingAlgorithm::Sha256,
                hex(POLICY_B_SHA256),
                SymmetricDefinitionObject::AES_128_CFB,
            ),
            Self::H3 | Self::H6 | Self::H7 => (
                HashingAlgorithm::Sha384,
                hex(POLICY_B_SHA384),
                SymmetricDefinitionObject::AES_256_CFB,
            ),
            Self::H4 => (
                HashingAlgorithm::Sha512,
                hex(POLICY_B_SHA512),
                SymmetricDefinitionObject::AES_256_CFB,
            ),
        };
        let builder = PublicBuilder::new()
            .with_name_hashing_algorithm(hash)
            .with_object_attributes(attributes)
            .with_auth_policy(Digest::try_from(policy).map_err(tpm_err)?);
        let rsa = |bits, unique: PublicKeyRsa| -> Result<Public> {
            builder
                .clone()
                .with_public_algorithm(PublicAlgorithm::Rsa)
                .with_rsa_parameters(
                    PublicRsaParametersBuilder::new()
                        .with_symmetric(symmetric)
                        .with_scheme(RsaScheme::Null)
                        .with_key_bits(bits)
                        .with_exponent(RsaExponent::default())
                        .with_is_decryption_key(true)
                        .with_restricted(true)
                        .build()
                        .map_err(tpm_err)?,
                )
                .with_rsa_unique_identifier(unique)
                .build()
                .map_err(tpm_err)
        };
        let ecc = |curve, size: usize| -> Result<Public> {
            builder
                .clone()
                .with_public_algorithm(PublicAlgorithm::Ecc)
                .with_ecc_parameters(
                    PublicEccParametersBuilder::new()
                        .with_symmetric(symmetric)
                        .with_ecc_scheme(EccScheme::Null)
                        .with_curve(curve)
                        .with_key_derivation_function_scheme(KeyDerivationFunctionScheme::Null)
                        .with_is_decryption_key(true)
                        .with_restricted(true)
                        .build()
                        .map_err(tpm_err)?,
                )
                .with_ecc_unique_identifier(EccPoint::new(
                    EccParameter::try_from(vec![0u8; size]).map_err(tpm_err)?,
                    EccParameter::try_from(vec![0u8; size]).map_err(tpm_err)?,
                ))
                .build()
                .map_err(tpm_err)
        };
        match self {
            // The low range fills unique with zeros; the high range leaves it
            // empty (Credential Profile 5.4.1).
            Self::L1 => rsa(
                RsaKeyBits::Rsa2048,
                PublicKeyRsa::new_empty_with_size(RsaKeyBits::Rsa2048),
            ),
            Self::L2 => ecc(TssCurve::NistP256, 32),
            Self::H1 => rsa(RsaKeyBits::Rsa2048, PublicKeyRsa::default()),
            Self::H2 => ecc(TssCurve::NistP256, 0),
            Self::H3 => ecc(TssCurve::NistP384, 0),
            Self::H4 => ecc(TssCurve::NistP521, 0),
            Self::H6 => rsa(RsaKeyBits::Rsa3072, PublicKeyRsa::default()),
            Self::H7 => rsa(RsaKeyBits::Rsa4096, PublicKeyRsa::default()),
        }
    }
}

/// The size in bits of an RSA modulus given without leading zero octets.
fn rsa_bits(modulus: &[u8]) -> usize {
    modulus.first().map_or(0, |first| {
        modulus.len() * 8 - usize::try_from(first.leading_zeros()).unwrap_or(0)
    })
}

/// A low-range EK Nonce put into a template's unique field (Credential
/// Profile 2.2.2.6): for RSA 2048 padded with zeros to 256 octets, for ECC
/// NIST P-256 into x padded to 32 octets, with y 32 zero octets.
fn with_nonce(template: Public, nonce: &[u8]) -> Result<Public> {
    match template {
        Public::Rsa {
            object_attributes,
            name_hashing_algorithm,
            auth_policy,
            parameters,
            ..
        } => {
            if nonce.len() > RSA_2048_MODULUS_BYTES {
                return Err(Error::Tpm("the EK Nonce is longer than 256 octets".into()));
            }
            let mut unique = nonce.to_vec();
            unique.resize(RSA_2048_MODULUS_BYTES, 0);
            Ok(Public::Rsa {
                object_attributes,
                name_hashing_algorithm,
                auth_policy,
                parameters,
                unique: PublicKeyRsa::try_from(unique).map_err(tpm_err)?,
            })
        }
        Public::Ecc {
            object_attributes,
            name_hashing_algorithm,
            auth_policy,
            parameters,
            ..
        } => {
            if nonce.len() > 32 {
                return Err(Error::Tpm("the EK Nonce is longer than 32 octets".into()));
            }
            let mut x = nonce.to_vec();
            x.resize(32, 0);
            Ok(Public::Ecc {
                object_attributes,
                name_hashing_algorithm,
                auth_policy,
                parameters,
                unique: EccPoint::new(
                    EccParameter::try_from(x).map_err(tpm_err)?,
                    EccParameter::try_from(vec![0u8; 32]).map_err(tpm_err)?,
                ),
            })
        }
        _ => Err(Error::Tpm(
            "an EK template that is neither RSA nor ECC".into(),
        )),
    }
}

/// Why the check stopped.
enum Stop {
    /// `before_command` said the time is up.
    Time,
    /// A TPM command failed where the check cannot go on.
    Tpm(String),
}

/// Where the next page of a handle scan from `from` up to `last` starts, or
/// `None` when the TPM returned the last of them. A page that claims more
/// but does not move past `from` is an error, not a partial list, as in
/// `next_handle_page`.
fn next_page(
    more: bool,
    from: u32,
    last: u32,
    page: &[u32],
) -> std::result::Result<Option<u32>, String> {
    if !more {
        return Ok(None);
    }
    match page.last() {
        Some(&next) if next >= from => Ok((next < last).then(|| next + 1)),
        _ => Err(format!(
            "the TPM reported more handles after {from:#010x} but returned none past it"
        )),
    }
}

/// A TPM conversation under the caller's deadline.
struct Run<'a, 'f> {
    ctx: &'a mut Context,
    before_command: &'a mut (dyn FnMut() -> bool + 'f),
    /// The persistent objects resolved so far, by TPM handle, each resolved
    /// once and closed only when the check ends ([`Run::close_persistent`]).
    /// An ESYS before 4.1.0 returns the same object for a handle resolved
    /// twice and frees it for both on the first close, and the EK scan
    /// meets irlume's original storage key (0x81010002 by default) in the
    /// endorsement primaries' range.
    persistent: Vec<(u32, ObjectHandle)>,
}

impl Run<'_, '_> {
    /// The ESYS object for the persistent `handle`, resolved once per check.
    fn persistent(&mut self, handle: u32) -> std::result::Result<ObjectHandle, Stop> {
        if let Some((_, object)) = self.persistent.iter().find(|(h, _)| *h == handle) {
            return Ok(*object);
        }
        let tpm_handle = PersistentTpmHandle::new(handle).map_err(|e| Stop::Tpm(e.to_string()))?;
        let object = self.tpm(|ctx| ctx.tr_from_tpm_public(TpmHandle::Persistent(tpm_handle)))?;
        self.persistent.push((handle, object));
        Ok(object)
    }

    /// Release ESYS's records of the persistent objects; the TPM keeps them.
    fn close_persistent(&mut self) {
        for (_, mut object) in self.persistent.drain(..) {
            let _ = self.ctx.tr_close(&mut object);
        }
    }

    /// Run one TPM command (or the session-wrapped derivation of the
    /// original storage key), first asking the deadline.
    fn tpm<T, E: std::fmt::Display>(
        &mut self,
        command: impl FnOnce(&mut Context) -> std::result::Result<T, E>,
    ) -> std::result::Result<T, Stop> {
        if !(self.before_command)() {
            return Err(Stop::Time);
        }
        command(self.ctx).map_err(|e| Stop::Tpm(e.to_string()))
    }

    /// As [`Run::tpm`], keeping the TPM's response code.
    fn tpm_rc<T>(
        &mut self,
        command: impl FnOnce(&mut Context) -> tss_esapi::Result<T>,
    ) -> std::result::Result<std::result::Result<T, tss_esapi::Error>, Stop> {
        if !(self.before_command)() {
            return Err(Stop::Time);
        }
        Ok(command(self.ctx))
    }

    /// One TPM property.
    fn property(&mut self, tag: PropertyTag) -> std::result::Result<Option<u32>, Stop> {
        let (data, _) =
            self.tpm(|ctx| ctx.get_capability(CapabilityType::TpmProperties, u32::from(tag), 1))?;
        let CapabilityData::TpmProperties(list) = data else {
            return Err(Stop::Tpm(
                "the TPM returned a non-property capability".into(),
            ));
        };
        Ok(list.find(tag).map(|property| property.value()))
    }

    /// Every handle the TPM reports from `first` to `last`.
    fn handles(&mut self, (first, last): (u32, u32)) -> std::result::Result<Vec<u32>, Stop> {
        let mut found = Vec::new();
        let mut from = first;
        loop {
            let (data, more) = self
                .tpm(|ctx| ctx.get_capability(CapabilityType::Handles, from, HANDLES_PER_PAGE))?;
            let CapabilityData::Handles(list) = data else {
                return Err(Stop::Tpm("the TPM returned a non-handle capability".into()));
            };
            let page: Vec<u32> = list.into_inner().into_iter().map(u32::from).collect();
            found.extend(page.iter().copied().filter(|h| (first..=last).contains(h)));
            match next_page(more, from, last, &page).map_err(Stop::Tpm)? {
                Some(next) => from = next,
                None => return Ok(found),
            }
        }
    }

    /// The contents of an NV index, read with the index's own (empty)
    /// authorization when it allows that, else the owner's.
    fn read_index(&mut self, index: u32) -> std::result::Result<Result<Vec<u8>>, Stop> {
        let handle = match NvIndexTpmHandle::new(index) {
            Ok(handle) => handle,
            Err(e) => return Ok(Err(tpm_err(e))),
        };
        let object = match self.tpm(|ctx| ctx.tr_from_tpm_public(TpmHandle::NvIndex(handle))) {
            Ok(object) => object,
            Err(Stop::Tpm(e)) => return Ok(Err(Error::Tpm(e))),
            Err(Stop::Time) => return Err(Stop::Time),
        };
        let nv = NvIndexHandle::from(object);
        let result = self.read_open_index(nv);
        let mut object = ObjectHandle::from(nv);
        let _ = self.ctx.tr_close(&mut object);
        result
    }

    fn read_open_index(&mut self, nv: NvIndexHandle) -> std::result::Result<Result<Vec<u8>>, Stop> {
        let public = match self.tpm(|ctx| ctx.nv_read_public(nv)) {
            Ok((public, _)) => public,
            Err(Stop::Tpm(e)) => return Ok(Err(Error::Tpm(e))),
            Err(Stop::Time) => return Err(Stop::Time),
        };
        let attributes: NvIndexAttributes = public.attributes();
        let auth = if attributes.auth_read() {
            NvAuth::NvIndex(nv)
        } else if attributes.owner_read() {
            NvAuth::Owner
        } else {
            return Ok(Err(Error::Tpm(
                "the index is readable only with platform authorization".into(),
            )));
        };
        let size = public.data_size();
        if size > MAX_INDEX_BYTES {
            return Ok(Err(Error::Tpm(format!("the index holds {size} octets"))));
        }
        let chunk = match self.property(PropertyTag::NvBufferMax)? {
            Some(max) => usize::try_from(max)
                .unwrap_or(1024)
                .clamp(64, MaxNvBuffer::MAX_SIZE),
            None => 1024,
        };
        let mut data = Vec::with_capacity(size);
        while data.len() < size {
            let length = (size - data.len()).min(chunk);
            let (length, offset) = (
                u16::try_from(length).expect("bounded by MAX_INDEX_BYTES"),
                u16::try_from(data.len()).expect("bounded by MAX_INDEX_BYTES"),
            );
            match self.tpm(|ctx| {
                ctx.execute_with_session(Some(AuthSession::Password), |ctx| {
                    ctx.nv_read(auth, nv, length, offset)
                })
            }) {
                Ok(buffer) => data.extend_from_slice(&buffer),
                Err(Stop::Tpm(e)) => return Ok(Err(Error::Tpm(e))),
                Err(Stop::Time) => return Err(Stop::Time),
            }
        }
        Ok(Ok(data))
    }
}

/// Run the check through `IRLUME_TCTI` (or the default transports), with
/// `before_command` asked before each TPM command and `anchors` the CAs to
/// judge chains against ([`Anchors::shipped`] outside tests).
///
/// Never fails: every reason it cannot judge is in the report, as
/// `unknown`.
pub fn endorsement_report(
    anchors: &Anchors,
    before_command: &mut dyn FnMut() -> bool,
) -> EndorsementReport {
    let mut ctx = match open_context() {
        Ok(ctx) => ctx,
        Err(e) => return stopped(format!("the TPM could not be opened: {e}")),
    };
    let mut run = Run {
        ctx: &mut ctx,
        before_command,
        persistent: Vec::new(),
    };
    let report = match report_through(&mut run, anchors) {
        Ok(report) => report,
        Err(Stop::Time) => stopped("ran out of time before reading the TPM".into()),
        Err(Stop::Tpm(e)) => stopped(format!("the TPM could not be read: {e}")),
    };
    run.close_persistent();
    report
}

fn stopped(reason: String) -> EndorsementReport {
    EndorsementReport::stopped(reason)
}

fn report_through(
    run: &mut Run<'_, '_>,
    anchors: &Anchors,
) -> std::result::Result<EndorsementReport, Stop> {
    let manufacturer = run.property(PropertyTag::Manufacturer)?;
    let permanent = run.property(PropertyTag::Permanent)?;
    let startup = run.property(PropertyTag::StartupClear)?;
    let (Some(manufacturer), Some(permanent), Some(startup)) = (manufacturer, permanent, startup)
    else {
        return Ok(stopped(
            "the TPM did not report its manufacturer and hierarchy state".into(),
        ));
    };
    // irlume never guesses an authorization (ADR-0036 section 3).
    if permanent & ENDORSEMENT_AUTH_SET != 0 {
        return Ok(stopped(
            "the endorsement hierarchy's authorization is set, so irlume does not use the EK"
                .into(),
        ));
    }
    if startup & EH_ENABLE == 0 {
        return Ok(stopped("the endorsement hierarchy is disabled".into()));
    }

    let present = run.handles(EK_RANGE)?;
    let mut judged = Vec::new();
    let mut not_judged = Vec::new();
    for (index, slot) in JUDGED {
        if present.contains(&index) {
            if judged.len() < MAX_JUDGED {
                judged.push((index, slot));
            } else {
                not_judged.push(index);
            }
        }
    }
    let skipped: Vec<SkippedCertificate> = present
        .iter()
        .filter_map(|&index| skipped_kind(index).map(|kind| SkippedCertificate { index, kind }))
        .collect();
    if judged.is_empty() {
        return Ok(EndorsementReport {
            state: EndorsementState::Info,
            stopped: None,
            certificates: Vec::new(),
            skipped,
            not_judged,
        });
    }

    // The chain indices are populated from the first one on, in order, and
    // read as one concatenation (Credential Profile 2.2.2.5.2).
    let mut joined = Vec::new();
    for index in CHAIN_RANGE.0..=CHAIN_RANGE.1 {
        if !present.contains(&index) {
            break;
        }
        match run.read_index(index)? {
            Ok(data) => joined.extend(data),
            Err(_) => break,
        }
    }
    let chain = ek_cert::chain_certificates(&joined);

    let mut check = Check {
        anchors,
        chain: &chain,
        manufacturer,
        permanent,
        present: &present,
        ek_handles: None,
        storage: None,
    };
    let mut certificates = Vec::with_capacity(judged.len());
    let mut out_of_time = false;
    for (index, slot) in judged {
        match check.judge(run, index, slot) {
            Ok(certificate) => certificates.push(certificate),
            Err(Stop::Time) => {
                out_of_time = true;
                break;
            }
            Err(Stop::Tpm(e)) => certificates.push(certificate_result(
                index,
                slot,
                EndorsementState::Unknown,
                format!("the TPM could not be read: {e}"),
            )),
        }
    }
    if let Some(Ok(Some(storage))) = check.storage.take() {
        storage.release(run.ctx);
    }
    let mut report = EndorsementReport {
        state: overall(&certificates, &not_judged),
        stopped: None,
        certificates,
        skipped,
        not_judged,
    };
    if out_of_time {
        // Evidence found before the deadline still counts; otherwise the
        // check reads unknown.
        if report.state != EndorsementState::Warn {
            report.state = EndorsementState::Unknown;
        }
        report.stopped = Some("ran out of time before every certificate was judged".into());
    }
    Ok(report)
}

/// Worst first: `warn` when any certificate is in a warn case; otherwise
/// `unknown` when a storage EK certificate was not judged; otherwise `pass`
/// when any passes; otherwise `unknown` when any cannot be judged; otherwise
/// `info` (ADR-0036 sections 1 and 4).
fn overall(certificates: &[EndorsementCertificate], not_judged: &[u32]) -> EndorsementState {
    let any = |state| certificates.iter().any(|c| c.state == state);
    if any(EndorsementState::Warn) {
        EndorsementState::Warn
    } else if !not_judged.is_empty() {
        EndorsementState::Unknown
    } else if any(EndorsementState::Pass) {
        EndorsementState::Pass
    } else if any(EndorsementState::Unknown) {
        EndorsementState::Unknown
    } else {
        EndorsementState::Info
    }
}

fn certificate_result(
    index: u32,
    slot: Slot,
    state: EndorsementState,
    detail: String,
) -> EndorsementCertificate {
    EndorsementCertificate {
        index,
        key: slot.label().to_owned(),
        state,
        detail,
        tpm: None,
        chain: Vec::new(),
    }
}

/// An EK as its public area states it.
struct EkObject {
    handle: KeyHandle,
    /// Derived for this check: flush it after use. A persistent one stays
    /// resolved until the check ends ([`Run::persistent`]).
    transient: bool,
    public: Public,
}

/// What every certificate is judged against.
struct Check<'c> {
    anchors: &'c Anchors,
    /// The certificates from the chain indices.
    chain: &'c [&'c [u8]],
    /// `TPM_PT_MANUFACTURER`.
    manufacturer: u32,
    /// `TPM_PT_PERMANENT`.
    permanent: u32,
    /// The populated handles in the EK range.
    present: &'c [u32],
    /// The persistent endorsement primaries, read once when first needed.
    ek_handles: Option<Vec<u32>>,
    /// The storage key the same-TPM test runs under, `None` during a
    /// lockout without the DA-exempt key, or why it is not available: found
    /// once, by the first test, and released after the last.
    storage: Option<std::result::Result<Option<StorageKey>, String>>,
}

impl Check<'_> {
    fn judge(
        &mut self,
        run: &mut Run<'_, '_>,
        index: u32,
        slot: Slot,
    ) -> std::result::Result<EndorsementCertificate, Stop> {
        let result = |state, detail| certificate_result(index, slot, state, detail);
        let contents = match run.read_index(index)? {
            Ok(contents) => contents,
            Err(e) => {
                return Ok(result(
                    EndorsementState::Unknown,
                    format!("the certificate index cannot be read: {e}"),
                ))
            }
        };
        let certificate = match ek_cert::certificate_in_nv(&contents)
            .map_err(|e| e.to_string())
            .and_then(|der| EkCertificate::from_der(der).map_err(|e| e.to_string()))
        {
            Ok(certificate) => certificate,
            Err(e) => {
                return Ok(result(
                    EndorsementState::Unknown,
                    format!("the index does not hold a certificate irlume can read: {e}"),
                ))
            }
        };
        let Some(certified_key) = certificate.public_key().cloned() else {
            return Ok(result(
            EndorsementState::Unknown,
            "the certificate's key is not RSA of 2048 to 4096 bits or NIST P-256, P-384 or P-521".into(),
        ));
        };
        let verdict = certificate.verify(self.chain, self.anchors, self.manufacturer);
        // What a verified chain says goes with every result judged after it
        // (ADR-0036, Phase 2 amendment "The report"), whatever the TPM does.
        let (tpm, chain) = match &verdict {
            ChainVerdict::Verified(chain) => (
                Some(CertifiedTpm {
                    manufacturer: chain.tpm.manufacturer,
                    model: chain.tpm.model.clone(),
                    version: chain.tpm.version.clone(),
                }),
                chain
                    .path
                    .iter()
                    .skip(1)
                    .map(|link| CertificateAuthority {
                        name: link.name.clone(),
                        not_after: link.not_after,
                    })
                    .collect(),
            ),
            _ => (None, Vec::new()),
        };
        let result = |state, detail| EndorsementCertificate {
            tpm: tpm.clone(),
            chain: chain.clone(),
            ..certificate_result(index, slot, state, detail)
        };
        // Evidence against the certificate is the result whatever the TPM
        // answers next, so no TPM failure or deadline can turn it unknown.
        if let ChainVerdict::Refused(refusal) = &verdict {
            return Ok(result(EndorsementState::Warn, refused(refusal)));
        }
        // The profile stores here the certificate of one EK: a certificate
        // for a key of another algorithm or size is not for it, whichever
        // EK of this TPM it names.
        if !slot.holds(&certified_key) {
            return Ok(result(
                EndorsementState::Warn,
                format!(
                    "the certificate is not for this TPM's endorsement key: its key is not the \
                     {} key the profile stores this index's certificate for",
                    slot.label()
                ),
            ));
        }

        let same_tpm = match self.ek_and_same_tpm(run, index, slot, &certified_key) {
            Ok(TpmPart::Tested(same_tpm)) => same_tpm,
            Ok(TpmPart::Decided(state, detail)) => return Ok(result(state, detail)),
            Err(Stop::Time) => return Err(Stop::Time),
            // A TPM failure keeps what a verified chain says, as every other
            // result after it does.
            Err(Stop::Tpm(e)) => {
                return Ok(result(
                    EndorsementState::Unknown,
                    format!("the TPM could not be read: {e}"),
                ))
            }
        };

        Ok(match (verdict, same_tpm) {
            // Returned above.
            (ChainVerdict::Refused(refusal), _) => {
                result(EndorsementState::Warn, refused(&refusal))
            }
            (_, SameTpm::Failed(why)) => result(
                EndorsementState::Warn,
                format!(
                    "irlume's storage key is not in the TPM that holds this certificate's \
                     endorsement key: {why}"
                ),
            ),
            (ChainVerdict::Verified(verified), SameTpm::Passed) => result(
                EndorsementState::Pass,
                format!(
                    "verifies to {}, matches the TPM's endorsement key, and irlume's storage \
                     key is in the same TPM",
                    verified
                        .path
                        .last()
                        .map_or("a pinned root", |root| root.name.as_str())
                ),
            ),
            (ChainVerdict::Unverifiable(why), _) => {
                result(EndorsementState::Unknown, unverifiable(&why))
            }
            (ChainVerdict::Verified(_), SameTpm::NotRun(why)) => result(
                EndorsementState::Unknown,
                format!("the certificate verifies, but the same-TPM test could not run: {why}"),
            ),
        })
    }

    /// Find the EK for `certified_key` (persistent, else derived from the
    /// slot's template) and run the same-TPM test with it, or the result
    /// decided on the way.
    fn ek_and_same_tpm(
        &mut self,
        run: &mut Run<'_, '_>,
        index: u32,
        slot: Slot,
        certified_key: &EkPublicKey,
    ) -> std::result::Result<TpmPart, Stop> {
        // A persistent EK with the certificate's key is the EK, whatever the
        // template indices hold; only a derivation needs them.
        let (persistent, unread) = persistent_ek(run, certified_key, &mut self.ek_handles)?;
        let ek = match persistent {
            Some(ek) => ek,
            None => {
                let template = match template_for(run, slot, index, self.present)? {
                    Ok(template) => template,
                    Err(e) => {
                        return Ok(TpmPart::Decided(
                            EndorsementState::Unknown,
                            format!("the EK template cannot be read: {e}"),
                        ))
                    }
                };
                match derive_ek(run, certified_key, template)? {
                    Ok(Some(ek)) => ek,
                    // A persistent EK that could not be read may be the
                    // certificate's: the mismatch is not evidence then.
                    Ok(None) if unread.is_some() => {
                        return Ok(TpmPart::Decided(
                            EndorsementState::Unknown,
                            format!(
                                "a persistent endorsement key could not be read ({}), and the \
                                 key the TPM derives from the certificate's template is not \
                                 the certificate's",
                                unread.unwrap_or_default()
                            ),
                        ))
                    }
                    Ok(None) => return Ok(TpmPart::Decided(
                        EndorsementState::Warn,
                        "the certificate is not for this TPM's endorsement key: the key the TPM \
                         derives from the certificate's template differs from the certificate's"
                            .into(),
                    )),
                    Err(e) => {
                        return Ok(TpmPart::Decided(
                            EndorsementState::Unknown,
                            format!("the EK could not be derived: {e}"),
                        ))
                    }
                }
            }
        };
        let same_tpm = same_tpm_test(run, &ek, self.permanent, &mut self.storage);
        if ek.transient {
            let _ = run.ctx.flush_context(ek.handle.into());
        }
        Ok(TpmPart::Tested(same_tpm?))
    }
}

/// What the TPM half of judging a certificate found.
enum TpmPart {
    /// A result decided before the same-TPM test could run.
    Decided(EndorsementState, String),
    /// The same-TPM test's result.
    Tested(SameTpm),
}

/// The template the EK for `index` is derived from: the populated template
/// index, else the default; in the low range with the EK Nonce applied.
fn template_for(
    run: &mut Run<'_, '_>,
    slot: Slot,
    index: u32,
    present: &[u32],
) -> std::result::Result<Result<Public>, Stop> {
    let template_index = slot.template_index(index);
    let template = if present.contains(&template_index) {
        match run.read_index(template_index)? {
            Ok(bytes) => unmarshal_exactly(&bytes),
            Err(e) => Err(e),
        }
    } else {
        slot.default_template()
    };
    let template = match template {
        Ok(template) => template,
        Err(e) => return Ok(Err(e)),
    };
    let Some(nonce_index) = slot.nonce_index(index).filter(|i| present.contains(i)) else {
        return Ok(Ok(template));
    };
    Ok(match run.read_index(nonce_index)? {
        Ok(nonce) => with_nonce(template, &nonce),
        Err(e) => Err(e),
    })
}

/// A TPMT_PUBLIC that fills the bytes exactly: tss-esapi's unmarshal
/// accepts trailing bytes, which would leave part of a template unread.
fn unmarshal_exactly(bytes: &[u8]) -> Result<Public> {
    let public = Public::unmarshall(bytes).map_err(tpm_err)?;
    if public.marshall().map_err(tpm_err)?.len() != bytes.len() {
        return Err(Error::Tpm(
            "the EK template has bytes after its TPMT_PUBLIC".into(),
        ));
    }
    Ok(public)
}

/// A persistent endorsement primary whose key is the certificate's, if one
/// is there, and why a listed one could not be read, if one could not.
fn persistent_ek(
    run: &mut Run<'_, '_>,
    certified: &EkPublicKey,
    ek_handles: &mut Option<Vec<u32>>,
) -> std::result::Result<(Option<EkObject>, Option<String>), Stop> {
    if ek_handles.is_none() {
        *ek_handles = Some(run.handles(EK_PERSISTENT)?);
    }
    let mut unread = None;
    for handle in ek_handles.clone().unwrap_or_default() {
        let object = match run.persistent(handle) {
            Ok(object) => object,
            Err(Stop::Time) => return Err(Stop::Time),
            Err(Stop::Tpm(e)) => {
                unread.get_or_insert(format!("{handle:#010x}: {e}"));
                continue;
            }
        };
        let key = KeyHandle::from(ESYS_TR::from(object));
        let public = match run.tpm(|ctx| ctx.read_public(key)) {
            Ok((public, _, _)) => public,
            Err(Stop::Time) => return Err(Stop::Time),
            Err(Stop::Tpm(e)) => {
                unread.get_or_insert(format!("{handle:#010x}: {e}"));
                continue;
            }
        };
        // Another persistent object stays resolved: the check may need it
        // (irlume's storage key), and closes all when it ends.
        if public_key(&public).as_ref() == Some(certified) {
            run.ctx
                .tr_set_auth(object, Auth::default())
                .map_err(|e| Stop::Tpm(e.to_string()))?;
            return Ok((
                Some(EkObject {
                    handle: key,
                    transient: false,
                    public,
                }),
                None,
            ));
        }
    }
    Ok((None, unread))
}

/// The EK `template` derives, if its key is the certificate's. `Ok(None)`
/// when the derived key differs.
fn derive_ek(
    run: &mut Run<'_, '_>,
    certified: &EkPublicKey,
    template: Public,
) -> std::result::Result<Result<Option<EkObject>>, Stop> {
    let created = run.tpm_rc(|ctx| {
        ctx.execute_with_session(Some(AuthSession::Password), |ctx| {
            ctx.create_primary(Hierarchy::Endorsement, template, None, None, None, None)
        })
    })?;
    let created = match created {
        Ok(created) => created,
        Err(e) => return Ok(Err(tpm_err(e))),
    };
    if public_key(&created.out_public).as_ref() == Some(certified) {
        return Ok(Ok(Some(EkObject {
            handle: created.key_handle,
            transient: true,
            public: created.out_public,
        })));
    }
    let _ = run.ctx.flush_context(created.key_handle.into());
    Ok(Ok(None))
}

/// The key in an EK public area, in the form a certificate states it.
fn public_key(public: &Public) -> Option<EkPublicKey> {
    match public {
        Public::Rsa {
            parameters, unique, ..
        } => {
            let modulus = unique.value();
            let start = modulus.iter().take_while(|b| **b == 0).count();
            let exponent = match parameters.exponent().value() {
                0 => 65_537,
                exponent => exponent,
            };
            Some(EkPublicKey::Rsa {
                modulus: modulus[start..].to_vec(),
                exponent,
            })
        }
        Public::Ecc {
            parameters, unique, ..
        } => {
            let (curve, size) = match parameters.ecc_curve() {
                TssCurve::NistP256 => (ek_cert::EccCurve::NistP256, 32),
                TssCurve::NistP384 => (ek_cert::EccCurve::NistP384, 48),
                TssCurve::NistP521 => (ek_cert::EccCurve::NistP521, 66),
                _ => return None,
            };
            let pad = |value: &[u8]| {
                (value.len() <= size).then(|| {
                    let mut padded = vec![0u8; size - value.len()];
                    padded.extend_from_slice(value);
                    padded
                })
            };
            Some(EkPublicKey::Ecc {
                curve,
                x: pad(unique.x().value())?,
                y: pad(unique.y().value())?,
            })
        }
        _ => None,
    }
}

/// The same-TPM test's result (ADR-0036 section 2.4).
enum SameTpm {
    Passed,
    /// The TPM refused the credential itself: `TPM_RC_INTEGRITY`, or a seed
    /// the EK cannot decrypt (`TPM_RC_VALUE` on the secret).
    Failed(String),
    /// Anything else: lockout, authorization, resources, transport.
    NotRun(String),
}

fn same_tpm_test(
    run: &mut Run<'_, '_>,
    ek: &EkObject,
    permanent: u32,
    storage: &mut Option<std::result::Result<Option<StorageKey>, String>>,
) -> std::result::Result<SameTpm, Stop> {
    let Some(name_alg) = NameAlg::from_tpm_alg(u16::from(ek.public.name_hashing_algorithm()))
    else {
        return Ok(SameTpm::NotRun(
            "the EK's name algorithm is not SHA-256, SHA-384 or SHA-512".into(),
        ));
    };
    // TPM2_ActivateCredential decrypts with the EK's own symmetric
    // definition; irlume makes credentials for the two the storage EK
    // templates use.
    let symmetric = match ek.public.symmetric_algorithm() {
        Some(SymmetricDefinitionObject::Aes {
            key_bits: AesKeyBits::Aes128,
            mode: SymmetricMode::Cfb,
        }) => EkSymmetric::Aes128Cfb,
        Some(SymmetricDefinitionObject::Aes {
            key_bits: AesKeyBits::Aes256,
            mode: SymmetricMode::Cfb,
        }) => EkSymmetric::Aes256Cfb,
        _ => {
            return Ok(SameTpm::NotRun(
                "the EK's symmetric algorithm is not AES-128 or AES-256 in CFB mode".into(),
            ))
        }
    };
    let Some(key) = public_key(&ek.public) else {
        return Ok(SameTpm::NotRun(
            "the EK's key is not one irlume can encrypt to".into(),
        ));
    };
    let policies = policies(name_alg);
    let route = if ek.public.auth_policy().value() == policies.a.as_slice() {
        PolicyRoute::Secret
    } else if ek.public.auth_policy().value() == policies.b.as_slice() {
        PolicyRoute::SecretOr
    } else {
        return Ok(SameTpm::NotRun(
            "the EK's authorization policy is not the profile's".into(),
        ));
    };

    let in_lockout = permanent & IN_LOCKOUT != 0;
    if storage.is_none() {
        *storage = Some(match find_storage_key(run, in_lockout) {
            Ok(found) => Ok(found),
            Err(Stop::Time) => return Err(Stop::Time),
            Err(Stop::Tpm(e)) => Err(e),
        });
    }
    let storage = match storage {
        Some(Ok(Some(storage))) => *storage,
        // The original storage key is not exempt from dictionary-attack
        // protection, so the test does not run under it during a lockout.
        Some(Ok(None)) => {
            return Ok(SameTpm::NotRun(
                "the TPM is in dictionary-attack lockout, and irlume's storage key is not exempt from it".into(),
            ))
        }
        Some(Err(e)) => {
            return Ok(SameTpm::NotRun(format!(
                "irlume's storage key is not available: {e}"
            )))
        }
        None => unreachable!("found above"),
    };
    let target = EkTarget {
        name_alg,
        symmetric,
        key: &key,
    };
    activate(run, ek, storage.handle, &target, &policies, route)
}

/// How an EK's authorization policy is satisfied for the USER role of
/// TPM2_ActivateCredential's keyHandle (Credential Profile 5.3.1, 5.4.3).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum PolicyRoute {
    /// PolicyA: TPM2_PolicySecret(TPM_RH_ENDORSEMENT), the low range.
    Secret,
    /// PolicyB: PolicySecret, then TPM2_PolicyOR(PolicyA, PolicyC). A
    /// password session would do too (userWithAuth is set), but fails during
    /// a lockout, as the EK is not DA-exempt.
    SecretOr,
}

/// The storage key the same-TPM test runs under.
#[derive(Debug, Clone, Copy)]
struct StorageKey {
    handle: KeyHandle,
    /// Derived for this check: flushed after it. A persistent key stays
    /// resolved until the check ends ([`Run::persistent`]).
    transient: bool,
}

impl StorageKey {
    fn release(self, ctx: &mut Context) {
        if self.transient {
            let _ = ctx.flush_context(self.handle.into());
        }
    }
}

/// The storage key new seals go under, found without persisting anything
/// and with the deadline asked before each command: irlume's recorded
/// DA-exempt key at its handle (as `da_exempt_key_at` finds it, its errors
/// included), else the original key at its handle, or derived for this
/// check (as `load_or_create_srk` does read-only). During a lockout the
/// original key is not looked for, nor derived: the test cannot run under
/// it (`None`).
fn find_storage_key(
    run: &mut Run<'_, '_>,
    in_lockout: bool,
) -> std::result::Result<Option<StorageKey>, Stop> {
    if let Some((handle, name)) = storage_key::recorded_key() {
        if OWNER_PERSISTENT.contains(&handle)
            && run.tpm(|ctx| persistent_handle_present(ctx, handle))?
        {
            let template = da_exempt_srk_template().map_err(|e| Stop::Tpm(e.to_string()))?;
            if let Some((object, handle)) = persistent_key(run, handle, |public, found| {
                found == name.as_slice() && has_template_shape(public, &template)
            })? {
                with_empty_auth(run, object)?;
                return Ok(Some(StorageKey {
                    handle,
                    transient: false,
                }));
            }
        }
    }
    if in_lockout {
        return Ok(None);
    }
    let persistent = persistent_srk_handle().map_err(|e| Stop::Tpm(e.to_string()))?;
    if run
        .tpm(|ctx| tpm_handle_exists(ctx, TPM2_HR_PERSISTENT, TpmHandle::Persistent(persistent)))?
    {
        let srk = srk_template().map_err(|e| Stop::Tpm(e.to_string()))?;
        // An original key that cannot be read is replaced by a derivation,
        // as `load_or_create_srk` does; failing to give ESYS its empty
        // authValue is an error there too.
        match persistent_key(run, u32::from(persistent), |public, _| {
            has_template_shape(public, &srk)
        }) {
            Ok(Some((object, handle))) => {
                with_empty_auth(run, object)?;
                return Ok(Some(StorageKey {
                    handle,
                    transient: false,
                }));
            }
            Ok(None) | Err(Stop::Tpm(_)) => {}
            Err(Stop::Time) => return Err(Stop::Time),
        }
    }
    Ok(Some(StorageKey {
        handle: run.tpm(create_srk)?,
        transient: true,
    }))
}

/// The persistent key at `handle` when `wanted` accepts its public area and
/// Name; `None` when `wanted` does not. A key that cannot be read is an
/// error. Either way the object stays resolved until the check ends
/// ([`Run::persistent`]).
fn persistent_key(
    run: &mut Run<'_, '_>,
    handle: u32,
    wanted: impl FnOnce(&Public, &[u8]) -> bool,
) -> std::result::Result<Option<(ObjectHandle, KeyHandle)>, Stop> {
    let object = run.persistent(handle)?;
    let key = KeyHandle::from(ESYS_TR::from(object));
    let (public, name, _) = run.tpm(|ctx| ctx.read_public(key))?;
    Ok(wanted(&public, name.value()).then_some((object, key)))
}

/// Tell ESYS that a storage key's authValue is empty, as `load_or_create_srk`
/// and `da_exempt_key_at` do; a failure is an error for both keys.
fn with_empty_auth(run: &mut Run<'_, '_>, object: ObjectHandle) -> std::result::Result<(), Stop> {
    run.ctx
        .tr_set_auth(object, Auth::default())
        .map_err(|e| Stop::Tpm(e.to_string()))
}

fn hashing(alg: NameAlg) -> HashingAlgorithm {
    match alg {
        NameAlg::Sha256 => HashingAlgorithm::Sha256,
        NameAlg::Sha384 => HashingAlgorithm::Sha384,
        NameAlg::Sha512 => HashingAlgorithm::Sha512,
    }
}

/// Make a credential for the storage key's Name, satisfy the EK's policy,
/// and ask the TPM to release the credential.
fn activate(
    run: &mut Run<'_, '_>,
    ek: &EkObject,
    storage: KeyHandle,
    target: &EkTarget<'_>,
    policies: &Policies,
    route: PolicyRoute,
) -> std::result::Result<SameTpm, Stop> {
    let not_run = |what: &str, e: String| SameTpm::NotRun(format!("{what}: {e}"));
    let name = match run.tpm(|ctx| ctx.read_public(storage)) {
        Ok((_, name, _)) => name,
        Err(Stop::Tpm(e)) => return Ok(not_run("irlume's storage key could not be read", e)),
        Err(Stop::Time) => return Err(Stop::Time),
    };
    let mut rng = rand::rng();
    let mut credential = Zeroizing::new(vec![0u8; target.name_alg.digest_len()]);
    rand::Rng::fill_bytes(&mut rng, &mut credential);
    let made = match tpm_credential::make_credential(target, name.value(), &credential, &mut rng) {
        Ok(made) => made,
        Err(e) => return Ok(not_run("a credential could not be made", e.to_string())),
    };

    let session = match run.tpm(|ctx| {
        ctx.start_auth_session(
            None,
            None,
            None,
            SessionType::Policy,
            SymmetricDefinition::Null,
            hashing(target.name_alg),
        )
    }) {
        Ok(Some(session)) => session,
        Ok(None) => return Ok(SameTpm::NotRun("the TPM returned no policy session".into())),
        Err(Stop::Tpm(e)) => return Ok(not_run("a policy session could not be started", e)),
        Err(Stop::Time) => return Err(Stop::Time),
    };
    let outcome = satisfy_and_activate(run, ek, storage, session, &made, policies, route);
    let _ = run.ctx.flush_context(SessionHandle::from(session).into());
    Ok(match outcome? {
        Ok(released) => classify(Ok(released), &credential),
        Err(SessionStep::Policy(e)) => {
            SameTpm::NotRun(format!("the EK's policy could not be satisfied: {e}"))
        }
        Err(SessionStep::Activate(e)) => classify(Err(e), &credential),
    })
}

/// Where in the session a step failed.
enum SessionStep {
    Policy(String),
    Activate(tss_esapi::Error),
}

fn satisfy_and_activate(
    run: &mut Run<'_, '_>,
    ek: &EkObject,
    storage: KeyHandle,
    session: AuthSession,
    made: &tpm_credential::Credential,
    policies: &Policies,
    route: PolicyRoute,
) -> std::result::Result<std::result::Result<Digest, SessionStep>, Stop> {
    let Ok(policy) = PolicySession::try_from(session) else {
        return Ok(Err(SessionStep::Policy("not a policy session".into())));
    };
    if let Err(e) = run.tpm_rc(|ctx| {
        ctx.execute_with_session(Some(AuthSession::Password), |ctx| {
            ctx.policy_secret(
                policy,
                AuthHandle::Endorsement,
                Nonce::default(),
                Digest::default(),
                Nonce::default(),
                None,
            )
        })
    })? {
        return Ok(Err(SessionStep::Policy(e.to_string())));
    }
    if route == PolicyRoute::SecretOr {
        let branches = [policies.a.clone(), policies.c.clone()]
            .into_iter()
            .map(Digest::try_from)
            .collect::<tss_esapi::Result<Vec<Digest>>>()
            .map_err(|e| Stop::Tpm(e.to_string()))?;
        let list = digest_list(&branches).map_err(|e| Stop::Tpm(e.to_string()))?;
        if let Err(e) = run.tpm_rc(|ctx| ctx.policy_or(policy, list))? {
            return Ok(Err(SessionStep::Policy(e.to_string())));
        }
    }
    let id_object =
        IdObject::try_from(made.id_object.clone()).map_err(|e| Stop::Tpm(e.to_string()))?;
    let secret = EncryptedSecret::try_from(made.encrypted_secret.clone())
        .map_err(|e| Stop::Tpm(e.to_string()))?;
    Ok(run
        .tpm_rc(|ctx| {
            // Session 1, ADMIN role of the storage key (adminWithPolicy is
            // clear, its authValue empty); session 2, USER role of the EK,
            // through its policy. A password session encrypts no parameter,
            // so the released credential arrives as the TPM sent it.
            ctx.execute_with_sessions((Some(AuthSession::Password), Some(session), None), |ctx| {
                ctx.activate_credential(storage, ek.handle, id_object, secret)
            })
        })?
        .map_err(SessionStep::Activate))
}

/// The same-TPM test's result from TPM2_ActivateCredential's answer. Only
/// the TPM refusing the credential itself is evidence (ADR-0036 section
/// 2.4): `TPM_RC_INTEGRITY`, the credential not bound to the storage key's
/// Name in the TPM holding this EK, or `TPM_RC_VALUE` on the secret, a seed
/// that EK cannot decrypt. Anything else cannot be judged.
fn classify(outcome: std::result::Result<Digest, tss_esapi::Error>, credential: &[u8]) -> SameTpm {
    match outcome {
        // tss-esapi keeps a `Digest`'s bytes in `Zeroizing`, so the released
        // copy is wiped when it drops here.
        Ok(released) if released.value() == credential => SameTpm::Passed,
        Ok(_) => SameTpm::Failed("the TPM released a different credential".into()),
        Err(tss_esapi::Error::Tss2Error(rc)) => match (rc.kind(), parameter_number(rc)) {
            (Some(Tss2ResponseCodeKind::Integrity), _) => SameTpm::Failed(
                "the TPM refused the credential bound to irlume's storage key (TPM_RC_INTEGRITY)"
                    .into(),
            ),
            (Some(Tss2ResponseCodeKind::Value), Some(2)) => SameTpm::Failed(
                "the endorsement key could not decrypt the credential's seed (TPM_RC_VALUE)".into(),
            ),
            _ => SameTpm::NotRun(format!("TPM2_ActivateCredential failed: {rc}")),
        },
        Err(e) => SameTpm::NotRun(format!("TPM2_ActivateCredential failed: {e}")),
    }
}

/// The parameter a format-one response code names, if it names one.
/// tss-esapi keeps the bit fields private, so this reads its display of the
/// raw code ("Response code value: 0x2c4"): TPM_RC_P (bit 6) marks a
/// parameter, numbered in bits 8 to 11 (Part 2 6.6).
fn parameter_number(rc: Tss2ResponseCode) -> Option<u32> {
    let Tss2ResponseCode::FormatOne(code) = rc else {
        return None;
    };
    let text = code.to_string();
    let raw = u32::from_str_radix(text.rsplit("0x").next()?, 16).ok()?;
    (raw & 0x40 != 0).then_some((raw >> 8) & 0xF)
}

fn refused(refusal: &Refusal) -> String {
    match refusal {
        Refusal::Signature {
            certificate,
            issuer,
        } => {
            format!("{certificate}'s signature does not verify with the key of {issuer}, which it names")
        }
        Refusal::NotACa { certificate } => {
            format!("{certificate} signs certificates but is not a CA")
        }
        Refusal::NoCertSign { certificate } => format!("{certificate} may not sign certificates"),
        Refusal::PathLength { certificate } => {
            format!("{certificate} exceeds its issuer's path length")
        }
        Refusal::CaPurpose { certificate } => {
            format!("{certificate} may not issue EK certificates (Extended Key Usage)")
        }
        Refusal::Leaf(problem) => format!(
            "the certificate is not an EK certificate: {}",
            leaf_problem(problem)
        ),
    }
}

fn leaf_problem(problem: &LeafProblem) -> String {
    match problem {
        LeafProblem::NotVersion3 => "not an X.509 v3 certificate".into(),
        LeafProblem::BasicConstraints => "its Basic Constraints is missing or not critical".into(),
        LeafProblem::IsCa => "it is marked as a CA".into(),
        LeafProblem::KeyUsageMissing => "its Key Usage is missing or not critical".into(),
        LeafProblem::KeyUsageWrong => "its Key Usage does not fit a storage EK".into(),
        LeafProblem::NoAlternativeName => "it names no TPM in a subject alternative name".into(),
        LeafProblem::AlternativeNameNotCritical => {
            "its subject is empty and its subject alternative name not critical".into()
        }
        LeafProblem::ConflictingAttributes => "it names the TPM twice, differently".into(),
        LeafProblem::NoManufacturer => "it names no TPM manufacturer".into(),
        LeafProblem::ManufacturerDiffers { certificate, tpm } => {
            format!("it names manufacturer {certificate:#010x}, but the TPM reports {tpm:#010x}")
        }
        LeafProblem::NoModel => "it names no TPM model".into(),
        LeafProblem::NoVersion => "it names no TPM firmware version".into(),
        LeafProblem::Purpose => "its Extended Key Usage leaves out EK certificates".into(),
        LeafProblem::PurposeCritical => "its Extended Key Usage is critical".into(),
    }
}

fn unverifiable(why: &Unverifiable) -> String {
    match why {
        Unverifiable::IssuerNotListed { issuer } => {
            format!("its issuer {issuer} is not in irlume's list of TPM vendor CAs")
        }
        Unverifiable::Algorithm {
            certificate,
            algorithm,
        } => {
            format!("{certificate} is signed with {algorithm}, which irlume does not accept")
        }
        Unverifiable::CriticalExtension {
            certificate,
            extension,
        } => {
            format!("{certificate} has a critical extension irlume does not process ({extension})")
        }
        Unverifiable::Constraints { certificate } => {
            format!(
                "{certificate} carries name or policy constraints, which irlume does not implement"
            )
        }
        Unverifiable::Malformed {
            certificate,
            detail,
        } => format!("{certificate}: {detail}"),
        Unverifiable::LeafKey => {
            "the certificate's key is not RSA of 2048 to 4096 bits or NIST P-256, P-384 or P-521"
                .into()
        }
    }
}

#[cfg(test)]
mod tests;

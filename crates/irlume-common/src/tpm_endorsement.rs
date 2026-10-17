// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright the irlume contributors.

//! What irlumed reads about the TPM's endorsement key (EK) certificates for
//! the `tpm-endorsement` doctor check (ADR-0036). Shared so the daemon, which
//! alone opens the TPM, and the CLI, which words the result, agree.
//!
//! Every string here that came from a certificate (a CA's name, the TPM model
//! and version) is untrusted: irlumed bounds it, and whoever prints it must
//! still render it as visible text (ADR-0036 section 7). Nothing here
//! identifies the TPM: no EK public key, hash, serial or fingerprint.

use std::time::Duration;

use serde::{Deserialize, Serialize};

/// How long a client waits for irlumed's answer to
/// [`crate::Request::TpmEndorsement`] (ADR-0036 section 4): deriving an EK
/// can take more than 10 seconds on a slow firmware TPM.
pub const CLIENT_BUDGET: Duration = Duration::from_secs(60);

/// How long irlumed lets the check run, from the request's submission to
/// its worker: after that it starts no TPM command that does work, releases
/// what it loaded (at most three TPM2_FlushContext) and answers `unknown`.
/// The rest of [`CLIENT_BUDGET`] covers the one slow command that may still
/// be running, those flushes and the reply.
pub const DAEMON_DEADLINE: Duration = Duration::from_secs(45);

/// The check's result, or one certificate's: worst first `warn`, then
/// `pass`, `unknown` and `info` (ADR-0036 section 1).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EndorsementState {
    /// A certificate verifies to a pinned vendor root, matches the TPM's EK,
    /// and irlume's storage key is in the same TPM.
    Pass,
    /// Evidence against the TPM: a certificate that does not match its EK,
    /// fails a signature or the EK profile on a path to a pinned root, or
    /// whose EK does not hold irlume's storage key.
    Warn,
    /// No EK certificate is stored.
    Info,
    /// The evidence cannot be judged; never "not genuine". Also what a state
    /// this build does not know (a newer daemon) reads as.
    #[serde(other)]
    Unknown,
}

/// What irlumed found for the `tpm-endorsement` check.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EndorsementReport {
    /// The check's result over every judged certificate.
    pub state: EndorsementState,
    /// Why the check stopped before judging the certificates: the
    /// endorsement hierarchy is disabled or its authorization is set, the
    /// TPM could not be read, or the time ran out.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub stopped: Option<String>,
    /// Each storage EK certificate judged, low range first.
    #[serde(default)]
    pub certificates: Vec<EndorsementCertificate>,
    /// Certificates the profile assigns to EKs irlume cannot test, named
    /// only: they do not change the result (ADR-0036 section 2.1).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub skipped: Vec<SkippedCertificate>,
    /// Storage EK certificate indices beyond the four judged: their presence
    /// keeps the result from `pass` (ADR-0036 section 4).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub not_judged: Vec<u32>,
}

impl EndorsementReport {
    /// A check that judged nothing: `unknown`, for `reason`.
    pub fn stopped(reason: impl Into<String>) -> Self {
        Self {
            state: EndorsementState::Unknown,
            stopped: Some(reason.into()),
            certificates: Vec::new(),
            skipped: Vec::new(),
            not_judged: Vec::new(),
        }
    }
}

/// One judged EK certificate.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EndorsementCertificate {
    /// Its NV index, such as `0x01C00002`.
    pub index: u32,
    /// The EK it is for, such as "RSA 2048" or "ECC NIST P-384".
    pub key: String,
    pub state: EndorsementState,
    /// Why, in one sentence. May quote a certificate (untrusted, bounded).
    pub detail: String,
    /// The TPM the certificate names, when its chain verified.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tpm: Option<CertifiedTpm>,
    /// The CAs from the certificate's issuer to the root, when its chain
    /// verified.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub chain: Vec<CertificateAuthority>,
}

/// The TPM a verified EK certificate names in its subject alternative name.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CertifiedTpm {
    /// The TCG vendor ID, equal to the TPM's `TPM_PT_MANUFACTURER`.
    pub manufacturer: u32,
    /// The part number. Untrusted, bounded.
    pub model: String,
    /// The firmware version when the certificate was issued, as the
    /// certificate states it. Untrusted, bounded.
    pub version: String,
}

/// One CA on a verified path.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CertificateAuthority {
    /// Its subject as RFC 4514 text. Untrusted, bounded.
    pub name: String,
    /// Its validity end, in seconds since the Unix epoch: reported, not
    /// enforced, so it may have passed.
    pub not_after: u64,
}

/// A populated certificate index irlume does not judge.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SkippedCertificate {
    pub index: u32,
    pub kind: SkippedKind,
}

/// Why a certificate is not judged.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SkippedKind {
    /// For a signing EK, which TPM2_ActivateCredential cannot use: H-8 to
    /// H-17, the firmware-limited signing EKs H-22 to H-25 and the ML-DSA
    /// ones.
    Signing,
    /// For a firmware-limited storage EK (H-18 to H-21), under a hierarchy
    /// irlume does not use.
    FirmwareLimited,
    /// For an ML-KEM storage EK.
    MlKem,
    /// For the SM2 storage EK.
    Sm2,
    /// A kind this build does not know (a newer daemon).
    #[serde(other)]
    Unknown,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_report_round_trips_and_an_unknown_state_or_kind_reads_as_unknown() {
        let report = EndorsementReport {
            state: EndorsementState::Pass,
            stopped: None,
            certificates: vec![EndorsementCertificate {
                index: 0x01C0_0002,
                key: "RSA 2048".into(),
                state: EndorsementState::Pass,
                detail: "verified".into(),
                tpm: Some(CertifiedTpm {
                    manufacturer: 0x5354_4D20,
                    model: "ST33HTPHAHB4".into(),
                    version: "id:00490004".into(),
                }),
                chain: vec![CertificateAuthority {
                    name: "CN=STM TPM EK Intermediate CA 05".into(),
                    not_after: 2_082_672_000,
                }],
            }],
            skipped: vec![SkippedCertificate {
                index: 0x01C0_0032,
                kind: SkippedKind::Signing,
            }],
            not_judged: vec![],
        };
        let wire = serde_json::to_string(&report).unwrap();
        assert_eq!(
            serde_json::from_str::<EndorsementReport>(&wire).unwrap(),
            report
        );
        assert!(
            !wire.contains("not_judged"),
            "empty lists stay off the wire: {wire}"
        );

        let newer = r#"{"state":"quarantined","certificates":[],
            "skipped":[{"index":29360256,"kind":"ml_dsa"}]}"#;
        let read: EndorsementReport = serde_json::from_str(newer).unwrap();
        assert_eq!(read.state, EndorsementState::Unknown);
        assert_eq!(read.skipped[0].kind, SkippedKind::Unknown);
    }
}

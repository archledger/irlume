// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright the irlume contributors.

use std::fmt;

use serde::{de::DeserializeOwned, Deserialize, Deserializer, Serialize, Serializer};

pub const RATE_SCALE_PPB: u64 = 1_000_000_000;
pub const MAX_CAMPAIGN_DOCUMENT_BYTES: usize = 256 * 1024;

const MAX_IDENTIFIER_BYTES: usize = 256;

#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct Identifier(String);

impl Identifier {
    /// Validates a bounded, non-control identifier.
    ///
    /// # Errors
    ///
    /// Returns [`CampaignError::InvalidIdentifier`] when `value` is empty,
    /// exceeds 256 bytes, or contains a control character.
    pub fn new(value: &str) -> Result<Self, CampaignError> {
        if value.is_empty()
            || value.len() > MAX_IDENTIFIER_BYTES
            || value.chars().any(char::is_control)
        {
            return Err(CampaignError::InvalidIdentifier);
        }
        Ok(Self(value.to_owned()))
    }

    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct Sha256Digest(String);

impl Sha256Digest {
    /// Validates a lowercase hexadecimal SHA-256 digest.
    ///
    /// # Errors
    ///
    /// Returns [`CampaignError::InvalidDigest`] unless `value` is exactly 64
    /// lowercase hexadecimal characters.
    pub fn new(value: &str) -> Result<Self, CampaignError> {
        if value.len() != 64
            || !value
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
        {
            return Err(CampaignError::InvalidDigest);
        }
        Ok(Self(value.to_owned()))
    }

    #[must_use]
    pub fn of(bytes: &[u8]) -> Self {
        Self(irlume_common::sha256_hex(bytes))
    }

    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct SignerFingerprint(String);

impl SignerFingerprint {
    /// Validates a full uppercase OpenPGP fingerprint.
    ///
    /// # Errors
    ///
    /// Returns [`CampaignError::InvalidSignerFingerprint`] unless `value` is
    /// exactly 40 uppercase hexadecimal characters.
    pub fn new(value: &str) -> Result<Self, CampaignError> {
        if value.len() != 40
            || !value
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'A'..=b'F').contains(&byte))
        {
            return Err(CampaignError::InvalidSignerFingerprint);
        }
        Ok(Self(value.to_owned()))
    }

    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct RatePpb(u64);

impl RatePpb {
    /// Validates a rate in integer parts per billion.
    ///
    /// # Errors
    ///
    /// Returns [`CampaignError::InvalidRate`] when `value` exceeds one.
    pub const fn new(value: u64) -> Result<Self, CampaignError> {
        if value > RATE_SCALE_PPB {
            return Err(CampaignError::InvalidRate);
        }
        Ok(Self(value))
    }

    #[must_use]
    pub const fn get(self) -> u64 {
        self.0
    }
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct SignedRateDifferencePpb(i64);

impl SignedRateDifferencePpb {
    /// Validates a signed rate difference in integer parts per billion.
    ///
    /// # Errors
    ///
    /// Returns [`CampaignError::InvalidRate`] when `value` lies outside
    /// `[-1, 1]`.
    pub const fn new(value: i64) -> Result<Self, CampaignError> {
        if value < -(RATE_SCALE_PPB as i64) || value > RATE_SCALE_PPB as i64 {
            return Err(CampaignError::InvalidRate);
        }
        Ok(Self(value))
    }

    #[must_use]
    pub const fn get(self) -> i64 {
        self.0
    }
}

macro_rules! string_wire {
    ($type:ty, $constructor:path) => {
        impl Serialize for $type {
            fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
            where
                S: Serializer,
            {
                self.as_str().serialize(serializer)
            }
        }

        impl<'de> Deserialize<'de> for $type {
            fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
            where
                D: Deserializer<'de>,
            {
                let value = String::deserialize(deserializer)?;
                $constructor(&value).map_err(serde::de::Error::custom)
            }
        }
    };
}

string_wire!(Identifier, Identifier::new);
string_wire!(Sha256Digest, Sha256Digest::new);
string_wire!(SignerFingerprint, SignerFingerprint::new);

impl Serialize for RatePpb {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        self.0.serialize(serializer)
    }
}

impl<'de> Deserialize<'de> for RatePpb {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        Self::new(u64::deserialize(deserializer)?).map_err(serde::de::Error::custom)
    }
}

impl Serialize for SignedRateDifferencePpb {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        self.0.serialize(serializer)
    }
}

impl<'de> Deserialize<'de> for SignedRateDifferencePpb {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        Self::new(i64::deserialize(deserializer)?).map_err(serde::de::Error::custom)
    }
}

pub(crate) mod private {
    pub trait Sealed {}
}

pub trait CanonicalDocument: private::Sealed + DeserializeOwned + Serialize + Sized {
    /// Parses a closed document and requires exact compact canonical bytes.
    ///
    /// # Errors
    ///
    /// Returns a fixed campaign error for oversized, malformed, noncanonical,
    /// or semantically invalid content.
    fn from_canonical_json(bytes: &[u8]) -> Result<Self, CampaignError>;

    /// Serializes the validated document as compact canonical JSON.
    ///
    /// # Errors
    ///
    /// Returns a fixed campaign error when validation or serialization fails.
    fn to_canonical_json(&self) -> Result<Vec<u8>, CampaignError>;

    fn signature_metadata(&self) -> &crate::SignatureMetadata;

    /// Returns the SHA-256 of canonical document bytes.
    ///
    /// # Errors
    ///
    /// Returns a fixed campaign error when canonical serialization fails.
    fn digest(&self) -> Result<Sha256Digest, CampaignError> {
        self.to_canonical_json()
            .map(|bytes| Sha256Digest::of(&bytes))
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CampaignDiagnostic {
    PolicyUnsupported,
    ProtocolInvalid,
    ConsentIneligible,
    CohortIncomplete,
    BundleUnsafe,
    CaptureIncomplete,
    ProvenanceMismatch,
    EvaluatorDrift,
    SecurityGateFailed,
    NoninferiorityFailed,
    LatencyFailed,
    ReviewMissing,
    ReviewRejected,
    ArtifactCompileFailed,
}

impl CampaignDiagnostic {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::PolicyUnsupported => "policy_unsupported",
            Self::ProtocolInvalid => "protocol_invalid",
            Self::ConsentIneligible => "consent_ineligible",
            Self::CohortIncomplete => "cohort_incomplete",
            Self::BundleUnsafe => "bundle_unsafe",
            Self::CaptureIncomplete => "capture_incomplete",
            Self::ProvenanceMismatch => "provenance_mismatch",
            Self::EvaluatorDrift => "evaluator_drift",
            Self::SecurityGateFailed => "security_gate_failed",
            Self::NoninferiorityFailed => "noninferiority_failed",
            Self::LatencyFailed => "latency_failed",
            Self::ReviewMissing => "review_missing",
            Self::ReviewRejected => "review_rejected",
            Self::ArtifactCompileFailed => "artifact_compile_failed",
        }
    }
}

impl fmt::Display for CampaignDiagnostic {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.as_str())
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum CampaignError {
    InvalidIdentifier,
    InvalidDigest,
    InvalidSignerFingerprint,
    InvalidRate,
    CanonicalInvalid,
    DocumentTooLarge,
    SignatureMissing,
    SignatureTooLarge,
    SignatureInvalid,
    SignatureRoleMismatch,
    SignatureSignerMismatch,
    SignatureVerifierInvalid,
    SignatureVerifierFailed,
    SignatureVerifierTimeout,
    PolicyUnsupported,
    ProtocolInvalid,
    ConsentIneligible,
    CohortIncomplete,
    BundleUnsafe,
    CaptureIncomplete,
    ProvenanceMismatch,
    EvaluatorDrift,
    SecurityGateFailed,
    NoninferiorityFailed,
    LatencyFailed,
    ReviewMissing,
    ReviewRejected,
    ArtifactCompileFailed,
}

impl CampaignError {
    #[must_use]
    pub const fn diagnostic(&self) -> CampaignDiagnostic {
        match self {
            Self::PolicyUnsupported => CampaignDiagnostic::PolicyUnsupported,
            Self::ConsentIneligible => CampaignDiagnostic::ConsentIneligible,
            Self::CohortIncomplete => CampaignDiagnostic::CohortIncomplete,
            Self::BundleUnsafe => CampaignDiagnostic::BundleUnsafe,
            Self::CaptureIncomplete => CampaignDiagnostic::CaptureIncomplete,
            Self::ProvenanceMismatch => CampaignDiagnostic::ProvenanceMismatch,
            Self::EvaluatorDrift => CampaignDiagnostic::EvaluatorDrift,
            Self::SecurityGateFailed => CampaignDiagnostic::SecurityGateFailed,
            Self::NoninferiorityFailed => CampaignDiagnostic::NoninferiorityFailed,
            Self::LatencyFailed => CampaignDiagnostic::LatencyFailed,
            Self::ReviewMissing => CampaignDiagnostic::ReviewMissing,
            Self::ReviewRejected => CampaignDiagnostic::ReviewRejected,
            Self::ArtifactCompileFailed => CampaignDiagnostic::ArtifactCompileFailed,
            Self::InvalidIdentifier
            | Self::InvalidDigest
            | Self::InvalidSignerFingerprint
            | Self::InvalidRate
            | Self::CanonicalInvalid
            | Self::DocumentTooLarge
            | Self::SignatureMissing
            | Self::SignatureTooLarge
            | Self::SignatureInvalid
            | Self::SignatureRoleMismatch
            | Self::SignatureSignerMismatch
            | Self::SignatureVerifierInvalid
            | Self::SignatureVerifierFailed
            | Self::SignatureVerifierTimeout
            | Self::ProtocolInvalid => CampaignDiagnostic::ProtocolInvalid,
        }
    }
}

impl fmt::Display for CampaignError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.diagnostic().fmt(formatter)
    }
}

impl std::error::Error for CampaignError {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn authority_atoms_reject_noncanonical_input() {
        assert!(Identifier::new("").is_err());
        assert!(Identifier::new(&"x".repeat(257)).is_err());
        assert!(Identifier::new("line\nbreak").is_err());
        assert!(Sha256Digest::new(&"ab".repeat(32)).is_ok());
        assert!(Sha256Digest::new(&"AB".repeat(32)).is_err());
        assert!(SignerFingerprint::new("F35053398E3C80FE20891B82C10B8492BD7F30C6").is_ok());
        assert!(SignerFingerprint::new("2BD7F30C6").is_err());
        assert!(RatePpb::new(1_000_000_001).is_err());
        assert!(SignedRateDifferencePpb::new(-1_000_000_001).is_err());
    }

    #[test]
    fn diagnostics_are_fixed_and_safe() {
        let diagnostics = [
            CampaignDiagnostic::PolicyUnsupported,
            CampaignDiagnostic::ProtocolInvalid,
            CampaignDiagnostic::ConsentIneligible,
            CampaignDiagnostic::CohortIncomplete,
            CampaignDiagnostic::BundleUnsafe,
            CampaignDiagnostic::CaptureIncomplete,
            CampaignDiagnostic::ProvenanceMismatch,
            CampaignDiagnostic::EvaluatorDrift,
            CampaignDiagnostic::SecurityGateFailed,
            CampaignDiagnostic::NoninferiorityFailed,
            CampaignDiagnostic::LatencyFailed,
            CampaignDiagnostic::ReviewMissing,
            CampaignDiagnostic::ReviewRejected,
            CampaignDiagnostic::ArtifactCompileFailed,
        ];
        let expected = [
            "policy_unsupported",
            "protocol_invalid",
            "consent_ineligible",
            "cohort_incomplete",
            "bundle_unsafe",
            "capture_incomplete",
            "provenance_mismatch",
            "evaluator_drift",
            "security_gate_failed",
            "noninferiority_failed",
            "latency_failed",
            "review_missing",
            "review_rejected",
            "artifact_compile_failed",
        ];
        for (diagnostic, expected) in diagnostics.into_iter().zip(expected) {
            let rendered = diagnostic.to_string();
            assert_eq!(rendered, expected);
            for forbidden in ["/", "\\", "gpg:", "token", "campaign-id", "serde"] {
                assert!(!rendered.contains(forbidden));
            }
        }

        let errors = [
            CampaignError::InvalidIdentifier,
            CampaignError::InvalidDigest,
            CampaignError::InvalidSignerFingerprint,
            CampaignError::InvalidRate,
            CampaignError::CanonicalInvalid,
            CampaignError::DocumentTooLarge,
            CampaignError::SignatureMissing,
            CampaignError::SignatureTooLarge,
            CampaignError::SignatureInvalid,
            CampaignError::SignatureRoleMismatch,
            CampaignError::SignatureSignerMismatch,
            CampaignError::SignatureVerifierInvalid,
            CampaignError::SignatureVerifierFailed,
            CampaignError::SignatureVerifierTimeout,
            CampaignError::PolicyUnsupported,
            CampaignError::ProtocolInvalid,
            CampaignError::ConsentIneligible,
            CampaignError::CohortIncomplete,
            CampaignError::BundleUnsafe,
            CampaignError::CaptureIncomplete,
            CampaignError::ProvenanceMismatch,
            CampaignError::EvaluatorDrift,
            CampaignError::SecurityGateFailed,
            CampaignError::NoninferiorityFailed,
            CampaignError::LatencyFailed,
            CampaignError::ReviewMissing,
            CampaignError::ReviewRejected,
            CampaignError::ArtifactCompileFailed,
        ];
        for error in errors {
            assert_eq!(error.to_string(), error.diagnostic().to_string());
        }
    }
}

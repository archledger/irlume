// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright the irlume contributors.

//! Governed, non-authorizing camera profile evaluation contracts.

use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};

pub use crate::profile::QualificationScene;

/// Signed protocol shape understood by this build.
pub const PROFILE_EVALUATION_PROTOCOL_SCHEMA_VERSION: u32 = 1;
/// Owner-pilot acceptance policy understood by this build.
pub const PROFILE_EVALUATION_ACCEPTANCE_POLICY_VERSION: u32 = 1;
/// Hard serialized bound for every evaluation control document.
pub const MAX_PROFILE_EVALUATION_DOCUMENT_BYTES: usize = 256 * 1024;
/// Hard bound on ordered protocol cases.
pub const MAX_PROFILE_EVALUATION_CASES: usize = 128;
/// Hard bound on protocol reference relationships.
pub const MAX_PROFILE_EVALUATION_REFERENCES: usize = 32;

const MAX_PROFILE_EVALUATION_ID_BYTES: usize = 256;
const OWNER_PILOT_ATTEMPTS_PER_SLOT: u32 = 6;

/// Non-authorizing purpose supported by protocol schema 1.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ProfileEvaluationPurpose {
    OwnerPilot,
}

/// Presentation classes supported by protocol schema 1.
#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum EvaluationPresentation {
    GenuineLive,
    NoFace,
}

/// Expected detector decision for one protocol case.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ExpectedDetection {
    Present,
    Absent,
}

/// Expected recognition decision without an identity or score.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ExpectedRecognition {
    Match,
    NoMatch,
    NotApplicable,
}

/// Expected liveness decision without a model score.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ExpectedLiveness {
    Live,
    Spoof,
    NotApplicable,
}

/// Expected PAD decision for one modality.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ExpectedPad {
    Genuine,
    Spoof,
    NotApplicable,
}

/// Explicit expected model decisions for one protocol case.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ExpectedAuthOutcomes {
    detection: ExpectedDetection,
    recognition: ExpectedRecognition,
    liveness: ExpectedLiveness,
    rgb_pad: ExpectedPad,
    ir_pad: ExpectedPad,
}

impl ExpectedAuthOutcomes {
    #[must_use]
    pub const fn detection(&self) -> ExpectedDetection {
        self.detection
    }

    #[must_use]
    pub const fn recognition(&self) -> ExpectedRecognition {
        self.recognition
    }

    #[must_use]
    pub const fn liveness(&self) -> ExpectedLiveness {
        self.liveness
    }

    #[must_use]
    pub const fn rgb_pad(&self) -> ExpectedPad {
        self.rgb_pad
    }

    #[must_use]
    pub const fn ir_pad(&self) -> ExpectedPad {
        self.ir_pad
    }
}

/// Pseudonymous relationship between genuine probes and future reference assets.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct EvaluationReferenceSet {
    reference_set_id: String,
    participant_token: String,
}

impl EvaluationReferenceSet {
    #[must_use]
    pub fn reference_set_id(&self) -> &str {
        &self.reference_set_id
    }

    #[must_use]
    pub fn participant_token(&self) -> &str {
        &self.participant_token
    }

    fn validate(&self) -> Result<(), ProfileEvaluationError> {
        validate_id(&self.reference_set_id)?;
        validate_id(&self.participant_token)
    }
}

/// One ordered expected-outcome case in the signed protocol.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct EvaluationProtocolCase {
    case_id: String,
    scene: QualificationScene,
    attempt_index: u32,
    presentation: EvaluationPresentation,
    participant_token: Option<String>,
    reference_set_id: Option<String>,
    expected: ExpectedAuthOutcomes,
}

impl EvaluationProtocolCase {
    #[must_use]
    pub fn case_id(&self) -> &str {
        &self.case_id
    }

    #[must_use]
    pub const fn scene(&self) -> QualificationScene {
        self.scene
    }

    #[must_use]
    pub const fn attempt_index(&self) -> u32 {
        self.attempt_index
    }

    #[must_use]
    pub const fn presentation(&self) -> EvaluationPresentation {
        self.presentation
    }

    #[must_use]
    pub fn participant_token(&self) -> Option<&str> {
        self.participant_token.as_deref()
    }

    #[must_use]
    pub fn reference_set_id(&self) -> Option<&str> {
        self.reference_set_id.as_deref()
    }

    #[must_use]
    pub const fn expected(&self) -> &ExpectedAuthOutcomes {
        &self.expected
    }

    fn validate(&self) -> Result<(), ProfileEvaluationError> {
        validate_id(&self.case_id)?;
        if self.attempt_index == 0 || self.attempt_index > OWNER_PILOT_ATTEMPTS_PER_SLOT {
            return Err(ProfileEvaluationError::PilotMatrixMismatch);
        }
        match self.presentation {
            EvaluationPresentation::GenuineLive => {
                let (Some(participant), Some(reference)) =
                    (&self.participant_token, &self.reference_set_id)
                else {
                    return Err(ProfileEvaluationError::MissingReference);
                };
                validate_id(participant)?;
                validate_id(reference)?;
                if self.expected.detection != ExpectedDetection::Present
                    || self.expected.recognition != ExpectedRecognition::Match
                    || self.expected.liveness != ExpectedLiveness::Live
                    || self.expected.rgb_pad != ExpectedPad::Genuine
                    || self.expected.ir_pad != ExpectedPad::Genuine
                {
                    return Err(ProfileEvaluationError::InvalidOutcomeCombination);
                }
            }
            EvaluationPresentation::NoFace => {
                if self.participant_token.is_some()
                    || self.reference_set_id.is_some()
                    || self.expected.detection != ExpectedDetection::Absent
                    || self.expected.recognition != ExpectedRecognition::NotApplicable
                    || self.expected.liveness != ExpectedLiveness::NotApplicable
                    || self.expected.rgb_pad != ExpectedPad::NotApplicable
                    || self.expected.ir_pad != ExpectedPad::NotApplicable
                {
                    return Err(ProfileEvaluationError::InvalidOutcomeCombination);
                }
            }
        }
        Ok(())
    }
}

/// Signed, profile-independent owner-pilot protocol.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ProfileEvaluationProtocolManifest {
    schema_version: u32,
    protocol_id: String,
    purpose: ProfileEvaluationPurpose,
    acceptance_policy_version: u32,
    created_at_unix: u64,
    reference_sets: Vec<EvaluationReferenceSet>,
    cases: Vec<EvaluationProtocolCase>,
}

impl ProfileEvaluationProtocolManifest {
    /// Parses and validates one bounded protocol document.
    ///
    /// # Errors
    ///
    /// Returns an error for oversized, malformed, unsupported, or inconsistent input.
    pub fn from_json(bytes: &[u8]) -> Result<Self, ProfileEvaluationError> {
        validate_document_size(bytes.len())?;
        let value: Self = serde_json::from_slice(bytes)
            .map_err(|error| ProfileEvaluationError::Json(error.to_string()))?;
        value.validate()?;
        Ok(value)
    }

    /// Returns the compact canonical JSON bytes represented as a string.
    ///
    /// # Errors
    ///
    /// Returns an error when validation or serialization fails.
    pub fn to_canonical_json(&self) -> Result<String, ProfileEvaluationError> {
        self.validate()?;
        let body = serde_json::to_string(self)
            .map_err(|error| ProfileEvaluationError::Json(error.to_string()))?;
        validate_document_size(body.len())?;
        Ok(body)
    }

    /// Returns an indented derived view that carries no independent authority.
    ///
    /// # Errors
    ///
    /// Returns an error when validation or serialization fails.
    pub fn to_pretty_json(&self) -> Result<String, ProfileEvaluationError> {
        self.validate()?;
        let body = serde_json::to_string_pretty(self)
            .map_err(|error| ProfileEvaluationError::Json(error.to_string()))?;
        validate_document_size(body.len())?;
        Ok(body)
    }

    /// Returns SHA-256 over the validated canonical compact JSON.
    ///
    /// # Errors
    ///
    /// Returns an error when validation or canonical serialization fails.
    pub fn digest(&self) -> Result<String, ProfileEvaluationError> {
        Ok(irlume_common::sha256_hex(
            self.to_canonical_json()?.as_bytes(),
        ))
    }

    #[must_use]
    pub fn protocol_id(&self) -> &str {
        &self.protocol_id
    }

    #[must_use]
    pub const fn purpose(&self) -> ProfileEvaluationPurpose {
        self.purpose
    }

    #[must_use]
    pub const fn created_at_unix(&self) -> u64 {
        self.created_at_unix
    }

    #[must_use]
    pub fn reference_sets(&self) -> &[EvaluationReferenceSet] {
        &self.reference_sets
    }

    #[must_use]
    pub fn cases(&self) -> &[EvaluationProtocolCase] {
        &self.cases
    }

    fn validate(&self) -> Result<(), ProfileEvaluationError> {
        if self.schema_version != PROFILE_EVALUATION_PROTOCOL_SCHEMA_VERSION {
            return Err(ProfileEvaluationError::UnsupportedProtocolSchema(
                self.schema_version,
            ));
        }
        if self.acceptance_policy_version != PROFILE_EVALUATION_ACCEPTANCE_POLICY_VERSION {
            return Err(ProfileEvaluationError::UnsupportedAcceptancePolicy(
                self.acceptance_policy_version,
            ));
        }
        validate_id(&self.protocol_id)?;
        if self.reference_sets.is_empty()
            || self.reference_sets.len() > MAX_PROFILE_EVALUATION_REFERENCES
        {
            return Err(ProfileEvaluationError::ProtocolReferenceCount);
        }
        if self.cases.is_empty() || self.cases.len() > MAX_PROFILE_EVALUATION_CASES {
            return Err(ProfileEvaluationError::ProtocolCaseCount);
        }

        let mut reference_ids = BTreeSet::new();
        let mut participants = BTreeSet::new();
        let mut references_by_participant = BTreeMap::new();
        for reference in &self.reference_sets {
            reference.validate()?;
            if !reference_ids.insert(reference.reference_set_id.as_str())
                || !participants.insert(reference.participant_token.as_str())
            {
                return Err(ProfileEvaluationError::DuplicateId);
            }
            references_by_participant.insert(
                reference.participant_token.as_str(),
                reference.reference_set_id.as_str(),
            );
        }

        let mut case_ids = BTreeSet::new();
        let mut slots = BTreeSet::new();
        let mut used_participants = BTreeSet::new();
        for case in &self.cases {
            case.validate()?;
            if !case_ids.insert(case.case_id.as_str()) {
                return Err(ProfileEvaluationError::DuplicateId);
            }
            if !slots.insert((case.scene, case.presentation, case.attempt_index)) {
                return Err(ProfileEvaluationError::PilotMatrixMismatch);
            }
            if let (Some(participant), Some(reference)) =
                (case.participant_token(), case.reference_set_id())
            {
                if references_by_participant.get(participant).copied() != Some(reference) {
                    return Err(ProfileEvaluationError::MissingReference);
                }
                used_participants.insert(participant);
            }
        }

        if slots.len() != 48
            || used_participants != participants
            || [
                QualificationScene::Lit,
                QualificationScene::Backlit,
                QualificationScene::LowLight,
                QualificationScene::DarkIr,
            ]
            .into_iter()
            .flat_map(|scene| {
                [
                    EvaluationPresentation::GenuineLive,
                    EvaluationPresentation::NoFace,
                ]
                .into_iter()
                .map(move |presentation| (scene, presentation))
            })
            .any(|(scene, presentation)| {
                (1..=OWNER_PILOT_ATTEMPTS_PER_SLOT)
                    .any(|attempt| !slots.contains(&(scene, presentation, attempt)))
            })
        {
            return Err(ProfileEvaluationError::PilotMatrixMismatch);
        }
        Ok(())
    }
}

fn validate_id(value: &str) -> Result<(), ProfileEvaluationError> {
    if value.is_empty()
        || value.len() > MAX_PROFILE_EVALUATION_ID_BYTES
        || value.chars().any(char::is_control)
    {
        return Err(ProfileEvaluationError::InvalidId);
    }
    Ok(())
}

fn validate_document_size(size: usize) -> Result<(), ProfileEvaluationError> {
    if size > MAX_PROFILE_EVALUATION_DOCUMENT_BYTES {
        return Err(ProfileEvaluationError::DocumentTooLarge);
    }
    Ok(())
}

/// Why an evaluation control document cannot be trusted.
#[derive(Clone, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum ProfileEvaluationError {
    Json(String),
    UnsupportedProtocolSchema(u32),
    UnsupportedCaptureSchema(u32),
    UnsupportedConsentSchema(u32),
    UnsupportedAcceptancePolicy(u32),
    DocumentTooLarge,
    InvalidId,
    InvalidDigest,
    InvalidPath,
    DuplicateId,
    ProtocolCaseCount,
    ProtocolReferenceCount,
    PilotMatrixMismatch,
    InvalidOutcomeCombination,
    MissingReference,
    CaptureAssetCount,
    DuplicateAsset,
    InvalidAsset,
    InvalidCaptureProfile,
    CaptureCaseMismatch,
    CaptureReferenceMismatch,
    CaptureAuthorityMismatch,
    IdenticalComparisonProfile,
    ConsentChainInvalid,
    ConsentRetentionExceeded,
    ConsentWithdrawn,
    ConsentExpired,
    ConsentMissing,
    ConsentPurposeMismatch,
    ConsentPresentationMismatch,
}

impl std::fmt::Display for ProfileEvaluationError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let category = match self {
            Self::Json(_) => "invalid JSON",
            Self::UnsupportedProtocolSchema(_) => "unsupported protocol schema",
            Self::UnsupportedCaptureSchema(_) => "unsupported capture schema",
            Self::UnsupportedConsentSchema(_) => "unsupported consent schema",
            Self::UnsupportedAcceptancePolicy(_) => "unsupported acceptance policy",
            Self::DocumentTooLarge => "document too large",
            Self::InvalidId => "invalid identifier",
            Self::InvalidDigest => "invalid digest",
            Self::InvalidPath => "invalid path",
            Self::DuplicateId => "duplicate identifier",
            Self::ProtocolCaseCount => "invalid protocol case count",
            Self::ProtocolReferenceCount => "invalid protocol reference count",
            Self::PilotMatrixMismatch => "owner pilot matrix mismatch",
            Self::InvalidOutcomeCombination => "invalid expected outcome combination",
            Self::MissingReference => "missing reference relationship",
            Self::CaptureAssetCount => "invalid capture asset count",
            Self::DuplicateAsset => "duplicate capture asset",
            Self::InvalidAsset => "invalid capture asset",
            Self::InvalidCaptureProfile => "invalid capture profile",
            Self::CaptureCaseMismatch => "capture case mismatch",
            Self::CaptureReferenceMismatch => "capture reference mismatch",
            Self::CaptureAuthorityMismatch => "capture authority mismatch",
            Self::IdenticalComparisonProfile => "identical comparison profile",
            Self::ConsentChainInvalid => "invalid consent chain",
            Self::ConsentRetentionExceeded => "consent retention exceeded",
            Self::ConsentWithdrawn => "consent withdrawn",
            Self::ConsentExpired => "consent expired",
            Self::ConsentMissing => "consent missing",
            Self::ConsentPurposeMismatch => "consent purpose mismatch",
            Self::ConsentPresentationMismatch => "consent presentation mismatch",
        };
        write!(formatter, "profile evaluation failed: {category}")
    }
}

impl std::error::Error for ProfileEvaluationError {}

#[cfg(test)]
mod tests {
    use super::*;

    fn protocol_value() -> serde_json::Value {
        let mut cases = Vec::new();
        for scene in ["lit", "backlit", "low_light", "dark_ir"] {
            for attempt_index in 1..=6 {
                cases.push(serde_json::json!({
                    "case_id": format!("{scene}-genuine-{attempt_index:02}"),
                    "scene": scene,
                    "attempt_index": attempt_index,
                    "presentation": "genuine_live",
                    "participant_token": "participant-01",
                    "reference_set_id": "reference-01",
                    "expected": {
                        "detection": "present",
                        "recognition": "match",
                        "liveness": "live",
                        "rgb_pad": "genuine",
                        "ir_pad": "genuine"
                    }
                }));
                cases.push(serde_json::json!({
                    "case_id": format!("{scene}-no-face-{attempt_index:02}"),
                    "scene": scene,
                    "attempt_index": attempt_index,
                    "presentation": "no_face",
                    "participant_token": null,
                    "reference_set_id": null,
                    "expected": {
                        "detection": "absent",
                        "recognition": "not_applicable",
                        "liveness": "not_applicable",
                        "rgb_pad": "not_applicable",
                        "ir_pad": "not_applicable"
                    }
                }));
            }
        }
        serde_json::json!({
            "schema_version": 1,
            "protocol_id": "owner-pilot-v1",
            "purpose": "owner_pilot",
            "acceptance_policy_version": 1,
            "created_at_unix": 1_788_192_000_u64,
            "reference_sets": [{
                "reference_set_id": "reference-01",
                "participant_token": "participant-01"
            }],
            "cases": cases
        })
    }

    fn protocol_json() -> String {
        protocol_value().to_string()
    }

    #[test]
    fn owner_pilot_protocol_roundtrips_with_explicit_no_face_na() {
        let protocol = ProfileEvaluationProtocolManifest::from_json(protocol_json().as_bytes())
            .expect("valid protocol");
        assert_eq!(protocol.purpose(), ProfileEvaluationPurpose::OwnerPilot);
        assert_eq!(protocol.cases().len(), 48);
        let no_face = protocol
            .cases()
            .iter()
            .find(|case| case.presentation() == EvaluationPresentation::NoFace)
            .unwrap();
        assert_eq!(
            no_face.expected().recognition(),
            ExpectedRecognition::NotApplicable
        );
        assert_eq!(
            ProfileEvaluationProtocolManifest::from_json(
                protocol.to_canonical_json().unwrap().as_bytes()
            )
            .unwrap(),
            protocol,
        );
    }

    #[test]
    fn detection_absent_rejects_claimed_downstream_results() {
        let mut body = protocol_value();
        body["cases"][1]["expected"]["recognition"] = serde_json::json!("no_match");
        assert_eq!(
            ProfileEvaluationProtocolManifest::from_json(body.to_string().as_bytes()).unwrap_err(),
            ProfileEvaluationError::InvalidOutcomeCombination,
        );
    }

    #[test]
    fn schema_one_rejects_authorizing_purpose_and_spoof_presentations() {
        let mut purpose = protocol_value();
        purpose["purpose"] = serde_json::json!("authorizing_cohort");
        assert!(matches!(
            ProfileEvaluationProtocolManifest::from_json(purpose.to_string().as_bytes()),
            Err(ProfileEvaluationError::Json(_)),
        ));

        let mut presentation = protocol_value();
        presentation["cases"][0]["presentation"] = serde_json::json!("printed_photo");
        assert!(matches!(
            ProfileEvaluationProtocolManifest::from_json(presentation.to_string().as_bytes()),
            Err(ProfileEvaluationError::Json(_)),
        ));
    }

    #[test]
    fn protocol_rejects_versions_unknown_fields_and_invalid_ids() {
        let mut schema = protocol_value();
        schema["schema_version"] = serde_json::json!(2);
        assert_eq!(
            ProfileEvaluationProtocolManifest::from_json(schema.to_string().as_bytes())
                .unwrap_err(),
            ProfileEvaluationError::UnsupportedProtocolSchema(2),
        );

        let mut policy = protocol_value();
        policy["acceptance_policy_version"] = serde_json::json!(2);
        assert_eq!(
            ProfileEvaluationProtocolManifest::from_json(policy.to_string().as_bytes())
                .unwrap_err(),
            ProfileEvaluationError::UnsupportedAcceptancePolicy(2),
        );

        let mut unknown = protocol_value();
        unknown["unexpected"] = serde_json::json!(true);
        assert!(matches!(
            ProfileEvaluationProtocolManifest::from_json(unknown.to_string().as_bytes()),
            Err(ProfileEvaluationError::Json(_)),
        ));

        for invalid in [String::new(), "x".repeat(257), "bad\0id".into()] {
            let mut body = protocol_value();
            body["protocol_id"] = serde_json::json!(invalid);
            assert_eq!(
                ProfileEvaluationProtocolManifest::from_json(body.to_string().as_bytes())
                    .unwrap_err(),
                ProfileEvaluationError::InvalidId,
            );
        }
    }

    #[test]
    fn protocol_rejects_duplicate_ids_or_orphan_reference_relationships() {
        let mut duplicate = protocol_value();
        duplicate["cases"][1]["case_id"] = duplicate["cases"][0]["case_id"].clone();
        assert_eq!(
            ProfileEvaluationProtocolManifest::from_json(duplicate.to_string().as_bytes())
                .unwrap_err(),
            ProfileEvaluationError::DuplicateId,
        );

        let mut orphan = protocol_value();
        orphan["cases"][0]["reference_set_id"] = serde_json::json!("missing-reference");
        assert_eq!(
            ProfileEvaluationProtocolManifest::from_json(orphan.to_string().as_bytes())
                .unwrap_err(),
            ProfileEvaluationError::MissingReference,
        );
    }

    #[test]
    fn protocol_requires_exact_six_attempt_matrix_without_duplicate_slots() {
        let mut five = protocol_value();
        five["cases"].as_array_mut().unwrap().remove(0);
        assert_eq!(
            ProfileEvaluationProtocolManifest::from_json(five.to_string().as_bytes()).unwrap_err(),
            ProfileEvaluationError::PilotMatrixMismatch,
        );

        let mut seven = protocol_value();
        let mut extra = seven["cases"][0].clone();
        extra["case_id"] = serde_json::json!("lit-genuine-07");
        extra["attempt_index"] = serde_json::json!(7);
        seven["cases"].as_array_mut().unwrap().push(extra);
        assert_eq!(
            ProfileEvaluationProtocolManifest::from_json(seven.to_string().as_bytes()).unwrap_err(),
            ProfileEvaluationError::PilotMatrixMismatch,
        );

        let mut duplicate_slot = protocol_value();
        duplicate_slot["cases"][2]["attempt_index"] = serde_json::json!(1);
        assert_eq!(
            ProfileEvaluationProtocolManifest::from_json(duplicate_slot.to_string().as_bytes())
                .unwrap_err(),
            ProfileEvaluationError::PilotMatrixMismatch,
        );
    }

    #[test]
    fn protocol_canonical_digest_is_deterministic_and_bounded() {
        let protocol = ProfileEvaluationProtocolManifest::from_json(protocol_json().as_bytes())
            .expect("valid protocol");
        let canonical = protocol.to_canonical_json().unwrap();
        assert_eq!(
            protocol.digest().unwrap(),
            irlume_common::sha256_hex(canonical.as_bytes())
        );
        assert_eq!(
            ProfileEvaluationProtocolManifest::from_json(
                protocol.to_pretty_json().unwrap().as_bytes()
            )
            .unwrap()
            .to_canonical_json()
            .unwrap(),
            canonical,
        );
        assert_eq!(
            ProfileEvaluationProtocolManifest::from_json(&vec![
                b' ';
                MAX_PROFILE_EVALUATION_DOCUMENT_BYTES
                    + 1
            ])
            .unwrap_err(),
            ProfileEvaluationError::DocumentTooLarge,
        );
    }
}

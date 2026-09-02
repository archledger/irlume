// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright the irlume contributors.

//! Closed aggregate release-qualification artifacts.

#![allow(
    dead_code,
    reason = "the verifier and selection consumers are implemented in later plan tasks"
)]

use std::fmt;

use serde::{Deserialize, Serialize};

use crate::{
    capture_qualification::{CameraEndpoint, QualificationContext},
    contracts::StreamRole,
    frame_interval::FrameInterval,
    profile::{CaptureSchedule, DecodedPixelFormat, PairTransportProfile, StreamTuple},
};

pub(crate) const RELEASE_QUALIFICATION_SCHEMA_VERSION: u32 = 1;
pub(crate) const RELEASE_QUALIFICATION_POLICY_VERSION: u32 = 1;
pub(crate) const RELEASE_QUALIFICATION_PRODUCER_VERSION: u32 = 1;
pub(crate) const HARDWARE_SCOPE_MATCH_POLICY_VERSION: u32 = 1;
pub(crate) const MAX_RELEASE_QUALIFICATION_BYTES: usize = 256 * 1024;

const MAX_IDENTIFIER_BYTES: usize = 256;

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum AggregateDisposition {
    Passed,
    Failed,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct ReleaseGateDispositions {
    detection: AggregateDisposition,
    recognition: AggregateDisposition,
    liveness: AggregateDisposition,
    rgb_pad: AggregateDisposition,
    ir_pad: AggregateDisposition,
    latency: AggregateDisposition,
}

impl ReleaseGateDispositions {
    fn validate(&self) -> Result<(), ReleaseQualificationError> {
        if [
            self.detection,
            self.recognition,
            self.liveness,
            self.rgb_pad,
            self.ir_pad,
            self.latency,
        ]
        .into_iter()
        .all(|gate| gate == AggregateDisposition::Passed)
        {
            Ok(())
        } else {
            Err(ReleaseQualificationError::ReleaseGateFailed)
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum ReleasePixelFormat {
    Yuyv,
    Nv12,
    Grey8,
    Grey16,
}

impl ReleasePixelFormat {
    const fn to_domain(self) -> DecodedPixelFormat {
        match self {
            Self::Yuyv => DecodedPixelFormat::Yuyv,
            Self::Nv12 => DecodedPixelFormat::Nv12,
            Self::Grey8 => DecodedPixelFormat::Grey8,
            Self::Grey16 => DecodedPixelFormat::Grey16,
        }
    }

    const fn supports_role(self, role: StreamRole) -> bool {
        matches!(
            (self, role),
            (Self::Yuyv | Self::Nv12, StreamRole::Rgb)
                | (Self::Grey8 | Self::Grey16, StreamRole::Ir)
        )
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct ReleaseStreamTuple {
    format: ReleasePixelFormat,
    width: u32,
    height: u32,
    interval_numerator: u32,
    interval_denominator: u32,
}

impl ReleaseStreamTuple {
    fn to_domain(&self, role: StreamRole) -> Result<StreamTuple, ReleaseQualificationError> {
        if !self.format.supports_role(role) {
            return Err(ReleaseQualificationError::InvalidProfile);
        }
        let interval = FrameInterval::new(self.interval_numerator, self.interval_denominator)
            .map_err(|_| ReleaseQualificationError::InvalidProfile)?;
        if interval.parts() != (self.interval_numerator, self.interval_denominator) {
            return Err(ReleaseQualificationError::InvalidProfile);
        }
        StreamTuple::new(
            role,
            self.format.to_domain(),
            self.width,
            self.height,
            interval,
        )
        .map_err(|_| ReleaseQualificationError::InvalidProfile)
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct ReleaseProfileContract {
    profile_id: String,
    requested_rgb: ReleaseStreamTuple,
    accepted_rgb: ReleaseStreamTuple,
    requested_ir: ReleaseStreamTuple,
    accepted_ir: ReleaseStreamTuple,
    schedule: CaptureSchedule,
}

impl ReleaseProfileContract {
    pub(crate) fn id(&self) -> &str {
        &self.profile_id
    }

    pub(crate) fn to_profile(&self) -> Result<PairTransportProfile, ReleaseQualificationError> {
        validate_identifier(&self.profile_id)?;
        PairTransportProfile::from_negotiated(
            self.profile_id.clone(),
            self.requested_rgb.to_domain(StreamRole::Rgb)?,
            self.accepted_rgb.to_domain(StreamRole::Rgb)?,
            self.requested_ir.to_domain(StreamRole::Ir)?,
            self.accepted_ir.to_domain(StreamRole::Ir)?,
            self.schedule,
        )
        .map_err(|_| ReleaseQualificationError::InvalidProfile)
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct ReleaseEndpointScope {
    descriptor_sha256: String,
    vid: u16,
    pid: u16,
    interface_number: u8,
    driver: String,
    backend: String,
    speed_millimbps: u64,
}

impl ReleaseEndpointScope {
    fn validate(&self) -> Result<(), ReleaseQualificationError> {
        validate_digest(&self.descriptor_sha256)?;
        validate_identifier(&self.driver)?;
        validate_identifier(&self.backend)?;
        Ok(())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct ReleaseHardwareScope {
    match_policy_version: u32,
    interface_layout_sha256: String,
    rgb: ReleaseEndpointScope,
    ir: ReleaseEndpointScope,
}

impl ReleaseHardwareScope {
    fn validate(&self) -> Result<(), ReleaseQualificationError> {
        if self.match_policy_version != HARDWARE_SCOPE_MATCH_POLICY_VERSION {
            return Err(ReleaseQualificationError::UnsupportedHardwareMatchPolicy(
                self.match_policy_version,
            ));
        }
        validate_digest(&self.interface_layout_sha256)?;
        self.rgb.validate()?;
        self.ir.validate()?;
        Ok(())
    }

    pub(crate) fn matches_context(
        &self,
        context: &QualificationContext,
        interface_layout_sha256: &str,
    ) -> bool {
        self.match_policy_version == HARDWARE_SCOPE_MATCH_POLICY_VERSION
            && self.interface_layout_sha256 == interface_layout_sha256
            && self.rgb.matches_endpoint(context.rgb_endpoint())
            && self.ir.matches_endpoint(context.ir_endpoint())
    }
}

impl ReleaseEndpointScope {
    fn matches_endpoint(&self, endpoint: &CameraEndpoint) -> bool {
        self.descriptor_sha256 == endpoint.descriptor_sha256()
            && self.vid == endpoint.vid()
            && self.pid == endpoint.pid()
            && self.interface_number == endpoint.interface_number()
            && self.driver == endpoint.connection().driver()
            && self.backend == endpoint.connection().backend()
            && self.speed_millimbps == endpoint.connection().speed_millimbps()
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum ReleaseSignatureAlgorithm {
    OpenPgp,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct ReleaseSignatureMetadata {
    algorithm: ReleaseSignatureAlgorithm,
    signer_fingerprint: String,
}

impl ReleaseSignatureMetadata {
    fn validate(&self) -> Result<(), ReleaseQualificationError> {
        validate_signer_fingerprint(&self.signer_fingerprint)
    }

    pub(crate) fn signer_fingerprint(&self) -> &str {
        &self.signer_fingerprint
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct ReleaseQualificationArtifact {
    schema_version: u32,
    policy_version: u32,
    producer_version: u32,
    campaign_id: String,
    campaign_protocol_sha256: String,
    campaign_result_sha256: String,
    qualified_at_unix: u64,
    expires_at_unix: Option<u64>,
    hardware_scope: ReleaseHardwareScope,
    baseline: ReleaseProfileContract,
    candidate: ReleaseProfileContract,
    conditioning_catalog_sha256: String,
    selected_policy_sha256: String,
    preprocessing_contract_sha256: String,
    model_contract_sha256: String,
    gates: ReleaseGateDispositions,
    signature: ReleaseSignatureMetadata,
}

impl ReleaseQualificationArtifact {
    pub(crate) fn from_canonical_json(bytes: &[u8]) -> Result<Self, ReleaseQualificationError> {
        if bytes.len() > MAX_RELEASE_QUALIFICATION_BYTES {
            return Err(ReleaseQualificationError::DocumentTooLarge);
        }
        let artifact: Self =
            serde_json::from_slice(bytes).map_err(|_| ReleaseQualificationError::Json)?;
        artifact.validate()?;
        let canonical =
            serde_json::to_vec(&artifact).map_err(|_| ReleaseQualificationError::Json)?;
        if canonical != bytes {
            return Err(ReleaseQualificationError::Json);
        }
        Ok(artifact)
    }

    pub(crate) fn to_canonical_json(&self) -> Result<String, ReleaseQualificationError> {
        self.validate()?;
        let body = serde_json::to_string(self).map_err(|_| ReleaseQualificationError::Json)?;
        if body.len() > MAX_RELEASE_QUALIFICATION_BYTES {
            return Err(ReleaseQualificationError::DocumentTooLarge);
        }
        Ok(body)
    }

    pub(crate) fn validate_at(&self, now_unix: u64) -> Result<(), ReleaseQualificationError> {
        self.validate()?;
        if now_unix < self.qualified_at_unix {
            return Err(ReleaseQualificationError::ArtifactNotYetValid);
        }
        if self
            .expires_at_unix
            .is_some_and(|expires_at| now_unix >= expires_at)
        {
            return Err(ReleaseQualificationError::ArtifactExpired);
        }
        Ok(())
    }

    fn validate(&self) -> Result<(), ReleaseQualificationError> {
        if self.schema_version != RELEASE_QUALIFICATION_SCHEMA_VERSION {
            return Err(ReleaseQualificationError::UnsupportedSchema(
                self.schema_version,
            ));
        }
        if self.policy_version != RELEASE_QUALIFICATION_POLICY_VERSION {
            return Err(ReleaseQualificationError::UnsupportedPolicy(
                self.policy_version,
            ));
        }
        if self.producer_version != RELEASE_QUALIFICATION_PRODUCER_VERSION {
            return Err(ReleaseQualificationError::UnsupportedProducer(
                self.producer_version,
            ));
        }
        validate_identifier(&self.campaign_id)?;
        validate_digest(&self.campaign_protocol_sha256)?;
        validate_digest(&self.campaign_result_sha256)?;
        if self.qualified_at_unix == 0
            || self
                .expires_at_unix
                .is_some_and(|expires_at| expires_at <= self.qualified_at_unix)
        {
            return Err(ReleaseQualificationError::InvalidTime);
        }
        self.hardware_scope.validate()?;
        self.baseline.to_profile()?;
        self.candidate.to_profile()?;
        if self.baseline == self.candidate {
            return Err(ReleaseQualificationError::IdenticalProfiles);
        }
        for digest in [
            &self.conditioning_catalog_sha256,
            &self.selected_policy_sha256,
            &self.preprocessing_contract_sha256,
            &self.model_contract_sha256,
        ] {
            validate_digest(digest)?;
        }
        self.gates.validate()?;
        self.signature.validate()
    }

    pub(crate) fn baseline_profile(&self) -> &ReleaseProfileContract {
        &self.baseline
    }

    pub(crate) fn candidate_profile(&self) -> &ReleaseProfileContract {
        &self.candidate
    }

    pub(crate) fn baseline_profile_sha256(&self) -> Result<String, ReleaseQualificationError> {
        let bytes =
            serde_json::to_vec(&self.baseline).map_err(|_| ReleaseQualificationError::Json)?;
        Ok(irlume_common::sha256_hex(&bytes))
    }

    pub(crate) fn candidate_profile_sha256(&self) -> Result<String, ReleaseQualificationError> {
        let bytes =
            serde_json::to_vec(&self.candidate).map_err(|_| ReleaseQualificationError::Json)?;
        Ok(irlume_common::sha256_hex(&bytes))
    }

    pub(crate) const fn hardware_scope(&self) -> &ReleaseHardwareScope {
        &self.hardware_scope
    }

    pub(crate) const fn signature(&self) -> &ReleaseSignatureMetadata {
        &self.signature
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) enum ReleaseQualificationError {
    Json,
    DocumentTooLarge,
    UnsupportedSchema(u32),
    UnsupportedPolicy(u32),
    UnsupportedProducer(u32),
    UnsupportedHardwareMatchPolicy(u32),
    InvalidIdentifier,
    InvalidDigest,
    InvalidSignerFingerprint,
    InvalidProfile,
    IdenticalProfiles,
    InvalidTime,
    ReleaseGateFailed,
    ArtifactNotYetValid,
    ArtifactExpired,
}

impl fmt::Display for ReleaseQualificationError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let category = match self {
            Self::Json => "release_qualification_json_invalid",
            Self::DocumentTooLarge => "release_qualification_too_large",
            Self::UnsupportedSchema(_) => "release_qualification_schema_unsupported",
            Self::UnsupportedPolicy(_) => "release_qualification_policy_unsupported",
            Self::UnsupportedProducer(_) => "release_qualification_producer_unsupported",
            Self::UnsupportedHardwareMatchPolicy(_) => "hardware_match_policy_unsupported",
            Self::InvalidIdentifier => "release_qualification_identifier_invalid",
            Self::InvalidDigest => "release_qualification_digest_invalid",
            Self::InvalidSignerFingerprint => "release_qualification_signer_invalid",
            Self::InvalidProfile => "release_qualification_profile_invalid",
            Self::IdenticalProfiles => "release_qualification_profiles_identical",
            Self::InvalidTime => "release_qualification_time_invalid",
            Self::ReleaseGateFailed => "release_qualification_gate_failed",
            Self::ArtifactNotYetValid => "release_qualification_not_yet_valid",
            Self::ArtifactExpired => "release_qualification_expired",
        };
        formatter.write_str(category)
    }
}

impl std::error::Error for ReleaseQualificationError {}

fn validate_identifier(value: &str) -> Result<(), ReleaseQualificationError> {
    if value.is_empty() || value.len() > MAX_IDENTIFIER_BYTES || value.chars().any(char::is_control)
    {
        return Err(ReleaseQualificationError::InvalidIdentifier);
    }
    Ok(())
}

fn validate_digest(value: &str) -> Result<(), ReleaseQualificationError> {
    if value.len() != 64
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err(ReleaseQualificationError::InvalidDigest);
    }
    Ok(())
}

fn validate_signer_fingerprint(value: &str) -> Result<(), ReleaseQualificationError> {
    if value.len() != 40
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'A'..=b'F').contains(&byte))
    {
        return Err(ReleaseQualificationError::InvalidSignerFingerprint);
    }
    Ok(())
}

#[cfg(test)]
pub(crate) fn fixture_artifact_value(baseline_id: &str, candidate_id: &str) -> serde_json::Value {
    let stream = |format: &str, height: u32, fps: u32| {
        serde_json::json!({
            "format": format,
            "width": 640,
            "height": height,
            "interval_numerator": 1,
            "interval_denominator": fps,
        })
    };
    let endpoint = |interface_number: u8| {
        serde_json::json!({
            "descriptor_sha256": "ab".repeat(32),
            "vid": 0x0bda,
            "pid": 0x5678,
            "interface_number": interface_number,
            "driver": "uvcvideo",
            "backend": "v4l2-uvc",
            "speed_millimbps": 5_000_000_u64,
        })
    };
    let profile = |id: &str, rgb_fps: u32| {
        serde_json::json!({
            "profile_id": id,
            "requested_rgb": stream("yuyv", 480, rgb_fps),
            "accepted_rgb": stream("yuyv", 480, rgb_fps),
            "requested_ir": stream("grey8", 400, 15),
            "accepted_ir": stream("grey8", 400, 15),
            "schedule": "concurrent",
        })
    };
    serde_json::json!({
        "schema_version": 1,
        "policy_version": 1,
        "producer_version": 1,
        "campaign_id": "campaign-1",
        "campaign_protocol_sha256": "11".repeat(32),
        "campaign_result_sha256": "22".repeat(32),
        "qualified_at_unix": 1_788_192_000_u64,
        "expires_at_unix": 1_788_278_400_u64,
        "hardware_scope": {
            "match_policy_version": 1,
            "interface_layout_sha256": "33".repeat(32),
            "rgb": endpoint(0),
            "ir": endpoint(2),
        },
        "baseline": profile(baseline_id, 30),
        "candidate": profile(candidate_id, 15),
        "conditioning_catalog_sha256": "44".repeat(32),
        "selected_policy_sha256": "55".repeat(32),
        "preprocessing_contract_sha256": "66".repeat(32),
        "model_contract_sha256": "77".repeat(32),
        "gates": {
            "detection": "passed",
            "recognition": "passed",
            "liveness": "passed",
            "rgb_pad": "passed",
            "ir_pad": "passed",
            "latency": "passed",
        },
        "signature": {
            "algorithm": "open_pgp",
            "signer_fingerprint": "F35053398E3C80FE20891B82C10B8492BD7F30C6",
        },
    })
}

#[cfg(test)]
pub(crate) fn fixture_json(baseline_id: &str, candidate_id: &str) -> Vec<u8> {
    let artifact: ReleaseQualificationArtifact =
        serde_json::from_value(fixture_artifact_value(baseline_id, candidate_id)).unwrap();
    artifact.validate().unwrap();
    serde_json::to_vec(&artifact).unwrap()
}

#[cfg(test)]
pub(crate) fn fixture_canonical_artifact() -> Vec<u8> {
    fixture_json("baseline-30-15", "candidate-15-15")
}

#[cfg(test)]
pub(crate) fn fixture_release_scope() -> ReleaseHardwareScope {
    ReleaseQualificationArtifact::from_canonical_json(&fixture_canonical_artifact())
        .unwrap()
        .hardware_scope
}

#[cfg(test)]
mod tests {
    use super::*;

    const FIXED_NOW: u64 = 1_788_192_050;
    type AuthorityMutation = (&'static str, fn(&mut serde_json::Value));

    fn parse_mutated(
        field: &str,
        value: serde_json::Value,
    ) -> Result<ReleaseQualificationArtifact, ReleaseQualificationError> {
        let mut artifact = fixture_artifact_value("baseline-30-15", "candidate-15-15");
        artifact[field] = value;
        ReleaseQualificationArtifact::from_canonical_json(
            serde_json::to_vec(&artifact).unwrap().as_slice(),
        )
    }

    fn parse_nested_mutated(
        parent: &str,
        field: &str,
        value: serde_json::Value,
    ) -> Result<ReleaseQualificationArtifact, ReleaseQualificationError> {
        let mut artifact = fixture_artifact_value("baseline-30-15", "candidate-15-15");
        artifact[parent][field] = value;
        ReleaseQualificationArtifact::from_canonical_json(
            serde_json::to_vec(&artifact).unwrap().as_slice(),
        )
    }

    fn parse_profile_mutated(
        profile: &str,
        tuple: &str,
        field: &str,
        value: serde_json::Value,
    ) -> Result<ReleaseQualificationArtifact, ReleaseQualificationError> {
        let mut artifact = fixture_artifact_value("baseline-30-15", "candidate-15-15");
        artifact[profile][tuple][field] = value;
        ReleaseQualificationArtifact::from_canonical_json(
            serde_json::to_vec(&artifact).unwrap().as_slice(),
        )
    }

    fn canonical_bytes_from_value(value: serde_json::Value) -> Vec<u8> {
        let artifact: ReleaseQualificationArtifact = serde_json::from_value(value).unwrap();
        artifact.validate().unwrap();
        serde_json::to_vec(&artifact).unwrap()
    }

    #[test]
    fn artifact_round_trips_canonically_and_binds_baseline_and_candidate() {
        let bytes = fixture_json("baseline-30-15", "candidate-15-15");
        let artifact = ReleaseQualificationArtifact::from_canonical_json(&bytes).unwrap();
        assert_eq!(
            artifact.to_canonical_json().unwrap().as_bytes(),
            bytes.as_slice()
        );
        assert_eq!(artifact.baseline_profile().id(), "baseline-30-15");
        assert_eq!(artifact.candidate_profile().id(), "candidate-15-15");
        assert_ne!(artifact.baseline_profile(), artifact.candidate_profile());
        let baseline = artifact.baseline_profile().to_profile().unwrap();
        let candidate = artifact.candidate_profile().to_profile().unwrap();
        assert_eq!(baseline.requested_rgb().interval().parts(), (1, 30));
        assert_eq!(baseline.accepted_rgb().interval().parts(), (1, 30));
        assert_eq!(baseline.requested_ir().interval().parts(), (1, 15));
        assert_eq!(baseline.accepted_ir().interval().parts(), (1, 15));
        assert_eq!(candidate.requested_rgb().interval().parts(), (1, 15));
        assert_eq!(candidate.accepted_rgb().interval().parts(), (1, 15));
        assert_eq!(candidate.requested_ir().interval().parts(), (1, 15));
        assert_eq!(candidate.accepted_ir().interval().parts(), (1, 15));
        assert_eq!(baseline.schedule(), CaptureSchedule::Concurrent);
        assert_eq!(candidate.schedule(), CaptureSchedule::Concurrent);
    }

    #[test]
    fn artifact_rejects_unknown_fields_versions_and_failed_gates() {
        assert_eq!(
            parse_mutated("unknown_authority", serde_json::json!(true)),
            Err(ReleaseQualificationError::Json),
        );
        assert_eq!(
            parse_mutated("schema_version", serde_json::json!(99)),
            Err(ReleaseQualificationError::UnsupportedSchema(99)),
        );
        assert_eq!(
            parse_nested_mutated("gates", "rgb_pad", serde_json::json!("failed")),
            Err(ReleaseQualificationError::ReleaseGateFailed),
        );
    }

    #[test]
    fn serialized_artifact_contains_only_approved_aggregate_fields() {
        let body = String::from_utf8(fixture_json("baseline", "candidate")).unwrap();
        for forbidden in [
            "identity",
            "participant",
            "template",
            "embedding",
            "score",
            "consent",
            "relative_path",
            "serial",
            "image",
            "tensor",
        ] {
            assert!(!body.contains(forbidden), "forbidden field {forbidden}");
        }
    }

    #[test]
    fn artifact_rejects_oversized_documents_and_identifiers() {
        assert_eq!(
            ReleaseQualificationArtifact::from_canonical_json(&vec![b' '; 256 * 1024 + 1]),
            Err(ReleaseQualificationError::DocumentTooLarge),
        );
        assert_eq!(
            parse_mutated("campaign_id", serde_json::json!("x".repeat(257))),
            Err(ReleaseQualificationError::InvalidIdentifier),
        );
        assert_eq!(
            parse_nested_mutated("candidate", "profile_id", serde_json::json!("")),
            Err(ReleaseQualificationError::InvalidIdentifier),
        );
    }

    #[test]
    fn artifact_rejects_invalid_digests_and_signature_metadata() {
        assert_eq!(
            parse_mutated("model_contract_sha256", serde_json::json!("AA".repeat(32))),
            Err(ReleaseQualificationError::InvalidDigest),
        );
        assert_eq!(
            parse_nested_mutated(
                "signature",
                "signer_fingerprint",
                serde_json::json!("BD7F30C6")
            ),
            Err(ReleaseQualificationError::InvalidSignerFingerprint),
        );
    }

    #[test]
    fn artifact_rejects_zero_and_unsupported_versions() {
        for (field, value, expected) in [
            (
                "schema_version",
                0,
                ReleaseQualificationError::UnsupportedSchema(0),
            ),
            (
                "policy_version",
                0,
                ReleaseQualificationError::UnsupportedPolicy(0),
            ),
            (
                "producer_version",
                0,
                ReleaseQualificationError::UnsupportedProducer(0),
            ),
        ] {
            assert_eq!(
                parse_mutated(field, serde_json::json!(value)),
                Err(expected)
            );
        }
        assert_eq!(
            parse_nested_mutated(
                "hardware_scope",
                "match_policy_version",
                serde_json::json!(99)
            ),
            Err(ReleaseQualificationError::UnsupportedHardwareMatchPolicy(
                99
            )),
        );
    }

    #[test]
    fn artifact_rejects_identical_profiles_and_untrusted_stream_shapes() {
        let mut artifact = fixture_artifact_value("baseline-30-15", "candidate-15-15");
        artifact["candidate"] = artifact["baseline"].clone();
        assert_eq!(
            ReleaseQualificationArtifact::from_canonical_json(
                serde_json::to_vec(&artifact).unwrap().as_slice(),
            ),
            Err(ReleaseQualificationError::IdenticalProfiles),
        );
        assert_eq!(
            parse_profile_mutated(
                "candidate",
                "requested_rgb",
                "role",
                serde_json::json!("ir")
            ),
            Err(ReleaseQualificationError::Json),
        );
        assert_eq!(
            parse_profile_mutated(
                "candidate",
                "requested_rgb",
                "format",
                serde_json::json!("mjpeg"),
            ),
            Err(ReleaseQualificationError::Json),
        );
    }

    #[test]
    fn artifact_rejects_pixel_formats_on_the_wrong_stream_role() {
        assert_eq!(
            parse_profile_mutated(
                "candidate",
                "requested_rgb",
                "format",
                serde_json::json!("grey8"),
            ),
            Err(ReleaseQualificationError::InvalidProfile),
        );
        assert_eq!(
            parse_profile_mutated(
                "candidate",
                "requested_ir",
                "format",
                serde_json::json!("yuyv"),
            ),
            Err(ReleaseQualificationError::InvalidProfile),
        );
    }

    #[test]
    fn artifact_rejects_zero_or_non_reduced_intervals() {
        assert_eq!(
            parse_profile_mutated(
                "candidate",
                "accepted_rgb",
                "interval_numerator",
                serde_json::json!(0),
            ),
            Err(ReleaseQualificationError::InvalidProfile),
        );
        let mut non_reduced = fixture_artifact_value("baseline-30-15", "candidate-15-15");
        non_reduced["candidate"]["accepted_rgb"]["interval_numerator"] = serde_json::json!(2);
        non_reduced["candidate"]["accepted_rgb"]["interval_denominator"] = serde_json::json!(30);
        assert_eq!(
            ReleaseQualificationArtifact::from_canonical_json(
                serde_json::to_vec(&non_reduced).unwrap().as_slice(),
            ),
            Err(ReleaseQualificationError::InvalidProfile),
        );
    }

    #[test]
    fn artifact_rejects_invalid_time_and_enforces_freshness() {
        assert_eq!(
            parse_mutated("qualified_at_unix", serde_json::json!(0)),
            Err(ReleaseQualificationError::InvalidTime),
        );
        assert_eq!(
            parse_mutated("expires_at_unix", serde_json::json!(1_788_192_000_u64)),
            Err(ReleaseQualificationError::InvalidTime),
        );
        let artifact =
            ReleaseQualificationArtifact::from_canonical_json(&fixture_canonical_artifact())
                .unwrap();
        assert_eq!(
            artifact.validate_at(1_788_191_999),
            Err(ReleaseQualificationError::ArtifactNotYetValid),
        );
        assert_eq!(artifact.validate_at(FIXED_NOW), Ok(()));
        assert_eq!(
            artifact.validate_at(1_788_278_400),
            Err(ReleaseQualificationError::ArtifactExpired),
        );
    }

    #[test]
    fn artifact_rejects_pretty_or_reordered_json() {
        let value = fixture_artifact_value("baseline-30-15", "candidate-15-15");
        assert_eq!(
            ReleaseQualificationArtifact::from_canonical_json(
                serde_json::to_string_pretty(&value).unwrap().as_bytes(),
            ),
            Err(ReleaseQualificationError::Json),
        );
        let reordered = serde_json::to_vec(&value).unwrap();
        assert_ne!(reordered, fixture_canonical_artifact());
        assert_eq!(
            ReleaseQualificationArtifact::from_canonical_json(&reordered),
            Err(ReleaseQualificationError::Json),
        );
    }

    #[test]
    fn changing_each_authority_binding_changes_canonical_digest() {
        let original = fixture_canonical_artifact();
        let original_digest = irlume_common::sha256_hex(&original);
        let mutations: [AuthorityMutation; 13] = [
            ("campaign id", |v| {
                v["campaign_id"] = serde_json::json!("campaign-2")
            }),
            ("campaign protocol", |v| {
                v["campaign_protocol_sha256"] = serde_json::json!("10".repeat(32))
            }),
            ("campaign result", |v| {
                v["campaign_result_sha256"] = serde_json::json!("20".repeat(32))
            }),
            ("qualification time", |v| {
                v["qualified_at_unix"] = serde_json::json!(1_788_192_001_u64)
            }),
            ("expiry", |v| {
                v["expires_at_unix"] = serde_json::json!(1_788_278_401_u64)
            }),
            ("hardware layout", |v| {
                v["hardware_scope"]["interface_layout_sha256"] = serde_json::json!("30".repeat(32))
            }),
            ("baseline", |v| {
                v["baseline"]["profile_id"] = serde_json::json!("baseline-other")
            }),
            ("candidate", |v| {
                v["candidate"]["profile_id"] = serde_json::json!("candidate-other")
            }),
            ("conditioning", |v| {
                v["conditioning_catalog_sha256"] = serde_json::json!("40".repeat(32))
            }),
            ("selected policy", |v| {
                v["selected_policy_sha256"] = serde_json::json!("50".repeat(32))
            }),
            ("preprocessing", |v| {
                v["preprocessing_contract_sha256"] = serde_json::json!("60".repeat(32))
            }),
            ("model", |v| {
                v["model_contract_sha256"] = serde_json::json!("70".repeat(32))
            }),
            ("signer", |v| {
                v["signature"]["signer_fingerprint"] =
                    serde_json::json!("A35053398E3C80FE20891B82C10B8492BD7F30C6")
            }),
        ];
        for (name, mutate) in mutations {
            let mut value = fixture_artifact_value("baseline-30-15", "candidate-15-15");
            mutate(&mut value);
            let bytes = canonical_bytes_from_value(value);
            assert_ne!(irlume_common::sha256_hex(&bytes), original_digest, "{name}");
        }
    }

    #[test]
    fn nested_profile_digests_bind_only_their_exact_contract() {
        let original =
            ReleaseQualificationArtifact::from_canonical_json(&fixture_canonical_artifact())
                .unwrap();
        let original_baseline = original.baseline_profile_sha256().unwrap();
        let original_candidate = original.candidate_profile_sha256().unwrap();
        assert_ne!(original_baseline, original_candidate);

        let mut changed_value = fixture_artifact_value("baseline-30-15", "candidate-15-15");
        changed_value["baseline"]["profile_id"] = serde_json::json!("baseline-other");
        let changed = ReleaseQualificationArtifact::from_canonical_json(
            &canonical_bytes_from_value(changed_value),
        )
        .unwrap();
        assert_ne!(
            changed.baseline_profile_sha256().unwrap(),
            original_baseline
        );
        assert_eq!(
            changed.candidate_profile_sha256().unwrap(),
            original_candidate
        );
    }
}

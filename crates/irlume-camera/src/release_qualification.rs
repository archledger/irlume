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

    pub(crate) const fn match_policy_version(&self) -> u32 {
        self.match_policy_version
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

    pub(crate) const fn policy_version(&self) -> u32 {
        self.policy_version
    }

    pub(crate) const fn producer_version(&self) -> u32 {
        self.producer_version
    }

    pub(crate) fn campaign_id(&self) -> &str {
        &self.campaign_id
    }

    pub(crate) fn campaign_protocol_sha256(&self) -> &str {
        &self.campaign_protocol_sha256
    }

    pub(crate) fn campaign_result_sha256(&self) -> &str {
        &self.campaign_result_sha256
    }

    pub(crate) fn conditioning_catalog_sha256(&self) -> &str {
        &self.conditioning_catalog_sha256
    }

    pub(crate) fn selected_policy_sha256(&self) -> &str {
        &self.selected_policy_sha256
    }

    pub(crate) fn preprocessing_contract_sha256(&self) -> &str {
        &self.preprocessing_contract_sha256
    }

    pub(crate) fn model_contract_sha256(&self) -> &str {
        &self.model_contract_sha256
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
    use irlume_qualification as qualification;
    use qualification::{CanonicalDocument, DetachedSignatureVerifier};
    use serde_json::{json, Value};

    const FIXED_NOW: u64 = 1_788_192_050;
    type AuthorityMutation = (&'static str, fn(&mut serde_json::Value));

    const POLICY_AUTHOR: &str = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";
    const OPERATOR: &str = "BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB";
    const EVALUATOR: &str = "CCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCC";
    const REVIEWER: &str = "DDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDD";
    const RELEASE_SIGNER: &str = "EEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEE";

    struct FakeVerifier(&'static str);

    impl DetachedSignatureVerifier for FakeVerifier {
        fn verify(
            &self,
            _canonical_payload: &[u8],
            _detached_signature: &[u8],
        ) -> Result<qualification::SignerFingerprint, qualification::CampaignError> {
            qualification::SignerFingerprint::new(self.0)
        }
    }

    fn qdigest(byte: &str) -> Value {
        json!(byte.repeat(64))
    }

    fn verify_q<T: CanonicalDocument>(
        value: &Value,
        role: qualification::SignerRole,
        signer: &'static str,
    ) -> qualification::Verified<T> {
        let expected = signer;
        let signer = qualification::SignerFingerprint::new(expected).unwrap();
        qualification::verify_document(
            &serde_json::to_vec(value).unwrap(),
            b"synthetic-signature",
            role,
            &signer,
            &FakeVerifier(expected),
        )
        .unwrap()
    }

    fn verify_q_document<T: CanonicalDocument>(
        document: &T,
        role: qualification::SignerRole,
        expected: &'static str,
    ) -> qualification::Verified<T> {
        let signer = qualification::SignerFingerprint::new(expected).unwrap();
        qualification::verify_document(
            &document.to_canonical_json().unwrap(),
            b"synthetic-signature",
            role,
            &signer,
            &FakeVerifier(expected),
        )
        .unwrap()
    }

    fn campaign_policy_value() -> Value {
        json!({
            "allowed_equipment_repeats": 2,
            "binary_gates": ["detection", "ir_pad", "liveness", "recognition", "rgb_pad"],
            "demographic_axes": [
                {"axis": "age", "categories": ["adult", "older_adult"], "minimum_cases": 40},
                {"axis": "gender", "categories": ["female", "male", "nonbinary"], "minimum_cases": 40},
                {"axis": "skin_tone", "categories": ["dark", "light", "medium"], "minimum_cases": 40}
            ],
            "excluded_pai_species": ["active_ir", "three_dimensional_mask"],
            "expiry_rules": {"artifact_seconds": 31536000, "bundle_seconds": 2592000, "protocol_seconds": 2592000, "result_seconds": 2592000, "review_seconds": 604800},
            "latency_bootstrap_resamples": 10000,
            "latency_budget_fraction_ppb": 50000000,
            "latency_method": "cluster_bootstrap_latency_v1",
            "minimum_public_cell_size": 20,
            "missingness_rule": "count_as_incorrect",
            "noninferiority_method": "paired_mover_wilson_v1",
            "one_sided_alpha_ppb": 50000000,
            "operational_axes": [
                {"axis": "eyewear", "categories": ["absent", "present"], "minimum_cases": 40},
                {"axis": "lighting", "categories": ["dim", "ordinary"], "minimum_cases": 40},
                {"axis": "range", "categories": ["near", "ordinary"], "minimum_cases": 40}
            ],
            "overall_margin_ppb": -20000000,
            "paired_crossover": true,
            "permitted_hardware_classes": ["usb-rgb-ir-v1"],
            "policy_id": "maintainer-camera-profile-v1",
            "policy_version": 1,
            "power_method": "paired_power_normal_v1",
            "presentation_classes": ["bona_fide", "display_replay", "no_face", "non_mated_live_cross_identity", "print"],
            "private_asset_retention_seconds": 31536000,
            "required_pai_species": ["display_replay", "print"],
            "required_power_ppb": 800000000,
            "role_separation_required": true,
            "schema_version": 1,
            "security_bound_method": "clopper_pearson_upper_v1",
            "signature": {"algorithm": "open_pgp", "role": "policy_author", "signer_fingerprint": POLICY_AUTHOR},
            "stopping_rule": "locked_sample_no_optional_stopping",
            "stratum_margin_ppb": -50000000,
            "target_population": "consenting-adults-in-declared-operating-range",
            "withdrawal_rule": "invalidate_before_publication_delete_after_publication"
        })
    }

    fn qstream(role: &str, format: &str, denominator: u32) -> Value {
        json!({"format": format, "height": if role == "rgb" { 480 } else { 400 }, "interval_denominator": denominator, "interval_numerator": 1, "role": role, "width": 640})
    }

    fn qcontracts() -> Value {
        json!({
            "conditioning_catalog_sha256": qdigest("1"), "model_contract_sha256": qdigest("2"),
            "preprocessing_contract_sha256": qdigest("3"), "producer_contract_sha256": qdigest("4"),
            "selected_policy_sha256": qdigest("5"), "software_contract_sha256": qdigest("6"),
            "threshold_contract_sha256": qdigest("7")
        })
    }

    fn qprofile(id: &str, denominator: u32) -> Value {
        json!({
            "accepted_ir": qstream("ir", "grey8", 15), "accepted_rgb": qstream("rgb", "yuyv", denominator),
            "contracts": qcontracts(), "profile_id": id, "requested_ir": qstream("ir", "grey8", 15),
            "requested_rgb": qstream("rgb", "yuyv", denominator), "schedule": "concurrent"
        })
    }

    fn campaign_protocol_value(policy_bytes: &[u8]) -> Value {
        let policy = campaign_policy_value();
        let mut strata = Vec::new();
        for field in ["demographic_axes", "operational_axes"] {
            for axis in policy[field].as_array().unwrap() {
                for category in axis["categories"].as_array().unwrap() {
                    let axis_name = axis["axis"].as_str().unwrap();
                    let category_name = category.as_str().unwrap();
                    strata.push(json!({"axis": axis_name, "category": category_name, "minimum_cases": axis["minimum_cases"], "stratum_id": format!("{axis_name}-{category_name}")}));
                }
            }
        }
        strata.sort_by(|a, b| a["stratum_id"].as_str().cmp(&b["stratum_id"].as_str()));
        let mut cells: Vec<_> = strata
            .iter()
            .map(|s| (s, "bona_fide", None, "accept"))
            .collect();
        cells.extend([
            (
                &strata[0],
                "display_replay",
                Some("display_replay"),
                "reject",
            ),
            (&strata[1], "no_face", None, "reject"),
            (&strata[2], "non_mated_live_cross_identity", None, "reject"),
            (&strata[3], "print", Some("print"), "reject"),
        ]);
        let mut cases = Vec::new();
        for (index, (stratum, presentation, pai, expected)) in cells.into_iter().enumerate() {
            let relation = match presentation {
                "bona_fide" => "mated",
                "non_mated_live_cross_identity" => "non_mated",
                "no_face" => "no_reference",
                _ => "pai_instrument",
            };
            let logical = format!("logical-{index:02}");
            for (side, position) in if index % 2 == 0 {
                [("baseline", "first"), ("candidate", "second")]
            } else {
                [("baseline", "second"), ("candidate", "first")]
            } {
                cases.push(json!({
                    "case_id": format!("{logical}-{side}"), "collection_block": format!("block-{index:02}"), "expected_outcome": expected,
                    "logical_case_id": logical, "order_position": position, "pai_instrument_id": pai.map(|_| format!("instrument-{index:02}")),
                    "pai_production_method": pai.map(|_| "protocol-declared-2d-production"), "pai_species": pai, "planned_count": 99,
                    "presentation_class": presentation, "profile_side": side, "reference_relation": relation, "scene_id": "ordinary-frontal", "stratum_id": stratum["stratum_id"]
                }));
            }
        }
        cases.sort_by(|a, b| a["case_id"].as_str().cmp(&b["case_id"].as_str()));
        let mut pilot = Vec::new();
        let mut samples = Vec::new();
        for gate in ["detection", "ir_pad", "liveness", "recognition", "rgb_pad"] {
            pilot.push(json!({"baseline_only_success_ppb": 20000000, "candidate_only_success_ppb": 20000000, "gate": gate, "stratum_id": null}));
            samples.push(json!({"gate": gate, "margin_ppb": -20000000, "planned_power_ppb": 800000000, "required_cases": 619, "stopping_rule": "locked_sample_no_optional_stopping", "stratum_id": null}));
            for stratum in &strata {
                pilot.push(json!({"baseline_only_success_ppb": 20000000, "candidate_only_success_ppb": 20000000, "gate": gate, "stratum_id": stratum["stratum_id"]}));
                samples.push(json!({"gate": gate, "margin_ppb": -50000000, "planned_power_ppb": 800000000, "required_cases": 99, "stopping_rule": "locked_sample_no_optional_stopping", "stratum_id": stratum["stratum_id"]}));
            }
        }
        json!({
            "balanced_order_seed": qdigest("8"), "baseline": qprofile("baseline-30fps", 30), "campaign_id": "campaign-2026-09-02-a",
            "candidate": qprofile("candidate-15fps", 15), "cases": cases, "collection_not_after_unix": 1788998400u64,
            "collection_not_before_unix": 1788393600u64, "contracts": qcontracts(), "created_at_unix": 1788307200u64,
            "equipment_invalidations": [{"code": "device_disconnect", "detection_phase": "pre_outcome", "maximum_repeats": 2}],
            "evaluation_not_after_unix": 1789603200u64, "evaluator_build_sha256": qdigest("9"), "expires_at_unix": 1790899200u64,
            "hardware_scope": {"hardware_class": "usb-rgb-ir-v1", "interface_layout_sha256": qdigest("a"),
                "ir": {"backend": "v4l2-uvc", "descriptor_sha256": qdigest("b"), "driver": "uvcvideo", "interface_number": 2, "pid": 0x5678, "speed_millimbps": 5000000u64, "vid": 0x0bda},
                "match_policy_version": 1,
                "rgb": {"backend": "v4l2-uvc", "descriptor_sha256": qdigest("c"), "driver": "uvcvideo", "interface_number": 0, "pid": 0x5678, "speed_millimbps": 5000000u64, "vid": 0x0bda}},
            "locked_sample_sizes": samples, "latency_budget_us": 1000000,
            "operating_points": [
                {"gate": "detection", "operating_point_id": "detection-v1", "threshold_ppb": 500000000}, {"gate": "ir_pad", "operating_point_id": "ir-pad-v1", "threshold_ppb": 500000000},
                {"gate": "liveness", "operating_point_id": "liveness-v1", "threshold_ppb": 500000000}, {"gate": "recognition", "operating_point_id": "recognition-v1", "threshold_ppb": 500000000},
                {"gate": "rgb_pad", "operating_point_id": "rgb-pad-v1", "threshold_ppb": 500000000}],
            "operator_fingerprint": OPERATOR, "pilot_discordance": pilot, "policy_id": "maintainer-camera-profile-v1",
            "policy_sha256": qualification::Sha256Digest::of(policy_bytes).as_str(), "public_regression_evidence": [], "review_not_after_unix": 1790208000u64,
            "schema_version": 1, "signature": {"algorithm": "open_pgp", "role": "protocol_author", "signer_fingerprint": "CCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCC"},
            "source_revision": qdigest("d"), "strata": strata
        })
    }

    fn snapshot_value(protocol_digest: &qualification::Sha256Digest) -> Value {
        let tokens = json!([qdigest("0"), qdigest("e")]);
        json!({
            "aggregate_publication_acknowledged": false,
            "allowed_presentations": ["bona_fide", "display_replay", "no_face", "non_mated_live_cross_identity", "print"],
            "collection_closes_unix": 1788998400u64, "collection_opens_unix": 1788393600u64,
            "phase": "collection", "predecessor_sha256": null, "protocol_sha256": protocol_digest.as_str(),
            "publication_boundary_acknowledged": false, "purpose": "camera-profile-release-qualification", "registry_revision": 1,
            "retention_expires_unix": 1790899200u64, "schema_version": 1,
            "signature": {"algorithm": "open_pgp", "role": "operator", "signer_fingerprint": OPERATOR},
            "statuses": [{"status": "active", "token_sha256": qdigest("0")}, {"status": "active", "token_sha256": qdigest("e")}],
            "token_set_sha256": qualification::Sha256Digest::of(&serde_json::to_vec(&tokens).unwrap()).as_str()
        })
    }

    fn capture_shard_value(
        protocol: &Value,
        protocol_digest: &qualification::Sha256Digest,
    ) -> Value {
        let hardware_digest = qualification::Sha256Digest::of(
            &serde_json::to_vec(&protocol["hardware_scope"]).unwrap(),
        );
        let pairs: Vec<_> = protocol["cases"].as_array().unwrap().chunks_exact(2).enumerate().map(|(position, pair)| {
            let side = |case: &Value, name: &str| {
                let profile = &protocol[name];
                let profile_digest = qualification::Sha256Digest::of(&serde_json::to_vec(profile).unwrap());
                json!({
                    "assets": [
                        {"content_sha256": qualification::Sha256Digest::of(format!("{position}-{name}-rgb").as_bytes()).as_str(), "height": 1, "path": format!("pair-{position}/{name}-rgb.bin"), "position": 0, "role": "rgb", "size_bytes": 1, "width": 1},
                        {"content_sha256": qualification::Sha256Digest::of(format!("{position}-{name}-ir").as_bytes()).as_str(), "height": 1, "path": format!("pair-{position}/{name}-ir.bin"), "position": 0, "role": "ir", "size_bytes": 1, "width": 1}
                    ],
                    "attempts": [{"attempt_position": 0, "conditioning_applied_sha256": profile["contracts"]["selected_policy_sha256"], "conditioning_before_sha256": qdigest("b"), "conditioning_restored_sha256": qdigest("b"), "invalidated_pre_outcome": false, "invalidation_code": null, "outcome_recorded": true}],
                    "capture_ended_unix": 1788500001u64, "capture_provenance_sha256": qualification::Sha256Digest::of(format!("provenance-{position}-{name}").as_bytes()).as_str(),
                    "capture_started_unix": 1788500000u64, "captured_count": case["planned_count"], "case_id": case["case_id"], "expected_outcome": case["expected_outcome"],
                    "hardware_scope_sha256": hardware_digest.as_str(), "order_position": case["order_position"], "presentation_class": case["presentation_class"],
                    "profile_id": profile["profile_id"], "profile_sha256": profile_digest.as_str(), "scene_id": case["scene_id"], "source_revision": protocol["source_revision"],
                    "stratum_id": case["stratum_id"], "token_sha256": if position % 2 == 0 { qdigest("0") } else { qdigest("e") }
                })
            };
            json!({"baseline": side(&pair[0], "baseline"), "candidate": side(&pair[1], "candidate"), "logical_case_id": pair[0]["logical_case_id"]})
        }).collect();
        json!({"cases": pairs, "protocol_sha256": protocol_digest.as_str(), "schema_version": 1, "shard_position": 0, "signature": {"algorithm": "open_pgp", "role": "operator", "signer_fingerprint": OPERATOR}})
    }

    fn passing_case_outcome(accept: bool) -> qualification::ProfileCaseOutcome {
        qualification::ProfileCaseOutcome {
            detection: qualification::StageOutcome::Success,
            recognition: qualification::StageOutcome::Success,
            liveness: qualification::StageOutcome::Success,
            rgb_pad: qualification::StageOutcome::Success,
            ir_pad: qualification::StageOutcome::Success,
            authentication_accept: accept,
            latency_us: 100,
            decision_value_ppb: None,
        }
    }

    fn compiled_campaign_artifact() -> (
        qualification::UnsignedReleaseArtifact,
        qualification::Sha256Digest,
        qualification::Sha256Digest,
    ) {
        let policy_value = campaign_policy_value();
        let policy_bytes = serde_json::to_vec(&policy_value).unwrap();
        let policy = verify_q::<qualification::CampaignPolicy>(
            &policy_value,
            qualification::SignerRole::PolicyAuthor,
            POLICY_AUTHOR,
        );
        let protocol_value = campaign_protocol_value(&policy_bytes);
        let verified_protocol = verify_q::<qualification::CampaignProtocol>(
            &protocol_value,
            qualification::SignerRole::ProtocolAuthor,
            EVALUATOR,
        );
        let protocol = qualification::ValidatedProtocol::new(&policy, verified_protocol).unwrap();

        let collection_value = snapshot_value(protocol.protocol_sha256());
        let collection_snapshot = verify_q::<qualification::EligibilitySnapshot>(
            &collection_value,
            qualification::SignerRole::Operator,
            OPERATOR,
        );
        let collection = qualification::validate_collection_eligibility(
            &protocol,
            collection_snapshot,
            1788500000,
        )
        .unwrap();
        let shard_value = capture_shard_value(&protocol_value, protocol.protocol_sha256());
        let shard = verify_q::<qualification::CaptureShard>(
            &shard_value,
            qualification::SignerRole::Operator,
            OPERATOR,
        );
        let index_value = json!({
            "collection_eligibility_sha256": collection.snapshot_sha256().as_str(), "ordered_shard_sha256": [shard.digest().as_str()],
            "protocol_sha256": protocol.protocol_sha256().as_str(), "schema_version": 1,
            "signature": {"algorithm": "open_pgp", "role": "operator", "signer_fingerprint": OPERATOR}
        });
        let index = verify_q::<qualification::BundleIndex>(
            &index_value,
            qualification::SignerRole::Operator,
            OPERATOR,
        );
        let bundle =
            qualification::validate_frozen_bundle(&protocol, &collection, index, vec![shard])
                .unwrap();

        let mut evaluation_value = snapshot_value(protocol.protocol_sha256());
        evaluation_value["phase"] = json!("evaluation");
        evaluation_value["registry_revision"] = json!(2);
        evaluation_value["predecessor_sha256"] = json!(collection.snapshot_sha256().as_str());
        let evaluation_snapshot = verify_q::<qualification::EligibilitySnapshot>(
            &evaluation_value,
            qualification::SignerRole::Operator,
            OPERATOR,
        );
        let evaluation = qualification::validate_evaluation_eligibility(
            &bundle,
            evaluation_snapshot,
            1789000000,
        )
        .unwrap();

        let outcomes: Vec<_> = protocol_value["cases"]
            .as_array()
            .unwrap()
            .chunks_exact(2)
            .zip(shard_value["cases"].as_array().unwrap())
            .flat_map(|(pair, captured)| {
                let expected_accept = pair[0]["expected_outcome"] == "accept";
                let presentation: qualification::PresentationClass =
                    serde_json::from_value(pair[0]["presentation_class"].clone()).unwrap();
                let expected: qualification::ExpectedOutcome =
                    serde_json::from_value(pair[0]["expected_outcome"].clone()).unwrap();
                let history = qualification::Sha256Digest::of(
                    &serde_json::to_vec(&json!([
                        captured["baseline"]["attempts"],
                        captured["candidate"]["attempts"]
                    ]))
                    .unwrap(),
                );
                (0..99).map(
                    move |instance_position| qualification::EvaluatedPairedCase {
                        case_id: qualification::Identifier::new(
                            pair[0]["logical_case_id"].as_str().unwrap(),
                        )
                        .unwrap(),
                        instance_position,
                        stratum_ids: vec![qualification::Identifier::new(
                            pair[0]["stratum_id"].as_str().unwrap(),
                        )
                        .unwrap()],
                        presentation,
                        expected,
                        baseline: passing_case_outcome(expected_accept),
                        candidate: passing_case_outcome(expected_accept),
                        attempt_history_sha256: history.clone(),
                    },
                )
            })
            .collect();
        let evaluator = qualification::SignerFingerprint::new(EVALUATOR).unwrap();
        let evaluator_provenance = qualification::Sha256Digest::of(b"evaluator-v1");
        let evaluator_signature: qualification::SignatureMetadata = serde_json::from_value(
            json!({"algorithm": "open_pgp", "role": "evaluator", "signer_fingerprint": EVALUATOR}),
        )
        .unwrap();
        let output = qualification::reduce_campaign(
            qualification::ReductionContext {
                protocol: &protocol,
                bundle: &bundle,
                evaluation: &evaluation,
                evaluator_fingerprint: &evaluator,
                evaluator_provenance_sha256: &evaluator_provenance,
                evaluated_at_unix: 1789000001,
                signature: &evaluator_signature,
            },
            outcomes,
        )
        .unwrap();

        let transcript = verify_q_document(
            &output.private_transcript_index,
            qualification::SignerRole::Evaluator,
            EVALUATOR,
        );
        let public_result = verify_q_document(
            &output.public_result,
            qualification::SignerRole::Evaluator,
            EVALUATOR,
        );
        let mut publication_value = snapshot_value(protocol.protocol_sha256());
        publication_value["phase"] = json!("publication");
        publication_value["registry_revision"] = json!(3);
        publication_value["predecessor_sha256"] = json!(evaluation.snapshot_sha256().as_str());
        publication_value["aggregate_publication_acknowledged"] = json!(true);
        publication_value["publication_boundary_acknowledged"] = json!(true);
        let publication_snapshot = verify_q::<qualification::EligibilitySnapshot>(
            &publication_value,
            qualification::SignerRole::Operator,
            OPERATOR,
        );
        let publication = qualification::validate_publication_eligibility(
            &evaluation,
            publication_snapshot,
            1789000001,
        )
        .unwrap();
        let review_value = json!({
            "bundle_sha256": bundle.bundle_index_sha256().as_str(),
            "checks": {"attacks": true, "cases": true, "cohort": true, "completeness": true, "consent": true, "expiry": true, "ordering": true, "provenance": true, "public_projection": true, "statistics": true},
            "collection_eligibility_sha256": publication.snapshot_sha256()[0].as_str(), "decision": "passed",
            "evaluation_eligibility_sha256": publication.snapshot_sha256()[1].as_str(), "evaluator_build_sha256": "9".repeat(64),
            "operator_fingerprint": OPERATOR, "policy_sha256": protocol.policy_sha256().as_str(), "protocol_sha256": protocol.protocol_sha256().as_str(),
            "public_result_sha256": public_result.digest().as_str(), "publication_eligibility_sha256": publication.snapshot_sha256()[2].as_str(),
            "reproduced_public_result_sha256": public_result.digest().as_str(), "reviewed_at_unix": 1789000002u64, "reviewer_fingerprint": REVIEWER,
            "schema_version": 1, "signature": {"algorithm": "open_pgp", "role": "reviewer", "signer_fingerprint": REVIEWER},
            "source_revision": "d".repeat(64), "transcript_sha256": transcript.digest().as_str()
        });
        let review = verify_q::<qualification::ReviewAttestation>(
            &review_value,
            qualification::SignerRole::Reviewer,
            REVIEWER,
        );
        let reproduced = public_result.digest().clone();
        let reviewed = qualification::assemble_reviewed_aggregate(
            qualification::ReviewContext {
                protocol: &protocol,
                bundle: &bundle,
                publication: &publication,
                transcript: &transcript,
                reproduced_public_result_sha256: &reproduced,
            },
            public_result,
            Some(review),
        )
        .unwrap();
        let expected_protocol = protocol.protocol_sha256().clone();
        let expected_result = reviewed.envelope_sha256().clone();
        let compiled = qualification::compile_unsigned_release_artifact(
            &reviewed,
            &qualification::SignerFingerprint::new(RELEASE_SIGNER).unwrap(),
        )
        .unwrap();
        (compiled, expected_protocol, expected_result)
    }

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
    fn qualification_compiler_bytes_match_private_camera_schema() {
        let (compiled, expected_protocol, expected_result) = compiled_campaign_artifact();
        let artifact =
            ReleaseQualificationArtifact::from_canonical_json(compiled.canonical_bytes()).unwrap();
        let wire: Value = serde_json::from_slice(compiled.canonical_bytes()).unwrap();
        assert_eq!(artifact.campaign_id(), "campaign-2026-09-02-a");
        assert_eq!(
            artifact.campaign_protocol_sha256(),
            expected_protocol.as_str()
        );
        assert_eq!(artifact.campaign_result_sha256(), expected_result.as_str());
        assert_eq!(wire["qualified_at_unix"], json!(1789000002u64));
        assert_eq!(wire["expires_at_unix"], json!(1790899200u64));
        assert_eq!(artifact.baseline_profile().id(), "baseline-30fps");
        assert_eq!(artifact.candidate_profile().id(), "candidate-15fps");
        let baseline = artifact.baseline_profile().to_profile().unwrap();
        let candidate = artifact.candidate_profile().to_profile().unwrap();
        assert_eq!(baseline.requested_rgb().interval().parts(), (1, 30));
        assert_eq!(candidate.requested_rgb().interval().parts(), (1, 15));
        assert_eq!(baseline.requested_ir().interval().parts(), (1, 15));
        assert_eq!(candidate.requested_ir().interval().parts(), (1, 15));
        assert_eq!(artifact.hardware_scope().match_policy_version, 1);
        assert_eq!(
            artifact.hardware_scope().interface_layout_sha256,
            "a".repeat(64)
        );
        assert_eq!(artifact.hardware_scope().rgb.interface_number, 0);
        assert_eq!(artifact.hardware_scope().ir.interface_number, 2);
        assert_eq!(artifact.conditioning_catalog_sha256(), "1".repeat(64));
        assert_eq!(artifact.selected_policy_sha256(), "5".repeat(64));
        assert_eq!(artifact.preprocessing_contract_sha256(), "3".repeat(64));
        assert_eq!(artifact.model_contract_sha256(), "2".repeat(64));
        assert_eq!(artifact.signature().signer_fingerprint(), RELEASE_SIGNER);
        assert_eq!(
            compiled.artifact_sha256().as_str(),
            irlume_common::sha256_hex(compiled.canonical_bytes())
        );
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

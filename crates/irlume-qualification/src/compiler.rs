// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright the irlume contributors.

use serde::{Deserialize, Serialize};

use crate::{
    CampaignError, CaptureSchedule, HardwareEndpointScope, HardwareScope, Identifier, PixelFormat,
    ProfileContract, PublicAggregateResult, ReviewedAggregate, Sha256Digest, SignerFingerprint,
    StreamContract, ValidatedProtocol, MAX_CAMPAIGN_DOCUMENT_BYTES,
};

const ARTIFACT_SCHEMA_VERSION: u32 = 1;
const ARTIFACT_POLICY_VERSION: u32 = 1;
const ARTIFACT_PRODUCER_VERSION: u32 = 1;
const MAX_ARTIFACT_LIFETIME_SECONDS: u64 = 31_536_000;

/// Canonical unsigned bytes ready for the separate release-signing boundary.
///
/// External code cannot construct or promote this value:
///
/// ```compile_fail
/// use irlume_qualification::UnsignedReleaseArtifact;
/// let _ = UnsignedReleaseArtifact {
///     canonical_bytes: b"{}".to_vec(),
///     artifact_sha256: todo!(),
/// };
/// ```
///
/// ```compile_fail
/// use irlume_qualification::UnsignedReleaseArtifact;
/// let unsigned: UnsignedReleaseArtifact = todo!();
/// let _ = unsigned.into_verified_release_qualification();
/// ```
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct UnsignedReleaseArtifact {
    canonical_bytes: Vec<u8>,
    artifact_sha256: Sha256Digest,
}

impl UnsignedReleaseArtifact {
    #[must_use]
    pub fn canonical_bytes(&self) -> &[u8] {
        &self.canonical_bytes
    }

    #[must_use]
    pub const fn artifact_sha256(&self) -> &Sha256Digest {
        &self.artifact_sha256
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
enum WireDisposition {
    Passed,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
enum WirePixelFormat {
    Yuyv,
    Nv12,
    Grey8,
    Grey16,
}

impl From<PixelFormat> for WirePixelFormat {
    fn from(value: PixelFormat) -> Self {
        match value {
            PixelFormat::Yuyv => Self::Yuyv,
            PixelFormat::Nv12 => Self::Nv12,
            PixelFormat::Grey8 => Self::Grey8,
            PixelFormat::Grey16 => Self::Grey16,
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
struct WireStream {
    format: WirePixelFormat,
    width: u32,
    height: u32,
    interval_numerator: u32,
    interval_denominator: u32,
}

impl From<&StreamContract> for WireStream {
    fn from(value: &StreamContract) -> Self {
        Self {
            format: value.format().into(),
            width: value.width(),
            height: value.height(),
            interval_numerator: value.interval_numerator(),
            interval_denominator: value.interval_denominator(),
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
enum WireSchedule {
    Concurrent,
    Sequential,
}

impl From<CaptureSchedule> for WireSchedule {
    fn from(value: CaptureSchedule) -> Self {
        match value {
            CaptureSchedule::Concurrent => Self::Concurrent,
            CaptureSchedule::Sequential => Self::Sequential,
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
struct WireProfile {
    profile_id: Identifier,
    requested_rgb: WireStream,
    accepted_rgb: WireStream,
    requested_ir: WireStream,
    accepted_ir: WireStream,
    schedule: WireSchedule,
}

impl From<&ProfileContract> for WireProfile {
    fn from(value: &ProfileContract) -> Self {
        Self {
            profile_id: value.profile_id().clone(),
            requested_rgb: value.requested_rgb().into(),
            accepted_rgb: value.accepted_rgb().into(),
            requested_ir: value.requested_ir().into(),
            accepted_ir: value.accepted_ir().into(),
            schedule: value.schedule().into(),
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
struct WireEndpoint {
    descriptor_sha256: Sha256Digest,
    vid: u16,
    pid: u16,
    interface_number: u8,
    driver: Identifier,
    backend: Identifier,
    speed_millimbps: u64,
}

impl From<&HardwareEndpointScope> for WireEndpoint {
    fn from(value: &HardwareEndpointScope) -> Self {
        Self {
            descriptor_sha256: value.descriptor_sha256().clone(),
            vid: value.vid(),
            pid: value.pid(),
            interface_number: value.interface_number(),
            driver: value.driver().clone(),
            backend: value.backend().clone(),
            speed_millimbps: value.speed_millimbps(),
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
struct WireHardware {
    match_policy_version: u32,
    interface_layout_sha256: Sha256Digest,
    rgb: WireEndpoint,
    ir: WireEndpoint,
}

impl From<&HardwareScope> for WireHardware {
    fn from(value: &HardwareScope) -> Self {
        Self {
            match_policy_version: value.match_policy_version(),
            interface_layout_sha256: value.interface_layout_sha256().clone(),
            rgb: value.rgb().into(),
            ir: value.ir().into(),
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
struct WireGates {
    detection: WireDisposition,
    recognition: WireDisposition,
    liveness: WireDisposition,
    rgb_pad: WireDisposition,
    ir_pad: WireDisposition,
    latency: WireDisposition,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
enum WireSignatureAlgorithm {
    OpenPgp,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
struct WireSignature {
    algorithm: WireSignatureAlgorithm,
    signer_fingerprint: SignerFingerprint,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
struct ArtifactWire {
    schema_version: u32,
    policy_version: u32,
    producer_version: u32,
    campaign_id: Identifier,
    campaign_protocol_sha256: Sha256Digest,
    campaign_result_sha256: Sha256Digest,
    qualified_at_unix: u64,
    expires_at_unix: u64,
    hardware_scope: WireHardware,
    baseline: WireProfile,
    candidate: WireProfile,
    conditioning_catalog_sha256: Sha256Digest,
    selected_policy_sha256: Sha256Digest,
    preprocessing_contract_sha256: Sha256Digest,
    model_contract_sha256: Sha256Digest,
    gates: WireGates,
    signature: WireSignature,
}

impl ArtifactWire {
    fn from_canonical_json(bytes: &[u8]) -> Result<Self, CampaignError> {
        if bytes.len() > MAX_CAMPAIGN_DOCUMENT_BYTES {
            return Err(CampaignError::ArtifactCompileFailed);
        }
        let value: Self =
            serde_json::from_slice(bytes).map_err(|_| CampaignError::ArtifactCompileFailed)?;
        let canonical =
            serde_json::to_vec(&value).map_err(|_| CampaignError::ArtifactCompileFailed)?;
        if canonical != bytes {
            return Err(CampaignError::ArtifactCompileFailed);
        }
        Ok(value)
    }
}

fn validate_target_bindings(
    protocol: &ValidatedProtocol,
    public: &PublicAggregateResult,
) -> Result<(), CampaignError> {
    let document = protocol.protocol();
    let contracts = document.runtime_contracts();
    if public.policy_sha256 != *protocol.policy_sha256()
        || public.protocol_sha256 != *protocol.protocol_sha256()
        || public.collection_not_before_unix != document.collection_not_before_unix()
        || public.collection_not_after_unix != document.collection_not_after_unix()
        || public.hardware_scope_sha256 != document.hardware_scope().lifecycle_sha256()?
        || public.baseline_profile_sha256 != document.baseline().lifecycle_sha256()?
        || public.candidate_profile_sha256 != document.candidate().lifecycle_sha256()?
        || public.conditioning_catalog_sha256 != *contracts.conditioning_catalog_sha256()
        || public.selected_policy_sha256 != *contracts.selected_policy_sha256()
        || public.preprocessing_contract_sha256 != *contracts.preprocessing_contract_sha256()
        || public.model_contract_sha256 != *contracts.model_contract_sha256()
        || public.producer_contract_sha256 != *contracts.producer_contract_sha256()
        || public.software_contract_sha256 != *contracts.software_contract_sha256()
        || public.threshold_contract_sha256 != *contracts.threshold_contract_sha256()
        || public.source_revision != *document.source_revision()
    {
        return Err(CampaignError::ArtifactCompileFailed);
    }
    Ok(())
}

fn bounded_expiry(
    protocol_expiry: u64,
    collection_not_after: u64,
    qualified_at: u64,
) -> Result<u64, CampaignError> {
    let collection_expiry = collection_not_after
        .checked_add(MAX_ARTIFACT_LIFETIME_SECONDS)
        .ok_or(CampaignError::ArtifactCompileFailed)?;
    let expires_at = protocol_expiry.min(collection_expiry);
    if qualified_at == 0 || expires_at <= qualified_at {
        return Err(CampaignError::ArtifactCompileFailed);
    }
    Ok(expires_at)
}

/// Compiles reviewed campaign authority into canonical unsigned schema-1 bytes.
///
/// # Errors
///
/// Returns `ArtifactCompileFailed` if retained authority is inconsistent, time
/// bounds cannot produce a live artifact, or canonical serialization fails.
pub fn compile_unsigned_release_artifact(
    reviewed: &ReviewedAggregate,
    release_signer: &SignerFingerprint,
) -> Result<UnsignedReleaseArtifact, CampaignError> {
    compile(reviewed, release_signer).map_err(|_| CampaignError::ArtifactCompileFailed)
}

fn compile(
    reviewed: &ReviewedAggregate,
    release_signer: &SignerFingerprint,
) -> Result<UnsignedReleaseArtifact, CampaignError> {
    let protocol = reviewed.protocol();
    let document = protocol.protocol();
    let public = reviewed.public_result().document();
    validate_target_bindings(protocol, public)?;
    let qualified_at_unix = reviewed.review().document().reviewed_at_unix();
    let expires_at_unix = bounded_expiry(
        document.expires_at_unix(),
        document.collection_not_after_unix(),
        qualified_at_unix,
    )?;
    let contracts = document.runtime_contracts();
    let wire = ArtifactWire {
        schema_version: ARTIFACT_SCHEMA_VERSION,
        policy_version: ARTIFACT_POLICY_VERSION,
        producer_version: ARTIFACT_PRODUCER_VERSION,
        campaign_id: document.campaign_id().clone(),
        campaign_protocol_sha256: protocol.protocol_sha256().clone(),
        campaign_result_sha256: reviewed.envelope_sha256().clone(),
        qualified_at_unix,
        expires_at_unix,
        hardware_scope: document.hardware_scope().into(),
        baseline: document.baseline().into(),
        candidate: document.candidate().into(),
        conditioning_catalog_sha256: contracts.conditioning_catalog_sha256().clone(),
        selected_policy_sha256: contracts.selected_policy_sha256().clone(),
        preprocessing_contract_sha256: contracts.preprocessing_contract_sha256().clone(),
        model_contract_sha256: contracts.model_contract_sha256().clone(),
        gates: WireGates {
            detection: WireDisposition::Passed,
            recognition: WireDisposition::Passed,
            liveness: WireDisposition::Passed,
            rgb_pad: WireDisposition::Passed,
            ir_pad: WireDisposition::Passed,
            latency: WireDisposition::Passed,
        },
        signature: WireSignature {
            algorithm: WireSignatureAlgorithm::OpenPgp,
            signer_fingerprint: release_signer.clone(),
        },
    };
    let canonical_bytes =
        serde_json::to_vec(&wire).map_err(|_| CampaignError::ArtifactCompileFailed)?;
    if canonical_bytes.len() > MAX_CAMPAIGN_DOCUMENT_BYTES {
        return Err(CampaignError::ArtifactCompileFailed);
    }
    let parsed = ArtifactWire::from_canonical_json(&canonical_bytes)?;
    if parsed != wire {
        return Err(CampaignError::ArtifactCompileFailed);
    }
    let artifact_sha256 = Sha256Digest::of(&canonical_bytes);
    Ok(UnsignedReleaseArtifact {
        canonical_bytes,
        artifact_sha256,
    })
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;
    use crate::{result::tests::passing_reviewed_aggregate, SignerFingerprint};

    const RELEASE_SIGNER: &str = "EEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEE";

    #[test]
    fn compiler_projects_exact_reviewed_schema_one_authority() {
        let reviewed = passing_reviewed_aggregate();
        let signer = SignerFingerprint::new(RELEASE_SIGNER).unwrap();
        let artifact = compile_unsigned_release_artifact(&reviewed, &signer).unwrap();
        let value: serde_json::Value = serde_json::from_slice(artifact.canonical_bytes()).unwrap();

        assert_eq!(value["schema_version"], json!(1));
        assert_eq!(value["policy_version"], json!(1));
        assert_eq!(value["producer_version"], json!(1));
        assert_eq!(value["campaign_id"], json!("campaign-2026-09-02-a"));
        assert_eq!(
            value["campaign_protocol_sha256"],
            json!(reviewed.envelope().protocol_sha256().as_str())
        );
        assert_eq!(
            value["campaign_result_sha256"],
            json!(reviewed.envelope_sha256().as_str())
        );
        assert_eq!(value["qualified_at_unix"], json!(1789000002u64));
        assert_eq!(value["expires_at_unix"], json!(1790899200u64));
        assert_eq!(value["hardware_scope"]["match_policy_version"], json!(1));
        assert_eq!(
            value["hardware_scope"]["interface_layout_sha256"],
            json!("a".repeat(64))
        );
        assert_eq!(value["hardware_scope"]["rgb"]["vid"], json!(0x0bda));
        assert_eq!(value["hardware_scope"]["rgb"]["interface_number"], json!(0));
        assert_eq!(value["hardware_scope"]["ir"]["interface_number"], json!(2));
        assert_eq!(value["baseline"]["profile_id"], json!("baseline-30fps"));
        assert_eq!(value["baseline"]["requested_rgb"]["format"], json!("yuyv"));
        assert_eq!(
            value["baseline"]["requested_rgb"]["interval_denominator"],
            json!(30)
        );
        assert_eq!(value["candidate"]["profile_id"], json!("candidate-15fps"));
        assert_eq!(value["candidate"]["accepted_ir"]["format"], json!("grey8"));
        assert_eq!(value["candidate"]["schedule"], json!("concurrent"));
        assert!(value["gates"]
            .as_object()
            .unwrap()
            .values()
            .all(|gate| gate == "passed"));
        assert_eq!(
            value["signature"],
            json!({
                "algorithm": "open_pgp",
                "signer_fingerprint": RELEASE_SIGNER
            })
        );
        assert_eq!(
            artifact.artifact_sha256(),
            &crate::Sha256Digest::of(artifact.canonical_bytes())
        );
    }

    #[test]
    fn compiler_wire_rejects_oversized_unknown_and_noncanonical_bytes() {
        let oversized = vec![b' '; crate::MAX_CAMPAIGN_DOCUMENT_BYTES + 1];
        assert_eq!(
            ArtifactWire::from_canonical_json(&oversized),
            Err(crate::CampaignError::ArtifactCompileFailed)
        );

        let reviewed = passing_reviewed_aggregate();
        let signer = SignerFingerprint::new(RELEASE_SIGNER).unwrap();
        let artifact = compile_unsigned_release_artifact(&reviewed, &signer).unwrap();
        let mut unknown: serde_json::Value =
            serde_json::from_slice(artifact.canonical_bytes()).unwrap();
        unknown["replacement_authority"] = json!(true);
        assert_eq!(
            ArtifactWire::from_canonical_json(&serde_json::to_vec(&unknown).unwrap()),
            Err(crate::CampaignError::ArtifactCompileFailed)
        );
        assert_eq!(
            ArtifactWire::from_canonical_json(&serde_json::to_vec_pretty(&unknown).unwrap()),
            Err(crate::CampaignError::ArtifactCompileFailed)
        );
    }

    #[test]
    fn compiler_output_excludes_private_campaign_material() {
        let reviewed = passing_reviewed_aggregate();
        let signer = SignerFingerprint::new(RELEASE_SIGNER).unwrap();
        let artifact = compile_unsigned_release_artifact(&reviewed, &signer).unwrap();
        let text = std::str::from_utf8(artifact.canonical_bytes()).unwrap();
        assert!(!text.contains(&"0".repeat(64)));
        for forbidden in [
            "identity",
            "participant",
            "token",
            "consent",
            "relative_path",
            "device_path",
            "devpath",
            "serial",
            "image",
            "crop",
            "tensor",
            "template",
            "embedding",
            "score",
            "third_party",
            "error_text",
        ] {
            assert!(!text.contains(forbidden), "artifact leaked {forbidden}");
        }
    }

    #[test]
    fn compiler_rejects_every_public_target_binding_mismatch() {
        let reviewed = passing_reviewed_aggregate();
        let original = reviewed.public_result().document();
        let original_value = serde_json::to_value(original).unwrap();
        for field in [
            "baseline_profile_sha256",
            "candidate_profile_sha256",
            "conditioning_catalog_sha256",
            "hardware_scope_sha256",
            "model_contract_sha256",
            "policy_sha256",
            "preprocessing_contract_sha256",
            "producer_contract_sha256",
            "protocol_sha256",
            "selected_policy_sha256",
            "software_contract_sha256",
            "source_revision",
            "threshold_contract_sha256",
        ] {
            let mut changed = original_value.clone();
            changed[field] = json!("e".repeat(64));
            let changed: crate::PublicAggregateResult = serde_json::from_value(changed).unwrap();
            assert_eq!(
                validate_target_bindings(reviewed.protocol(), &changed),
                Err(crate::CampaignError::ArtifactCompileFailed),
                "accepted mismatched {field}"
            );
        }
        for (field, value) in [
            ("collection_not_before_unix", 1788393601u64),
            ("collection_not_after_unix", 1788998399u64),
        ] {
            let mut changed = original_value.clone();
            changed[field] = json!(value);
            let changed: crate::PublicAggregateResult = serde_json::from_value(changed).unwrap();
            assert_eq!(
                validate_target_bindings(reviewed.protocol(), &changed),
                Err(crate::CampaignError::ArtifactCompileFailed),
                "accepted mismatched {field}"
            );
        }
    }

    #[test]
    fn compiler_expiry_is_checked_bounded_and_strictly_live() {
        assert_eq!(
            bounded_expiry(u64::MAX, u64::MAX, 1),
            Err(CampaignError::ArtifactCompileFailed)
        );
        assert_eq!(
            bounded_expiry(200, 100, 0),
            Err(CampaignError::ArtifactCompileFailed)
        );
        assert_eq!(
            bounded_expiry(200, 100, 200),
            Err(CampaignError::ArtifactCompileFailed)
        );
        assert_eq!(bounded_expiry(200, 100, 99), Ok(200));
        assert_eq!(bounded_expiry(u64::MAX, 100, 99), Ok(31_536_100));
    }
}

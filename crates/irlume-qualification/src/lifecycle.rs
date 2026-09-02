// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright the irlume contributors.

use serde::{Deserialize, Serialize};

use crate::{
    canonical::private,
    policy::{parse_canonical, to_canonical},
    CampaignError, CanonicalDocument, Identifier, PresentationClass, Sha256Digest,
    SignatureMetadata, SignerRole, StreamRole, ValidatedProtocol, Verified,
    MAX_ASSETS_PER_ROLE_PER_CASE, MAX_ASSET_BYTES, MAX_CAPTURE_SHARD_CASES,
    MAX_PRIVATE_RETENTION_SECONDS,
};

const ELIGIBILITY_SCHEMA_VERSION: u32 = 1;
const QUALIFICATION_PURPOSE: &str = "camera-profile-release-qualification";

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum EligibilityPhase {
    Collection,
    Evaluation,
    Publication,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum EligibilityStatus {
    Active,
    Expired,
    Withdrawn,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum CaptureOrderPosition {
    First,
    Second,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct TokenEligibility {
    status: EligibilityStatus,
    token_sha256: Sha256Digest,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct EligibilitySnapshot {
    aggregate_publication_acknowledged: bool,
    allowed_presentations: Vec<PresentationClass>,
    collection_closes_unix: u64,
    collection_opens_unix: u64,
    phase: EligibilityPhase,
    predecessor_sha256: Option<Sha256Digest>,
    protocol_sha256: Sha256Digest,
    publication_boundary_acknowledged: bool,
    purpose: Identifier,
    registry_revision: u64,
    retention_expires_unix: u64,
    schema_version: u32,
    signature: SignatureMetadata,
    statuses: Vec<TokenEligibility>,
    token_set_sha256: Sha256Digest,
}

impl EligibilitySnapshot {
    fn validate_document(&self) -> Result<(), CampaignError> {
        let expected_presentations = [
            PresentationClass::BonaFide,
            PresentationClass::DisplayReplay,
            PresentationClass::NoFace,
            PresentationClass::NonMatedLiveCrossIdentity,
            PresentationClass::Print,
        ];
        let token_digests: Vec<_> = self
            .statuses
            .iter()
            .map(|token| &token.token_sha256)
            .collect();
        let token_bytes = to_canonical(&token_digests)?;
        if self.schema_version != ELIGIBILITY_SCHEMA_VERSION
            || self.signature.role() != SignerRole::Operator
            || self.purpose.as_str() != QUALIFICATION_PURPOSE
            || self.registry_revision == 0
            || self.statuses.is_empty()
            || !self
                .statuses
                .windows(2)
                .all(|pair| pair[0].token_sha256 < pair[1].token_sha256)
            || self.allowed_presentations != expected_presentations
            || self.token_set_sha256 != Sha256Digest::of(&token_bytes)
            || self.collection_opens_unix >= self.collection_closes_unix
            || self
                .retention_expires_unix
                .checked_sub(self.collection_closes_unix)
                .is_none_or(|duration| duration > MAX_PRIVATE_RETENTION_SECONDS)
        {
            return Err(CampaignError::ConsentIneligible);
        }
        Ok(())
    }
}

impl private::Sealed for EligibilitySnapshot {}

impl CanonicalDocument for EligibilitySnapshot {
    fn from_canonical_json(bytes: &[u8]) -> Result<Self, CampaignError> {
        let document: Self = parse_canonical(bytes)?;
        document.validate_document()?;
        Ok(document)
    }

    fn to_canonical_json(&self) -> Result<Vec<u8>, CampaignError> {
        self.validate_document()?;
        to_canonical(self)
    }

    fn signature_metadata(&self) -> &SignatureMetadata {
        &self.signature
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ValidatedCollectionEligibility {
    allowed_presentations: Vec<PresentationClass>,
    collection_closes_unix: u64,
    collection_opens_unix: u64,
    retention_expires_unix: u64,
    snapshot_sha256: Sha256Digest,
    token_set_sha256: Sha256Digest,
    operator_fingerprint: crate::SignerFingerprint,
    token_sha256: Vec<Sha256Digest>,
}

impl ValidatedCollectionEligibility {
    #[must_use]
    pub const fn snapshot_sha256(&self) -> &Sha256Digest {
        &self.snapshot_sha256
    }

    #[must_use]
    pub const fn token_set_sha256(&self) -> &Sha256Digest {
        &self.token_set_sha256
    }
}

/// Validates the root collection eligibility snapshot for one protocol.
///
/// # Errors
///
/// Returns `ConsentIneligible` when the snapshot is not an active, in-window
/// root revision bound to the exact protocol.
pub fn validate_collection_eligibility(
    protocol: &ValidatedProtocol,
    snapshot: Verified<EligibilitySnapshot>,
    now_unix: u64,
) -> Result<ValidatedCollectionEligibility, CampaignError> {
    let document = snapshot.document();
    if document.phase != EligibilityPhase::Collection
        || document.predecessor_sha256.is_some()
        || document.registry_revision != 1
        || document.protocol_sha256 != *protocol.protocol_sha256()
        || snapshot.signer() != protocol.protocol().operator_fingerprint()
        || document.collection_opens_unix != protocol.protocol().collection_not_before_unix()
        || document.collection_closes_unix != protocol.protocol().collection_not_after_unix()
        || document.retention_expires_unix > protocol.protocol().expires_at_unix()
        || now_unix < document.collection_opens_unix
        || now_unix > document.collection_closes_unix
        || document
            .statuses
            .iter()
            .any(|token| token.status != EligibilityStatus::Active)
        || document.aggregate_publication_acknowledged
        || document.publication_boundary_acknowledged
    {
        return Err(CampaignError::ConsentIneligible);
    }
    Ok(ValidatedCollectionEligibility {
        allowed_presentations: document.allowed_presentations.clone(),
        collection_closes_unix: document.collection_closes_unix,
        collection_opens_unix: document.collection_opens_unix,
        retention_expires_unix: document.retention_expires_unix,
        snapshot_sha256: snapshot.digest().clone(),
        token_set_sha256: document.token_set_sha256.clone(),
        operator_fingerprint: snapshot.signer().clone(),
        token_sha256: document
            .statuses
            .iter()
            .map(|token| token.token_sha256.clone())
            .collect(),
    })
}

fn valid_asset_path(path: &str) -> bool {
    !path.is_empty()
        && path.len() <= 4096
        && !path.starts_with('/')
        && !path.contains('\\')
        && !path.contains('\0')
        && path
            .split('/')
            .all(|component| !component.is_empty() && component != "." && component != "..")
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct AssetDescriptor {
    content_sha256: Sha256Digest,
    height: u32,
    path: String,
    position: u32,
    role: StreamRole,
    size_bytes: u64,
    width: u32,
}

impl AssetDescriptor {
    fn validate(&self) -> Result<(), CampaignError> {
        if !valid_asset_path(&self.path)
            || self.size_bytes == 0
            || self.size_bytes > MAX_ASSET_BYTES
            || self.width == 0
            || self.height == 0
        {
            return Err(CampaignError::BundleUnsafe);
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct AttemptRecord {
    attempt_position: u32,
    conditioning_applied_sha256: Sha256Digest,
    conditioning_before_sha256: Sha256Digest,
    conditioning_restored_sha256: Sha256Digest,
    invalidated_pre_outcome: bool,
    invalidation_code: Option<Identifier>,
    outcome_recorded: bool,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct CaseSideCapture {
    assets: Vec<AssetDescriptor>,
    attempts: Vec<AttemptRecord>,
    capture_ended_unix: u64,
    capture_provenance_sha256: Sha256Digest,
    capture_started_unix: u64,
    captured_count: u32,
    case_id: Identifier,
    expected_outcome: crate::ExpectedOutcome,
    hardware_scope_sha256: Sha256Digest,
    order_position: CaptureOrderPosition,
    presentation_class: PresentationClass,
    profile_id: Identifier,
    profile_sha256: Sha256Digest,
    scene_id: Identifier,
    source_revision: Sha256Digest,
    stratum_id: Identifier,
    token_sha256: Sha256Digest,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct PairedCaseCapture {
    baseline: CaseSideCapture,
    candidate: CaseSideCapture,
    logical_case_id: Identifier,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct CaptureShard {
    cases: Vec<PairedCaseCapture>,
    protocol_sha256: Sha256Digest,
    schema_version: u32,
    shard_position: u32,
    signature: SignatureMetadata,
}

impl CaptureShard {
    fn validate_document(&self) -> Result<(), CampaignError> {
        if self.schema_version != 1
            || self.signature.role() != SignerRole::Operator
            || self.cases.is_empty()
            || self.cases.len() > MAX_CAPTURE_SHARD_CASES
        {
            return Err(CampaignError::BundleUnsafe);
        }
        for pair in &self.cases {
            if pair.baseline.case_id == pair.candidate.case_id
                || pair.baseline.profile_id == pair.candidate.profile_id
                || pair.baseline.token_sha256 != pair.candidate.token_sha256
                || pair.baseline.capture_provenance_sha256
                    == pair.candidate.capture_provenance_sha256
            {
                return Err(CampaignError::BundleUnsafe);
            }
            for side in [&pair.baseline, &pair.candidate] {
                if side.assets.is_empty()
                    || side.assets.len() > MAX_ASSETS_PER_ROLE_PER_CASE * 2
                    || [StreamRole::Rgb, StreamRole::Ir].into_iter().any(|role| {
                        side.assets
                            .iter()
                            .filter(|asset| asset.role == role)
                            .count()
                            > MAX_ASSETS_PER_ROLE_PER_CASE
                    })
                    || side.attempts.is_empty()
                    || side
                        .attempts
                        .iter()
                        .filter(|attempt| attempt.outcome_recorded)
                        .count()
                        != 1
                    || side.capture_started_unix >= side.capture_ended_unix
                    || side.captured_count == 0
                    || side.assets.iter().any(|asset| asset.validate().is_err())
                    || [StreamRole::Rgb, StreamRole::Ir].into_iter().any(|role| {
                        !side
                            .assets
                            .iter()
                            .filter(|asset| asset.role == role)
                            .enumerate()
                            .all(|(position, asset)| {
                                usize::try_from(asset.position) == Ok(position)
                            })
                    })
                    || !side.attempts.iter().enumerate().all(|(position, attempt)| {
                        usize::try_from(attempt.attempt_position) == Ok(position)
                            && attempt.conditioning_before_sha256
                                == attempt.conditioning_restored_sha256
                            && matches!(
                                (
                                    attempt.invalidation_code.is_some(),
                                    attempt.invalidated_pre_outcome,
                                    attempt.outcome_recorded,
                                ),
                                (true, true, false) | (false, false, true)
                            )
                    })
                    || side.attempts.last().is_none_or(|attempt| {
                        attempt.invalidation_code.is_some()
                            || attempt.invalidated_pre_outcome
                            || !attempt.outcome_recorded
                    })
                {
                    return Err(CampaignError::BundleUnsafe);
                }
            }
        }
        Ok(())
    }
}

impl private::Sealed for CaptureShard {}
impl CanonicalDocument for CaptureShard {
    fn from_canonical_json(bytes: &[u8]) -> Result<Self, CampaignError> {
        let value: Self = parse_canonical(bytes)?;
        value.validate_document()?;
        Ok(value)
    }
    fn to_canonical_json(&self) -> Result<Vec<u8>, CampaignError> {
        self.validate_document()?;
        to_canonical(self)
    }
    fn signature_metadata(&self) -> &SignatureMetadata {
        &self.signature
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct BundleIndex {
    collection_eligibility_sha256: Sha256Digest,
    ordered_shard_sha256: Vec<Sha256Digest>,
    protocol_sha256: Sha256Digest,
    schema_version: u32,
    signature: SignatureMetadata,
}

impl BundleIndex {
    fn validate_document(&self) -> Result<(), CampaignError> {
        if self.schema_version != 1
            || self.signature.role() != SignerRole::Operator
            || self.ordered_shard_sha256.is_empty()
            || self
                .ordered_shard_sha256
                .iter()
                .collect::<std::collections::BTreeSet<_>>()
                .len()
                != self.ordered_shard_sha256.len()
        {
            return Err(CampaignError::BundleUnsafe);
        }
        Ok(())
    }
}
impl private::Sealed for BundleIndex {}
impl CanonicalDocument for BundleIndex {
    fn from_canonical_json(bytes: &[u8]) -> Result<Self, CampaignError> {
        let value: Self = parse_canonical(bytes)?;
        value.validate_document()?;
        Ok(value)
    }
    fn to_canonical_json(&self) -> Result<Vec<u8>, CampaignError> {
        self.validate_document()?;
        to_canonical(self)
    }
    fn signature_metadata(&self) -> &SignatureMetadata {
        &self.signature
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ValidatedFrozenBundle {
    allowed_presentations: Vec<PresentationClass>,
    bundle_index_sha256: Sha256Digest,
    collection_snapshot_sha256: Sha256Digest,
    protocol_sha256: Sha256Digest,
    token_set_sha256: Sha256Digest,
    evaluation_not_after_unix: u64,
    collection_closes_unix: u64,
    collection_opens_unix: u64,
    retention_expires_unix: u64,
    review_not_after_unix: u64,
    operator_fingerprint: crate::SignerFingerprint,
    asset_sha256: Vec<Sha256Digest>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ValidatedEvaluationEligibility {
    allowed_presentations: Vec<PresentationClass>,
    bundle_index_sha256: Sha256Digest,
    collection_snapshot_sha256: Sha256Digest,
    evaluation_snapshot_sha256: Sha256Digest,
    protocol_sha256: Sha256Digest,
    token_set_sha256: Sha256Digest,
    collection_closes_unix: u64,
    collection_opens_unix: u64,
    retention_expires_unix: u64,
    validated_at_unix: u64,
    review_not_after_unix: u64,
    operator_fingerprint: crate::SignerFingerprint,
}

impl ValidatedEvaluationEligibility {
    #[must_use]
    pub const fn snapshot_sha256(&self) -> &Sha256Digest {
        &self.evaluation_snapshot_sha256
    }
    #[must_use]
    pub const fn token_set_sha256(&self) -> &Sha256Digest {
        &self.token_set_sha256
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ValidatedPublicationEligibility {
    bundle_index_sha256: Sha256Digest,
    operator_fingerprint: crate::SignerFingerprint,
    protocol_sha256: Sha256Digest,
    snapshot_sha256: [Sha256Digest; 3],
    token_set_sha256: Sha256Digest,
    validated_at_unix: u64,
}

impl ValidatedPublicationEligibility {
    #[must_use]
    pub const fn snapshot_sha256(&self) -> &[Sha256Digest; 3] {
        &self.snapshot_sha256
    }
    #[must_use]
    pub const fn token_set_sha256(&self) -> &Sha256Digest {
        &self.token_set_sha256
    }
}

/// Validates the evaluation successor of a frozen collection bundle.
///
/// # Errors
/// Returns `ConsentIneligible` when the revision, predecessor, token set, or deadline differs.
pub fn validate_evaluation_eligibility(
    bundle: &ValidatedFrozenBundle,
    snapshot: Verified<EligibilitySnapshot>,
    now_unix: u64,
) -> Result<ValidatedEvaluationEligibility, CampaignError> {
    let document = snapshot.document();
    if document.phase != EligibilityPhase::Evaluation
        || document.registry_revision != 2
        || document.predecessor_sha256.as_ref() != Some(&bundle.collection_snapshot_sha256)
        || document.protocol_sha256 != bundle.protocol_sha256
        || snapshot.signer() != &bundle.operator_fingerprint
        || document.token_set_sha256 != bundle.token_set_sha256
        || document.allowed_presentations != bundle.allowed_presentations
        || document.collection_opens_unix != bundle.collection_opens_unix
        || document.collection_closes_unix != bundle.collection_closes_unix
        || document.retention_expires_unix != bundle.retention_expires_unix
        || now_unix <= bundle.collection_closes_unix
        || now_unix > document.retention_expires_unix
        || now_unix > bundle.evaluation_not_after_unix
        || document
            .statuses
            .iter()
            .any(|token| token.status != EligibilityStatus::Active)
        || document.aggregate_publication_acknowledged
        || document.publication_boundary_acknowledged
    {
        return Err(CampaignError::ConsentIneligible);
    }
    Ok(ValidatedEvaluationEligibility {
        allowed_presentations: bundle.allowed_presentations.clone(),
        bundle_index_sha256: bundle.bundle_index_sha256.clone(),
        collection_snapshot_sha256: bundle.collection_snapshot_sha256.clone(),
        evaluation_snapshot_sha256: snapshot.digest().clone(),
        protocol_sha256: bundle.protocol_sha256.clone(),
        token_set_sha256: bundle.token_set_sha256.clone(),
        collection_closes_unix: bundle.collection_closes_unix,
        collection_opens_unix: bundle.collection_opens_unix,
        retention_expires_unix: bundle.retention_expires_unix,
        validated_at_unix: now_unix,
        review_not_after_unix: bundle.review_not_after_unix,
        operator_fingerprint: bundle.operator_fingerprint.clone(),
    })
}

/// Validates the publication successor and binds the complete snapshot chain.
///
/// # Errors
/// Returns `ConsentIneligible` when publication skips or replaces a predecessor.
pub fn validate_publication_eligibility(
    evaluation: &ValidatedEvaluationEligibility,
    snapshot: Verified<EligibilitySnapshot>,
    now_unix: u64,
) -> Result<ValidatedPublicationEligibility, CampaignError> {
    let document = snapshot.document();
    if document.phase != EligibilityPhase::Publication
        || document.registry_revision != 3
        || document.predecessor_sha256.as_ref() != Some(&evaluation.evaluation_snapshot_sha256)
        || document.protocol_sha256 != evaluation.protocol_sha256
        || snapshot.signer() != &evaluation.operator_fingerprint
        || document.token_set_sha256 != evaluation.token_set_sha256
        || document.allowed_presentations != evaluation.allowed_presentations
        || document.collection_opens_unix != evaluation.collection_opens_unix
        || document.collection_closes_unix != evaluation.collection_closes_unix
        || document.retention_expires_unix != evaluation.retention_expires_unix
        || now_unix < evaluation.validated_at_unix
        || now_unix > evaluation.review_not_after_unix
        || now_unix > document.retention_expires_unix
        || document
            .statuses
            .iter()
            .any(|token| token.status != EligibilityStatus::Active)
        || !document.aggregate_publication_acknowledged
        || !document.publication_boundary_acknowledged
    {
        return Err(CampaignError::ConsentIneligible);
    }
    Ok(ValidatedPublicationEligibility {
        bundle_index_sha256: evaluation.bundle_index_sha256.clone(),
        operator_fingerprint: evaluation.operator_fingerprint.clone(),
        protocol_sha256: evaluation.protocol_sha256.clone(),
        snapshot_sha256: [
            evaluation.collection_snapshot_sha256.clone(),
            evaluation.evaluation_snapshot_sha256.clone(),
            snapshot.digest().clone(),
        ],
        token_set_sha256: evaluation.token_set_sha256.clone(),
        validated_at_unix: now_unix,
    })
}

impl ValidatedFrozenBundle {
    #[must_use]
    pub const fn bundle_index_sha256(&self) -> &Sha256Digest {
        &self.bundle_index_sha256
    }
    #[must_use]
    pub const fn token_set_sha256(&self) -> &Sha256Digest {
        &self.token_set_sha256
    }
}

/// Validates a frozen metadata index without opening any asset path.
///
/// # Errors
/// Returns `BundleUnsafe` for any digest, ordering, protocol, or metadata mismatch.
pub fn validate_frozen_bundle(
    protocol: &ValidatedProtocol,
    collection: &ValidatedCollectionEligibility,
    index: Verified<BundleIndex>,
    shards: Vec<Verified<CaptureShard>>,
) -> Result<ValidatedFrozenBundle, CampaignError> {
    let expected: Vec<_> = shards.iter().map(|shard| shard.digest().clone()).collect();
    if index.signer() != protocol.protocol().operator_fingerprint()
        || index.document().protocol_sha256 != *protocol.protocol_sha256()
        || index.document().collection_eligibility_sha256 != *collection.snapshot_sha256()
        || index.document().ordered_shard_sha256 != expected
        || shards.iter().enumerate().any(|(position, shard)| {
            shard.signer() != protocol.protocol().operator_fingerprint()
                || shard.document().protocol_sha256 != *protocol.protocol_sha256()
                || usize::try_from(shard.document().shard_position) != Ok(position)
        })
    {
        return Err(CampaignError::BundleUnsafe);
    }

    let actual_cases: Vec<_> = shards
        .iter()
        .flat_map(|shard| &shard.document().cases)
        .flat_map(|pair| {
            [
                (&pair.baseline, &pair.logical_case_id, true),
                (&pair.candidate, &pair.logical_case_id, false),
            ]
        })
        .collect();
    let baseline_sha256 = protocol.protocol().baseline().lifecycle_sha256()?;
    let candidate_sha256 = protocol.protocol().candidate().lifecycle_sha256()?;
    let baseline_conditioning_sha256 = protocol.protocol().baseline().selected_policy_sha256();
    let candidate_conditioning_sha256 = protocol.protocol().candidate().selected_policy_sha256();
    let hardware_scope_sha256 = protocol.protocol().hardware_scope().lifecycle_sha256()?;
    let actual_tokens: std::collections::BTreeSet<_> = actual_cases
        .iter()
        .map(|(side, _, _)| &side.token_sha256)
        .collect();
    let eligible_tokens: std::collections::BTreeSet<_> = collection.token_sha256.iter().collect();
    if !actual_tokens.is_subset(&eligible_tokens) {
        return Err(CampaignError::ConsentIneligible);
    }
    if actual_tokens != eligible_tokens {
        return Err(CampaignError::CohortIncomplete);
    }
    if actual_cases.iter().any(|(side, _, _)| {
        [StreamRole::Rgb, StreamRole::Ir]
            .into_iter()
            .any(|role| !side.assets.iter().any(|asset| asset.role == role))
    }) {
        return Err(CampaignError::CaptureIncomplete);
    }
    if actual_cases.len() != protocol.protocol().cases().len()
        || actual_cases.iter().zip(protocol.protocol().cases()).any(
            |((actual, logical, baseline), planned)| {
                actual.case_id != *planned.case_id()
                    || **logical != *planned.logical_case_id()
                    || *baseline != planned.is_baseline()
                    || actual.expected_outcome != planned.expected_outcome()
                    || actual.captured_count != planned.planned_count()
                    || actual.presentation_class != planned.presentation_class()
                    || actual.scene_id != *planned.scene_id()
                    || actual.stratum_id != *planned.stratum_id()
                    || matches!(actual.order_position, CaptureOrderPosition::First)
                        != planned.is_first()
            },
        )
    {
        return Err(CampaignError::CaptureIncomplete);
    }
    if actual_cases.iter().any(|(actual, _, baseline)| {
        actual.hardware_scope_sha256 != hardware_scope_sha256
            || actual.source_revision != *protocol.protocol().source_revision()
            || actual.profile_sha256
                != if *baseline {
                    baseline_sha256.clone()
                } else {
                    candidate_sha256.clone()
                }
            || actual.profile_id
                != *if *baseline {
                    protocol.protocol().baseline().profile_id()
                } else {
                    protocol.protocol().candidate().profile_id()
                }
            || actual.attempts.iter().any(|attempt| {
                &attempt.conditioning_applied_sha256
                    != if *baseline {
                        baseline_conditioning_sha256
                    } else {
                        candidate_conditioning_sha256
                    }
            })
    }) {
        return Err(CampaignError::ProvenanceMismatch);
    }
    for side in actual_cases.iter().map(|(side, _, _)| *side) {
        if side.capture_started_unix < protocol.protocol().collection_not_before_unix()
            || side.capture_ended_unix > protocol.protocol().collection_not_after_unix()
        {
            return Err(CampaignError::BundleUnsafe);
        }
        let mut repeats = std::collections::BTreeMap::<&Identifier, u32>::new();
        for code in side
            .attempts
            .iter()
            .filter_map(|attempt| attempt.invalidation_code.as_ref())
        {
            let count = repeats.entry(code).or_default();
            *count = count.saturating_add(1);
            if protocol
                .protocol()
                .maximum_repeats(code)
                .is_none_or(|maximum| *count > maximum)
            {
                return Err(CampaignError::BundleUnsafe);
            }
        }
    }
    let mut paths = std::collections::BTreeSet::new();
    let mut digests = std::collections::BTreeSet::new();
    let mut asset_sha256 = Vec::new();
    for asset in shards
        .iter()
        .flat_map(|shard| &shard.document().cases)
        .flat_map(|pair| [&pair.baseline, &pair.candidate])
        .flat_map(|side| &side.assets)
    {
        if !paths.insert(&asset.path) || !digests.insert(&asset.content_sha256) {
            return Err(CampaignError::BundleUnsafe);
        }
        asset_sha256.push(asset.content_sha256.clone());
    }
    asset_sha256.sort();
    Ok(ValidatedFrozenBundle {
        allowed_presentations: collection.allowed_presentations.clone(),
        bundle_index_sha256: index.digest().clone(),
        collection_snapshot_sha256: collection.snapshot_sha256().clone(),
        protocol_sha256: protocol.protocol_sha256().clone(),
        token_set_sha256: collection.token_set_sha256().clone(),
        evaluation_not_after_unix: protocol.protocol().evaluation_not_after_unix(),
        collection_closes_unix: collection.collection_closes_unix,
        collection_opens_unix: collection.collection_opens_unix,
        retention_expires_unix: collection.retention_expires_unix,
        review_not_after_unix: protocol.protocol().review_not_after_unix(),
        operator_fingerprint: collection.operator_fingerprint.clone(),
        asset_sha256,
    })
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum DeletionReason {
    Withdrawal,
    Expiry,
    CampaignInvalidated,
}
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum DeletionStatus {
    Completed,
    Interrupted,
    Failed,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct DeletionRecord {
    affected_asset_sha256: Vec<Sha256Digest>,
    campaign_sha256: Sha256Digest,
    completed_at_unix: u64,
    reason: DeletionReason,
    reviewer_fingerprint: crate::SignerFingerprint,
    signature: SignatureMetadata,
    status: DeletionStatus,
}

impl DeletionRecord {
    fn validate_document(&self) -> Result<(), CampaignError> {
        if self.signature.role() != SignerRole::Reviewer
            || self.signature.signer_fingerprint() != &self.reviewer_fingerprint
            || self.affected_asset_sha256.is_empty()
            || !self
                .affected_asset_sha256
                .windows(2)
                .all(|pair| pair[0] < pair[1])
            || self.completed_at_unix == 0
        {
            return Err(CampaignError::BundleUnsafe);
        }
        Ok(())
    }
    const fn closes_retention(&self) -> bool {
        matches!(self.status, DeletionStatus::Completed)
    }
}
impl private::Sealed for DeletionRecord {}
impl CanonicalDocument for DeletionRecord {
    fn from_canonical_json(bytes: &[u8]) -> Result<Self, CampaignError> {
        let value: Self = parse_canonical(bytes)?;
        value.validate_document()?;
        Ok(value)
    }
    fn to_canonical_json(&self) -> Result<Vec<u8>, CampaignError> {
        self.validate_document()?;
        to_canonical(self)
    }
    fn signature_metadata(&self) -> &SignatureMetadata {
        &self.signature
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DeletionDisposition {
    CampaignInvalidated,
    PublishedAggregatePreserved,
}

/// Resolves a verified deletion against one exact frozen campaign bundle.
///
/// # Errors
///
/// Returns `BundleUnsafe` when deletion is incomplete, signed by the operator,
/// affects another campaign or asset set, or references another publication.
pub fn resolve_deletion(
    bundle: &ValidatedFrozenBundle,
    record: Verified<DeletionRecord>,
    publication: Option<&ValidatedPublicationEligibility>,
) -> Result<DeletionDisposition, CampaignError> {
    let document = record.document();
    if !document.closes_retention()
        || record.signer() == &bundle.operator_fingerprint
        || document.campaign_sha256 != bundle.protocol_sha256
        || document.affected_asset_sha256 != bundle.asset_sha256
        || document.completed_at_unix < bundle.collection_closes_unix
        || publication.is_some_and(|authority| {
            authority.bundle_index_sha256 != bundle.bundle_index_sha256
                || authority.protocol_sha256 != bundle.protocol_sha256
                || authority.operator_fingerprint != bundle.operator_fingerprint
                || document.completed_at_unix < authority.validated_at_unix
        })
    {
        return Err(CampaignError::BundleUnsafe);
    }
    Ok(if publication.is_some() {
        DeletionDisposition::PublishedAggregatePreserved
    } else {
        DeletionDisposition::CampaignInvalidated
    })
}

#[cfg(test)]
mod tests {
    use serde_json::{json, Value};

    use super::*;
    use crate::{
        protocol::tests::{protocol_value, validate},
        verify_document, CampaignError, DetachedSignatureVerifier, Sha256Digest, SignerFingerprint,
        SignerRole,
    };

    const OPERATOR: &str = "BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB";

    struct AcceptOperator;

    impl DetachedSignatureVerifier for AcceptOperator {
        fn verify(
            &self,
            _canonical_payload: &[u8],
            _detached_signature: &[u8],
        ) -> Result<SignerFingerprint, CampaignError> {
            SignerFingerprint::new(OPERATOR)
        }
    }

    struct AcceptSigner(&'static str);

    impl DetachedSignatureVerifier for AcceptSigner {
        fn verify(
            &self,
            _canonical_payload: &[u8],
            _detached_signature: &[u8],
        ) -> Result<SignerFingerprint, CampaignError> {
            SignerFingerprint::new(self.0)
        }
    }

    fn digest(byte: &str) -> Value {
        json!(byte.repeat(64))
    }

    fn snapshot_value(protocol_sha256: &Sha256Digest) -> Value {
        let statuses = json!([
            {"status": "active", "token_sha256": digest("1")},
            {"status": "active", "token_sha256": digest("2")}
        ]);
        let token_set_sha256 =
            Sha256Digest::of(&serde_json::to_vec(&json!([digest("1"), digest("2")])).unwrap());
        json!({
            "aggregate_publication_acknowledged": false,
            "allowed_presentations": ["bona_fide", "display_replay", "no_face", "non_mated_live_cross_identity", "print"],
            "collection_closes_unix": 1788998400u64,
            "collection_opens_unix": 1788393600u64,
            "phase": "collection",
            "predecessor_sha256": null,
            "protocol_sha256": protocol_sha256.as_str(),
            "publication_boundary_acknowledged": false,
            "purpose": "camera-profile-release-qualification",
            "registry_revision": 1,
            "retention_expires_unix": 1790899200u64,
            "schema_version": 1,
            "signature": {"algorithm": "open_pgp", "role": "operator", "signer_fingerprint": OPERATOR},
            "statuses": statuses,
            "token_set_sha256": token_set_sha256.as_str()
        })
    }

    fn verified_snapshot(
        value: &Value,
    ) -> Result<crate::Verified<EligibilitySnapshot>, CampaignError> {
        let bytes = serde_json::to_vec(value).unwrap();
        let signer = SignerFingerprint::new(OPERATOR).unwrap();
        verify_document(
            &bytes,
            b"eligibility-signature",
            SignerRole::Operator,
            &signer,
            &AcceptOperator,
        )
    }

    fn verified_snapshot_as(
        value: &Value,
        signer_value: &'static str,
    ) -> Result<crate::Verified<EligibilitySnapshot>, CampaignError> {
        let bytes = serde_json::to_vec(value).unwrap();
        let signer = SignerFingerprint::new(signer_value).unwrap();
        verify_document(
            &bytes,
            b"eligibility-signature",
            SignerRole::Operator,
            &signer,
            &AcceptSigner(signer_value),
        )
    }

    fn verified_operator_document<T: CanonicalDocument>(
        value: &Value,
    ) -> Result<crate::Verified<T>, CampaignError> {
        let bytes = serde_json::to_vec(value).unwrap();
        let signer = SignerFingerprint::new(OPERATOR).unwrap();
        verify_document(
            &bytes,
            b"operator-signature",
            SignerRole::Operator,
            &signer,
            &AcceptOperator,
        )
    }

    fn verified_document_as<T: CanonicalDocument>(
        value: &Value,
        signer_value: &'static str,
    ) -> Result<crate::Verified<T>, CampaignError> {
        let bytes = serde_json::to_vec(value).unwrap();
        let signer = SignerFingerprint::new(signer_value).unwrap();
        verify_document(
            &bytes,
            b"document-signature",
            SignerRole::Operator,
            &signer,
            &AcceptSigner(signer_value),
        )
    }

    fn shard_value(protocol: &Value, protocol_sha256: &Sha256Digest) -> Value {
        let cases = protocol["cases"].as_array().unwrap();
        let hardware_scope_sha256 =
            Sha256Digest::of(&serde_json::to_vec(&protocol["hardware_scope"]).unwrap());
        let pairs: Vec<_> = cases
            .chunks_exact(2)
            .enumerate()
            .map(|(pair_position, pair)| {
                let side = |case: &Value, side_name: &str| {
                    let profile = &protocol[side_name];
                    let profile_sha256 =
                        Sha256Digest::of(&serde_json::to_vec(profile).unwrap());
                    json!({
                        "assets": [
                            {
                                "content_sha256": Sha256Digest::of(format!("{pair_position}-{side_name}-rgb").as_bytes()).as_str(),
                                "height": 1,
                                "path": format!("pair-{pair_position}/{side_name}-rgb.bin"),
                                "position": 0,
                                "role": "rgb",
                                "size_bytes": 1,
                                "width": 1
                            },
                            {
                                "content_sha256": Sha256Digest::of(format!("{pair_position}-{side_name}-ir").as_bytes()).as_str(),
                                "height": 1,
                                "path": format!("pair-{pair_position}/{side_name}-ir.bin"),
                                "position": 0,
                                "role": "ir",
                                "size_bytes": 1,
                                "width": 1
                            }
                        ],
                        "attempts": [{
                            "attempt_position": 0,
                            "conditioning_applied_sha256": profile["contracts"]["selected_policy_sha256"],
                            "conditioning_before_sha256": digest("b"),
                            "conditioning_restored_sha256": digest("b"),
                            "invalidated_pre_outcome": false,
                            "invalidation_code": null,
                            "outcome_recorded": true
                        }],
                        "capture_ended_unix": 1788500001u64,
                        "capture_provenance_sha256": Sha256Digest::of(format!("provenance-{pair_position}-{side_name}").as_bytes()).as_str(),
                        "capture_started_unix": 1788500000u64,
                        "captured_count": case["planned_count"],
                        "case_id": case["case_id"],
                        "expected_outcome": case["expected_outcome"],
                        "hardware_scope_sha256": hardware_scope_sha256.as_str(),
                        "order_position": case["order_position"],
                        "presentation_class": case["presentation_class"],
                        "profile_id": profile["profile_id"],
                        "profile_sha256": profile_sha256.as_str(),
                        "scene_id": case["scene_id"],
                        "source_revision": protocol["source_revision"],
                        "stratum_id": case["stratum_id"],
                        "token_sha256": if pair_position % 2 == 0 { digest("1") } else { digest("2") }
                    })
                };
                json!({
                    "baseline": side(&pair[0], "baseline"),
                    "candidate": side(&pair[1], "candidate"),
                    "logical_case_id": pair[0]["logical_case_id"]
                })
            })
            .collect();
        json!({
            "cases": pairs,
            "protocol_sha256": protocol_sha256.as_str(),
            "schema_version": 1,
            "shard_position": 0,
            "signature": {"algorithm": "open_pgp", "role": "operator", "signer_fingerprint": OPERATOR}
        })
    }

    fn freeze_bundle(
        protocol: &ValidatedProtocol,
        collection: &ValidatedCollectionEligibility,
        shard_value: &Value,
    ) -> Result<ValidatedFrozenBundle, CampaignError> {
        let shard = verified_operator_document::<CaptureShard>(shard_value)?;
        let index_value = json!({
            "collection_eligibility_sha256": collection.snapshot_sha256().as_str(),
            "ordered_shard_sha256": [shard.digest().as_str()],
            "protocol_sha256": protocol.protocol_sha256().as_str(),
            "schema_version": 1,
            "signature": {"algorithm": "open_pgp", "role": "operator", "signer_fingerprint": OPERATOR}
        });
        let index = verified_operator_document::<BundleIndex>(&index_value)?;
        validate_frozen_bundle(protocol, collection, index, vec![shard])
    }

    fn bundle_inputs() -> (ValidatedProtocol, ValidatedCollectionEligibility, Value) {
        let protocol_value = protocol_value();
        let protocol = validate(&protocol_value).unwrap();
        let collection_snapshot =
            verified_snapshot(&snapshot_value(protocol.protocol_sha256())).unwrap();
        let collection =
            validate_collection_eligibility(&protocol, collection_snapshot, 1788500000).unwrap();
        let shard = shard_value(&protocol_value, protocol.protocol_sha256());
        (protocol, collection, shard)
    }

    fn publication_inputs() -> (
        ValidatedEvaluationEligibility,
        crate::Verified<EligibilitySnapshot>,
    ) {
        let protocol = validate(&protocol_value()).unwrap();
        let collection_snapshot =
            verified_snapshot(&snapshot_value(protocol.protocol_sha256())).unwrap();
        let collection_digest = collection_snapshot.digest().clone();
        let collection =
            validate_collection_eligibility(&protocol, collection_snapshot, 1788500000).unwrap();
        let bundle = ValidatedFrozenBundle {
            allowed_presentations: collection.allowed_presentations.clone(),
            bundle_index_sha256: Sha256Digest::new(&"4".repeat(64)).unwrap(),
            collection_snapshot_sha256: collection_digest.clone(),
            protocol_sha256: protocol.protocol_sha256().clone(),
            token_set_sha256: collection.token_set_sha256().clone(),
            evaluation_not_after_unix: 1789603200,
            collection_closes_unix: collection.collection_closes_unix,
            collection_opens_unix: collection.collection_opens_unix,
            retention_expires_unix: collection.retention_expires_unix,
            review_not_after_unix: 1790208000,
            operator_fingerprint: collection.operator_fingerprint.clone(),
            asset_sha256: Vec::new(),
        };
        let mut evaluation_value = snapshot_value(protocol.protocol_sha256());
        evaluation_value["phase"] = json!("evaluation");
        evaluation_value["registry_revision"] = json!(2);
        evaluation_value["predecessor_sha256"] = json!(collection_digest.as_str());
        let evaluation_snapshot = verified_snapshot(&evaluation_value).unwrap();
        let evaluation_digest = evaluation_snapshot.digest().clone();
        let evaluation =
            validate_evaluation_eligibility(&bundle, evaluation_snapshot, 1789000000).unwrap();
        let mut publication_value = snapshot_value(protocol.protocol_sha256());
        publication_value["phase"] = json!("publication");
        publication_value["registry_revision"] = json!(3);
        publication_value["predecessor_sha256"] = json!(evaluation_digest.as_str());
        publication_value["aggregate_publication_acknowledged"] = json!(true);
        publication_value["publication_boundary_acknowledged"] = json!(true);
        (evaluation, verified_snapshot(&publication_value).unwrap())
    }

    #[test]
    fn eligibility_phases_and_statuses_are_closed() {
        assert_ne!(EligibilityPhase::Collection, EligibilityPhase::Evaluation);
        assert_ne!(EligibilityPhase::Evaluation, EligibilityPhase::Publication);
        assert_ne!(EligibilityStatus::Active, EligibilityStatus::Expired);
        assert_ne!(EligibilityStatus::Active, EligibilityStatus::Withdrawn);
    }

    #[test]
    fn eligibility_collection_requires_active_root_snapshot() {
        let protocol = validate(&protocol_value()).unwrap();
        let mut value = snapshot_value(protocol.protocol_sha256());
        let snapshot = verified_snapshot(&value).unwrap();
        assert!(validate_collection_eligibility(&protocol, snapshot, 1788500000).is_ok());

        value["predecessor_sha256"] = digest("4");
        let snapshot = verified_snapshot(&value).unwrap();
        assert_eq!(
            validate_collection_eligibility(&protocol, snapshot, 1788500000),
            Err(CampaignError::ConsentIneligible)
        );
    }

    #[test]
    fn eligibility_token_set_digest_does_not_change_with_status() {
        let protocol = validate(&protocol_value()).unwrap();
        let mut value = snapshot_value(protocol.protocol_sha256());
        value["statuses"][0]["status"] = json!("withdrawn");

        assert!(verified_snapshot(&value).is_ok());
    }

    #[test]
    fn eligibility_collection_requires_protocol_operator() {
        const OTHER_OPERATOR: &str = "DDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDD";
        let protocol = validate(&protocol_value()).unwrap();
        let mut value = snapshot_value(protocol.protocol_sha256());
        value["signature"]["signer_fingerprint"] = json!(OTHER_OPERATOR);
        let snapshot = verified_snapshot_as(&value, OTHER_OPERATOR).unwrap();

        assert_eq!(
            validate_collection_eligibility(&protocol, snapshot, 1788500000),
            Err(CampaignError::ConsentIneligible)
        );
    }

    #[test]
    fn eligibility_rejects_status_token_and_identity_integrity_failures() {
        let protocol = validate(&protocol_value()).unwrap();
        for status in ["expired", "withdrawn"] {
            let mut value = snapshot_value(protocol.protocol_sha256());
            value["statuses"][0]["status"] = json!(status);
            let snapshot = verified_snapshot(&value).unwrap();
            assert_eq!(
                validate_collection_eligibility(&protocol, snapshot, 1788500000),
                Err(CampaignError::ConsentIneligible),
                "{status}"
            );
        }

        let mut missing = snapshot_value(protocol.protocol_sha256());
        missing["statuses"].as_array_mut().unwrap().pop();
        assert_eq!(
            verified_snapshot(&missing),
            Err(CampaignError::ConsentIneligible)
        );

        let mut duplicate = snapshot_value(protocol.protocol_sha256());
        let duplicate_status = duplicate["statuses"][0].clone();
        duplicate["statuses"]
            .as_array_mut()
            .unwrap()
            .push(duplicate_status);
        duplicate["token_set_sha256"] = json!(Sha256Digest::of(
            &serde_json::to_vec(&json!([digest("1"), digest("2"), digest("1")])).unwrap()
        )
        .as_str());
        assert_eq!(
            verified_snapshot(&duplicate),
            Err(CampaignError::ConsentIneligible)
        );

        let mut identity = snapshot_value(protocol.protocol_sha256());
        identity["real_name"] = json!("must-not-appear");
        assert_eq!(
            verified_snapshot(&identity),
            Err(CampaignError::CanonicalInvalid)
        );
    }

    #[test]
    fn eligibility_rejects_purpose_class_window_and_retention_drift() {
        let protocol = validate(&protocol_value()).unwrap();
        for (field, value) in [
            ("purpose", json!("another-purpose")),
            ("allowed_presentations", json!(["bona_fide"])),
            ("collection_opens_unix", json!(1788393601u64)),
            ("collection_closes_unix", json!(1788998399u64)),
            ("retention_expires_unix", json!(1820534401u64)),
        ] {
            let mut snapshot_value = snapshot_value(protocol.protocol_sha256());
            snapshot_value[field] = value;
            let result = verified_snapshot(&snapshot_value).and_then(|snapshot| {
                validate_collection_eligibility(&protocol, snapshot, 1788500000).map(|_| ())
            });
            assert_eq!(result, Err(CampaignError::ConsentIneligible), "{field}");
        }
    }

    #[test]
    fn bundle_paths_are_strictly_relative_components() {
        assert!(valid_asset_path("shard-01/rgb/frame-001.bin"));
        for invalid in ["", "/absolute", ".", "..", "a/../b", "a//b", "a\\b", "a\0b"] {
            assert!(!valid_asset_path(invalid), "{invalid:?}");
        }
        assert!(!valid_asset_path(&"a".repeat(4097)));
    }

    #[test]
    fn bundle_asset_descriptor_rejects_unsafe_metadata() {
        let asset = AssetDescriptor {
            content_sha256: Sha256Digest::new(&"1".repeat(64)).unwrap(),
            height: 1,
            path: "../escape".to_owned(),
            position: 0,
            role: crate::StreamRole::Rgb,
            size_bytes: 1,
            width: 1,
        };
        assert_eq!(asset.validate(), Err(CampaignError::BundleUnsafe));
    }

    fn test_assets(role: StreamRole, count: u32, prefix: &str) -> Vec<AssetDescriptor> {
        (0..count)
            .map(|position| AssetDescriptor {
                content_sha256: Sha256Digest::of(format!("{prefix}-{position}").as_bytes()),
                height: 1,
                path: format!("{prefix}/{position}.bin"),
                position,
                role,
                size_bytes: 1,
                width: 1,
            })
            .collect()
    }

    fn test_side(id: &str, profile: &str, assets: Vec<AssetDescriptor>) -> CaseSideCapture {
        CaseSideCapture {
            assets,
            attempts: vec![AttemptRecord {
                attempt_position: 0,
                conditioning_applied_sha256: Sha256Digest::new(&"1".repeat(64)).unwrap(),
                conditioning_before_sha256: Sha256Digest::new(&"2".repeat(64)).unwrap(),
                conditioning_restored_sha256: Sha256Digest::new(&"2".repeat(64)).unwrap(),
                invalidated_pre_outcome: false,
                invalidation_code: None,
                outcome_recorded: true,
            }],
            capture_ended_unix: 2,
            capture_provenance_sha256: Sha256Digest::of(id.as_bytes()),
            capture_started_unix: 1,
            captured_count: 1,
            case_id: Identifier::new(id).unwrap(),
            expected_outcome: crate::ExpectedOutcome::Accept,
            hardware_scope_sha256: Sha256Digest::new(&"3".repeat(64)).unwrap(),
            order_position: CaptureOrderPosition::First,
            presentation_class: PresentationClass::BonaFide,
            profile_id: Identifier::new(profile).unwrap(),
            profile_sha256: Sha256Digest::new(&"4".repeat(64)).unwrap(),
            scene_id: Identifier::new("scene").unwrap(),
            source_revision: Sha256Digest::new(&"5".repeat(64)).unwrap(),
            stratum_id: Identifier::new("stratum").unwrap(),
            token_sha256: Sha256Digest::new(&"6".repeat(64)).unwrap(),
        }
    }

    #[test]
    fn bundle_rejects_more_than_32_assets_for_one_role() {
        let shard = CaptureShard {
            cases: vec![PairedCaseCapture {
                baseline: test_side(
                    "baseline",
                    "baseline-profile",
                    test_assets(StreamRole::Rgb, 33, "b"),
                ),
                candidate: test_side(
                    "candidate",
                    "candidate-profile",
                    test_assets(StreamRole::Ir, 1, "c"),
                ),
                logical_case_id: Identifier::new("logical").unwrap(),
            }],
            protocol_sha256: Sha256Digest::new(&"1".repeat(64)).unwrap(),
            schema_version: 1,
            shard_position: 0,
            signature: SignatureMetadata::new(
                SignerRole::Operator,
                SignerFingerprint::new(OPERATOR).unwrap(),
            ),
        };

        assert_eq!(shard.validate_document(), Err(CampaignError::BundleUnsafe));
    }

    #[test]
    fn bundle_rejects_repeat_cap_overflow() {
        let protocol_value = protocol_value();
        let protocol = validate(&protocol_value).unwrap();
        let collection_snapshot =
            verified_snapshot(&snapshot_value(protocol.protocol_sha256())).unwrap();
        let collection =
            validate_collection_eligibility(&protocol, collection_snapshot, 1788500000).unwrap();
        let mut shard = shard_value(&protocol_value, protocol.protocol_sha256());
        let completed = shard["cases"][0]["baseline"]["attempts"][0].clone();
        let invalidated = |position: u32| {
            let mut attempt = completed.clone();
            attempt["attempt_position"] = json!(position);
            attempt["invalidated_pre_outcome"] = json!(true);
            attempt["invalidation_code"] = json!("device_disconnect");
            attempt["outcome_recorded"] = json!(false);
            attempt
        };
        let mut final_attempt = completed.clone();
        final_attempt["attempt_position"] = json!(3);
        shard["cases"][0]["baseline"]["attempts"] = Value::Array(vec![
            invalidated(0),
            invalidated(1),
            invalidated(2),
            final_attempt,
        ]);

        assert_eq!(
            freeze_bundle(&protocol, &collection, &shard),
            Err(CampaignError::BundleUnsafe)
        );
    }

    #[test]
    fn bundle_accepts_exact_case_and_provenance_metadata() {
        let protocol_value = protocol_value();
        let protocol = validate(&protocol_value).unwrap();
        let collection_snapshot =
            verified_snapshot(&snapshot_value(protocol.protocol_sha256())).unwrap();
        let collection =
            validate_collection_eligibility(&protocol, collection_snapshot, 1788500000).unwrap();
        let shard = shard_value(&protocol_value, protocol.protocol_sha256());

        assert!(freeze_bundle(&protocol, &collection, &shard).is_ok());
    }

    #[test]
    fn bundle_rejects_missing_stream_role_assets() {
        let protocol_value = protocol_value();
        let protocol = validate(&protocol_value).unwrap();
        let collection_snapshot =
            verified_snapshot(&snapshot_value(protocol.protocol_sha256())).unwrap();
        let collection =
            validate_collection_eligibility(&protocol, collection_snapshot, 1788500000).unwrap();
        let mut shard = shard_value(&protocol_value, protocol.protocol_sha256());
        shard["cases"][0]["baseline"]["assets"]
            .as_array_mut()
            .unwrap()
            .pop();

        assert_eq!(
            freeze_bundle(&protocol, &collection, &shard),
            Err(CampaignError::CaptureIncomplete)
        );
    }

    #[test]
    fn bundle_rejects_profile_provenance_mismatch() {
        let protocol_value = protocol_value();
        let protocol = validate(&protocol_value).unwrap();
        let collection_snapshot =
            verified_snapshot(&snapshot_value(protocol.protocol_sha256())).unwrap();
        let collection =
            validate_collection_eligibility(&protocol, collection_snapshot, 1788500000).unwrap();
        let mut shard = shard_value(&protocol_value, protocol.protocol_sha256());
        shard["cases"][0]["baseline"]["profile_sha256"] = digest("f");

        assert_eq!(
            freeze_bundle(&protocol, &collection, &shard),
            Err(CampaignError::ProvenanceMismatch)
        );
    }

    #[test]
    fn bundle_rejects_conditioning_policy_provenance_mismatch() {
        let protocol_value = protocol_value();
        let protocol = validate(&protocol_value).unwrap();
        let collection_snapshot =
            verified_snapshot(&snapshot_value(protocol.protocol_sha256())).unwrap();
        let collection =
            validate_collection_eligibility(&protocol, collection_snapshot, 1788500000).unwrap();
        let mut shard = shard_value(&protocol_value, protocol.protocol_sha256());
        shard["cases"][0]["baseline"]["attempts"][0]["conditioning_applied_sha256"] = digest("f");

        assert_eq!(
            freeze_bundle(&protocol, &collection, &shard),
            Err(CampaignError::ProvenanceMismatch)
        );
    }

    #[test]
    fn bundle_requires_protocol_operator_for_every_signed_document() {
        const OTHER_OPERATOR: &str = "DDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDD";
        let protocol_value = protocol_value();
        let protocol = validate(&protocol_value).unwrap();
        let collection_snapshot =
            verified_snapshot(&snapshot_value(protocol.protocol_sha256())).unwrap();
        let collection =
            validate_collection_eligibility(&protocol, collection_snapshot, 1788500000).unwrap();
        let mut shard_value = shard_value(&protocol_value, protocol.protocol_sha256());
        shard_value["signature"]["signer_fingerprint"] = json!(OTHER_OPERATOR);
        let shard = verified_document_as::<CaptureShard>(&shard_value, OTHER_OPERATOR).unwrap();
        let index_value = json!({
            "collection_eligibility_sha256": collection.snapshot_sha256().as_str(),
            "ordered_shard_sha256": [shard.digest().as_str()],
            "protocol_sha256": protocol.protocol_sha256().as_str(),
            "schema_version": 1,
            "signature": {"algorithm": "open_pgp", "role": "operator", "signer_fingerprint": OPERATOR}
        });
        let index = verified_operator_document::<BundleIndex>(&index_value).unwrap();

        assert_eq!(
            validate_frozen_bundle(&protocol, &collection, index, vec![shard]),
            Err(CampaignError::BundleUnsafe)
        );
    }

    #[test]
    fn bundle_index_rejects_nonadjacent_duplicate_shard_digest() {
        let index = BundleIndex {
            collection_eligibility_sha256: Sha256Digest::new(&"1".repeat(64)).unwrap(),
            ordered_shard_sha256: vec![
                Sha256Digest::new(&"2".repeat(64)).unwrap(),
                Sha256Digest::new(&"3".repeat(64)).unwrap(),
                Sha256Digest::new(&"2".repeat(64)).unwrap(),
            ],
            protocol_sha256: Sha256Digest::new(&"4".repeat(64)).unwrap(),
            schema_version: 1,
            signature: SignatureMetadata::new(
                SignerRole::Operator,
                SignerFingerprint::new(OPERATOR).unwrap(),
            ),
        };

        assert_eq!(index.validate_document(), Err(CampaignError::BundleUnsafe));
    }

    #[test]
    fn bundle_rejects_token_outside_collection_eligibility() {
        let protocol_value = protocol_value();
        let protocol = validate(&protocol_value).unwrap();
        let collection_snapshot =
            verified_snapshot(&snapshot_value(protocol.protocol_sha256())).unwrap();
        let collection =
            validate_collection_eligibility(&protocol, collection_snapshot, 1788500000).unwrap();
        let mut shard = shard_value(&protocol_value, protocol.protocol_sha256());
        shard["cases"][0]["baseline"]["token_sha256"] = digest("f");
        shard["cases"][0]["candidate"]["token_sha256"] = digest("f");

        assert_eq!(
            freeze_bundle(&protocol, &collection, &shard),
            Err(CampaignError::ConsentIneligible)
        );
    }

    #[test]
    fn bundle_rejects_case_matrix_tampering() {
        let (protocol, collection, shard) = bundle_inputs();

        let mut missing = shard.clone();
        missing["cases"].as_array_mut().unwrap().pop();
        assert_eq!(
            freeze_bundle(&protocol, &collection, &missing),
            Err(CampaignError::CaptureIncomplete)
        );

        let mut reordered = shard.clone();
        reordered["cases"].as_array_mut().unwrap().swap(0, 1);
        assert_eq!(
            freeze_bundle(&protocol, &collection, &reordered),
            Err(CampaignError::CaptureIncomplete)
        );

        let mut wrong_outcome = shard;
        wrong_outcome["cases"][0]["baseline"]["expected_outcome"] = json!("reject");
        assert_eq!(
            freeze_bundle(&protocol, &collection, &wrong_outcome),
            Err(CampaignError::CaptureIncomplete)
        );

        let (_, _, mut wrong_count) = bundle_inputs();
        wrong_count["cases"][0]["baseline"]["captured_count"] = json!(39);
        assert_eq!(
            freeze_bundle(&protocol, &collection, &wrong_count),
            Err(CampaignError::CaptureIncomplete)
        );
    }

    #[test]
    fn bundle_rejects_asset_metadata_tampering() {
        let (protocol, collection, shard) = bundle_inputs();

        let mut oversized = shard.clone();
        oversized["cases"][0]["baseline"]["assets"][0]["size_bytes"] = json!(MAX_ASSET_BYTES + 1);
        assert_eq!(
            freeze_bundle(&protocol, &collection, &oversized),
            Err(CampaignError::BundleUnsafe)
        );

        let mut duplicate = shard.clone();
        duplicate["cases"][0]["candidate"]["assets"][0]["path"] =
            duplicate["cases"][0]["baseline"]["assets"][0]["path"].clone();
        duplicate["cases"][0]["candidate"]["assets"][0]["content_sha256"] =
            duplicate["cases"][0]["baseline"]["assets"][0]["content_sha256"].clone();
        assert_eq!(
            freeze_bundle(&protocol, &collection, &duplicate),
            Err(CampaignError::BundleUnsafe)
        );

        let mut uncertain_restoration = shard;
        uncertain_restoration["cases"][0]["baseline"]["attempts"][0]
            ["conditioning_restored_sha256"] = digest("f");
        assert_eq!(
            freeze_bundle(&protocol, &collection, &uncertain_restoration),
            Err(CampaignError::BundleUnsafe)
        );
    }

    #[test]
    fn bundle_rejects_index_digest_mismatch() {
        let (protocol, collection, shard_value) = bundle_inputs();
        let shard = verified_operator_document::<CaptureShard>(&shard_value).unwrap();
        let index_value = json!({
            "collection_eligibility_sha256": collection.snapshot_sha256().as_str(),
            "ordered_shard_sha256": [digest("f")],
            "protocol_sha256": protocol.protocol_sha256().as_str(),
            "schema_version": 1,
            "signature": {"algorithm": "open_pgp", "role": "operator", "signer_fingerprint": OPERATOR}
        });
        let index = verified_operator_document::<BundleIndex>(&index_value).unwrap();

        assert_eq!(
            validate_frozen_bundle(&protocol, &collection, index, vec![shard]),
            Err(CampaignError::BundleUnsafe)
        );
    }

    #[test]
    fn bundle_rejects_shard_bounds_and_duplicate_positions() {
        let (protocol, collection, shard) = bundle_inputs();

        let pair = PairedCaseCapture {
            baseline: test_side(
                "baseline",
                "baseline-profile",
                test_assets(StreamRole::Rgb, 1, "bound-b"),
            ),
            candidate: test_side(
                "candidate",
                "candidate-profile",
                test_assets(StreamRole::Ir, 1, "bound-c"),
            ),
            logical_case_id: Identifier::new("logical").unwrap(),
        };
        let too_many_cases = CaptureShard {
            cases: vec![pair; MAX_CAPTURE_SHARD_CASES + 1],
            protocol_sha256: protocol.protocol_sha256().clone(),
            schema_version: 1,
            shard_position: 0,
            signature: SignatureMetadata::new(
                SignerRole::Operator,
                SignerFingerprint::new(OPERATOR).unwrap(),
            ),
        };
        assert_eq!(
            too_many_cases.validate_document(),
            Err(CampaignError::BundleUnsafe)
        );

        let mut duplicate_position = shard;
        let mut duplicate_asset = duplicate_position["cases"][0]["baseline"]["assets"][0].clone();
        duplicate_asset["content_sha256"] = digest("e");
        duplicate_asset["path"] = json!("pair-0/duplicate-rgb.bin");
        duplicate_position["cases"][0]["baseline"]["assets"]
            .as_array_mut()
            .unwrap()
            .push(duplicate_asset);
        assert_eq!(
            freeze_bundle(&protocol, &collection, &duplicate_position),
            Err(CampaignError::BundleUnsafe)
        );
    }

    #[test]
    fn bundle_rejects_invalid_invalidation_history() {
        let protocol_value = protocol_value();
        let protocol = validate(&protocol_value).unwrap();
        let collection_snapshot =
            verified_snapshot(&snapshot_value(protocol.protocol_sha256())).unwrap();
        let collection =
            validate_collection_eligibility(&protocol, collection_snapshot, 1788500000).unwrap();

        let mut outcome_known = shard_value(&protocol_value, protocol.protocol_sha256());
        outcome_known["cases"][0]["baseline"]["attempts"][0]["invalidated_pre_outcome"] =
            json!(true);
        assert_eq!(
            freeze_bundle(&protocol, &collection, &outcome_known),
            Err(CampaignError::BundleUnsafe)
        );

        let mut no_completed_attempt = shard_value(&protocol_value, protocol.protocol_sha256());
        let mut invalidated = no_completed_attempt["cases"][0]["baseline"]["attempts"][0].clone();
        invalidated["invalidated_pre_outcome"] = json!(true);
        invalidated["invalidation_code"] = json!("device_disconnect");
        invalidated["outcome_recorded"] = json!(false);
        no_completed_attempt["cases"][0]["baseline"]["attempts"] = Value::Array(vec![invalidated]);
        assert_eq!(
            freeze_bundle(&protocol, &collection, &no_completed_attempt),
            Err(CampaignError::BundleUnsafe)
        );
    }

    #[test]
    fn bundle_rejects_multiple_outcome_recorded_attempts() {
        let (protocol, collection, mut shard) = bundle_inputs();
        let first = shard["cases"][0]["baseline"]["attempts"][0].clone();
        let mut second = first.clone();
        second["attempt_position"] = json!(1);
        shard["cases"][0]["baseline"]["attempts"] = Value::Array(vec![first, second]);

        assert_eq!(
            freeze_bundle(&protocol, &collection, &shard),
            Err(CampaignError::BundleUnsafe)
        );
    }

    #[test]
    fn eligibility_evaluation_rejects_changed_collection_window() {
        let protocol = validate(&protocol_value()).unwrap();
        let collection_snapshot =
            verified_snapshot(&snapshot_value(protocol.protocol_sha256())).unwrap();
        let collection_digest = collection_snapshot.digest().clone();
        let collection =
            validate_collection_eligibility(&protocol, collection_snapshot, 1788500000).unwrap();
        let bundle = ValidatedFrozenBundle {
            allowed_presentations: collection.allowed_presentations.clone(),
            bundle_index_sha256: Sha256Digest::new(&"4".repeat(64)).unwrap(),
            collection_snapshot_sha256: collection_digest.clone(),
            protocol_sha256: protocol.protocol_sha256().clone(),
            token_set_sha256: collection.token_set_sha256().clone(),
            evaluation_not_after_unix: 1789603200,
            collection_closes_unix: collection.collection_closes_unix,
            collection_opens_unix: collection.collection_opens_unix,
            retention_expires_unix: collection.retention_expires_unix,
            review_not_after_unix: 1790208000,
            operator_fingerprint: collection.operator_fingerprint.clone(),
            asset_sha256: Vec::new(),
        };
        let mut value = snapshot_value(protocol.protocol_sha256());
        value["phase"] = json!("evaluation");
        value["registry_revision"] = json!(2);
        value["predecessor_sha256"] = json!(collection_digest.as_str());
        value["collection_closes_unix"] = json!(1788998399u64);
        let evaluation = verified_snapshot(&value).unwrap();
        assert_eq!(
            validate_evaluation_eligibility(&bundle, evaluation, 1789000000),
            Err(CampaignError::ConsentIneligible)
        );
    }

    #[test]
    fn eligibility_evaluation_cannot_start_before_collection_closes() {
        let protocol = validate(&protocol_value()).unwrap();
        let collection_snapshot =
            verified_snapshot(&snapshot_value(protocol.protocol_sha256())).unwrap();
        let collection_digest = collection_snapshot.digest().clone();
        let collection =
            validate_collection_eligibility(&protocol, collection_snapshot, 1788500000).unwrap();
        let bundle = ValidatedFrozenBundle {
            allowed_presentations: collection.allowed_presentations.clone(),
            bundle_index_sha256: Sha256Digest::new(&"4".repeat(64)).unwrap(),
            collection_snapshot_sha256: collection_digest.clone(),
            protocol_sha256: protocol.protocol_sha256().clone(),
            token_set_sha256: collection.token_set_sha256().clone(),
            evaluation_not_after_unix: 1789603200,
            collection_closes_unix: collection.collection_closes_unix,
            collection_opens_unix: collection.collection_opens_unix,
            retention_expires_unix: collection.retention_expires_unix,
            review_not_after_unix: 1790208000,
            operator_fingerprint: collection.operator_fingerprint.clone(),
            asset_sha256: Vec::new(),
        };
        let mut value = snapshot_value(protocol.protocol_sha256());
        value["phase"] = json!("evaluation");
        value["registry_revision"] = json!(2);
        value["predecessor_sha256"] = json!(collection_digest.as_str());
        let evaluation = verified_snapshot(&value).unwrap();

        assert_eq!(
            validate_evaluation_eligibility(&bundle, evaluation, 1788998399),
            Err(CampaignError::ConsentIneligible)
        );
    }

    #[test]
    fn eligibility_publication_cannot_predate_evaluation_validation() {
        let (evaluation, publication) = publication_inputs();

        assert_eq!(
            validate_publication_eligibility(&evaluation, publication, 1788999999),
            Err(CampaignError::ConsentIneligible)
        );
    }

    #[test]
    fn eligibility_publication_respects_protocol_review_deadline() {
        let (evaluation, publication) = publication_inputs();
        assert_eq!(
            validate_publication_eligibility(&evaluation, publication, 1790208001),
            Err(CampaignError::ConsentIneligible)
        );
    }

    #[test]
    fn eligibility_publication_rejects_disconnected_revision_and_token_replacement() {
        let (evaluation, _) = publication_inputs();
        let publication_value = || {
            let mut value = snapshot_value(&evaluation.protocol_sha256);
            value["phase"] = json!("publication");
            value["registry_revision"] = json!(3);
            value["predecessor_sha256"] = json!(evaluation.snapshot_sha256().as_str());
            value["aggregate_publication_acknowledged"] = json!(true);
            value["publication_boundary_acknowledged"] = json!(true);
            value
        };

        let mut no_predecessor = publication_value();
        no_predecessor["predecessor_sha256"] = Value::Null;
        assert_eq!(
            validate_publication_eligibility(
                &evaluation,
                verified_snapshot(&no_predecessor).unwrap(),
                1790000000,
            ),
            Err(CampaignError::ConsentIneligible)
        );

        let mut wrong_revision = publication_value();
        wrong_revision["registry_revision"] = json!(4);
        assert_eq!(
            validate_publication_eligibility(
                &evaluation,
                verified_snapshot(&wrong_revision).unwrap(),
                1790000000,
            ),
            Err(CampaignError::ConsentIneligible)
        );

        let mut changed_tokens = publication_value();
        changed_tokens["statuses"][1]["token_sha256"] = digest("f");
        changed_tokens["token_set_sha256"] = json!(Sha256Digest::of(
            &serde_json::to_vec(&json!([digest("1"), digest("f")])).unwrap()
        )
        .as_str());
        assert_eq!(
            validate_publication_eligibility(
                &evaluation,
                verified_snapshot(&changed_tokens).unwrap(),
                1790000000,
            ),
            Err(CampaignError::ConsentIneligible)
        );
    }

    #[test]
    fn deletion_withdrawal_invalidates_before_publication_and_preserves_after() {
        const REVIEWER: &str = "EEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEE";
        let protocol_value = protocol_value();
        let protocol = validate(&protocol_value).unwrap();
        let collection_snapshot =
            verified_snapshot(&snapshot_value(protocol.protocol_sha256())).unwrap();
        let collection =
            validate_collection_eligibility(&protocol, collection_snapshot, 1788500000).unwrap();
        let shard_value = shard_value(&protocol_value, protocol.protocol_sha256());
        let mut affected: Vec<_> = shard_value["cases"]
            .as_array()
            .unwrap()
            .iter()
            .flat_map(|pair| [&pair["baseline"], &pair["candidate"]])
            .flat_map(|side| side["assets"].as_array().unwrap())
            .map(|asset| asset["content_sha256"].as_str().unwrap().to_owned())
            .collect();
        affected.sort();
        let bundle = freeze_bundle(&protocol, &collection, &shard_value).unwrap();
        let deletion_value = json!({
            "affected_asset_sha256": affected,
            "campaign_sha256": protocol.protocol_sha256().as_str(),
            "completed_at_unix": 1790300000u64,
            "reason": "withdrawal",
            "reviewer_fingerprint": REVIEWER,
            "signature": {"algorithm": "open_pgp", "role": "reviewer", "signer_fingerprint": REVIEWER},
            "status": "completed"
        });
        let deletion_bytes = serde_json::to_vec(&deletion_value).unwrap();
        let reviewer = SignerFingerprint::new(REVIEWER).unwrap();
        let verified_deletion = || {
            verify_document::<DeletionRecord>(
                &deletion_bytes,
                b"reviewer-signature",
                SignerRole::Reviewer,
                &reviewer,
                &AcceptSigner(REVIEWER),
            )
            .unwrap()
        };

        assert_eq!(
            resolve_deletion(&bundle, verified_deletion(), None).unwrap(),
            DeletionDisposition::CampaignInvalidated
        );

        let mut evaluation_value = snapshot_value(protocol.protocol_sha256());
        evaluation_value["phase"] = json!("evaluation");
        evaluation_value["registry_revision"] = json!(2);
        evaluation_value["predecessor_sha256"] = json!(bundle.collection_snapshot_sha256.as_str());
        let evaluation_snapshot = verified_snapshot(&evaluation_value).unwrap();
        let evaluation_digest = evaluation_snapshot.digest().clone();
        let evaluation =
            validate_evaluation_eligibility(&bundle, evaluation_snapshot, 1789000000).unwrap();
        let mut publication_value = snapshot_value(protocol.protocol_sha256());
        publication_value["phase"] = json!("publication");
        publication_value["registry_revision"] = json!(3);
        publication_value["predecessor_sha256"] = json!(evaluation_digest.as_str());
        publication_value["aggregate_publication_acknowledged"] = json!(true);
        publication_value["publication_boundary_acknowledged"] = json!(true);
        let publication = validate_publication_eligibility(
            &evaluation,
            verified_snapshot(&publication_value).unwrap(),
            1790000000,
        )
        .unwrap();
        assert_eq!(
            resolve_deletion(&bundle, verified_deletion(), Some(&publication)).unwrap(),
            DeletionDisposition::PublishedAggregatePreserved
        );
    }

    #[test]
    fn deletion_interrupted_failed_and_operator_signed_records_block_reuse() {
        const REVIEWER: &str = "EEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEE";
        let (protocol, collection, shard) = bundle_inputs();
        let bundle = freeze_bundle(&protocol, &collection, &shard).unwrap();

        for status in ["interrupted", "failed"] {
            let value = json!({
                "affected_asset_sha256": bundle.asset_sha256.iter().map(Sha256Digest::as_str).collect::<Vec<_>>(),
                "campaign_sha256": protocol.protocol_sha256().as_str(),
                "completed_at_unix": 1790300000u64,
                "reason": "expiry",
                "reviewer_fingerprint": REVIEWER,
                "signature": {"algorithm": "open_pgp", "role": "reviewer", "signer_fingerprint": REVIEWER},
                "status": status
            });
            let bytes = serde_json::to_vec(&value).unwrap();
            let reviewer = SignerFingerprint::new(REVIEWER).unwrap();
            let record = verify_document::<DeletionRecord>(
                &bytes,
                b"reviewer-signature",
                SignerRole::Reviewer,
                &reviewer,
                &AcceptSigner(REVIEWER),
            )
            .unwrap();
            assert_eq!(
                resolve_deletion(&bundle, record, None),
                Err(CampaignError::BundleUnsafe),
                "{status}"
            );
        }

        let operator_value = json!({
            "affected_asset_sha256": bundle.asset_sha256.iter().map(Sha256Digest::as_str).collect::<Vec<_>>(),
            "campaign_sha256": protocol.protocol_sha256().as_str(),
            "completed_at_unix": 1790300000u64,
            "reason": "campaign_invalidated",
            "reviewer_fingerprint": OPERATOR,
            "signature": {"algorithm": "open_pgp", "role": "reviewer", "signer_fingerprint": OPERATOR},
            "status": "completed"
        });
        let operator_bytes = serde_json::to_vec(&operator_value).unwrap();
        let operator = SignerFingerprint::new(OPERATOR).unwrap();
        let record = verify_document::<DeletionRecord>(
            &operator_bytes,
            b"operator-signature",
            SignerRole::Reviewer,
            &operator,
            &AcceptSigner(OPERATOR),
        )
        .unwrap();
        assert_eq!(
            resolve_deletion(&bundle, record, None),
            Err(CampaignError::BundleUnsafe)
        );
    }
}

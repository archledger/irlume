// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright the irlume contributors.

use std::cmp::Ordering;

use serde::{Deserialize, Serialize};

use crate::{
    canonical::private,
    minimum_paired_sample_size,
    policy::{parse_canonical, to_canonical},
    BinaryGate, CampaignError, CampaignPolicy, CanonicalDocument, ExpectedOutcome, Identifier,
    PaiSpecies, PresentationClass, RatePpb, Sha256Digest, SignatureMetadata,
    SignedRateDifferencePpb, SignerFingerprint, SignerRole, StratificationAxis, Verified,
    OVERALL_MARGIN_PPB, RATE_SCALE_PPB, STRATUM_MARGIN_PPB,
};

pub const CAMPAIGN_PROTOCOL_SCHEMA_VERSION: u32 = 1;
pub const HARDWARE_SCOPE_MATCH_POLICY_VERSION: u32 = 1;

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum StreamRole {
    Rgb,
    Ir,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum PixelFormat {
    Yuyv,
    Nv12,
    Grey8,
    Grey16,
}

impl PixelFormat {
    const fn supports(self, role: StreamRole) -> bool {
        matches!(
            (self, role),
            (Self::Yuyv | Self::Nv12, StreamRole::Rgb)
                | (Self::Grey8 | Self::Grey16, StreamRole::Ir)
        )
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum CaptureSchedule {
    Concurrent,
    Sequential,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct StreamContract {
    format: PixelFormat,
    height: u32,
    interval_denominator: u32,
    interval_numerator: u32,
    role: StreamRole,
    width: u32,
}

impl StreamContract {
    fn validate(&self, expected_role: StreamRole) -> Result<(), CampaignError> {
        if self.role != expected_role
            || !self.format.supports(self.role)
            || self.width == 0
            || self.height == 0
            || self.interval_numerator == 0
            || self.interval_denominator == 0
            || gcd(self.interval_numerator, self.interval_denominator) != 1
        {
            return Err(CampaignError::ProtocolInvalid);
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct RuntimeContractDigests {
    conditioning_catalog_sha256: Sha256Digest,
    model_contract_sha256: Sha256Digest,
    preprocessing_contract_sha256: Sha256Digest,
    producer_contract_sha256: Sha256Digest,
    selected_policy_sha256: Sha256Digest,
    software_contract_sha256: Sha256Digest,
    threshold_contract_sha256: Sha256Digest,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ProfileContract {
    accepted_ir: StreamContract,
    accepted_rgb: StreamContract,
    contracts: RuntimeContractDigests,
    profile_id: Identifier,
    requested_ir: StreamContract,
    requested_rgb: StreamContract,
    schedule: CaptureSchedule,
}

impl ProfileContract {
    fn validate(&self, contracts: &RuntimeContractDigests) -> Result<(), CampaignError> {
        self.accepted_ir.validate(StreamRole::Ir)?;
        self.accepted_rgb.validate(StreamRole::Rgb)?;
        self.requested_ir.validate(StreamRole::Ir)?;
        self.requested_rgb.validate(StreamRole::Rgb)?;
        if &self.contracts != contracts {
            return Err(CampaignError::ProtocolInvalid);
        }
        Ok(())
    }

    #[must_use]
    pub fn profile_id(&self) -> &Identifier {
        &self.profile_id
    }

    fn same_transport_as(&self, other: &Self) -> bool {
        self.accepted_ir == other.accepted_ir
            && self.accepted_rgb == other.accepted_rgb
            && self.requested_ir == other.requested_ir
            && self.requested_rgb == other.requested_rgb
            && self.schedule == other.schedule
    }

    pub(crate) fn lifecycle_sha256(&self) -> Result<Sha256Digest, CampaignError> {
        to_canonical(self).map(|bytes| Sha256Digest::of(&bytes))
    }

    pub(crate) const fn selected_policy_sha256(&self) -> &Sha256Digest {
        &self.contracts.selected_policy_sha256
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct HardwareScope {
    hardware_class: Identifier,
    interface_layout_sha256: Sha256Digest,
    ir_descriptor_sha256: Sha256Digest,
    match_policy_version: u32,
    rgb_descriptor_sha256: Sha256Digest,
}

impl HardwareScope {
    fn validate(&self) -> Result<(), CampaignError> {
        if self.match_policy_version != HARDWARE_SCOPE_MATCH_POLICY_VERSION
            || self.rgb_descriptor_sha256 == self.ir_descriptor_sha256
        {
            return Err(CampaignError::ProtocolInvalid);
        }
        Ok(())
    }

    #[must_use]
    pub fn hardware_class(&self) -> &Identifier {
        &self.hardware_class
    }

    pub(crate) fn lifecycle_sha256(&self) -> Result<Sha256Digest, CampaignError> {
        to_canonical(self).map(|bytes| Sha256Digest::of(&bytes))
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct OperatingPoint {
    gate: BinaryGate,
    operating_point_id: Identifier,
    threshold_ppb: RatePpb,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct StratumPlan {
    axis: StratificationAxis,
    category: Identifier,
    minimum_cases: u32,
    stratum_id: Identifier,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
enum ProfileSide {
    Baseline,
    Candidate,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
enum OrderPosition {
    First,
    Second,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
enum ReferenceRelation {
    Mated,
    NoReference,
    NonMated,
    PaiInstrument,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct CasePlan {
    case_id: Identifier,
    collection_block: Identifier,
    expected_outcome: ExpectedOutcome,
    logical_case_id: Identifier,
    order_position: OrderPosition,
    pai_instrument_id: Option<Identifier>,
    pai_production_method: Option<Identifier>,
    pai_species: Option<PaiSpecies>,
    planned_count: u32,
    presentation_class: PresentationClass,
    profile_side: ProfileSide,
    reference_relation: ReferenceRelation,
    scene_id: Identifier,
    stratum_id: Identifier,
}

impl CasePlan {
    fn validate(&self) -> Result<(), CampaignError> {
        let expected = if self.presentation_class == PresentationClass::BonaFide {
            ExpectedOutcome::Accept
        } else {
            ExpectedOutcome::Reject
        };
        let expected_pai = match self.presentation_class {
            PresentationClass::DisplayReplay => Some(PaiSpecies::DisplayReplay),
            PresentationClass::Print => Some(PaiSpecies::Print),
            _ => None,
        };
        let expected_reference = match self.presentation_class {
            PresentationClass::BonaFide => ReferenceRelation::Mated,
            PresentationClass::NonMatedLiveCrossIdentity => ReferenceRelation::NonMated,
            PresentationClass::NoFace => ReferenceRelation::NoReference,
            PresentationClass::DisplayReplay | PresentationClass::Print => {
                ReferenceRelation::PaiInstrument
            }
        };
        let pai_metadata_matches = if expected_pai.is_some() {
            self.pai_instrument_id.is_some() && self.pai_production_method.is_some()
        } else {
            self.pai_instrument_id.is_none() && self.pai_production_method.is_none()
        };
        if self.planned_count == 0
            || self.expected_outcome != expected
            || self.pai_species != expected_pai
            || self.reference_relation != expected_reference
            || !pai_metadata_matches
        {
            return Err(CampaignError::ProtocolInvalid);
        }
        Ok(())
    }

    fn matches_logical_case(&self, other: &Self) -> bool {
        self.collection_block == other.collection_block
            && self.expected_outcome == other.expected_outcome
            && self.logical_case_id == other.logical_case_id
            && self.pai_instrument_id == other.pai_instrument_id
            && self.pai_production_method == other.pai_production_method
            && self.pai_species == other.pai_species
            && self.planned_count == other.planned_count
            && self.presentation_class == other.presentation_class
            && self.reference_relation == other.reference_relation
            && self.scene_id == other.scene_id
            && self.stratum_id == other.stratum_id
    }

    pub(crate) const fn case_id(&self) -> &Identifier {
        &self.case_id
    }
    pub(crate) const fn logical_case_id(&self) -> &Identifier {
        &self.logical_case_id
    }
    pub(crate) const fn expected_outcome(&self) -> ExpectedOutcome {
        self.expected_outcome
    }
    pub(crate) const fn is_baseline(&self) -> bool {
        matches!(self.profile_side, ProfileSide::Baseline)
    }
    pub(crate) const fn is_first(&self) -> bool {
        matches!(self.order_position, OrderPosition::First)
    }
    pub(crate) const fn presentation_class(&self) -> PresentationClass {
        self.presentation_class
    }
    pub(crate) const fn scene_id(&self) -> &Identifier {
        &self.scene_id
    }
    pub(crate) const fn stratum_id(&self) -> &Identifier {
        &self.stratum_id
    }
    pub(crate) const fn planned_count(&self) -> u32 {
        self.planned_count
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct PilotDiscordance {
    baseline_only_success_ppb: RatePpb,
    candidate_only_success_ppb: RatePpb,
    gate: BinaryGate,
    stratum_id: Option<Identifier>,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
enum SampleStoppingRule {
    LockedSampleNoOptionalStopping,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct LockedSampleSize {
    gate: BinaryGate,
    margin_ppb: SignedRateDifferencePpb,
    planned_power_ppb: RatePpb,
    required_cases: u32,
    stopping_rule: SampleStoppingRule,
    stratum_id: Option<Identifier>,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
enum InvalidationDetectionPhase {
    PreOutcome,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct EquipmentInvalidation {
    code: Identifier,
    detection_phase: InvalidationDetectionPhase,
    maximum_repeats: u32,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct PublicRegressionEvidence {
    content_sha256: Sha256Digest,
    license_id: Identifier,
    mirror_id: Identifier,
    model_calibration_result_sha256: Sha256Digest,
    operating_point_id: Identifier,
    source_url: Identifier,
}

impl PublicRegressionEvidence {
    fn validate(&self, operating_points: &[OperatingPoint]) -> Result<(), CampaignError> {
        if !self.source_url.as_str().starts_with("https://")
            || !operating_points
                .iter()
                .any(|point| point.operating_point_id == self.operating_point_id)
        {
            return Err(CampaignError::ProtocolInvalid);
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct CampaignProtocol {
    balanced_order_seed: Sha256Digest,
    baseline: ProfileContract,
    campaign_id: Identifier,
    candidate: ProfileContract,
    cases: Vec<CasePlan>,
    collection_not_after_unix: u64,
    collection_not_before_unix: u64,
    contracts: RuntimeContractDigests,
    created_at_unix: u64,
    equipment_invalidations: Vec<EquipmentInvalidation>,
    evaluation_not_after_unix: u64,
    evaluator_build_sha256: Sha256Digest,
    expires_at_unix: u64,
    hardware_scope: HardwareScope,
    locked_sample_sizes: Vec<LockedSampleSize>,
    operating_points: Vec<OperatingPoint>,
    operator_fingerprint: SignerFingerprint,
    pilot_discordance: Vec<PilotDiscordance>,
    policy_id: Identifier,
    policy_sha256: Sha256Digest,
    public_regression_evidence: Vec<PublicRegressionEvidence>,
    review_not_after_unix: u64,
    schema_version: u32,
    signature: SignatureMetadata,
    source_revision: Sha256Digest,
    strata: Vec<StratumPlan>,
}

impl CampaignProtocol {
    fn validate_structure(&self) -> Result<(), CampaignError> {
        if self.schema_version != CAMPAIGN_PROTOCOL_SCHEMA_VERSION
            || self.signature.role() != SignerRole::ProtocolAuthor
            || self.signature.signer_fingerprint() == &self.operator_fingerprint
            || self.baseline == self.candidate
            || self.baseline.profile_id == self.candidate.profile_id
            || self.baseline.same_transport_as(&self.candidate)
            || !(self.created_at_unix < self.collection_not_before_unix
                && self.collection_not_before_unix <= self.collection_not_after_unix
                && self.collection_not_after_unix <= self.evaluation_not_after_unix
                && self.evaluation_not_after_unix <= self.review_not_after_unix
                && self.review_not_after_unix <= self.expires_at_unix)
        {
            return Err(CampaignError::ProtocolInvalid);
        }
        self.hardware_scope.validate()?;
        self.baseline.validate(&self.contracts)?;
        self.candidate.validate(&self.contracts)?;
        validate_operating_points(&self.operating_points)?;
        validate_strata_order(&self.strata)?;
        validate_cases(&self.cases, &self.strata)?;
        validate_sample_matrix(
            &self.pilot_discordance,
            &self.locked_sample_sizes,
            &self.strata,
        )?;
        if !strictly_sorted_by(&self.equipment_invalidations, |left, right| {
            left.code.cmp(&right.code)
        }) || self
            .equipment_invalidations
            .iter()
            .any(|rule| rule.maximum_repeats == 0)
        {
            return Err(CampaignError::ProtocolInvalid);
        }
        if !strictly_sorted_by(&self.public_regression_evidence, |left, right| {
            left.content_sha256.cmp(&right.content_sha256)
        }) {
            return Err(CampaignError::ProtocolInvalid);
        }
        for evidence in &self.public_regression_evidence {
            evidence.validate(&self.operating_points)?;
        }
        Ok(())
    }

    #[must_use]
    pub fn campaign_id(&self) -> &Identifier {
        &self.campaign_id
    }

    #[must_use]
    pub fn hardware_scope(&self) -> &HardwareScope {
        &self.hardware_scope
    }

    #[must_use]
    pub fn baseline(&self) -> &ProfileContract {
        &self.baseline
    }

    #[must_use]
    pub fn candidate(&self) -> &ProfileContract {
        &self.candidate
    }

    pub(crate) const fn collection_not_before_unix(&self) -> u64 {
        self.collection_not_before_unix
    }

    pub(crate) const fn collection_not_after_unix(&self) -> u64 {
        self.collection_not_after_unix
    }

    pub(crate) const fn evaluation_not_after_unix(&self) -> u64 {
        self.evaluation_not_after_unix
    }

    pub(crate) const fn review_not_after_unix(&self) -> u64 {
        self.review_not_after_unix
    }

    pub(crate) const fn operator_fingerprint(&self) -> &SignerFingerprint {
        &self.operator_fingerprint
    }

    pub(crate) const fn expires_at_unix(&self) -> u64 {
        self.expires_at_unix
    }

    pub(crate) fn cases(&self) -> &[CasePlan] {
        &self.cases
    }

    pub(crate) fn maximum_repeats(&self, code: &Identifier) -> Option<u32> {
        self.equipment_invalidations
            .iter()
            .find(|rule| &rule.code == code)
            .map(|rule| rule.maximum_repeats)
    }

    pub(crate) const fn source_revision(&self) -> &Sha256Digest {
        &self.source_revision
    }
}

impl private::Sealed for CampaignProtocol {}

impl CanonicalDocument for CampaignProtocol {
    fn from_canonical_json(bytes: &[u8]) -> Result<Self, CampaignError> {
        let protocol: Self = parse_canonical(bytes)?;
        protocol.validate_structure()?;
        Ok(protocol)
    }

    fn to_canonical_json(&self) -> Result<Vec<u8>, CampaignError> {
        self.validate_structure()?;
        to_canonical(self)
    }

    fn signature_metadata(&self) -> &SignatureMetadata {
        &self.signature
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ValidatedProtocol {
    protocol: Verified<CampaignProtocol>,
    policy_sha256: Sha256Digest,
}

impl ValidatedProtocol {
    /// Binds one verified protocol to the exact verified policy it inherits.
    ///
    /// # Errors
    ///
    /// Returns `ProtocolInvalid` when any policy, hardware, lifetime, stratum,
    /// sample-size, repeat, signer, or case-matrix binding differs.
    pub fn new(
        policy: &Verified<CampaignPolicy>,
        protocol: Verified<CampaignProtocol>,
    ) -> Result<Self, CampaignError> {
        let document = protocol.document();
        if document.policy_id != *policy.document().policy_id()
            || document.policy_sha256 != *policy.digest()
            || !policy
                .document()
                .permits_hardware_class(&document.hardware_scope.hardware_class)
            || document
                .expires_at_unix
                .checked_sub(document.created_at_unix)
                .is_none_or(|duration| duration > policy.document().protocol_expiry_seconds())
            || document
                .equipment_invalidations
                .iter()
                .any(|rule| rule.maximum_repeats > policy.document().allowed_equipment_repeats())
        {
            return Err(CampaignError::ProtocolInvalid);
        }
        validate_policy_strata(policy.document(), &document.strata)?;
        validate_locked_samples_against_policy(policy.document(), document)?;
        Ok(Self {
            policy_sha256: policy.digest().clone(),
            protocol,
        })
    }

    #[must_use]
    pub fn protocol(&self) -> &CampaignProtocol {
        self.protocol.document()
    }

    #[must_use]
    pub fn protocol_sha256(&self) -> &Sha256Digest {
        self.protocol.digest()
    }

    #[must_use]
    pub const fn policy_sha256(&self) -> &Sha256Digest {
        &self.policy_sha256
    }
}

fn validate_operating_points(points: &[OperatingPoint]) -> Result<(), CampaignError> {
    let required = [
        BinaryGate::Detection,
        BinaryGate::IrPad,
        BinaryGate::Liveness,
        BinaryGate::Recognition,
        BinaryGate::RgbPad,
    ];
    if points.len() != required.len()
        || !points
            .iter()
            .zip(required)
            .all(|(point, gate)| point.gate == gate)
    {
        return Err(CampaignError::ProtocolInvalid);
    }
    Ok(())
}

fn validate_strata_order(strata: &[StratumPlan]) -> Result<(), CampaignError> {
    if strata.is_empty()
        || !strictly_sorted_by(strata, |left, right| left.stratum_id.cmp(&right.stratum_id))
        || strata.iter().any(|stratum| stratum.minimum_cases == 0)
    {
        return Err(CampaignError::ProtocolInvalid);
    }
    Ok(())
}

fn validate_cases(cases: &[CasePlan], strata: &[StratumPlan]) -> Result<(), CampaignError> {
    if cases.len()
        != strata
            .len()
            .checked_mul(2)
            .ok_or(CampaignError::ProtocolInvalid)?
        || !strictly_sorted_by(cases, |left, right| left.case_id.cmp(&right.case_id))
    {
        return Err(CampaignError::ProtocolInvalid);
    }
    let mut baseline_first = 0usize;
    let mut candidate_first = 0usize;
    for pair in cases.chunks_exact(2) {
        let left = &pair[0];
        let right = &pair[1];
        left.validate()?;
        right.validate()?;
        if !left.matches_logical_case(right)
            || left.profile_side != ProfileSide::Baseline
            || right.profile_side != ProfileSide::Candidate
            || left.order_position == right.order_position
            || !strata.iter().any(|stratum| {
                stratum.stratum_id == left.stratum_id && left.planned_count >= stratum.minimum_cases
            })
        {
            return Err(CampaignError::ProtocolInvalid);
        }
        if left.order_position == OrderPosition::First {
            baseline_first += 1;
        } else {
            candidate_first += 1;
        }
    }
    if baseline_first != candidate_first
        || strata.iter().any(|stratum| {
            !cases
                .iter()
                .any(|case| case.stratum_id == stratum.stratum_id)
        })
    {
        return Err(CampaignError::ProtocolInvalid);
    }
    let required_presentations = [
        PresentationClass::BonaFide,
        PresentationClass::DisplayReplay,
        PresentationClass::NoFace,
        PresentationClass::NonMatedLiveCrossIdentity,
        PresentationClass::Print,
    ];
    if required_presentations.iter().any(|required| {
        !cases
            .iter()
            .any(|case| case.presentation_class == *required)
    }) {
        return Err(CampaignError::ProtocolInvalid);
    }
    Ok(())
}

fn validate_sample_matrix(
    pilot: &[PilotDiscordance],
    samples: &[LockedSampleSize],
    strata: &[StratumPlan],
) -> Result<(), CampaignError> {
    let expected_len = 5usize
        .checked_mul(strata.len() + 1)
        .ok_or(CampaignError::ProtocolInvalid)?;
    if pilot.len() != expected_len
        || samples.len() != expected_len
        || !strictly_sorted_by(pilot, |left, right| {
            sample_key(left.gate, &left.stratum_id).cmp(&sample_key(right.gate, &right.stratum_id))
        })
        || !strictly_sorted_by(samples, |left, right| {
            sample_key(left.gate, &left.stratum_id).cmp(&sample_key(right.gate, &right.stratum_id))
        })
        || !pilot.iter().zip(samples).all(|(pilot, sample)| {
            pilot.gate == sample.gate && pilot.stratum_id == sample.stratum_id
        })
        || pilot.iter().any(|estimate| {
            estimate
                .baseline_only_success_ppb
                .get()
                .checked_add(estimate.candidate_only_success_ppb.get())
                .is_none_or(|sum| sum > RATE_SCALE_PPB)
        })
    {
        return Err(CampaignError::ProtocolInvalid);
    }
    Ok(())
}

fn validate_policy_strata(
    policy: &CampaignPolicy,
    strata: &[StratumPlan],
) -> Result<(), CampaignError> {
    if strata.len() != policy.stratum_count() {
        return Err(CampaignError::ProtocolInvalid);
    }
    for stratum in strata {
        if policy.stratum_minimum(stratum.axis, &stratum.category) != Some(stratum.minimum_cases) {
            return Err(CampaignError::ProtocolInvalid);
        }
    }
    Ok(())
}

fn validate_locked_samples_against_policy(
    _policy: &CampaignPolicy,
    protocol: &CampaignProtocol,
) -> Result<(), CampaignError> {
    let overall_capture_target = protocol
        .cases
        .iter()
        .filter(|case| case.is_baseline())
        .try_fold(0u64, |sum, case| {
            sum.checked_add(u64::from(case.planned_count))
        })
        .ok_or(CampaignError::ProtocolInvalid)?;
    for (pilot, sample) in protocol
        .pilot_discordance
        .iter()
        .zip(&protocol.locked_sample_sizes)
    {
        let (expected_margin, capture_target) = match &sample.stratum_id {
            None => (OVERALL_MARGIN_PPB, overall_capture_target),
            Some(stratum_id) => {
                let case = protocol
                    .cases
                    .iter()
                    .find(|case| case.is_baseline() && &case.stratum_id == stratum_id)
                    .ok_or(CampaignError::ProtocolInvalid)?;
                (STRATUM_MARGIN_PPB, u64::from(case.planned_count))
            }
        };
        let margin_ppb = RatePpb::new(expected_margin.unsigned_abs())?;
        let power = minimum_paired_sample_size(
            pilot.candidate_only_success_ppb,
            pilot.baseline_only_success_ppb,
            margin_ppb,
        )?;
        if sample.margin_ppb.get() != expected_margin
            || u64::from(sample.required_cases) < power.minimum_pairs()
            || u64::from(sample.required_cases) > capture_target
            || sample.planned_power_ppb != power.target_power_ppb()
        {
            return Err(CampaignError::ProtocolInvalid);
        }
    }
    Ok(())
}

fn sample_key(gate: BinaryGate, stratum_id: &Option<Identifier>) -> (BinaryGate, Option<&str>) {
    (gate, stratum_id.as_ref().map(Identifier::as_str))
}

fn strictly_sorted_by<T>(values: &[T], mut compare: impl FnMut(&T, &T) -> Ordering) -> bool {
    values
        .windows(2)
        .all(|pair| compare(&pair[0], &pair[1]) == Ordering::Less)
}

const fn gcd(mut left: u32, mut right: u32) -> u32 {
    while right != 0 {
        let remainder = left % right;
        left = right;
        right = remainder;
    }
    left
}

#[cfg(test)]
pub(crate) mod tests {
    use serde_json::{json, Value};

    use super::*;
    use crate::{
        policy::tests::policy_value, verify_document, CampaignError, CampaignPolicy,
        DetachedSignatureVerifier, Sha256Digest, SignerFingerprint, SignerRole,
    };

    const POLICY_AUTHOR: &str = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";
    const OPERATOR: &str = "BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB";
    const PROTOCOL_AUTHOR: &str = "CCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCC";

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

    fn stream(role: &str, format: &str, interval_denominator: u32) -> Value {
        json!({
            "format": format,
            "height": if role == "rgb" { 480 } else { 400 },
            "interval_denominator": interval_denominator,
            "interval_numerator": 1,
            "role": role,
            "width": 640
        })
    }

    fn contracts() -> Value {
        json!({
            "conditioning_catalog_sha256": digest("1"),
            "model_contract_sha256": digest("2"),
            "preprocessing_contract_sha256": digest("3"),
            "producer_contract_sha256": digest("4"),
            "selected_policy_sha256": digest("5"),
            "software_contract_sha256": digest("6"),
            "threshold_contract_sha256": digest("7")
        })
    }

    fn profile(id: &str, rgb_interval_denominator: u32) -> Value {
        json!({
            "accepted_ir": stream("ir", "grey8", 15),
            "accepted_rgb": stream("rgb", "yuyv", rgb_interval_denominator),
            "contracts": contracts(),
            "profile_id": id,
            "requested_ir": stream("ir", "grey8", 15),
            "requested_rgb": stream("rgb", "yuyv", rgb_interval_denominator),
            "schedule": "concurrent"
        })
    }

    fn strata() -> Vec<Value> {
        let policy = policy_value();
        let mut strata = Vec::new();
        for field in ["demographic_axes", "operational_axes"] {
            for axis in policy[field].as_array().unwrap() {
                for category in axis["categories"].as_array().unwrap() {
                    let axis_name = axis["axis"].as_str().unwrap();
                    let category_name = category.as_str().unwrap();
                    strata.push(json!({
                        "axis": axis_name,
                        "category": category_name,
                        "minimum_cases": axis["minimum_cases"],
                        "stratum_id": format!("{axis_name}-{category_name}")
                    }));
                }
            }
        }
        strata.sort_by(|left, right| {
            left["stratum_id"]
                .as_str()
                .cmp(&right["stratum_id"].as_str())
        });
        strata
    }

    fn cases(strata: &[Value]) -> Vec<Value> {
        let presentations = [
            ("bona_fide", None, "accept"),
            ("display_replay", Some("display_replay"), "reject"),
            ("no_face", None, "reject"),
            ("non_mated_live_cross_identity", None, "reject"),
            ("print", Some("print"), "reject"),
        ];
        let mut cases = Vec::new();
        for (index, stratum) in strata.iter().enumerate() {
            let (presentation, pai_species, expected) = presentations[index % presentations.len()];
            let reference_relation = match presentation {
                "bona_fide" => "mated",
                "non_mated_live_cross_identity" => "non_mated",
                "no_face" => "no_reference",
                _ => "pai_instrument",
            };
            let logical_id = format!("logical-{index:02}");
            for (side, position) in if index % 2 == 0 {
                [("baseline", "first"), ("candidate", "second")]
            } else {
                [("baseline", "second"), ("candidate", "first")]
            } {
                cases.push(json!({
                    "case_id": format!("{logical_id}-{side}"),
                    "collection_block": format!("block-{index:02}"),
                    "expected_outcome": expected,
                    "logical_case_id": logical_id,
                    "order_position": position,
                    "pai_instrument_id": pai_species.map(|_| format!("instrument-{index:02}")),
                    "pai_production_method": pai_species.map(|_| "protocol-declared-2d-production"),
                    "pai_species": pai_species,
                    "planned_count": 99,
                    "presentation_class": presentation,
                    "profile_side": side,
                    "reference_relation": reference_relation,
                    "scene_id": "ordinary-frontal",
                    "stratum_id": stratum["stratum_id"]
                }));
            }
        }
        cases.sort_by(|left, right| left["case_id"].as_str().cmp(&right["case_id"].as_str()));
        cases
    }

    fn pilot_and_samples(strata: &[Value]) -> (Vec<Value>, Vec<Value>) {
        let gates = ["detection", "ir_pad", "liveness", "recognition", "rgb_pad"];
        let mut pilot = Vec::new();
        let mut samples = Vec::new();
        for gate in gates {
            pilot.push(json!({
                "baseline_only_success_ppb": 20000000,
                "candidate_only_success_ppb": 20000000,
                "gate": gate,
                "stratum_id": null
            }));
            samples.push(json!({
                "gate": gate,
                "margin_ppb": -20000000,
                "planned_power_ppb": 800000000,
                "required_cases": 619,
                "stopping_rule": "locked_sample_no_optional_stopping",
                "stratum_id": null
            }));
            for stratum in strata {
                pilot.push(json!({
                    "baseline_only_success_ppb": 20000000,
                    "candidate_only_success_ppb": 20000000,
                    "gate": gate,
                    "stratum_id": stratum["stratum_id"]
                }));
                samples.push(json!({
                    "gate": gate,
                    "margin_ppb": -50000000,
                    "planned_power_ppb": 800000000,
                    "required_cases": 99,
                    "stopping_rule": "locked_sample_no_optional_stopping",
                    "stratum_id": stratum["stratum_id"]
                }));
            }
        }
        (pilot, samples)
    }

    fn policy_bytes() -> Vec<u8> {
        serde_json::to_vec(&policy_value()).unwrap()
    }

    pub(crate) fn protocol_value() -> Value {
        let policy = policy_bytes();
        let strata = strata();
        let cases = cases(&strata);
        let (pilot_discordance, locked_sample_sizes) = pilot_and_samples(&strata);
        json!({
            "balanced_order_seed": digest("8"),
            "baseline": profile("baseline-30fps", 30),
            "campaign_id": "campaign-2026-09-02-a",
            "candidate": profile("candidate-15fps", 15),
            "cases": cases,
            "collection_not_after_unix": 1788998400u64,
            "collection_not_before_unix": 1788393600u64,
            "contracts": contracts(),
            "created_at_unix": 1788307200u64,
            "equipment_invalidations": [
                {"code": "device_disconnect", "detection_phase": "pre_outcome", "maximum_repeats": 2}
            ],
            "evaluation_not_after_unix": 1789603200u64,
            "evaluator_build_sha256": digest("9"),
            "expires_at_unix": 1790899200u64,
            "hardware_scope": {
                "hardware_class": "usb-rgb-ir-v1",
                "interface_layout_sha256": digest("a"),
                "ir_descriptor_sha256": digest("b"),
                "match_policy_version": 1,
                "rgb_descriptor_sha256": digest("c")
            },
            "locked_sample_sizes": locked_sample_sizes,
            "operating_points": [
                {"gate": "detection", "operating_point_id": "detection-v1", "threshold_ppb": 500000000},
                {"gate": "ir_pad", "operating_point_id": "ir-pad-v1", "threshold_ppb": 500000000},
                {"gate": "liveness", "operating_point_id": "liveness-v1", "threshold_ppb": 500000000},
                {"gate": "recognition", "operating_point_id": "recognition-v1", "threshold_ppb": 500000000},
                {"gate": "rgb_pad", "operating_point_id": "rgb-pad-v1", "threshold_ppb": 500000000}
            ],
            "operator_fingerprint": OPERATOR,
            "pilot_discordance": pilot_discordance,
            "policy_id": "maintainer-camera-profile-v1",
            "policy_sha256": Sha256Digest::of(&policy).as_str(),
            "public_regression_evidence": [],
            "review_not_after_unix": 1790208000u64,
            "schema_version": 1,
            "signature": {
                "algorithm": "open_pgp",
                "role": "protocol_author",
                "signer_fingerprint": PROTOCOL_AUTHOR
            },
            "source_revision": digest("d"),
            "strata": strata
        })
    }

    fn verified_policy() -> crate::Verified<CampaignPolicy> {
        let bytes = policy_bytes();
        let signer = SignerFingerprint::new(POLICY_AUTHOR).unwrap();
        verify_document(
            &bytes,
            b"policy-signature",
            SignerRole::PolicyAuthor,
            &signer,
            &AcceptSigner(POLICY_AUTHOR),
        )
        .unwrap()
    }

    fn verified_protocol(
        value: &Value,
    ) -> Result<crate::Verified<CampaignProtocol>, CampaignError> {
        let bytes = serde_json::to_vec(value).unwrap();
        let signer = SignerFingerprint::new(PROTOCOL_AUTHOR).unwrap();
        verify_document(
            &bytes,
            b"protocol-signature",
            SignerRole::ProtocolAuthor,
            &signer,
            &AcceptSigner(PROTOCOL_AUTHOR),
        )
    }

    pub(crate) fn validate(value: &Value) -> Result<ValidatedProtocol, CampaignError> {
        ValidatedProtocol::new(&verified_policy(), verified_protocol(value)?)
    }

    #[test]
    fn protocol_binds_one_exact_profile_pair_policy_and_hardware_class() {
        assert!(validate(&protocol_value()).is_ok());

        let mut identical = protocol_value();
        identical["candidate"] = identical["baseline"].clone();
        assert_eq!(validate(&identical), Err(CampaignError::ProtocolInvalid));

        let mut renamed_identical = protocol_value();
        renamed_identical["candidate"] = renamed_identical["baseline"].clone();
        renamed_identical["candidate"]["profile_id"] = json!("renamed-identical-profile");
        assert_eq!(
            validate(&renamed_identical),
            Err(CampaignError::ProtocolInvalid)
        );

        let mut wrong_role = protocol_value();
        wrong_role["candidate"]["accepted_rgb"]["role"] = json!("ir");
        assert_eq!(validate(&wrong_role), Err(CampaignError::ProtocolInvalid));

        let mut non_reduced = protocol_value();
        non_reduced["candidate"]["accepted_rgb"]["interval_numerator"] = json!(2);
        non_reduced["candidate"]["accepted_rgb"]["interval_denominator"] = json!(30);
        assert_eq!(validate(&non_reduced), Err(CampaignError::ProtocolInvalid));

        let mut hardware = protocol_value();
        hardware["hardware_scope"]["hardware_class"] = json!("another-class");
        assert_eq!(validate(&hardware), Err(CampaignError::ProtocolInvalid));

        let mut policy_digest = protocol_value();
        policy_digest["policy_sha256"] = digest("e");
        assert_eq!(
            validate(&policy_digest),
            Err(CampaignError::ProtocolInvalid)
        );

        let mut unknown = protocol_value();
        unknown["operator_override"] = json!(true);
        assert_eq!(validate(&unknown), Err(CampaignError::CanonicalInvalid));

        for field in [
            "conditioning_catalog_sha256",
            "model_contract_sha256",
            "preprocessing_contract_sha256",
            "producer_contract_sha256",
            "selected_policy_sha256",
            "software_contract_sha256",
            "threshold_contract_sha256",
        ] {
            let mut drift = protocol_value();
            drift["contracts"][field] = digest("f");
            assert_eq!(
                validate(&drift),
                Err(CampaignError::ProtocolInvalid),
                "{field}"
            );
        }
    }

    #[test]
    fn protocol_requires_complete_balanced_candidate_independent_case_matrix() {
        let mut candidate_outcome = protocol_value();
        let candidate = candidate_outcome["cases"]
            .as_array_mut()
            .unwrap()
            .iter_mut()
            .find(|case| case["profile_side"] == "candidate")
            .unwrap();
        candidate["expected_outcome"] = if candidate["expected_outcome"] == "accept" {
            json!("reject")
        } else {
            json!("accept")
        };
        assert_eq!(
            validate(&candidate_outcome),
            Err(CampaignError::ProtocolInvalid)
        );

        let mut missing_side = protocol_value();
        missing_side["cases"].as_array_mut().unwrap().remove(0);
        assert_eq!(validate(&missing_side), Err(CampaignError::ProtocolInvalid));

        let mut duplicate = protocol_value();
        let first = duplicate["cases"][0].clone();
        duplicate["cases"].as_array_mut().unwrap().insert(1, first);
        assert_eq!(validate(&duplicate), Err(CampaignError::ProtocolInvalid));

        let mut unbalanced = protocol_value();
        let logical = unbalanced["cases"][0]["logical_case_id"].clone();
        for case in unbalanced["cases"].as_array_mut().unwrap() {
            if case["logical_case_id"] == logical {
                case["order_position"] = json!("first");
            }
        }
        assert_eq!(validate(&unbalanced), Err(CampaignError::ProtocolInvalid));

        let mut unknown_pai = protocol_value();
        unknown_pai["cases"][0]["pai_species"] = json!("paper_mask");
        assert_eq!(validate(&unknown_pai), Err(CampaignError::CanonicalInvalid));

        let mut missing_pai_method = protocol_value();
        let logical = missing_pai_method["cases"]
            .as_array()
            .unwrap()
            .iter()
            .find(|case| case["pai_species"] == "print")
            .unwrap()["logical_case_id"]
            .clone();
        for case in missing_pai_method["cases"].as_array_mut().unwrap() {
            if case["logical_case_id"] == logical {
                case["pai_production_method"] = Value::Null;
            }
        }
        assert_eq!(
            validate(&missing_pai_method),
            Err(CampaignError::ProtocolInvalid)
        );

        let mut wrong_reference = protocol_value();
        let logical = wrong_reference["cases"]
            .as_array()
            .unwrap()
            .iter()
            .find(|case| case["pai_species"] == "display_replay")
            .unwrap()["logical_case_id"]
            .clone();
        for case in wrong_reference["cases"].as_array_mut().unwrap() {
            if case["logical_case_id"] == logical {
                case["reference_relation"] = json!("mated");
            }
        }
        assert_eq!(
            validate(&wrong_reference),
            Err(CampaignError::ProtocolInvalid)
        );

        let mut missing_stratum = protocol_value();
        missing_stratum["strata"].as_array_mut().unwrap().remove(0);
        assert_eq!(
            validate(&missing_stratum),
            Err(CampaignError::ProtocolInvalid)
        );

        let mut coordinated_removal = protocol_value();
        let removed: Vec<_> = coordinated_removal["strata"]
            .as_array_mut()
            .unwrap()
            .drain(0..2)
            .map(|stratum| stratum["stratum_id"].as_str().unwrap().to_owned())
            .collect();
        coordinated_removal["cases"]
            .as_array_mut()
            .unwrap()
            .retain(|case| !removed.iter().any(|id| case["stratum_id"] == id.as_str()));
        coordinated_removal["pilot_discordance"]
            .as_array_mut()
            .unwrap()
            .retain(|row| !removed.iter().any(|id| row["stratum_id"] == id.as_str()));
        coordinated_removal["locked_sample_sizes"]
            .as_array_mut()
            .unwrap()
            .retain(|row| !removed.iter().any(|id| row["stratum_id"] == id.as_str()));
        for sample in coordinated_removal["locked_sample_sizes"]
            .as_array_mut()
            .unwrap()
        {
            if sample["stratum_id"].is_null() {
                sample["required_cases"] = json!(480);
            }
        }
        assert_eq!(
            validate(&coordinated_removal),
            Err(CampaignError::ProtocolInvalid)
        );
    }

    #[test]
    fn protocol_locks_power_stopping_expiry_roles_and_optional_public_evidence() {
        let mut unlocked = protocol_value();
        unlocked["locked_sample_sizes"]
            .as_array_mut()
            .unwrap()
            .remove(0);
        assert_eq!(validate(&unlocked), Err(CampaignError::ProtocolInvalid));

        let mut underpowered = protocol_value();
        underpowered["locked_sample_sizes"][0]["planned_power_ppb"] = json!(799999999);
        assert_eq!(validate(&underpowered), Err(CampaignError::ProtocolInvalid));

        let mut impossible_discordance = protocol_value();
        impossible_discordance["pilot_discordance"][0]["baseline_only_success_ppb"] =
            json!(600000000);
        impossible_discordance["pilot_discordance"][0]["candidate_only_success_ppb"] =
            json!(600000000);
        assert_eq!(
            validate(&impossible_discordance),
            Err(CampaignError::ProtocolInvalid)
        );

        let mut below_recomputed_overall = protocol_value();
        below_recomputed_overall["locked_sample_sizes"][0]["required_cases"] = json!(618);
        assert_eq!(
            validate(&below_recomputed_overall),
            Err(CampaignError::ProtocolInvalid)
        );

        let mut below_recomputed_stratum = protocol_value();
        let stratum_sample = below_recomputed_stratum["locked_sample_sizes"]
            .as_array_mut()
            .unwrap()
            .iter_mut()
            .find(|sample| !sample["stratum_id"].is_null())
            .unwrap();
        stratum_sample["required_cases"] = json!(98);
        assert_eq!(
            validate(&below_recomputed_stratum),
            Err(CampaignError::ProtocolInvalid)
        );

        let mut changed_pilot_requires_more_pairs = protocol_value();
        changed_pilot_requires_more_pairs["pilot_discordance"][0]["candidate_only_success_ppb"] =
            json!(15000000);
        assert_eq!(
            validate(&changed_pilot_requires_more_pairs),
            Err(CampaignError::ProtocolInvalid)
        );

        let mut premature_capture = protocol_value();
        let stratum_id = premature_capture["strata"][0]["stratum_id"].clone();
        for case in premature_capture["cases"].as_array_mut().unwrap() {
            if case["stratum_id"] == stratum_id {
                case["planned_count"] = json!(98);
            }
        }
        assert_eq!(
            validate(&premature_capture),
            Err(CampaignError::ProtocolInvalid)
        );

        let mut supported_larger_lock = protocol_value();
        let stratum_id = supported_larger_lock["strata"][0]["stratum_id"].clone();
        for case in supported_larger_lock["cases"].as_array_mut().unwrap() {
            if case["stratum_id"] == stratum_id {
                case["planned_count"] = json!(100);
            }
        }
        let stratum_sample = supported_larger_lock["locked_sample_sizes"]
            .as_array_mut()
            .unwrap()
            .iter_mut()
            .find(|sample| sample["stratum_id"] == stratum_id)
            .unwrap();
        stratum_sample["required_cases"] = json!(100);
        assert!(validate(&supported_larger_lock).is_ok());

        let mut power_target_drift = protocol_value();
        power_target_drift["locked_sample_sizes"][0]["planned_power_ppb"] = json!(800000001);
        assert_eq!(
            validate(&power_target_drift),
            Err(CampaignError::ProtocolInvalid)
        );

        let mut optional_stopping = protocol_value();
        optional_stopping["locked_sample_sizes"][0]["stopping_rule"] = json!("stop_when_passing");
        assert_eq!(
            validate(&optional_stopping),
            Err(CampaignError::CanonicalInvalid)
        );

        let mut expired = protocol_value();
        expired["expires_at_unix"] = json!(1819843200u64);
        assert_eq!(validate(&expired), Err(CampaignError::ProtocolInvalid));

        let mut same_authority = protocol_value();
        same_authority["operator_fingerprint"] = json!(PROTOCOL_AUTHOR);
        assert_eq!(
            validate(&same_authority),
            Err(CampaignError::ProtocolInvalid)
        );

        let mut with_public_evidence = protocol_value();
        with_public_evidence["public_regression_evidence"] = json!([{
            "content_sha256": digest("e"),
            "license_id": "cc-by-4.0",
            "mirror_id": "approved-mirror-1",
            "model_calibration_result_sha256": digest("f"),
            "operating_point_id": "recognition-v1",
            "source_url": "https://example.invalid/public-regression"
        }]);
        assert!(validate(&with_public_evidence).is_ok());
        with_public_evidence["cases"]
            .as_array_mut()
            .unwrap()
            .remove(0);
        assert_eq!(
            validate(&with_public_evidence),
            Err(CampaignError::ProtocolInvalid)
        );
    }
}

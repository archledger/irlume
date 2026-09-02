// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright the irlume contributors.

use serde::{Deserialize, Serialize};

use crate::{
    canonical::private,
    policy::{parse_canonical, to_canonical},
    BinaryGate, CampaignError, CanonicalDocument, ExpectedOutcome, Identifier,
    IntersectionDecision, PaiSpecies, PresentationClass, ProfileCaseOutcome, RatePpb, Sha256Digest,
    SignatureMetadata, SignedRateDifferencePpb, SignerFingerprint, SignerRole,
    ValidatedFrozenBundle, ValidatedProtocol, ValidatedPublicationEligibility, Verified,
    MAX_CAPTURE_SHARD_CASES,
};

pub const RESULT_SCHEMA_VERSION: u32 = 1;

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct PrivateTranscriptCase {
    pub(crate) attempt_history_sha256: Sha256Digest,
    pub(crate) baseline: ProfileCaseOutcome,
    pub(crate) baseline_case_id: Identifier,
    pub(crate) candidate: ProfileCaseOutcome,
    pub(crate) candidate_case_id: Identifier,
    pub(crate) case_id: Identifier,
    pub(crate) expected: ExpectedOutcome,
    pub(crate) instance_position: u32,
    pub(crate) pai_instrument_id: Option<Identifier>,
    pub(crate) pai_production_method: Option<Identifier>,
    pub(crate) pai_species: Option<PaiSpecies>,
    pub(crate) presentation: PresentationClass,
    pub(crate) stratum_ids: Vec<Identifier>,
    pub(crate) token_sha256: Sha256Digest,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct PrivateTranscriptShard {
    pub(crate) bundle_index_sha256: Sha256Digest,
    pub(crate) cases: Vec<PrivateTranscriptCase>,
    pub(crate) evaluation_eligibility_sha256: Sha256Digest,
    pub(crate) evaluator_provenance_sha256: Sha256Digest,
    pub(crate) predecessor_sha256: Option<Sha256Digest>,
    pub(crate) protocol_sha256: Sha256Digest,
    pub(crate) schema_version: u32,
    pub(crate) shard_position: u32,
    pub(crate) signature: SignatureMetadata,
}

impl PrivateTranscriptShard {
    fn validate(&self) -> Result<(), CampaignError> {
        if self.schema_version != RESULT_SCHEMA_VERSION
            || self.signature.role() != SignerRole::Evaluator
            || self.cases.is_empty()
            || self.cases.len() > MAX_CAPTURE_SHARD_CASES
            || !self
                .cases
                .windows(2)
                .all(|pair| case_key(&pair[0]) < case_key(&pair[1]))
        {
            return Err(CampaignError::EvaluatorDrift);
        }
        Ok(())
    }
}

fn case_key(case: &PrivateTranscriptCase) -> (&Identifier, u32) {
    (&case.case_id, case.instance_position)
}

impl private::Sealed for PrivateTranscriptShard {}
impl CanonicalDocument for PrivateTranscriptShard {
    fn from_canonical_json(bytes: &[u8]) -> Result<Self, CampaignError> {
        let value: Self = parse_canonical(bytes)?;
        value.validate()?;
        Ok(value)
    }
    fn to_canonical_json(&self) -> Result<Vec<u8>, CampaignError> {
        self.validate()?;
        to_canonical(self)
    }
    fn signature_metadata(&self) -> &SignatureMetadata {
        &self.signature
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct PrivateTranscriptIndex {
    bundle_index_sha256: Sha256Digest,
    evaluation_eligibility_sha256: Sha256Digest,
    evaluator_provenance_sha256: Sha256Digest,
    ordered_shard_sha256: Vec<Sha256Digest>,
    protocol_sha256: Sha256Digest,
    reducer_input_sha256: Sha256Digest,
    schema_version: u32,
    signature: SignatureMetadata,
}

impl PrivateTranscriptIndex {
    pub(crate) fn new(
        bundle_index_sha256: Sha256Digest,
        evaluation_eligibility_sha256: Sha256Digest,
        evaluator_provenance_sha256: Sha256Digest,
        ordered_shard_sha256: Vec<Sha256Digest>,
        protocol_sha256: Sha256Digest,
        reducer_input_sha256: Sha256Digest,
        signature: SignatureMetadata,
    ) -> Result<Self, CampaignError> {
        let value = Self {
            bundle_index_sha256,
            evaluation_eligibility_sha256,
            evaluator_provenance_sha256,
            ordered_shard_sha256,
            protocol_sha256,
            reducer_input_sha256,
            schema_version: RESULT_SCHEMA_VERSION,
            signature,
        };
        value.validate()?;
        Ok(value)
    }
    fn validate(&self) -> Result<(), CampaignError> {
        if self.schema_version != RESULT_SCHEMA_VERSION
            || self.signature.role() != SignerRole::Evaluator
            || self.ordered_shard_sha256.is_empty()
            || self
                .ordered_shard_sha256
                .iter()
                .collect::<std::collections::BTreeSet<_>>()
                .len()
                != self.ordered_shard_sha256.len()
        {
            return Err(CampaignError::EvaluatorDrift);
        }
        Ok(())
    }
}

impl private::Sealed for PrivateTranscriptIndex {}
impl CanonicalDocument for PrivateTranscriptIndex {
    fn from_canonical_json(bytes: &[u8]) -> Result<Self, CampaignError> {
        let value: Self = parse_canonical(bytes)?;
        value.validate()?;
        Ok(value)
    }
    fn to_canonical_json(&self) -> Result<Vec<u8>, CampaignError> {
        self.validate()?;
        to_canonical(self)
    }
    fn signature_metadata(&self) -> &SignatureMetadata {
        &self.signature
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ResultDisposition {
    Pass,
    Fail,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum PublicPresentationCategory {
    BonaFide,
    DisplayReplay,
    NoFace,
    NonMatedLive,
    Print,
}

impl From<IntersectionDecision> for ResultDisposition {
    fn from(value: IntersectionDecision) -> Self {
        match value {
            IntersectionDecision::Pass => Self::Pass,
            IntersectionDecision::Fail => Self::Fail,
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct PublicPairedTable {
    pub both_fail: u64,
    pub candidate_only_success: u64,
    pub baseline_only_success: u64,
    pub both_succeed: u64,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct PublicGateResult {
    pub disposition: ResultDisposition,
    pub estimate_ppb: SignedRateDifferencePpb,
    pub gate: BinaryGate,
    pub lower_ppb: SignedRateDifferencePpb,
    pub margin_ppb: SignedRateDifferencePpb,
    pub stratum_id: Option<Identifier>,
    pub table: PublicPairedTable,
    pub upper_ppb: SignedRateDifferencePpb,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct PublicSecurityResult {
    pub accepts: u64,
    pub presentation: PublicPresentationCategory,
    pub trials: u64,
    pub upper_ppb: RatePpb,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct PublicCategoryCount {
    pub baseline_accepts: u64,
    pub candidate_accepts: u64,
    pub presentation: PublicPresentationCategory,
    pub trials: u64,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct PublicLatencyResult {
    pub allowed_increase_us: u64,
    pub baseline_p50_us: u64,
    pub baseline_p95_us: u64,
    pub budget_us: u64,
    pub candidate_p50_us: u64,
    pub candidate_p95_us: u64,
    pub disposition: ResultDisposition,
    pub upper_increase_us: i64,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct PublicAggregateResult {
    pub availability_disposition: ResultDisposition,
    pub baseline_profile_sha256: Sha256Digest,
    pub bundle_index_sha256: Sha256Digest,
    pub candidate_profile_sha256: Sha256Digest,
    pub category_counts: Vec<PublicCategoryCount>,
    pub collection_not_after_unix: u64,
    pub collection_not_before_unix: u64,
    pub completeness_disposition: ResultDisposition,
    pub conditioning_catalog_sha256: Sha256Digest,
    pub evaluated_at_unix: u64,
    pub evaluation_eligibility_sha256: Sha256Digest,
    pub evaluator_provenance_sha256: Sha256Digest,
    pub excluded_pai_species: [PaiSpecies; 2],
    pub gate_results: Vec<PublicGateResult>,
    pub hardware_scope_sha256: Sha256Digest,
    pub latency: PublicLatencyResult,
    pub model_contract_sha256: Sha256Digest,
    pub noninferiority_disposition: ResultDisposition,
    pub policy_sha256: Sha256Digest,
    pub preprocessing_contract_sha256: Sha256Digest,
    pub producer_contract_sha256: Sha256Digest,
    pub protocol_sha256: Sha256Digest,
    pub provenance_disposition: ResultDisposition,
    pub schema_version: u32,
    pub security_disposition: ResultDisposition,
    pub security_results: Vec<PublicSecurityResult>,
    pub selected_policy_sha256: Sha256Digest,
    pub signature: SignatureMetadata,
    pub software_contract_sha256: Sha256Digest,
    pub source_revision: Sha256Digest,
    pub threshold_contract_sha256: Sha256Digest,
    pub transcript_index_sha256: Sha256Digest,
}

impl PublicAggregateResult {
    fn validate(&self) -> Result<(), CampaignError> {
        let expected_categories = [
            PublicPresentationCategory::BonaFide,
            PublicPresentationCategory::DisplayReplay,
            PublicPresentationCategory::NoFace,
            PublicPresentationCategory::NonMatedLive,
            PublicPresentationCategory::Print,
        ];
        let expected_security = &expected_categories[1..];
        if self.schema_version != RESULT_SCHEMA_VERSION
            || self.signature.role() != SignerRole::Evaluator
            || self.gate_results.is_empty()
            || self.category_counts.len() != expected_categories.len()
            || !self
                .category_counts
                .iter()
                .zip(expected_categories)
                .all(|(count, presentation)| {
                    count.presentation == presentation
                        && count.trials > 0
                        && count.baseline_accepts <= count.trials
                        && count.candidate_accepts <= count.trials
                })
            || self.security_results.len() != expected_security.len()
            || !self
                .security_results
                .iter()
                .zip(expected_security)
                .all(|(result, presentation)| {
                    &result.presentation == presentation
                        && result.trials > 0
                        && result.accepts <= result.trials
                })
            || self.collection_not_before_unix >= self.collection_not_after_unix
            || [
                self.availability_disposition,
                self.completeness_disposition,
                self.noninferiority_disposition,
                self.provenance_disposition,
                self.security_disposition,
                self.latency.disposition,
            ]
            .into_iter()
            .any(|disposition| disposition != ResultDisposition::Pass)
            || self
                .gate_results
                .iter()
                .any(|result| result.disposition != ResultDisposition::Pass)
        {
            return Err(CampaignError::EvaluatorDrift);
        }
        Ok(())
    }
}

impl private::Sealed for PublicAggregateResult {}
impl CanonicalDocument for PublicAggregateResult {
    fn from_canonical_json(bytes: &[u8]) -> Result<Self, CampaignError> {
        let value: Self = parse_canonical(bytes)?;
        value.validate()?;
        Ok(value)
    }
    fn to_canonical_json(&self) -> Result<Vec<u8>, CampaignError> {
        self.validate()?;
        to_canonical(self)
    }
    fn signature_metadata(&self) -> &SignatureMetadata {
        &self.signature
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ReductionOutput {
    pub private_transcript_index: PrivateTranscriptIndex,
    pub private_transcript_shards: Vec<PrivateTranscriptShard>,
    pub public_result: PublicAggregateResult,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ReviewChecks {
    attacks: bool,
    cases: bool,
    cohort: bool,
    completeness: bool,
    consent: bool,
    expiry: bool,
    ordering: bool,
    provenance: bool,
    public_projection: bool,
    statistics: bool,
}

impl ReviewChecks {
    fn all_passed(&self) -> bool {
        self.attacks
            && self.cases
            && self.cohort
            && self.completeness
            && self.consent
            && self.expiry
            && self.ordering
            && self.provenance
            && self.public_projection
            && self.statistics
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ReviewDecision {
    Passed,
    Rejected,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ReviewAttestation {
    bundle_sha256: Sha256Digest,
    checks: ReviewChecks,
    collection_eligibility_sha256: Sha256Digest,
    decision: ReviewDecision,
    evaluation_eligibility_sha256: Sha256Digest,
    evaluator_build_sha256: Sha256Digest,
    operator_fingerprint: SignerFingerprint,
    policy_sha256: Sha256Digest,
    protocol_sha256: Sha256Digest,
    public_result_sha256: Sha256Digest,
    publication_eligibility_sha256: Sha256Digest,
    reproduced_public_result_sha256: Sha256Digest,
    reviewed_at_unix: u64,
    reviewer_fingerprint: SignerFingerprint,
    schema_version: u32,
    signature: SignatureMetadata,
    source_revision: Sha256Digest,
    transcript_sha256: Sha256Digest,
}

impl ReviewAttestation {
    fn validate(&self) -> Result<(), CampaignError> {
        if self.schema_version != RESULT_SCHEMA_VERSION
            || self.reviewed_at_unix == 0
            || self.signature.role() != SignerRole::Reviewer
            || self.signature.signer_fingerprint() != &self.reviewer_fingerprint
        {
            return Err(CampaignError::ReviewRejected);
        }
        Ok(())
    }

    #[must_use]
    pub const fn reviewed_at_unix(&self) -> u64 {
        self.reviewed_at_unix
    }
}

impl private::Sealed for ReviewAttestation {}
impl CanonicalDocument for ReviewAttestation {
    fn from_canonical_json(bytes: &[u8]) -> Result<Self, CampaignError> {
        let value: Self = parse_canonical(bytes)?;
        value.validate()?;
        Ok(value)
    }

    fn to_canonical_json(&self) -> Result<Vec<u8>, CampaignError> {
        self.validate()?;
        to_canonical(self)
    }

    fn signature_metadata(&self) -> &SignatureMetadata {
        &self.signature
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct ReviewedAggregateEnvelope {
    campaign_id: Identifier,
    evaluator_fingerprint: SignerFingerprint,
    policy_sha256: Sha256Digest,
    protocol_sha256: Sha256Digest,
    public_result_sha256: Sha256Digest,
    review_attestation_sha256: Sha256Digest,
    reviewed_at_unix: u64,
    reviewer_fingerprint: SignerFingerprint,
    schema_version: u32,
}

impl ReviewedAggregateEnvelope {
    fn digest(&self) -> Result<Sha256Digest, CampaignError> {
        Ok(Sha256Digest::of(&to_canonical(self)?))
    }

    #[must_use]
    pub const fn campaign_id(&self) -> &Identifier {
        &self.campaign_id
    }

    #[must_use]
    pub const fn protocol_sha256(&self) -> &Sha256Digest {
        &self.protocol_sha256
    }
}

/// Opaque authority proving that a passing aggregate completed independent review.
///
/// External code cannot forge this authority from fields:
///
/// ```compile_fail
/// use irlume_qualification::ReviewedAggregate;
/// let _forged = ReviewedAggregate {
///     envelope: todo!(),
///     envelope_sha256: todo!(),
///     protocol: todo!(),
///     public_result: todo!(),
///     review: todo!(),
/// };
/// ```
///
/// Nor can external code forge the verified inputs it consumes:
///
/// ```compile_fail
/// use irlume_qualification::Verified;
/// let _forged: Verified<()> = Verified {
///     document: (),
///     digest: todo!(),
///     signer: todo!(),
/// };
/// ```
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ReviewedAggregate {
    envelope: ReviewedAggregateEnvelope,
    envelope_sha256: Sha256Digest,
    protocol: ValidatedProtocol,
    public_result: Verified<PublicAggregateResult>,
    review: Verified<ReviewAttestation>,
}

impl ReviewedAggregate {
    #[must_use]
    pub const fn envelope(&self) -> &ReviewedAggregateEnvelope {
        &self.envelope
    }

    #[must_use]
    pub const fn envelope_sha256(&self) -> &Sha256Digest {
        &self.envelope_sha256
    }

    pub(crate) const fn protocol(&self) -> &ValidatedProtocol {
        &self.protocol
    }

    #[must_use]
    pub const fn public_result(&self) -> &Verified<PublicAggregateResult> {
        &self.public_result
    }

    #[must_use]
    pub const fn review(&self) -> &Verified<ReviewAttestation> {
        &self.review
    }
}

#[derive(Clone, Copy)]
pub struct ReviewContext<'a> {
    pub protocol: &'a ValidatedProtocol,
    pub bundle: &'a ValidatedFrozenBundle,
    pub publication: &'a ValidatedPublicationEligibility,
    pub transcript: &'a Verified<PrivateTranscriptIndex>,
    pub reproduced_public_result_sha256: &'a Sha256Digest,
}

/// Binds a verified passing result to its exact independent review authority.
///
/// # Errors
///
/// Returns `ReviewMissing` when no verified review is supplied and
/// `ReviewRejected` for every rejected, stale, non-independent, or mismatched review.
pub fn assemble_reviewed_aggregate(
    context: ReviewContext<'_>,
    public_result: Verified<PublicAggregateResult>,
    review: Option<Verified<ReviewAttestation>>,
) -> Result<ReviewedAggregate, CampaignError> {
    let review = review.ok_or(CampaignError::ReviewMissing)?;
    let public = public_result.document();
    let transcript = context.transcript.document();
    let attestation = review.document();
    let protocol = context.protocol.protocol();
    let snapshots = context.publication.snapshot_sha256();

    if attestation.decision != ReviewDecision::Passed
        || !attestation.checks.all_passed()
        || review.signer() != &attestation.reviewer_fingerprint
        || public_result.signer() != context.transcript.signer()
        || public_result.signer() == context.bundle.operator_fingerprint()
        || review.signer() == context.bundle.operator_fingerprint()
        || review.signer() == public_result.signer()
        || context.publication.protocol_sha256() != context.protocol.protocol_sha256()
        || context.publication.bundle_index_sha256() != context.bundle.bundle_index_sha256()
        || context.publication.operator_fingerprint() != context.bundle.operator_fingerprint()
        || public.policy_sha256 != *context.protocol.policy_sha256()
        || public.protocol_sha256 != *context.protocol.protocol_sha256()
        || public.bundle_index_sha256 != *context.bundle.bundle_index_sha256()
        || public.evaluation_eligibility_sha256 != snapshots[1]
        || public.transcript_index_sha256 != *context.transcript.digest()
        || public.evaluator_provenance_sha256 != transcript.evaluator_provenance_sha256
        || public.source_revision != *protocol.source_revision()
        || transcript.bundle_index_sha256 != *context.bundle.bundle_index_sha256()
        || transcript.evaluation_eligibility_sha256 != snapshots[1]
        || transcript.protocol_sha256 != *context.protocol.protocol_sha256()
        || attestation.policy_sha256 != *context.protocol.policy_sha256()
        || attestation.protocol_sha256 != *context.protocol.protocol_sha256()
        || attestation.collection_eligibility_sha256 != snapshots[0]
        || attestation.evaluation_eligibility_sha256 != snapshots[1]
        || attestation.publication_eligibility_sha256 != snapshots[2]
        || attestation.bundle_sha256 != *context.bundle.bundle_index_sha256()
        || attestation.evaluator_build_sha256 != *protocol.evaluator_build_sha256()
        || attestation.transcript_sha256 != *context.transcript.digest()
        || attestation.public_result_sha256 != *public_result.digest()
        || attestation.source_revision != *protocol.source_revision()
        || attestation.reproduced_public_result_sha256 != *public_result.digest()
        || context.reproduced_public_result_sha256 != public_result.digest()
        || attestation.operator_fingerprint != *context.bundle.operator_fingerprint()
        || attestation.reviewed_at_unix < context.publication.validated_at_unix()
        || attestation.reviewed_at_unix > protocol.review_not_after_unix()
        || attestation.reviewed_at_unix > protocol.expires_at_unix()
    {
        return Err(CampaignError::ReviewRejected);
    }

    let envelope = ReviewedAggregateEnvelope {
        campaign_id: protocol.campaign_id().clone(),
        evaluator_fingerprint: public_result.signer().clone(),
        policy_sha256: context.protocol.policy_sha256().clone(),
        protocol_sha256: context.protocol.protocol_sha256().clone(),
        public_result_sha256: public_result.digest().clone(),
        review_attestation_sha256: review.digest().clone(),
        reviewed_at_unix: attestation.reviewed_at_unix,
        reviewer_fingerprint: review.signer().clone(),
        schema_version: RESULT_SCHEMA_VERSION,
    };
    let envelope_sha256 = envelope.digest()?;
    Ok(ReviewedAggregate {
        envelope,
        envelope_sha256,
        protocol: context.protocol.clone(),
        public_result,
        review,
    })
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use crate::{
        lifecycle::tests::review_inputs, reducer::tests::passing_output, verify_document,
        DetachedSignatureVerifier, ReviewContext, SignerFingerprint, Verified,
    };

    const EVALUATOR: &str = "CCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCC";
    const REVIEWER: &str = "DDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDD";

    struct AcceptSigner(SignerFingerprint);

    impl DetachedSignatureVerifier for AcceptSigner {
        fn verify(
            &self,
            _canonical_payload: &[u8],
            _detached_signature: &[u8],
        ) -> Result<SignerFingerprint, CampaignError> {
            Ok(self.0.clone())
        }
    }

    fn verified<T: CanonicalDocument>(
        document: &T,
        role: SignerRole,
        signer: &SignerFingerprint,
    ) -> Verified<T> {
        verify_document(
            &document.to_canonical_json().unwrap(),
            b"detached-signature",
            role,
            signer,
            &AcceptSigner(signer.clone()),
        )
        .unwrap()
    }

    fn review_value(
        protocol: &crate::ValidatedProtocol,
        bundle: &crate::ValidatedFrozenBundle,
        publication: &crate::ValidatedPublicationEligibility,
        transcript: &Verified<PrivateTranscriptIndex>,
        public_result: &Verified<PublicAggregateResult>,
    ) -> serde_json::Value {
        let reviewer = SignerFingerprint::new(REVIEWER).unwrap();
        serde_json::json!({
            "bundle_sha256": bundle.bundle_index_sha256().as_str(),
            "checks": {
                "attacks": true,
                "cases": true,
                "cohort": true,
                "completeness": true,
                "consent": true,
                "expiry": true,
                "ordering": true,
                "provenance": true,
                "public_projection": true,
                "statistics": true
            },
            "collection_eligibility_sha256": publication.snapshot_sha256()[0].as_str(),
            "decision": "passed",
            "evaluation_eligibility_sha256": publication.snapshot_sha256()[1].as_str(),
            "evaluator_build_sha256": protocol.protocol().evaluator_build_sha256().as_str(),
            "operator_fingerprint": bundle.operator_fingerprint().as_str(),
            "policy_sha256": protocol.policy_sha256().as_str(),
            "protocol_sha256": protocol.protocol_sha256().as_str(),
            "public_result_sha256": public_result.digest().as_str(),
            "publication_eligibility_sha256": publication.snapshot_sha256()[2].as_str(),
            "reproduced_public_result_sha256": public_result.digest().as_str(),
            "reviewed_at_unix": 1789000002u64,
            "reviewer_fingerprint": reviewer.as_str(),
            "schema_version": 1,
            "signature": {
                "algorithm": "open_pgp",
                "role": "reviewer",
                "signer_fingerprint": reviewer.as_str()
            },
            "source_revision": protocol.protocol().source_revision().as_str(),
            "transcript_sha256": transcript.digest().as_str()
        })
    }

    fn verified_review_inputs() -> (
        crate::ValidatedProtocol,
        crate::ValidatedFrozenBundle,
        crate::ValidatedPublicationEligibility,
        Verified<PrivateTranscriptIndex>,
        Verified<PublicAggregateResult>,
    ) {
        let (protocol, bundle, publication) = review_inputs();
        let output = passing_output();
        let evaluator = SignerFingerprint::new(EVALUATOR).unwrap();
        let transcript = verified(
            &output.private_transcript_index,
            SignerRole::Evaluator,
            &evaluator,
        );
        let public_result = verified(&output.public_result, SignerRole::Evaluator, &evaluator);
        (protocol, bundle, publication, transcript, public_result)
    }

    fn assemble_review_value(
        value: &serde_json::Value,
        expected_reviewer: &SignerFingerprint,
        reproduced: Option<Sha256Digest>,
    ) -> Result<ReviewedAggregate, CampaignError> {
        let (protocol, bundle, publication, transcript, public_result) = verified_review_inputs();
        let review = verify_document::<ReviewAttestation>(
            &serde_json::to_vec(value).unwrap(),
            b"review-signature",
            SignerRole::Reviewer,
            expected_reviewer,
            &AcceptSigner(expected_reviewer.clone()),
        )?;
        let reproduced = reproduced.unwrap_or_else(|| public_result.digest().clone());
        assemble_reviewed_aggregate(
            ReviewContext {
                protocol: &protocol,
                bundle: &bundle,
                publication: &publication,
                transcript: &transcript,
                reproduced_public_result_sha256: &reproduced,
            },
            public_result,
            Some(review),
        )
    }

    pub(crate) fn passing_reviewed_aggregate() -> ReviewedAggregate {
        let (protocol, bundle, publication, transcript, public_result) = verified_review_inputs();
        let reviewer = SignerFingerprint::new(REVIEWER).unwrap();
        assemble_review_value(
            &review_value(
                &protocol,
                &bundle,
                &publication,
                &transcript,
                &public_result,
            ),
            &reviewer,
            None,
        )
        .unwrap()
    }

    #[test]
    fn result_documents_round_trip_only_in_canonical_evaluator_form() {
        let output = passing_output();
        let public_bytes = output.public_result.to_canonical_json().unwrap();
        assert_eq!(
            PublicAggregateResult::from_canonical_json(&public_bytes).unwrap(),
            output.public_result
        );
        for shard in &output.private_transcript_shards {
            let bytes = shard.to_canonical_json().unwrap();
            assert_eq!(
                PrivateTranscriptShard::from_canonical_json(&bytes).unwrap(),
                *shard
            );
        }
        let index_bytes = output.private_transcript_index.to_canonical_json().unwrap();
        assert_eq!(
            PrivateTranscriptIndex::from_canonical_json(&index_bytes).unwrap(),
            output.private_transcript_index
        );

        let mut unknown: serde_json::Value = serde_json::from_slice(&public_bytes).unwrap();
        unknown["error_text"] = serde_json::json!("private failure");
        assert!(
            PublicAggregateResult::from_canonical_json(&serde_json::to_vec(&unknown).unwrap())
                .is_err()
        );

        let mut wrong_role: serde_json::Value = serde_json::from_slice(&public_bytes).unwrap();
        wrong_role["signature"]["role"] = serde_json::json!("operator");
        let wrong_role: PublicAggregateResult = serde_json::from_value(wrong_role).unwrap();
        assert_eq!(
            wrong_role.to_canonical_json(),
            Err(CampaignError::EvaluatorDrift)
        );
    }

    #[test]
    fn review_missing_is_a_fixed_failure() {
        let (protocol, bundle, publication, transcript, public_result) = verified_review_inputs();
        let reproduced = public_result.digest().clone();
        let context = ReviewContext {
            protocol: &protocol,
            bundle: &bundle,
            publication: &publication,
            transcript: &transcript,
            reproduced_public_result_sha256: &reproduced,
        };
        assert_eq!(
            assemble_reviewed_aggregate(context, public_result, None),
            Err(CampaignError::ReviewMissing)
        );
    }

    #[test]
    fn review_passes_only_with_verified_independent_authority() {
        let reviewed = passing_reviewed_aggregate();
        assert_eq!(
            reviewed.envelope_sha256(),
            &reviewed.envelope().digest().unwrap()
        );
    }

    #[test]
    fn reviewed_aggregate_retains_only_its_exact_validated_protocol() {
        let reviewed = passing_reviewed_aggregate();
        assert_eq!(
            reviewed.protocol().protocol_sha256(),
            reviewed.envelope().protocol_sha256()
        );
    }

    #[test]
    fn review_rejects_every_attestation_authority_mismatch() {
        let (protocol, bundle, publication, transcript, public_result) = verified_review_inputs();
        let value = review_value(
            &protocol,
            &bundle,
            &publication,
            &transcript,
            &public_result,
        );
        let reviewer = SignerFingerprint::new(REVIEWER).unwrap();
        let digest_fields = [
            "bundle_sha256",
            "collection_eligibility_sha256",
            "evaluation_eligibility_sha256",
            "evaluator_build_sha256",
            "policy_sha256",
            "protocol_sha256",
            "public_result_sha256",
            "publication_eligibility_sha256",
            "reproduced_public_result_sha256",
            "source_revision",
            "transcript_sha256",
        ];
        for field in digest_fields {
            let mut changed = value.clone();
            changed[field] = serde_json::json!("a".repeat(64));
            assert_eq!(
                assemble_review_value(&changed, &reviewer, None),
                Err(CampaignError::ReviewRejected),
                "accepted mismatched {field}"
            );
        }
    }

    #[test]
    fn review_rejects_false_checks_decision_and_stale_times() {
        let (protocol, bundle, publication, transcript, public_result) = verified_review_inputs();
        let value = review_value(
            &protocol,
            &bundle,
            &publication,
            &transcript,
            &public_result,
        );
        let reviewer = SignerFingerprint::new(REVIEWER).unwrap();
        let checks = [
            "attacks",
            "cases",
            "cohort",
            "completeness",
            "consent",
            "expiry",
            "ordering",
            "provenance",
            "public_projection",
            "statistics",
        ];
        for check in checks {
            let mut changed = value.clone();
            changed["checks"][check] = serde_json::json!(false);
            assert_eq!(
                assemble_review_value(&changed, &reviewer, None),
                Err(CampaignError::ReviewRejected),
                "accepted false {check} check"
            );
        }
        for (field, replacement) in [
            ("decision", serde_json::json!("rejected")),
            ("reviewed_at_unix", serde_json::json!(1789000000u64)),
            ("reviewed_at_unix", serde_json::json!(1790208001u64)),
        ] {
            let mut changed = value.clone();
            changed[field] = replacement;
            assert_eq!(
                assemble_review_value(&changed, &reviewer, None),
                Err(CampaignError::ReviewRejected)
            );
        }
    }

    #[test]
    fn review_requires_three_separate_roles_and_independent_reproduction() {
        let (protocol, bundle, publication, transcript, public_result) = verified_review_inputs();
        let value = review_value(
            &protocol,
            &bundle,
            &publication,
            &transcript,
            &public_result,
        );
        for signer in [
            bundle.operator_fingerprint().clone(),
            public_result.signer().clone(),
        ] {
            let mut changed = value.clone();
            changed["reviewer_fingerprint"] = serde_json::json!(signer.as_str());
            changed["signature"]["signer_fingerprint"] = serde_json::json!(signer.as_str());
            assert_eq!(
                assemble_review_value(&changed, &signer, None),
                Err(CampaignError::ReviewRejected)
            );
        }

        let reviewer = SignerFingerprint::new(REVIEWER).unwrap();
        assert_eq!(
            assemble_review_value(
                &value,
                &reviewer,
                Some(Sha256Digest::new(&"a".repeat(64)).unwrap())
            ),
            Err(CampaignError::ReviewRejected)
        );

        let mut wrong_role = value;
        wrong_role["signature"]["role"] = serde_json::json!("operator");
        assert!(assemble_review_value(&wrong_role, &reviewer, None).is_err());
    }

    #[test]
    fn review_rejects_tampered_public_or_private_evaluator_output() {
        let (protocol, bundle, publication, transcript, public_result) = verified_review_inputs();
        let reviewer = SignerFingerprint::new(REVIEWER).unwrap();
        let review = verified(
            &ReviewAttestation::from_canonical_json(
                &serde_json::to_vec(&review_value(
                    &protocol,
                    &bundle,
                    &publication,
                    &transcript,
                    &public_result,
                ))
                .unwrap(),
            )
            .unwrap(),
            SignerRole::Reviewer,
            &reviewer,
        );
        let reproduced = public_result.digest().clone();

        let mut public_value: serde_json::Value =
            serde_json::from_slice(&public_result.document().to_canonical_json().unwrap()).unwrap();
        public_value["bundle_index_sha256"] = serde_json::json!("a".repeat(64));
        let tampered_public: PublicAggregateResult = serde_json::from_value(public_value).unwrap();
        let evaluator = public_result.signer().clone();
        let tampered_public = verified(&tampered_public, SignerRole::Evaluator, &evaluator);
        assert_eq!(
            assemble_reviewed_aggregate(
                ReviewContext {
                    protocol: &protocol,
                    bundle: &bundle,
                    publication: &publication,
                    transcript: &transcript,
                    reproduced_public_result_sha256: &reproduced,
                },
                tampered_public,
                Some(review.clone()),
            ),
            Err(CampaignError::ReviewRejected)
        );

        let mut transcript_value: serde_json::Value =
            serde_json::from_slice(&transcript.document().to_canonical_json().unwrap()).unwrap();
        transcript_value["bundle_index_sha256"] = serde_json::json!("a".repeat(64));
        let tampered_transcript: PrivateTranscriptIndex =
            serde_json::from_value(transcript_value).unwrap();
        let tampered_transcript = verified(&tampered_transcript, SignerRole::Evaluator, &evaluator);
        assert_eq!(
            assemble_reviewed_aggregate(
                ReviewContext {
                    protocol: &protocol,
                    bundle: &bundle,
                    publication: &publication,
                    transcript: &tampered_transcript,
                    reproduced_public_result_sha256: &reproduced,
                },
                public_result,
                Some(review),
            ),
            Err(CampaignError::ReviewRejected)
        );
    }

    #[test]
    fn every_reviewed_envelope_authority_field_changes_its_digest() {
        let (protocol, bundle, publication, transcript, public_result) = verified_review_inputs();
        let reviewer = SignerFingerprint::new(REVIEWER).unwrap();
        let reviewed = assemble_review_value(
            &review_value(
                &protocol,
                &bundle,
                &publication,
                &transcript,
                &public_result,
            ),
            &reviewer,
            None,
        )
        .unwrap();
        let original = reviewed.envelope().digest().unwrap();
        let mut variants = Vec::new();
        let mut changed = reviewed.envelope().clone();
        changed.schema_version += 1;
        variants.push(changed);
        let mut changed = reviewed.envelope().clone();
        changed.campaign_id = Identifier::new("other-campaign").unwrap();
        variants.push(changed);
        let mut changed = reviewed.envelope().clone();
        changed.policy_sha256 = Sha256Digest::new(&"a".repeat(64)).unwrap();
        variants.push(changed);
        let mut changed = reviewed.envelope().clone();
        changed.protocol_sha256 = Sha256Digest::new(&"a".repeat(64)).unwrap();
        variants.push(changed);
        let mut changed = reviewed.envelope().clone();
        changed.public_result_sha256 = Sha256Digest::new(&"a".repeat(64)).unwrap();
        variants.push(changed);
        let mut changed = reviewed.envelope().clone();
        changed.review_attestation_sha256 = Sha256Digest::new(&"a".repeat(64)).unwrap();
        variants.push(changed);
        let mut changed = reviewed.envelope().clone();
        changed.evaluator_fingerprint =
            SignerFingerprint::new("EEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEE").unwrap();
        variants.push(changed);
        let mut changed = reviewed.envelope().clone();
        changed.reviewer_fingerprint =
            SignerFingerprint::new("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF").unwrap();
        variants.push(changed);
        let mut changed = reviewed.envelope().clone();
        changed.reviewed_at_unix += 1;
        variants.push(changed);

        assert!(variants
            .into_iter()
            .all(|envelope| envelope.digest().unwrap() != original));
    }
}

// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright the irlume contributors.

use serde::{Deserialize, Serialize};

use crate::{
    canonical::private,
    policy::{parse_canonical, to_canonical},
    BinaryGate, CampaignError, CanonicalDocument, ExpectedOutcome, Identifier,
    IntersectionDecision, PaiSpecies, PresentationClass, ProfileCaseOutcome, RatePpb, Sha256Digest,
    SignatureMetadata, SignedRateDifferencePpb, SignerRole, MAX_CAPTURE_SHARD_CASES,
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::reducer::tests::passing_output;

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
}

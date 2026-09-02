// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright the irlume contributors.

use serde::{Deserialize, Serialize};

use crate::{
    clopper_pearson, cluster_bootstrap_latency, paired_mover_wilson,
    policy::to_canonical,
    result::{
        PrivateTranscriptCase, PrivateTranscriptIndex, PrivateTranscriptShard,
        PublicAggregateResult, PublicCategoryCount, PublicGateResult, PublicLatencyResult,
        PublicPairedTable, PublicPresentationCategory, PublicSecurityResult, ReductionOutput,
        ResultDisposition, RESULT_SCHEMA_VERSION,
    },
    BinaryGate, CampaignError, CanonicalDocument, ClusterLatency, ExpectedOutcome, Identifier,
    PaiSpecies, PairedLatencyUs, PairedTable, PresentationClass, RatePpb, Sha256Digest,
    SignatureMetadata, SignedRateDifferencePpb, SignerFingerprint, SignerRole,
    ValidatedEvaluationEligibility, ValidatedFrozenBundle, ValidatedProtocol, OVERALL_MARGIN_PPB,
    STRATUM_MARGIN_PPB,
};

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum StageOutcome {
    Success,
    Incorrect,
    NotApplicable,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ProfileCaseOutcome {
    pub detection: StageOutcome,
    pub recognition: StageOutcome,
    pub liveness: StageOutcome,
    pub rgb_pad: StageOutcome,
    pub ir_pad: StageOutcome,
    pub authentication_accept: bool,
    pub latency_us: u64,
    pub decision_value_ppb: Option<RatePpb>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct EvaluatedPairedCase {
    pub case_id: Identifier,
    pub instance_position: u32,
    pub stratum_ids: Vec<Identifier>,
    pub presentation: PresentationClass,
    pub expected: ExpectedOutcome,
    pub baseline: ProfileCaseOutcome,
    pub candidate: ProfileCaseOutcome,
    pub attempt_history_sha256: Sha256Digest,
}

#[derive(Clone, Copy)]
pub struct ReductionContext<'a> {
    pub protocol: &'a ValidatedProtocol,
    pub bundle: &'a ValidatedFrozenBundle,
    pub evaluation: &'a ValidatedEvaluationEligibility,
    pub evaluator_fingerprint: &'a SignerFingerprint,
    pub evaluator_provenance_sha256: &'a Sha256Digest,
    pub evaluated_at_unix: u64,
    pub signature: &'a SignatureMetadata,
}

/// Reduces exact categorical paired outcomes into a private transcript and public aggregate.
///
/// # Errors
/// Returns a closed campaign error when authority, completeness, provenance, security,
/// non-inferiority, availability, or latency validation fails.
pub fn reduce_campaign(
    context: ReductionContext<'_>,
    mut cases: Vec<EvaluatedPairedCase>,
) -> Result<ReductionOutput, CampaignError> {
    if !context.evaluation.authorizes_reduction_of(context.bundle)
        || context.signature.role() != SignerRole::Evaluator
        || context.signature.signer_fingerprint() != context.evaluator_fingerprint
        || context.evaluator_fingerprint == context.bundle.operator_fingerprint()
        || context.evaluated_at_unix < context.evaluation.validated_at_unix()
        || context.evaluated_at_unix > context.protocol.protocol().evaluation_not_after_unix()
    {
        return Err(CampaignError::EvaluatorDrift);
    }
    cases.sort_by(|left, right| case_key(left).cmp(&case_key(right)));
    if cases
        .windows(2)
        .any(|pair| case_key(&pair[0]) == case_key(&pair[1]))
    {
        return Err(CampaignError::CaptureIncomplete);
    }

    let mut authority = std::collections::BTreeMap::new();
    for cell in context.bundle.evaluation_cells() {
        for instance_position in 0..cell.planned_count {
            authority.insert((cell.logical_case_id.clone(), instance_position), cell);
        }
    }
    if authority.len() != cases.len() {
        return Err(CampaignError::CaptureIncomplete);
    }
    for case in &cases {
        let Some(cell) = authority.get(&(case.case_id.clone(), case.instance_position)) else {
            return Err(CampaignError::CaptureIncomplete);
        };
        if case.stratum_ids != [cell.stratum_id.clone()]
            || case.presentation != cell.presentation_class
            || case.expected != cell.expected_outcome
            || case.attempt_history_sha256 != cell.attempt_history_sha256
            || case.baseline.latency_us == 0
            || case.candidate.latency_us == 0
        {
            return Err(CampaignError::ProvenanceMismatch);
        }
    }

    if cases.iter().any(|case| {
        case.presentation != PresentationClass::BonaFide && case.candidate.authentication_accept
    }) {
        return Err(CampaignError::SecurityGateFailed);
    }
    if cases.iter().any(|case| {
        case.presentation == PresentationClass::BonaFide
            && required_stages(case)
                .into_iter()
                .any(|outcome| matches!(outcome, StageOutcome::NotApplicable))
    }) {
        return Err(CampaignError::CaptureIncomplete);
    }

    let gate_results = build_gate_results(&cases)?;
    if gate_results
        .iter()
        .any(|result| result.disposition == ResultDisposition::Fail)
    {
        return Err(CampaignError::NoninferiorityFailed);
    }

    let security_results = build_security_results(&cases)?;
    let latency = build_latency(context, &cases, &authority)?;
    if latency.disposition == ResultDisposition::Fail {
        return Err(CampaignError::LatencyFailed);
    }

    let private_cases: Vec<_> = cases
        .iter()
        .map(|case| {
            let cell = authority
                .get(&(case.case_id.clone(), case.instance_position))
                .ok_or(CampaignError::CaptureIncomplete)?;
            Ok(PrivateTranscriptCase {
                attempt_history_sha256: case.attempt_history_sha256.clone(),
                baseline: case.baseline.clone(),
                baseline_case_id: cell.baseline_case_id.clone(),
                candidate: case.candidate.clone(),
                candidate_case_id: cell.candidate_case_id.clone(),
                case_id: case.case_id.clone(),
                expected: case.expected,
                instance_position: case.instance_position,
                pai_instrument_id: cell.pai_instrument_id.clone(),
                pai_production_method: cell.pai_production_method.clone(),
                pai_species: cell.pai_species,
                presentation: case.presentation,
                stratum_ids: case.stratum_ids.clone(),
                token_sha256: cell.token_sha256.clone(),
            })
        })
        .collect::<Result<Vec<_>, CampaignError>>()?;
    let case_digests = private_cases
        .iter()
        .map(|case| to_canonical(case).map(|bytes| Sha256Digest::of(&bytes)))
        .collect::<Result<Vec<_>, CampaignError>>()?;
    let reducer_input_sha256 = Sha256Digest::of(&to_canonical(&case_digests)?);
    let mut predecessor_sha256 = None;
    let mut private_transcript_shards = Vec::new();
    let mut ordered_shard_sha256 = Vec::new();
    for (position, chunk) in private_cases
        .chunks(crate::MAX_CAPTURE_SHARD_CASES)
        .enumerate()
    {
        let shard = PrivateTranscriptShard {
            bundle_index_sha256: context.bundle.bundle_index_sha256().clone(),
            cases: chunk.to_vec(),
            evaluation_eligibility_sha256: context.evaluation.snapshot_sha256().clone(),
            evaluator_provenance_sha256: context.evaluator_provenance_sha256.clone(),
            predecessor_sha256,
            protocol_sha256: context.protocol.protocol_sha256().clone(),
            schema_version: RESULT_SCHEMA_VERSION,
            shard_position: u32::try_from(position).map_err(|_| CampaignError::EvaluatorDrift)?,
            signature: context.signature.clone(),
        };
        let digest = Sha256Digest::of(&shard.to_canonical_json()?);
        predecessor_sha256 = Some(digest.clone());
        ordered_shard_sha256.push(digest);
        private_transcript_shards.push(shard);
    }
    let private_transcript_index = PrivateTranscriptIndex::new(
        context.bundle.bundle_index_sha256().clone(),
        context.evaluation.snapshot_sha256().clone(),
        context.evaluator_provenance_sha256.clone(),
        ordered_shard_sha256,
        context.protocol.protocol_sha256().clone(),
        reducer_input_sha256,
        context.signature.clone(),
    )?;
    let transcript_index_sha256 = Sha256Digest::of(&private_transcript_index.to_canonical_json()?);
    let protocol = context.protocol.protocol();
    let contracts = protocol.runtime_contracts();
    let public_result = PublicAggregateResult {
        availability_disposition: ResultDisposition::Pass,
        baseline_profile_sha256: protocol.baseline().lifecycle_sha256()?,
        bundle_index_sha256: context.bundle.bundle_index_sha256().clone(),
        candidate_profile_sha256: protocol.candidate().lifecycle_sha256()?,
        category_counts: build_category_counts(&cases)?,
        collection_not_after_unix: protocol.collection_not_after_unix(),
        collection_not_before_unix: protocol.collection_not_before_unix(),
        completeness_disposition: ResultDisposition::Pass,
        conditioning_catalog_sha256: contracts.conditioning_catalog_sha256().clone(),
        evaluated_at_unix: context.evaluated_at_unix,
        evaluation_eligibility_sha256: context.evaluation.snapshot_sha256().clone(),
        evaluator_provenance_sha256: context.evaluator_provenance_sha256.clone(),
        excluded_pai_species: [PaiSpecies::ActiveIr, PaiSpecies::ThreeDimensionalMask],
        gate_results,
        hardware_scope_sha256: protocol.hardware_scope().lifecycle_sha256()?,
        latency,
        model_contract_sha256: contracts.model_contract_sha256().clone(),
        noninferiority_disposition: ResultDisposition::Pass,
        policy_sha256: context.protocol.policy_sha256().clone(),
        preprocessing_contract_sha256: contracts.preprocessing_contract_sha256().clone(),
        producer_contract_sha256: contracts.producer_contract_sha256().clone(),
        protocol_sha256: context.protocol.protocol_sha256().clone(),
        provenance_disposition: ResultDisposition::Pass,
        schema_version: RESULT_SCHEMA_VERSION,
        security_disposition: ResultDisposition::Pass,
        security_results,
        selected_policy_sha256: contracts.selected_policy_sha256().clone(),
        signature: context.signature.clone(),
        software_contract_sha256: contracts.software_contract_sha256().clone(),
        source_revision: protocol.source_revision().clone(),
        threshold_contract_sha256: contracts.threshold_contract_sha256().clone(),
        transcript_index_sha256,
    };
    public_result.to_canonical_json()?;
    Ok(ReductionOutput {
        private_transcript_index,
        private_transcript_shards,
        public_result,
    })
}

fn case_key(case: &EvaluatedPairedCase) -> (&Identifier, u32) {
    (&case.case_id, case.instance_position)
}

fn required_stages(case: &EvaluatedPairedCase) -> [StageOutcome; 10] {
    [
        case.baseline.detection,
        case.baseline.recognition,
        case.baseline.liveness,
        case.baseline.rgb_pad,
        case.baseline.ir_pad,
        case.candidate.detection,
        case.candidate.recognition,
        case.candidate.liveness,
        case.candidate.rgb_pad,
        case.candidate.ir_pad,
    ]
}

fn stage(outcome: &ProfileCaseOutcome, gate: BinaryGate) -> StageOutcome {
    match gate {
        BinaryGate::Detection => outcome.detection,
        BinaryGate::Recognition => outcome.recognition,
        BinaryGate::Liveness => outcome.liveness,
        BinaryGate::RgbPad => outcome.rgb_pad,
        BinaryGate::IrPad => outcome.ir_pad,
    }
}

fn table_for<'a>(
    cases: impl Iterator<Item = &'a EvaluatedPairedCase>,
    gate: BinaryGate,
) -> PublicPairedTable {
    let mut table = PublicPairedTable {
        both_fail: 0,
        candidate_only_success: 0,
        baseline_only_success: 0,
        both_succeed: 0,
    };
    for case in cases {
        match (
            stage(&case.baseline, gate) == StageOutcome::Success,
            stage(&case.candidate, gate) == StageOutcome::Success,
        ) {
            (false, false) => table.both_fail += 1,
            (false, true) => table.candidate_only_success += 1,
            (true, false) => table.baseline_only_success += 1,
            (true, true) => table.both_succeed += 1,
        }
    }
    table
}

fn gate_result(
    gate: BinaryGate,
    stratum_id: Option<Identifier>,
    table: PublicPairedTable,
) -> Result<PublicGateResult, CampaignError> {
    let statistics = paired_mover_wilson(PairedTable::new(
        table.both_fail,
        table.candidate_only_success,
        table.baseline_only_success,
        table.both_succeed,
    ))?;
    let margin = SignedRateDifferencePpb::new(if stratum_id.is_some() {
        STRATUM_MARGIN_PPB
    } else {
        OVERALL_MARGIN_PPB
    })?;
    Ok(PublicGateResult {
        disposition: statistics.decision(margin).into(),
        estimate_ppb: statistics.estimate_ppb(),
        gate,
        lower_ppb: statistics.lower_ppb(),
        margin_ppb: margin,
        stratum_id,
        table,
        upper_ppb: statistics.upper_ppb(),
    })
}

fn build_gate_results(
    cases: &[EvaluatedPairedCase],
) -> Result<Vec<PublicGateResult>, CampaignError> {
    let bona_fide: Vec<_> = cases
        .iter()
        .filter(|case| case.presentation == PresentationClass::BonaFide)
        .collect();
    let strata: std::collections::BTreeSet<_> = bona_fide
        .iter()
        .flat_map(|case| case.stratum_ids.iter().cloned())
        .collect();
    let mut results = Vec::new();
    for gate in [
        BinaryGate::Detection,
        BinaryGate::IrPad,
        BinaryGate::Liveness,
        BinaryGate::Recognition,
        BinaryGate::RgbPad,
    ] {
        results.push(gate_result(
            gate,
            None,
            table_for(bona_fide.iter().copied(), gate),
        )?);
        for stratum_id in &strata {
            results.push(gate_result(
                gate,
                Some(stratum_id.clone()),
                table_for(
                    bona_fide
                        .iter()
                        .copied()
                        .filter(|case| case.stratum_ids.contains(stratum_id)),
                    gate,
                ),
            )?);
        }
    }
    Ok(results)
}

fn build_security_results(
    cases: &[EvaluatedPairedCase],
) -> Result<Vec<PublicSecurityResult>, CampaignError> {
    let mut results = Vec::new();
    for presentation in [
        PresentationClass::DisplayReplay,
        PresentationClass::NoFace,
        PresentationClass::NonMatedLiveCrossIdentity,
        PresentationClass::Print,
    ] {
        let selected: Vec<_> = cases
            .iter()
            .filter(|case| case.presentation == presentation)
            .collect();
        let trials = u64::try_from(selected.len()).map_err(|_| CampaignError::ProtocolInvalid)?;
        let accepts = u64::try_from(
            selected
                .iter()
                .filter(|case| case.candidate.authentication_accept)
                .count(),
        )
        .map_err(|_| CampaignError::ProtocolInvalid)?;
        let bound = clopper_pearson(accepts, trials)?;
        results.push(PublicSecurityResult {
            accepts,
            presentation: public_presentation(presentation),
            trials,
            upper_ppb: bound.upper_ppb(),
        });
    }
    Ok(results)
}

fn build_category_counts(
    cases: &[EvaluatedPairedCase],
) -> Result<Vec<PublicCategoryCount>, CampaignError> {
    [
        PresentationClass::BonaFide,
        PresentationClass::DisplayReplay,
        PresentationClass::NoFace,
        PresentationClass::NonMatedLiveCrossIdentity,
        PresentationClass::Print,
    ]
    .into_iter()
    .map(|presentation| {
        let selected: Vec<_> = cases
            .iter()
            .filter(|case| case.presentation == presentation)
            .collect();
        Ok(PublicCategoryCount {
            baseline_accepts: u64::try_from(
                selected
                    .iter()
                    .filter(|case| case.baseline.authentication_accept)
                    .count(),
            )
            .map_err(|_| CampaignError::ProtocolInvalid)?,
            candidate_accepts: u64::try_from(
                selected
                    .iter()
                    .filter(|case| case.candidate.authentication_accept)
                    .count(),
            )
            .map_err(|_| CampaignError::ProtocolInvalid)?,
            presentation: public_presentation(presentation),
            trials: u64::try_from(selected.len()).map_err(|_| CampaignError::ProtocolInvalid)?,
        })
    })
    .collect()
}

const fn public_presentation(presentation: PresentationClass) -> PublicPresentationCategory {
    match presentation {
        PresentationClass::BonaFide => PublicPresentationCategory::BonaFide,
        PresentationClass::DisplayReplay => PublicPresentationCategory::DisplayReplay,
        PresentationClass::NoFace => PublicPresentationCategory::NoFace,
        PresentationClass::NonMatedLiveCrossIdentity => PublicPresentationCategory::NonMatedLive,
        PresentationClass::Print => PublicPresentationCategory::Print,
    }
}

fn build_latency(
    context: ReductionContext<'_>,
    cases: &[EvaluatedPairedCase],
    authority: &std::collections::BTreeMap<
        (Identifier, u32),
        &crate::lifecycle::ValidatedEvaluationCell,
    >,
) -> Result<PublicLatencyResult, CampaignError> {
    let mut clustered = std::collections::BTreeMap::<Identifier, Vec<PairedLatencyUs>>::new();
    for case in cases {
        let cell = authority
            .get(&(case.case_id.clone(), case.instance_position))
            .ok_or(CampaignError::CaptureIncomplete)?;
        clustered
            .entry(Identifier::new(cell.token_sha256.as_str())?)
            .or_default()
            .push(PairedLatencyUs::new(
                case.baseline.latency_us,
                case.candidate.latency_us,
            ));
    }
    let clusters: Vec<_> = clustered
        .into_iter()
        .map(|(id, observations)| ClusterLatency::new(id, observations))
        .collect();
    let result = cluster_bootstrap_latency(
        &clusters,
        context.protocol.protocol().latency_budget_us(),
        context.protocol.protocol_sha256(),
    )?;
    Ok(PublicLatencyResult {
        allowed_increase_us: result.allowed_increase_us(),
        baseline_p50_us: result.baseline_p50_us(),
        baseline_p95_us: result.baseline_p95_us(),
        budget_us: result.budget_us(),
        candidate_p50_us: result.candidate_p50_us(),
        candidate_p95_us: result.candidate_p95_us(),
        disposition: result.decision().into(),
        upper_increase_us: result.upper_increase_us(),
    })
}

#[cfg(test)]
pub(crate) mod tests {
    use super::{
        reduce_campaign, EvaluatedPairedCase, ProfileCaseOutcome, ReductionContext, StageOutcome,
    };
    use crate::{
        lifecycle::tests::reduction_inputs, CampaignError, Sha256Digest, SignatureMetadata,
        SignerFingerprint,
    };

    fn outcome(authentication_accept: bool) -> ProfileCaseOutcome {
        ProfileCaseOutcome {
            detection: StageOutcome::Success,
            recognition: StageOutcome::Success,
            liveness: StageOutcome::Success,
            rgb_pad: StageOutcome::Success,
            ir_pad: StageOutcome::Success,
            authentication_accept,
            latency_us: 100,
            decision_value_ppb: None,
        }
    }

    fn complete_cases(bundle: &crate::ValidatedFrozenBundle) -> Vec<EvaluatedPairedCase> {
        bundle
            .evaluation_cells()
            .iter()
            .flat_map(|cell| {
                (0..cell.planned_count).map(|instance_position| EvaluatedPairedCase {
                    case_id: cell.logical_case_id.clone(),
                    instance_position,
                    stratum_ids: vec![cell.stratum_id.clone()],
                    presentation: cell.presentation_class,
                    expected: cell.expected_outcome,
                    baseline: outcome(cell.expected_outcome == crate::ExpectedOutcome::Accept),
                    candidate: outcome(cell.expected_outcome == crate::ExpectedOutcome::Accept),
                    attempt_history_sha256: cell.attempt_history_sha256.clone(),
                })
            })
            .collect()
    }

    pub(crate) fn passing_output() -> crate::ReductionOutput {
        let (protocol, bundle, evaluation) = reduction_inputs();
        let evaluator_fingerprint =
            SignerFingerprint::new("CCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCC").unwrap();
        let evaluator_provenance_sha256 = Sha256Digest::of(b"evaluator-v1");
        let signature: SignatureMetadata = serde_json::from_value(serde_json::json!({
            "algorithm": "open_pgp",
            "role": "evaluator",
            "signer_fingerprint": evaluator_fingerprint.as_str()
        }))
        .unwrap();
        reduce_campaign(
            ReductionContext {
                protocol: &protocol,
                bundle: &bundle,
                evaluation: &evaluation,
                evaluator_fingerprint: &evaluator_fingerprint,
                evaluator_provenance_sha256: &evaluator_provenance_sha256,
                evaluated_at_unix: 1789000001,
                signature: &signature,
            },
            complete_cases(&bundle),
        )
        .unwrap()
    }

    #[test]
    fn reducer_inputs_are_closed_categorical_outcomes() {
        let outcome = ProfileCaseOutcome {
            detection: StageOutcome::Success,
            recognition: StageOutcome::Incorrect,
            liveness: StageOutcome::NotApplicable,
            rgb_pad: StageOutcome::Incorrect,
            ir_pad: StageOutcome::Success,
            authentication_accept: false,
            latency_us: 1,
            decision_value_ppb: None,
        };
        let _: Option<EvaluatedPairedCase> = None;
        assert!(!outcome.authentication_accept);
    }

    #[test]
    fn reducer_rejects_every_missing_or_duplicate_authorized_instance() {
        let (protocol, bundle, evaluation) = reduction_inputs();
        let evaluator_fingerprint =
            SignerFingerprint::new("CCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCC").unwrap();
        let evaluator_provenance_sha256 = Sha256Digest::of(b"evaluator-v1");
        let signature: SignatureMetadata = serde_json::from_value(serde_json::json!({
            "algorithm": "open_pgp",
            "role": "evaluator",
            "signer_fingerprint": evaluator_fingerprint.as_str()
        }))
        .unwrap();
        let context = ReductionContext {
            protocol: &protocol,
            bundle: &bundle,
            evaluation: &evaluation,
            evaluator_fingerprint: &evaluator_fingerprint,
            evaluator_provenance_sha256: &evaluator_provenance_sha256,
            evaluated_at_unix: 1789000001,
            signature: &signature,
        };
        let complete = complete_cases(&bundle);
        assert!(reduce_campaign(context, complete.clone()).is_ok());

        let mut missing = complete.clone();
        missing.pop();
        assert_eq!(
            reduce_campaign(context, missing),
            Err(CampaignError::CaptureIncomplete)
        );
        let mut duplicate = complete;
        duplicate.push(duplicate[0].clone());
        assert_eq!(
            reduce_campaign(context, duplicate),
            Err(CampaignError::CaptureIncomplete)
        );
    }

    #[test]
    fn reducer_output_is_independent_of_input_order() {
        let (protocol, bundle, evaluation) = reduction_inputs();
        let evaluator_fingerprint =
            SignerFingerprint::new("CCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCC").unwrap();
        let evaluator_provenance_sha256 = Sha256Digest::of(b"evaluator-v1");
        let signature: SignatureMetadata = serde_json::from_value(serde_json::json!({
            "algorithm": "open_pgp",
            "role": "evaluator",
            "signer_fingerprint": evaluator_fingerprint.as_str()
        }))
        .unwrap();
        let context = ReductionContext {
            protocol: &protocol,
            bundle: &bundle,
            evaluation: &evaluation,
            evaluator_fingerprint: &evaluator_fingerprint,
            evaluator_provenance_sha256: &evaluator_provenance_sha256,
            evaluated_at_unix: 1789000001,
            signature: &signature,
        };
        let cases = complete_cases(&bundle);
        let mut reversed = cases.clone();
        reversed.reverse();
        assert_eq!(
            reduce_campaign(context, cases).unwrap(),
            reduce_campaign(context, reversed).unwrap()
        );
    }

    #[test]
    fn public_projection_contains_only_aggregate_categorical_counts() {
        let (protocol, bundle, evaluation) = reduction_inputs();
        let evaluator_fingerprint =
            SignerFingerprint::new("CCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCC").unwrap();
        let evaluator_provenance_sha256 = Sha256Digest::of(b"evaluator-v1");
        let signature: SignatureMetadata = serde_json::from_value(serde_json::json!({
            "algorithm": "open_pgp",
            "role": "evaluator",
            "signer_fingerprint": evaluator_fingerprint.as_str()
        }))
        .unwrap();
        let output = reduce_campaign(
            ReductionContext {
                protocol: &protocol,
                bundle: &bundle,
                evaluation: &evaluation,
                evaluator_fingerprint: &evaluator_fingerprint,
                evaluator_provenance_sha256: &evaluator_provenance_sha256,
                evaluated_at_unix: 1789000001,
                signature: &signature,
            },
            complete_cases(&bundle),
        )
        .unwrap();
        assert_eq!(output.public_result.category_counts.len(), 5);
        assert!(output
            .public_result
            .category_counts
            .iter()
            .all(|count| count.trials == 99 || count.trials == 1_386));
    }

    #[test]
    fn reducer_fails_closed_for_each_pre_review_gate_category() {
        let (protocol, bundle, evaluation) = reduction_inputs();
        let evaluator_fingerprint =
            SignerFingerprint::new("CCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCC").unwrap();
        let evaluator_provenance_sha256 = Sha256Digest::of(b"evaluator-v1");
        let signature: SignatureMetadata = serde_json::from_value(serde_json::json!({
            "algorithm": "open_pgp",
            "role": "evaluator",
            "signer_fingerprint": evaluator_fingerprint.as_str()
        }))
        .unwrap();
        let context = ReductionContext {
            protocol: &protocol,
            bundle: &bundle,
            evaluation: &evaluation,
            evaluator_fingerprint: &evaluator_fingerprint,
            evaluator_provenance_sha256: &evaluator_provenance_sha256,
            evaluated_at_unix: 1789000001,
            signature: &signature,
        };
        let complete = complete_cases(&bundle);

        let operator_fingerprint =
            SignerFingerprint::new("BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB").unwrap();
        let operator_as_evaluator: SignatureMetadata = serde_json::from_value(serde_json::json!({
            "algorithm": "open_pgp",
            "role": "evaluator",
            "signer_fingerprint": operator_fingerprint.as_str()
        }))
        .unwrap();
        assert_eq!(
            reduce_campaign(
                ReductionContext {
                    evaluator_fingerprint: &operator_fingerprint,
                    signature: &operator_as_evaluator,
                    ..context
                },
                complete.clone()
            ),
            Err(CampaignError::EvaluatorDrift)
        );

        let mut corrupt = complete.clone();
        corrupt[0].attempt_history_sha256 = Sha256Digest::of(b"corrupt");
        assert_eq!(
            reduce_campaign(context, corrupt),
            Err(CampaignError::ProvenanceMismatch)
        );

        let mut unavailable = complete.clone();
        unavailable[0].candidate.detection = StageOutcome::NotApplicable;
        assert_eq!(
            reduce_campaign(context, unavailable),
            Err(CampaignError::CaptureIncomplete)
        );

        let mut insecure = complete.clone();
        insecure
            .iter_mut()
            .find(|case| case.presentation != crate::PresentationClass::BonaFide)
            .unwrap()
            .candidate
            .authentication_accept = true;
        assert_eq!(
            reduce_campaign(context, insecure),
            Err(CampaignError::SecurityGateFailed)
        );

        for gate in [
            crate::BinaryGate::Detection,
            crate::BinaryGate::Recognition,
            crate::BinaryGate::Liveness,
            crate::BinaryGate::RgbPad,
            crate::BinaryGate::IrPad,
        ] {
            let mut inferior = complete.clone();
            for case in inferior
                .iter_mut()
                .filter(|case| case.presentation == crate::PresentationClass::BonaFide)
            {
                let stage = match gate {
                    crate::BinaryGate::Detection => &mut case.candidate.detection,
                    crate::BinaryGate::Recognition => &mut case.candidate.recognition,
                    crate::BinaryGate::Liveness => &mut case.candidate.liveness,
                    crate::BinaryGate::RgbPad => &mut case.candidate.rgb_pad,
                    crate::BinaryGate::IrPad => &mut case.candidate.ir_pad,
                };
                *stage = StageOutcome::Incorrect;
            }
            assert_eq!(
                reduce_campaign(context, inferior),
                Err(CampaignError::NoninferiorityFailed),
                "accepted failed {gate:?} intersection"
            );
        }

        let mut slow = complete;
        slow.iter_mut()
            .for_each(|case| case.candidate.latency_us = 2_000_000);
        assert_eq!(
            reduce_campaign(context, slow),
            Err(CampaignError::LatencyFailed)
        );
    }

    #[test]
    fn public_projection_omits_private_case_and_token_material() {
        use crate::CanonicalDocument;

        let (protocol, bundle, evaluation) = reduction_inputs();
        let evaluator_fingerprint =
            SignerFingerprint::new("CCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCC").unwrap();
        let evaluator_provenance_sha256 = Sha256Digest::of(b"evaluator-v1");
        let signature: SignatureMetadata = serde_json::from_value(serde_json::json!({
            "algorithm": "open_pgp",
            "role": "evaluator",
            "signer_fingerprint": evaluator_fingerprint.as_str()
        }))
        .unwrap();
        let output = reduce_campaign(
            ReductionContext {
                protocol: &protocol,
                bundle: &bundle,
                evaluation: &evaluation,
                evaluator_fingerprint: &evaluator_fingerprint,
                evaluator_provenance_sha256: &evaluator_provenance_sha256,
                evaluated_at_unix: 1789000001,
                signature: &signature,
            },
            complete_cases(&bundle),
        )
        .unwrap();
        let public = String::from_utf8(output.public_result.to_canonical_json().unwrap()).unwrap();
        for forbidden in [
            "identity",
            "token",
            "path",
            "image",
            "crop",
            "tensor",
            "template",
            "embedding",
            "score",
            "serial",
            "consent",
            "per_case",
            "error_text",
        ] {
            assert!(
                !public.contains(forbidden),
                "leaked field fragment: {forbidden}"
            );
        }
        assert!(!public.contains(&"0".repeat(64)));
        assert!(!public.contains(&"e".repeat(64)));
        assert!(output.private_transcript_shards.iter().all(|shard| {
            shard.to_canonical_json().unwrap().len() <= crate::MAX_CAMPAIGN_DOCUMENT_BYTES
        }));
    }
}

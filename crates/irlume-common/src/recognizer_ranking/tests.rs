// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright the irlume contributors.

use super::*;

const WORKLOAD: WorkloadKey<'_> = WorkloadKey(b"synthetic-workload");
const ON: Switches = Switches {
    npu: true,
    gpu: true,
};

fn candidate(accelerator: Accelerator) -> Candidate<'static> {
    Candidate {
        accelerator,
        key: CandidateKey(match accelerator {
            Accelerator::Npu => b"synthetic-npu",
            Accelerator::Gpu => b"synthetic-gpu",
        }),
        workload: WORKLOAD,
        assessment: Assessment::ReportedEligible,
    }
}

fn ordered(candidate: Candidate<'_>) -> OrderedTarget<'_> {
    OrderedTarget::Accelerator {
        accelerator: candidate.accelerator,
        key: candidate.key,
    }
}

fn expected(candidate: Candidate<'_>, reason: Reason) -> Recommendation<'_> {
    Recommendation {
        target: RecommendedTarget::Accelerator {
            accelerator: candidate.accelerator,
            key: candidate.key,
        },
        reason,
    }
}

fn cpu(reason: Reason) -> Recommendation<'static> {
    Recommendation {
        target: RecommendedTarget::Cpu,
        reason,
    }
}

fn auto<'a>(
    switches: Switches,
    candidates: &[Candidate<'a>],
    targets: &[OrderedTarget<'_>],
) -> Recommendation<'a> {
    super::recommend(
        Preference::Auto,
        switches,
        WORKLOAD,
        candidates,
        Some(&EvidenceOrder {
            workload: WORKLOAD,
            targets,
        }),
    )
}

#[test]
fn explicit_cpu_ignores_candidates_keys_and_evidence() {
    let malformed = Candidate {
        key: CandidateKey(b""),
        workload: WorkloadKey(b""),
        ..candidate(Accelerator::Gpu)
    };
    let too_many = [malformed; MAX_CANDIDATES + 1];
    let targets = [OrderedTarget::Cpu; MAX_ORDER_TARGETS + 1];
    assert_eq!(
        super::recommend(
            Preference::Cpu,
            ON,
            WorkloadKey(b""),
            &too_many,
            Some(&EvidenceOrder {
                workload: WorkloadKey(b""),
                targets: &targets,
            }),
        ),
        cpu(Reason::ExplicitPreference)
    );
}

#[test]
fn explicit_accelerators_use_matching_assertions_without_ranking_evidence() {
    for (preference, accelerator) in [
        (Preference::Npu, Accelerator::Npu),
        (Preference::Gpu, Accelerator::Gpu),
    ] {
        let selected = candidate(accelerator);
        assert_eq!(
            super::recommend(preference, ON, WORKLOAD, &[selected], None),
            expected(selected, Reason::ExplicitPreference)
        );
    }
}

#[test]
fn explicit_preferences_never_substitute_the_other_accelerator() {
    for (preference, other) in [
        (Preference::Npu, Accelerator::Gpu),
        (Preference::Gpu, Accelerator::Npu),
    ] {
        assert_eq!(
            super::recommend(preference, ON, WORKLOAD, &[candidate(other)], None),
            cpu(Reason::MissingCandidate)
        );
    }
}

#[test]
fn explicit_switch_refusal_precedes_candidate_and_scope_validation() {
    let malformed = Candidate {
        key: CandidateKey(b""),
        workload: WorkloadKey(b""),
        ..candidate(Accelerator::Gpu)
    };
    for preference in [Preference::Npu, Preference::Gpu] {
        assert_eq!(
            super::recommend(
                preference,
                Switches {
                    npu: false,
                    gpu: false,
                },
                WorkloadKey(b""),
                &[malformed; MAX_CANDIDATES + 1],
                None,
            ),
            cpu(Reason::SwitchDisabled)
        );
    }
}

#[test]
fn explicit_preferences_preserve_each_asserted_refusal_and_unobserved_state() {
    for (preference, accelerator) in [
        (Preference::Npu, Accelerator::Npu),
        (Preference::Gpu, Accelerator::Gpu),
    ] {
        for refusal in [
            Refusal::UnsupportedBuild,
            Refusal::LoadingNotAdmitted,
            Refusal::RuntimeUnavailable,
            Refusal::IdentityUnavailable,
            Refusal::AmbiguousDevice,
            Refusal::NotCertified,
        ] {
            let refused = Candidate {
                assessment: Assessment::Refused(refusal),
                ..candidate(accelerator)
            };
            assert_eq!(
                super::recommend(preference, ON, WORKLOAD, &[refused], None),
                cpu(Reason::Refused(refusal))
            );
        }
        let unobserved = Candidate {
            assessment: Assessment::Unobserved,
            ..candidate(accelerator)
        };
        assert_eq!(
            super::recommend(preference, ON, WORKLOAD, &[unobserved], None),
            cpu(Reason::Unobserved)
        );
    }
}

#[test]
fn explicit_preference_ignores_other_class_assessment_and_evidence() {
    let selected = candidate(Accelerator::Npu);
    let unrelated = Candidate {
        key: CandidateKey(b""),
        workload: WorkloadKey(b"different-workload"),
        ..candidate(Accelerator::Gpu)
    };
    let targets = [OrderedTarget::Cpu, OrderedTarget::Cpu];
    assert_eq!(
        super::recommend(
            Preference::Npu,
            ON,
            WORKLOAD,
            &[unrelated, selected],
            Some(&EvidenceOrder {
                workload: WorkloadKey(b"different-workload"),
                targets: &targets,
            }),
        ),
        expected(selected, Reason::ExplicitPreference)
    );
}

#[test]
fn auto_follows_either_evidence_order_independent_of_candidate_enumeration() {
    let npu = candidate(Accelerator::Npu);
    let gpu = candidate(Accelerator::Gpu);
    for candidates in [[npu, gpu], [gpu, npu]] {
        for (first, second) in [(npu, gpu), (gpu, npu)] {
            assert_eq!(
                auto(
                    ON,
                    &candidates,
                    &[ordered(first), ordered(second), OrderedTarget::Cpu],
                ),
                expected(first, Reason::OrderedEvidence)
            );
        }
    }
}

#[test]
fn auto_can_recommend_cpu_ahead_of_both_asserted_eligible_accelerators() {
    let npu = candidate(Accelerator::Npu);
    let gpu = candidate(Accelerator::Gpu);
    assert_eq!(
        auto(
            ON,
            &[npu, gpu],
            &[OrderedTarget::Cpu, ordered(gpu), ordered(npu)],
        ),
        cpu(Reason::OrderedEvidence)
    );
}

#[test]
fn independent_switches_filter_hypothetical_assertions_not_runtime_collectors() {
    let npu = candidate(Accelerator::Npu);
    let gpu = candidate(Accelerator::Gpu);
    let targets = [ordered(gpu), ordered(npu), OrderedTarget::Cpu];
    for (switches, recommendation) in [
        (ON, expected(gpu, Reason::OrderedEvidence)),
        (
            Switches {
                npu: true,
                gpu: false,
            },
            expected(npu, Reason::OrderedEvidence),
        ),
        (
            Switches {
                npu: false,
                gpu: true,
            },
            expected(gpu, Reason::OrderedEvidence),
        ),
        (
            Switches {
                npu: false,
                gpu: false,
            },
            cpu(Reason::NoEligibleAccelerator),
        ),
    ] {
        assert_eq!(auto(switches, &[gpu, npu], &targets), recommendation);
    }
}

#[test]
fn auto_skips_refused_and_unobserved_candidates_even_if_ordered_first() {
    let npu = candidate(Accelerator::Npu);
    let gpu = candidate(Accelerator::Gpu);
    for assessment in [
        Assessment::Unobserved,
        Assessment::Refused(Refusal::NotCertified),
        Assessment::Refused(Refusal::LoadingNotAdmitted),
    ] {
        assert_eq!(
            auto(
                ON,
                &[Candidate { assessment, ..gpu }, npu],
                &[ordered(gpu), ordered(npu), OrderedTarget::Cpu],
            ),
            expected(npu, Reason::OrderedEvidence)
        );
    }
}

#[test]
fn auto_without_eligible_candidates_needs_no_order() {
    let refused = Candidate {
        assessment: Assessment::Refused(Refusal::NotCertified),
        ..candidate(Accelerator::Gpu)
    };
    let unobserved = Candidate {
        assessment: Assessment::Unobserved,
        ..candidate(Accelerator::Npu)
    };
    for candidates in [&[][..], &[refused][..], &[refused, unobserved][..]] {
        assert_eq!(
            super::recommend(Preference::Auto, ON, WORKLOAD, candidates, None),
            cpu(Reason::NoEligibleAccelerator)
        );
    }
}

#[test]
fn eligible_auto_candidate_without_evidence_does_not_get_a_default_rank() {
    assert_eq!(
        super::recommend(
            Preference::Auto,
            ON,
            WORKLOAD,
            &[candidate(Accelerator::Gpu)],
            None,
        ),
        cpu(Reason::MissingEvidence)
    );
}

#[test]
fn repeated_enabled_candidates_refuse_identical_and_conflicting_assertions() {
    let gpu = candidate(Accelerator::Gpu);
    for duplicate in [
        gpu,
        Candidate {
            key: CandidateKey(b"different-gpu"),
            ..gpu
        },
        Candidate {
            assessment: Assessment::Unobserved,
            ..gpu
        },
        Candidate {
            assessment: Assessment::Refused(Refusal::NotCertified),
            ..gpu
        },
    ] {
        for candidates in [[gpu, duplicate], [duplicate, gpu]] {
            for preference in [Preference::Auto, Preference::Gpu] {
                assert_eq!(
                    super::recommend(preference, ON, WORKLOAD, &candidates, None),
                    cpu(Reason::AmbiguousCandidates)
                );
            }
        }
    }
}

#[test]
fn repeated_disabled_class_records_are_not_considered() {
    let gpu = candidate(Accelerator::Gpu);
    assert_eq!(
        super::recommend(
            Preference::Auto,
            Switches {
                npu: true,
                gpu: false,
            },
            WORKLOAD,
            &[gpu, gpu],
            None,
        ),
        cpu(Reason::NoEligibleAccelerator)
    );
    assert_eq!(
        super::recommend(Preference::Npu, ON, WORKLOAD, &[gpu, gpu], None),
        cpu(Reason::MissingCandidate)
    );
}

#[test]
fn candidate_records_are_bounded() {
    let candidates = [candidate(Accelerator::Gpu); MAX_CANDIDATES + 1];
    for preference in [Preference::Auto, Preference::Gpu] {
        assert_eq!(
            super::recommend(preference, ON, WORKLOAD, &candidates, None),
            cpu(Reason::AmbiguousCandidates)
        );
    }
}

#[test]
fn orders_are_bounded_and_require_cpu_exactly_once() {
    let gpu = candidate(Accelerator::Gpu);
    let too_many = [OrderedTarget::Cpu; MAX_ORDER_TARGETS + 1];
    for targets in [
        &[][..],
        &[ordered(gpu)][..],
        &[OrderedTarget::Cpu, OrderedTarget::Cpu, ordered(gpu)][..],
        &too_many[..],
    ] {
        assert_eq!(auto(ON, &[gpu], targets), cpu(Reason::InvalidOrder));
    }
}

#[test]
fn duplicate_order_classes_refuse_even_when_the_class_is_ineligible() {
    let npu = candidate(Accelerator::Npu);
    let gpu = candidate(Accelerator::Gpu);
    let different_gpu = Candidate {
        key: CandidateKey(b"different-gpu"),
        ..gpu
    };
    for second in [gpu, different_gpu] {
        let targets = [ordered(gpu), ordered(second), OrderedTarget::Cpu];
        assert_eq!(auto(ON, &[gpu], &targets), cpu(Reason::InvalidOrder));
        assert_eq!(auto(ON, &[npu], &targets), cpu(Reason::InvalidOrder));
    }
}

#[test]
fn missing_eligible_targets_refuse_even_when_cpu_is_first() {
    let npu = candidate(Accelerator::Npu);
    let gpu = candidate(Accelerator::Gpu);
    for targets in [
        &[OrderedTarget::Cpu][..],
        &[OrderedTarget::Cpu, ordered(gpu)][..],
    ] {
        assert_eq!(auto(ON, &[npu, gpu], targets), cpu(Reason::InvalidOrder));
    }
}

#[test]
fn unknown_identity_for_an_eligible_class_refuses_instead_of_skipping() {
    let gpu = candidate(Accelerator::Gpu);
    let unknown = OrderedTarget::Accelerator {
        accelerator: Accelerator::Gpu,
        key: CandidateKey(b"unknown-gpu"),
    };
    for targets in [[unknown, OrderedTarget::Cpu], [OrderedTarget::Cpu, unknown]] {
        assert_eq!(auto(ON, &[gpu], &targets), cpu(Reason::InvalidOrder));
    }
}

#[test]
fn nonempty_unknown_identity_for_an_ineligible_class_may_be_skipped() {
    let npu = candidate(Accelerator::Npu);
    let unknown = OrderedTarget::Accelerator {
        accelerator: Accelerator::Gpu,
        key: CandidateKey(b"unavailable-gpu"),
    };
    assert_eq!(
        auto(ON, &[npu], &[unknown, ordered(npu), OrderedTarget::Cpu]),
        expected(npu, Reason::OrderedEvidence)
    );
}

#[test]
fn candidate_workload_mismatch_refuses_explicit_and_auto_recommendations() {
    let gpu = Candidate {
        workload: WorkloadKey(b"different-workload"),
        ..candidate(Accelerator::Gpu)
    };
    for preference in [Preference::Gpu, Preference::Auto] {
        assert_eq!(
            super::recommend(preference, ON, WORKLOAD, &[gpu], None),
            cpu(Reason::WorkloadMismatch)
        );
    }
}

#[test]
fn one_matching_candidate_does_not_hide_another_eligible_workload_mismatch() {
    let npu = Candidate {
        workload: WorkloadKey(b"different-workload"),
        ..candidate(Accelerator::Npu)
    };
    let gpu = candidate(Accelerator::Gpu);
    assert_eq!(
        auto(
            ON,
            &[gpu, npu],
            &[ordered(gpu), ordered(npu), OrderedTarget::Cpu],
        ),
        cpu(Reason::WorkloadMismatch)
    );
}

#[test]
fn evidence_workload_must_match_exactly() {
    let gpu = candidate(Accelerator::Gpu);
    let targets = [ordered(gpu), OrderedTarget::Cpu];
    for workload in [
        WorkloadKey(b"Synthetic-workload"),
        WorkloadKey(b"synthetic-workload "),
        WorkloadKey(b"synthetic-workload\0"),
    ] {
        assert_eq!(
            super::recommend(
                Preference::Auto,
                ON,
                WORKLOAD,
                &[gpu],
                Some(&EvidenceOrder {
                    workload,
                    targets: &targets,
                }),
            ),
            cpu(Reason::EvidenceMismatch)
        );
    }
}

#[test]
fn empty_requested_or_eligible_candidate_keys_refuse() {
    let gpu = candidate(Accelerator::Gpu);
    for preference in [Preference::Auto, Preference::Gpu] {
        for (workload, selected) in [
            (WorkloadKey(b""), gpu),
            (
                WORKLOAD,
                Candidate {
                    key: CandidateKey(b""),
                    ..gpu
                },
            ),
            (
                WORKLOAD,
                Candidate {
                    workload: WorkloadKey(b""),
                    ..gpu
                },
            ),
        ] {
            assert_eq!(
                super::recommend(preference, ON, workload, &[selected], None),
                cpu(Reason::InvalidKey)
            );
        }
    }
}

#[test]
fn empty_evidence_workload_or_order_key_refuses() {
    let gpu = candidate(Accelerator::Gpu);
    let targets = [ordered(gpu), OrderedTarget::Cpu];
    assert_eq!(
        super::recommend(
            Preference::Auto,
            ON,
            WORKLOAD,
            &[gpu],
            Some(&EvidenceOrder {
                workload: WorkloadKey(b""),
                targets: &targets,
            }),
        ),
        cpu(Reason::InvalidKey)
    );
    for accelerator in [Accelerator::Gpu, Accelerator::Npu] {
        let empty = OrderedTarget::Accelerator {
            accelerator,
            key: CandidateKey(b""),
        };
        assert_eq!(
            auto(ON, &[gpu], &[empty, OrderedTarget::Cpu]),
            cpu(Reason::InvalidKey)
        );
    }
}

#[test]
fn disabled_and_unobserved_candidate_keys_are_not_treated_as_evidence() {
    let npu = candidate(Accelerator::Npu);
    let invalid_gpu = Candidate {
        key: CandidateKey(b""),
        workload: WorkloadKey(b""),
        ..candidate(Accelerator::Gpu)
    };
    let targets = [ordered(npu), OrderedTarget::Cpu];
    assert_eq!(
        auto(
            Switches {
                npu: true,
                gpu: false,
            },
            &[invalid_gpu, npu],
            &targets,
        ),
        expected(npu, Reason::OrderedEvidence)
    );
    assert_eq!(
        auto(
            ON,
            &[
                Candidate {
                    assessment: Assessment::Unobserved,
                    ..invalid_gpu
                },
                npu,
            ],
            &targets,
        ),
        expected(npu, Reason::OrderedEvidence)
    );
}

#[test]
fn candidate_key_equality_does_not_trim_fold_case_or_ignore_trailing_bytes() {
    let gpu = candidate(Accelerator::Gpu);
    for key in [
        b"Synthetic-gpu".as_slice(),
        b"synthetic-gpu ",
        b"synthetic-gpu\0",
    ] {
        let target = OrderedTarget::Accelerator {
            accelerator: Accelerator::Gpu,
            key: CandidateKey(key),
        };
        assert_eq!(
            auto(ON, &[gpu], &[target, OrderedTarget::Cpu]),
            cpu(Reason::InvalidOrder)
        );
    }
}

#[test]
fn opaque_binary_keys_are_not_required_to_be_hashes_or_utf8() {
    let workload = WorkloadKey(&[0xff, 0, 0x81]);
    let gpu = Candidate {
        key: CandidateKey(&[0xff, 0, 7]),
        workload,
        ..candidate(Accelerator::Gpu)
    };
    let targets = [ordered(gpu), OrderedTarget::Cpu];
    assert_eq!(
        super::recommend(
            Preference::Auto,
            ON,
            workload,
            &[gpu],
            Some(&EvidenceOrder {
                workload,
                targets: &targets,
            }),
        ),
        expected(gpu, Reason::OrderedEvidence)
    );
}

#[test]
fn equal_candidate_bytes_do_not_confuse_accelerator_classes() {
    let npu = candidate(Accelerator::Npu);
    let gpu = Candidate {
        key: npu.key,
        ..candidate(Accelerator::Gpu)
    };
    assert_eq!(
        auto(
            ON,
            &[npu, gpu],
            &[ordered(gpu), ordered(npu), OrderedTarget::Cpu],
        ),
        expected(gpu, Reason::OrderedEvidence)
    );
}

#[test]
fn recommendation_borrows_the_candidate_key_not_the_evidence_key() {
    let candidate_bytes = Vec::from(b"synthetic-gpu");
    let gpu = Candidate {
        key: CandidateKey(&candidate_bytes),
        ..candidate(Accelerator::Gpu)
    };
    let recommendation = {
        let evidence_bytes = candidate_bytes.clone();
        let targets = [
            OrderedTarget::Accelerator {
                accelerator: Accelerator::Gpu,
                key: CandidateKey(&evidence_bytes),
            },
            OrderedTarget::Cpu,
        ];
        auto(ON, &[gpu], &targets)
    };
    assert_eq!(recommendation, expected(gpu, Reason::OrderedEvidence));
    let RecommendedTarget::Accelerator { key, .. } = recommendation.target else {
        panic!("expected the hypothetical GPU recommendation");
    };
    assert!(std::ptr::eq(key.0.as_ptr(), candidate_bytes.as_ptr()));
}

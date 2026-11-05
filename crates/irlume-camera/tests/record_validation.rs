// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright the irlume contributors.

use irlume_camera::measurement as m;

fn record() -> m::MeasurementRecord {
    let round = m::RateRound {
        deltas: 30,
        timestamp_span_us: 1_000_000,
        wall_clock_us: Some(1_000_001),
        max_inter_frame_gap_us: Some(33_334),
        continuity_errors: 0,
        meets_floor: true,
    };
    m::MeasurementRecord {
        schema_version: m::MEASUREMENT_SCHEMA_VERSION,
        policy: m::AcceptancePolicy {
            policy_version: 1,
            min_completed_rounds: 1,
            max_failed_rounds: 0,
            max_inter_frame_gap_us: None,
            require_all_rounds_meet_floor: true,
        },
        tool_revision: "synthetic".into(),
        measured_at_unix: 1,
        method: "single-role control".into(),
        stages: Vec::new(),
        rates: vec![(
            m::MeasuredRole::Ir,
            m::RateEvidence::from_rounds(&[round], 0).unwrap(),
        )],
        arm_failed_rounds: 0,
        acceptance: m::Acceptance {
            accepted: true,
            failures: Vec::new(),
        },
    }
}

#[test]
fn consistent_single_role_records_remain_valid() {
    let record = record();
    assert!(record.validate().is_ok());
    assert!(record.evaluate_acceptance().unwrap().accepted);
}

#[test]
fn structural_validation_does_not_rewrite_acceptance() {
    let mut record = record();
    record.acceptance.accepted = false;
    record
        .acceptance
        .failures
        .push(m::AcceptanceFailure::TooFewCompletedRounds {
            role: m::MeasuredRole::Rgb,
            completed: 0,
            required: 1,
        });
    let refusal = record.acceptance.clone();
    assert!(record.validate().is_ok());
    assert_eq!(record.acceptance, refusal);
    assert!(record.evaluate_acceptance().unwrap().accepted);
}

#[test]
fn invalid_nested_rounds_and_aggregates_are_rejected() {
    type Corrupt = fn(&mut m::RateEvidence);
    let cases: &[(&str, Corrupt)] = &[
        ("zero deltas", |e| e.rounds[0].deltas = 0),
        ("zero span", |e| e.rounds[0].timestamp_span_us = 0),
        ("short wall clock", |e| e.rounds[0].wall_clock_us = Some(1)),
        ("excess gap", |e| {
            e.rounds[0].max_inter_frame_gap_us = Some(1_000_001)
        }),
        ("empty rounds", |e| e.rounds.clear()),
        ("too many rounds", |e| {
            e.rounds = vec![e.rounds[0]; m::MAX_ROUNDS + 1]
        }),
        ("completed count", |e| e.rounds_completed += 1),
        ("minimum", |e| e.rate_min.deltas += 1),
        ("p05", |e| e.rate_p05.span_us += 1),
        ("p50", |e| e.rate_p50.deltas += 1),
        ("maximum", |e| e.rate_max.span_us += 1),
        ("continuity total", |e| e.continuity_errors += 1),
        ("aggregate gap", |e| e.max_inter_frame_gap_us = None),
    ];
    let mut missed = Vec::new();
    for &(name, corrupt) in cases {
        let mut bad = record();
        corrupt(&mut bad.rates[0].1);
        if bad.validate().is_ok() {
            missed.push(format!("validate: {name}"));
        }
        if bad.evaluate_acceptance().is_ok() {
            missed.push(format!("evaluate: {name}"));
        }
    }
    assert!(missed.is_empty(), "{}", missed.join(", "));
}

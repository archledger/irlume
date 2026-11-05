// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright the irlume contributors.

use irlume_camera::measurement as m;
use irlume_camera::{pair_sample_measurement_record, PairSample};

fn round(drops: u64) -> m::RateRound {
    m::RateRound::from_window_facts(30, 1_000_000, drops, 33_334, true).unwrap()
}

fn pair() -> PairSample {
    PairSample {
        rounds: 1,
        rgb_rate_rounds: vec![round(0)],
        ir_rate_rounds: vec![round(0)],
        ..PairSample::default()
    }
}

fn record(sample: &PairSample) -> m::MeasurementRecord {
    pair_sample_measurement_record("sequential", sample, 1, "synthetic").unwrap()
}

fn assert_missing(record: &m::MeasurementRecord, missing: &[m::MeasuredRole]) {
    assert!(!record.acceptance.accepted);
    assert_eq!(record.rates.len(), 2 - missing.len());
    for role in missing {
        assert!(!record.rates.iter().any(|(actual, _)| actual == role));
        assert!(record.acceptance.failures.contains(
            &m::AcceptanceFailure::TooFewCompletedRounds {
                role: *role,
                completed: 0,
                required: 1,
            }
        ));
    }
    assert_eq!(record.acceptance.failures.len(), missing.len());
}

#[test]
fn complete_pair_accepts_without_extra_failures() {
    let record = record(&pair());
    assert!(record.acceptance.accepted);
    assert!(record.acceptance.failures.is_empty());
    assert_eq!(record.rates.len(), 2);
}

#[test]
fn missing_rgb_refuses_without_inventing_observations() {
    let mut sample = pair();
    sample.rgb_rate_rounds.clear();
    assert_missing(&record(&sample), &[m::MeasuredRole::Rgb]);
}

#[test]
fn missing_ir_refuses_without_inventing_observations() {
    let mut sample = pair();
    sample.ir_rate_rounds.clear();
    assert_missing(&record(&sample), &[m::MeasuredRole::Ir]);
}

#[test]
fn empty_pair_refuses_both_roles() {
    let sample = PairSample {
        rounds: 1,
        ..PairSample::default()
    };
    assert_missing(
        &record(&sample),
        &[m::MeasuredRole::Rgb, m::MeasuredRole::Ir],
    );
}

#[test]
fn generic_single_role_evaluation_remains_valid() {
    let mut sample = pair();
    sample.rgb_rate_rounds.clear();
    let record = record(&sample);
    assert_eq!(record.rates.len(), 1);
    assert!(record.validate().is_ok());
    assert!(record.evaluate_acceptance().unwrap().accepted);
}

#[test]
fn existing_floor_and_arm_failures_remain_refusals() {
    let mut floor = pair();
    floor.rgb_rate_rounds[0].meets_floor = false;
    assert!(!record(&floor).acceptance.accepted);
    let mut failed = pair();
    failed.failed = 1;
    assert!(!record(&failed).acceptance.accepted);
}

#[test]
fn continuity_totals_saturate_and_keep_the_original_rounds() {
    let cases = [
        (1, 2, 3),
        (u32::MAX - 1, 1, u32::MAX),
        (u32::MAX, 1, u32::MAX),
        (u32::MAX, u32::MAX, u32::MAX),
    ];
    let mut failures = Vec::new();
    for (first, second, expected) in cases {
        let rounds = [round(u64::from(first)), round(u64::from(second))];
        match std::panic::catch_unwind(|| m::RateEvidence::from_rounds(&rounds, 0)) {
            Ok(Ok(evidence)) => {
                if evidence.continuity_errors != expected || evidence.rounds != rounds {
                    failures.push(format!(
                        "{first}+{second}: {:?}",
                        evidence.continuity_errors
                    ));
                }
            }
            Ok(Err(error)) => failures.push(format!("{first}+{second}: {error:?}")),
            Err(_) => failures.push(format!("{first}+{second}: panicked")),
        }
    }
    assert!(failures.is_empty(), "{}", failures.join(", "));
}

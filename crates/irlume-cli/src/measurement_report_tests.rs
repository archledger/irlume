// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright the irlume contributors.

#[test]
fn invalid_success_still_has_defensive_inconsistent_reporting() {
    use irlume_camera::measurement as m;
    let round = m::RateRound::from_window_facts(30, 1_000_000, 0, 25_000, true).unwrap();
    let good = m::MeasurementRecord {
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
        method: "sequential".into(),
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
    };
    let mut invalid = good.clone();
    invalid.schema_version += 1;
    assert!(invalid.evaluate_acceptance().is_err());
    let reference = super::measurement_drift_report(&[invalid.clone()], &[good.clone()]).join("\n");
    assert!(
        reference.contains("accepted inconsistent -> true"),
        "{reference}"
    );
    let fresh = super::measurement_drift_report(&[good], &[invalid]).join("\n");
    assert!(fresh.contains("accepted true -> inconsistent"), "{fresh}");
}

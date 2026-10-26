// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright the irlume contributors.

use super::*;

const EPOCH: Epoch = Epoch(41);
const CLEAN: CleanupEvidence = CleanupEvidence {
    total_j_empty: true,
    fully_reaped: true,
    fixture_consumers: 0,
};

fn apply(job: &mut Job, event: Event) {
    assert_eq!(job.apply(EPOCH, event), Ok(()));
    let report = job.report();
    assert_eq!(report.epoch, EPOCH);
    assert!(!report.native_authorized, "m13_claim_native_authority");
    assert!(!report.full_contract_proven, "m14_claim_full_contract");
}

fn running() -> Job {
    let mut job = Job::new(EPOCH);
    apply(&mut job, Event::Reserve(Lease::Identity));
    apply(&mut job, Event::Reserve(Lease::Generation));
    apply(&mut job, Event::Create);
    job
}

#[test]
fn c01_both_reservations_precede_create() {
    for (reservation, mutation) in [
        (Lease::Identity, "m01_skip_generation_reservation"),
        (Lease::Generation, "m02_skip_identity_reservation"),
    ] {
        let mut job = Job::new(EPOCH);
        assert_eq!(job.apply(EPOCH, Event::Create), Err(Reject::InvalidOrder));
        apply(&mut job, Event::Reserve(reservation));
        assert_eq!(
            job.apply(EPOCH, Event::Create),
            Err(Reject::InvalidOrder),
            "{mutation}"
        );
        assert_eq!(job.report().phase, Phase::Reserving);
    }
    assert_eq!(running().report().phase, Phase::Running);
}

#[test]
fn c02_complete_result_and_terminal_worker_precede_cutover() {
    for first in [Event::ResultComplete, Event::WorkerTerminal] {
        let mut job = running();
        assert_eq!(
            job.apply(EPOCH, Event::BeginTeardown),
            Err(Reject::InvalidOrder),
            "m11_skip_complete_result / m12_skip_worker_terminal"
        );
        apply(&mut job, first);
        assert_eq!(
            job.apply(EPOCH, Event::BeginTeardown),
            Err(Reject::InvalidOrder)
        );
        let second = match first {
            Event::ResultComplete => Event::WorkerTerminal,
            _ => Event::ResultComplete,
        };
        apply(&mut job, second);
        apply(&mut job, Event::BeginTeardown);
        assert_eq!(job.report().phase, Phase::Teardown);
        assert_eq!(job.report().outcome, None);
        assert_eq!(job.apply(EPOCH, Event::Release), Err(Reject::InvalidOrder));
    }
}

#[test]
fn c03_clean_completion_releases_each_lease_once() {
    let mut job = running();
    apply(&mut job, Event::ResultComplete);
    apply(&mut job, Event::WorkerTerminal);
    apply(&mut job, Event::BeginTeardown);
    apply(&mut job, Event::ObserveCleanup(CLEAN));
    assert_eq!(job.report().outcome, Some(Outcome::FixtureComplete));
    assert_eq!(job.report().leases, [LeaseState::Held; 2]);
    assert!(
        job.report().custody_retained,
        "m15_drop_custody_before_cleanup_decision"
    );
    apply(&mut job, Event::Release);
    assert_eq!(job.report().leases, [LeaseState::Released; 2]);
    assert!(!job.report().custody_retained);
    let released = job.report();
    assert_eq!(job.apply(EPOCH, Event::Release), Err(Reject::InvalidOrder));
    assert_eq!(job.report(), released, "m03_repeat_release");
}

#[test]
fn c04_cleanup_requires_all_three_independent_predicates() {
    for mask in 0..8 {
        let mut job = running();
        apply(&mut job, Event::ResultComplete);
        apply(&mut job, Event::WorkerTerminal);
        apply(&mut job, Event::BeginTeardown);
        let evidence = CleanupEvidence {
            total_j_empty: mask & 1 != 0,
            fully_reaped: mask & 2 != 0,
            fixture_consumers: u32::from(mask & 4 == 0),
        };
        apply(&mut job, Event::ObserveCleanup(evidence));
        if mask == 7 {
            assert_eq!(job.report().phase, Phase::Cleaned);
        } else {
            assert_eq!(
                job.report().phase,
                Phase::Teardown,
                "mask {mask}: m04_skip_total_j_empty / m05_skip_reaping / m06_skip_consumers"
            );
            assert_eq!(job.report().outcome, None);
            assert_eq!(job.apply(EPOCH, Event::Release), Err(Reject::InvalidOrder));
            assert_eq!(job.report().leases, [LeaseState::Held; 2]);
        }
    }
}

#[test]
fn c05_cleanup_evidence_cannot_be_accumulated_across_incomplete_observations() {
    let mut job = running();
    apply(&mut job, Event::ResultComplete);
    apply(&mut job, Event::WorkerTerminal);
    apply(&mut job, Event::BeginTeardown);
    for evidence in [
        CleanupEvidence {
            total_j_empty: false,
            ..CLEAN
        },
        CleanupEvidence {
            fully_reaped: false,
            ..CLEAN
        },
        CleanupEvidence {
            fixture_consumers: 1,
            ..CLEAN
        },
    ] {
        apply(&mut job, Event::ObserveCleanup(evidence));
        assert_eq!(job.apply(EPOCH, Event::Release), Err(Reject::InvalidOrder));
    }
    apply(&mut job, Event::ObserveCleanup(CLEAN));
    assert_eq!(job.report().phase, Phase::Cleaned);
}

#[test]
fn c06_pre_cutover_supervisor_loss_aborts_even_with_complete_inputs() {
    for complete_inputs in [false, true] {
        let mut job = running();
        if complete_inputs {
            apply(&mut job, Event::ResultComplete);
            apply(&mut job, Event::WorkerTerminal);
        }
        apply(&mut job, Event::SupervisorLost);
        assert_eq!(job.report().reason, Some(AbortReason::SupervisorLost));
        for event in [
            Event::ResultComplete,
            Event::WorkerTerminal,
            Event::BeginTeardown,
        ] {
            assert_eq!(
                job.apply(EPOCH, event),
                Err(Reject::InvalidOrder),
                "m07_revive_aborted_job"
            );
        }
        assert_eq!(job.report().outcome, None);
        apply(&mut job, Event::ObserveCleanup(CLEAN));
        assert_eq!(job.report().outcome, Some(Outcome::AbortedClean));
        assert_eq!(job.report().cleanup, Cleanup::Complete);
        apply(&mut job, Event::Release);
        assert_eq!(job.report().outcome, Some(Outcome::AbortedClean));
    }
}

#[test]
fn c07_planned_supervisor_stop_after_cutover_is_not_an_abort() {
    let mut job = running();
    apply(&mut job, Event::ResultComplete);
    apply(&mut job, Event::WorkerTerminal);
    apply(&mut job, Event::BeginTeardown);
    apply(&mut job, Event::SupervisorLost);
    assert_eq!(
        job.report().reason,
        None,
        "m08_conflate_planned_stop_with_loss"
    );
    assert_eq!(
        job.apply(EPOCH, Event::ResultComplete),
        Err(Reject::InvalidOrder)
    );
    assert_eq!(job.apply(EPOCH, Event::Release), Err(Reject::InvalidOrder));
    apply(&mut job, Event::ObserveCleanup(CLEAN));
    assert_eq!(job.report().outcome, Some(Outcome::FixtureComplete));
}

#[test]
fn c08_abort_reason_stays_distinct_from_cleanup_status() {
    for reason in [
        AbortReason::Expired,
        AbortReason::OperationFailed,
        AbortReason::Unsupported,
    ] {
        let mut job = running();
        apply(&mut job, Event::Abort(reason));
        assert_eq!(job.report().reason, Some(reason));
        assert_eq!(job.report().cleanup, Cleanup::Pending);
        assert_eq!(job.report().outcome, None);
        assert_eq!(
            job.apply(EPOCH, Event::Abort(AbortReason::OperationFailed)),
            Err(Reject::InvalidOrder)
        );
        apply(&mut job, Event::ObserveCleanup(CLEAN));
        let expected = if reason == AbortReason::Unsupported {
            Outcome::Unsupported
        } else {
            Outcome::AbortedClean
        };
        assert_eq!(job.report().outcome, Some(expected));
        assert_eq!(job.report().reason, Some(reason));
    }
}

#[test]
fn c09_cleanup_expiry_quarantines_and_late_evidence_cannot_release() {
    for aborted in [false, true] {
        let mut job = running();
        if aborted {
            apply(&mut job, Event::Abort(AbortReason::Expired));
        } else {
            apply(&mut job, Event::ResultComplete);
            apply(&mut job, Event::WorkerTerminal);
            apply(&mut job, Event::BeginTeardown);
        }
        apply(&mut job, Event::CleanupExpired);
        let quarantined = job.report();
        assert_eq!(quarantined.outcome, Some(Outcome::CleanupIncomplete));
        assert_eq!(quarantined.cleanup, Cleanup::Incomplete);
        assert_eq!(quarantined.leases, [LeaseState::Held; 2]);
        assert!(quarantined.custody_retained);
        for event in [
            Event::ResultComplete,
            Event::WorkerTerminal,
            Event::BeginTeardown,
            Event::ObserveCleanup(CLEAN),
            Event::Release,
            Event::CleanupExpired,
        ] {
            assert_eq!(
                job.apply(EPOCH, event),
                Err(Reject::InvalidOrder),
                "m09_revive_quarantine"
            );
            assert_eq!(job.report(), quarantined);
        }
    }
}

fn reject_unchanged(job: &mut Job, epoch: Epoch, event: Event, reason: Reject) {
    let before = job.clone();
    assert_eq!(job.apply(epoch, event), Err(reason), "event {event:?}");
    assert_eq!(*job, before, "rejected event {event:?} changed state");
}

#[test]
fn c10_wrong_epoch_events_never_change_any_lifecycle_state() {
    let mut job = Job::new(EPOCH);
    let mut states = vec![job.clone()];
    for event in [
        Event::Reserve(Lease::Identity),
        Event::Reserve(Lease::Generation),
        Event::Create,
        Event::ResultComplete,
        Event::WorkerTerminal,
        Event::BeginTeardown,
        Event::SupervisorLost,
        Event::ObserveCleanup(CLEAN),
        Event::Release,
    ] {
        apply(&mut job, event);
        states.push(job.clone());
    }
    let mut aborted = running();
    apply(&mut aborted, Event::Abort(AbortReason::Expired));
    states.push(aborted.clone());
    apply(&mut aborted, Event::CleanupExpired);
    states.push(aborted);
    for mut state in states {
        for event in [
            Event::Reserve(Lease::Identity),
            Event::Reserve(Lease::Generation),
            Event::Create,
            Event::ResultComplete,
            Event::WorkerTerminal,
            Event::BeginTeardown,
            Event::SupervisorLost,
            Event::Abort(AbortReason::OperationFailed),
            Event::ObserveCleanup(CLEAN),
            Event::CleanupExpired,
            Event::Release,
        ] {
            // m10_accept_wrong_epoch: covers progress, fault and cleanup events alike.
            reject_unchanged(&mut state, Epoch(42), event, Reject::WrongEpoch);
        }
    }
}

#[test]
fn c11_duplicate_transitions_never_get_second_credit() {
    let mut job = Job::new(EPOCH);
    for event in [
        Event::Reserve(Lease::Identity),
        Event::Reserve(Lease::Generation),
        Event::Create,
        Event::ResultComplete,
        Event::WorkerTerminal,
        Event::BeginTeardown,
        Event::SupervisorLost,
        Event::ObserveCleanup(CLEAN),
        Event::Release,
    ] {
        apply(&mut job, event);
        reject_unchanged(&mut job, EPOCH, event, Reject::InvalidOrder);
    }
}

#[test]
fn c12_out_of_order_evidence_never_advances_a_job() {
    let mut job = Job::new(EPOCH);
    for event in [
        Event::Create,
        Event::ResultComplete,
        Event::WorkerTerminal,
        Event::BeginTeardown,
        Event::SupervisorLost,
        Event::ObserveCleanup(CLEAN),
        Event::CleanupExpired,
        Event::Release,
    ] {
        reject_unchanged(&mut job, EPOCH, event, Reject::InvalidOrder);
    }
    let mut job = running();
    for event in [
        Event::Reserve(Lease::Identity),
        Event::ObserveCleanup(CLEAN),
        Event::Release,
        Event::CleanupExpired,
    ] {
        reject_unchanged(&mut job, EPOCH, event, Reject::InvalidOrder);
    }
}

#[test]
fn c13_partial_reservation_failure_releases_only_held_leases_after_cleanup() {
    for lease in [None, Some(Lease::Identity), Some(Lease::Generation)] {
        let mut job = Job::new(EPOCH);
        if let Some(lease) = lease {
            apply(&mut job, Event::Reserve(lease));
        }
        apply(&mut job, Event::Abort(AbortReason::OperationFailed));
        reject_unchanged(&mut job, EPOCH, Event::Create, Reject::InvalidOrder);
        reject_unchanged(&mut job, EPOCH, Event::Release, Reject::InvalidOrder);
        apply(&mut job, Event::ObserveCleanup(CLEAN));
        apply(&mut job, Event::Release);
        let expected = match lease {
            None => [LeaseState::Unreserved; 2],
            Some(Lease::Identity) => [LeaseState::Released, LeaseState::Unreserved],
            Some(Lease::Generation) => [LeaseState::Unreserved, LeaseState::Released],
        };
        assert_eq!(job.report().leases, expected);
        assert_eq!(job.report().outcome, Some(Outcome::AbortedClean));
    }
}

#[test]
fn c14_failure_after_cutover_still_prevents_success() {
    let mut job = running();
    apply(&mut job, Event::ResultComplete);
    apply(&mut job, Event::WorkerTerminal);
    apply(&mut job, Event::BeginTeardown);
    apply(&mut job, Event::Abort(AbortReason::OperationFailed));
    apply(&mut job, Event::SupervisorLost);
    assert_eq!(job.report().reason, Some(AbortReason::OperationFailed));
    reject_unchanged(&mut job, EPOCH, Event::ResultComplete, Reject::InvalidOrder);
    apply(&mut job, Event::ObserveCleanup(CLEAN));
    assert_eq!(job.report().outcome, Some(Outcome::AbortedClean));
}

#[test]
fn c15_cleaned_evidence_is_terminal_before_explicit_release() {
    let mut job = running();
    apply(&mut job, Event::ResultComplete);
    apply(&mut job, Event::WorkerTerminal);
    apply(&mut job, Event::BeginTeardown);
    apply(&mut job, Event::ObserveCleanup(CLEAN));
    let cleaned = job.report();
    assert_eq!(cleaned.phase, Phase::Cleaned);
    assert_eq!(cleaned.outcome, Some(Outcome::FixtureComplete));
    assert_eq!(cleaned.cleanup, Cleanup::Complete);
    assert_eq!(cleaned.leases, [LeaseState::Held; 2]);
    assert!(cleaned.custody_retained);
    for evidence in [
        CleanupEvidence {
            total_j_empty: false,
            ..CLEAN
        },
        CleanupEvidence {
            fully_reaped: false,
            ..CLEAN
        },
        CleanupEvidence {
            fixture_consumers: 1,
            ..CLEAN
        },
    ] {
        // m16_reaccept_cleaned_observation must fail this rejection assertion.
        reject_unchanged(
            &mut job,
            EPOCH,
            Event::ObserveCleanup(evidence),
            Reject::InvalidOrder,
        );
        assert_eq!(job.report(), cleaned);
    }
    apply(&mut job, Event::Release);
    let released = job.report();
    assert_eq!(released.phase, Phase::Released);
    assert_eq!(released.outcome, cleaned.outcome);
    assert_eq!(released.cleanup, cleaned.cleanup);
    assert_eq!(released.leases, [LeaseState::Released; 2]);
    assert!(!released.custody_retained);
    for event in [
        Event::Release,
        Event::ResultComplete,
        Event::Abort(AbortReason::OperationFailed),
        Event::ObserveCleanup(CLEAN),
        Event::ObserveCleanup(CleanupEvidence {
            total_j_empty: false,
            ..CLEAN
        }),
        Event::CleanupExpired,
    ] {
        reject_unchanged(&mut job, EPOCH, event, Reject::InvalidOrder);
        assert_eq!(job.report(), released);
    }
}

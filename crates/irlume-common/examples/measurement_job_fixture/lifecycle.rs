// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright the irlume contributors.

//! Synthetic events only, with no OS resource operations or native execution.
//! Cleanup evidence is supplied by tests, not observed from a running job.

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct Epoch(u64);

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Lease {
    Identity,
    Generation,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum LeaseState {
    Unreserved,
    Held,
    Released,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Phase {
    Reserving,
    Running,
    Teardown,
    Cleaned,
    Quarantined,
    Released,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum AbortReason {
    SupervisorLost,
    Expired,
    OperationFailed,
    Unsupported,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Cleanup {
    Pending,
    Complete,
    Incomplete,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Outcome {
    FixtureComplete,
    AbortedClean,
    Unsupported,
    CleanupIncomplete,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct CleanupEvidence {
    total_j_empty: bool,
    fully_reaped: bool,
    // M's intentional custody is not a fixture consumer.
    fixture_consumers: u32,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Event {
    Reserve(Lease),
    Create,
    ResultComplete,
    WorkerTerminal,
    BeginTeardown,
    SupervisorLost,
    Abort(AbortReason),
    ObserveCleanup(CleanupEvidence),
    CleanupExpired,
    Release,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Reject {
    WrongEpoch,
    InvalidOrder,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct Report {
    epoch: Epoch,
    phase: Phase,
    leases: [LeaseState; 2],
    outcome: Option<Outcome>,
    reason: Option<AbortReason>,
    cleanup: Cleanup,
    custody_retained: bool,
    native_authorized: bool,
    full_contract_proven: bool,
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct Job {
    epoch: Epoch,
    phase: Phase,
    leases: [LeaseState; 2],
    result_complete: bool,
    worker_terminal: bool,
    supervisor_stopped: bool,
    abort_reason: Option<AbortReason>,
}

impl Job {
    fn new(epoch: Epoch) -> Self {
        Self {
            epoch,
            phase: Phase::Reserving,
            leases: [LeaseState::Unreserved; 2],
            result_complete: false,
            worker_terminal: false,
            supervisor_stopped: false,
            abort_reason: None,
        }
    }

    fn apply(&mut self, epoch: Epoch, event: Event) -> Result<(), Reject> {
        // Rejected events get no credit and cannot change the retained state.
        if epoch != self.epoch {
            return Err(Reject::WrongEpoch);
        }
        match event {
            Event::Reserve(lease) if self.phase == Phase::Reserving => {
                let index = match lease {
                    Lease::Identity => 0,
                    Lease::Generation => 1,
                };
                if self.leases[index] != LeaseState::Unreserved {
                    return Err(Reject::InvalidOrder);
                }
                self.leases[index] = LeaseState::Held;
            }
            Event::Create
                if self.phase == Phase::Reserving && self.leases == [LeaseState::Held; 2] =>
            {
                self.phase = Phase::Running;
            }
            Event::ResultComplete if self.phase == Phase::Running && !self.result_complete => {
                self.result_complete = true;
            }
            Event::WorkerTerminal if self.phase == Phase::Running && !self.worker_terminal => {
                self.worker_terminal = true;
            }
            Event::BeginTeardown
                if self.phase == Phase::Running && self.result_complete && self.worker_terminal =>
            {
                self.phase = Phase::Teardown;
            }
            Event::SupervisorLost
                if !self.supervisor_stopped
                    && matches!(self.phase, Phase::Running | Phase::Teardown) =>
            {
                self.supervisor_stopped = true;
                if self.phase == Phase::Running {
                    self.abort(AbortReason::SupervisorLost);
                }
            }
            Event::Abort(reason)
                if self.abort_reason.is_none()
                    && matches!(
                        self.phase,
                        Phase::Reserving | Phase::Running | Phase::Teardown
                    ) =>
            {
                self.abort(reason);
            }
            Event::ObserveCleanup(evidence) if self.phase == Phase::Teardown => {
                if evidence.total_j_empty
                    && evidence.fully_reaped
                    && evidence.fixture_consumers == 0
                {
                    // Commit terminal synthetic completion, not refreshable runtime evidence.
                    // Later contradictions are rejected; real contradictions need qualification.
                    self.phase = Phase::Cleaned;
                }
            }
            Event::CleanupExpired if self.phase == Phase::Teardown => {
                self.phase = Phase::Quarantined;
            }
            Event::Release if self.phase == Phase::Cleaned => {
                for lease in &mut self.leases {
                    if *lease == LeaseState::Held {
                        *lease = LeaseState::Released;
                    }
                }
                self.phase = Phase::Released;
            }
            _ => return Err(Reject::InvalidOrder),
        }
        Ok(())
    }

    fn abort(&mut self, reason: AbortReason) {
        self.abort_reason = Some(reason);
        self.result_complete = false;
        self.worker_terminal = false;
        self.phase = Phase::Teardown;
    }

    fn report(&self) -> Report {
        let (cleanup, outcome) = match self.phase {
            Phase::Reserving | Phase::Running | Phase::Teardown => (Cleanup::Pending, None),
            Phase::Quarantined => (Cleanup::Incomplete, Some(Outcome::CleanupIncomplete)),
            Phase::Cleaned | Phase::Released => {
                // Cleaned has an outcome but still holds dummy leases and M's custody.
                // Only the explicit Release transition releases them.
                let outcome = match self.abort_reason {
                    None => Outcome::FixtureComplete,
                    Some(AbortReason::Unsupported) => Outcome::Unsupported,
                    Some(
                        AbortReason::SupervisorLost
                        | AbortReason::Expired
                        | AbortReason::OperationFailed,
                    ) => Outcome::AbortedClean,
                };
                (Cleanup::Complete, Some(outcome))
            }
        };
        Report {
            epoch: self.epoch,
            phase: self.phase,
            leases: self.leases,
            outcome,
            reason: self.abort_reason,
            cleanup,
            custody_retained: self.phase != Phase::Released,
            native_authorized: false,
            full_contract_proven: false,
        }
    }
}

#[path = "lifecycle_tests.rs"]
mod tests;

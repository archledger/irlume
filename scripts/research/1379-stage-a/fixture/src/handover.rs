// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright the irlume contributors.

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) struct Scope {
    pub boot: u64,
    pub stack: u64,
    pub graph: u64,
    pub attempt: u64,
    pub reservation: u64,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum Route {
    Rgb,
    Ir,
}

#[derive(Clone, Copy)]
pub(super) enum Order {
    RgbIrRgb,
    IrRgbIr,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) struct PhaseKey {
    pub scope: Scope,
    pub ordinal: u8,
    pub route: Route,
    pub queue_generation: u64,
    pub stop_generation: u64,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum Observation {
    Confirmed,
    Failed,
    Unknown,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum ScopedKind {
    Owner,
    OpticalBaseline,
    Restored,
    Released,
}

#[derive(Clone, Copy)]
pub(super) struct ScopedReceipt {
    pub scope: Scope,
    pub kind: ScopedKind,
    pub observed: Observation,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum Stage {
    OwnerEntry,
    OwnerExit,
    SoftwareDrained,
    ManagerRetired,
    ImguStopped,
    ReceiverStopped,
    DmaHalted,
    SensorStopped,
    GraphReadback,
    OpticalOff,
}

#[derive(Clone, Copy)]
pub(super) enum PhaseFact {
    Observed(Observation),
    NoEffect,
}

#[derive(Clone, Copy)]
pub(super) struct PhaseReceipt {
    pub key: PhaseKey,
    pub stage: Stage,
    pub fact: PhaseFact,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum WorkerResult {
    Completed,
    Refused,
    TimedOut,
}

pub(super) struct Phase {
    pub worker: WorkerResult,
    pub receipts: Vec<PhaseReceipt>,
}

pub(super) struct Script {
    pub owner: Option<ScopedReceipt>,
    pub baseline: Option<ScopedReceipt>,
    pub phases: [Phase; 3],
    pub restored: Option<ScopedReceipt>,
    pub released: Option<ScopedReceipt>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum Event {
    IntentRecorded,
    BeginPhase(PhaseKey),
    RestoreGraph,
    Release,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum Outcome {
    Complete,
    Refused,
    Held,
}

fn confirmed_scope(receipt: Option<ScopedReceipt>, scope: Scope, kind: ScopedKind) -> bool {
    receipt
        .is_some_and(|r| r.scope == scope && r.kind == kind && r.observed == Observation::Confirmed)
}

fn confirmed_phase(
    receipts: &[PhaseReceipt],
    key: PhaseKey,
    stage: Stage,
    allow_no_effect: bool,
) -> bool {
    let mut matching = receipts.iter().filter(|r| r.stage == stage);
    let Some(receipt) = matching.next() else {
        return false;
    };
    receipt.key == key
        && matching.next().is_none()
        && match receipt.fact {
            PhaseFact::Observed(observed) => observed == Observation::Confirmed,
            PhaseFact::NoEffect => allow_no_effect,
        }
}

fn confirmed_teardown(phase: &Phase, key: PhaseKey) -> bool {
    let receipts = &phase.receipts;
    let allow_no_effect = phase.worker != WorkerResult::Completed;
    let mandatory = [Stage::OwnerExit, Stage::GraphReadback];
    let common = [
        Stage::SoftwareDrained,
        Stage::ReceiverStopped,
        Stage::DmaHalted,
        Stage::SensorStopped,
    ];
    mandatory
        .into_iter()
        .all(|stage| confirmed_phase(receipts, key, stage, false))
        && common
            .into_iter()
            .all(|stage| confirmed_phase(receipts, key, stage, allow_no_effect))
        && match key.route {
            Route::Rgb => [Stage::ManagerRetired, Stage::ImguStopped]
                .into_iter()
                .all(|stage| confirmed_phase(receipts, key, stage, allow_no_effect)),
            Route::Ir => confirmed_phase(receipts, key, Stage::OpticalOff, false),
        }
}

pub(super) fn run_fixture(
    scope: Scope,
    order: Order,
    script: &Script,
    record_intent: impl FnOnce() -> bool,
    mut emit: impl FnMut(Event),
) -> Outcome {
    if !confirmed_scope(script.owner, scope, ScopedKind::Owner)
        || !confirmed_scope(script.baseline, scope, ScopedKind::OpticalBaseline)
    {
        return Outcome::Refused;
    }
    if !record_intent() {
        return Outcome::Held;
    }
    emit(Event::IntentRecorded);

    let routes = match order {
        Order::RgbIrRgb => [Route::Rgb, Route::Ir, Route::Rgb],
        Order::IrRgbIr => [Route::Ir, Route::Rgb, Route::Ir],
    };
    let mut outcome = Outcome::Complete;
    for ((ordinal, route), phase) in (1..=3).zip(routes).zip(&script.phases) {
        let key = PhaseKey {
            scope,
            ordinal,
            route,
            queue_generation: u64::from(ordinal),
            stop_generation: u64::from(ordinal),
        };
        if !confirmed_phase(&phase.receipts, key, Stage::OwnerEntry, false) {
            return Outcome::Held;
        }
        emit(Event::BeginPhase(key));
        if !confirmed_teardown(phase, key) {
            return Outcome::Held;
        }
        if phase.worker != WorkerResult::Completed {
            outcome = Outcome::Refused;
            break;
        }
    }

    emit(Event::RestoreGraph);
    if !confirmed_scope(script.restored, scope, ScopedKind::Restored) {
        return Outcome::Held;
    }
    emit(Event::Release);
    if !confirmed_scope(script.released, scope, ScopedKind::Released) {
        return Outcome::Held;
    }
    outcome
}

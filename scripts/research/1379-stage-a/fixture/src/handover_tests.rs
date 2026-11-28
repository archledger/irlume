// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright the irlume contributors.

use super::handover::{
    run_fixture, Event, Observation, Order, Outcome, Phase, PhaseFact, PhaseKey, PhaseReceipt,
    Route, Scope, ScopedKind, ScopedReceipt, Script, Stage, WorkerResult,
};
use std::cell::Cell;

pub(super) const SCOPE: Scope = Scope {
    boot: 10,
    stack: 20,
    graph: 30,
    attempt: 40,
    reservation: 50,
};

fn key(scope: Scope, ordinal: u8, route: Route) -> PhaseKey {
    PhaseKey {
        scope,
        ordinal,
        route,
        queue_generation: u64::from(ordinal),
        stop_generation: u64::from(ordinal),
    }
}

pub(super) fn valid_script(scope: Scope, order: Order) -> Script {
    let routes = match order {
        Order::RgbIrRgb => [Route::Rgb, Route::Ir, Route::Rgb],
        Order::IrRgbIr => [Route::Ir, Route::Rgb, Route::Ir],
    };
    let scoped = |kind| {
        Some(ScopedReceipt {
            scope,
            kind,
            observed: Observation::Confirmed,
        })
    };
    let phase = |ordinal, route| {
        let mut stages = vec![
            Stage::OwnerEntry,
            Stage::OwnerExit,
            Stage::SoftwareDrained,
            Stage::ReceiverStopped,
            Stage::DmaHalted,
            Stage::SensorStopped,
            Stage::GraphReadback,
        ];
        match route {
            Route::Rgb => stages.extend([Stage::ManagerRetired, Stage::ImguStopped]),
            Route::Ir => stages.push(Stage::OpticalOff),
        }
        Phase {
            worker: WorkerResult::Completed,
            receipts: stages
                .iter()
                .map(|&stage| PhaseReceipt {
                    key: key(scope, ordinal, route),
                    stage,
                    fact: PhaseFact::Observed(Observation::Confirmed),
                })
                .collect(),
        }
    };
    Script {
        owner: scoped(ScopedKind::Owner),
        baseline: scoped(ScopedKind::OpticalBaseline),
        phases: [
            phase(1, routes[0]),
            phase(2, routes[1]),
            phase(3, routes[2]),
        ],
        restored: scoped(ScopedKind::Restored),
        released: scoped(ScopedKind::Released),
    }
}

fn evaluate(order: Order, script: &Script) -> (Outcome, Vec<Event>) {
    let mut events = Vec::new();
    let result = run_fixture(SCOPE, order, script, || true, |event| events.push(event));
    (result, events)
}

#[test]
fn both_orders_one_reservation() {
    for (order, first, second) in [
        (Order::RgbIrRgb, Route::Rgb, Route::Ir),
        (Order::IrRgbIr, Route::Ir, Route::Rgb),
    ] {
        let intent = Cell::new(false);
        let mut events = Vec::new();
        let result = run_fixture(
            SCOPE,
            order,
            &valid_script(SCOPE, order),
            || {
                intent.set(true);
                true
            },
            |event| {
                assert!(intent.get());
                events.push(event);
            },
        );
        assert_eq!(result, Outcome::Complete);
        assert_eq!(
            events,
            [
                Event::IntentRecorded,
                Event::BeginPhase(key(SCOPE, 1, first)),
                Event::BeginPhase(key(SCOPE, 2, second)),
                Event::BeginPhase(key(SCOPE, 3, first)),
                Event::RestoreGraph,
                Event::Release,
            ]
        );
        println!("{first:?} -> {second:?} -> {first:?}: {result:?}, {events:?}");
    }
}

#[test]
fn no_owner_means_no_intent_or_phase() {
    let order = Order::RgbIrRgb;
    for defect in 0..4 {
        let mut script = valid_script(SCOPE, order);
        match defect {
            0 => script.owner = None,
            1 => script.owner.as_mut().unwrap().observed = Observation::Unknown,
            2 => script.owner.as_mut().unwrap().scope.graph += 1,
            3 => script.baseline = None,
            _ => unreachable!(),
        }
        assert_eq!(
            run_fixture(
                SCOPE,
                order,
                &script,
                || panic!("unowned intent"),
                |_| panic!("unowned event")
            ),
            Outcome::Refused
        );
    }
}

#[test]
fn unconfirmed_intent_refuses_before_effect() {
    let order = Order::RgbIrRgb;
    let attempted = Cell::new(false);
    let result = run_fixture(
        SCOPE,
        order,
        &valid_script(SCOPE, order),
        || {
            attempted.set(true);
            false
        },
        |_| panic!("effect without synced intent"),
    );
    assert!(attempted.get());
    assert_eq!(result, Outcome::Held);
}

#[test]
fn prior_ir_receipt_cannot_clear_later_phase() {
    let order = Order::IrRgbIr;
    for stage in [Stage::OpticalOff, Stage::SensorStopped] {
        let mut script = valid_script(SCOPE, order);
        let first = *script.phases[0]
            .receipts
            .iter()
            .find(|r| r.stage == stage)
            .unwrap();
        *script.phases[2]
            .receipts
            .iter_mut()
            .find(|r| r.stage == stage)
            .unwrap() = first;
        let result = evaluate(order, &script);
        println!("stale {stage:?}: {result:?}");
        assert_eq!(
            result,
            (
                Outcome::Held,
                vec![
                    Event::IntentRecorded,
                    Event::BeginPhase(key(SCOPE, 1, Route::Ir)),
                    Event::BeginPhase(key(SCOPE, 2, Route::Rgb)),
                    Event::BeginPhase(key(SCOPE, 3, Route::Ir)),
                ]
            )
        );
    }
}

#[test]
fn cleanup_is_not_worker_success() {
    let order = Order::RgbIrRgb;
    for (ordinal, stage) in [
        (0, Stage::SoftwareDrained),
        (0, Stage::ManagerRetired),
        (0, Stage::ImguStopped),
        (0, Stage::ReceiverStopped),
        (0, Stage::DmaHalted),
        (0, Stage::SensorStopped),
        (0, Stage::GraphReadback),
        (0, Stage::OwnerExit),
        (1, Stage::OpticalOff),
    ] {
        for defect in 0..5 {
            let mut script = valid_script(SCOPE, order);
            let receipts = &mut script.phases[ordinal].receipts;
            let index = receipts.iter().position(|r| r.stage == stage).unwrap();
            match defect {
                0 => receipts[index].fact = PhaseFact::Observed(Observation::Unknown),
                1 => receipts[index].fact = PhaseFact::Observed(Observation::Failed),
                2 => receipts[index].key.scope.reservation += 1,
                3 => receipts[index].key.stop_generation += 1,
                4 => receipts.push(receipts[index]),
                _ => unreachable!(),
            }
            let (result, events) = evaluate(order, &script);
            assert_eq!(result, Outcome::Held, "{stage:?}, defect {defect}");
            assert_eq!(events.len(), ordinal + 2);
            assert!(events
                .iter()
                .all(|e| !matches!(e, Event::RestoreGraph | Event::Release)));
        }
    }
}

#[test]
fn entry_owner_loss_blocks_the_next_phase() {
    let order = Order::RgbIrRgb;
    let mut script = valid_script(SCOPE, order);
    script.phases[1]
        .receipts
        .retain(|r| r.stage != Stage::OwnerEntry);
    assert_eq!(
        evaluate(order, &script),
        (
            Outcome::Held,
            vec![
                Event::IntentRecorded,
                Event::BeginPhase(key(SCOPE, 1, Route::Rgb)),
            ]
        )
    );
}

#[test]
fn timeout_distinguishes_known_cleanup() {
    let order = Order::RgbIrRgb;
    for worker in [WorkerResult::Refused, WorkerResult::TimedOut] {
        let mut script = valid_script(SCOPE, order);
        script.phases[0].worker = worker;
        let mut events = vec![
            Event::IntentRecorded,
            Event::BeginPhase(key(SCOPE, 1, Route::Rgb)),
        ];
        events.extend([Event::RestoreGraph, Event::Release]);
        assert_eq!(evaluate(order, &script), (Outcome::Refused, events));
        let teardown = script.phases[0]
            .receipts
            .iter_mut()
            .find(|r| r.stage == Stage::ImguStopped)
            .unwrap();
        teardown.fact = PhaseFact::NoEffect;
        assert_eq!(evaluate(order, &script).0, Outcome::Refused);
        script.phases[0]
            .receipts
            .retain(|r| r.stage != Stage::ImguStopped);
        assert_eq!(
            evaluate(order, &script),
            (
                Outcome::Held,
                vec![
                    Event::IntentRecorded,
                    Event::BeginPhase(key(SCOPE, 1, Route::Rgb)),
                ]
            )
        );
    }
}

#[test]
fn lost_final_observation_is_not_complete() {
    let order = Order::RgbIrRgb;
    for lost_release in [false, true] {
        for defect in 0..3 {
            let mut script = valid_script(SCOPE, order);
            let receipt = if lost_release {
                &mut script.released
            } else {
                &mut script.restored
            };
            match defect {
                0 => *receipt = None,
                1 => receipt.as_mut().unwrap().scope.attempt += 1,
                2 => receipt.as_mut().unwrap().observed = Observation::Unknown,
                _ => unreachable!(),
            }
            let mut events = vec![
                Event::IntentRecorded,
                Event::BeginPhase(key(SCOPE, 1, Route::Rgb)),
                Event::BeginPhase(key(SCOPE, 2, Route::Ir)),
                Event::BeginPhase(key(SCOPE, 3, Route::Rgb)),
                Event::RestoreGraph,
            ];
            if lost_release {
                events.push(Event::Release);
            }
            assert_eq!(evaluate(order, &script), (Outcome::Held, events));
        }
    }
}

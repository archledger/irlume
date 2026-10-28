// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright the irlume contributors.

use super::*;
use crate::kernel::{bounds::BoundCase, Case, Cut, Outcome};

fn context() -> Context<'static> {
    Context {
        run_id: "run-01",
        boot_input_sha256: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        guest_boot_id: "01234567-89ab-cdef-0123-456789abcdef",
        build_sha256: "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
        input_manifest_sha256: "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc",
        sequence: 0,
    }
}

fn report() -> crate::kernel::Report {
    use crate::kernel::{Report, Wait};
    let mut terminal = [None; 33];
    terminal[0] = Some(Wait::Terminal {
        pid: 101,
        code: 2,
        status: 9,
    });
    Report {
        bounds: None,
        case: Case::SupervisorOnly,
        reached: None,
        injected: false,
        registered: false,
        placed: false,
        placement_verified: false,
        worker_pid: None,
        descendant_pid: None,
        worker_reaped: false,
        descendant_reaped: false,
        oom_observations: 0,
        oom_kills: [0; 3],
        epoch: 41,
        outcome: Outcome::Complete,
        reserved: true,
        leases_held: [false; 2],
        custody_retained: false,
        releases: 1,
        first: None,
        errors: [None; 16],
        errors_truncated: false,
        kill: true,
        empty: true,
        direct_reaped: true,
        drained: true,
        consumers: 0,
        adopted: 0,
        terminal,
        operations: 30,
        native_authorized: false,
        full_contract_proven: false,
    }
}

fn bounds_report(case: BoundCase) -> crate::kernel::Report {
    use crate::kernel::{bounds::State, failure, message, Wait};
    let mut value = report();
    value.case = Case::Bounds(case);
    value.registered = true;
    value.placed = true;
    value.placement_verified = true;
    value.worker_pid = Some(102);
    value.worker_reaped = true;
    value.adopted = 1;
    value.terminal[1] = Some(Wait::Terminal {
        pid: 102,
        code: 1,
        status: 0,
    });
    value.oom_observations = 3;
    value.bounds = Some(State {
        active: true,
        candidate_received: true,
        result_frame: Some(message(2, 41)),
        result_return: Some(9_000_000_000),
        result_valid: true,
        worker_terminal: true,
        cutover: true,
        stopped_oom_checked: true,
        sentinel_created: true,
        sentinel_pre: true,
        sentinel_post: true,
        sentinel_stopped: true,
        work_cap: 10_000_000_000,
        caps: [
            5_000_000_000,
            10_000_000_000,
            15_000_000_000,
            20_000_000_000,
        ],
        ..State::default()
    });
    value.bounds.as_mut().unwrap().output.bytes = 9;
    if case == BoundCase::WithheldWait {
        value.outcome = Outcome::Incomplete;
        value.leases_held = [true; 2];
        value.custody_retained = true;
        value.releases = 0;
        value.first = Some(failure("fixture-withheld-wait", 0));
        value.errors[0] = value.first;
        value.worker_reaped = false;
        value.drained = false;
        value.consumers = 1;
        value.adopted = 0;
        value.terminal[1] = None;
    }
    value
}

fn case_report(case: Case) -> crate::kernel::Report {
    use crate::kernel::{failure, message, Wait};
    let mut r = case.bounds().map_or_else(report, bounds_report);
    r.case = case;
    if let Some(cut) = case.cut() {
        r.outcome = Outcome::AbortedClean;
        r.reached = Some(cut);
        r.injected = true;
        r.first = Some(failure("supervisor-loss-injected", 0));
        r.errors[0] = r.first;
        r.oom_observations = 3;
        if cut != Cut::BeforeBirth {
            r.worker_pid = Some(102);
            r.worker_reaped = true;
            r.adopted = 1;
            r.terminal[1] = Some(Wait::Terminal {
                pid: 102,
                code: 2,
                status: 9,
            });
        }
        r.registered = matches!(
            cut,
            Cut::BeforePlacement | Cut::BeforeReadback | Cut::AfterReadback
        );
        r.placed = matches!(cut, Cut::BeforeReadback | Cut::AfterReadback);
        r.placement_verified = cut == Cut::AfterReadback;
        if case == Case::DoubleFork {
            r.descendant_pid = Some(103);
            r.descendant_reaped = true;
            r.adopted = 2;
            r.terminal[2] = Some(Wait::Terminal {
                pid: 103,
                code: 2,
                status: 9,
            });
        }
    }
    if let Case::Bounds(case) = case {
        let s = r.bounds.as_mut().unwrap();
        let operation = match case {
            BoundCase::Complete | BoundCase::WithheldWait => None,
            BoundCase::SupervisorStall
            | BoundCase::WorkerStall
            | BoundCase::LateRead
            | BoundCase::WithheldConsumer => Some("expired"),
            BoundCase::ExtensionFlood => Some("bounds-result-record"),
            BoundCase::OutputFlood => Some("output-cap"),
            BoundCase::Replay => Some("bounds-result-epoch"),
            BoundCase::PreCutoverLoss => Some("bounds-supervisor-loss"),
            BoundCase::WithheldPopulation => Some("fixture-withheld-population"),
            BoundCase::WithheldSentinel => Some("fixture-withheld-sentinel"),
        };
        if let Some(operation) = operation {
            r.first = Some(failure(operation, 0));
            r.errors[0] = r.first;
            r.outcome = expected_outcome(Case::Bounds(case));
            if r.outcome == Outcome::Incomplete {
                r.releases = 0;
                r.leases_held = [true; 2];
                r.custody_retained = true;
            } else {
                s.cutover = false;
                s.result_valid = case == BoundCase::PreCutoverLoss;
                s.worker_terminal = case == BoundCase::PreCutoverLoss;
                if case != BoundCase::PreCutoverLoss {
                    s.candidate_received = false;
                    s.result_frame = None;
                    s.result_return = None;
                    s.stopped_oom_checked = false;
                    s.sentinel_stopped = false;
                }
            }
        }
        match case {
            BoundCase::Replay => {
                s.replay_epoch = Some(42);
                s.result_frame = Some(message(2, 42));
            }
            BoundCase::LateRead => {
                s.candidate_received = true;
                s.result_frame = Some(message(2, 41));
                s.result_return = Some(s.work_cap);
            }
            BoundCase::ExtensionFlood => s.result_frame = Some(message(12, 41)),
            BoundCase::PreCutoverLoss => s.loss_observed = true,
            BoundCase::WithheldPopulation => r.empty = false,
            BoundCase::WithheldConsumer => {
                r.consumers = 1;
                s.consumer_withheld = true;
            }
            BoundCase::WithheldSentinel => {
                s.sentinel_post = false;
                s.sentinel_stopped = false;
            }
            _ => {}
        }
    }
    r
}

/// Synthetic codec vectors, not runtime evidence. Consume with the Python
/// test script's explicit --rust-frames mode after a --nocapture test run.
#[test]
fn emit_cross_language_corpus() {
    for case in CASES {
        let source = case_report(case);
        if case != Case::SupervisorOnly {
            assert!(source.case_passed(), "{}", case_id(case));
        }
        let kind = if source.outcome == Outcome::Incomplete {
            CompletionKind::Quarantined
        } else {
            CompletionKind::Clean
        };
        let frame = encode(&source, kind, &context()).unwrap();
        let encoded = frame
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect::<String>();
        println!("\nR1_FRAME {} {encoded}", case_id(case));
    }
}

#[test]
fn largest_integer_and_bounded_error_arrays_are_lossless() {
    let mut source = report();
    source.epoch = u64::MAX;
    source.oom_kills = [u64::MAX; 3];
    source.first = Some(crate::kernel::failure("failed-operation", i32::MAX));
    source.errors = [source.first; 16];
    let data = encode(&source, CompletionKind::Clean, &context()).unwrap();
    let row: serde_json::Value = serde_json::from_slice(&data[4..]).unwrap();
    assert_eq!(row["report"]["epoch"].as_u64(), Some(u64::MAX));
    assert_eq!(row["report"]["oom_kills"][2].as_u64(), Some(u64::MAX));
    assert_eq!(row["report"]["errors"].as_array().unwrap().len(), 16);
    assert_eq!(
        row["report"]["errors"][15]["errno"].as_i64(),
        Some(i64::from(i32::MAX))
    );
}

#[test]
fn frame_is_length_prefixed_json_and_preserves_complete_report() {
    let data = encode(&report(), CompletionKind::Clean, &context()).unwrap();
    assert_eq!(
        u32::from_be_bytes(data[..4].try_into().unwrap()) as usize,
        data.len() - 4
    );
    let value: serde_json::Value = serde_json::from_slice(&data[4..]).unwrap();
    assert_eq!(value["scope"], "contained-job-report-v1");
    assert_eq!(value["mode"], "runtime-candidate");
    assert_eq!(value["completion"], "clean");
    assert_eq!(value["report"]["terminal"][0]["pid"], 101);
    assert_eq!(value["report"]["epoch"], 41);
    assert_eq!(value["report"].as_object().unwrap().len(), 32);
    assert_eq!(value["report"]["native_authorized"], false);
    assert!(data.len() <= MAX_FRAME + 4);
}

#[test]
fn bounds_and_quarantine_preserve_all_evidence() {
    let source = bounds_report(BoundCase::WithheldWait);
    let data = encode(&source, CompletionKind::Quarantined, &context()).unwrap();
    let value: serde_json::Value = serde_json::from_slice(&data[4..]).unwrap();
    assert_eq!(value["report"]["outcome"], "incomplete");
    assert_eq!(value["report"]["releases"], 0);
    assert_eq!(value["report"]["custody_retained"], true);
    assert_eq!(
        value["report"]["first"]["operation"],
        "fixture-withheld-wait"
    );
    assert_eq!(value["report"]["bounds"]["result_frame"][0], 2);
    assert_eq!(value["report"]["bounds"]["result_frame"][1], 41);
    assert_eq!(value["report"]["bounds"].as_object().unwrap().len(), 20);
    assert_eq!(source.releases, 0);
    assert!(source.custody_retained);
}

#[test]
fn no_job_does_not_gain_cleanup_facts() {
    let mut source = report();
    source.outcome = Outcome::NoJobCreated;
    source.kill = false;
    source.empty = false;
    source.direct_reaped = false;
    source.drained = false;
    source.terminal = [None; 33];
    source.operations = 0;
    let data = encode(&source, CompletionKind::Clean, &context()).unwrap();
    let value: serde_json::Value = serde_json::from_slice(&data[4..]).unwrap();
    assert_eq!(value["report"]["outcome"], "no_job_created");
    assert_eq!(value["report"]["empty"], false);
    assert_eq!(value["report"]["terminal"][0], serde_json::Value::Null);
    source.direct_reaped = true;
    assert!(encode(&source, CompletionKind::Clean, &context()).is_err());
}

#[test]
fn encoder_rejects_bad_context_authority_and_invalid_wait() {
    for bad in ["", "../x", "run-\n", "UPPER", "run-é"] {
        let mut identity = context();
        identity.run_id = bad;
        assert!(encode(&report(), CompletionKind::Clean, &identity).is_err());
    }
    let mut identity = context();
    identity.sequence = 6;
    assert!(encode(&report(), CompletionKind::Clean, &identity).is_err());
    let mut source = report();
    source.native_authorized = true;
    assert!(encode(&source, CompletionKind::Clean, &context()).is_err());
    source.native_authorized = false;
    source.terminal[0] = Some(crate::kernel::Wait::Pending);
    assert!(encode(&source, CompletionKind::Clean, &context()).is_err());
    source.terminal[0] = None;
    source.first = Some(crate::kernel::failure("unquoted\"error", 0));
    assert!(encode(&source, CompletionKind::Clean, &context()).is_err());
    let mut source = bounds_report(BoundCase::Complete);
    source.bounds.as_mut().unwrap().replay_epoch = Some(0);
    assert!(encode(&source, CompletionKind::Clean, &context()).is_err());
}

#[test]
fn every_context_digest_uuid_and_zero_epoch_is_checked() {
    for field in 0..4 {
        let mut identity = context();
        match field {
            0 => identity.boot_input_sha256 = "bad",
            1 => identity.build_sha256 = "bad",
            2 => identity.input_manifest_sha256 = "bad",
            3 => identity.guest_boot_id = "bad",
            _ => unreachable!(),
        }
        assert_eq!(
            encode(&report(), CompletionKind::Clean, &identity),
            Err(Error::InvalidContext)
        );
    }
    let mut source = report();
    source.epoch = 0;
    assert_eq!(
        encode(&source, CompletionKind::Clean, &context()),
        Err(Error::InvalidReport)
    );
}

#[test]
fn case_inventory_names_every_native_variant_once() {
    let expected = [
        "supervisor-only",
        "loss-before-birth",
        "loss-before-delivery",
        "loss-before-registration",
        "loss-before-placement",
        "loss-before-readback",
        "loss-after-readback",
        "double-fork",
        "zombie",
        "bounds-complete",
        "bounds-supervisor-stall",
        "bounds-worker-stall",
        "bounds-extension-flood",
        "bounds-output-flood",
        "bounds-replay",
        "bounds-late-read",
        "bounds-pre-cutover-loss",
        "bounds-withheld-wait",
        "bounds-withheld-population",
        "bounds-withheld-consumer",
        "bounds-withheld-sentinel",
    ];
    let native = std::iter::once(Case::SupervisorOnly)
        .chain(Cut::ALL.into_iter().map(Case::Loss))
        .chain([Case::DoubleFork, Case::Zombie])
        .chain(BoundCase::ALL.into_iter().map(Case::Bounds))
        .collect::<Vec<_>>();
    assert_eq!(native, CASES);
    for (case, name) in native.into_iter().zip(expected) {
        assert_eq!(case_id(case), name);
        assert_eq!(case_from_id(name), Ok(case));
    }
}

#[test]
fn case_policy_never_expects_no_job_created() {
    for case in CASES {
        let expected = match case {
            Case::SupervisorOnly | Case::Bounds(BoundCase::Complete) => Outcome::Complete,
            Case::Bounds(
                BoundCase::WithheldWait
                | BoundCase::WithheldPopulation
                | BoundCase::WithheldConsumer
                | BoundCase::WithheldSentinel,
            ) => Outcome::Incomplete,
            _ => Outcome::AbortedClean,
        };
        assert_eq!(expected_outcome(case), expected);
        assert_ne!(expected_outcome(case), Outcome::NoJobCreated);
    }
}

#[test]
fn unknown_or_aliased_case_names_refuse() {
    for name in [
        "",
        "normal",
        "bounds_complete",
        "Bounds-Complete",
        "bounds-complete\0",
        " bounds-complete",
        "bounds-complete ",
        "bounds-withheld-unknown",
    ] {
        assert!(case_from_id(name).is_err(), "{name:?}");
    }
}

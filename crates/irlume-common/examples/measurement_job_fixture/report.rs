// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright the irlume contributors.

//! Pure report framing for the private contained-job experiment.
//!
//! These are bounded candidate bytes, not proof of execution, ownership,
//! finalization or a qualified case. This module performs no I/O or syscalls.
//! The later adapter must derive [`CompletionKind`] from its retained completion
//! owner and obey the independently enforced case deadline even after encoding.

use super::kernel::{bounds::BoundCase, Case, Cut, Failure, Outcome, Report, Wait};
use serde_json::{json, Value};

/// Maximum JSON payload bytes, excluding the four-byte big-endian length.
pub const MAX_FRAME: usize = 16 * 1024;

/// Correlation inputs selected outside the received report, not credentials.
#[derive(Clone, Debug)]
pub struct Context<'a> {
    pub run_id: &'a str,
    pub boot_input_sha256: &'a str,
    pub guest_boot_id: &'a str,
    pub build_sha256: &'a str,
    pub input_manifest_sha256: &'a str,
    pub sequence: u32,
}

/// Describes the retained native completion owner, never replaces it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CompletionKind {
    Clean,
    Quarantined,
}

/// Fixed inventory. Batch selection cannot redefine a case's expected outcome.
pub const CASES: [Case; 21] = [
    Case::SupervisorOnly,
    Case::Loss(Cut::BeforeBirth),
    Case::Loss(Cut::BeforeDelivery),
    Case::Loss(Cut::BeforeRegistration),
    Case::Loss(Cut::BeforePlacement),
    Case::Loss(Cut::BeforeReadback),
    Case::Loss(Cut::AfterReadback),
    Case::DoubleFork,
    Case::Zombie,
    Case::Bounds(BoundCase::Complete),
    Case::Bounds(BoundCase::SupervisorStall),
    Case::Bounds(BoundCase::WorkerStall),
    Case::Bounds(BoundCase::ExtensionFlood),
    Case::Bounds(BoundCase::OutputFlood),
    Case::Bounds(BoundCase::Replay),
    Case::Bounds(BoundCase::LateRead),
    Case::Bounds(BoundCase::PreCutoverLoss),
    Case::Bounds(BoundCase::WithheldWait),
    Case::Bounds(BoundCase::WithheldPopulation),
    Case::Bounds(BoundCase::WithheldConsumer),
    Case::Bounds(BoundCase::WithheldSentinel),
];

/// A refused private report, never an OS or launch result.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Error {
    UnknownCase,
    InvalidContext,
    InvalidReport,
    FrameSize,
    Serialization,
}

/// Stable fixture-only case names; adding a native variant requires an explicit arm.
pub const fn case_id(case: Case) -> &'static str {
    match case {
        Case::SupervisorOnly => "supervisor-only",
        Case::Loss(Cut::BeforeBirth) => "loss-before-birth",
        Case::Loss(Cut::BeforeDelivery) => "loss-before-delivery",
        Case::Loss(Cut::BeforeRegistration) => "loss-before-registration",
        Case::Loss(Cut::BeforePlacement) => "loss-before-placement",
        Case::Loss(Cut::BeforeReadback) => "loss-before-readback",
        Case::Loss(Cut::AfterReadback) => "loss-after-readback",
        Case::DoubleFork => "double-fork",
        Case::Zombie => "zombie",
        Case::Bounds(BoundCase::Complete) => "bounds-complete",
        Case::Bounds(BoundCase::SupervisorStall) => "bounds-supervisor-stall",
        Case::Bounds(BoundCase::WorkerStall) => "bounds-worker-stall",
        Case::Bounds(BoundCase::ExtensionFlood) => "bounds-extension-flood",
        Case::Bounds(BoundCase::OutputFlood) => "bounds-output-flood",
        Case::Bounds(BoundCase::Replay) => "bounds-replay",
        Case::Bounds(BoundCase::LateRead) => "bounds-late-read",
        Case::Bounds(BoundCase::PreCutoverLoss) => "bounds-pre-cutover-loss",
        Case::Bounds(BoundCase::WithheldWait) => "bounds-withheld-wait",
        Case::Bounds(BoundCase::WithheldPopulation) => "bounds-withheld-population",
        Case::Bounds(BoundCase::WithheldConsumer) => "bounds-withheld-consumer",
        Case::Bounds(BoundCase::WithheldSentinel) => "bounds-withheld-sentinel",
    }
}

/// Parse an exact fixture-only case name.
///
/// # Errors
/// Rejects unknown names, aliases and whitespace.
pub fn case_from_id(name: &str) -> Result<Case, Error> {
    CASES
        .into_iter()
        .find(|case| case_id(*case) == name)
        .ok_or(Error::UnknownCase)
}

/// Expected native outcome only; neither this value nor a report grants acceptance.
pub const fn expected_outcome(case: Case) -> Outcome {
    match case {
        Case::SupervisorOnly | Case::Bounds(BoundCase::Complete) => Outcome::Complete,
        Case::Bounds(
            BoundCase::WithheldWait
            | BoundCase::WithheldPopulation
            | BoundCase::WithheldConsumer
            | BoundCase::WithheldSentinel,
        ) => Outcome::Incomplete,
        Case::Loss(_)
        | Case::DoubleFork
        | Case::Zombie
        | Case::Bounds(
            BoundCase::SupervisorStall
            | BoundCase::WorkerStall
            | BoundCase::ExtensionFlood
            | BoundCase::OutputFlood
            | BoundCase::Replay
            | BoundCase::LateRead
            | BoundCase::PreCutoverLoss,
        ) => Outcome::AbortedClean,
    }
}

fn identifier(value: &str) -> bool {
    let alnum = |b: u8| b.is_ascii_lowercase() || b.is_ascii_digit();
    (1..=64).contains(&value.len())
        && value.bytes().next().is_some_and(alnum)
        && value.bytes().all(|b| alnum(b) || b == b'-')
}

fn hex(byte: u8) -> bool {
    byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte)
}

fn digest(value: &str) -> bool {
    value.len() == 64 && value.bytes().all(hex)
}

fn uuid(value: &str) -> bool {
    value.len() == 36
        && value.bytes().enumerate().all(|(i, b)| {
            if [8, 13, 18, 23].contains(&i) {
                b == b'-'
            } else {
                hex(b)
            }
        })
}

fn failure_value(value: &Option<Failure>) -> Result<Value, Error> {
    match value {
        None => Ok(Value::Null),
        Some(f) if identifier(f.operation) && f.errno >= 0 => {
            Ok(json!({"operation": f.operation, "errno": f.errno}))
        }
        Some(_) => Err(Error::InvalidReport),
    }
}

fn pid_valid(value: u32) -> bool {
    (1..=i32::MAX as u32).contains(&value)
}

fn wait_value(value: &Option<Wait>) -> Result<Value, Error> {
    match value {
        None => Ok(Value::Null),
        Some(Wait::Terminal { pid, code, status })
            if pid_valid(*pid)
                && ((*code == 1 && (0..=255).contains(status))
                    || ((2..=3).contains(code) && (1..=64).contains(status))) =>
        {
            Ok(json!({"pid": pid, "code": code, "status": status}))
        }
        Some(Wait::Pending | Wait::NoChildren | Wait::Terminal { .. }) => Err(Error::InvalidReport),
    }
}

fn outcome_id(value: Outcome) -> &'static str {
    match value {
        Outcome::Complete => "complete",
        Outcome::AbortedClean => "aborted_clean",
        Outcome::NoJobCreated => "no_job_created",
        Outcome::Incomplete => "incomplete",
    }
}

fn cut_id(value: Cut) -> &'static str {
    match value {
        Cut::BeforeBirth => "before-birth",
        Cut::BeforeDelivery => "before-delivery",
        Cut::BeforeRegistration => "before-registration",
        Cut::BeforePlacement => "before-placement",
        Cut::BeforeReadback => "before-readback",
        Cut::AfterReadback => "after-readback",
    }
}

fn bounds_value(value: &Option<super::kernel::bounds::State>) -> Value {
    use super::kernel::bounds::{OutputBudget, State};
    let Some(State {
        output: OutputBudget { bytes, exhausted },
        work_cap,
        caps,
        active,
        candidate_received,
        result_frame,
        result_return,
        result_postcheck_pending,
        replay_epoch,
        result_valid,
        worker_terminal,
        cutover,
        loss_observed,
        stopped_oom_checked,
        sentinel_created,
        sentinel_pre,
        sentinel_post,
        sentinel_stopped,
        sentinel_failed,
        consumer_withheld,
    }) = value
    else {
        return Value::Null;
    };
    json!({
        "output": {"bytes": bytes, "exhausted": exhausted},
        "work_cap": work_cap, "caps": caps, "active": active,
        "candidate_received": candidate_received, "result_frame": result_frame,
        "result_return": result_return, "result_postcheck_pending": result_postcheck_pending,
        "replay_epoch": replay_epoch, "result_valid": result_valid,
        "worker_terminal": worker_terminal, "cutover": cutover,
        "loss_observed": loss_observed, "stopped_oom_checked": stopped_oom_checked,
        "sentinel_created": sentinel_created, "sentinel_pre": sentinel_pre,
        "sentinel_post": sentinel_post, "sentinel_stopped": sentinel_stopped,
        "sentinel_failed": sentinel_failed, "consumer_withheld": consumer_withheld,
    })
}

/// Encode one complete, length-prefixed JSON candidate without consuming custody.
///
/// Integer/enum domains and binding syntax are checked, not the truth of any
/// claim. Field counts and string bounds cap the object before serialization;
/// the final frame-size check is an additional invariant. No arbitrary strings,
/// paths, debug representations, descriptors or native capability are emitted.
///
/// # Errors
/// Rejects malformed context, invalid primitive report values, mismatched
/// completion kind, authority claims, nonterminal waits or an oversized frame.
pub fn encode(
    report: &Report,
    kind: CompletionKind,
    context: &Context<'_>,
) -> Result<Vec<u8>, Error> {
    if !identifier(context.run_id)
        || !digest(context.boot_input_sha256)
        || !uuid(context.guest_boot_id)
        || !digest(context.build_sha256)
        || !digest(context.input_manifest_sha256)
        || context.sequence >= 6
    {
        return Err(Error::InvalidContext);
    }
    if report.epoch == 0
        || report.native_authorized
        || report.full_contract_proven
        || report.adopted > 32
        || report.worker_pid.is_some_and(|pid| !pid_valid(pid))
        || report.descendant_pid.is_some_and(|pid| !pid_valid(pid))
        || report.case.bounds().is_some() != report.bounds.is_some()
        || report
            .bounds
            .as_ref()
            .is_some_and(|s| s.replay_epoch == Some(0))
        || (report.outcome == Outcome::Incomplete) != (kind == CompletionKind::Quarantined)
    {
        return Err(Error::InvalidReport);
    }
    if report.outcome == Outcome::NoJobCreated
        && (report.kill
            || report.empty
            || report.direct_reaped
            || report.drained
            || report.worker_reaped
            || report.descendant_reaped
            || report.consumers != 0
            || report.adopted != 0
            || report.worker_pid.is_some()
            || report.descendant_pid.is_some()
            || report.terminal.iter().any(Option::is_some)
            || report.releases != 1
            || report.leases_held != [false; 2]
            || report.custody_retained)
    {
        return Err(Error::InvalidReport);
    }
    // Exhaustive destructuring forces an explicit schema decision for new fields.
    let Report {
        bounds,
        case,
        reached,
        injected,
        registered,
        placed,
        placement_verified,
        worker_pid,
        descendant_pid,
        worker_reaped,
        descendant_reaped,
        oom_observations,
        oom_kills,
        epoch,
        outcome,
        reserved,
        leases_held,
        custody_retained,
        releases,
        first,
        errors,
        errors_truncated,
        kill,
        empty,
        direct_reaped,
        drained,
        consumers,
        adopted,
        terminal,
        operations,
        native_authorized,
        full_contract_proven,
    } = report;
    let errors = errors
        .iter()
        .map(failure_value)
        .collect::<Result<Vec<_>, _>>()?;
    let terminal = terminal
        .iter()
        .map(wait_value)
        .collect::<Result<Vec<_>, _>>()?;
    let row = json!({
        "scope": "contained-job-report-v1", "mode": "runtime-candidate",
        "identity": {
            "run_id": context.run_id, "boot_input_sha256": context.boot_input_sha256,
            "guest_boot_id": context.guest_boot_id, "build_sha256": context.build_sha256,
            "input_manifest_sha256": context.input_manifest_sha256,
        },
        "sequence": context.sequence,
        "limits": {
            "case_total_ns": 20_000_000_000_u64, "phase_ns": 5_000_000_000_u64,
            "case_output_bytes": super::kernel::bounds::OUTPUT_LIMIT,
            "max_operations": super::kernel::MAX_OPERATIONS, "batch_cases": 6,
        },
        "completion": match kind { CompletionKind::Clean => "clean", CompletionKind::Quarantined => "quarantined" },
        "report": {
            "bounds": bounds_value(bounds), "case": case_id(*case), "reached": reached.map(cut_id),
            "injected": injected, "registered": registered, "placed": placed,
            "placement_verified": placement_verified, "worker_pid": worker_pid,
            "descendant_pid": descendant_pid, "worker_reaped": worker_reaped,
            "descendant_reaped": descendant_reaped, "oom_observations": oom_observations,
            "oom_kills": oom_kills, "epoch": epoch, "outcome": outcome_id(*outcome),
            "reserved": reserved, "leases_held": leases_held, "custody_retained": custody_retained,
            "releases": releases, "first": failure_value(first)?, "errors": errors,
            "errors_truncated": errors_truncated, "kill": kill, "empty": empty,
            "direct_reaped": direct_reaped, "drained": drained, "consumers": consumers,
            "adopted": adopted, "terminal": terminal, "operations": operations,
            "native_authorized": native_authorized, "full_contract_proven": full_contract_proven,
        },
    });
    let payload = serde_json::to_vec(&row).map_err(|_| Error::Serialization)?;
    if payload.len() > MAX_FRAME {
        return Err(Error::FrameSize);
    }
    let size = u32::try_from(payload.len()).map_err(|_| Error::FrameSize)?;
    let mut frame = Vec::with_capacity(4 + payload.len());
    frame.extend_from_slice(&size.to_be_bytes());
    frame.extend_from_slice(&payload);
    Ok(frame)
}

#[cfg(test)]
#[path = "report_tests.rs"]
mod tests;

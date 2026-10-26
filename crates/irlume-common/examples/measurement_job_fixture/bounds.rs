// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright the irlume contributors.

//! Fixed public data and bounded exercise protocol for the private job fixture.

use super::{
    check_oom, failure, guard, message, peek, read_record, send_command, step, stop_supervisor,
    Case, Effects, Outcome, Phase, Quarantine, Read, Report, Result,
};

pub const OUTPUT_LIMIT: usize = 1024 * 1024;
pub const POLL_MS: i32 = 10;
pub const SENTINEL_MARKER: &[u8] = b"irlume-job-custody-v1\0";
pub const SENTINEL_LEN: usize = SENTINEL_MARKER.len() + 8;
pub const SENTINEL_SEALS: i32 = 0x2f;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum BoundCase {
    Complete,
    SupervisorStall,
    WorkerStall,
    ExtensionFlood,
    OutputFlood,
    Replay,
    LateRead,
    PreCutoverLoss,
    WithheldWait,
    WithheldPopulation,
    WithheldConsumer,
    WithheldSentinel,
}

impl BoundCase {
    pub const ALL: [Self; 12] = [
        Self::Complete,
        Self::SupervisorStall,
        Self::WorkerStall,
        Self::ExtensionFlood,
        Self::OutputFlood,
        Self::Replay,
        Self::LateRead,
        Self::PreCutoverLoss,
        Self::WithheldWait,
        Self::WithheldPopulation,
        Self::WithheldConsumer,
        Self::WithheldSentinel,
    ];
}

#[derive(Clone, Debug, Default)]
pub struct State {
    pub output: OutputBudget,
    pub work_cap: u64,
    pub caps: [u64; 4],
    pub active: bool,
    pub candidate_received: bool,
    pub result_frame: Option<[u8; 9]>,
    pub result_return: Option<u64>,
    pub result_postcheck_pending: bool,
    pub replay_epoch: Option<u64>,
    pub result_valid: bool,
    pub worker_terminal: bool,
    pub cutover: bool,
    pub loss_observed: bool,
    pub stopped_oom_checked: bool,
    pub sentinel_created: bool,
    pub sentinel_pre: bool,
    pub sentinel_post: bool,
    pub sentinel_stopped: bool,
    pub sentinel_failed: bool,
    pub consumer_withheld: bool,
}

fn state<H>(owner: &mut Quarantine<H>) -> Result<&mut State> {
    owner
        .report
        .bounds
        .as_mut()
        .ok_or(failure("bounds-state", 0))
}

pub(super) fn exercise<E: Effects>(os: &mut E, owner: &mut Quarantine<E::Handle>) -> Result<()> {
    let Case::Bounds(case) = owner.report.case else {
        return Err(failure("bounds-case", 0));
    };
    let cap = owner
        .deadlines
        .as_ref()
        .ok_or(failure("bounds-deadline", 0))?
        .cap(Phase::Exercise);
    step(os, owner, Phase::Exercise, |os, owner| {
        state(owner)?.work_cap = cap;
        os.arm_work(cap)
    })?;
    send_command(os, owner, 7)?;
    let mut active = [0; 9];
    read_record(
        os,
        owner,
        Read::Active,
        Phase::Exercise,
        &mut active,
        |_, _| Ok(()),
    )?;
    if active != message(9, owner.report.epoch) {
        return Err(failure("bounds-active", 0));
    }
    state(owner)?.active = true;
    send_command(os, owner, 10)?;
    let mut result = [0; 9];
    read_record(
        os,
        owner,
        Read::Complete,
        Phase::Exercise,
        &mut result,
        |owner, bytes| {
            let expected_epoch = owner.report.epoch;
            let frame: [u8; 9] = bytes
                .try_into()
                .map_err(|_| failure("bounds-result-record", 0))?;
            let epoch = u64::from_le_bytes(
                frame[1..]
                    .try_into()
                    .map_err(|_| failure("bounds-result-record", 0))?,
            );
            let s = state(owner)?;
            s.result_frame = Some(frame);
            if frame[0] != 2 || epoch == 0 {
                return Err(failure("bounds-result-record", 0));
            }
            if epoch != expected_epoch {
                s.replay_epoch = Some(epoch);
                return Err(failure("bounds-result-epoch", 0));
            }
            s.candidate_received = true;
            s.result_postcheck_pending = true;
            Ok(())
        },
    )?;
    state(owner)?.result_valid = true;
    step(os, owner, Phase::Exercise, |os, owner| {
        if !os.worker_terminal(owner.worker.as_ref().ok_or(failure("worker-missing", 0))?)? {
            return Err(failure("worker-not-terminal", 0));
        }
        state(owner)?.worker_terminal = true;
        Ok(())
    })?;
    peek(os, owner, Phase::Exercise)?;
    check_oom(os, owner, Phase::Exercise)?;
    if case == BoundCase::PreCutoverLoss {
        stop_supervisor(os, owner)?;
        state(owner)?.loss_observed = true;
        return Err(failure("bounds-supervisor-loss", 0));
    }
    // No external effect or fallible postcheck follows the cutover commit.
    guard(os, owner, Phase::Exercise)?;
    let committed = state(owner)?;
    committed.cutover = true;
    committed.consumer_withheld = case == BoundCase::WithheldConsumer;
    if case == BoundCase::WithheldConsumer {
        owner.report.consumers += 1;
    }
    Ok(())
}

pub(super) fn observe_stopped<E: Effects>(
    os: &mut E,
    owner: &mut Quarantine<E::Handle>,
) -> Result<()> {
    if owner.report.direct_reaped
        && owner
            .report
            .bounds
            .as_ref()
            .is_some_and(|s| s.worker_terminal && !s.stopped_oom_checked)
    {
        // Bounds cases create exactly S and B. B was terminal before cutover;
        // once S is terminal no fixed actor remains capable of another OOM.
        check_oom(os, owner, Phase::Cleanup)?;
        state(owner)?.stopped_oom_checked = true;
    }
    if owner.report.case != Case::Bounds(BoundCase::WithheldSentinel)
        && owner
            .report
            .bounds
            .as_ref()
            .is_some_and(|s| s.stopped_oom_checked && !s.sentinel_stopped && !s.sentinel_failed)
    {
        let result = step(os, owner, Phase::Cleanup, |os, owner| {
            os.verify_sentinel(&owner.resources, owner.report.epoch, true)
        });
        match result {
            Ok(()) => state(owner)?.sentinel_stopped = true,
            Err(error) => {
                state(owner)?.sentinel_failed = true;
                return Err(error);
            }
        }
    }
    Ok(())
}

pub fn case_passed(report: &Report, case: BoundCase) -> bool {
    let Some(s) = &report.bounds else {
        return false;
    };
    if report.native_authorized
        || report.full_contract_proven
        || report.errors_truncated
        || !s.active
        || !s.sentinel_pre
        || s.sentinel_failed
        || report.oom_kills != [0; 3]
    {
        return false;
    }
    let only = |allowed: &[&str]| {
        report
            .errors
            .iter()
            .flatten()
            .all(|e| allowed.contains(&e.operation))
    };
    let first = report.first.map(|e| e.operation);
    let clean = report.kill
        && report.empty
        && report.direct_reaped
        && report.drained
        && report.worker_reaped
        && report.consumers == 0
        && report.releases == 1
        && report.leases_held == [false; 2]
        && !report.custody_retained
        && s.sentinel_post;
    let quarantined = report.outcome == Outcome::Incomplete
        && report.releases == 0
        && report.leases_held == [true; 2]
        && report.custody_retained
        && s.cutover
        && s.result_valid
        && s.worker_terminal
        && s.stopped_oom_checked
        && report.direct_reaped;
    match case {
        BoundCase::Complete => {
            clean
                && s.cutover
                && s.result_valid
                && s.worker_terminal
                && report.outcome == Outcome::Complete
                && first.is_none()
        }
        BoundCase::SupervisorStall | BoundCase::WorkerStall => {
            clean && !s.cutover && !s.result_valid && first == Some("expired") && only(&["expired"])
        }
        BoundCase::ExtensionFlood | BoundCase::OutputFlood => {
            clean
                && !s.cutover
                && first.is_some_and(|e| {
                    ["bounds-result-record", "channel-surplus", "output-cap"].contains(&e)
                })
                && only(&["bounds-result-record", "channel-surplus", "output-cap"])
        }
        BoundCase::Replay => {
            clean
                && !s.cutover
                && s.replay_epoch.is_some_and(|epoch| {
                    epoch != 0 && epoch != report.epoch && s.result_frame == Some(message(2, epoch))
                })
                && first == Some("bounds-result-epoch")
                && only(&["bounds-result-epoch"])
        }
        BoundCase::LateRead => {
            clean
                && !s.cutover
                && s.candidate_received
                && s.result_frame == Some(message(2, report.epoch))
                && s.work_cap != 0
                && s.result_return.is_some_and(|time| time >= s.work_cap)
                && !s.result_valid
                && first == Some("expired")
                && only(&["expired"])
        }
        BoundCase::PreCutoverLoss => {
            clean
                && !s.cutover
                && s.loss_observed
                && s.result_valid
                && s.worker_terminal
                && first == Some("bounds-supervisor-loss")
                && only(&["bounds-supervisor-loss"])
        }
        BoundCase::WithheldWait => {
            quarantined
                && s.sentinel_stopped
                && report.empty
                && !report.worker_reaped
                && !report.drained
                && report.consumers == 1
                && first == Some("fixture-withheld-wait")
                && only(&["fixture-withheld-wait", "expired"])
        }
        BoundCase::WithheldPopulation => {
            quarantined
                && s.sentinel_stopped
                && !report.empty
                && report.worker_reaped
                && report.drained
                && report.consumers == 0
                && first == Some("fixture-withheld-population")
                && only(&["fixture-withheld-population", "expired"])
        }
        BoundCase::WithheldConsumer => {
            quarantined
                && s.sentinel_stopped
                && report.empty
                && report.worker_reaped
                && report.drained
                && report.consumers == 1
                && s.consumer_withheld
                && first == Some("expired")
                && only(&["expired"])
        }
        BoundCase::WithheldSentinel => {
            quarantined
                && report.empty
                && report.worker_reaped
                && report.drained
                && report.consumers == 0
                && !s.sentinel_post
                && first == Some("fixture-withheld-sentinel")
                && only(&["fixture-withheld-sentinel"])
        }
    }
}

#[derive(Clone, Debug, Default)]
pub struct OutputBudget {
    pub bytes: usize,
    pub exhausted: bool,
}

impl OutputBudget {
    /// # Errors
    /// Refuses overflow, exhausted state, or a total above the fixed limit.
    pub fn charge(&mut self, count: usize) -> Result<()> {
        if self.exhausted {
            return Err(failure("output-cap", 0));
        }
        let Some(total) = self.bytes.checked_add(count) else {
            self.exhausted = true;
            return Err(failure("output-cap", 0));
        };
        self.bytes = total;
        if total > OUTPUT_LIMIT {
            self.exhausted = true;
            return Err(failure("output-cap", 0));
        }
        Ok(())
    }
}

pub fn sentinel(epoch: u64) -> [u8; SENTINEL_LEN] {
    let mut bytes = [0; SENTINEL_LEN];
    bytes[..SENTINEL_MARKER.len()].copy_from_slice(SENTINEL_MARKER);
    bytes[SENTINEL_MARKER.len()..].copy_from_slice(&epoch.to_le_bytes());
    bytes
}

/// # Errors
/// Refuses missing seals, wrong bytes/size, or executable/nonregular mode.
pub fn validate_sentinel(bytes: &[u8], size: i64, mode: u32, seals: i32, epoch: u64) -> Result<()> {
    if size != SENTINEL_LEN as i64
        || mode & 0o170000 != 0o100000
        || mode & 0o111 != 0
        || seals < 0
        || seals & SENTINEL_SEALS != SENTINEL_SEALS
        || bytes != sentinel(epoch)
    {
        return Err(failure("sentinel-proof", 0));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn output_exhaustion_is_sticky_and_checked() {
        let mut budget = OutputBudget::default();
        budget.charge(OUTPUT_LIMIT).unwrap();
        assert_eq!(budget.bytes, OUTPUT_LIMIT);
        assert!(budget.charge(1).is_err());
        assert!(budget.charge(0).is_err());
        assert!(budget.exhausted);
        let mut overflow = OutputBudget::default();
        overflow.charge(1).unwrap();
        assert!(overflow.charge(usize::MAX).is_err());
        assert!(overflow.charge(1).is_err());
    }

    #[test]
    fn sentinel_is_fixed_public_data_bound_to_epoch() {
        assert_ne!(sentinel(1), sentinel(2));
        assert_ne!(sentinel(9), sentinel(9 | (1u64 << 63)));
        assert_eq!(&sentinel(9)[SENTINEL_LEN - 8..], &9u64.to_le_bytes());
        assert_eq!(&sentinel(u64::MAX)[..SENTINEL_LEN - 8], SENTINEL_MARKER);
    }

    #[test]
    fn sentinel_requires_all_seals_exact_data_size_and_nonexec_regular_mode() {
        let bytes = sentinel(9);
        assert_eq!(
            validate_sentinel(&bytes, SENTINEL_LEN as i64, 0o100600, 0x2f, 9),
            Ok(())
        );
        for bit in [1, 2, 4, 8, 32] {
            assert!(
                validate_sentinel(&bytes, SENTINEL_LEN as i64, 0o100600, 0x2f ^ bit, 9).is_err()
            );
        }
        for mode in [0o100700, 0o100610, 0o100601, 0o040600] {
            assert!(validate_sentinel(&bytes, SENTINEL_LEN as i64, mode, 0x2f, 9).is_err());
        }
        for size in [-1, 0, SENTINEL_LEN as i64 - 1, SENTINEL_LEN as i64 + 1] {
            assert!(validate_sentinel(&bytes, size, 0o100600, 0x2f, 9).is_err());
        }
        assert!(validate_sentinel(&sentinel(8), SENTINEL_LEN as i64, 0o100600, 0x2f, 9).is_err());
        assert!(validate_sentinel(&bytes, SENTINEL_LEN as i64, 0o100600, -1, 9).is_err());
        let mut corrupt = bytes;
        corrupt[0] ^= 1;
        assert!(validate_sentinel(&corrupt, SENTINEL_LEN as i64, 0o100600, 0x2f, 9).is_err());
        assert!(validate_sentinel(
            &bytes[..SENTINEL_LEN - 1],
            SENTINEL_LEN as i64,
            0o100600,
            0x2f,
            9
        )
        .is_err());
    }
}

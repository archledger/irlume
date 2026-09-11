// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright the irlume contributors.

use crate::{IrSession, RgbSession, MAX_RATE_FILL_ATTEMPTS};
use irlume_common::{Error, Result};
use std::sync::atomic::{AtomicBool, Ordering};

/// Process captured evidence on the calling thread while both queues are serviced.
///
/// Use after [`crate::capture_pair_with`] on the same held sessions. Each queue
/// is drained independently, preserving delivered-rate, continuity, lease and
/// IR metadata/privacy checks. Neither processing nor its result needs `Send`.
/// An authentication result may remain nested inside the outer transport result.
///
/// Both scoped workers are joined, including their in-flight tail dequeues,
/// before a result is returned. Caller-owned sessions remain held; this function
/// neither captures a new pair nor recovers a failed stream. Cancellation is
/// cooperative at returned driver-call boundaries and cannot interrupt the
/// processing callback. Each worker has a bounded discard budget.
///
/// # Errors
/// Returns cancellation, deadline, stale-lease or either worker's transport
/// error, discarding even a successful processing result. The caller must also
/// discard any authentication evidence the callback mutated outside its return
/// value; this function cannot roll back callback side effects.
///
/// # Panics
/// Resumes a processing or drain panic after both workers have been joined.
pub fn process_pair_while_draining<T>(
    rgb: &mut RgbSession<'_>,
    ir: &mut IrSession<'_>,
    process: impl FnOnce() -> T,
) -> Result<T> {
    check_pair(rgb, ir)?;
    let rgb_lease = rgb.cam.lease.clone();
    let ir_lease = ir.cam.lease.clone();
    let result = process_with_pair_drains(
        process,
        || rgb_lease.run_active(|| rgb.discard_frame()),
        || ir_lease.run_active(|| ir.discard_frame()),
    );
    finish_processing(result, || check_controls(rgb, ir), || check_leases(rgb, ir))
}

fn check_pair(rgb: &RgbSession<'_>, ir: &IrSession<'_>) -> Result<()> {
    check_controls(rgb, ir)?;
    check_leases(rgb, ir)
}

fn check_controls(rgb: &RgbSession<'_>, ir: &IrSession<'_>) -> Result<()> {
    merge_checks(rgb.stream.control.check(), ir.stream.control.check())
}

fn check_leases(rgb: &RgbSession<'_>, ir: &IrSession<'_>) -> Result<()> {
    rgb.cam
        .lease
        .require_endpoint(&rgb.cam.device)
        .and_then(|()| ir.cam.lease.require_endpoint(&ir.cam.device))
        .map_err(|error| Error::Hardware(error.to_string()))
}

// This final gate is also reached on transport failure so request control can
// take precedence before the caller classifies a camera fault.
pub(super) fn finish_processing<T>(
    processed: Result<T>,
    check_control: impl FnOnce() -> Result<()>,
    check_lease: impl FnOnce() -> Result<()>,
) -> Result<T> {
    match (processed, check_control()) {
        (Ok(result), Ok(())) => {
            check_lease()?;
            Ok(result)
        }
        (Err(transport), Err(control)) => Err(prefer_control_error(transport, control)),
        (Err(transport), Ok(())) => Err(transport),
        (Ok(_), Err(control)) => Err(control),
    }
}

fn merge_checks(first: Result<()>, second: Result<()>) -> Result<()> {
    match (first, second) {
        (Err(first), Err(second)) => Err(prefer_control_error(first, second)),
        (Err(error), _) | (_, Err(error)) => Err(error),
        (Ok(()), Ok(())) => Ok(()),
    }
}

fn prefer_control_error(first: Error, second: Error) -> Error {
    // A request cancellation must not become a hardware fallback, even when
    // the other worker observed its deadline or a transport error first.
    match (first, second) {
        (error @ Error::Preempted(_), _) | (_, error @ Error::Preempted(_)) => error,
        (error @ Error::DeadlineExpired, _) | (_, error @ Error::DeadlineExpired) => error,
        (first, _) => first,
    }
}

struct Finished<'a>(&'a AtomicBool);

impl Drop for Finished<'_> {
    fn drop(&mut self) {
        self.0.store(true, Ordering::Release);
    }
}

pub(super) fn drain_until_finished(
    finished: &AtomicBool,
    mut drain: impl FnMut() -> Result<()>,
) -> Result<()> {
    // A transport error or panic must also release the companion worker.
    let _finished = Finished(finished);
    for _ in 0..2 * MAX_RATE_FILL_ATTEMPTS {
        if finished.load(Ordering::Acquire) {
            return Ok(());
        }
        drain()?;
    }
    if finished.load(Ordering::Acquire) {
        Ok(())
    } else {
        Err(Error::Hardware(
            "paired processing exceeded its bounded drain".into(),
        ))
    }
}

pub(super) fn process_with_pair_drains<T>(
    process: impl FnOnce() -> T,
    rgb_drain: impl FnMut() -> Result<()> + Send,
    ir_drain: impl FnMut() -> Result<()> + Send,
) -> Result<T> {
    let finished = AtomicBool::new(false);
    std::thread::scope(|scope| {
        // Declare before spawning: a failed second spawn must not strand the
        // first worker while the scope waits for it to terminate.
        let completion = Finished(&finished);
        let rgb = scope.spawn(|| drain_until_finished(&finished, rgb_drain));
        let ir = scope.spawn(|| drain_until_finished(&finished, ir_drain));
        let processed = std::panic::catch_unwind(std::panic::AssertUnwindSafe(process));
        drop(completion);
        let rgb = rgb.join();
        let ir = ir.join();
        // Join both before propagating either panic or error. A successful
        // callback result is still discarded if an in-flight dequeue failed.
        let result = processed.unwrap_or_else(|panic| std::panic::resume_unwind(panic));
        let rgb = rgb.unwrap_or_else(|panic| std::panic::resume_unwind(panic));
        let ir = ir.unwrap_or_else(|panic| std::panic::resume_unwind(panic));
        merge_checks(rgb, ir)?;
        Ok(result)
    })
}

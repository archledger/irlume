use super::{
    CaptureControl, Frame, IrCamera, IrCaptureStats, Progress, RgbCamera, RuntimePairContract,
};
use irlume_common::{Error, Result};
use std::time::{Duration, Instant};

/// Bounds for one all-or-nothing sequential capture batch.
#[derive(Clone, Copy, Debug)]
pub struct SequentialBatchRequest {
    /// Number of fresh pairs, from one through five.
    pub pairs: usize,
    /// Maximum allowed separation between corresponding RGB and IR windows.
    pub pair_gap_limit: Duration,
    /// Original operation deadline; capture never extends it.
    pub deadline: Instant,
}

/// Collect bounded fresh sequential evidence using already negotiated cameras.
///
/// The caller owns the camera operation and qualification/security policy.
/// RGB is fully released before IR starts. No recovery or partial batch reuse is
/// performed. An in-flight bounded driver call cannot be interrupted, but an
/// expired batch is never returned.
///
/// # Errors
/// Returns an error on invalid count, capture/lease failure, invalid runtime
/// contract, overlapping/out-of-order windows, excessive pair gap or deadline.
pub fn capture_sequential_batch_with_progress(
    rgb: &RgbCamera,
    ir: &IrCamera,
    contract: &RuntimePairContract,
    request: SequentialBatchRequest,
    progress: &Progress,
) -> Result<Vec<(Frame, Frame, IrCaptureStats)>> {
    capture_sequential_batch_with_control(
        rgb,
        ir,
        contract,
        request,
        &CaptureControl::with_progress(progress.clone()),
    )
}

/// Collect a sequential batch with cooperative request cancellation.
///
/// # Errors
/// Returns cancellation without partial evidence, or any error documented by
/// [`capture_sequential_batch_with_progress`]. Existing stream owners clean up
/// before another phase or downstream inference can run.
pub fn capture_sequential_batch_with_control(
    rgb: &RgbCamera,
    ir: &IrCamera,
    contract: &RuntimePairContract,
    request: SequentialBatchRequest,
    control: &CaptureControl,
) -> Result<Vec<(Frame, Frame, IrCaptureStats)>> {
    capture_batch_controlled_with(
        request,
        contract,
        (
            || rgb.session_with_control(control),
            |session| session.denoised(),
        ),
        (
            || ir.session_with_control_and_startup(control, super::IrSessionStartup::Adaptive),
            |session| session.capture_with_stats(),
        ),
        Instant::now,
        control,
        || {
            rgb.lease
                .require_endpoint(&rgb.device)
                .and_then(|()| ir.lease.require_endpoint(&ir.device))
                .map_err(|error| Error::Hardware(error.to_string()))
        },
    )
}

#[cfg(test)]
pub(super) fn capture_batch_with<R, I>(
    request: SequentialBatchRequest,
    contract: &RuntimePairContract,
    rgb: (
        impl FnOnce() -> Result<R>,
        impl FnMut(&mut R) -> Result<Frame>,
    ),
    ir: (
        impl FnOnce() -> Result<I>,
        impl FnMut(&mut I) -> Result<(Frame, IrCaptureStats)>,
    ),
    now: impl Fn() -> Instant,
    live: impl FnOnce() -> Result<()>,
) -> Result<Vec<(Frame, Frame, IrCaptureStats)>> {
    capture_batch_controlled_with(
        request,
        contract,
        rgb,
        ir,
        now,
        &CaptureControl::with_progress(super::no_progress()),
        live,
    )
}

pub(super) fn capture_batch_controlled_with<R, I>(
    request: SequentialBatchRequest,
    contract: &RuntimePairContract,
    rgb: (
        impl FnOnce() -> Result<R>,
        impl FnMut(&mut R) -> Result<Frame>,
    ),
    ir: (
        impl FnOnce() -> Result<I>,
        impl FnMut(&mut I) -> Result<(Frame, IrCaptureStats)>,
    ),
    now: impl Fn() -> Instant,
    control: &CaptureControl,
    live: impl FnOnce() -> Result<()>,
) -> Result<Vec<(Frame, Frame, IrCaptureStats)>> {
    if !(1..=5).contains(&request.pairs) {
        return Err(Error::Hardware(
            "sequential batch requires one through five pairs".into(),
        ));
    }
    let checkpoint = || {
        control.check()?;
        if now() >= request.deadline {
            Err(Error::Hardware("sequential batch deadline expired".into()))
        } else {
            Ok(())
        }
    };
    // Each phase owns its stream, including all error/unwind paths. The first
    // owner is dropped before the second opener can run; neither survives into
    // validation or downstream inference.
    let rgb = collect_phase(request.pairs, rgb, &checkpoint)?;
    let ir = collect_phase(request.pairs, ir, &checkpoint)?;
    checkpoint()?;
    if rgb
        .last()
        .zip(ir.first())
        .is_some_and(|(r, (i, _))| r.captured.end >= i.captured.start)
    {
        return Err(Error::Hardware(
            "sequential batch capture phases overlap".into(),
        ));
    }
    let mut pairs = Vec::with_capacity(request.pairs);
    let mut previous: Option<(super::CaptureWindow, super::CaptureWindow)> = None;
    for (r, (i, stats)) in rgb.into_iter().zip(ir) {
        checkpoint()?;
        contract.validate_pair(&r, &i).map_err(|error| {
            Error::Hardware(format!("invalid sequential batch pair: {error:?}"))
        })?;
        let rw = r.captured;
        let iw = i.captured;
        if rw.start > rw.end
            || iw.start > iw.end
            || previous.is_some_and(|(pr, pi)| pr.end >= rw.start || pi.end >= iw.start)
        {
            return Err(Error::Hardware(
                "sequential batch samples are not ordered and disjoint".into(),
            ));
        }
        if rw.gap_to(iw) > request.pair_gap_limit {
            return Err(Error::Hardware(
                "sequential batch pair gap exceeds limit".into(),
            ));
        }
        previous = Some((rw, iw));
        checkpoint()?;
        pairs.push((r, i, stats));
    }
    checkpoint()?;
    live()?;
    checkpoint()?;
    Ok(pairs)
}

fn collect_phase<S, T>(
    count: usize,
    (open, mut capture): (impl FnOnce() -> Result<S>, impl FnMut(&mut S) -> Result<T>),
    checkpoint: &impl Fn() -> Result<()>,
) -> Result<Vec<T>> {
    checkpoint()?;
    let mut session = open()?;
    checkpoint()?;
    let mut samples = Vec::with_capacity(count);
    for _ in 0..count {
        checkpoint()?;
        samples.push(capture(&mut session)?);
        checkpoint()?;
    }
    checkpoint()?;
    drop(session);
    checkpoint()?;
    Ok(samples)
}

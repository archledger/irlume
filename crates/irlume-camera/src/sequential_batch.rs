// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright the irlume contributors.

use super::{
    CaptureControl, Frame, IrCamera, IrCaptureStats, Progress, RgbCamera, RuntimePairContract,
};
use irlume_common::{Error, Result};
use std::sync::atomic::{AtomicBool, Ordering};
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

/// One timed phase of a sequential batch, reported when it ends, whether or
/// not it succeeded. Durations only: no frame, statistic or error text.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SequentialBatchPhase {
    /// RGB session start on the open camera: stream setup, buffers and the
    /// backlight write.
    RgbStart,
    /// One denoised RGB sample. The first of a session also starts the
    /// stream, waits out the auto-exposure warm-up and fills the
    /// delivered-rate window.
    RgbSample,
    /// RGB session release: stream stop, buffer release and backlight
    /// restore. Ends before the IR session starts.
    RgbRelease,
    /// IR session start: buffers, metadata queue, emitter enable, stream
    /// start and warm-up, delivered-rate fill.
    IrStart,
    /// One IR burst and its gate frame.
    IrSample,
    /// IR session release: stream stop, metadata close, buffer release and
    /// emitter restore.
    IrRelease,
}

/// The phase labels of one role's session in a batch.
#[derive(Clone, Copy)]
pub(crate) struct PhaseLabels {
    start: SequentialBatchPhase,
    sample: SequentialBatchPhase,
    release: SequentialBatchPhase,
}

pub(crate) const RGB_PHASES: PhaseLabels = PhaseLabels {
    start: SequentialBatchPhase::RgbStart,
    sample: SequentialBatchPhase::RgbSample,
    release: SequentialBatchPhase::RgbRelease,
};

pub(crate) const IR_PHASES: PhaseLabels = PhaseLabels {
    start: SequentialBatchPhase::IrStart,
    sample: SequentialBatchPhase::IrSample,
    release: SequentialBatchPhase::IrRelease,
};

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
    capture_sequential_batch_observed(rgb, ir, contract, request, control, &|_, _| {})
}

/// [`capture_sequential_batch_with_control`], reporting each phase's elapsed
/// time to `observe` on the calling thread as the phase ends. Observation
/// changes no capture, ordering or cleanup; `observe` must not block.
///
/// # Errors
/// The errors of [`capture_sequential_batch_with_control`].
pub fn capture_sequential_batch_observed(
    rgb: &RgbCamera,
    ir: &IrCamera,
    contract: &RuntimePairContract,
    request: SequentialBatchRequest,
    control: &CaptureControl,
    observe: &dyn Fn(SequentialBatchPhase, Duration),
) -> Result<Vec<(Frame, Frame, IrCaptureStats)>> {
    production_batch(
        rgb,
        ir,
        contract,
        request,
        control,
        observe,
        None::<NoOverlap>,
    )
    .map(|(pairs, _)| pairs)
}

/// What an overlap worker of [`capture_sequential_batch_overlapped`] asks
/// between units of its work: whether the IR phase it overlaps has ended,
/// so the batch waits at most for the unit in flight and the caller does
/// whatever the worker did not reach.
pub struct OverlapStop<'a>(&'a AtomicBool);

impl OverlapStop<'_> {
    /// True once the overlapped IR phase has ended, with or without its
    /// samples, or is unwinding.
    pub fn requested(&self) -> bool {
        self.0.load(Ordering::Acquire)
    }
}

/// The pairs of an overlapped batch and its worker's result, `None` when the
/// worker never ran (see [`capture_sequential_batch_overlapped`]).
pub type OverlappedBatch<W> = (Vec<(Frame, Frame, IrCaptureStats)>, Option<W>);

/// [`capture_sequential_batch_observed`] that also runs `overlap` over the
/// RGB samples while the IR session captures, so work that depends only on
/// RGB leaves the critical path.
///
/// `overlap` starts on a scoped thread after the RGB session is released and
/// receives the RGB samples in capture order; the IR session runs on the
/// calling thread as it does without overlap, and the RGB samples are
/// immutable while both run. When the IR phase ends, with its samples or
/// not, [`OverlapStop`] rises, so the worker hands back what it finished
/// and the batch waits at most for the unit in flight; the caller does the
/// rest itself, as it would without overlap. The worker joins before
/// validation on every path, failure and unwinding included, so neither its
/// borrows nor its thread outlive this call. A panicking worker resumes its
/// panic here after the IR session has been released. The result carries
/// `None` when the system refused the thread, in which case nothing ran.
/// Capture, ordering, cleanup and validation are those of
/// [`capture_sequential_batch_observed`].
///
/// # Errors
/// The errors of [`capture_sequential_batch_with_control`].
///
/// # Panics
/// Resumes a panic of `overlap` once the IR session has been released.
pub fn capture_sequential_batch_overlapped<W: Send>(
    rgb: &RgbCamera,
    ir: &IrCamera,
    contract: &RuntimePairContract,
    request: SequentialBatchRequest,
    control: &CaptureControl,
    observe: &dyn Fn(SequentialBatchPhase, Duration),
    overlap: impl FnOnce(&[Frame], &OverlapStop<'_>) -> W + Send,
) -> Result<OverlappedBatch<W>> {
    production_batch(rgb, ir, contract, request, control, observe, Some(overlap))
}

/// The production camera boundaries of a sequential batch, with or without
/// an overlap worker.
fn production_batch<W: Send>(
    rgb: &RgbCamera,
    ir: &IrCamera,
    contract: &RuntimePairContract,
    request: SequentialBatchRequest,
    control: &CaptureControl,
    observe: &dyn Fn(SequentialBatchPhase, Duration),
    overlap: Option<impl FnOnce(&[Frame], &OverlapStop<'_>) -> W + Send>,
) -> Result<OverlappedBatch<W>> {
    capture_batch_overlapped_with(
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
        observe,
        overlap,
    )
}

/// Bounds for one all-or-nothing single-stream RGB batch.
#[derive(Clone, Copy, Debug)]
pub struct RgbBatchRequest {
    /// Number of denoised samples, from one through five.
    pub samples: usize,
    /// Original operation deadline; capture never extends it.
    pub deadline: Instant,
}

/// Collect `request.samples` denoised RGB frames from ONE armed session on an
/// already negotiated camera. The convenience (RGB-only) tier pays stream
/// open, arm, warm-up and rate-window fill once per group instead of once per
/// PAD sample; measured 2026-09-17, per-sample setup of ~2.3s on a 15 fps RGB
/// sensor made the five-sample vote unreachable inside the default presence
/// window. The caller owns the camera operation and security policy. No
/// partial batch is returned on error.
///
/// # Errors
/// Returns an error on invalid count, capture/lease failure or deadline.
pub fn capture_rgb_denoised_batch_with_control(
    rgb: &RgbCamera,
    request: RgbBatchRequest,
    control: &CaptureControl,
) -> Result<Vec<Frame>> {
    let started = Instant::now();
    let frames = capture_rgb_batch_controlled_with(
        request,
        (
            || rgb.session_with_control(control),
            |session| session.denoised(),
        ),
        Instant::now,
        control,
        || {
            rgb.lease
                .require_endpoint(&rgb.device)
                .map_err(|error| Error::Hardware(error.to_string()))
        },
    )?;
    irlume_common::dlog!(
        "[capture-stage] rgb-batch {}: samples={} elapsed={}ms",
        rgb.device,
        frames.len(),
        started.elapsed().as_millis()
    );
    Ok(frames)
}

#[cfg(test)]
pub(super) fn capture_rgb_batch_with<R>(
    request: RgbBatchRequest,
    rgb: (
        impl FnOnce() -> Result<R>,
        impl FnMut(&mut R) -> Result<Frame>,
    ),
    now: impl Fn() -> Instant,
    live: impl FnOnce() -> Result<()>,
) -> Result<Vec<Frame>> {
    capture_rgb_batch_controlled_with(
        request,
        rgb,
        now,
        &CaptureControl::with_progress(super::no_progress()),
        live,
    )
}

pub(super) fn capture_rgb_batch_controlled_with<R>(
    request: RgbBatchRequest,
    (open, mut denoised): (
        impl FnOnce() -> Result<R>,
        impl FnMut(&mut R) -> Result<Frame>,
    ),
    now: impl Fn() -> Instant,
    control: &CaptureControl,
    live: impl FnOnce() -> Result<()>,
) -> Result<Vec<Frame>> {
    if !(1..=5).contains(&request.samples) {
        return Err(Error::Hardware(
            "RGB batch requires one through five samples".into(),
        ));
    }
    let checkpoint = || {
        control.check()?;
        if now() >= request.deadline {
            Err(Error::Hardware("RGB batch deadline expired".into()))
        } else {
            Ok(())
        }
    };
    // The session owns the stream across every sample in the group, including
    // all error/unwind paths, exactly like the sequential pair phases above.
    checkpoint()?;
    let mut session = open()?;
    checkpoint()?;
    let mut samples = Vec::with_capacity(request.samples);
    for _ in 0..request.samples {
        checkpoint()?;
        samples.push(denoised(&mut session)?);
        checkpoint()?;
    }
    checkpoint()?;
    drop(session);
    checkpoint()?;
    live()?;
    checkpoint()?;
    Ok(samples)
}

#[cfg(test)]
#[expect(
    clippy::too_many_arguments,
    reason = "the camera boundaries stay injectable for the scripted batch tests"
)]
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
    observe: &dyn Fn(SequentialBatchPhase, Duration),
) -> Result<Vec<(Frame, Frame, IrCaptureStats)>> {
    capture_batch_overlapped_with(
        request,
        contract,
        rgb,
        ir,
        now,
        control,
        live,
        observe,
        None::<NoOverlap>,
    )
    .map(|(pairs, _)| pairs)
}

/// The overlap of a batch that runs none: no thread is started.
type NoOverlap = fn(&[Frame], &OverlapStop<'_>);

#[expect(
    clippy::too_many_arguments,
    reason = "the camera boundaries stay injectable for the scripted batch tests"
)]
pub(super) fn capture_batch_overlapped_with<R, I, W: Send>(
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
    observe: &dyn Fn(SequentialBatchPhase, Duration),
    overlap: Option<impl FnOnce(&[Frame], &OverlapStop<'_>) -> W + Send>,
) -> Result<OverlappedBatch<W>> {
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
    // owner is dropped before the second opener can run, and the second
    // before validation. An overlap worker reads only the released RGB
    // frames: it starts after the RGB owner is gone and joins before
    // validation, so it changes no stream's lifetime, though its inference
    // runs while the IR stream is live.
    let rgb = collect_phase(request.pairs, rgb, &checkpoint, RGB_PHASES, observe)?;
    let ir_phase = || collect_phase(request.pairs, ir, &checkpoint, IR_PHASES, observe);
    let (ir, overlapped) = match overlap {
        Some(work) => overlap_ir_phase(&rgb, work, ir_phase),
        None => (ir_phase(), None),
    };
    let ir = ir?;
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
    Ok((pairs, overlapped))
}

/// Run `ir_phase` on the calling thread while `work` reads `rgb` on a scoped
/// thread; see [`capture_sequential_batch_overlapped`] for the contract.
fn overlap_ir_phase<T, W: Send>(
    rgb: &[Frame],
    work: impl FnOnce(&[Frame], &OverlapStop<'_>) -> W + Send,
    ir_phase: impl FnOnce() -> Result<T>,
) -> (Result<T>, Option<W>) {
    /// Raises the stop flag when dropped: when the IR phase returns, and on
    /// unwinding, where the scope then joins the worker before the panic
    /// continues.
    struct RaiseOnDrop<'a>(&'a AtomicBool);
    impl Drop for RaiseOnDrop<'_> {
        fn drop(&mut self) {
            self.0.store(true, Ordering::Release);
        }
    }
    let stop = AtomicBool::new(false);
    std::thread::scope(|scope| {
        let worker = std::thread::Builder::new()
            .name("irlume-rgb-overlap".into())
            .spawn_scoped(scope, || work(rgb, &OverlapStop(&stop)));
        if let Err(error) = &worker {
            // The system refused the thread: nothing runs beside the IR
            // phase, and the caller does the work after the batch as it would
            // without overlap.
            irlume_common::dlog!(
                "sequential batch: the RGB overlap thread did not start ({error}); \
                 the RGB half is left to the evaluation"
            );
        }
        let raise = RaiseOnDrop(&stop);
        let ir = ir_phase();
        drop(raise);
        let overlapped = match worker {
            Ok(handle) => match handle.join() {
                Ok(done) => Some(done),
                Err(panic) => std::panic::resume_unwind(panic),
            },
            Err(_) => None,
        };
        (ir, overlapped)
    })
}

pub(crate) fn collect_phase<S, T>(
    count: usize,
    (open, capture): (impl FnOnce() -> Result<S>, impl FnMut(&mut S) -> Result<T>),
    checkpoint: &impl Fn() -> Result<()>,
    phases: PhaseLabels,
    observe: &dyn Fn(SequentialBatchPhase, Duration),
) -> Result<Vec<T>> {
    checkpoint()?;
    let started = Instant::now();
    let session = open();
    observe(phases.start, started.elapsed());
    let mut session = session?;
    let samples = collect_samples(count, &mut session, capture, checkpoint, phases, observe);
    // The owner is dropped here on success and on every error, as before;
    // only an unwinding capture skips this report.
    let released = Instant::now();
    drop(session);
    observe(phases.release, released.elapsed());
    let samples = samples?;
    checkpoint()?;
    Ok(samples)
}

fn collect_samples<S, T>(
    count: usize,
    session: &mut S,
    mut capture: impl FnMut(&mut S) -> Result<T>,
    checkpoint: &impl Fn() -> Result<()>,
    phases: PhaseLabels,
    observe: &dyn Fn(SequentialBatchPhase, Duration),
) -> Result<Vec<T>> {
    checkpoint()?;
    let mut samples = Vec::with_capacity(count);
    for _ in 0..count {
        checkpoint()?;
        let started = Instant::now();
        let sample = capture(session);
        observe(phases.sample, started.elapsed());
        samples.push(sample?);
        checkpoint()?;
    }
    checkpoint()?;
    Ok(samples)
}

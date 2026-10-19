// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright the irlume contributors.

//! Sequential two-device capture under one retained operation capability.

use crate::{
    contracts::{IlluminationProvenance, StreamRole},
    frame_provenance::FrameBinding,
    lease::{split_trust_admitted, CameraOperationKind, CameraOperationSession},
    CaptureControl, Frame, IrCaptureStats, Spectrum,
};
use irlume_common::{Error, Result};
use std::time::{Duration, Instant};

/// Complete evidence captured together under one original split operation.
///
/// Privately constructed by the sequential capture path. It retains the original
/// reservation, frames and associated statistics; callers cannot certify an
/// arbitrary pair of old frames as a fresh split capture.
pub struct SplitPairCapture {
    operation: crate::lease::CameraLease,
    rgb_dev: String,
    ir_dev: String,
    rgb: Frame,
    ir: Frame,
    stats: IrCaptureStats,
}

impl SplitPairCapture {
    /// Read the captured RGB frame without separating it from its receipt.
    #[must_use]
    pub fn rgb(&self) -> &Frame {
        &self.rgb
    }

    /// Read the captured IR frame without separating it from its receipt.
    #[must_use]
    pub fn ir(&self) -> &Frame {
        &self.ir
    }

    /// Revalidate the original operation and both complete-pair frames.
    ///
    /// # Errors
    /// Refuses a different operation, expired original session or changed camera
    /// facts. Equal instance IDs and generations never substitute a later lease.
    pub fn revalidate(&self, operation: &CameraOperationSession) -> Result<()> {
        if !self.operation.same_operation(operation.lease()) {
            return Err(Error::Hardware(
                "split capture belongs to a different operation".into(),
            ));
        }
        validate_split_pair_in_operation(
            &self.rgb_dev,
            &self.ir_dev,
            operation,
            &self.rgb,
            &self.ir,
            self.stats.camera_classified_frames,
        )
    }

    /// Consume complete evidence only for the original still-valid operation.
    ///
    /// # Errors
    /// Returns the errors of [`Self::revalidate`]. Extraction does not let callers
    /// construct another receipt from the separated frames.
    pub fn into_parts(
        self,
        operation: &CameraOperationSession,
    ) -> Result<(Frame, Frame, IrCaptureStats)> {
        self.revalidate(operation)?;
        Ok((self.rgb, self.ir, self.stats))
    }
}

/// Capture one complete split pair, RGB first and IR only after RGB has stopped.
///
/// Reuses production one-shot capture and its fd, stream, metadata and control
/// owners. Both incarnations stay reserved until the caller drops `operation`.
/// Failure returns no partial evidence and never retries or changes either side.
/// This primitive supplies no account or administrator authorization and does not
/// enable split enrollment/authentication.
///
/// # Errors
/// Refuses ordinary or unsupported operations, stale/wrong-role endpoints,
/// cancellation/deadline, capture failure or invalid complete-pair provenance.
pub fn capture_split_pair_with_control(
    rgb_dev: &str,
    ir_dev: &str,
    operation: &CameraOperationSession,
    control: &CaptureControl,
) -> Result<SplitPairCapture> {
    capture_split_pair_observed(rgb_dev, ir_dev, operation, control, &|_, _| {})
}

/// [`capture_split_pair_with_control`], reporting each role's complete one-shot
/// duration after its resource owners have returned. `observe` must not block.
///
/// # Errors
/// Returns the errors of [`capture_split_pair_with_control`].
pub fn capture_split_pair_observed(
    rgb_dev: &str,
    ir_dev: &str,
    operation: &CameraOperationSession,
    control: &CaptureControl,
    observe: &dyn Fn(StreamRole, Duration),
) -> Result<SplitPairCapture> {
    capture_split_pair_observed_with(
        rgb_dev,
        ir_dev,
        operation,
        control,
        || crate::capture_rgb_denoised_with_control(rgb_dev, control),
        || crate::capture_ir_sequential_with_stats_and_control(ir_dev, control),
        observe,
    )
}

#[cfg(feature = "test-support")]
pub(crate) fn capture_split_pair_with(
    rgb_dev: &str,
    ir_dev: &str,
    operation: &CameraOperationSession,
    control: &CaptureControl,
    rgb: impl FnOnce() -> Result<Frame>,
    ir: impl FnOnce() -> Result<(Frame, IrCaptureStats)>,
) -> Result<SplitPairCapture> {
    capture_split_pair_observed_with(rgb_dev, ir_dev, operation, control, rgb, ir, &|_, _| {})
}

fn capture_split_pair_observed_with(
    rgb_dev: &str,
    ir_dev: &str,
    operation: &CameraOperationSession,
    control: &CaptureControl,
    capture_rgb: impl FnOnce() -> Result<Frame>,
    capture_ir: impl FnOnce() -> Result<(Frame, IrCaptureStats)>,
    observe: &dyn Fn(StreamRole, Duration),
) -> Result<SplitPairCapture> {
    control.check()?;
    let (rgb_binding, _) = split_bindings(rgb_dev, ir_dev, operation)?;
    operation
        .run(|| {
            let started = Instant::now();
            let rgb = capture_rgb();
            observe(StreamRole::Rgb, started.elapsed());
            let rgb = rgb?;
            control.check()?;
            // The first callback has released its stream/device. Check BOTH sides
            // before opening IR; a departure never turns into a fresh path lookup.
            split_bindings(rgb_dev, ir_dev, operation)?;
            validate_frame(&rgb, &rgb_binding, Spectrum::Rgb)?;
            let started = Instant::now();
            let ir = capture_ir();
            observe(StreamRole::Ir, started.elapsed());
            let (ir, stats) = ir?;
            control.check()?;
            validate_split_pair_in_operation(
                rgb_dev,
                ir_dev,
                operation,
                &rgb,
                &ir,
                stats.camera_classified_frames,
            )?;
            control.check()?;
            Ok(SplitPairCapture {
                operation: operation.lease().clone(),
                rgb_dev: rgb_dev.into(),
                ir_dev: ir_dev.into(),
                rgb,
                ir,
                stats,
            })
        })
        .map_err(|error| Error::Hardware(error.to_string()))?
}

/// Bounds for one all-or-nothing split batch (ADR-0032, amendment
/// 2026-10-13, section 8).
#[derive(Clone, Copy, Debug)]
pub struct SplitBatchRequest {
    /// Number of fresh pairs, from one through five.
    pub pairs: usize,
    /// Original operation deadline; capture never extends it.
    pub deadline: Instant,
}

/// A group of complete split pairs captured under one original split
/// operation: one RGB session, released before one IR session starts.
///
/// Privately constructed like [`SplitPairCapture`]; it yields its pairs only
/// as receipts revalidated against the same operation.
pub struct SplitBatchCapture {
    pairs: Vec<SplitPairCapture>,
}

impl SplitBatchCapture {
    /// How many pairs the batch holds.
    #[must_use]
    pub fn len(&self) -> usize {
        self.pairs.len()
    }

    /// Whether the batch holds no pair; a returned batch never does.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.pairs.is_empty()
    }

    /// Consume the batch into its per-pair receipts, each revalidated against
    /// the original operation.
    ///
    /// # Errors
    /// Returns the errors of [`SplitPairCapture::revalidate`] for any pair.
    pub fn into_pair_captures(
        self,
        operation: &CameraOperationSession,
    ) -> Result<Vec<SplitPairCapture>> {
        for pair in &self.pairs {
            pair.revalidate(operation)?;
        }
        Ok(self.pairs)
    }
}

/// Capture `request.pairs` complete split pairs under one original split
/// operation: one RGB session yields that many denoised samples and is
/// released, then one IR session yields that many bursts with statistics.
///
/// Stream setup is paid once per role instead of once per pair, so a group
/// fits the windows a one-shot attempt per PAD vote cannot (ADR-0032,
/// amendment 2026-10-13, section 8). Every pair passes the split frame
/// contract. Failure returns no partial batch and never retries either side.
///
/// # Errors
/// Refuses an invalid count, ordinary or unsupported operations, stale or
/// wrong-role endpoints, cancellation or deadline, capture failure, unordered
/// samples or invalid complete-pair provenance.
pub fn capture_split_batch_observed(
    rgb_dev: &str,
    ir_dev: &str,
    operation: &CameraOperationSession,
    control: &CaptureControl,
    request: SplitBatchRequest,
    observe: &dyn Fn(crate::SequentialBatchPhase, Duration),
) -> Result<SplitBatchCapture> {
    use crate::sequential_batch::{collect_phase, IR_PHASES, RGB_PHASES};
    capture_split_batch_with(
        rgb_dev,
        ir_dev,
        operation,
        control,
        request,
        |checkpoint| {
            let checkpoint = || checkpoint();
            let camera = crate::RgbCamera::open(rgb_dev)?;
            collect_phase(
                request.pairs,
                (
                    || camera.session_with_control(control),
                    |session| session.denoised(),
                ),
                &checkpoint,
                RGB_PHASES,
                observe,
            )
        },
        |checkpoint| {
            let checkpoint = || checkpoint();
            let camera = crate::IrCamera::open(ir_dev)?;
            collect_phase(
                request.pairs,
                (
                    || {
                        camera.session_with_control_and_startup(
                            control,
                            crate::IrSessionStartup::Adaptive,
                        )
                    },
                    |session| session.capture_with_stats(),
                ),
                &checkpoint,
                IR_PHASES,
                observe,
            )
        },
    )
}

/// [`capture_split_batch_observed`] with the two role captures injected; each
/// receives the batch checkpoint (cancellation and deadline).
pub(crate) fn capture_split_batch_with(
    rgb_dev: &str,
    ir_dev: &str,
    operation: &CameraOperationSession,
    control: &CaptureControl,
    request: SplitBatchRequest,
    capture_rgb: impl FnOnce(&dyn Fn() -> Result<()>) -> Result<Vec<Frame>>,
    capture_ir: impl FnOnce(&dyn Fn() -> Result<()>) -> Result<Vec<(Frame, IrCaptureStats)>>,
) -> Result<SplitBatchCapture> {
    if !(1..=5).contains(&request.pairs) {
        return Err(Error::Hardware(
            "split batch requires one through five pairs".into(),
        ));
    }
    control.check()?;
    let (rgb_binding, _) = split_bindings(rgb_dev, ir_dev, operation)?;
    let checkpoint = || -> Result<()> {
        control.check()?;
        if Instant::now() >= request.deadline {
            Err(Error::Hardware("split batch deadline expired".into()))
        } else {
            Ok(())
        }
    };
    operation
        .run(|| {
            checkpoint()?;
            let rgb = capture_rgb(&checkpoint)?;
            checkpoint()?;
            // The RGB owner has released its stream and device. Check BOTH
            // sides before opening IR; a departure never becomes a new lookup.
            split_bindings(rgb_dev, ir_dev, operation)?;
            for frame in &rgb {
                validate_frame(frame, &rgb_binding, Spectrum::Rgb)?;
            }
            let ir = capture_ir(&checkpoint)?;
            checkpoint()?;
            if rgb.len() != request.pairs || ir.len() != request.pairs {
                return Err(Error::Hardware("split batch is incomplete".into()));
            }
            if rgb
                .last()
                .zip(ir.first())
                .is_some_and(|(r, (i, _))| r.captured.end > i.captured.start)
            {
                return Err(Error::Hardware(
                    "split batch phases are not RGB then IR".into(),
                ));
            }
            let mut pairs = Vec::with_capacity(request.pairs);
            let mut previous: Option<(crate::CaptureWindow, crate::CaptureWindow)> = None;
            for (rgb, (ir, stats)) in rgb.into_iter().zip(ir) {
                checkpoint()?;
                if previous
                    .is_some_and(|(r, i)| r.end >= rgb.captured.start || i.end >= ir.captured.start)
                {
                    return Err(Error::Hardware(
                        "split batch samples are not ordered and disjoint".into(),
                    ));
                }
                validate_split_pair_in_operation(
                    rgb_dev,
                    ir_dev,
                    operation,
                    &rgb,
                    &ir,
                    stats.camera_classified_frames,
                )?;
                previous = Some((rgb.captured, ir.captured));
                pairs.push(SplitPairCapture {
                    operation: operation.lease().clone(),
                    rgb_dev: rgb_dev.into(),
                    ir_dev: ir_dev.into(),
                    rgb,
                    ir,
                    stats,
                });
            }
            checkpoint()?;
            Ok(SplitBatchCapture { pairs })
        })
        .map_err(|error| Error::Hardware(error.to_string()))?
}

/// Validate both frames against the same retained split capability.
///
/// This checks runtime bindings, geometry, spectrum, immutable capture windows,
/// delivery/continuity and active-IR evidence. It does not authorize a concurrent
/// schedule or change the downstream stale-RGB pairing budget.
///
/// `ir_classified` is how many of the IR burst's frames the camera's own
/// illumination records classified (`IrCaptureStats::camera_classified_frames`).
///
/// # Errors
/// Refuses an unsupported/stale operation, wrong endpoint/role/incarnation,
/// malformed frame, unhealthy delivery, unknown illumination or reversed windows.
/// Unknown illumination on a burst none of whose frames a record classified is
/// [`Error::IrIlluminationUnreported`]; every other refusal keeps its type.
fn validate_split_pair_in_operation(
    rgb_dev: &str,
    ir_dev: &str,
    operation: &CameraOperationSession,
    rgb: &Frame,
    ir: &Frame,
    ir_classified: usize,
) -> Result<()> {
    let (rgb_binding, ir_binding) = split_bindings(rgb_dev, ir_dev, operation)?;
    validate_frame(rgb, &rgb_binding, Spectrum::Rgb)?;
    validate_frame(ir, &ir_binding, Spectrum::Ir)?;
    if rgb.captured.end > ir.captured.start {
        return Err(Error::Hardware(
            "split capture windows are not RGB then IR".into(),
        ));
    }
    match ir.provenance().illumination() {
        IlluminationProvenance::ActiveIr => {}
        // No record named any frame of the burst: typed, so the attempt loop
        // can capture again within the window (#1063). An aggregate that is
        // unknown although records classified its frames (an ambient
        // subtraction over unsuitable states, mixed contributors) is not that
        // case. The check is unchanged.
        IlluminationProvenance::Unknown if ir_classified == 0 => {
            return Err(Error::IrIlluminationUnreported(
                "split IR frame lacks active illumination provenance".into(),
            ));
        }
        IlluminationProvenance::Unknown | IlluminationProvenance::Ambient => {
            return Err(Error::Hardware(
                "split IR frame lacks active illumination provenance".into(),
            ));
        }
    }
    operation
        .lease()
        .validate()
        .map_err(|error| Error::Hardware(error.to_string()))
}

fn split_bindings(
    rgb_dev: &str,
    ir_dev: &str,
    operation: &CameraOperationSession,
) -> Result<(FrameBinding, FrameBinding)> {
    // The same admission rule as split acquisition, checked again on every
    // capture and receipt check: Capture is never admitted, and a trust kind
    // only while `split_trust_admitted` admits it.
    let kind = operation.lease().operation();
    if !operation.lease().is_split_pair()
        || !(matches!(
            kind,
            CameraOperationKind::Diagnostics
                | CameraOperationKind::Setup
                | CameraOperationKind::Preview
        ) || split_trust_admitted(kind))
    {
        return Err(Error::Hardware(
            "split capture requires a supported two-device operation".into(),
        ));
    }
    let binding = |path, role| {
        operation
            .lease()
            .frame_binding(path, role)
            .map_err(|error| Error::Hardware(error.to_string()))
    };
    Ok((
        binding(rgb_dev, StreamRole::Rgb)?,
        binding(ir_dev, StreamRole::Ir)?,
    ))
}

fn validate_frame(frame: &Frame, binding: &FrameBinding, spectrum: Spectrum) -> Result<()> {
    match frame_contract_fault(frame, binding, spectrum) {
        None => Ok(()),
        // The first failed condition by name (#1144): one message for nine
        // conditions sent the reporter to an instrumented build to learn
        // which. The prefix is unchanged for anyone matching on it.
        Some(fault) => Err(Error::Hardware(format!(
            "split frame does not match its retained capture contract ({}: {fault})",
            if spectrum == Spectrum::Rgb {
                "RGB"
            } else {
                "IR"
            }
        ))),
    }
}

/// The first condition of the split frame contract `frame` fails, by name,
/// in the order the contract checks them; `None` when it holds.
fn frame_contract_fault(
    frame: &Frame,
    binding: &FrameBinding,
    spectrum: Spectrum,
) -> Option<String> {
    let provenance = frame.provenance();
    let channels = if spectrum == Spectrum::Rgb { 3_u64 } else { 1 };
    let length = u64::from(frame.width)
        .checked_mul(u64::from(frame.height))
        .and_then(|pixels| pixels.checked_mul(channels))
        .and_then(|bytes| usize::try_from(bytes).ok());
    let window = provenance.capture_window();
    if provenance.binding() != binding {
        Some("binding".into())
    } else if frame.spectrum != spectrum {
        Some("spectrum".into())
    } else if (frame.width, frame.height)
        != (provenance.format().width(), provenance.format().height())
    {
        Some("geometry".into())
    } else if length != Some(frame.data.len()) {
        Some("data length".into())
    } else if frame.captured.start != window.start
        || frame.captured.end != window.end
        || window.start > window.end
    {
        Some("capture window".into())
    } else if !provenance.rate_evidence().meets_floor() {
        Some("delivered rate below floor".into())
    } else {
        provenance
            .continuity_fault()
            .map(|fault| format!("continuity, {fault}"))
    }
}

#[cfg(all(test, feature = "test-support"))]
#[path = "split_capture_tests.rs"]
mod tests;

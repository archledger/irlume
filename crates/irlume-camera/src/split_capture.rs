// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright the irlume contributors.

//! Sequential two-device capture under one retained operation capability.

use crate::{
    contracts::{IlluminationProvenance, StreamRole},
    frame_provenance::FrameBinding,
    lease::{CameraOperationKind, CameraOperationSession},
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
            validate_split_pair_in_operation(rgb_dev, ir_dev, operation, &rgb, &ir)?;
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

/// Validate both frames against the same retained split capability.
///
/// This checks runtime bindings, geometry, spectrum, immutable capture windows,
/// delivery/continuity and active-IR evidence. It does not authorize a concurrent
/// schedule or change the downstream stale-RGB pairing budget.
///
/// # Errors
/// Refuses an unsupported/stale operation, wrong endpoint/role/incarnation,
/// malformed frame, unhealthy delivery, unknown illumination or reversed windows.
fn validate_split_pair_in_operation(
    rgb_dev: &str,
    ir_dev: &str,
    operation: &CameraOperationSession,
    rgb: &Frame,
    ir: &Frame,
) -> Result<()> {
    let (rgb_binding, ir_binding) = split_bindings(rgb_dev, ir_dev, operation)?;
    validate_frame(rgb, &rgb_binding, Spectrum::Rgb)?;
    validate_frame(ir, &ir_binding, Spectrum::Ir)?;
    if rgb.captured.end > ir.captured.start {
        return Err(Error::Hardware(
            "split capture windows are not RGB then IR".into(),
        ));
    }
    if ir.provenance().illumination() != IlluminationProvenance::ActiveIr {
        return Err(Error::Hardware(
            "split IR frame lacks active illumination provenance".into(),
        ));
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
    if !operation.lease().is_split_pair()
        || !matches!(
            operation.lease().operation(),
            CameraOperationKind::Diagnostics
                | CameraOperationKind::Setup
                | CameraOperationKind::Preview
        )
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
    let provenance = frame.provenance();
    let channels = if spectrum == Spectrum::Rgb { 3_u64 } else { 1 };
    let length = u64::from(frame.width)
        .checked_mul(u64::from(frame.height))
        .and_then(|pixels| pixels.checked_mul(channels))
        .and_then(|bytes| usize::try_from(bytes).ok());
    let window = provenance.capture_window();
    if provenance.binding() != binding
        || frame.spectrum != spectrum
        || (frame.width, frame.height)
            != (provenance.format().width(), provenance.format().height())
        || length != Some(frame.data.len())
        || frame.captured.start != window.start
        || frame.captured.end != window.end
        || window.start > window.end
        || !provenance.rate_evidence().meets_floor()
        || !provenance.is_continuous()
    {
        return Err(Error::Hardware(
            "split frame does not match its retained capture contract".into(),
        ));
    }
    Ok(())
}

#[cfg(all(test, feature = "test-support"))]
#[path = "split_capture_tests.rs"]
mod tests;

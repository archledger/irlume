// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright the irlume contributors.

//! Owned canonical RGB8 and GREY8 camera evidence.

use std::num::NonZeroU32;

use crate::contracts::{IlluminationProvenance, StreamRole};
use crate::frame_provenance::{
    AggregateFrameProvenance, ContributorSelection, DeliveredRateEvidence, RuntimeFrameProvenance,
    RuntimeProvenanceError,
};
use crate::{CaptureWindow, Frame, IrCaptureStats, Spectrum};

const MAX_CONTRIBUTORS: usize = 64;

/// Why captured pixels cannot enter the canonical evidence boundary.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum EvidenceError {
    InvalidGeometry,
    PayloadLength,
    WrongRole,
    TooFewContributors,
    TooManyContributors,
    InvalidSelection,
    InvalidStatistics,
    InvalidProvenance,
}

impl std::fmt::Display for EvidenceError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Self::InvalidGeometry => "canonical evidence geometry must be nonzero",
            Self::PayloadLength => "canonical evidence payload length disagrees with geometry",
            Self::WrongRole => "canonical evidence role disagrees with its pixel contract",
            Self::TooFewContributors => "canonical evidence has no contributors",
            Self::TooManyContributors => "canonical evidence exceeds 64 contributors",
            Self::InvalidSelection => "canonical evidence selection is out of bounds",
            Self::InvalidStatistics => "canonical IR statistics disagree with contributors",
            Self::InvalidProvenance => "canonical evidence contributors have invalid provenance",
        })
    }
}

impl std::error::Error for EvidenceError {}

impl From<RuntimeProvenanceError> for EvidenceError {
    fn from(error: RuntimeProvenanceError) -> Self {
        match error {
            RuntimeProvenanceError::TooFewContributors => Self::TooFewContributors,
            RuntimeProvenanceError::TooManyContributors => Self::TooManyContributors,
            RuntimeProvenanceError::InvalidSelection
            | RuntimeProvenanceError::EqualSubtractionIndices => Self::InvalidSelection,
            _ => Self::InvalidProvenance,
        }
    }
}

/// How a bounded contributor window produced canonical pixels.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum EvidenceSelection {
    Single,
    Selected {
        index: usize,
    },
    ReducedOverAll,
    Subtracted {
        lit_index: usize,
        ambient_index: usize,
    },
}

/// Complete runtime provenance retained behind a format-neutral manifest API.
pub struct EvidenceManifest {
    provenance: RuntimeFrameProvenance,
    selection: EvidenceSelection,
    contributor_count: usize,
}

impl EvidenceManifest {
    fn new(provenance: RuntimeFrameProvenance) -> Self {
        let (selection, contributor_count) = match &provenance {
            RuntimeFrameProvenance::Single(_) => (EvidenceSelection::Single, 1),
            RuntimeFrameProvenance::Aggregate(aggregate) => {
                let selection = match aggregate.selection() {
                    ContributorSelection::Selected { index } => {
                        EvidenceSelection::Selected { index }
                    }
                    ContributorSelection::ReducedOverAll => EvidenceSelection::ReducedOverAll,
                    ContributorSelection::Subtracted {
                        lit_index,
                        ambient_index,
                    } => EvidenceSelection::Subtracted {
                        lit_index,
                        ambient_index,
                    },
                };
                (selection, aggregate.contributors().len())
            }
        };
        Self {
            provenance,
            selection,
            contributor_count,
        }
    }

    /// Smallest monotonic window containing every pixel contributor.
    #[must_use]
    pub const fn capture_window(&self) -> CaptureWindow {
        self.provenance.capture_window()
    }

    /// Number of validated dequeues retained by this bounded manifest.
    #[must_use]
    pub const fn contributor_count(&self) -> usize {
        self.contributor_count
    }

    /// How the retained contributors influenced the canonical pixels.
    #[must_use]
    pub const fn selection(&self) -> EvidenceSelection {
        self.selection
    }

    /// Delivered-rate evidence attached to the final contributor.
    #[must_use]
    pub fn rate_evidence(&self) -> DeliveredRateEvidence {
        self.provenance.rate_evidence()
    }

    /// Whether every contributor stayed in one continuous stream epoch.
    #[must_use]
    pub fn is_continuous(&self) -> bool {
        self.provenance.is_continuous()
    }

    pub(crate) const fn runtime_provenance(&self) -> &RuntimeFrameProvenance {
        &self.provenance
    }
}

impl std::fmt::Debug for EvidenceManifest {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("EvidenceManifest")
            .field("selection", &self.selection)
            .field("contributor_count", &self.contributor_count)
            .finish_non_exhaustive()
    }
}

/// Owned, validated RGB8 scene evidence before model-specific preprocessing.
///
/// Canonical evidence can only be produced by capture-owned reduction paths.
///
/// ```compile_fail
/// use irlume_camera::{CanonicalRgbEvidence, Frame};
///
/// fn mint_from_mutable_frame(frame: Frame) {
///     let _ = CanonicalRgbEvidence::try_from(frame);
/// }
/// ```
pub struct CanonicalRgbEvidence {
    width: NonZeroU32,
    height: NonZeroU32,
    rgb8: Vec<u8>,
    manifest: EvidenceManifest,
}

impl CanonicalRgbEvidence {
    pub(crate) fn from_temporal_median(mut frames: Vec<Frame>) -> Result<Self, EvidenceError> {
        if frames.is_empty() {
            return Err(EvidenceError::TooFewContributors);
        }
        if frames.len() > MAX_CONTRIBUTORS {
            return Err(EvidenceError::TooManyContributors);
        }
        for frame in &frames {
            validate_frame(frame, Spectrum::Rgb, 3)?;
        }
        if frames.len() == 1 {
            let frame = frames.pop().expect("one validated contributor");
            return Self::from_parts(frame.width, frame.height, frame.data, frame.provenance);
        }

        let width = frames[0].width;
        let height = frames[0].height;
        let payload_len = frames[0].data.len();
        if frames
            .iter()
            .any(|frame| frame.width != width || frame.height != height)
        {
            return Err(EvidenceError::InvalidProvenance);
        }
        let mut rgb8 = vec![0_u8; payload_len];
        let mut column = vec![0_u8; frames.len()];
        for (index, output) in rgb8.iter_mut().enumerate() {
            for (contributor, frame) in frames.iter().enumerate() {
                column[contributor] = frame.data[index];
            }
            column.sort_unstable();
            *output = column[column.len() / 2];
        }
        let contributors = frames
            .into_iter()
            .map(Frame::into_single_provenance)
            .collect::<Result<Vec<_>, _>>()?;
        let provenance = RuntimeFrameProvenance::Aggregate(AggregateFrameProvenance::new(
            contributors,
            ContributorSelection::ReducedOverAll,
        )?);
        Self::from_parts(width, height, rgb8, provenance)
    }

    fn from_parts(
        width: u32,
        height: u32,
        rgb8: Vec<u8>,
        provenance: RuntimeFrameProvenance,
    ) -> Result<Self, EvidenceError> {
        let width = NonZeroU32::new(width).ok_or(EvidenceError::InvalidGeometry)?;
        let height = NonZeroU32::new(height).ok_or(EvidenceError::InvalidGeometry)?;
        validate_payload(width, height, 3, rgb8.len())?;
        if provenance.stream_role() != StreamRole::Rgb {
            return Err(EvidenceError::WrongRole);
        }
        Ok(Self {
            width,
            height,
            rgb8,
            manifest: EvidenceManifest::new(provenance),
        })
    }

    /// Validated RGB8 pixels in row-major, interleaved RGB order.
    #[must_use]
    pub fn pixels(&self) -> &[u8] {
        &self.rgb8
    }

    #[must_use]
    pub const fn dimensions(&self) -> (u32, u32) {
        (self.width.get(), self.height.get())
    }

    #[must_use]
    pub const fn width(&self) -> u32 {
        self.width.get()
    }

    #[must_use]
    pub const fn height(&self) -> u32 {
        self.height.get()
    }

    #[must_use]
    pub const fn capture_window(&self) -> CaptureWindow {
        self.manifest.capture_window()
    }

    #[must_use]
    pub const fn manifest(&self) -> &EvidenceManifest {
        &self.manifest
    }
}

impl std::fmt::Debug for CanonicalRgbEvidence {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CanonicalRgbEvidence")
            .field("width", &self.width)
            .field("height", &self.height)
            .field("pixel_bytes", &self.rgb8.len())
            .field("manifest", &self.manifest)
            .finish()
    }
}

/// Owned, validated GREY8 scene evidence before model-specific preprocessing.
///
/// Canonical evidence can only be produced by capture-owned reduction paths.
///
/// ```compile_fail
/// use irlume_camera::{CanonicalIrEvidence, Frame, IrCaptureStats};
///
/// fn mint_from_mutable_frame(input: (Frame, IrCaptureStats)) {
///     let _ = CanonicalIrEvidence::try_from(input);
/// }
/// ```
pub struct CanonicalIrEvidence {
    width: NonZeroU32,
    height: NonZeroU32,
    grey8: Vec<u8>,
    saturation_source: Option<Vec<u8>>,
    stats: IrCaptureStats,
    manifest: EvidenceManifest,
}

impl CanonicalIrEvidence {
    pub(crate) fn from_burst(
        frames: Vec<Frame>,
        selected_index: usize,
        ambient_index: Option<usize>,
        stats: IrCaptureStats,
    ) -> Result<Self, EvidenceError> {
        if frames.len() < 2 {
            return Err(EvidenceError::TooFewContributors);
        }
        if frames.len() > MAX_CONTRIBUTORS {
            return Err(EvidenceError::TooManyContributors);
        }
        for frame in &frames {
            validate_frame(frame, Spectrum::Ir, 1)?;
        }
        let selected = frames
            .get(selected_index)
            .ok_or(EvidenceError::InvalidSelection)?;
        let width = selected.width;
        let height = selected.height;
        if frames
            .iter()
            .any(|frame| frame.width != width || frame.height != height)
        {
            return Err(EvidenceError::InvalidProvenance);
        }
        validate_ir_statistics(&frames, selected_index, ambient_index, &stats)?;
        let (grey8, saturation_source, selection) = match ambient_index {
            Some(ambient_index) if ambient_index != selected_index => {
                let ambient = frames
                    .get(ambient_index)
                    .ok_or(EvidenceError::InvalidSelection)?;
                let grey8 = crate::ir_probe::subtract(&selected.data, &ambient.data);
                let saturation_source = stats.white_level.map(|_| selected.data.clone());
                (
                    grey8,
                    saturation_source,
                    ContributorSelection::Subtracted {
                        lit_index: selected_index,
                        ambient_index,
                    },
                )
            }
            Some(_) => return Err(EvidenceError::InvalidSelection),
            None => (
                selected.data.clone(),
                None,
                ContributorSelection::Selected {
                    index: selected_index,
                },
            ),
        };
        let contributors = frames
            .into_iter()
            .map(Frame::into_single_provenance)
            .collect::<Result<Vec<_>, _>>()?;
        let provenance = RuntimeFrameProvenance::Aggregate(AggregateFrameProvenance::new(
            contributors,
            selection,
        )?);
        Self::from_parts(width, height, grey8, saturation_source, stats, provenance)
    }

    fn from_parts(
        width: u32,
        height: u32,
        grey8: Vec<u8>,
        saturation_source: Option<Vec<u8>>,
        stats: IrCaptureStats,
        provenance: RuntimeFrameProvenance,
    ) -> Result<Self, EvidenceError> {
        let width = NonZeroU32::new(width).ok_or(EvidenceError::InvalidGeometry)?;
        let height = NonZeroU32::new(height).ok_or(EvidenceError::InvalidGeometry)?;
        validate_payload(width, height, 1, grey8.len())?;
        if let Some(source) = &saturation_source {
            validate_payload(width, height, 1, source.len())?;
        }
        if provenance.stream_role() != StreamRole::Ir {
            return Err(EvidenceError::WrongRole);
        }
        Ok(Self {
            width,
            height,
            grey8,
            saturation_source,
            stats,
            manifest: EvidenceManifest::new(provenance),
        })
    }

    /// Validated GREY8 pixels in row-major order.
    #[must_use]
    pub fn pixels(&self) -> &[u8] {
        &self.grey8
    }

    /// Raw selected pixels used for clipping checks before any subtraction.
    #[must_use]
    pub fn saturation_pixels(&self) -> &[u8] {
        self.saturation_source.as_deref().unwrap_or(&self.grey8)
    }

    #[must_use]
    pub const fn dimensions(&self) -> (u32, u32) {
        (self.width.get(), self.height.get())
    }

    #[must_use]
    pub const fn width(&self) -> u32 {
        self.width.get()
    }

    #[must_use]
    pub const fn height(&self) -> u32 {
        self.height.get()
    }

    #[must_use]
    pub const fn capture_window(&self) -> CaptureWindow {
        self.manifest.capture_window()
    }

    #[must_use]
    pub const fn stats(&self) -> &IrCaptureStats {
        &self.stats
    }

    #[must_use]
    pub const fn manifest(&self) -> &EvidenceManifest {
        &self.manifest
    }

    pub(crate) fn into_frame(self) -> Result<Frame, EvidenceError> {
        Frame::from_provenance(
            self.width.get(),
            self.height.get(),
            Spectrum::Ir,
            self.grey8,
            self.manifest.provenance,
        )
        .map_err(|_| EvidenceError::InvalidProvenance)
    }

    #[cfg(test)]
    pub(crate) fn from_test_frame(
        frame: Frame,
        stats: IrCaptureStats,
    ) -> Result<Self, EvidenceError> {
        validate_frame(&frame, Spectrum::Ir, 1)?;
        Self::from_parts(
            frame.width,
            frame.height,
            frame.data,
            None,
            stats,
            frame.provenance,
        )
    }
}

impl std::fmt::Debug for CanonicalIrEvidence {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CanonicalIrEvidence")
            .field("width", &self.width)
            .field("height", &self.height)
            .field("pixel_bytes", &self.grey8.len())
            .field(
                "saturation_source_bytes",
                &self.saturation_source.as_ref().map(Vec::len),
            )
            .field("manifest", &self.manifest)
            .finish_non_exhaustive()
    }
}

fn validate_frame(
    frame: &Frame,
    expected_spectrum: Spectrum,
    bytes_per_pixel: usize,
) -> Result<(), EvidenceError> {
    let expected_role = match expected_spectrum {
        Spectrum::Rgb => StreamRole::Rgb,
        Spectrum::Ir => StreamRole::Ir,
    };
    if frame.spectrum != expected_spectrum || frame.provenance.stream_role() != expected_role {
        return Err(EvidenceError::WrongRole);
    }
    let format = frame.provenance.format();
    if frame.width != format.width() || frame.height != format.height() {
        return Err(EvidenceError::InvalidProvenance);
    }
    let width = NonZeroU32::new(frame.width).ok_or(EvidenceError::InvalidGeometry)?;
    let height = NonZeroU32::new(frame.height).ok_or(EvidenceError::InvalidGeometry)?;
    validate_payload(width, height, bytes_per_pixel, frame.data.len())
}

fn validate_payload(
    width: NonZeroU32,
    height: NonZeroU32,
    bytes_per_pixel: usize,
    actual: usize,
) -> Result<(), EvidenceError> {
    let expected = usize::try_from(width.get())
        .ok()
        .and_then(|width| {
            usize::try_from(height.get())
                .ok()
                .and_then(|height| width.checked_mul(height))
        })
        .and_then(|pixels| pixels.checked_mul(bytes_per_pixel))
        .ok_or(EvidenceError::PayloadLength)?;
    if actual != expected {
        return Err(EvidenceError::PayloadLength);
    }
    Ok(())
}

fn validate_ir_statistics(
    frames: &[Frame],
    selected_index: usize,
    ambient_index: Option<usize>,
    stats: &IrCaptureStats,
) -> Result<(), EvidenceError> {
    let means: Vec<f64> = frames
        .iter()
        .map(|frame| {
            frame
                .data
                .iter()
                .map(|&pixel| f64::from(pixel))
                .sum::<f64>()
                / frame.data.len() as f64
        })
        .collect();
    let flags: Vec<Option<crate::ir_metadata::Illumination>> = frames
        .iter()
        .map(|frame| match frame.provenance.illumination() {
            IlluminationProvenance::ActiveIr => Some(crate::ir_metadata::Illumination::Lit),
            IlluminationProvenance::Ambient => Some(crate::ir_metadata::Illumination::Dark),
            IlluminationProvenance::Unknown => None,
        })
        .collect();
    let camera_classified_frames = flags.iter().filter(|flag| flag.is_some()).count();
    let camera_lit_frames = flags
        .iter()
        .filter(|flag| matches!(flag, Some(crate::ir_metadata::Illumination::Lit)))
        .count();
    let ambient_observed = camera_lit_frames > 0
        && flags
            .iter()
            .any(|flag| matches!(flag, Some(crate::ir_metadata::Illumination::Dark)));
    let clipped_fracs: Option<Vec<f64>> = stats.white_level.map(|white| {
        frames
            .iter()
            .map(|frame| crate::ir_probe::saturated_fraction(&frame.data, white))
            .collect()
    });
    let expected_selected =
        crate::ir_metadata::best_gate_frame(&means, &flags, clipped_fracs.as_deref())
            .ok_or(EvidenceError::InvalidStatistics)?;
    if selected_index != expected_selected {
        return Err(EvidenceError::InvalidStatistics);
    }
    if let Some(ambient_index) = ambient_index {
        if crate::ir_metadata::ambient_partner(selected_index, &means, &flags)
            != Some(ambient_index)
        {
            return Err(EvidenceError::InvalidStatistics);
        }
    }

    let burst_min = means.iter().copied().fold(f64::INFINITY, f64::min);
    let burst_max = means.iter().copied().fold(f64::NEG_INFINITY, f64::max);
    let (lit_mean, ambient_mean) = if camera_classified_frames == 0 {
        (burst_max, burst_min)
    } else {
        let dark_min = means
            .iter()
            .zip(&flags)
            .filter(|(_, flag)| matches!(flag, Some(crate::ir_metadata::Illumination::Dark)))
            .map(|(mean, _)| *mean)
            .fold(f64::INFINITY, f64::min);
        (
            means[selected_index],
            if dark_min.is_finite() {
                dark_min
            } else {
                burst_min
            },
        )
    };
    let (lit_saturated_frac, ambient_saturated_frac, persistent_saturated_frac) =
        expected_saturation_statistics(frames, &means, &flags, selected_index, stats.white_level);
    if stats.burst_frames != frames.len()
        || stats.camera_classified_frames != camera_classified_frames
        || stats.camera_lit_frames != camera_lit_frames
        || stats.ambient_observed != ambient_observed
        || stats.lit_mean != lit_mean as f32
        || stats.ambient_mean != ambient_mean as f32
        || stats.lit_saturated_frac != lit_saturated_frac
        || stats.ambient_saturated_frac != ambient_saturated_frac
        || stats.persistent_saturated_frac != persistent_saturated_frac
    {
        return Err(EvidenceError::InvalidStatistics);
    }
    Ok(())
}

fn expected_saturation_statistics(
    frames: &[Frame],
    means: &[f64],
    flags: &[Option<crate::ir_metadata::Illumination>],
    selected_index: usize,
    white_level: Option<u8>,
) -> (Option<f32>, Option<f32>, Option<f32>) {
    let Some(white) = white_level else {
        return (None, None, None);
    };
    if !matches!(
        flags.get(selected_index),
        Some(Some(crate::ir_metadata::Illumination::Lit))
    ) {
        return (None, None, None);
    }
    let lit = &frames[selected_index].data;
    let lit_saturated = Some(crate::ir_probe::saturated_fraction(lit, white) as f32);
    let Some(ambient_index) = crate::ir_metadata::ambient_partner(selected_index, means, flags)
    else {
        return (lit_saturated, None, None);
    };
    if !matches!(
        flags.get(ambient_index),
        Some(Some(crate::ir_metadata::Illumination::Dark))
    ) {
        return (lit_saturated, None, None);
    }
    let ambient = &frames[ambient_index].data;
    let ambient_saturated = Some(crate::ir_probe::saturated_fraction(ambient, white) as f32);
    let persistent_saturated = Some(
        lit.iter()
            .zip(ambient)
            .filter(|(lit, ambient)| **lit >= white && **ambient >= white)
            .count() as f32
            / lit.len() as f32,
    );
    (lit_saturated, ambient_saturated, persistent_saturated)
}

#[cfg(test)]
mod tests {
    use super::{CanonicalIrEvidence, CanonicalRgbEvidence, EvidenceError, EvidenceSelection};
    use crate::contracts::{
        CameraGeneration, CameraInstanceId, IlluminationProvenance, StreamRole,
    };
    use crate::frame_provenance::{
        DeliveredRateEvidence, DequeuedBufferFacts, FrameBinding, SequenceTracker, TimestampClock,
        TimestampSource, TimestampTracker, ValidatedFormatIdentity,
    };
    use crate::{checked_single_provenance, Frame, IrCaptureStats, Spectrum};

    struct FixtureStream {
        sequence: SequenceTracker,
        timestamp: TimestampTracker,
        next: u32,
        role: StreamRole,
        spectrum: Spectrum,
        width: u32,
        height: u32,
    }

    impl FixtureStream {
        fn new(spectrum: Spectrum, width: u32, height: u32) -> Self {
            let role = match spectrum {
                Spectrum::Rgb => StreamRole::Rgb,
                Spectrum::Ir => StreamRole::Ir,
            };
            Self {
                sequence: SequenceTracker::new(),
                timestamp: TimestampTracker::new(),
                next: 1,
                role,
                spectrum,
                width,
                height,
            }
        }

        fn frame(&mut self, data: Vec<u8>, illumination: IlluminationProvenance) -> Frame {
            let raw = self.next;
            self.next += 1;
            let micros = i64::from(raw) * 1_000;
            let metadata = v4l::buffer::Metadata {
                bytesused: u32::try_from(data.len()).expect("fixture payload fits u32"),
                sequence: raw,
                timestamp: v4l::timestamp::Timestamp::new(0, micros),
                flags: v4l::buffer::Flags::TIMESTAMP_MONOTONIC,
                ..Default::default()
            };
            let facts = DequeuedBufferFacts::from_v4l(&metadata, data.len())
                .expect("fixture dequeue facts");
            let sequence = self.sequence.observe(raw).expect("fixture sequence");
            let timestamp = self
                .timestamp
                .observe(
                    micros,
                    TimestampClock::Monotonic,
                    TimestampSource::EndOfFrame,
                )
                .expect("fixture timestamp");
            let binding = FrameBinding::new(
                CameraInstanceId::new("33333333333333333333333333333333")
                    .expect("fixture identity"),
                CameraGeneration::INITIAL,
                self.role,
            );
            let bytes_per_pixel = if self.spectrum == Spectrum::Rgb { 3 } else { 1 };
            let mut format = v4l::Format::new(
                self.width,
                self.height,
                v4l::FourCC::new(if self.spectrum == Spectrum::Rgb {
                    b"RGB3"
                } else {
                    b"GREY"
                }),
            );
            format.stride = self.width.saturating_mul(bytes_per_pixel);
            format.size = format.stride.saturating_mul(self.height);
            let format = ValidatedFormatIdentity::from_stable_format(&format);
            let provenance = checked_single_provenance(
                binding,
                format,
                facts,
                sequence,
                timestamp,
                std::time::Instant::now(),
                illumination,
                DeliveredRateEvidence::new(
                    self.role,
                    (1, 15),
                    (1, 15),
                    (15, 1),
                    98,
                    30,
                    2_000_000,
                    (15, 1),
                    true,
                    &sequence,
                    &timestamp,
                ),
            )
            .expect("fixture provenance");
            Frame::from_provenance(self.width, self.height, self.spectrum, data, provenance)
                .expect("fixture frame")
        }
    }

    fn ir_stats(white_level: Option<u8>) -> IrCaptureStats {
        IrCaptureStats {
            lit_mean: 100.0,
            ambient_mean: 10.0,
            ambient_observed: true,
            burst_frames: 2,
            camera_classified_frames: 2,
            camera_lit_frames: 1,
            white_level,
            lit_saturated_frac: Some(0.25),
            ambient_saturated_frac: Some(0.0),
            persistent_saturated_frac: Some(0.0),
        }
    }

    fn coherent_ir_stats(
        lit_mean: f32,
        ambient_mean: f32,
        burst_frames: usize,
        white_level: Option<u8>,
        lit_saturated_frac: Option<f32>,
    ) -> IrCaptureStats {
        IrCaptureStats {
            lit_mean,
            ambient_mean,
            ambient_observed: true,
            burst_frames,
            camera_classified_frames: burst_frames,
            camera_lit_frames: 1,
            white_level,
            lit_saturated_frac,
            ambient_saturated_frac: white_level.map(|_| 0.0),
            persistent_saturated_frac: white_level.map(|_| 0.0),
        }
    }

    #[test]
    fn canonical_rgb_rejects_short_zero_geometry_and_wrong_role_frames() {
        let mut short = FixtureStream::new(Spectrum::Rgb, 4, 4);
        assert_eq!(
            CanonicalRgbEvidence::from_temporal_median(vec![
                short.frame(vec![0; 47], IlluminationProvenance::Unknown)
            ])
            .unwrap_err(),
            EvidenceError::PayloadLength
        );

        let mut zero = FixtureStream::new(Spectrum::Rgb, 0, 4);
        assert_eq!(
            CanonicalRgbEvidence::from_temporal_median(vec![
                zero.frame(vec![], IlluminationProvenance::Unknown)
            ])
            .unwrap_err(),
            EvidenceError::InvalidGeometry
        );

        let mut ir = FixtureStream::new(Spectrum::Ir, 4, 4);
        assert_eq!(
            CanonicalRgbEvidence::from_temporal_median(vec![
                ir.frame(vec![0; 16], IlluminationProvenance::ActiveIr)
            ])
            .unwrap_err(),
            EvidenceError::WrongRole
        );
    }

    #[test]
    fn canonical_ir_rejects_short_zero_geometry_and_wrong_role_frames() {
        let mut short = FixtureStream::new(Spectrum::Ir, 4, 4);
        assert_eq!(
            CanonicalIrEvidence::from_burst(
                vec![
                    short.frame(vec![0; 15], IlluminationProvenance::ActiveIr),
                    short.frame(vec![0; 16], IlluminationProvenance::Ambient),
                ],
                0,
                None,
                ir_stats(Some(255)),
            )
            .unwrap_err(),
            EvidenceError::PayloadLength
        );

        let mut zero = FixtureStream::new(Spectrum::Ir, 4, 0);
        assert_eq!(
            CanonicalIrEvidence::from_burst(
                vec![
                    zero.frame(vec![], IlluminationProvenance::ActiveIr),
                    zero.frame(vec![], IlluminationProvenance::Ambient),
                ],
                0,
                None,
                ir_stats(Some(255)),
            )
            .unwrap_err(),
            EvidenceError::InvalidGeometry
        );

        let mut rgb = FixtureStream::new(Spectrum::Rgb, 2, 2);
        assert_eq!(
            CanonicalIrEvidence::from_burst(
                vec![
                    rgb.frame(vec![0; 12], IlluminationProvenance::Unknown),
                    rgb.frame(vec![0; 12], IlluminationProvenance::Unknown),
                ],
                0,
                None,
                ir_stats(Some(255)),
            )
            .unwrap_err(),
            EvidenceError::WrongRole
        );
    }

    #[test]
    fn rgb_temporal_median_is_byte_exact_and_manifest_is_bounded() {
        let mut stream = FixtureStream::new(Spectrum::Rgb, 2, 1);
        let frames = [
            [1, 90, 5, 200, 9, 7],
            [8, 40, 4, 100, 3, 9],
            [4, 70, 3, 150, 8, 6],
            [2, 60, 2, 250, 7, 8],
            [6, 50, 1, 50, 5, 5],
        ]
        .into_iter()
        .map(|pixels| stream.frame(pixels.to_vec(), IlluminationProvenance::Unknown))
        .collect();

        let evidence =
            CanonicalRgbEvidence::from_temporal_median(frames).expect("valid five-frame median");

        assert_eq!(evidence.pixels(), &[4, 60, 3, 150, 7, 7]);
        assert_eq!(evidence.dimensions(), (2, 1));
        assert_eq!(evidence.manifest().contributor_count(), 5);
        assert_eq!(
            evidence.manifest().selection(),
            EvidenceSelection::ReducedOverAll
        );
        assert!(evidence.capture_window().start <= evidence.capture_window().end);
    }

    #[test]
    fn temporal_median_rejects_more_than_the_bounded_contributor_window() {
        let mut stream = FixtureStream::new(Spectrum::Rgb, 1, 1);
        let frames = (0..65)
            .map(|value| stream.frame(vec![value, value, value], IlluminationProvenance::Unknown))
            .collect();

        assert_eq!(
            CanonicalRgbEvidence::from_temporal_median(frames).unwrap_err(),
            EvidenceError::TooManyContributors
        );
    }

    #[test]
    fn canonical_reduction_rejects_geometry_that_disagrees_with_provenance() {
        let mut stream = FixtureStream::new(Spectrum::Rgb, 2, 1);
        let mut frame = stream.frame(vec![1, 2, 3, 4, 5, 6], IlluminationProvenance::Unknown);
        frame.width = 1;
        frame.data.truncate(3);

        assert_eq!(
            CanonicalRgbEvidence::from_temporal_median(vec![frame]).unwrap_err(),
            EvidenceError::InvalidProvenance
        );

        let mut stream = FixtureStream::new(Spectrum::Ir, 2, 1);
        let mut lit = stream.frame(vec![100, 110], IlluminationProvenance::ActiveIr);
        lit.width = 1;
        lit.data.truncate(1);
        let ambient = stream.frame(vec![10, 20], IlluminationProvenance::Ambient);
        assert_eq!(
            CanonicalIrEvidence::from_burst(vec![lit, ambient], 0, None, ir_stats(None),)
                .unwrap_err(),
            EvidenceError::InvalidProvenance
        );
    }

    #[test]
    fn ir_burst_rejects_contributor_count_statistics_mismatch() {
        let burst = || {
            let mut stream = FixtureStream::new(Spectrum::Ir, 1, 1);
            vec![
                stream.frame(vec![10], IlluminationProvenance::Ambient),
                stream.frame(vec![100], IlluminationProvenance::ActiveIr),
            ]
        };
        let mut stats = coherent_ir_stats(100.0, 10.0, 2, None, None);
        stats.burst_frames = 3;
        assert_eq!(
            CanonicalIrEvidence::from_burst(burst(), 1, None, stats).unwrap_err(),
            EvidenceError::InvalidStatistics
        );

        let mut stats = coherent_ir_stats(100.0, 10.0, 2, None, None);
        stats.camera_classified_frames = 1;
        assert_eq!(
            CanonicalIrEvidence::from_burst(burst(), 1, None, stats).unwrap_err(),
            EvidenceError::InvalidStatistics
        );

        let mut stats = coherent_ir_stats(100.0, 10.0, 2, None, None);
        stats.camera_lit_frames = 2;
        assert_eq!(
            CanonicalIrEvidence::from_burst(burst(), 1, None, stats).unwrap_err(),
            EvidenceError::InvalidStatistics
        );
    }

    #[test]
    fn ir_burst_rejects_ambient_statistics_mismatch() {
        let burst = || {
            let mut stream = FixtureStream::new(Spectrum::Ir, 1, 1);
            vec![
                stream.frame(vec![10], IlluminationProvenance::Ambient),
                stream.frame(vec![100], IlluminationProvenance::ActiveIr),
            ]
        };
        let mut stats = coherent_ir_stats(100.0, 10.0, 2, None, None);
        stats.ambient_observed = false;
        assert_eq!(
            CanonicalIrEvidence::from_burst(burst(), 1, None, stats).unwrap_err(),
            EvidenceError::InvalidStatistics
        );

        let mut stats = coherent_ir_stats(100.0, 10.0, 2, None, None);
        stats.ambient_mean = 11.0;
        assert_eq!(
            CanonicalIrEvidence::from_burst(burst(), 1, None, stats).unwrap_err(),
            EvidenceError::InvalidStatistics
        );
    }

    #[test]
    fn ir_burst_rejects_selected_and_subtracted_contributor_mismatch() {
        let mut selected_stream = FixtureStream::new(Spectrum::Ir, 1, 1);
        let selected_frames = vec![
            selected_stream.frame(vec![10], IlluminationProvenance::Ambient),
            selected_stream.frame(vec![100], IlluminationProvenance::ActiveIr),
        ];
        let stats = coherent_ir_stats(100.0, 10.0, 2, None, None);
        assert_eq!(
            CanonicalIrEvidence::from_burst(selected_frames, 0, None, stats).unwrap_err(),
            EvidenceError::InvalidStatistics
        );

        let mut subtracted_stream = FixtureStream::new(Spectrum::Ir, 1, 1);
        let subtracted_frames = vec![
            subtracted_stream.frame(vec![10], IlluminationProvenance::Ambient),
            subtracted_stream.frame(vec![100], IlluminationProvenance::ActiveIr),
            subtracted_stream.frame(vec![20], IlluminationProvenance::Ambient),
            subtracted_stream.frame(vec![5], IlluminationProvenance::Ambient),
        ];
        let stats = coherent_ir_stats(100.0, 5.0, 4, None, None);
        assert_eq!(
            CanonicalIrEvidence::from_burst(subtracted_frames, 1, Some(3), stats).unwrap_err(),
            EvidenceError::InvalidStatistics
        );
    }

    #[test]
    fn ir_burst_accepts_statistics_derived_from_its_contributors() {
        let mut stream = FixtureStream::new(Spectrum::Ir, 1, 1);
        let frames = vec![
            stream.frame(vec![10], IlluminationProvenance::Ambient),
            stream.frame(vec![255], IlluminationProvenance::ActiveIr),
        ];
        let stats = coherent_ir_stats(255.0, 10.0, 2, Some(255), Some(1.0));

        let evidence = CanonicalIrEvidence::from_burst(frames, 1, None, stats)
            .expect("coherent burst statistics");

        assert_eq!(evidence.pixels(), &[255]);
        assert_eq!(evidence.stats().burst_frames, 2);
    }

    #[test]
    fn ir_default_selection_preserves_raw_pixels_and_clipping_source() {
        let mut stream = FixtureStream::new(Spectrum::Ir, 2, 2);
        let frames = vec![
            stream.frame(vec![3, 4, 5, 6], IlluminationProvenance::Ambient),
            stream.frame(vec![100, 255, 120, 130], IlluminationProvenance::ActiveIr),
        ];

        let stats = coherent_ir_stats(151.25, 4.5, 2, Some(255), Some(0.25));
        let evidence = CanonicalIrEvidence::from_burst(frames, 1, None, stats)
            .expect("valid selected IR frame");

        assert_eq!(evidence.pixels(), &[100, 255, 120, 130]);
        assert_eq!(evidence.saturation_pixels(), &[100, 255, 120, 130]);
        assert_eq!(evidence.dimensions(), (2, 2));
        assert_eq!(evidence.stats().lit_mean, 151.25);
        assert_eq!(
            evidence.manifest().selection(),
            EvidenceSelection::Selected { index: 1 }
        );
        assert_eq!(evidence.manifest().contributor_count(), 2);
    }

    #[test]
    fn subtracted_ir_owns_lit_and_ambient_contributors_and_preserves_raw_clipping_source() {
        let mut stream = FixtureStream::new(Spectrum::Ir, 2, 2);
        let frames = vec![
            stream.frame(vec![10, 30, 100, 255], IlluminationProvenance::ActiveIr),
            stream.frame(vec![3, 40, 20, 1], IlluminationProvenance::Ambient),
        ];

        let stats = coherent_ir_stats(98.75, 16.0, 2, Some(255), Some(0.25));
        let evidence = CanonicalIrEvidence::from_burst(frames, 0, Some(1), stats)
            .expect("valid subtracted IR evidence");

        assert_eq!(evidence.pixels(), &[7, 0, 80, 254]);
        assert_eq!(evidence.saturation_pixels(), &[10, 30, 100, 255]);
        assert_eq!(
            evidence.manifest().selection(),
            EvidenceSelection::Subtracted {
                lit_index: 0,
                ambient_index: 1,
            }
        );
        assert_eq!(evidence.manifest().contributor_count(), 2);
    }
}

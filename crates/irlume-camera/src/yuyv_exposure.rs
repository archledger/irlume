// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright the irlume contributors.

//! ADR-0031 §4 prerequisite facts for YUYV luma: the reported range of a raw
//! single-planar format and one frame's footroom and chroma. Pure. It yields
//! no ceiling and no attestation, and `clipping_white_level` stays `None` for
//! YUYV.
//!
//! Discriminants always come from the generated `v4l::v4l_sys` constants. No
//! raw value is converted to an enum: unknown and unsupported values stay
//! unresolved and refuse. Nothing here opens a device, logs or keeps state
//! between frames: `yuyv_fd` reads the format from the fd, and the session
//! latch and limited-to-full expansion are later changes.
#![cfg_attr(
    not(test),
    expect(
        dead_code,
        reason = "ADR-0031 §4 pure prerequisite; the frame checks gain a production caller with the session latch"
    )
)]

use crate::frame_provenance::{DequeuedBufferError, PayloadLayout};
use crate::ValidatedDequeueError;
use v4l::v4l_sys;

/// Raw `VIDIOC_G_FMT` facts of a single-planar format, as `yuyv_fd` copies
/// them from the fd.
///
/// Field names follow bindgen's `v4l2_pix_format`, except that `buffer_type`
/// is `v4l2_format.type_`, `fourcc` is `pixelformat` as little-endian bytes
/// and `ycbcr_enc` is taken out of its union; `ext_pix_format_supported`
/// records whether the node
/// advertised `V4L2_CAP_EXT_PIX_FORMAT`. This is an internal transfer value,
/// not `repr(C)` and not a trusted attestation. Range classification consults
/// only `buffer_type`, `fourcc`, `ext_pix_format_supported`, `priv_`,
/// `colorspace`, `ycbcr_enc` and `quantization`; frame inspection adds
/// `width`, `height` and `bytesperline`. `field`, `xfer_func`, `flags` and
/// `sizeimage` are identity only: `yuyv_fd` compares them with the
/// negotiation and at every stream boundary.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct RawYuyvFormat {
    pub(crate) buffer_type: u32,
    pub(crate) width: u32,
    pub(crate) height: u32,
    pub(crate) fourcc: [u8; 4],
    pub(crate) field: u32,
    pub(crate) bytesperline: u32,
    pub(crate) sizeimage: u32,
    pub(crate) colorspace: u32,
    pub(crate) priv_: u32,
    pub(crate) flags: u32,
    pub(crate) ycbcr_enc: u32,
    pub(crate) quantization: u32,
    pub(crate) xfer_func: u32,
    pub(crate) ext_pix_format_supported: bool,
}

/// The nominal range a raw format reports. `Limited` is the reported
/// quantization only, never a ceiling: xvYCC is limited range that carries
/// values outside it. The effective encoding is a recognized, non-default
/// `v4l2_ycbcr_encoding` discriminant.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum ReportedRange {
    Limited { effective_encoding: u32 },
    Full { effective_encoding: u32 },
    Unresolved { reason: RangeUnresolved },
}

/// Why a raw format has no reported range inside the supported domain.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum RangeUnresolved {
    /// Not `V4L2_BUF_TYPE_VIDEO_CAPTURE`.
    WrongType,
    /// Not YUYV.
    WrongFormat,
    /// The node does not advertise `V4L2_CAP_EXT_PIX_FORMAT`, or `priv` is not
    /// `V4L2_PIX_FMT_PRIV_MAGIC`, so the extended fields are undefined.
    ExtendedFieldsUnavailable,
    /// `V4L2_COLORSPACE_DEFAULT`: no format field resolves it, and the frame
    /// size is not used to guess.
    UnresolvedColorspaceDefault,
    /// The deprecated BT878 colorspace, or RAW.
    UnsupportedColorspace,
    /// A colorspace value this build does not know.
    UnknownColorspace,
    /// SYCC, `BT2020_CONST_LUM` or an HSV encoding.
    UnsupportedEncoding,
    /// An encoding value this build does not know.
    UnknownEncoding,
    /// A quantization value this build does not know.
    UnknownQuantization,
}

/// Reported metadata that the ADR-0031 §4 range condition accepts: nominal
/// limited range in the supported domain, without extended gamut or JPEG.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct EligibleLimited {
    pub(crate) effective_encoding: u32,
}

/// Why reported metadata fails the ADR-0031 §4 range condition.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum MetadataRefusal {
    Unresolved(RangeUnresolved),
    FullRange,
    /// XV601 or XV709, under either quantization: limited range that allows
    /// values outside it, so 235 is not its ceiling.
    ExtendedGamut,
    /// Explicit limited range with the JPEG colorspace, which `videodev2.h`
    /// defines as full range.
    JpegColorspace,
}

/// A pixel counts toward footroom when its raw luma is below this (strict).
pub(crate) const FOOTROOM_LUMA_FLOOR: u8 = 15;
/// One low pixel is allowed per this many pixels: more than 0.5% fails.
pub(crate) const FOOTROOM_PIXELS_PER_ALLOWED_LOW: usize = 200;
/// The widest combined U and V span a flat frame may have. Preliminary and
/// uncalibrated (ADR-0031, Amendment 2026-10-06).
pub(crate) const MAX_COMBINED_CHROMA_SPAN: u8 = 2;

/// Footroom and chroma facts of one validated YUYV frame. Only
/// `inspect_yuyv_frame` builds one, so its counts always describe a whole
/// image of at least one macropixel.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct YuyvFrameFacts {
    pixels: usize,
    below_15: usize,
    raw_luma_sum: u64,
    u_min: u8,
    u_max: u8,
    v_min: u8,
    v_max: u8,
}

impl YuyvFrameFacts {
    /// Pixels in the image, two per macropixel.
    pub(crate) const fn pixels(&self) -> usize {
        self.pixels
    }

    /// Pixels whose raw luma is below `FOOTROOM_LUMA_FLOOR`.
    pub(crate) const fn below_15(&self) -> usize {
        self.below_15
    }

    /// Sum of every raw luma byte in the image.
    pub(crate) const fn raw_luma_sum(&self) -> u64 {
        self.raw_luma_sum
    }

    pub(crate) const fn u_min(&self) -> u8 {
        self.u_min
    }

    pub(crate) const fn u_max(&self) -> u8 {
        self.u_max
    }

    pub(crate) const fn v_min(&self) -> u8 {
        self.v_min
    }

    pub(crate) const fn v_max(&self) -> u8 {
        self.v_max
    }

    /// The span of the U and V bytes pooled together:
    /// `max(u_max, v_max) - min(u_min, v_min)`.
    pub(crate) const fn combined_chroma_span(&self) -> u8 {
        let high = if self.u_max > self.v_max {
            self.u_max
        } else {
            self.v_max
        };
        let low = if self.u_min < self.v_min {
            self.u_min
        } else {
            self.v_min
        };
        high.abs_diff(low)
    }

    /// More than 0.5% of the pixels have raw luma below 15, in integers
    /// `below_15 > pixels / 200`.
    pub(crate) const fn footroom_violated(&self) -> bool {
        self.below_15 > self.pixels / FOOTROOM_PIXELS_PER_ALLOWED_LOW
    }

    /// The pooled chroma span is at most `MAX_COMBINED_CHROMA_SPAN`. Judged
    /// within this frame only, with no test for closeness to 128.
    pub(crate) const fn chroma_flat(&self) -> bool {
        self.combined_chroma_span() <= MAX_COMBINED_CHROMA_SPAN
    }
}

/// Why one dequeued buffer yields no YUYV frame facts.
#[derive(Debug)]
pub(crate) enum YuyvFrameError {
    /// Not a single-planar capture YUYV format; no byte was read.
    NotYuyv,
    /// The existing tight-layout refusal.
    Layout(DequeuedBufferError),
    /// The existing dequeue boundary refusal.
    Dequeue(ValidatedDequeueError),
    /// The raw luma sum overflowed `u64`.
    LumaSumOverflow,
}

/// What the open file descriptor proved about the §1 attestation. There is no
/// proving variant: `yuyv_fd::FormatEvidence` is that proof, and the change
/// that gives YUYV a ceiling joins it with the session latch and the burst's
/// emitter alternation.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum FdAttestation {
    Absent,
    Refused,
}

/// The combined §4 prerequisite verdict. It is always a refusal, because
/// `FdAttestation` cannot prove the first condition; the
/// remaining fields say which other conditions also fail.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct PrerequisiteRefusal {
    pub(crate) attestation: FdAttestation,
    pub(crate) metadata: Option<MetadataRefusal>,
    pub(crate) footroom_violated: bool,
    pub(crate) chroma_not_flat: bool,
}

const YUYV: [u8; 4] = *b"YUYV";

/// The nominal range `raw` reports, or why it has none in the supported
/// domain.
pub(crate) fn classify_reported_range(raw: &RawYuyvFormat) -> ReportedRange {
    match resolve_range(raw) {
        Ok(range) => range,
        Err(reason) => ReportedRange::Unresolved { reason },
    }
}

/// Type, format, extended-field validity, colorspace, encoding and
/// quantization, in that order; the first failure wins.
fn resolve_range(raw: &RawYuyvFormat) -> Result<ReportedRange, RangeUnresolved> {
    if raw.buffer_type != v4l_sys::v4l2_buf_type_V4L2_BUF_TYPE_VIDEO_CAPTURE {
        return Err(RangeUnresolved::WrongType);
    }
    if raw.fourcc != YUYV {
        return Err(RangeUnresolved::WrongFormat);
    }
    if !raw.ext_pix_format_supported || raw.priv_ != v4l_sys::V4L2_PIX_FMT_PRIV_MAGIC {
        return Err(RangeUnresolved::ExtendedFieldsUnavailable);
    }
    let default_encoding = colorspace_default_encoding(raw.colorspace)?;
    let effective_encoding = effective_encoding(raw.ycbcr_enc, default_encoding)?;
    match raw.quantization {
        v4l_sys::v4l2_quantization_V4L2_QUANTIZATION_LIM_RANGE => {
            Ok(ReportedRange::Limited { effective_encoding })
        }
        v4l_sys::v4l2_quantization_V4L2_QUANTIZATION_FULL_RANGE => {
            Ok(ReportedRange::Full { effective_encoding })
        }
        // `V4L2_MAP_QUANTIZATION_DEFAULT` for Y'CbCr: full range for the JPEG
        // colorspace, limited otherwise. It ignores the encoding.
        v4l_sys::v4l2_quantization_V4L2_QUANTIZATION_DEFAULT
            if raw.colorspace == v4l_sys::v4l2_colorspace_V4L2_COLORSPACE_JPEG =>
        {
            Ok(ReportedRange::Full { effective_encoding })
        }
        v4l_sys::v4l2_quantization_V4L2_QUANTIZATION_DEFAULT => {
            Ok(ReportedRange::Limited { effective_encoding })
        }
        _ => Err(RangeUnresolved::UnknownQuantization),
    }
}

/// The supported colorspace domain, each member answered with the encoding
/// `V4L2_MAP_YCBCR_ENC_DEFAULT` gives it. Every other value is unresolved.
fn colorspace_default_encoding(colorspace: u32) -> Result<u32, RangeUnresolved> {
    match colorspace {
        v4l_sys::v4l2_colorspace_V4L2_COLORSPACE_REC709
        | v4l_sys::v4l2_colorspace_V4L2_COLORSPACE_DCI_P3 => {
            Ok(v4l_sys::v4l2_ycbcr_encoding_V4L2_YCBCR_ENC_709)
        }
        v4l_sys::v4l2_colorspace_V4L2_COLORSPACE_BT2020 => {
            Ok(v4l_sys::v4l2_ycbcr_encoding_V4L2_YCBCR_ENC_BT2020)
        }
        v4l_sys::v4l2_colorspace_V4L2_COLORSPACE_SMPTE240M => {
            Ok(v4l_sys::v4l2_ycbcr_encoding_V4L2_YCBCR_ENC_SMPTE240M)
        }
        v4l_sys::v4l2_colorspace_V4L2_COLORSPACE_SMPTE170M
        | v4l_sys::v4l2_colorspace_V4L2_COLORSPACE_470_SYSTEM_M
        | v4l_sys::v4l2_colorspace_V4L2_COLORSPACE_470_SYSTEM_BG
        | v4l_sys::v4l2_colorspace_V4L2_COLORSPACE_SRGB
        | v4l_sys::v4l2_colorspace_V4L2_COLORSPACE_OPRGB
        | v4l_sys::v4l2_colorspace_V4L2_COLORSPACE_JPEG => {
            Ok(v4l_sys::v4l2_ycbcr_encoding_V4L2_YCBCR_ENC_601)
        }
        v4l_sys::v4l2_colorspace_V4L2_COLORSPACE_DEFAULT => {
            Err(RangeUnresolved::UnresolvedColorspaceDefault)
        }
        v4l_sys::v4l2_colorspace_V4L2_COLORSPACE_BT878
        | v4l_sys::v4l2_colorspace_V4L2_COLORSPACE_RAW => {
            Err(RangeUnresolved::UnsupportedColorspace)
        }
        _ => Err(RangeUnresolved::UnknownColorspace),
    }
}

/// The encoding in the supported domain, with DEFAULT resolved to the
/// colorspace's `default_encoding`.
fn effective_encoding(ycbcr_enc: u32, default_encoding: u32) -> Result<u32, RangeUnresolved> {
    match ycbcr_enc {
        v4l_sys::v4l2_ycbcr_encoding_V4L2_YCBCR_ENC_DEFAULT => Ok(default_encoding),
        v4l_sys::v4l2_ycbcr_encoding_V4L2_YCBCR_ENC_601
        | v4l_sys::v4l2_ycbcr_encoding_V4L2_YCBCR_ENC_709
        | v4l_sys::v4l2_ycbcr_encoding_V4L2_YCBCR_ENC_XV601
        | v4l_sys::v4l2_ycbcr_encoding_V4L2_YCBCR_ENC_XV709
        | v4l_sys::v4l2_ycbcr_encoding_V4L2_YCBCR_ENC_BT2020
        | v4l_sys::v4l2_ycbcr_encoding_V4L2_YCBCR_ENC_SMPTE240M => Ok(ycbcr_enc),
        v4l_sys::v4l2_ycbcr_encoding_V4L2_YCBCR_ENC_SYCC
        | v4l_sys::v4l2_ycbcr_encoding_V4L2_YCBCR_ENC_BT2020_CONST_LUM
        | v4l_sys::v4l2_hsv_encoding_V4L2_HSV_ENC_180
        | v4l_sys::v4l2_hsv_encoding_V4L2_HSV_ENC_256 => Err(RangeUnresolved::UnsupportedEncoding),
        _ => Err(RangeUnresolved::UnknownEncoding),
    }
}

/// Whether `raw` meets the ADR-0031 §4 range condition.
///
/// # Errors
///
/// Returns the `MetadataRefusal` for an unresolved, full-range, extended-gamut
/// or limited-range JPEG format.
pub(crate) fn limited_range_eligibility(
    raw: &RawYuyvFormat,
) -> Result<EligibleLimited, MetadataRefusal> {
    match classify_reported_range(raw) {
        ReportedRange::Unresolved { reason } => Err(MetadataRefusal::Unresolved(reason)),
        ReportedRange::Full { .. } => Err(MetadataRefusal::FullRange),
        ReportedRange::Limited {
            effective_encoding:
                v4l_sys::v4l2_ycbcr_encoding_V4L2_YCBCR_ENC_XV601
                | v4l_sys::v4l2_ycbcr_encoding_V4L2_YCBCR_ENC_XV709,
        } => Err(MetadataRefusal::ExtendedGamut),
        ReportedRange::Limited { .. }
            if raw.colorspace == v4l_sys::v4l2_colorspace_V4L2_COLORSPACE_JPEG =>
        {
            Err(MetadataRefusal::JpegColorspace)
        }
        ReportedRange::Limited { effective_encoding } => Ok(EligibleLimited { effective_encoding }),
    }
}

/// Footroom and chroma facts of one dequeued YUYV buffer, read only within the
/// image the tight layout defines.
///
/// # Errors
///
/// Returns `YuyvFrameError::NotYuyv` before reading any byte when `raw` is not
/// a single-planar capture YUYV format, the existing layout and dequeue
/// refusals unchanged, and `YuyvFrameError::LumaSumOverflow` if the raw luma
/// sum overflows.
pub(crate) fn inspect_yuyv_frame(
    raw: &RawYuyvFormat,
    mapped: &[u8],
    metadata: &v4l::buffer::Metadata,
) -> Result<YuyvFrameFacts, YuyvFrameError> {
    if raw.buffer_type != v4l_sys::v4l2_buf_type_V4L2_BUF_TYPE_VIDEO_CAPTURE || raw.fourcc != YUYV {
        return Err(YuyvFrameError::NotYuyv);
    }
    let layout = PayloadLayout::new(YUYV, raw.width, raw.height, raw.bytesperline)
        .map_err(YuyvFrameError::Layout)?;
    let (payload, _) =
        crate::validate_dequeued(mapped, metadata, layout).map_err(YuyvFrameError::Dequeue)?;
    // `validate_dequeued` already refused a payload shorter than the image;
    // this keeps the slice free of a panic all the same.
    let Some(image) = payload.get(..layout.image_bytes()) else {
        return Err(YuyvFrameError::Dequeue(ValidatedDequeueError::Facts(
            DequeuedBufferError::PayloadTooShort {
                bytes_used: payload.len(),
                minimum: layout.image_bytes(),
            },
        )));
    };
    let mut below_15 = 0_usize;
    let mut raw_luma_sum = 0_u64;
    let (mut u_min, mut u_max) = (u8::MAX, u8::MIN);
    let (mut v_min, mut v_max) = (u8::MAX, u8::MIN);
    for macropixel in image.chunks_exact(4) {
        // Always four bytes: Y0 U Y1 V.
        if let &[y0, u, y1, v] = macropixel {
            below_15 +=
                usize::from(y0 < FOOTROOM_LUMA_FLOOR) + usize::from(y1 < FOOTROOM_LUMA_FLOOR);
            raw_luma_sum = raw_luma_sum
                .checked_add(u64::from(y0) + u64::from(y1))
                .ok_or(YuyvFrameError::LumaSumOverflow)?;
            u_min = u_min.min(u);
            u_max = u_max.max(u);
            v_min = v_min.min(v);
            v_max = v_max.max(v);
        }
    }
    Ok(YuyvFrameFacts {
        pixels: image.len() / 2,
        below_15,
        raw_luma_sum,
        u_min,
        u_max,
        v_min,
        v_max,
    })
}

/// The combined §4 prerequisite verdict for one format and frame. Metadata and
/// content never stand in for the fd attestation, so it always refuses here.
pub(crate) fn exposure_prerequisite(
    attestation: FdAttestation,
    raw: &RawYuyvFormat,
    facts: &YuyvFrameFacts,
) -> PrerequisiteRefusal {
    PrerequisiteRefusal {
        attestation,
        metadata: limited_range_eligibility(raw).err(),
        footroom_violated: facts.footroom_violated(),
        chroma_not_flat: !facts.chroma_flat(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use v4l::buffer::{Flags, Metadata};
    use v4l::format::Quantization;

    const CAPTURE: u32 = v4l::v4l_sys::v4l2_buf_type_V4L2_BUF_TYPE_VIDEO_CAPTURE;
    const CAPTURE_MPLANE: u32 = v4l::v4l_sys::v4l2_buf_type_V4L2_BUF_TYPE_VIDEO_CAPTURE_MPLANE;
    const OUTPUT: u32 = v4l::v4l_sys::v4l2_buf_type_V4L2_BUF_TYPE_VIDEO_OUTPUT;

    const CS_DEFAULT: u32 = v4l::v4l_sys::v4l2_colorspace_V4L2_COLORSPACE_DEFAULT;
    const SMPTE170M: u32 = v4l::v4l_sys::v4l2_colorspace_V4L2_COLORSPACE_SMPTE170M;
    const CS_470_SYSTEM_M: u32 = v4l::v4l_sys::v4l2_colorspace_V4L2_COLORSPACE_470_SYSTEM_M;
    const CS_470_SYSTEM_BG: u32 = v4l::v4l_sys::v4l2_colorspace_V4L2_COLORSPACE_470_SYSTEM_BG;
    const SRGB: u32 = v4l::v4l_sys::v4l2_colorspace_V4L2_COLORSPACE_SRGB;
    const OPRGB: u32 = v4l::v4l_sys::v4l2_colorspace_V4L2_COLORSPACE_OPRGB;
    const JPEG: u32 = v4l::v4l_sys::v4l2_colorspace_V4L2_COLORSPACE_JPEG;
    const REC709: u32 = v4l::v4l_sys::v4l2_colorspace_V4L2_COLORSPACE_REC709;
    const DCI_P3: u32 = v4l::v4l_sys::v4l2_colorspace_V4L2_COLORSPACE_DCI_P3;
    const CS_BT2020: u32 = v4l::v4l_sys::v4l2_colorspace_V4L2_COLORSPACE_BT2020;
    const CS_SMPTE240M: u32 = v4l::v4l_sys::v4l2_colorspace_V4L2_COLORSPACE_SMPTE240M;
    const BT878: u32 = v4l::v4l_sys::v4l2_colorspace_V4L2_COLORSPACE_BT878;
    const CS_RAW: u32 = v4l::v4l_sys::v4l2_colorspace_V4L2_COLORSPACE_RAW;

    const ENC_DEFAULT: u32 = v4l::v4l_sys::v4l2_ycbcr_encoding_V4L2_YCBCR_ENC_DEFAULT;
    const ENC_601: u32 = v4l::v4l_sys::v4l2_ycbcr_encoding_V4L2_YCBCR_ENC_601;
    const ENC_709: u32 = v4l::v4l_sys::v4l2_ycbcr_encoding_V4L2_YCBCR_ENC_709;
    const XV601: u32 = v4l::v4l_sys::v4l2_ycbcr_encoding_V4L2_YCBCR_ENC_XV601;
    const XV709: u32 = v4l::v4l_sys::v4l2_ycbcr_encoding_V4L2_YCBCR_ENC_XV709;
    const SYCC: u32 = v4l::v4l_sys::v4l2_ycbcr_encoding_V4L2_YCBCR_ENC_SYCC;
    const ENC_BT2020: u32 = v4l::v4l_sys::v4l2_ycbcr_encoding_V4L2_YCBCR_ENC_BT2020;
    const BT2020_CONST_LUM: u32 = v4l::v4l_sys::v4l2_ycbcr_encoding_V4L2_YCBCR_ENC_BT2020_CONST_LUM;
    const ENC_SMPTE240M: u32 = v4l::v4l_sys::v4l2_ycbcr_encoding_V4L2_YCBCR_ENC_SMPTE240M;
    const HSV_180: u32 = v4l::v4l_sys::v4l2_hsv_encoding_V4L2_HSV_ENC_180;
    const HSV_256: u32 = v4l::v4l_sys::v4l2_hsv_encoding_V4L2_HSV_ENC_256;

    const Q_DEFAULT: u32 = v4l::v4l_sys::v4l2_quantization_V4L2_QUANTIZATION_DEFAULT;
    const FULL: u32 = v4l::v4l_sys::v4l2_quantization_V4L2_QUANTIZATION_FULL_RANGE;
    const LIM: u32 = v4l::v4l_sys::v4l2_quantization_V4L2_QUANTIZATION_LIM_RANGE;

    /// The smallest tight YUYV image: two pixels, luma 16 and 235, neutral
    /// chroma.
    const L01: [u8; 4] = [16, 128, 235, 128];

    /// Single-planar capture YUYV 2x1, valid extended fields, sRGB, explicit
    /// BT.601 and explicit limited range.
    fn base() -> RawYuyvFormat {
        RawYuyvFormat {
            buffer_type: CAPTURE,
            width: 2,
            height: 1,
            fourcc: *b"YUYV",
            field: v4l::v4l_sys::v4l2_field_V4L2_FIELD_NONE,
            bytesperline: 4,
            sizeimage: 4,
            colorspace: SRGB,
            priv_: v4l::v4l_sys::V4L2_PIX_FMT_PRIV_MAGIC,
            flags: 0,
            ycbcr_enc: ENC_601,
            quantization: LIM,
            xfer_func: v4l::v4l_sys::v4l2_xfer_func_V4L2_XFER_FUNC_SRGB,
            ext_pix_format_supported: true,
        }
    }

    fn with(change: impl FnOnce(&mut RawYuyvFormat)) -> RawYuyvFormat {
        let mut raw = base();
        change(&mut raw);
        raw
    }

    fn meta(bytesused: u32, flags: Flags) -> Metadata {
        Metadata {
            bytesused,
            flags,
            field: 1,
            timestamp: v4l::timestamp::Timestamp::new(1, 0),
            sequence: 0,
        }
    }

    #[track_caller]
    fn facts_of(raw: &RawYuyvFormat, mapped: &[u8], metadata: &Metadata) -> YuyvFrameFacts {
        match inspect_yuyv_frame(raw, mapped, metadata) {
            Ok(facts) => facts,
            Err(error) => panic!("expected frame facts, got {error:?}"),
        }
    }

    #[track_caller]
    fn refusal(raw: &RawYuyvFormat, mapped: &[u8], metadata: &Metadata) -> YuyvFrameError {
        match inspect_yuyv_frame(raw, mapped, metadata) {
            Ok(facts) => panic!("expected a refusal, got {facts:?}"),
            Err(error) => error,
        }
    }

    /// `base()` at `width` x `height` with a tight stride, inspected over
    /// exactly `bytes`.
    #[track_caller]
    fn frame(width: u32, height: u32, bytes: &[u8]) -> YuyvFrameFacts {
        let raw = with(|raw| {
            raw.width = width;
            raw.height = height;
            raw.bytesperline = 2 * width;
        });
        let bytesused = u32::try_from(bytes.len()).expect("fixture length fits u32");
        facts_of(&raw, bytes, &meta(bytesused, Flags::empty()))
    }

    fn l01_facts() -> YuyvFrameFacts {
        facts_of(&base(), &L01, &meta(4, Flags::empty()))
    }

    /// A `width` x `height` image of raw luma `luma` and chroma 128, with raw
    /// luma 14 at each listed pixel index.
    fn luma_bytes(width: usize, height: usize, luma: u8, low_pixels: &[usize]) -> Vec<u8> {
        let mut bytes = [luma, 128].repeat(width * height);
        for &pixel in low_pixels {
            bytes[2 * pixel] = 14;
        }
        bytes
    }

    #[track_caller]
    fn assert_range(
        raw: &RawYuyvFormat,
        range: ReportedRange,
        eligibility: Result<EligibleLimited, MetadataRefusal>,
    ) {
        assert_eq!(classify_reported_range(raw), range, "range of {raw:?}");
        assert_eq!(
            limited_range_eligibility(raw),
            eligibility,
            "eligibility of {raw:?}"
        );
    }

    #[track_caller]
    fn assert_unresolved(raw: &RawYuyvFormat, reason: RangeUnresolved) {
        assert_range(
            raw,
            ReportedRange::Unresolved { reason },
            Err(MetadataRefusal::Unresolved(reason)),
        );
    }

    const fn limited(effective_encoding: u32) -> ReportedRange {
        ReportedRange::Limited { effective_encoding }
    }

    const fn full(effective_encoding: u32) -> ReportedRange {
        ReportedRange::Full { effective_encoding }
    }

    const fn eligible(effective_encoding: u32) -> Result<EligibleLimited, MetadataRefusal> {
        Ok(EligibleLimited { effective_encoding })
    }

    #[test]
    fn r01_explicit_limited_601_is_limited_eligible_and_never_a_ceiling() {
        assert_range(&base(), limited(ENC_601), eligible(ENC_601));
        for quantization in [
            Quantization::Default,
            Quantization::FullRange,
            Quantization::LimitedRange,
        ] {
            assert_eq!(
                crate::clipping_white_level(crate::IrPixel::YuyvLuma, quantization),
                None
            );
        }
    }

    #[test]
    fn r02_default_quantization_srgb_601_resolves_limited() {
        let raw = with(|raw| raw.quantization = Q_DEFAULT);
        assert_range(&raw, limited(ENC_601), eligible(ENC_601));
    }

    #[test]
    fn r03_default_encoding_with_srgb_resolves_to_601_limited() {
        let raw = with(|raw| {
            raw.quantization = Q_DEFAULT;
            raw.ycbcr_enc = ENC_DEFAULT;
        });
        assert_range(&raw, limited(ENC_601), eligible(ENC_601));
    }

    #[test]
    fn r04_rec709_and_dci_p3_defaults_resolve_to_709_limited() {
        for colorspace in [REC709, DCI_P3] {
            let raw = with(|raw| {
                raw.colorspace = colorspace;
                raw.quantization = Q_DEFAULT;
                raw.ycbcr_enc = ENC_DEFAULT;
            });
            assert_range(&raw, limited(ENC_709), eligible(ENC_709));
        }
    }

    #[test]
    fn r05_bt2020_default_resolves_to_bt2020_limited() {
        let raw = with(|raw| {
            raw.colorspace = CS_BT2020;
            raw.quantization = Q_DEFAULT;
            raw.ycbcr_enc = ENC_DEFAULT;
        });
        assert_range(&raw, limited(ENC_BT2020), eligible(ENC_BT2020));
    }

    #[test]
    fn r06_smpte240m_default_resolves_to_smpte240m_limited() {
        let raw = with(|raw| {
            raw.colorspace = CS_SMPTE240M;
            raw.quantization = Q_DEFAULT;
            raw.ycbcr_enc = ENC_DEFAULT;
        });
        assert_range(&raw, limited(ENC_SMPTE240M), eligible(ENC_SMPTE240M));
    }

    #[test]
    fn r07_default_quantization_with_jpeg_is_full_and_refused() {
        let raw = with(|raw| {
            raw.colorspace = JPEG;
            raw.quantization = Q_DEFAULT;
            raw.ycbcr_enc = ENC_DEFAULT;
        });
        assert_range(&raw, full(ENC_601), Err(MetadataRefusal::FullRange));
    }

    #[test]
    fn r08_explicit_full_range_is_refused_even_with_flat_content() {
        let raw = with(|raw| raw.quantization = FULL);
        assert_range(&raw, full(ENC_601), Err(MetadataRefusal::FullRange));
        // xvYCC has no full-range variant, so this tuple contradicts the
        // UAPI; an explicit FULL_RANGE still refuses as full range.
        for encoding in [XV601, XV709] {
            let xv = with(|raw| {
                raw.quantization = FULL;
                raw.ycbcr_enc = encoding;
            });
            assert_range(&xv, full(encoding), Err(MetadataRefusal::FullRange));
        }
        assert_eq!(
            exposure_prerequisite(FdAttestation::Absent, &raw, &l01_facts()),
            PrerequisiteRefusal {
                attestation: FdAttestation::Absent,
                metadata: Some(MetadataRefusal::FullRange),
                footroom_violated: false,
                chroma_not_flat: false,
            }
        );
    }

    #[test]
    fn r09_default_quantization_xv_encodings_are_limited_but_refused() {
        for encoding in [XV601, XV709] {
            let raw = with(|raw| {
                raw.colorspace = REC709;
                raw.quantization = Q_DEFAULT;
                raw.ycbcr_enc = encoding;
            });
            assert_range(&raw, limited(encoding), Err(MetadataRefusal::ExtendedGamut));
        }
    }

    #[test]
    fn r10_explicit_limited_xv_encodings_are_limited_but_refused() {
        for encoding in [XV601, XV709] {
            let raw = with(|raw| raw.ycbcr_enc = encoding);
            assert_range(&raw, limited(encoding), Err(MetadataRefusal::ExtendedGamut));
        }
    }

    #[test]
    fn r11_missing_capability_or_magic_leaves_the_range_unresolved() {
        for raw in [
            with(|raw| raw.ext_pix_format_supported = false),
            with(|raw| raw.priv_ = 0xdead_beef),
            with(|raw| raw.priv_ = 0),
        ] {
            assert_eq!(raw.quantization, LIM);
            assert_unresolved(&raw, RangeUnresolved::ExtendedFieldsUnavailable);
        }
    }

    #[test]
    fn r12_wrong_buffer_type_or_fourcc_is_outside_the_helper() {
        let wrong_type = [CAPTURE_MPLANE, OUTPUT].map(|buffer_type| {
            (
                with(|raw| raw.buffer_type = buffer_type),
                RangeUnresolved::WrongType,
            )
        });
        let wrong_format = [*b"GREY", *b"NV12", *b"UYVY"].map(|fourcc| {
            (
                with(|raw| raw.fourcc = fourcc),
                RangeUnresolved::WrongFormat,
            )
        });
        for (raw, reason) in wrong_type.into_iter().chain(wrong_format) {
            assert_unresolved(&raw, reason);
            let error = refusal(&raw, &L01, &meta(4, Flags::empty()));
            assert!(matches!(error, YuyvFrameError::NotYuyv), "{error:?}");
        }
    }

    #[test]
    fn r13_unknown_unsupported_and_default_colorimetry_stays_unresolved() {
        let mut cases = Vec::new();
        for quantization in [3, u32::MAX] {
            cases.push((
                with(|raw| raw.quantization = quantization),
                RangeUnresolved::UnknownQuantization,
            ));
        }
        for encoding in [9, 127, 130, u32::MAX] {
            cases.push((
                with(|raw| raw.ycbcr_enc = encoding),
                RangeUnresolved::UnknownEncoding,
            ));
        }
        for colorspace in [13, u32::MAX] {
            cases.push((
                with(|raw| raw.colorspace = colorspace),
                RangeUnresolved::UnknownColorspace,
            ));
        }
        cases.push((
            with(|raw| raw.colorspace = CS_DEFAULT),
            RangeUnresolved::UnresolvedColorspaceDefault,
        ));
        for colorspace in [BT878, CS_RAW] {
            cases.push((
                with(|raw| raw.colorspace = colorspace),
                RangeUnresolved::UnsupportedColorspace,
            ));
        }
        for encoding in [SYCC, BT2020_CONST_LUM, HSV_180, HSV_256] {
            cases.push((
                with(|raw| raw.ycbcr_enc = encoding),
                RangeUnresolved::UnsupportedEncoding,
            ));
        }
        assert_eq!(cases.len(), 15);
        for (raw, reason) in cases {
            assert_unresolved(&raw, reason);
        }
    }

    #[test]
    fn r14_encoding_only_change_differs_in_raw_identity() {
        let a = base();
        let b = with(|raw| raw.ycbcr_enc = ENC_709);
        assert_ne!(a, b);
        assert_range(&a, limited(ENC_601), eligible(ENC_601));
        assert_range(&b, limited(ENC_709), eligible(ENC_709));
    }

    #[test]
    fn r15_identity_only_fields_differ_in_raw_identity() {
        let still_limited = [
            with(|raw| raw.flags = v4l::v4l_sys::V4L2_PIX_FMT_FLAG_SET_CSC),
            with(|raw| raw.xfer_func = v4l::v4l_sys::v4l2_xfer_func_V4L2_XFER_FUNC_709),
            with(|raw| raw.field = v4l::v4l_sys::v4l2_field_V4L2_FIELD_INTERLACED),
            with(|raw| raw.sizeimage = 8),
        ];
        for raw in still_limited {
            assert_ne!(base(), raw);
            assert_range(&raw, limited(ENC_601), eligible(ENC_601));
        }
        let unavailable = [
            with(|raw| raw.priv_ = 0),
            with(|raw| raw.ext_pix_format_supported = false),
        ];
        for raw in unavailable {
            assert_ne!(base(), raw);
            assert_unresolved(&raw, RangeUnresolved::ExtendedFieldsUnavailable);
        }
    }

    #[test]
    fn r16_explicit_limited_jpeg_is_limited_but_refused() {
        for (encoding, effective) in [
            (ENC_DEFAULT, ENC_601),
            (ENC_601, ENC_601),
            (ENC_709, ENC_709),
            (ENC_BT2020, ENC_BT2020),
            (ENC_SMPTE240M, ENC_SMPTE240M),
        ] {
            let raw = with(|raw| {
                raw.colorspace = JPEG;
                raw.ycbcr_enc = encoding;
            });
            assert_eq!(raw.quantization, LIM);
            assert_range(
                &raw,
                limited(effective),
                Err(MetadataRefusal::JpegColorspace),
            );
        }
    }

    #[test]
    fn r17_metadata_and_content_never_stand_in_for_fd_attestation() {
        let raw = base();
        let facts = l01_facts();
        for attestation in [FdAttestation::Absent, FdAttestation::Refused] {
            assert_eq!(
                exposure_prerequisite(attestation, &raw, &facts),
                PrerequisiteRefusal {
                    attestation,
                    metadata: None,
                    footroom_violated: false,
                    chroma_not_flat: false,
                }
            );
        }
    }

    #[test]
    fn r18_composite_takes_each_content_field_from_its_own_predicate() {
        let raw = base();
        let cases = [
            ("L01", l01_facts(), false, false),
            ("L02", frame(2, 1, &[14, 10, 16, 240]), true, true),
            ("C01", frame(2, 1, &[16, 10, 16, 240]), false, true),
            (
                "F02",
                frame(100, 2, &luma_bytes(100, 2, 16, &[3, 150])),
                true,
                false,
            ),
        ];
        for (name, facts, footroom_violated, chroma_not_flat) in cases {
            for attestation in [FdAttestation::Absent, FdAttestation::Refused] {
                assert_eq!(
                    exposure_prerequisite(attestation, &raw, &facts),
                    PrerequisiteRefusal {
                        attestation,
                        metadata: None,
                        footroom_violated,
                        chroma_not_flat,
                    },
                    "{name} facts {facts:?}"
                );
            }
        }
    }

    #[test]
    fn r19_every_domain_colorspace_resolves_its_default_encoding() {
        // `V4L2_MAP_YCBCR_ENC_DEFAULT`, then `V4L2_MAP_QUANTIZATION_DEFAULT`.
        let domain: [(u32, u32); 10] = [
            (SMPTE170M, ENC_601),
            (CS_470_SYSTEM_M, ENC_601),
            (CS_470_SYSTEM_BG, ENC_601),
            (SRGB, ENC_601),
            (OPRGB, ENC_601),
            (JPEG, ENC_601),
            (REC709, ENC_709),
            (DCI_P3, ENC_709),
            (CS_BT2020, ENC_BT2020),
            (CS_SMPTE240M, ENC_SMPTE240M),
        ];
        for (colorspace, encoding) in domain {
            let raw = with(|raw| {
                raw.colorspace = colorspace;
                raw.ycbcr_enc = ENC_DEFAULT;
                raw.quantization = Q_DEFAULT;
            });
            if colorspace == JPEG {
                assert_range(&raw, full(encoding), Err(MetadataRefusal::FullRange));
            } else {
                assert_range(&raw, limited(encoding), eligible(encoding));
            }
        }
    }

    #[test]
    fn r20_explicit_domain_encodings_override_the_colorspace_default() {
        for colorspace in [SRGB, REC709] {
            for encoding in [ENC_601, ENC_709, ENC_BT2020, ENC_SMPTE240M] {
                let raw = with(|raw| {
                    raw.colorspace = colorspace;
                    raw.ycbcr_enc = encoding;
                });
                assert_eq!(raw.quantization, LIM);
                assert_range(&raw, limited(encoding), eligible(encoding));
            }
        }
    }

    #[test]
    fn l01_smallest_tight_payload_yields_exact_facts() {
        let facts = l01_facts();
        assert_eq!(facts.pixels(), 2);
        assert_eq!(facts.raw_luma_sum(), 251);
        assert_eq!(facts.below_15(), 0);
        assert_eq!((facts.u_min(), facts.u_max()), (128, 128));
        assert_eq!((facts.v_min(), facts.v_max()), (128, 128));
        assert_eq!(facts.combined_chroma_span(), 0);
        assert!(!facts.footroom_violated());
        assert!(facts.chroma_flat());
    }

    #[test]
    fn l02_low_luma_and_split_chroma_are_counted() {
        let facts = frame(2, 1, &[14, 10, 16, 240]);
        assert_eq!(facts.raw_luma_sum(), 30);
        assert_eq!(facts.below_15(), 1);
        assert_eq!((facts.u_min(), facts.u_max()), (10, 10));
        assert_eq!((facts.v_min(), facts.v_max()), (240, 240));
        assert_eq!(facts.combined_chroma_span(), 230);
        assert!(facts.footroom_violated());
        assert!(!facts.chroma_flat());
    }

    #[test]
    fn l03_surplus_payload_never_changes_the_facts() {
        let surplus = facts_of(
            &base(),
            &[16, 128, 235, 128, 0, 0, 0, 255],
            &meta(8, Flags::empty()),
        );
        assert_eq!(surplus, l01_facts());
    }

    #[test]
    fn l04_existing_geometry_and_stride_refusals_are_preserved() {
        let metadata = meta(4, Flags::empty());
        let error = refusal(&with(|raw| raw.width = 0), &L01, &metadata);
        assert!(
            matches!(
                error,
                YuyvFrameError::Layout(DequeuedBufferError::InvalidGeometry {
                    width: 0,
                    height: 1
                })
            ),
            "{error:?}"
        );
        let error = refusal(&with(|raw| raw.height = 0), &L01, &metadata);
        assert!(
            matches!(
                error,
                YuyvFrameError::Layout(DequeuedBufferError::InvalidGeometry {
                    width: 2,
                    height: 0
                })
            ),
            "{error:?}"
        );
        let odd = with(|raw| {
            raw.width = 3;
            raw.bytesperline = 6;
        });
        let error = refusal(&odd, &[16; 6], &meta(6, Flags::empty()));
        assert!(
            matches!(
                error,
                YuyvFrameError::Layout(DequeuedBufferError::InvalidGeometry {
                    width: 3,
                    height: 1
                })
            ),
            "{error:?}"
        );
        for stride in [0, 6] {
            let error = refusal(&with(|raw| raw.bytesperline = stride), &L01, &metadata);
            assert!(
                matches!(
                    error,
                    YuyvFrameError::Layout(DequeuedBufferError::UnsupportedStride {
                        expected: 4,
                        actual,
                    }) if actual == stride as usize
                ),
                "{error:?}"
            );
        }
        let tall = frame(2, 3, &[16, 128, 16, 128].repeat(3));
        assert_eq!(tall.pixels(), 6);
    }

    #[test]
    fn l05_short_payload_is_refused_without_partial_facts() {
        let error = refusal(&base(), &[16; 8], &meta(3, Flags::empty()));
        assert!(
            matches!(
                error,
                YuyvFrameError::Dequeue(ValidatedDequeueError::Facts(
                    DequeuedBufferError::PayloadTooShort {
                        bytes_used: 3,
                        minimum: 4
                    }
                ))
            ),
            "{error:?}"
        );
    }

    #[test]
    fn l06_payload_beyond_mapping_is_refused() {
        let error = refusal(&base(), &L01, &meta(8, Flags::empty()));
        assert!(
            matches!(
                error,
                YuyvFrameError::Dequeue(ValidatedDequeueError::Facts(
                    DequeuedBufferError::PayloadExceedsMapping {
                        bytes_used: 8,
                        mapped_len: 4
                    }
                ))
            ),
            "{error:?}"
        );
    }

    #[test]
    fn l07_driver_corruption_is_refused() {
        let error = refusal(&base(), &L01, &meta(4, Flags::ERROR));
        assert!(
            matches!(
                error,
                YuyvFrameError::Dequeue(ValidatedDequeueError::Corrupt(_))
            ),
            "{error:?}"
        );
    }

    #[test]
    fn l08_arithmetic_limits_refuse_without_allocation() {
        let wide = with(|raw| {
            raw.width = 0x8000_0000;
            raw.bytesperline = u32::MAX;
        });
        let error = refusal(&wide, &[0; 4], &meta(4, Flags::empty()));
        #[cfg(target_pointer_width = "64")]
        assert!(
            matches!(
                error,
                YuyvFrameError::Layout(DequeuedBufferError::UnsupportedStride {
                    expected,
                    actual,
                }) if expected == 1_usize << 32 && actual == u32::MAX as usize
            ),
            "{error:?}"
        );
        #[cfg(target_pointer_width = "32")]
        assert!(
            matches!(
                error,
                YuyvFrameError::Layout(DequeuedBufferError::PayloadSizeOverflow)
            ),
            "{error:?}"
        );

        let tall = with(|raw| raw.height = u32::MAX);
        let error = refusal(&tall, &L01, &meta(4, Flags::empty()));
        #[cfg(target_pointer_width = "64")]
        assert!(
            matches!(
                error,
                YuyvFrameError::Dequeue(ValidatedDequeueError::Facts(
                    DequeuedBufferError::PayloadTooShort {
                        bytes_used: 4,
                        minimum,
                    }
                )) if minimum == 4 * (u32::MAX as usize)
            ),
            "{error:?}"
        );
        #[cfg(target_pointer_width = "32")]
        assert!(
            matches!(
                error,
                YuyvFrameError::Layout(DequeuedBufferError::PayloadSizeOverflow)
            ),
            "{error:?}"
        );
    }

    #[test]
    fn f01_exactly_half_a_percent_below_15_passes() {
        let facts = frame(100, 2, &luma_bytes(100, 2, 16, &[57]));
        assert_eq!(facts.pixels(), 200);
        assert_eq!(facts.below_15(), 1);
        assert!(!facts.footroom_violated());
    }

    #[test]
    fn f02_one_percent_below_15_fails() {
        let facts = frame(100, 2, &luma_bytes(100, 2, 16, &[3, 150]));
        assert_eq!(facts.below_15(), 2);
        assert!(facts.footroom_violated());
    }

    #[test]
    fn f03_integer_threshold_is_not_rounded_up() {
        let facts = frame(198, 1, &luma_bytes(198, 1, 16, &[0]));
        assert_eq!((facts.pixels(), facts.below_15()), (198, 1));
        assert!(facts.footroom_violated());
        let facts = frame(202, 1, &luma_bytes(202, 1, 16, &[0]));
        assert_eq!((facts.pixels(), facts.below_15()), (202, 1));
        assert!(!facts.footroom_violated());
    }

    #[test]
    fn f04_four_hundred_pixels_allow_two_low_samples() {
        let facts = frame(200, 2, &luma_bytes(200, 2, 16, &[1, 399]));
        assert_eq!((facts.pixels(), facts.below_15()), (400, 2));
        assert!(!facts.footroom_violated());
        let facts = frame(200, 2, &luma_bytes(200, 2, 16, &[1, 200, 399]));
        assert_eq!(facts.below_15(), 3);
        assert!(facts.footroom_violated());
    }

    #[test]
    fn f05_raw_15_is_not_counted_and_all_14_fails() {
        for luma in [15, 16] {
            let facts = frame(100, 2, &luma_bytes(100, 2, luma, &[]));
            assert_eq!(facts.below_15(), 0, "luma {luma}");
            assert!(!facts.footroom_violated(), "luma {luma}");
        }
        let facts = frame(100, 2, &luma_bytes(100, 2, 14, &[]));
        assert_eq!(facts.below_15(), facts.pixels());
        assert!(facts.footroom_violated());
    }

    #[test]
    fn f06_every_luma_slot_and_row_is_counted() {
        for byte in [0, 2, 14, 8] {
            let mut bytes = luma_bytes(4, 2, 16, &[]);
            bytes[byte] = 14;
            let facts = frame(4, 2, &bytes);
            assert_eq!(facts.below_15(), 1, "low luma at byte {byte}");
            assert_eq!(facts.raw_luma_sum(), 126, "low luma at byte {byte}");
            assert!(facts.footroom_violated(), "low luma at byte {byte}");
        }
    }

    #[test]
    fn f07_macropixel_and_luma_permutations_keep_the_facts() {
        let original = frame(4, 1, &[20, 100, 30, 101, 40, 102, 50, 103]);
        let reversed = frame(4, 1, &[40, 102, 50, 103, 20, 100, 30, 101]);
        let swapped = frame(4, 1, &[30, 100, 20, 101, 50, 102, 40, 103]);
        assert_eq!(original.raw_luma_sum(), 140);
        assert_eq!(reversed, original);
        assert_eq!(swapped, original);
    }

    #[test]
    fn c01_chroma_span_pools_u_and_v() {
        let facts = frame(2, 1, &[16, 10, 16, 240]);
        assert!(!facts.footroom_violated());
        assert_eq!(facts.u_max() - facts.u_min(), 0);
        assert_eq!(facts.v_max() - facts.v_min(), 0);
        assert_eq!(facts.combined_chroma_span(), 230);
        assert!(!facts.chroma_flat());
    }

    #[test]
    fn c02_combined_span_two_passes_and_three_fails() {
        let facts = frame(2, 1, &[16, 100, 16, 102]);
        assert_eq!(facts.combined_chroma_span(), 2);
        assert!(facts.chroma_flat());
        let facts = frame(2, 1, &[16, 100, 16, 103]);
        assert_eq!(facts.combined_chroma_span(), 3);
        assert!(!facts.chroma_flat());
    }

    #[test]
    fn c03_either_chroma_channel_can_break_flatness() {
        let v_varies = frame(4, 1, &[16, 100, 16, 100, 16, 100, 16, 103]);
        assert_eq!(v_varies.u_max() - v_varies.u_min(), 0);
        assert_eq!(v_varies.v_max() - v_varies.v_min(), 3);
        assert_eq!(v_varies.combined_chroma_span(), 3);
        assert!(!v_varies.chroma_flat());
        let u_varies = frame(4, 1, &[16, 100, 16, 100, 16, 103, 16, 100]);
        assert_eq!(u_varies.u_max() - u_varies.u_min(), 3);
        assert_eq!(u_varies.v_max() - u_varies.v_min(), 0);
        assert_eq!(u_varies.combined_chroma_span(), 3);
        assert!(!u_varies.chroma_flat());
    }

    #[test]
    fn c04_flat_non_neutral_chroma_passes_per_frame() {
        for chroma in [40, 200] {
            let facts = frame(2, 1, &[16, chroma, 16, chroma]);
            assert_eq!(facts.combined_chroma_span(), 0, "chroma {chroma}");
            assert!(facts.chroma_flat(), "chroma {chroma}");
        }
    }
}

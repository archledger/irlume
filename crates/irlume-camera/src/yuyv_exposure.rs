// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright the irlume contributors.

//! ADR-0031 §4 prerequisite facts for YUYV luma: the reported range of a raw
//! single-planar format, one frame's footroom and chroma, the session latch
//! over them and the fixed limited-to-full luma expansion. Pure. It yields no
//! ceiling and no attestation, and `clipping_white_level` stays `None` for
//! YUYV.
//!
//! Discriminants always come from the generated `v4l::v4l_sys` constants. No
//! raw value is converted to an enum: unknown and unsupported values stay
//! unresolved and refuse. Nothing here opens a device or logs: `yuyv_fd`
//! reads the format from the fd, and `IrSession` offers the latch every frame
//! its bursts dequeue. The latch only refuses and nothing reads it yet; the
//! expansion has no caller until the ceiling.
#![cfg_attr(
    not(test),
    expect(
        dead_code,
        reason = "ADR-0031 §4 pure prerequisite; exposure_prerequisite and the limited-to-full expansion gain a production caller with the ceiling"
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

/// Footroom and chroma facts of one validated YUYV frame. Only `scan_image`
/// builds one, from an image the tight layout defines, so its counts always
/// describe a whole image of at least one macropixel.
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
    let layout = yuyv_layout(raw)?;
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
    scan_image(image)
}

/// The tight layout of `raw`'s image, before any byte is read.
///
/// # Errors
///
/// Returns `YuyvFrameError::NotYuyv` when `raw` is not a single-planar
/// capture YUYV format, and the existing layout refusal unchanged.
fn yuyv_layout(raw: &RawYuyvFormat) -> Result<PayloadLayout, YuyvFrameError> {
    if raw.buffer_type != v4l_sys::v4l2_buf_type_V4L2_BUF_TYPE_VIDEO_CAPTURE || raw.fourcc != YUYV {
        return Err(YuyvFrameError::NotYuyv);
    }
    PayloadLayout::new(YUYV, raw.width, raw.height, raw.bytesperline)
        .map_err(YuyvFrameError::Layout)
}

/// Footroom and chroma facts of `image`, which the caller has already cut to
/// the layout's image bytes.
///
/// # Errors
///
/// Returns `YuyvFrameError::LumaSumOverflow` if the raw luma sum overflows.
fn scan_image(image: &[u8]) -> Result<YuyvFrameFacts, YuyvFrameError> {
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

/// Why a session's content latch refuses. Each reason is set by the first
/// frame that shows it and never cleared.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct ContentRefusal {
    /// A frame had more than 0.5% of its pixels below raw luma 15.
    pub(crate) footroom: bool,
    /// A frame's U and V bytes together spanned more than
    /// `MAX_COMBINED_CHROMA_SPAN` codes.
    pub(crate) chroma: bool,
    /// A payload was not exactly the `2 * width * height` image bytes.
    pub(crate) payload_length: bool,
    /// A frame could not be read: the format has no tight single-planar YUYV
    /// layout, or the raw luma sum overflowed.
    pub(crate) uninspectable: bool,
}

impl ContentRefusal {
    /// No reason set.
    pub(crate) const NONE: Self = Self {
        footroom: false,
        chroma: false,
        payload_length: false,
        uninspectable: false,
    };

    const fn any(self) -> bool {
        self.footroom || self.chroma || self.payload_length || self.uninspectable
    }

    const fn union(self, other: Self) -> Self {
        Self {
            footroom: self.footroom || other.footroom,
            chroma: self.chroma || other.chroma,
            payload_length: self.payload_length || other.payload_length,
            uninspectable: self.uninspectable || other.uninspectable,
        }
    }

    /// The reasons set here and not in `before`.
    const fn without(self, before: Self) -> Self {
        Self {
            footroom: self.footroom && !before.footroom,
            chroma: self.chroma && !before.chroma,
            payload_length: self.payload_length && !before.payload_length,
            uninspectable: self.uninspectable && !before.uninspectable,
        }
    }
}

impl std::fmt::Display for ContentRefusal {
    /// The set reasons by name, for the debug journal; never a pixel value.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let reasons = [
            (self.footroom, "footroom"),
            (self.chroma, "chroma span"),
            (self.payload_length, "payload length"),
            (self.uninspectable, "uninspectable frame"),
        ];
        let mut separator = "";
        for (set, name) in reasons {
            if set {
                write!(f, "{separator}{name}")?;
                separator = ", ";
            }
        }
        Ok(())
    }
}

/// ADR-0031 §4's session latch over the footroom and flat-chroma conditions.
/// `IrSession` holds one for a camera with fd-bound format evidence and
/// offers it every frame its bursts dequeue, before decode. Nothing resets
/// it, so a violation holds through later captures and `recover()` until the
/// session ends. It only refuses: an empty latch is the absence of a refusal,
/// not proof, and it yields no ceiling.
#[derive(Debug)]
pub(crate) struct YuyvContentLatch {
    /// The fd-bound raw format every frame is read with.
    raw: RawYuyvFormat,
    inspected: u64,
    refused: ContentRefusal,
}

impl YuyvContentLatch {
    /// An empty latch for frames of `raw`, the camera's frozen format.
    pub(crate) const fn new(raw: RawYuyvFormat) -> Self {
        Self {
            raw,
            inspected: 0,
            refused: ContentRefusal::NONE,
        }
    }

    /// Judge one dequeued payload and latch what it shows. Returns only the
    /// reasons this frame newly latched. It never fails: a frame that cannot
    /// be read latches `uninspectable` instead.
    pub(crate) fn observe(&mut self, payload: &[u8]) -> Option<ContentRefusal> {
        let shown = frame_refusal(&self.raw, payload);
        self.inspected = self.inspected.saturating_add(1);
        let newly = shown.without(self.refused);
        self.refused = self.refused.union(shown);
        newly.any().then_some(newly)
    }

    /// Every reason latched so far, or `None` when no frame offered so far
    /// violated. `None` is not a proof, a ceiling or a clipping level.
    pub(crate) fn refusal(&self) -> Option<ContentRefusal> {
        self.refused.any().then_some(self.refused)
    }

    /// Frames offered so far, readable or not, saturating.
    pub(crate) const fn inspected(&self) -> u64 {
        self.inspected
    }
}

/// What one payload shows against `raw`'s layout, on raw bytes before any
/// expansion. A payload other than exactly the image refuses on its own and
/// its image part is still read; bytes after the image never are.
fn frame_refusal(raw: &RawYuyvFormat, payload: &[u8]) -> ContentRefusal {
    let Ok(layout) = yuyv_layout(raw) else {
        return ContentRefusal {
            uninspectable: true,
            ..ContentRefusal::NONE
        };
    };
    let image_bytes = layout.image_bytes();
    let mut shown = ContentRefusal {
        payload_length: payload.len() != image_bytes,
        ..ContentRefusal::NONE
    };
    match payload.get(..image_bytes).map(scan_image) {
        Some(Ok(facts)) => {
            shown.footroom = facts.footroom_violated();
            shown.chroma = !facts.chroma_flat();
        }
        Some(Err(_)) => shown.uninspectable = true,
        // Shorter than the image: `payload_length` is already set.
        None => {}
    }
    shown
}

/// Limited-range raw luma expanded to full range: 0 for `y <= 16`, 255 for
/// `y >= 235`, and `round((y - 16) * 255 / 219)` between, which never lands
/// on a half because 219 is odd, so `E(234) = 254`. A fixed map, never
/// scaled by a frame's own values (ADR-0031 §4, Amendment 2026-10-07).
///
/// The content checks run on raw bytes before it, since raw 14, 15 and 16
/// all expand to 0. Nothing calls it until the ceiling: decoding YUYV
/// through it now would move IR face detection, the gate frame and the
/// enrollment preflight's lit test.
pub(crate) const fn expand_limited_luma(y: u8) -> u8 {
    if y <= 16 {
        0
    } else if y >= 235 {
        u8::MAX
    } else {
        // At most 218 * 510 + 219 = 111,399, whose quotient is 254.
        (((y - 16) as u32 * 510 + 219) / 438) as u8
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

    const FOOTROOM: ContentRefusal = ContentRefusal {
        footroom: true,
        ..ContentRefusal::NONE
    };
    const CHROMA: ContentRefusal = ContentRefusal {
        chroma: true,
        ..ContentRefusal::NONE
    };
    const FOOTROOM_AND_CHROMA: ContentRefusal = ContentRefusal {
        footroom: true,
        chroma: true,
        ..ContentRefusal::NONE
    };
    const PAYLOAD_LENGTH: ContentRefusal = ContentRefusal {
        payload_length: true,
        ..ContentRefusal::NONE
    };
    const UNINSPECTABLE: ContentRefusal = ContentRefusal {
        uninspectable: true,
        ..ContentRefusal::NONE
    };

    /// A session's latch for `base()` at `width` x `height` with a tight
    /// stride.
    fn fresh(width: u32, height: u32) -> YuyvContentLatch {
        YuyvContentLatch::new(with(|raw| {
            raw.width = width;
            raw.height = height;
            raw.bytesperline = 2 * width;
        }))
    }

    /// A `width` x `height` image of raw luma `luma` and constant chroma
    /// `chroma` in both U and V.
    fn flat_bytes(width: usize, height: usize, luma: u8, chroma: u8) -> Vec<u8> {
        [luma, chroma].repeat(width * height)
    }

    /// An emitter-off frame as §4 records the T480's: raw luma cycling
    /// through 16 to 20 and chroma 137, with raw luma 10 at each listed pixel.
    fn dark_bytes(width: usize, height: usize, low_pixels: &[usize]) -> Vec<u8> {
        let mut bytes: Vec<u8> = (16_u8..=20)
            .cycle()
            .take(width * height)
            .flat_map(|luma| [luma, 137])
            .collect();
        for &pixel in low_pixels {
            bytes[2 * pixel] = 10;
        }
        bytes
    }

    /// `count` pixel indexes spread across an image, 199 apart.
    fn spread(count: usize) -> Vec<usize> {
        (0..count).map(|i| i * 199).collect()
    }

    #[test]
    fn k01_a_new_latch_holds_no_refusal() {
        let latch = fresh(2, 1);
        assert_eq!(latch.refusal(), None);
        assert_eq!(latch.inspected(), 0);
    }

    #[test]
    fn k02_exactly_half_a_percent_keeps_the_latch_clear() {
        let mut one = fresh(100, 2);
        assert_eq!(one.observe(&luma_bytes(100, 2, 16, &[57])), None);
        assert_eq!(one.refusal(), None);
        let mut two = fresh(100, 2);
        assert_eq!(
            two.observe(&luma_bytes(100, 2, 16, &[3, 150])),
            Some(FOOTROOM)
        );
        assert_eq!(two.refusal(), Some(FOOTROOM));
        // 340x340 is 115,600 pixels, which allow 578 low ones.
        let mut at = fresh(340, 340);
        assert_eq!(at.observe(&luma_bytes(340, 340, 16, &spread(578))), None);
        assert_eq!(at.refusal(), None);
        let mut above = fresh(340, 340);
        assert_eq!(
            above.observe(&luma_bytes(340, 340, 16, &spread(579))),
            Some(FOOTROOM)
        );
        assert_eq!(above.refusal(), Some(FOOTROOM));
    }

    #[test]
    fn k03_raw_14_counts_and_raw_15_and_16_do_not() {
        for luma in [15, 16] {
            let mut latch = fresh(100, 2);
            assert_eq!(
                latch.observe(&luma_bytes(100, 2, luma, &[])),
                None,
                "luma {luma}"
            );
            assert_eq!(latch.refusal(), None, "luma {luma}");
        }
        let mut latch = fresh(100, 2);
        assert_eq!(latch.observe(&luma_bytes(100, 2, 14, &[])), Some(FOOTROOM));
        assert_eq!(latch.refusal(), Some(FOOTROOM));
    }

    #[test]
    fn k04_a_violation_in_an_unselected_dark_frame_latches() {
        let (width, height) = (20, 10);
        // Lit and dark frames alternate; dark frame 1 has 4 of its 200 pixels
        // (2%) at raw luma 10.
        let burst: Vec<Vec<u8>> = (0..10)
            .map(|i| match i {
                1 => dark_bytes(width, height, &[0, 50, 100, 150]),
                i if i % 2 == 1 => dark_bytes(width, height, &[]),
                _ => flat_bytes(width, height, 120, 128),
            })
            .collect();
        let means: Vec<f64> = burst
            .iter()
            .map(|frame| {
                let luma = crate::decode_ir(frame, crate::IrPixel::YuyvLuma, 20, 10);
                luma.iter().map(|&y| f64::from(y)).sum::<f64>() / luma.len() as f64
            })
            .collect();
        let selected = crate::ir_metadata::best_gate_frame(&means, &[None; 10], None)
            .expect("a burst always has a gate frame");
        assert_eq!(
            selected % 2,
            0,
            "the gate frame is a lit one, not {selected}"
        );
        let mut alone = fresh(20, 10);
        assert_eq!(alone.observe(&burst[selected]), None);
        assert_eq!(alone.refusal(), None);
        let mut session = fresh(20, 10);
        for frame in &burst {
            session.observe(frame);
        }
        assert_eq!(session.refusal(), Some(FOOTROOM));
        assert_eq!(session.inspected(), 10);
    }

    #[test]
    fn k05_later_frames_and_captures_never_clear_the_latch() {
        let clean = luma_bytes(100, 2, 16, &[]);
        let violating = luma_bytes(100, 2, 16, &[3, 150]);
        let mut latch = fresh(100, 2);
        assert_eq!(latch.observe(&clean), None);
        assert_eq!(latch.refusal(), None);
        assert_eq!(latch.observe(&violating), Some(FOOTROOM));
        // Three more 10-frame captures, every frame clean.
        for capture in 0..3 {
            for frame in 0..10 {
                assert_eq!(latch.observe(&clean), None);
                assert_eq!(
                    latch.refusal(),
                    Some(FOOTROOM),
                    "capture {capture} frame {frame}"
                );
            }
        }
        assert_eq!(latch.inspected(), 32);
        // A clean frame of the exact length clears no other reason either.
        for (first, reason) in [
            (&[16, 100, 16, 103][..], CHROMA),
            (&L01[..3], PAYLOAD_LENGTH),
        ] {
            let mut latch = fresh(2, 1);
            assert_eq!(latch.observe(first), Some(reason));
            assert_eq!(latch.observe(&L01), None);
            assert_eq!(latch.refusal(), Some(reason), "{reason}");
        }
    }

    #[test]
    fn k06_chroma_is_judged_within_each_frame() {
        let mut apart = fresh(2, 1);
        assert_eq!(apart.observe(&[16, 40, 16, 40]), None);
        assert_eq!(apart.observe(&[16, 200, 16, 200]), None);
        assert_eq!(apart.refusal(), None, "frames are never pooled");
        // §4's T480 pattern: lit frames at 128, dark frames at 137 to 138.
        let mut t480 = fresh(2, 1);
        assert_eq!(t480.observe(&[120, 128, 121, 128]), None);
        assert_eq!(t480.observe(&[17, 137, 18, 138]), None);
        assert_eq!(t480.refusal(), None);
        let mut two = fresh(2, 1);
        assert_eq!(two.observe(&[16, 100, 16, 102]), None);
        assert_eq!(two.refusal(), None);
        let mut three = fresh(2, 1);
        assert_eq!(three.observe(&[16, 100, 16, 103]), Some(CHROMA));
        assert_eq!(three.refusal(), Some(CHROMA));
        for (channel, bytes) in [
            ("U", [16, 100, 16, 100, 16, 103, 16, 100]),
            ("V", [16, 100, 16, 100, 16, 100, 16, 103]),
        ] {
            let mut latch = fresh(4, 1);
            assert_eq!(latch.observe(&bytes), Some(CHROMA), "{channel} only");
            assert_eq!(latch.refusal(), Some(CHROMA), "{channel} only");
        }
    }

    #[test]
    fn k07_reasons_latch_independently_and_accumulate() {
        let footroom = [14, 128, 14, 128];
        let chroma = [16, 100, 16, 103];
        for order in [[footroom, chroma], [chroma, footroom]] {
            let mut latch = fresh(2, 1);
            for frame in order {
                latch.observe(&frame);
            }
            assert_eq!(latch.refusal(), Some(FOOTROOM_AND_CHROMA), "{order:?}");
        }
    }

    #[test]
    fn k08_a_payload_other_than_the_image_latches_its_own_refusal() {
        let mut exact = fresh(2, 1);
        assert_eq!(exact.observe(&L01), None);
        assert_eq!(exact.refusal(), None);
        // Read as image, the surplus would fail footroom and chroma too.
        let mut surplus = fresh(2, 1);
        assert_eq!(
            surplus.observe(&[16, 128, 235, 128, 0, 0, 0, 255]),
            Some(PAYLOAD_LENGTH)
        );
        assert_eq!(surplus.refusal(), Some(PAYLOAD_LENGTH));
        // Surplus never dilutes the image: 2 of its 200 pixels are low, 2 of
        // 400 would pass.
        let mut diluted = fresh(100, 2);
        let mut bytes = luma_bytes(100, 2, 16, &[3, 150]);
        bytes.extend(luma_bytes(100, 2, 16, &[]));
        let both = ContentRefusal {
            footroom: true,
            payload_length: true,
            ..ContentRefusal::NONE
        };
        assert_eq!(diluted.observe(&bytes), Some(both));
        assert_eq!(diluted.refusal(), Some(both));
        let mut short = fresh(2, 1);
        assert_eq!(short.observe(&[16, 128, 235]), Some(PAYLOAD_LENGTH));
        assert_eq!(short.observe(&[]), None);
        assert_eq!(short.refusal(), Some(PAYLOAD_LENGTH));
        assert_eq!(short.inspected(), 2);
    }

    #[test]
    fn k09_an_unreadable_frame_latches_uninspectable() {
        let unreadable = [
            with(|raw| raw.fourcc = *b"GREY"),
            with(|raw| raw.buffer_type = CAPTURE_MPLANE),
            with(|raw| {
                raw.width = 3;
                raw.bytesperline = 6;
            }),
            with(|raw| raw.width = 0),
            with(|raw| raw.bytesperline = 6),
        ];
        for raw in unreadable {
            let mut latch = YuyvContentLatch::new(raw);
            assert_eq!(latch.observe(&L01), Some(UNINSPECTABLE), "{raw:?}");
            assert_eq!(latch.observe(&[]), None, "{raw:?}");
            assert_eq!(latch.refusal(), Some(UNINSPECTABLE), "{raw:?}");
            assert_eq!(latch.inspected(), 2, "{raw:?}");
        }
    }

    #[test]
    fn k10_observe_reports_each_reason_once() {
        let mut latch = fresh(2, 1);
        assert_eq!(latch.observe(&L01), None);
        assert_eq!(latch.observe(&[14, 128, 14, 128]), Some(FOOTROOM));
        assert_eq!(latch.observe(&[14, 128, 14, 128]), None);
        assert_eq!(latch.observe(&[14, 100, 14, 103]), Some(CHROMA));
        assert_eq!(latch.observe(&[14, 100, 14, 103]), None);
        assert_eq!(latch.refusal(), Some(FOOTROOM_AND_CHROMA));
    }

    #[test]
    fn k11_each_session_starts_its_own_latch() {
        let mut first = fresh(2, 1);
        assert_eq!(first.observe(&[14, 128, 14, 128]), Some(FOOTROOM));
        assert_eq!(first.refusal(), Some(FOOTROOM));
        let second = fresh(2, 1);
        assert_eq!(second.refusal(), None);
        assert_eq!(second.inspected(), 0);
    }

    #[test]
    fn k12_the_journal_names_reasons_without_measurements() {
        assert_eq!(FOOTROOM.to_string(), "footroom");
        assert_eq!(FOOTROOM_AND_CHROMA.to_string(), "footroom, chroma span");
        let every = ContentRefusal {
            footroom: true,
            chroma: true,
            payload_length: true,
            uninspectable: true,
        };
        assert_eq!(
            every.to_string(),
            "footroom, chroma span, payload length, uninspectable frame"
        );
    }

    #[test]
    fn x01_expansion_matches_exact_rounding_on_every_input() {
        for y in 0..=u8::MAX {
            // `(Y - 16) * 255 / 219` never lands on a half: 510 * (Y - 16) is
            // even and 219 is odd, so the f64 rounding mode cannot matter.
            if (16..=235).contains(&y) {
                assert_ne!(510 * (u32::from(y) - 16) % 438, 219, "Y {y}");
            }
            let exact = ((f64::from(y) - 16.0) * 255.0 / 219.0)
                .round()
                .clamp(0.0, 255.0) as u8;
            assert_eq!(expand_limited_luma(y), exact, "Y {y}");
        }
    }

    #[test]
    fn x02_expansion_endpoints_and_footroom() {
        for (y, expanded) in [
            (0, 0),
            (14, 0),
            (15, 0),
            (16, 0),
            (17, 1),
            (40, 28),
            (50, 40),
            (234, 254),
            (235, 255),
            (255, 255),
        ] {
            assert_eq!(expand_limited_luma(y), expanded, "Y {y}");
        }
        for y in 0..=u8::MAX {
            assert_eq!(expand_limited_luma(y) == 255, y >= 235, "Y {y}");
            assert_eq!(expand_limited_luma(y) == 0, y <= 16, "Y {y}");
        }
        for y in 111..=116 {
            assert_eq!(expand_limited_luma(y), y, "Y {y} is a fixed point");
        }
    }

    #[test]
    fn x03_expansion_is_monotone() {
        for y in 0..u8::MAX {
            let (low, high) = (expand_limited_luma(y), expand_limited_luma(y + 1));
            assert!(low <= high, "Y {y}");
            assert!(high - low <= 2, "Y {y}");
        }
    }

    #[test]
    fn x04_expansion_does_not_round_low_like_298_over_256() {
        for (y, expanded) in [
            (86, 82),
            (147, 153),
            (153, 160),
            (159, 167),
            (214, 231),
            (220, 238),
            (226, 245),
            (232, 252),
        ] {
            assert_eq!(expand_limited_luma(y), expanded, "Y {y}");
            assert_eq!(
                ((u32::from(y) - 16) * 298 + 128) >> 8,
                u32::from(expanded) - 1,
                "298/256 reads Y {y} one low"
            );
        }
    }
}

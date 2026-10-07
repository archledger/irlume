// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright the irlume contributors.

//! ADR-0031 §4's first two conditions, bound to the open file descriptor
//! (#887): the §1 attestation re-derived from the fd over a format list read
//! to its end, and the raw `VIDIOC_G_FMT` tuple the range is judged from,
//! frozen after negotiation and re-read at every stream boundary.
//!
//! Evidence is not a ceiling. `clipping_white_level` stays `None` for YUYV;
//! the session content latch, the burst's emitter alternation and the
//! limited-to-full expansion are later changes.

use crate::yuyv_exposure::RawYuyvFormat;
use v4l::v4l_sys;
use v4l::Device;

const CAPTURE: u32 = v4l_sys::v4l2_buf_type_V4L2_BUF_TYPE_VIDEO_CAPTURE;

/// The most `VIDIOC_ENUM_FMT` entries a complete list may hold. uvcvideo
/// answers one per format descriptor and a YUYV-only node has one; a node
/// still answering past this is not ending its list.
const MAX_LISTED_FORMATS: u32 = 64;

/// Why a node's format list was not read to its end.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum ListIncomplete {
    /// `VIDIOC_ENUM_FMT` failed at `index` with an errno other than EINVAL,
    /// the only answer that ends the list.
    Failed { index: u32, errno: Option<i32> },
    /// The answer at `index` named another index or buffer type.
    Malformed { index: u32 },
    /// No EINVAL within `MAX_LISTED_FORMATS` entries.
    Unterminated,
}

/// Every single-planar capture fourcc a node lists, in order, read until
/// EINVAL ends the list (Linux `vidioc-enum-fmt.rst`). The pinned v4l 0.14.0
/// `enum_formats` stops at any error and returns what it has, so a YUYV entry
/// followed by EIO reads there as a YUYV-only node; here it is incomplete.
pub(crate) fn listed_formats(
    mut entry: impl FnMut(u32) -> std::io::Result<v4l_sys::v4l2_fmtdesc>,
) -> Result<Vec<[u8; 4]>, ListIncomplete> {
    let mut formats = Vec::new();
    for index in 0..MAX_LISTED_FORMATS {
        match entry(index) {
            Ok(desc) if desc.index == index && desc.type_ == CAPTURE => {
                formats.push(desc.pixelformat.to_le_bytes());
            }
            Ok(_) => return Err(ListIncomplete::Malformed { index }),
            Err(error) if error.raw_os_error() == Some(libc::EINVAL) => return Ok(formats),
            Err(error) => {
                return Err(ListIncomplete::Failed {
                    index,
                    errno: error.raw_os_error(),
                })
            }
        }
    }
    Err(ListIncomplete::Unterminated)
}

/// The node an fd was opened through, from `fstat`: the character device's
/// number and the inode and filesystem of its `/dev` entry.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct NodeIdentity {
    rdev: libc::dev_t,
    dev: libc::dev_t,
    ino: libc::ino_t,
}

/// The fd reads evidence is bound from and rechecked against: ioctls and
/// `fstat` on one open device, injected in tests.
pub(crate) trait FormatReads {
    /// `VIDIOC_ENUM_FMT` for single-planar capture at `index`.
    fn listed_format(&self, index: u32) -> std::io::Result<v4l_sys::v4l2_fmtdesc>;
    /// ADR-0031 §1's attestation, re-derived from the fd's USB descriptor.
    fn descriptor_attested(&self) -> bool;
    /// `VIDIOC_QUERYCAP` and `VIDIOC_G_FMT`.
    fn raw_format(&self) -> std::io::Result<RawYuyvFormat>;
    /// `fstat`.
    fn node(&self) -> std::io::Result<NodeIdentity>;
}

/// [`FormatReads`] on one open device.
pub(crate) struct DeviceReads<'a> {
    dev: &'a Device,
}

impl<'a> DeviceReads<'a> {
    pub(crate) const fn new(dev: &'a Device) -> Self {
        Self { dev }
    }
}

impl FormatReads for DeviceReads<'_> {
    fn listed_format(&self, index: u32) -> std::io::Result<v4l_sys::v4l2_fmtdesc> {
        // SAFETY: `v4l2_fmtdesc` holds only integers and byte arrays, for
        // which all-zero is a valid value.
        let mut desc: v4l_sys::v4l2_fmtdesc = unsafe { std::mem::zeroed() };
        desc.index = index;
        desc.type_ = CAPTURE;
        // SAFETY: `self.dev` owns the fd for the length of this call, and
        // `desc` is a correctly sized v4l2_fmtdesc, which is what
        // VIDIOC_ENUM_FMT reads and writes.
        let rc = unsafe {
            libc::ioctl(
                self.dev.handle().fd(),
                v4l::v4l2::vidioc::VIDIOC_ENUM_FMT,
                &mut desc as *mut _ as *mut libc::c_void,
            )
        };
        if rc < 0 {
            return Err(std::io::Error::last_os_error());
        }
        Ok(desc)
    }

    fn descriptor_attested(&self) -> bool {
        crate::uvc_descriptor::identity_from_fd(self.dev.handle().fd())
            .is_ok_and(|identity| identity.ir_function_evidence().is_ok())
    }

    fn raw_format(&self) -> std::io::Result<RawYuyvFormat> {
        let caps = crate::queried_caps(self.dev)?;
        let ext_pix_format_supported =
            crate::node_device_caps(&caps) & v4l_sys::V4L2_CAP_EXT_PIX_FORMAT != 0;
        // SAFETY: `v4l2_format` is a plain C ABI object of integers and
        // unions of integers, for which all-zero is a valid value.
        let mut wire: v4l_sys::v4l2_format = unsafe { std::mem::zeroed() };
        wire.type_ = CAPTURE;
        // SAFETY: `self.dev` owns the fd for the length of this call, and
        // `wire` is a correctly sized v4l2_format with `type_` set, which is
        // what VIDIOC_G_FMT reads and writes. Nothing is requested: G_FMT
        // reports the current format and changes no state.
        let rc = unsafe {
            libc::ioctl(
                self.dev.handle().fd(),
                v4l::v4l2::vidioc::VIDIOC_G_FMT,
                &mut wire as *mut _ as *mut libc::c_void,
            )
        };
        if rc < 0 {
            return Err(std::io::Error::last_os_error());
        }
        Ok(raw_from_wire(&wire, ext_pix_format_supported))
    }

    fn node(&self) -> std::io::Result<NodeIdentity> {
        // SAFETY: `libc::stat` holds only integers, for which all-zero is a
        // valid value.
        let mut stat: libc::stat = unsafe { std::mem::zeroed() };
        // SAFETY: `self.dev` owns the fd for the length of this call, and
        // `stat` is a correctly sized buffer for fstat to fill.
        let rc = unsafe { libc::fstat(self.dev.handle().fd(), &mut stat) };
        if rc < 0 {
            return Err(std::io::Error::last_os_error());
        }
        Ok(NodeIdentity {
            rdev: stat.st_rdev,
            dev: stat.st_dev,
            ino: stat.st_ino,
        })
    }
}

/// The raw tuple of a `VIDIOC_G_FMT` answer, copied field by field from the
/// generated ABI with nothing converted, beside the capability fact that
/// says whether its extended fields are defined.
fn raw_from_wire(wire: &v4l_sys::v4l2_format, ext_pix_format_supported: bool) -> RawYuyvFormat {
    // SAFETY: every arm of the `fmt` union is plain integers, so any bytes
    // are a valid `v4l2_pix_format`; it is the arm single-planar capture
    // fills, and the buffer type is kept so a caller can refuse another.
    let pix = unsafe { wire.fmt.pix };
    // SAFETY: both members of this anonymous union, `ycbcr_enc` and
    // `hsv_enc`, are one `u32`, so either reads the same initialized word.
    let ycbcr_enc = unsafe { pix.__bindgen_anon_1.ycbcr_enc };
    RawYuyvFormat {
        buffer_type: wire.type_,
        width: pix.width,
        height: pix.height,
        fourcc: pix.pixelformat.to_le_bytes(),
        field: pix.field,
        bytesperline: pix.bytesperline,
        sizeimage: pix.sizeimage,
        colorspace: pix.colorspace,
        priv_: pix.priv_,
        flags: pix.flags,
        ycbcr_enc,
        quantization: pix.quantization,
        xfer_func: pix.xfer_func,
        ext_pix_format_supported,
    }
}

/// The raw format of an attested, YUYV-only node, read from its fd after
/// negotiation and frozen for the camera's life. Only [`FormatEvidence::bind`]
/// builds one.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct FormatEvidence {
    raw: RawYuyvFormat,
    node: NodeIdentity,
}

/// Why an open camera has no fd format evidence.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum BindRefusal {
    /// `fstat` on the fd failed.
    Node { errno: Option<i32> },
    /// The format list was not read to its end.
    List(ListIncomplete),
    /// The complete list is not YUYV alone.
    NotYuyvOnly,
    /// The fd's USB descriptor does not attest an IR function (ADR-0031 §1).
    NotAttested,
    /// `VIDIOC_QUERYCAP` or `VIDIOC_G_FMT` failed.
    RawRead { errno: Option<i32> },
    /// A field the v4l wrapper keeps differs from the negotiated format.
    Disagrees { field: &'static str },
}

/// Why a stream boundary refuses the evidence frozen at open.
#[derive(Debug)]
pub(crate) enum FormatDrift {
    /// `fstat`, `VIDIOC_QUERYCAP` or `VIDIOC_G_FMT` failed.
    Read(std::io::Error),
    /// The fd names another node than the one the evidence was frozen from.
    Node,
    /// `field` moved; values are the raw words, the fourcc little-endian and
    /// the capability fact as 0 or 1.
    Moved {
        field: &'static str,
        now: u32,
        frozen: u32,
    },
}

impl FormatEvidence {
    /// Bind evidence to the fd `reads` answers for, once negotiation settled
    /// on `negotiated`.
    ///
    /// In order: the fd's node; the format list read to its end, which must
    /// be YUYV alone; the §1 attestation from the same fd, read only for that
    /// shape; and the raw format, every field of which the v4l wrapper keeps
    /// must equal `negotiated`. The fields the wrapper drops (the Y'CbCr
    /// encoding, `priv`, flag bits it does not know) and the extended-format
    /// capability are frozen as read: the range is judged from them, not
    /// here.
    ///
    /// # Errors
    ///
    /// The first [`BindRefusal`] that applies.
    pub(crate) fn bind(
        reads: &impl FormatReads,
        negotiated: &v4l::Format,
    ) -> Result<Self, BindRefusal> {
        let node = reads.node().map_err(|error| BindRefusal::Node {
            errno: error.raw_os_error(),
        })?;
        let listed =
            listed_formats(|index| reads.listed_format(index)).map_err(BindRefusal::List)?;
        if !crate::offers_only_luma_ir_container(&listed) {
            return Err(BindRefusal::NotYuyvOnly);
        }
        if !reads.descriptor_attested() {
            return Err(BindRefusal::NotAttested);
        }
        let raw = reads.raw_format().map_err(|error| BindRefusal::RawRead {
            errno: error.raw_os_error(),
        })?;
        if let Some(field) = disagreement(&raw, negotiated) {
            return Err(BindRefusal::Disagrees { field });
        }
        Ok(Self { raw, node })
    }

    /// Re-read the fd and compare the whole raw tuple with the frozen one.
    ///
    /// # Errors
    ///
    /// A failed read, another node, or the first field that moved.
    pub(crate) fn recheck(&self, reads: &impl FormatReads) -> Result<(), FormatDrift> {
        if reads.node().map_err(FormatDrift::Read)? != self.node {
            return Err(FormatDrift::Node);
        }
        let now = reads.raw_format().map_err(FormatDrift::Read)?;
        match first_moved(&self.raw, &now) {
            Some((field, now, frozen)) => Err(FormatDrift::Moved { field, now, frozen }),
            None => Ok(()),
        }
    }
}

#[cfg(test)]
impl FormatEvidence {
    /// Evidence frozen from `reads` without the list and descriptor checks,
    /// so a test can run the production boundary rechecks on a real node
    /// that is not an attested YUYV camera.
    pub(crate) fn frozen_from(reads: &impl FormatReads) -> std::io::Result<Self> {
        Ok(Self {
            node: reads.node()?,
            raw: reads.raw_format()?,
        })
    }

    /// This evidence with its frozen tuple changed by `change`.
    pub(crate) fn with_raw(mut self, change: impl FnOnce(&mut RawYuyvFormat)) -> Self {
        change(&mut self.raw);
        self
    }
}

/// The first field of `raw` the v4l wrapper keeps that differs from the
/// negotiated readback, or a buffer type other than single-planar capture.
/// The wrapper truncates flag bits it does not know, so only the bits it can
/// represent are compared; the whole raw word is what binding freezes.
pub(crate) fn disagreement(raw: &RawYuyvFormat, negotiated: &v4l::Format) -> Option<&'static str> {
    [
        ("type", raw.buffer_type == CAPTURE),
        ("fourcc", raw.fourcc == negotiated.fourcc.repr),
        ("width", raw.width == negotiated.width),
        ("height", raw.height == negotiated.height),
        ("field", raw.field == negotiated.field_order as u32),
        ("bytesperline", raw.bytesperline == negotiated.stride),
        ("sizeimage", raw.sizeimage == negotiated.size),
        ("colorspace", raw.colorspace == negotiated.colorspace as u32),
        (
            "flags",
            v4l::format::Flags::from(raw.flags).bits() == negotiated.flags.bits(),
        ),
        (
            "quantization",
            raw.quantization == negotiated.quantization as u32,
        ),
        ("xfer_func", raw.xfer_func == negotiated.transfer as u32),
    ]
    .into_iter()
    .find_map(|(field, same)| (!same).then_some(field))
}

/// The first field of the raw tuple that moved, as `(field, now, frozen)`.
/// The destructuring names every field, so a field added to
/// `RawYuyvFormat` fails to compile here until it is compared.
fn first_moved(frozen: &RawYuyvFormat, now: &RawYuyvFormat) -> Option<(&'static str, u32, u32)> {
    let words = |raw: &RawYuyvFormat| {
        let RawYuyvFormat {
            buffer_type,
            width,
            height,
            fourcc,
            field,
            bytesperline,
            sizeimage,
            colorspace,
            priv_,
            flags,
            ycbcr_enc,
            quantization,
            xfer_func,
            ext_pix_format_supported,
        } = *raw;
        [
            ("type", buffer_type),
            ("fourcc", u32::from_le_bytes(fourcc)),
            ("width", width),
            ("height", height),
            ("field", field),
            ("bytesperline", bytesperline),
            ("sizeimage", sizeimage),
            ("colorspace", colorspace),
            ("priv", priv_),
            ("flags", flags),
            ("ycbcr_enc", ycbcr_enc),
            ("quantization", quantization),
            ("xfer_func", xfer_func),
            ("ext_pix_format", u32::from(ext_pix_format_supported)),
        ]
    };
    words(frozen)
        .into_iter()
        .zip(words(now))
        .find_map(|((field, frozen), (_, now))| (now != frozen).then_some((field, now, frozen)))
}

fn errno_text(errno: Option<i32>) -> String {
    errno.map_or_else(
        || "no errno".to_owned(),
        |errno| std::io::Error::from_raw_os_error(errno).to_string(),
    )
}

impl std::fmt::Display for ListIncomplete {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Failed { index, errno } => write!(
                f,
                "the format list failed at entry {index}: {}",
                errno_text(*errno)
            ),
            Self::Malformed { index } => write!(
                f,
                "format list entry {index} answered for another index or buffer type"
            ),
            Self::Unterminated => write!(
                f,
                "the format list did not end within {MAX_LISTED_FORMATS} entries"
            ),
        }
    }
}

impl std::fmt::Display for BindRefusal {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Node { errno } => write!(f, "fstat failed: {}", errno_text(*errno)),
            Self::List(incomplete) => incomplete.fmt(f),
            Self::NotYuyvOnly => f.write_str("the node does not list YUYV alone"),
            Self::NotAttested => {
                f.write_str("the fd's USB descriptor does not attest an IR function")
            }
            Self::RawRead { errno } => {
                write!(f, "the raw format read failed: {}", errno_text(*errno))
            }
            Self::Disagrees { field } => {
                write!(f, "raw {field} disagrees with the negotiated format")
            }
        }
    }
}

impl std::fmt::Display for FormatDrift {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Read(error) => write!(f, "the raw format re-read failed: {error}"),
            Self::Node => f.write_str("the fd names another node than its frozen format"),
            Self::Moved { field, now, frozen } => {
                write!(f, "raw {field} is now {now}, frozen at open as {frozen}")
            }
        }
    }
}

impl std::fmt::Display for FormatEvidence {
    /// The frozen metadata and the range verdict, for the debug journal: the
    /// numbers attended qualification records (ADR-0031 §4).
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let raw = &self.raw;
        write!(
            f,
            "{}x{} colorspace {} ycbcr_enc {} quantization {} xfer_func {} \
             ext_pix_format {} priv_magic {}; range ",
            raw.width,
            raw.height,
            raw.colorspace,
            raw.ycbcr_enc,
            raw.quantization,
            raw.xfer_func,
            u8::from(raw.ext_pix_format_supported),
            u8::from(raw.priv_ == v4l_sys::V4L2_PIX_FMT_PRIV_MAGIC),
        )?;
        match crate::yuyv_exposure::limited_range_eligibility(raw) {
            Ok(eligible) => write!(f, "limited, encoding {}", eligible.effective_encoding),
            Err(refusal) => write!(f, "refused: {refusal:?}"),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::yuyv_exposure::MetadataRefusal;

    /// A field's name and a change to that field alone.
    type FieldChange = (&'static str, fn(&mut RawYuyvFormat));

    /// What one `VIDIOC_ENUM_FMT` index answers.
    #[derive(Clone, Copy)]
    enum Entry {
        Format([u8; 4]),
        Errno(i32),
        WrongIndex,
        WrongType,
    }

    /// Injected fd reads. Indices past `list` answer `after`; every read is
    /// counted so a test can see which ran.
    struct FakeReads {
        list: Vec<Entry>,
        after: Entry,
        attested: bool,
        raw: std::cell::RefCell<std::collections::VecDeque<Result<RawYuyvFormat, i32>>>,
        raw_default: Result<RawYuyvFormat, i32>,
        node: std::cell::Cell<Result<NodeIdentity, i32>>,
        list_reads: std::cell::Cell<u32>,
        attestation_reads: std::cell::Cell<u32>,
        raw_reads: std::cell::Cell<u32>,
    }

    impl FakeReads {
        fn attested_yuyv() -> Self {
            Self {
                list: vec![Entry::Format(*b"YUYV")],
                after: Entry::Errno(libc::EINVAL),
                attested: true,
                raw: std::cell::RefCell::default(),
                raw_default: Ok(t480_raw()),
                node: std::cell::Cell::new(Ok(NODE)),
                list_reads: std::cell::Cell::new(0),
                attestation_reads: std::cell::Cell::new(0),
                raw_reads: std::cell::Cell::new(0),
            }
        }
    }

    impl FormatReads for FakeReads {
        fn listed_format(&self, index: u32) -> std::io::Result<v4l_sys::v4l2_fmtdesc> {
            self.list_reads.set(self.list_reads.get() + 1);
            let entry = self.list.get(index as usize).copied().unwrap_or(self.after);
            // SAFETY: integers and byte arrays only; all-zero is valid.
            let mut desc: v4l_sys::v4l2_fmtdesc = unsafe { std::mem::zeroed() };
            desc.index = index;
            desc.type_ = CAPTURE;
            match entry {
                Entry::Format(fourcc) => desc.pixelformat = u32::from_le_bytes(fourcc),
                Entry::Errno(errno) => return Err(std::io::Error::from_raw_os_error(errno)),
                Entry::WrongIndex => desc.index = index + 1,
                Entry::WrongType => desc.type_ = v4l_sys::v4l2_buf_type_V4L2_BUF_TYPE_META_CAPTURE,
            }
            Ok(desc)
        }

        fn descriptor_attested(&self) -> bool {
            self.attestation_reads.set(self.attestation_reads.get() + 1);
            self.attested
        }

        fn raw_format(&self) -> std::io::Result<RawYuyvFormat> {
            self.raw_reads.set(self.raw_reads.get() + 1);
            self.raw
                .borrow_mut()
                .pop_front()
                .unwrap_or(self.raw_default)
                .map_err(std::io::Error::from_raw_os_error)
        }

        fn node(&self) -> std::io::Result<NodeIdentity> {
            self.node.get().map_err(std::io::Error::from_raw_os_error)
        }
    }

    const NODE: NodeIdentity = NodeIdentity {
        rdev: 0x5100,
        dev: 6,
        ino: 812,
    };

    /// The tuple ADR-0031 §4 records for the T480: YUYV 340x340, default
    /// quantization, BT.601 encoding, with the extended fields defined.
    fn t480_raw() -> RawYuyvFormat {
        RawYuyvFormat {
            buffer_type: CAPTURE,
            width: 340,
            height: 340,
            fourcc: *b"YUYV",
            field: v4l_sys::v4l2_field_V4L2_FIELD_NONE,
            bytesperline: 680,
            sizeimage: 680 * 340,
            colorspace: v4l_sys::v4l2_colorspace_V4L2_COLORSPACE_SRGB,
            priv_: v4l_sys::V4L2_PIX_FMT_PRIV_MAGIC,
            flags: 0,
            ycbcr_enc: v4l_sys::v4l2_ycbcr_encoding_V4L2_YCBCR_ENC_601,
            quantization: v4l_sys::v4l2_quantization_V4L2_QUANTIZATION_DEFAULT,
            xfer_func: v4l_sys::v4l2_xfer_func_V4L2_XFER_FUNC_709,
            ext_pix_format_supported: true,
        }
    }

    /// The readback the v4l wrapper makes of `raw`, through the same
    /// conversion `Capture::format` uses.
    fn wrapper(raw: &RawYuyvFormat) -> v4l::Format {
        // SAFETY: integers and a union of integers only; all-zero is valid.
        let mut pix: v4l_sys::v4l2_pix_format = unsafe { std::mem::zeroed() };
        pix.width = raw.width;
        pix.height = raw.height;
        pix.pixelformat = u32::from_le_bytes(raw.fourcc);
        pix.field = raw.field;
        pix.bytesperline = raw.bytesperline;
        pix.sizeimage = raw.sizeimage;
        pix.colorspace = raw.colorspace;
        pix.priv_ = raw.priv_;
        pix.flags = raw.flags;
        pix.__bindgen_anon_1.ycbcr_enc = raw.ycbcr_enc;
        pix.quantization = raw.quantization;
        pix.xfer_func = raw.xfer_func;
        v4l::Format::from(pix)
    }

    // The format list (slice B, first row of the 2026-10-01 design).

    #[test]
    fn e01_a_list_ended_by_einval_is_complete() {
        let reads = FakeReads::attested_yuyv();
        assert_eq!(
            listed_formats(|index| reads.listed_format(index)),
            Ok(vec![*b"YUYV"])
        );
        assert_eq!(reads.list_reads.get(), 2, "one entry and its EINVAL");
    }

    #[test]
    fn e02_an_error_at_index_zero_is_not_an_empty_list() {
        let mut reads = FakeReads::attested_yuyv();
        reads.list = vec![Entry::Errno(libc::EIO)];
        assert_eq!(
            listed_formats(|index| reads.listed_format(index)),
            Err(ListIncomplete::Failed {
                index: 0,
                errno: Some(libc::EIO)
            })
        );
    }

    #[test]
    fn e03_yuyv_followed_by_an_error_does_not_prove_yuyv_only() {
        let mut reads = FakeReads::attested_yuyv();
        reads.after = Entry::Errno(libc::EIO);
        assert_eq!(
            listed_formats(|index| reads.listed_format(index)),
            Err(ListIncomplete::Failed {
                index: 1,
                errno: Some(libc::EIO)
            })
        );
        assert_eq!(
            FormatEvidence::bind(&reads, &wrapper(&t480_raw())),
            Err(BindRefusal::List(ListIncomplete::Failed {
                index: 1,
                errno: Some(libc::EIO)
            }))
        );
        assert_eq!(
            reads.attestation_reads.get(),
            0,
            "no attestation for an incomplete list"
        );
    }

    #[test]
    fn e04_einval_at_index_zero_is_an_empty_list_and_refuses() {
        let mut reads = FakeReads::attested_yuyv();
        reads.list = Vec::new();
        assert_eq!(
            listed_formats(|index| reads.listed_format(index)),
            Ok(Vec::new())
        );
        assert_eq!(
            FormatEvidence::bind(&reads, &wrapper(&t480_raw())),
            Err(BindRefusal::NotYuyvOnly)
        );
    }

    #[test]
    fn e05_a_list_that_never_ends_is_incomplete() {
        let mut reads = FakeReads::attested_yuyv();
        reads.after = Entry::Format(*b"YUYV");
        assert_eq!(
            listed_formats(|index| reads.listed_format(index)),
            Err(ListIncomplete::Unterminated)
        );
        assert_eq!(reads.list_reads.get(), MAX_LISTED_FORMATS);
    }

    #[test]
    fn e06_an_answer_for_another_index_or_type_is_malformed() {
        for (entry, at) in [(Entry::WrongIndex, 0), (Entry::WrongType, 1)] {
            let mut reads = FakeReads::attested_yuyv();
            reads.list = vec![Entry::Format(*b"YUYV"); at as usize];
            reads.list.push(entry);
            assert_eq!(
                listed_formats(|index| reads.listed_format(index)),
                Err(ListIncomplete::Malformed { index: at })
            );
        }
    }

    #[test]
    fn e07_another_format_beside_yuyv_refuses_before_the_descriptor_read() {
        for list in [
            vec![Entry::Format(*b"YUYV"), Entry::Format(*b"MJPG")],
            vec![Entry::Format(*b"GREY")],
            vec![Entry::Format(*b"NV12"), Entry::Format(*b"YUYV")],
        ] {
            let mut reads = FakeReads::attested_yuyv();
            reads.list = list;
            assert_eq!(
                FormatEvidence::bind(&reads, &wrapper(&t480_raw())),
                Err(BindRefusal::NotYuyvOnly)
            );
            assert_eq!(reads.attestation_reads.get(), 0);
            assert_eq!(reads.raw_reads.get(), 0);
        }
    }

    #[test]
    fn e08_a_repeated_yuyv_entry_is_still_yuyv_only() {
        let mut reads = FakeReads::attested_yuyv();
        reads.list = vec![Entry::Format(*b"YUYV"), Entry::Format(*b"YUYV")];
        assert!(FormatEvidence::bind(&reads, &wrapper(&t480_raw())).is_ok());
    }

    // Binding.

    #[test]
    fn b01_an_attested_yuyv_only_node_freezes_the_raw_tuple_it_read() {
        let reads = FakeReads::attested_yuyv();
        let evidence = FormatEvidence::bind(&reads, &wrapper(&t480_raw())).expect("binds");
        assert_eq!(evidence.raw, t480_raw());
        assert_eq!(evidence.node, NODE);
        assert_eq!(reads.attestation_reads.get(), 1);
        assert_eq!(reads.raw_reads.get(), 1);
    }

    #[test]
    fn b02_a_refused_descriptor_refuses_before_the_raw_read() {
        let mut reads = FakeReads::attested_yuyv();
        reads.attested = false;
        assert_eq!(
            FormatEvidence::bind(&reads, &wrapper(&t480_raw())),
            Err(BindRefusal::NotAttested)
        );
        assert_eq!(reads.raw_reads.get(), 0);
    }

    #[test]
    fn b03_a_failed_raw_read_or_fstat_refuses() {
        let reads = FakeReads::attested_yuyv();
        reads.raw.borrow_mut().push_back(Err(libc::ENOTTY));
        assert_eq!(
            FormatEvidence::bind(&reads, &wrapper(&t480_raw())),
            Err(BindRefusal::RawRead {
                errno: Some(libc::ENOTTY)
            })
        );

        let reads = FakeReads::attested_yuyv();
        reads.node.set(Err(libc::EBADF));
        assert_eq!(
            FormatEvidence::bind(&reads, &wrapper(&t480_raw())),
            Err(BindRefusal::Node {
                errno: Some(libc::EBADF)
            })
        );
        assert_eq!(reads.list_reads.get(), 0);
    }

    /// Every field the wrapper keeps must agree with the negotiation; the
    /// raw read is the one that differs here, as a driver answering two
    /// reads differently would.
    #[test]
    fn b04_each_wrapper_field_that_disagrees_refuses_by_name() {
        let negotiated = wrapper(&t480_raw());
        let cases: [FieldChange; 11] = [
            ("type", |raw| {
                raw.buffer_type = v4l_sys::v4l2_buf_type_V4L2_BUF_TYPE_VIDEO_OUTPUT;
            }),
            ("fourcc", |raw| raw.fourcc = *b"UYVY"),
            ("width", |raw| raw.width = 640),
            ("height", |raw| raw.height = 480),
            ("field", |raw| {
                raw.field = v4l_sys::v4l2_field_V4L2_FIELD_TOP
            }),
            ("bytesperline", |raw| raw.bytesperline = 688),
            ("sizeimage", |raw| raw.sizeimage += 1),
            ("colorspace", |raw| {
                raw.colorspace = v4l_sys::v4l2_colorspace_V4L2_COLORSPACE_REC709;
            }),
            ("flags", |raw| {
                raw.flags = v4l_sys::V4L2_PIX_FMT_FLAG_PREMUL_ALPHA;
            }),
            ("quantization", |raw| {
                raw.quantization = v4l_sys::v4l2_quantization_V4L2_QUANTIZATION_LIM_RANGE;
            }),
            ("xfer_func", |raw| {
                raw.xfer_func = v4l_sys::v4l2_xfer_func_V4L2_XFER_FUNC_SRGB;
            }),
        ];
        for (field, change) in cases {
            let reads = FakeReads::attested_yuyv();
            let mut raw = t480_raw();
            change(&mut raw);
            reads.raw.borrow_mut().push_back(Ok(raw));
            assert_eq!(
                FormatEvidence::bind(&reads, &negotiated),
                Err(BindRefusal::Disagrees { field }),
                "{field}"
            );
        }
    }

    /// The fields the wrapper drops are frozen as read, whatever the range
    /// verdict on them: binding judges the fd, the range check judges the
    /// tuple.
    #[test]
    fn b05_fields_the_wrapper_drops_bind_as_read_and_are_judged_later() {
        let mut raw = t480_raw();
        raw.ycbcr_enc = v4l_sys::v4l2_ycbcr_encoding_V4L2_YCBCR_ENC_XV601;
        let reads = FakeReads::attested_yuyv();
        reads.raw.borrow_mut().push_back(Ok(raw));
        let evidence = FormatEvidence::bind(&reads, &wrapper(&t480_raw())).expect("binds");
        assert_eq!(evidence.raw.ycbcr_enc, raw.ycbcr_enc);
        assert_eq!(
            crate::yuyv_exposure::limited_range_eligibility(&evidence.raw),
            Err(MetadataRefusal::ExtendedGamut)
        );

        let mut raw = t480_raw();
        raw.priv_ = 0;
        raw.ext_pix_format_supported = false;
        let reads = FakeReads::attested_yuyv();
        reads.raw.borrow_mut().push_back(Ok(raw));
        let evidence = FormatEvidence::bind(&reads, &wrapper(&t480_raw())).expect("binds");
        assert_eq!(evidence.raw, raw);
        assert!(matches!(
            crate::yuyv_exposure::limited_range_eligibility(&evidence.raw),
            Err(MetadataRefusal::Unresolved(_))
        ));
    }

    /// A flag bit the pinned wrapper does not know, such as
    /// `V4L2_PIX_FMT_FLAG_SET_CSC`, is absent from its readback of the same
    /// answer. It binds, is frozen in the whole raw word, and losing it later
    /// is drift.
    #[test]
    fn b06_a_flag_bit_the_wrapper_drops_binds_and_is_frozen_whole() {
        let mut raw = t480_raw();
        raw.flags = v4l_sys::V4L2_PIX_FMT_FLAG_SET_CSC;
        let negotiated = wrapper(&raw);
        assert_eq!(negotiated.flags.bits(), 0, "the wrapper truncates the bit");
        let reads = FakeReads::attested_yuyv();
        reads.raw.borrow_mut().push_back(Ok(raw));
        let evidence = FormatEvidence::bind(&reads, &negotiated).expect("binds");
        assert_eq!(evidence.raw.flags, v4l_sys::V4L2_PIX_FMT_FLAG_SET_CSC);

        reads.raw.borrow_mut().push_back(Ok(t480_raw()));
        match evidence.recheck(&reads) {
            Err(FormatDrift::Moved {
                field: "flags",
                now: 0,
                frozen,
            }) => assert_eq!(frozen, v4l_sys::V4L2_PIX_FMT_FLAG_SET_CSC),
            other => panic!("{other:?}"),
        }
    }

    // Rechecks at a stream boundary.

    fn bound(reads: &FakeReads) -> FormatEvidence {
        FormatEvidence::bind(reads, &wrapper(&t480_raw())).expect("binds")
    }

    #[test]
    fn r01_an_unchanged_fd_rechecks_clean_every_time() {
        let reads = FakeReads::attested_yuyv();
        let evidence = bound(&reads);
        for _ in 0..4 {
            evidence.recheck(&reads).expect("unchanged");
        }
        assert_eq!(reads.raw_reads.get(), 5);
    }

    /// Every field of the raw tuple is compared, including the four the
    /// wrapper cannot see.
    #[test]
    fn r02_each_raw_field_that_moves_is_named() {
        let cases: [FieldChange; 14] = [
            ("type", |raw| raw.buffer_type += 1),
            ("fourcc", |raw| raw.fourcc = *b"YVYU"),
            ("width", |raw| raw.width += 2),
            ("height", |raw| raw.height += 1),
            ("field", |raw| raw.field += 1),
            ("bytesperline", |raw| raw.bytesperline += 4),
            ("sizeimage", |raw| raw.sizeimage += 1),
            ("colorspace", |raw| raw.colorspace += 1),
            ("priv", |raw| raw.priv_ = 0),
            ("flags", |raw| raw.flags = 2),
            ("ycbcr_enc", |raw| raw.ycbcr_enc += 1),
            ("quantization", |raw| raw.quantization += 1),
            ("xfer_func", |raw| raw.xfer_func += 1),
            ("ext_pix_format", |raw| raw.ext_pix_format_supported = false),
        ];
        for (field, change) in cases {
            let reads = FakeReads::attested_yuyv();
            let evidence = bound(&reads);
            let mut moved = t480_raw();
            change(&mut moved);
            reads.raw.borrow_mut().push_back(Ok(moved));
            match evidence.recheck(&reads) {
                Err(FormatDrift::Moved { field: named, .. }) => assert_eq!(named, field),
                other => panic!("{field}: {other:?}"),
            }
        }
    }

    /// An encoding change that leaves the range as it was is still drift:
    /// equal nominal range is not format identity (slice A, R14).
    #[test]
    fn r03_encoding_only_drift_with_the_same_range_refuses_with_its_values() {
        let reads = FakeReads::attested_yuyv();
        let evidence = bound(&reads);
        let mut moved = t480_raw();
        moved.ycbcr_enc = v4l_sys::v4l2_ycbcr_encoding_V4L2_YCBCR_ENC_709;
        assert_eq!(
            crate::yuyv_exposure::classify_reported_range(&moved),
            crate::yuyv_exposure::ReportedRange::Limited {
                effective_encoding: moved.ycbcr_enc
            }
        );
        reads.raw.borrow_mut().push_back(Ok(moved));
        let drift = evidence.recheck(&reads).expect_err("drift");
        assert_eq!(
            drift.to_string(),
            format!(
                "raw ycbcr_enc is now {}, frozen at open as {}",
                v4l_sys::v4l2_ycbcr_encoding_V4L2_YCBCR_ENC_709,
                v4l_sys::v4l2_ycbcr_encoding_V4L2_YCBCR_ENC_601
            )
        );
    }

    #[test]
    fn r04_another_node_or_a_failed_read_refuses() {
        let reads = FakeReads::attested_yuyv();
        let evidence = bound(&reads);
        reads.node.set(Ok(NodeIdentity { ino: 813, ..NODE }));
        assert!(matches!(evidence.recheck(&reads), Err(FormatDrift::Node)));
        reads.node.set(Ok(NodeIdentity {
            rdev: 0x5101,
            ..NODE
        }));
        assert!(matches!(evidence.recheck(&reads), Err(FormatDrift::Node)));
        reads.node.set(Err(libc::EBADF));
        assert!(matches!(
            evidence.recheck(&reads),
            Err(FormatDrift::Read(_))
        ));

        let reads = FakeReads::attested_yuyv();
        let evidence = bound(&reads);
        reads.raw.borrow_mut().push_back(Err(libc::ENODEV));
        match evidence.recheck(&reads) {
            Err(FormatDrift::Read(error)) => {
                assert_eq!(error.raw_os_error(), Some(libc::ENODEV));
            }
            other => panic!("{other:?}"),
        }
    }

    // The wire copy.

    #[test]
    fn w01_the_wire_copy_keeps_every_field_and_the_encoding_union() {
        // SAFETY: integers and a union of integers only; all-zero is valid.
        let mut pix: v4l_sys::v4l2_pix_format = unsafe { std::mem::zeroed() };
        pix.width = 1;
        pix.height = 2;
        pix.pixelformat = u32::from_le_bytes(*b"YUYV");
        pix.field = 3;
        pix.bytesperline = 4;
        pix.sizeimage = 5;
        pix.colorspace = 6;
        pix.priv_ = 7;
        pix.flags = 8;
        pix.__bindgen_anon_1.ycbcr_enc = 9;
        pix.quantization = 10;
        pix.xfer_func = 11;
        // SAFETY: integers and unions of integers only; all-zero is valid.
        let mut wire: v4l_sys::v4l2_format = unsafe { std::mem::zeroed() };
        wire.type_ = CAPTURE;
        wire.fmt.pix = pix;
        for ext in [true, false] {
            assert_eq!(
                raw_from_wire(&wire, ext),
                RawYuyvFormat {
                    buffer_type: CAPTURE,
                    width: 1,
                    height: 2,
                    fourcc: *b"YUYV",
                    field: 3,
                    bytesperline: 4,
                    sizeimage: 5,
                    colorspace: 6,
                    priv_: 7,
                    flags: 8,
                    ycbcr_enc: 9,
                    quantization: 10,
                    xfer_func: 11,
                    ext_pix_format_supported: ext,
                }
            );
        }
    }

    #[test]
    fn w02_the_journal_line_names_the_tuple_and_the_range_verdict() {
        let reads = FakeReads::attested_yuyv();
        assert_eq!(
            bound(&reads).to_string(),
            format!(
                "340x340 colorspace {} ycbcr_enc {} quantization 0 xfer_func {} \
                 ext_pix_format 1 priv_magic 1; range limited, encoding {}",
                v4l_sys::v4l2_colorspace_V4L2_COLORSPACE_SRGB,
                v4l_sys::v4l2_ycbcr_encoding_V4L2_YCBCR_ENC_601,
                v4l_sys::v4l2_xfer_func_V4L2_XFER_FUNC_709,
                v4l_sys::v4l2_ycbcr_encoding_V4L2_YCBCR_ENC_601,
            )
        );
        let mut raw = t480_raw();
        raw.quantization = v4l_sys::v4l2_quantization_V4L2_QUANTIZATION_FULL_RANGE;
        let reads = FakeReads::attested_yuyv();
        reads.raw.borrow_mut().push_back(Ok(raw));
        let evidence = FormatEvidence::bind(&reads, &wrapper(&raw)).expect("binds");
        assert!(
            evidence.to_string().ends_with("; range refused: FullRange"),
            "{evidence}"
        );
    }
}

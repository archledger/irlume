// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright the irlume contributors.

//! The camera's own answer to "was the illuminator on for this frame?".
//!
//! irlume used to decide which IR frames were lit by averaging pixels and
//! comparing against a fixed threshold. A dark room, an empty chair, and a
//! camera with no working emitter all produce the same reading, and on the
//! development machine a lit frame measured 38.9 against a threshold of 40, so
//! the answer turned on a rounding error. Under #159 that guess was also
//! permission to write guessed values to camera firmware, which destroyed a
//! reporter's camera; 0.7.1 removed the writing, and this removes the guess.
//!
//! Microsoft's UVC 1.5 extensions define `MetadataId_FrameIllumination`, a
//! 16-byte record carried across a frame's payload headers, whose first
//! flag bit says whether the illuminator fired. In D1 (alternative frame
//! illumination), the mode `ir_emitter` selects, the camera is required to
//! strobe the illuminator and mark each frame. irlume already asks for that
//! mode. It simply never read the marks.
//!
//! # What was measured, on an ASUS IR module under kernel 7.1.5
//!
//! - `V4L2_META_FMT_UVC_MSXU_1_5` (`UVCM`) is offered on the metadata node
//!   paired with the IR streaming interface, and `VIDIOC_S_FMT` accepts it.
//!   `v4l2-ctl --set-fmt-meta=pixelformat=UVCM` does NOT work and reports no
//!   error, which is why this was previously believed unavailable.
//! - **The metadata queue must be streaming before the image queue starts.**
//!   Starting video first produced zero metadata bytes over 25 seconds.
//!   `open` therefore issues `STREAMON` itself, and the caller must call it
//!   before the first image dequeue.
//! - Every image buffer's `timestamp` equalled its metadata buffer's
//!   `timestamp` exactly, across 24 of 24 frames, and the sequence numbers
//!   matched 1:1. Timestamp is the key used here; dequeue order is not.
//! - The first frame after `STREAMON` carries no illumination record at all
//!   (a 12-byte header with nothing appended). Absence is per-frame and normal.
//! - The selected metadata format persists after close, so it is restored on
//!   drop rather than left changed for the next process on the device.
//!
//! # Three cameras, three answers
//!
//! - ASUS IR module and NexiGo HelloCam N930W: `UVCM` accepted, and every frame
//!   of a burst carries a record. These are the cameras the path exists for.
//! - Lenovo Integrated Camera (RGB only, no illuminator): `UVCM` accepted and
//!   metadata buffers delivered, correlated 12 of 12, carrying **no
//!   illumination record at all**. Offering the format is not a promise to
//!   report illumination, so an absent record means "the camera did not say",
//!   never "the illuminator was off". `parse_illumination` returns `None` here
//!   and the burst keeps its brightness rule.
//!
//! A camera with no metadata node at all (v4l2loopback, for one) is the fourth
//! case, and lands on the same fallback.
//!
//! # Failure policy
//!
//! Every step here is best-effort. A camera without a metadata node, without
//! `UVCM`, or that refuses any of these ioctls is not an error: `open` returns
//! `None` and the caller keeps its brightness heuristic. Authentication must
//! never fail because a camera declined to describe itself.

use libc::c_int;

/// `V4L2_BUF_TYPE_META_CAPTURE`.
const META_CAPTURE: u32 = 13;
/// `V4L2_MEMORY_MMAP`.
const MEMORY_MMAP: u32 = 1;
/// `V4L2_META_FMT_UVC_MSXU_1_5`, four character code `UVCM`.
const UVCM: u32 = fourcc(b"UVCM");
/// `V4L2_META_FMT_UVC`, four character code `UVCH`. The kernel's default and
/// what a device falls back to when it does not recognise a requested format,
/// which makes it the value that proves a request was refused.
#[cfg(test)]
const UVCH: u32 = fourcc(b"UVCH");

/// `MetadataId_FrameIllumination` from Microsoft's UVC extensions.
const METADATA_ID_FRAME_ILLUMINATION: u32 = 6;

/// Ring size for metadata buffers.
///
/// Larger than the image ring because metadata is drained opportunistically
/// between image dequeues rather than in its own loop; a few frames of slack
/// costs 1MiB per buffer and avoids losing records to a slow burst iteration.
const META_BUFFERS: u32 = 8;
/// uvcvideo records one block per payload header and completes a metadata
/// buffer only together with an image frame, so the first buffer collects
/// every header sent while the sensor starts: 54 KiB on a Logitech BRIO and up
/// to 68 KiB on a NexiGo N930W, against 4-10 KiB per steady-state frame. The
/// count is unbounded by the device, and no descriptor reports it reliably, so
/// ask for several seconds of start-up headroom. Linux before v7.1 ignores the
/// request and keeps its fixed 10 KiB; whatever is negotiated is what is used.
const REQUESTED_META_BUFFER_SIZE: u32 = 1024 * 1024;

// Application allocation ceiling, not a UVC wire limit. Startup requests
// REQUESTED_META_BUFFER_SIZE, but refuse unexpectedly large negotiated buffers
// before allocating a ring. A larger original snapshot can still be restored.
const MAX_META_BUFFER_SIZE: u32 = 1024 * 1024;

const fn fourcc(c: &[u8; 4]) -> u32 {
    (c[0] as u32) | ((c[1] as u32) << 8) | ((c[2] as u32) << 16) | ((c[3] as u32) << 24)
}

/// `struct v4l2_format`.
///
/// The union is 200 bytes and 8-byte aligned (it embeds `v4l2_window`, whose
/// `__user` pointers force the alignment), so the payload starts at offset 8
/// and the whole struct is 208 bytes. Getting this wrong does not fail loudly:
/// the size is encoded in the ioctl request number, so every call returns
/// ENOTTY, which reads exactly like a device that does not support metadata.
/// The assertion below is the guard against that.
/// `align(8)` is explicit because this Rust struct spells the union out as
/// plain `u32`s and would otherwise align to 4, unlike the C type it stands in
/// for.
#[repr(C, align(8))]
struct V4l2Format {
    kind: u32,
    _pad: u32,
    /// `struct v4l2_meta_format { __u32 dataformat; __u32 buffersize; __u32
    /// width; __u32 height; __u32 bytesperline; }` packed, followed by the rest
    /// of the 200-byte union. Only the first two are set: the three line-based
    /// fields do not apply to UVC metadata. The union is 200 bytes whichever
    /// fields the kernel adds, so the layout below is unaffected by the three
    /// that arrived after this comment was first written.
    dataformat: u32,
    buffersize: u32,
    _rest: [u8; 192],
}
const _: () = assert!(core::mem::size_of::<V4l2Format>() == 208);
const _: () = assert!(core::mem::align_of::<V4l2Format>() == 8);

/// `struct v4l2_requestbuffers`.
#[repr(C)]
struct V4l2RequestBuffers {
    count: u32,
    kind: u32,
    memory: u32,
    capabilities: u32,
    flags: u8,
    _reserved: [u8; 3],
}
const _: () = assert!(core::mem::size_of::<V4l2RequestBuffers>() == 20);

/// `struct timeval` on 64-bit Linux.
#[repr(C)]
#[derive(Clone, Copy, Default)]
struct Timeval {
    sec: i64,
    usec: i64,
}

/// `struct v4l2_timecode`.
#[repr(C)]
#[derive(Clone, Copy, Default)]
struct V4l2Timecode {
    kind: u32,
    flags: u32,
    frames: u8,
    seconds: u8,
    minutes: u8,
    hours: u8,
    userbits: [u8; 4],
}

/// `struct v4l2_buffer`.
#[repr(C)]
struct V4l2Buffer {
    index: u32,
    kind: u32,
    bytesused: u32,
    flags: u32,
    field: u32,
    _pad: u32,
    timestamp: Timeval,
    timecode: V4l2Timecode,
    sequence: u32,
    memory: u32,
    /// The `m` union; only `offset` is used, and only with `V4L2_MEMORY_MMAP`.
    offset: u32,
    _m_pad: u32,
    length: u32,
    _reserved2: u32,
    _reserved: u32,
    _tail_pad: u32,
}
const _: () = assert!(core::mem::size_of::<V4l2Buffer>() == 88);

const fn iowr(nr: libc::c_ulong, size: usize) -> libc::c_ulong {
    const DIR_RW: libc::c_ulong = 3;
    (DIR_RW << 30) | ((size as libc::c_ulong) << 16) | ((b'V' as libc::c_ulong) << 8) | nr
}

const fn iow(nr: libc::c_ulong, size: usize) -> libc::c_ulong {
    const DIR_W: libc::c_ulong = 1;
    (DIR_W << 30) | ((size as libc::c_ulong) << 16) | ((b'V' as libc::c_ulong) << 8) | nr
}

fn vidioc_g_fmt() -> libc::c_ulong {
    iowr(4, core::mem::size_of::<V4l2Format>())
}
fn vidioc_s_fmt() -> libc::c_ulong {
    iowr(5, core::mem::size_of::<V4l2Format>())
}
fn vidioc_reqbufs() -> libc::c_ulong {
    iowr(8, core::mem::size_of::<V4l2RequestBuffers>())
}
fn vidioc_querybuf() -> libc::c_ulong {
    iowr(9, core::mem::size_of::<V4l2Buffer>())
}
fn vidioc_qbuf() -> libc::c_ulong {
    iowr(15, core::mem::size_of::<V4l2Buffer>())
}
fn vidioc_dqbuf() -> libc::c_ulong {
    iowr(17, core::mem::size_of::<V4l2Buffer>())
}
fn vidioc_streamon() -> libc::c_ulong {
    iow(18, core::mem::size_of::<c_int>())
}
fn vidioc_streamoff() -> libc::c_ulong {
    iow(19, core::mem::size_of::<c_int>())
}

// ---------------------------------------------------------------------------
// Parsing. Pure; lifecycle fault injection is tested separately below.
// ---------------------------------------------------------------------------

/// One frame's worth of illumination, as the camera reported it.
///
/// Public for the fuzz harness only (#568); production consumers go through
/// the capture path.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Illumination {
    /// The illuminator fired for this frame.
    Lit,
    /// The illuminator did not fire; this frame is the ambient exposure.
    Dark,
}

/// Read the illumination flag out of one metadata buffer.
///
/// uvcvideo hands each buffer as `struct uvc_meta_buf`, packed:
///
/// ```text
/// __u64 ns; __u16 sof; __u8 length; __u8 flags; __u8 buf[];
/// ```
///
/// where `length` is the payload header's `bHeaderLength` and `flags` its
/// `bmHeaderInfo`, so `buf` carries the remaining `length - 2` bytes. The
/// standard part of the header is 2 bytes plus 4 for a presentation timestamp
/// and 6 for a source clock reference, each present only if `bmHeaderInfo`
/// says so. Concatenate the extra bytes from all payload headers in this
/// frame before reading Microsoft's records, each an 8-byte little-endian
/// `{id, size}` followed by its body (Microsoft UVC extensions, section 2.2.3.2).
///
/// A record may cross any payload boundary. Unknown items are skipped by their
/// whole size, including opaque bytes that resemble an illumination item.
/// Validate the entire stream before returning evidence: malformed tails, UVC
/// errors, conflicting frame IDs, continuation after EOF and contradictory
/// illumination records make the frame unknown. EOF itself is optional.
/// Assembly is local to this call, never shared across V4L2 frame buffers.
///
/// Returns `None` when the buffer carries no illumination record, which is
/// normal for the first frame after `STREAMON` and must not be read as "dark".
///
/// Public for the fuzz harness only (#568): uvcvideo permits partial first
/// metadata buffers (fixed only in the 6.12.97-era "Avoid partial metadata
/// buffers" series), and a camera is external hardware, so this parses
/// attacker-reachable bytes for a root daemon and must never panic.
pub fn parse_illumination(buf: &[u8]) -> Option<Illumination> {
    const FID: u8 = 1;
    const EOF: u8 = 1 << 1;
    const PTS: u8 = 1 << 2;
    const SCR: u8 = 1 << 3;
    const ERR: u8 = 1 << 6;
    // Allocation is bounded by supplied bytes, never by a device-declared item
    // size. Production passes at most one mapped metadata buffer.
    let mut extra = Vec::new();
    extra.try_reserve_exact(buf.len()).ok()?;
    let mut at = 0usize;
    let mut fid = None;
    let mut ended = false;
    while at < buf.len() {
        let body_start = at.checked_add(UVC_META_BUF_HEADER)?;
        if body_start > buf.len() {
            return None;
        }
        let length = usize::from(buf[at + 10]);
        let flags = buf[at + 11];
        // A header shorter than its own two mandatory bytes is not a header.
        if length < 2 || flags & ERR != 0 {
            return None;
        }
        // An empty preceding image can leave different wire frames in one
        // kernel metadata buffer. The retained headers must agree themselves.
        if ended || fid.is_some_and(|first| first != flags & FID) {
            return None;
        }
        fid = Some(flags & FID);
        ended = flags & EOF != 0;
        let body_end = body_start.checked_add(length - 2)?;
        let body = buf.get(body_start..body_end)?;
        let standard =
            (if flags & PTS != 0 { 4 } else { 0 }) + (if flags & SCR != 0 { 6 } else { 0 });
        extra.extend_from_slice(body.get(standard..)?);
        at = body_end;
    }
    illumination_in_frame(&extra)
}

/// Size of uvcvideo's own per-buffer header, before the UVC payload header's
/// third byte.
const UVC_META_BUF_HEADER: usize = 12;

/// Walk the assembled Microsoft metadata item stream for one frame.
///
/// Require the complete 16-byte FrameIllumination structure and eight-byte
/// item alignment. Preserve compatibility with aligned extensions and unknown
/// flag/reserved bits: only the defined illumination bit is interpreted.
fn illumination_in_frame(extra: &[u8]) -> Option<Illumination> {
    let mut at = 0usize;
    let mut found = None;
    while at < extra.len() {
        let header = extra.get(at..at.checked_add(8)?)?;
        let id = u32::from_le_bytes(header[..4].try_into().ok()?);
        let size = u32::from_le_bytes(header[4..].try_into().ok()?) as usize;
        // A record must at least contain its own header, and must fit. Either
        // failure means this is not a record stream, so stop rather than
        // resynchronise onto whatever the bytes happen to look like.
        if size < 8 || size % 8 != 0 {
            return None;
        }
        let end = at.checked_add(size)?;
        let item = extra.get(at..end)?;
        if id == METADATA_ID_FRAME_ILLUMINATION {
            if size < 16 {
                return None;
            }
            let raw = u32::from_le_bytes(item[8..12].try_into().ok()?);
            let illumination = if raw & 1 != 0 {
                Illumination::Lit
            } else {
                Illumination::Dark
            };
            if found.is_some_and(|previous| previous != illumination) {
                return None;
            }
            found = Some(illumination);
        }
        at = end;
    }
    found
}

fn illumination_in_dequeued_buffer(bytes: &[u8], flags: u32) -> Option<Illumination> {
    const V4L2_BUF_FLAG_ERROR: u32 = 0x0040;
    if flags & V4L2_BUF_FLAG_ERROR != 0 {
        return None;
    }
    parse_illumination(bytes)
}

/// Pick the frame to hand downstream, given what the camera said about each.
///
/// The rule is the brightest frame **among those the camera flagged lit**.
/// Metadata decides eligibility; the existing brightest-of-burst rule chooses
/// within it. That ordering matters for compatibility: in the ordinary case
/// both agree on the same frame, so IR templates enrolled before this change
/// stay comparable, and the only behaviour that changes is that a frame the
/// camera says was dark can no longer win on brightness alone.
///
/// Falls back to the brightest frame overall when no frame was flagged lit,
/// which covers a camera that reports no illumination records at all.
///
/// Public for the fuzz harness only (#568).
pub fn brightest_lit(means: &[f64], flags: &[Option<Illumination>]) -> Option<usize> {
    let eligible = |i: usize| matches!(flags.get(i), Some(Some(Illumination::Lit)));
    let any_lit = (0..means.len()).any(eligible);
    // Strictly-greater keeps the FIRST frame holding the maximum, matching the
    // long-standing incremental scan; `max_by` would keep the last on a tie and
    // silently change which frame is chosen.
    let mut best: Option<(usize, f64)> = None;
    for (i, &m) in means.iter().enumerate() {
        if any_lit && !eligible(i) {
            continue;
        }
        if best.is_none_or(|(_, b)| m > b) {
            best = Some((i, m));
        }
    }
    best.map(|(i, _)| i)
}

/// A gate frame may clip at most this fraction of its pixels before selection
/// prefers a cleaner frame. 5% is the cutoff the ambient-subtract debug line
/// has always used for "blown exposure", and it sits under the smallest
/// clipping measured to move the centre/edge ratio (#221: captures at 0.9-13%
/// read 1.41-1.54, 20.5% read 1.39, 70%+ read 1.11-1.19 against a 1.03 floor).
pub(crate) const CLIPPED_FRAC_MAX: f64 = 0.05;

/// Pick the burst frame the liveness gate and matcher read.
///
/// The brightest frame of a warming burst is precisely the most likely to
/// clip: the first capture after a daemon restart at close range gated a frame
/// with 78.8% of its pixels at the ceiling, the IR detector found no facial
/// structure in it, and a real user was denied as a spoof; the same position
/// one capture later read 12.7% (#221). So among the frames the camera itself
/// flagged lit, take the brightest whose clipped fraction is at most
/// [`CLIPPED_FRAC_MAX`], and when every lit frame clips harder than that, the
/// least clipped one (brightest on a tie): the gate reads the best frame that
/// exists rather than the worst.
///
/// `clipped[i]` is the fraction of frame `i`'s pixels at the sensor ceiling,
/// `None` when the source format cannot say where its ceiling is
/// ([`super::clipping_white_level`]). A missing per-frame entry is treated as
/// fully clipped, never as clean: failure to observe must not authorize.
///
/// Both fallbacks keep the long-standing brightest scan unchanged: without
/// camera illumination flags a strobing burst's cleanest frames are the
/// emitter-OFF ones, so clip-aware selection there would trade a clipped face
/// for no face at all.
pub(crate) fn best_gate_frame(
    means: &[f64],
    flags: &[Option<Illumination>],
    clipped: Option<&[f64]>,
) -> Option<usize> {
    let lit = |i: usize| matches!(flags.get(i), Some(Some(Illumination::Lit)));
    let any_lit = (0..means.len()).any(lit);
    let Some(clipped) = clipped.filter(|_| any_lit) else {
        return brightest_lit(means, flags);
    };
    debug_assert_eq!(clipped.len(), means.len());
    // Strictly-greater keeps the FIRST frame on a mean tie, matching
    // `brightest_lit`'s long-standing scan.
    let mut clean: Option<(usize, f64)> = None;
    let mut least: Option<(usize, f64, f64)> = None; // (index, clipped, mean)
    for (i, &m) in means.iter().enumerate() {
        if !lit(i) {
            continue;
        }
        let c = clipped.get(i).copied().unwrap_or(1.0);
        if c <= CLIPPED_FRAC_MAX && clean.is_none_or(|(_, best)| m > best) {
            clean = Some((i, m));
        }
        if least.is_none_or(|(_, bc, bm)| c < bc || (c == bc && m > bm)) {
            least = Some((i, c, m));
        }
    }
    clean.map(|(i, _)| i).or(least.map(|(i, _, _)| i))
}

/// The IR gate burst's early-exit rule: once the brightest CLEAN,
/// camera-flagged-lit frame is at least two frames behind the head and
/// nothing since has improved on it, the emitter is on a steady plateau
/// (or the strobe's lit phase has already passed) - the remaining frames
/// of the burst cannot produce a better gate frame; they only delay the
/// attempt. The two trailing frames also preserve the ambient-pair window
/// around the chosen frame, so the pairing and saturation evidence keep
/// the neighbors [`ambient_partner`] wants.
///
/// Fires only when BOTH the camera's illumination flags and the format's
/// clip ceiling are measurable: without them "clean" and "lit" are
/// guesses, and the burst must complete exactly as it always did.
pub(crate) fn burst_plateau_reached(
    means: &[f64],
    flags: &[Option<Illumination>],
    clipped: Option<&[f64]>,
) -> bool {
    let Some(clipped) = clipped else {
        return false;
    };
    if means.len() < 3 || flags.len() != means.len() || clipped.len() != means.len() {
        return false;
    }
    let mut best: Option<(usize, f64)> = None;
    for (i, &m) in means.iter().enumerate() {
        if !matches!(flags[i], Some(Illumination::Lit)) {
            continue;
        }
        if clipped[i] <= CLIPPED_FRAC_MAX && best.is_none_or(|(_, b)| m > b) {
            best = Some((i, m));
        }
    }
    let Some((best_i, best_mean)) = best else {
        return false;
    };
    // Two frames after the best exist, and none of them improves on it
    // (a later clean, camera-lit frame with a strictly higher mean would).
    means.len() >= best_i + 3
        && means[best_i + 1..]
            .iter()
            .zip(&flags[best_i + 1..])
            .zip(&clipped[best_i + 1..])
            .all(|((&m, flag), &c)| {
                !(matches!(flag, Some(Illumination::Lit)) && c <= CLIPPED_FRAC_MAX && m > best_mean)
            })
}

/// Pick the ambient partner for `lit_i`: an adjacent frame the camera flagged
/// dark, else the darker of the two neighbours.
///
/// Adjacency is what keeps auto-exposure drift between the pair small, so it is
/// preserved; metadata only settles which neighbour is genuinely the
/// emitter-off exposure instead of inferring it from which one looks darker.
pub(crate) fn ambient_partner(
    lit_i: usize,
    means: &[f64],
    flags: &[Option<Illumination>],
) -> Option<usize> {
    let neighbours: Vec<usize> = [lit_i.checked_sub(1), lit_i.checked_add(1)]
        .into_iter()
        .flatten()
        .filter(|&i| i < means.len())
        .collect();
    let flagged_dark: Vec<usize> = neighbours
        .iter()
        .copied()
        .filter(|&i| matches!(flags.get(i), Some(Some(Illumination::Dark))))
        .collect();
    let pool = if flagged_dark.is_empty() {
        &neighbours
    } else {
        &flagged_dark
    };
    pool.iter()
        .copied()
        .min_by(|&a, &b| means[a].total_cmp(&means[b]))
}

// ---------------------------------------------------------------------------
// The metadata stream itself.
// ---------------------------------------------------------------------------

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct MetadataFormat {
    dataformat: u32,
    buffersize: u32,
}

#[derive(Clone, Copy, Debug)]
enum FormatChange {
    Unchanged,
    // A failed S_FMT does not prove zero mutation, nor does a later G_FMT
    // establish who wrote that state. Keep the snapshot but never guess an undo.
    Uncertain,
    Applied(MetadataFormat),
}

/// A memory-mapped metadata buffer.
struct MappedBuffer {
    ptr: *mut libc::c_void,
    len: usize,
    #[cfg(test)]
    lifecycle: Option<std::sync::Arc<std::sync::Mutex<tests::lifecycle::FakeDevice>>>,
}

// SAFETY: the mapping belongs to this value alone. It is created in
// `request_and_map`, reachable only through the owning `IlluminationLog`, and
// unmapped exactly once in `Drop`. Moving that ownership to another thread
// transfers exclusive access rather than sharing it, which is what the capture
// path does: `IrSession` runs on a scoped thread. Deliberately not `Sync` —
// nothing here is safe to touch from two threads at once.
unsafe impl Send for MappedBuffer {}

impl Drop for MappedBuffer {
    fn drop(&mut self) {
        // SAFETY: ptr/len come from the mmap that created this value and are
        // unmapped exactly once, here.
        unsafe { libc::munmap(self.ptr, self.len) };
        #[cfg(test)]
        if let Some(device) = &self.lifecycle {
            device.lock().unwrap().unmapped();
        }
    }
}

/// A running metadata stream, recording each frame's illumination flag against
/// the buffer timestamp that identifies its image frame.
pub(crate) struct IlluminationLog {
    fd: c_int,
    device: String,
    buffers: Vec<MappedBuffer>,
    /// Illumination by image-buffer timestamp in microseconds. Timestamp
    /// rather than dequeue order or sequence: it was measured identical across
    /// both queues for every frame, and it survives a dropped metadata buffer.
    by_timestamp: std::collections::HashMap<i64, Illumination>,
    /// What the metadata node was set to before we changed it, so it can be
    /// put back; the format persists across close and would otherwise be left
    /// changed for the next process to open this camera.
    restore_format: Option<MetadataFormat>,
    format_change: FormatChange,
    buffers_requested: bool,
    streaming: bool,
    timing: crate::capture_timing::Recorder,
    producer: Option<crate::capture_shutdown::Producer>,
    retired: bool,
    #[cfg(test)]
    sentinel_events: Option<std::sync::Arc<std::sync::Mutex<Vec<&'static str>>>>,
    #[cfg(test)]
    lifecycle: Option<std::sync::Arc<std::sync::Mutex<tests::lifecycle::FakeDevice>>>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum MetadataSelection<'a> {
    Discover,
    Exact(&'a str),
    Absent,
}

impl IlluminationLog {
    pub(crate) fn with_producer(mut self, producer: crate::capture_shutdown::Producer) -> Self {
        self.producer = Some(producer);
        self
    }
    pub(crate) fn with_timing(mut self, timing: crate::capture_timing::Recorder) -> Self {
        self.timing = timing;
        self
    }

    /// Set up and start the metadata queue for the IR node at `ir_device`.
    ///
    /// Must be called before the image stream's first dequeue: uvcvideo
    /// produces no metadata at all if the image queue starts first.
    ///
    /// `None` means this camera cannot report illumination, which is a normal
    /// outcome and not an error.
    pub(crate) fn open(ir_device: &str) -> Option<Self> {
        Self::open_selected(ir_device, MetadataSelection::Discover)
            .ok()
            .flatten()
    }

    pub(crate) fn open_selected(
        ir_device: &str,
        selection: MetadataSelection<'_>,
    ) -> Result<Option<Self>, String> {
        Self::open_selected_with(ir_device, selection, metadata_node_for, Self::open_node)
    }

    fn open_selected_with<T>(
        ir_device: &str,
        selection: MetadataSelection<'_>,
        discover: impl FnOnce(&str) -> Option<String>,
        open: impl FnOnce(&str, &str) -> Result<T, String>,
    ) -> Result<Option<T>, String> {
        match selection {
            MetadataSelection::Discover => {
                let Some(node) = discover(ir_device) else {
                    return Ok(None);
                };
                Ok(open(ir_device, &node).ok())
            }
            MetadataSelection::Absent => Ok(None),
            MetadataSelection::Exact(node) => {
                if std::env::var_os("IRLUME_NO_ILLUM_META").is_some_and(|v| v == "1") {
                    return Err("required illumination metadata is disabled".into());
                }
                open(ir_device, node).map(Some)
            }
        }
    }

    fn open_node(ir_device: &str, node: &str) -> Result<Self, String> {
        // SAFETY: a NUL-terminated path built directly below.
        let path = std::ffi::CString::new(node.as_bytes())
            .map_err(|_| "metadata node path contains NUL".to_string())?;
        #[expect(clippy::undocumented_unsafe_blocks, reason = "doc backlog")]
        let fd = unsafe { libc::open(path.as_ptr(), libc::O_RDWR | libc::O_NONBLOCK) };
        if fd < 0 {
            irlume_common::dlog!(
                "{ir_device}: metadata node {node} would not open; using brightness"
            );
            return Err(format!("metadata node {node} would not open"));
        }
        let mut log = Self::from_fd(fd, node);
        match log.start() {
            Ok(()) => Ok(log),
            Err(why) => {
                irlume_common::dlog!(
                    "{ir_device}: no illumination metadata from {node} ({why}); using brightness"
                );
                Err(why)
            }
        }
    }

    // Takes sole ownership of the already-open fd, including on startup error.
    fn from_fd(fd: c_int, node: &str) -> Self {
        Self {
            fd,
            device: node.to_string(),
            buffers: Vec::new(),
            by_timestamp: std::collections::HashMap::new(),
            restore_format: None,
            format_change: FormatChange::Unchanged,
            buffers_requested: false,
            streaming: false,
            timing: crate::capture_timing::Recorder::default(),
            producer: None,
            retired: false,
            #[cfg(test)]
            sentinel_events: None,
            #[cfg(test)]
            lifecycle: None,
        }
    }

    fn start(&mut self) -> std::result::Result<(), String> {
        let original = self.get_format()?;
        self.restore_format = Some(original);
        self.format_change = FormatChange::Uncertain;
        let got = self.set_format(MetadataFormat {
            dataformat: UVCM,
            buffersize: REQUESTED_META_BUFFER_SIZE,
        })?;
        self.format_change = if got == original {
            FormatChange::Unchanged
        } else {
            FormatChange::Applied(got)
        };
        if got.dataformat != UVCM {
            // The driver coerces an unrecognised format to UVCH rather than
            // failing, so a successful ioctl proves nothing on its own.
            return Err("the device does not accept the UVCM metadata format".into());
        }
        if got.buffersize == 0 || got.buffersize > MAX_META_BUFFER_SIZE {
            return Err("the device negotiated an unsupported metadata buffer size".into());
        }
        self.request_and_map()?;
        self.stream_on()?;
        self.streaming = true;
        Ok(())
    }

    fn get_format(&self) -> std::result::Result<MetadataFormat, String> {
        let mut f = zeroed_format();
        f.kind = META_CAPTURE;
        self.ioctl(
            vidioc_g_fmt(),
            &mut f as *mut _ as *mut libc::c_void,
            "G_FMT",
        )?;
        Ok(MetadataFormat {
            dataformat: f.dataformat,
            buffersize: f.buffersize,
        })
    }

    fn set_format(&self, want: MetadataFormat) -> std::result::Result<MetadataFormat, String> {
        let mut f = zeroed_format();
        f.kind = META_CAPTURE;
        f.dataformat = want.dataformat;
        f.buffersize = want.buffersize;
        self.ioctl(
            vidioc_s_fmt(),
            &mut f as *mut _ as *mut libc::c_void,
            "S_FMT",
        )?;
        Ok(MetadataFormat {
            dataformat: f.dataformat,
            buffersize: f.buffersize,
        })
    }

    fn request_and_map(&mut self) -> std::result::Result<(), String> {
        let mut req = V4l2RequestBuffers {
            count: META_BUFFERS,
            kind: META_CAPTURE,
            memory: MEMORY_MMAP,
            capabilities: 0,
            flags: 0,
            _reserved: [0; 3],
        };
        // Even an allocation error gets fd-scoped REQBUFS(0) cleanup: the
        // driver may have made partial progress before reporting failure.
        self.buffers_requested = true;
        self.ioctl(
            vidioc_reqbufs(),
            &mut req as *mut _ as *mut libc::c_void,
            "REQBUFS",
        )?;
        if req.count == 0 {
            return Err("the device granted no metadata buffers".into());
        }
        if req.count > META_BUFFERS {
            return Err("the device granted too many metadata buffers".into());
        }
        for index in 0..req.count {
            let mut buf = zeroed_buffer(index);
            self.ioctl(
                vidioc_querybuf(),
                &mut buf as *mut _ as *mut libc::c_void,
                "QUERYBUF",
            )?;
            if buf.length == 0 || buf.length > MAX_META_BUFFER_SIZE {
                return Err(format!(
                    "unsupported metadata buffer length at index {index}"
                ));
            }
            self.buffers.push(self.map_buffer(&buf)?);
            let mut q = zeroed_buffer(index);
            self.ioctl(vidioc_qbuf(), &mut q as *mut _ as *mut libc::c_void, "QBUF")?;
        }
        Ok(())
    }

    fn map_buffer(&self, buf: &V4l2Buffer) -> Result<MappedBuffer, String> {
        #[cfg(test)]
        if let Some(device) = &self.lifecycle {
            return tests::lifecycle::map_buffer(device, buf);
        }
        // SAFETY: offset and length are the driver's answer for this index;
        // the mapping is owned by MappedBuffer from here.
        let ptr = unsafe {
            libc::mmap(
                std::ptr::null_mut(),
                buf.length as usize,
                libc::PROT_READ,
                libc::MAP_SHARED,
                self.fd,
                i64::from(buf.offset),
            )
        };
        if ptr == libc::MAP_FAILED {
            return Err(format!("mapping metadata buffer {} failed", buf.index));
        }
        Ok(MappedBuffer {
            ptr,
            len: buf.length as usize,
            #[cfg(test)]
            lifecycle: None,
        })
    }

    fn stream_on(&self) -> std::result::Result<(), String> {
        let mut kind = META_CAPTURE as c_int;
        self.ioctl(
            vidioc_streamon(),
            &mut kind as *mut _ as *mut libc::c_void,
            "STREAMON",
        )
    }

    fn restore_owned_format(&self, buffers_released: bool) {
        let Some(original) = self.restore_format else {
            return;
        };
        let applied = match self.format_change {
            FormatChange::Unchanged => return,
            FormatChange::Uncertain => {
                irlume_common::dlog!(
                    "{}: metadata S_FMT outcome uncertain; original {original:?}; no speculative restore",
                    self.device
                );
                return;
            }
            FormatChange::Applied(applied) => applied,
        };
        let _timing = self
            .timing
            .stage(crate::capture_timing::Stage::MetadataFormat);
        if !buffers_released {
            irlume_common::dlog!(
                "{}: metadata buffers not released; skipping format restore",
                self.device
            );
            return;
        }
        match self.get_format() {
            Ok(current) if current == applied => {}
            Ok(current) => {
                irlume_common::dlog!(
                    "{}: metadata format changed since negotiation ({current:?}); leaving it alone",
                    self.device
                );
                return;
            }
            Err(error) => {
                irlume_common::dlog!("{}: metadata restore read failed: {error}", self.device);
                return;
            }
        }
        // V4L2 has no atomic compare-and-set. This is a best-effort ownership
        // check, not protection against an uncooperative writer racing these
        // ioctls (or replacing the state with identical values).
        match self.set_format(original) {
            Ok(restored) if restored == original => {}
            Ok(restored) => irlume_common::dlog!(
                "{}: metadata restore was adjusted: wanted {original:?}, got {restored:?}",
                self.device
            ),
            Err(error) => irlume_common::dlog!(
                "{}: metadata restore failed ({error}); outcome uncertain, no retry",
                self.device
            ),
        }
    }

    /// Drop the previous burst's records.
    ///
    /// Correlation only ever looks at the burst being captured, and a session
    /// is held across many captures in `irlume-auth`, so without this the map
    /// would grow for the life of the session. Called once before a burst
    /// rather than inside `drain`, which runs per frame.
    pub(crate) fn begin_burst(&mut self) {
        #[cfg(test)]
        if let Some(events) = &self.sentinel_events {
            events
                .lock()
                .unwrap_or_else(|error| error.into_inner())
                .push("metadata-begin-burst");
        }
        self.by_timestamp.clear();
    }

    /// Pull every metadata buffer the driver has ready, without blocking.
    ///
    /// Called between image dequeues rather than from its own thread: the two
    /// queues advance together, so a drain per image frame keeps up, and a
    /// missed record costs one frame's classification rather than a stall.
    pub(crate) fn drain(&mut self) {
        if self.retired || self.producer.as_ref().is_some_and(|p| p.check().is_err()) {
            self.by_timestamp.clear();
            return;
        }
        #[cfg(test)]
        if let Some(events) = &self.sentinel_events {
            events
                .lock()
                .unwrap_or_else(|error| error.into_inner())
                .push("metadata-drain");
            return;
        }
        if !self.streaming {
            return;
        }
        loop {
            let mut buf = zeroed_buffer(0);
            if !self.dequeue_buffer(&mut buf) {
                // EAGAIN simply means nothing is ready yet, which is the
                // ordinary way this loop ends on a non-blocking fd.
                return;
            }
            if buf.flags & v4l::buffer::Flags::ERROR.bits() != 0 {
                // Inspect ioctl metadata before forming any mapped reference.
                // Keep this retired ring until its main producer is quiescent.
                self.retired = true;
                self.by_timestamp.clear();
                return;
            }
            let index = buf.index as usize;
            if let Some(mapped) = self.buffers.get(index) {
                let used = (buf.bytesused as usize).min(mapped.len);
                #[cfg(test)]
                if let Some(device) = &self.lifecycle {
                    device.lock().unwrap().view_created();
                }
                // SAFETY: the driver has handed this buffer back to us and will
                // not touch it until it is re-queued below; `used` is within
                // the mapping.
                let bytes = unsafe { std::slice::from_raw_parts(mapped.ptr as *const u8, used) };
                if let Some(illum) = (buf.bytesused as usize <= mapped.len)
                    .then(|| illumination_in_dequeued_buffer(bytes, buf.flags))
                    .flatten()
                {
                    let us = buf.timestamp.sec * 1_000_000 + buf.timestamp.usec;
                    self.by_timestamp.insert(us, illum);
                }
            }
            let mut again = zeroed_buffer(buf.index);
            if self
                .ioctl(
                    vidioc_qbuf(),
                    &mut again as *mut _ as *mut libc::c_void,
                    "QBUF",
                )
                .is_err()
            {
                // A buffer we cannot return is a buffer the driver will never
                // refill; stop rather than spin on the remaining ones.
                return;
            }
        }
    }

    /// What the camera said about the image frame captured at `timestamp`.
    pub(crate) fn illumination_at(&self, timestamp_us: i64) -> Option<Illumination> {
        self.by_timestamp.get(&timestamp_us).copied()
    }

    fn dequeue_buffer(&self, buf: &mut V4l2Buffer) -> bool {
        #[cfg(test)]
        if self.lifecycle.is_some() {
            return self
                .ioctl(vidioc_dqbuf(), (buf as *mut V4l2Buffer).cast(), "DQBUF")
                .is_ok();
        }
        // SAFETY: buf is a valid, correctly sized v4l2_buffer; fd is ours.
        unsafe {
            libc::ioctl(
                self.fd,
                vidioc_dqbuf(),
                (buf as *mut V4l2Buffer).cast::<libc::c_void>(),
            ) >= 0
        }
    }

    fn ioctl(
        &self,
        request: libc::c_ulong,
        argp: *mut libc::c_void,
        what: &str,
    ) -> std::result::Result<(), String> {
        #[cfg(test)]
        if let Some(device) = &self.lifecycle {
            // SAFETY: callers supply the same typed arguments as for libc::ioctl.
            return unsafe { device.lock().unwrap().ioctl(request, argp, what) };
        }
        // SAFETY: fd is a valid open metadata node owned by self, and argp
        // points at a correctly sized struct for `request`.
        let rc = unsafe { libc::ioctl(self.fd, request, argp) };
        if rc >= 0 {
            return Ok(());
        }
        Err(format!(
            "{what} failed: {}",
            std::io::Error::last_os_error()
        ))
    }

    #[cfg(test)]
    pub(crate) fn test_sentinel(
        events: std::sync::Arc<std::sync::Mutex<Vec<&'static str>>>,
    ) -> Self {
        Self {
            fd: -1,
            device: "test-metadata".into(),
            buffers: Vec::new(),
            by_timestamp: std::collections::HashMap::new(),
            restore_format: None,
            format_change: FormatChange::Unchanged,
            buffers_requested: false,
            streaming: false,
            timing: crate::capture_timing::Recorder::default(),
            producer: None,
            retired: false,
            sentinel_events: Some(events),
            lifecycle: None,
        }
    }
}

impl Drop for IlluminationLog {
    fn drop(&mut self) {
        if let Some(producer) = self.producer.take() {
            if !producer.is_quiescent() {
                // The replacement is inert; the deferred owner has no Producer
                // link, so retention cannot make a reference cycle.
                let owner = std::mem::replace(self, Self::from_fd(-1, "deferred metadata"));
                producer.after_stop(owner);
                return;
            }
        }
        #[cfg(test)]
        if let Some(events) = &self.sentinel_events {
            events
                .lock()
                .unwrap_or_else(|error| error.into_inner())
                .push("metadata-drop");
            return;
        }
        if self.streaming {
            let _timing = self
                .timing
                .stage(crate::capture_timing::Stage::MetadataStreamoff);
            let mut kind = META_CAPTURE as c_int;
            if let Err(error) = self.ioctl(
                vidioc_streamoff(),
                &mut kind as *mut _ as *mut libc::c_void,
                "STREAMOFF",
            ) {
                irlume_common::dlog!("{}: metadata stop failed: {error}", self.device);
            }
        }
        // Unmap our views, then hand the buffers back to the driver. Both are
        // needed before the format can be changed: unmapping alone leaves the
        // queue allocated and V4L2 refuses S_FMT on an allocated queue, so
        // skipping this silently left the node on UVCM for the next process
        // (measured: the format survived every capture until REQBUFS(0) was
        // added here).
        let mut buffers_released = !self.buffers_requested;
        {
            let _timing = self
                .timing
                .stage(crate::capture_timing::Stage::MetadataBuffers);
            self.buffers.clear();
            let mut release = V4l2RequestBuffers {
                count: 0,
                kind: META_CAPTURE,
                memory: MEMORY_MMAP,
                capabilities: 0,
                flags: 0,
                _reserved: [0; 3],
            };
            if self.buffers_requested {
                match self.ioctl(
                    vidioc_reqbufs(),
                    &mut release as *mut _ as *mut libc::c_void,
                    "REQBUFS(0)",
                ) {
                    Ok(()) => buffers_released = true,
                    Err(error) => irlume_common::dlog!(
                        "{}: metadata buffer release failed: {error}",
                        self.device
                    ),
                }
            }
        }
        // The format outlives this process, so hand the node back as found.
        self.restore_owned_format(buffers_released);
        if self.fd >= 0 {
            let _timing = self
                .timing
                .stage(crate::capture_timing::Stage::MetadataClose);
            // SAFETY: fd was opened by this type and is closed exactly once.
            unsafe { libc::close(self.fd) };
            #[cfg(test)]
            if let Some(device) = &self.lifecycle {
                device.lock().unwrap().closed();
            }
        }
        irlume_common::dlog!(
            "{}: illumination metadata closed after {} classified frames",
            self.device,
            self.by_timestamp.len()
        );
    }
}

fn zeroed_format() -> V4l2Format {
    V4l2Format {
        kind: 0,
        _pad: 0,
        dataformat: 0,
        buffersize: 0,
        _rest: [0; 192],
    }
}

fn zeroed_buffer(index: u32) -> V4l2Buffer {
    V4l2Buffer {
        index,
        kind: META_CAPTURE,
        bytesused: 0,
        flags: 0,
        field: 0,
        _pad: 0,
        timestamp: Timeval::default(),
        timecode: V4l2Timecode::default(),
        sequence: 0,
        memory: MEMORY_MMAP,
        offset: 0,
        _m_pad: 0,
        length: 0,
        _reserved2: 0,
        _reserved: 0,
        _tail_pad: 0,
    }
}

// ---------------------------------------------------------------------------
// Finding the metadata node.
// ---------------------------------------------------------------------------

/// The metadata node paired with an IR video node, if the kernel made one.
///
/// uvcvideo registers the metadata node against the same USB interface as its
/// image node, so the pairing is "same `device` link, different node". The
/// interface alone is NOT enough on a camera whose streams all share one
/// interface (Logitech Brio: video0 RGB, video1 its metadata, video2 IR,
/// video3 its metadata): the old lowest-number-first rule handed the IR
/// camera the RGB stream's metadata queue, whose timestamps can never match
/// IR frames, so the reader classified nothing forever (#310). Within a
/// stream the kernel registers the metadata node immediately AFTER its image
/// node (measured on the Brio's media topology: entity pairs 1/4 and 7/10),
/// so the right sibling is the lowest-numbered one ABOVE the image node.
pub(crate) fn metadata_node_for(ir_device: &str) -> Option<String> {
    // Diagnostic kill switch, added while working #187's hardware session.
    // Absence of the variable changes nothing.
    if std::env::var_os("IRLUME_NO_ILLUM_META").is_some_and(|v| v == "1") {
        irlume_common::dlog!("{ir_device}: illumination metadata disabled (IRLUME_NO_ILLUM_META)");
        return None;
    }
    let sysfs = std::path::Path::new("/sys/class/video4linux");
    let found = pick_metadata_sibling(
        ir_device,
        siblings_on_same_interface(ir_device, sysfs),
        offers_uvcm,
    );
    if found.is_none() {
        irlume_common::dlog!(
            "{ir_device}: no sibling node offers UVCM metadata; illumination will come from brightness"
        );
    }
    found
}

/// How many burst frames the camera itself flagged lit (#568 diagnostics).
pub(crate) fn count_lit(flags: &[Option<Illumination>]) -> usize {
    flags
        .iter()
        .filter(|flag| matches!(flag, Some(Illumination::Lit)))
        .count()
}

/// Map a discovered metadata node onto qualification-record evidence (#568).
///
/// `Some(node)` from [`metadata_node_for`] means a same-interface sibling
/// above the image node accepted the UVCM probe; `None` covers every other
/// outcome (no node, format refused, kill switch). Presence, not the node
/// path: `/dev/videoN` numbering is not stable across reboots and a reshuffle
/// must never look like a hardware change.
pub(crate) fn presence_from_discovered(
    found: Option<String>,
) -> crate::capture_qualification::IlluminationMetadataPresence {
    if found.is_some() {
        crate::capture_qualification::IlluminationMetadataPresence::Present
    } else {
        crate::capture_qualification::IlluminationMetadataPresence::Absent
    }
}

/// The sibling that is this image node's OWN metadata node: the FIRST
/// same-interface candidate above the image node, and only when it offers
/// the format. `candidates` must be sorted lowest node number first (as
/// [`siblings_on_same_interface`] returns them).
///
/// A candidate below the image node is an earlier stream's queue (#310).
/// Scanning FORWARD past a non-metadata node would borrow a LATER stream's
/// queue: uvcvideo ignores a failed metadata registration and keeps
/// registering later streams (uvc_driver.c, uvc_meta_register's return
/// value discarded), so an image node can legitimately have no metadata
/// node while the next stream has both. Either way a wrong queue's
/// timestamps never match this stream's frames, so no pair means no
/// reader, and illumination falls back to brightness by design.
fn pick_metadata_sibling(
    image_device: &str,
    candidates: Vec<String>,
    offers: impl Fn(&str) -> bool,
) -> Option<String> {
    let image = node_number(image_device);
    candidates
        .into_iter()
        .find(|c| node_number(c) > image)
        .filter(|c| offers(c))
}

/// Every other v4l2 node registered against the same physical interface as
/// `video_device`, lowest node number first.
///
/// A node whose sysfs entry cannot be read is SKIPPED, not fatal. Virtual
/// devices (v4l2loopback, for one) have no `device` link at all, and treating
/// the first of those as the end of the search made this return nothing on any
/// machine with a loopback device present — measured on a box where a real
/// camera's metadata node existed and was never found because dummy nodes were
/// enumerated first.
fn siblings_on_same_interface(video_device: &str, sysfs: &std::path::Path) -> Vec<String> {
    let Some(name) = std::path::Path::new(video_device).file_name() else {
        return Vec::new();
    };
    let Ok(want) = std::fs::canonicalize(sysfs.join(name).join("device")) else {
        return Vec::new();
    };
    let Ok(entries) = std::fs::read_dir(sysfs) else {
        return Vec::new();
    };

    let mut candidates: Vec<String> = Vec::new();
    for entry in entries.flatten() {
        if entry.file_name() == name {
            continue;
        }
        let Ok(interface) = std::fs::canonicalize(entry.path().join("device")) else {
            continue;
        };
        if interface != want {
            continue;
        }
        if let Some(node) = entry.file_name().to_str().map(|n| format!("/dev/{n}")) {
            candidates.push(node);
        }
    }
    // Lowest node NUMBER first, so the pairing is deterministic on a device
    // that somehow exposes more than one metadata node per interface. Sorting
    // the strings would order /dev/video10 before /dev/video2, which is the
    // opposite of what the rule says and is reachable on any host with
    // double-digit node numbers.
    candidates.sort_by_key(|node| (node_number(node), node.clone()));
    candidates
}

/// The trailing integer of a `/dev/videoN` path, for ordering. A path with no
/// trailing digits sorts last and then by name, so an unexpected shape is
/// merely deprioritised rather than treated as node zero.
pub(crate) fn node_number(node: &str) -> u32 {
    let digits: String = node
        .chars()
        .rev()
        .take_while(char::is_ascii_digit)
        .collect::<Vec<_>>()
        .into_iter()
        .rev()
        .collect();
    digits.parse().unwrap_or(u32::MAX)
}

/// Whether `node` is a metadata node that offers the Microsoft format.
///
/// Probing by attempting the format is deliberate. `VIDIOC_ENUM_FMT` would
/// also answer, but the set is what actually matters and the driver coerces a
/// format it does not support instead of refusing it, so the only reliable
/// question is whether the value sticks.
fn offers_uvcm(node: &str) -> bool {
    let Ok(path) = std::ffi::CString::new(node.as_bytes()) else {
        return false;
    };
    // SAFETY: path is a valid NUL-terminated C string.
    let fd = unsafe { libc::open(path.as_ptr(), libc::O_RDWR | libc::O_NONBLOCK) };
    if fd < 0 {
        return false;
    }
    let mut f = zeroed_format();
    f.kind = META_CAPTURE;
    f.dataformat = UVCM;
    // SAFETY: fd is open and f is a correctly sized v4l2_format.
    let rc = unsafe {
        libc::ioctl(
            fd,
            iowr(64, core::mem::size_of::<V4l2Format>()), // VIDIOC_TRY_FMT
            &mut f as *mut _ as *mut libc::c_void,
        )
    };
    // SAFETY: fd was opened above and is closed exactly once.
    unsafe { libc::close(fd) };
    rc >= 0 && f.dataformat == UVCM
}

#[cfg(test)]
mod tests {
    pub(super) mod lifecycle;
    #[cfg(feature = "capture-timing")]
    #[test]
    fn teardown_timing_keeps_close_after_metadata_ioctl_failures() {
        use std::{
            io::Read,
            os::{fd::IntoRawFd, unix::net::UnixStream},
        };
        let (mut peer, owned) = UnixStream::pair().unwrap();
        peer.set_read_timeout(Some(std::time::Duration::from_secs(1)))
            .unwrap();
        let timings = crate::CaptureTimings::default();
        let control = crate::CaptureControl::with_progress(crate::no_progress())
            .with_capture_timings(Some(timings.clone()));
        // A socket rejects V4L2 ioctls. Exercise the real error cleanup and fd
        // ownership without opening a camera or depending on fd-number reuse.
        let mut log = super::IlluminationLog::test_sentinel(Default::default());
        log.sentinel_events = None;
        log.fd = owned.into_raw_fd();
        log.streaming = true;
        log.restore_format = Some(super::MetadataFormat {
            dataformat: super::UVCH,
            buffersize: 65536,
        });
        log.format_change = super::FormatChange::Applied(super::MetadataFormat {
            dataformat: super::UVCM,
            buffersize: 10240,
        });
        log.buffers_requested = true;
        drop(log.with_timing(crate::capture_timing::Recorder::from_control(&control)));
        assert_eq!(peer.read(&mut [0u8; 1]).unwrap(), 0);
        let snapshot = timings.snapshot();
        for label in [
            "metadata_streamoff",
            "metadata_buffers",
            "metadata_format",
            "metadata_close",
        ] {
            assert!(snapshot[label].is_some(), "unrecorded {label}");
        }
        assert!(snapshot["image_stop"].is_none());
        assert!(snapshot["emitter_restore"].is_none());
    }
    use super::*;
    use crate::capture_qualification::IlluminationMetadataPresence;

    #[test]
    fn explicit_absence_and_exact_failure_never_fall_back_to_discovery() {
        assert!(IlluminationLog::open_selected(
            "/dev/a-configured-ir-node",
            MetadataSelection::Absent
        )
        .unwrap()
        .is_none());
        let error = IlluminationLog::open_selected(
            "/dev/a-configured-ir-node",
            MetadataSelection::Exact("/definitely/missing/metadata"),
        )
        .err()
        .expect("required exact metadata must fail");
        assert!(error.contains("would not open"), "{error}");
    }

    #[test]
    fn exact_metadata_selection_calls_only_the_permitted_open() {
        let events = std::cell::RefCell::new(Vec::new());
        let selected = IlluminationLog::open_selected_with(
            "/dev/video2",
            MetadataSelection::Exact("/dev/video3"),
            |_| {
                events.borrow_mut().push("discover".to_string());
                Some("/dev/video1".into())
            },
            |image, metadata| {
                events.borrow_mut().push(format!("open:{image}:{metadata}"));
                Ok(())
            },
        )
        .unwrap();
        assert_eq!(selected, Some(()));
        assert_eq!(events.into_inner(), ["open:/dev/video2:/dev/video3"]);
    }

    #[test]
    fn a_discovered_node_maps_to_present_and_no_node_to_absent() {
        assert_eq!(
            presence_from_discovered(Some("/dev/video3".into())),
            IlluminationMetadataPresence::Present
        );
        assert_eq!(
            presence_from_discovered(None),
            IlluminationMetadataPresence::Absent
        );
    }

    #[test]
    fn counting_lit_flags_counts_only_the_frames_the_camera_called_lit() {
        use Illumination::{Dark, Lit};
        assert_eq!(
            count_lit(&[Some(Lit), None, Some(Dark), Some(Lit), None]),
            2
        );
        assert_eq!(count_lit(&[None, None]), 0);
        assert_eq!(count_lit(&[]), 0);
    }

    /// #310, the Brio layout: four nodes on ONE interface, so the IR node's
    /// same-interface candidates include the RGB stream's metadata queue at a
    /// LOWER number. The pair rule must skip it and take the next node above.
    #[test]
    fn single_interface_camera_pairs_ir_with_its_own_metadata_node() {
        let candidates = vec![
            "/dev/video0".to_string(), // RGB image
            "/dev/video1".to_string(), // RGB metadata: the wrong-pair trap
            "/dev/video3".to_string(), // IR metadata
        ];
        let offers = |c: &str| c.ends_with('1') || c.ends_with('3');
        assert_eq!(
            pick_metadata_sibling("/dev/video2", candidates, offers),
            Some("/dev/video3".to_string()),
            "the IR camera must arm ITS stream's metadata node, not RGB's"
        );
    }

    /// Split-interface cameras (NexiGo): the only sibling is the pair.
    #[test]
    fn split_interface_pairing_is_unchanged() {
        let offers = |_: &str| true;
        assert_eq!(
            pick_metadata_sibling("/dev/video0", vec!["/dev/video1".into()], offers),
            Some("/dev/video1".to_string())
        );
    }

    /// Only lower-numbered siblings offer the format: that is another
    /// stream's queue, and no reader beats a wrong reader (brightness is the
    /// designed fallback).
    #[test]
    fn a_lower_numbered_metadata_node_is_never_borrowed() {
        let offers = |_: &str| true;
        assert_eq!(
            pick_metadata_sibling("/dev/video2", vec!["/dev/video1".into()], offers),
            None
        );
    }

    /// Codex round: uvcvideo ignores a failed metadata registration and keeps
    /// going, so THIS stream can lack its metadata node while a later stream
    /// on the same interface has both. Scanning forward would borrow the
    /// later stream's queue; only the immediately next node can be the pair.
    #[test]
    fn a_later_streams_metadata_node_is_never_borrowed() {
        let candidates = vec![
            "/dev/video1".to_string(), // earlier stream's metadata
            "/dev/video3".to_string(), // later stream's image
            "/dev/video4".to_string(), // later stream's metadata
        ];
        let offers = |candidate: &str| candidate.ends_with('1') || candidate.ends_with('4');
        assert_eq!(
            pick_metadata_sibling("/dev/video2", candidates, offers),
            None,
            "missing metadata for this stream must fall back, not borrow a later stream"
        );
    }

    /// Double-digit nodes order numerically, not lexically: video10's
    /// metadata is video11, even with a video9 sibling in the list.
    #[test]
    fn pairing_orders_numerically_on_double_digit_nodes() {
        let candidates = vec!["/dev/video9".to_string(), "/dev/video11".to_string()];
        let offers = |_: &str| true;
        assert_eq!(
            pick_metadata_sibling("/dev/video10", candidates, offers),
            Some("/dev/video11".to_string())
        );
    }

    /// Bytes captured from an ASUS IR module, kernel 7.1.5: uvcvideo's 12-byte
    /// header, then a 28-byte payload header (2 standard + PTS + SCR + one
    /// 16-byte Microsoft record).
    fn real_buffer(illuminated: bool, header_flags: u8) -> Vec<u8> {
        let mut b = Vec::new();
        b.extend_from_slice(&924_485_039_416u64.to_le_bytes()); // ns
        b.extend_from_slice(&817u16.to_le_bytes()); // sof
        b.push(28); // bHeaderLength
        b.push(header_flags); // bmHeaderInfo
        b.extend_from_slice(&2_115_448u32.to_le_bytes()); // PTS
        b.extend_from_slice(&[0u8; 6]); // SCR
        b.extend_from_slice(&METADATA_ID_FRAME_ILLUMINATION.to_le_bytes());
        b.extend_from_slice(&16u32.to_le_bytes());
        b.extend_from_slice(&u32::from(illuminated).to_le_bytes());
        b.extend_from_slice(&[0u8; 4]); // Reserved
        b
    }

    /// 0x8d and 0x8c are the two values observed alternating on real hardware:
    /// end-of-header, SCR, PTS, and the frame id toggling.
    const LIT_FLAGS: u8 = 0x8d;
    const DARK_FLAGS: u8 = 0x8c;

    // Independent wire fixtures: Microsoft UVC extensions sections 2.2.3.2
    // (concatenated partial blobs) and 2.2.3.4.4 (four u32 fields).
    fn illumination_item(lit: bool) -> Vec<u8> {
        let mut item = vec![6, 0, 0, 0, 16, 0, 0, 0];
        item.extend_from_slice(&u32::from(lit).to_le_bytes());
        item.extend_from_slice(&[0; 4]);
        item
    }

    fn metadata_fragment(extra: &[u8], flags: u8) -> Vec<u8> {
        let standard = usize::from(flags & 4 != 0) * 4 + usize::from(flags & 8 != 0) * 6;
        let mut block = vec![0; 10]; // Linux host timestamp and SOF
        block.push(u8::try_from(2 + standard + extra.len()).unwrap());
        block.push(flags);
        block.resize(12 + standard, 0);
        block.extend_from_slice(extra);
        block
    }

    #[test]
    fn metadata_rejects_kernel_reachable_cross_fid_record_assembly() {
        // Linux can retain both headers when the FID=0 frame has no image
        // bytes. Neither frame supplies a complete illumination record.
        let mut frame = metadata_fragment(&[6, 0, 0, 0, 16, 0, 0, 0], 0x80);
        frame.extend(metadata_fragment(&[1, 0, 0, 0, 0, 0, 0, 0], 0x83));
        assert_eq!(parse_illumination(&frame), None);
    }

    #[test]
    fn metadata_rejects_fid_changes_even_in_standard_only_headers() {
        for fid in [0, 1] {
            let full = metadata_fragment(&illumination_item(true), 0x80 | fid);
            let other = metadata_fragment(&[], 0x8c | (fid ^ 1));
            assert_eq!(
                parse_illumination(&[full.clone(), other.clone()].concat()),
                None
            );
            assert_eq!(parse_illumination(&[other, full].concat()), None);
        }
    }

    #[test]
    fn metadata_refuses_any_header_after_observed_eof() {
        let item = illumination_item(true);
        for split in 1..=item.len() {
            let mut frame = metadata_fragment(&item[..split], 0x82);
            frame.extend(metadata_fragment(&item[split..], 0x80));
            assert_eq!(parse_illumination(&frame), None, "split {split}");
        }
    }

    #[test]
    fn metadata_preserves_same_fid_splits_with_optional_final_eof() {
        for fid in [0, 1] {
            for eof in [0, 2] {
                for lit in [false, true] {
                    let item = illumination_item(lit);
                    for split in 1..item.len() {
                        let mut frame = metadata_fragment(&item[..split], 0x84 | fid);
                        frame.extend(metadata_fragment(&item[split..], 0x88 | fid | eof));
                        assert_eq!(
                            parse_illumination(&frame),
                            Some(if lit {
                                Illumination::Lit
                            } else {
                                Illumination::Dark
                            })
                        );
                    }
                }
            }
        }
    }

    #[test]
    fn metadata_record_survives_every_split_and_optional_timestamp_layout() {
        for lit in [false, true] {
            let item = illumination_item(lit);
            let expected = Some(if lit {
                Illumination::Lit
            } else {
                Illumination::Dark
            });
            for first_flags in [0x80, 0x84, 0x88, 0x8c] {
                for last_flags in [0x80, 0x84, 0x88, 0x8c] {
                    for split in 1..item.len() {
                        let mut frame = metadata_fragment(&item[..split], first_flags);
                        frame.extend(metadata_fragment(&[], 0x8c));
                        frame.extend(metadata_fragment(&item[split..], last_flags));
                        assert_eq!(
                            parse_illumination(&frame),
                            expected,
                            "split {split}, flags {first_flags:x}/{last_flags:x}"
                        );
                    }
                }
            }
        }
    }

    #[test]
    fn metadata_custom_continuation_is_never_illumination_evidence() {
        let mut items = vec![0, 0, 0, 0x80, 24, 0, 0, 0];
        items.extend(illumination_item(true)); // opaque custom payload
        items.extend(illumination_item(false)); // actual frame evidence
        assert_eq!(
            parse_illumination(&metadata_fragment(&items, 0x8c)),
            Some(Illumination::Dark)
        );
        for split in 1..items.len() {
            let mut frame = metadata_fragment(&items[..split], 0x8c);
            frame.extend(metadata_fragment(&items[split..], 0x8c));
            assert_eq!(
                parse_illumination(&frame),
                Some(Illumination::Dark),
                "split {split}"
            );
        }
        let frame: Vec<_> = items
            .chunks(1)
            .flat_map(|part| metadata_fragment(part, 0x80))
            .collect();
        assert_eq!(parse_illumination(&frame), Some(Illumination::Dark));
    }

    #[test]
    fn metadata_illumination_requires_the_complete_sixteen_byte_record() {
        let mut item = illumination_item(true);
        item[4..8].copy_from_slice(&12u32.to_le_bytes());
        item.truncate(12);
        assert_eq!(parse_illumination(&metadata_fragment(&item, 0x80)), None);
    }

    #[test]
    fn metadata_conflicting_duplicates_are_unknown_in_either_order() {
        for lit in [true, false] {
            let mut items = illumination_item(lit);
            items.extend(illumination_item(!lit));
            assert_eq!(parse_illumination(&metadata_fragment(&items, 0x80)), None);
        }
        let items = illumination_item(true).repeat(2);
        assert_eq!(
            parse_illumination(&metadata_fragment(&items, 0x80)),
            Some(Illumination::Lit)
        );
    }

    #[test]
    fn metadata_valid_prefix_does_not_hide_malformed_trailing_data() {
        let good = metadata_fragment(&illumination_item(true), 0x80);
        for tail in [vec![0], vec![0; 11], metadata_fragment(&[1], 0x80)] {
            let mut frame = good.clone();
            frame.extend(tail);
            assert_eq!(parse_illumination(&frame), None);
        }
        for size in [0u32, 4, 9, u32::MAX] {
            let mut items = illumination_item(true);
            items.extend_from_slice(&0x8000_0000u32.to_le_bytes());
            items.extend_from_slice(&size.to_le_bytes());
            items.push(0);
            assert_eq!(parse_illumination(&metadata_fragment(&items, 0x80)), None);
        }
    }

    #[test]
    fn metadata_error_header_invalidates_the_whole_frame() {
        let good = metadata_fragment(&illumination_item(true), 0x80);
        let bad = metadata_fragment(&[], 0xc0); // UVC ERR
        for frame in [[good.clone(), bad.clone()].concat(), [bad, good].concat()] {
            assert_eq!(parse_illumination(&frame), None);
        }
    }

    #[test]
    fn metadata_dequeue_error_discards_even_a_complete_lit_record() {
        let frame = metadata_fragment(&illumination_item(true), 0x80);
        assert_eq!(
            illumination_in_dequeued_buffer(&frame, 0x2000),
            Some(Illumination::Lit)
        );
        assert_eq!(illumination_in_dequeued_buffer(&frame, 0x2040), None);
    }

    #[test]
    fn metadata_complete_extensions_keep_the_defined_bit_semantics() {
        let mut item = illumination_item(true);
        item[4..8].copy_from_slice(&24u32.to_le_bytes());
        item[8..12].copy_from_slice(&0x8000_0001u32.to_le_bytes());
        item[12..16].copy_from_slice(&0xdead_beefu32.to_le_bytes());
        item.extend_from_slice(&[0xff; 8]);
        assert_eq!(
            parse_illumination(&metadata_fragment(&item, 0x80)),
            Some(Illumination::Lit)
        );
        item[8] = 0;
        assert_eq!(
            parse_illumination(&metadata_fragment(&item, 0x80)),
            Some(Illumination::Dark)
        );
    }

    #[test]
    fn metadata_large_custom_item_is_skipped_across_many_fragments() {
        let mut items = vec![0, 0, 0, 0x80, 0, 4, 0, 0]; // Size = 1024
        items.resize(1024, 0xff);
        items.extend(illumination_item(true));
        for chunk in [1, 7, 127, 243] {
            let frame: Vec<_> = items
                .chunks(chunk)
                .flat_map(|part| metadata_fragment(part, 0x8c))
                .collect();
            assert_eq!(parse_illumination(&frame), Some(Illumination::Lit));
        }
    }

    #[test]
    fn metadata_incomplete_optional_timestamp_is_not_a_new_record_start() {
        let good = metadata_fragment(&illumination_item(true), 0x80);
        for flags in [0x84, 0x88, 0x8c] {
            let mut broken = metadata_fragment(&[], flags);
            broken.pop();
            broken[10] -= 1;
            assert_eq!(parse_illumination(&[good.clone(), broken].concat()), None);
        }
    }

    #[test]
    fn metadata_incomplete_frames_are_not_joined_across_calls() {
        let item = illumination_item(true);
        for split in 1..item.len() {
            assert_eq!(
                parse_illumination(&metadata_fragment(&item[..split], 0x80)),
                None
            );
            assert_eq!(
                parse_illumination(&metadata_fragment(&item[split..], 0x80)),
                None
            );
        }
        assert_eq!(
            parse_illumination(&metadata_fragment(&item, 0x80)),
            Some(Illumination::Lit)
        );
    }

    #[test]
    fn reads_the_illumination_flag_from_a_real_buffer() {
        assert_eq!(
            parse_illumination(&real_buffer(true, LIT_FLAGS)),
            Some(Illumination::Lit)
        );
        assert_eq!(
            parse_illumination(&real_buffer(false, DARK_FLAGS)),
            Some(Illumination::Dark)
        );
    }

    #[test]
    fn a_header_with_no_appended_record_is_unknown_not_dark() {
        // The first frame after STREAMON, measured: bHeaderLength 12, nothing
        // appended. Reading this as "dark" would make the burst discard a frame
        // the camera never said anything about.
        let mut b = Vec::new();
        b.extend_from_slice(&1u64.to_le_bytes());
        b.extend_from_slice(&673u16.to_le_bytes());
        b.push(12);
        b.push(DARK_FLAGS);
        b.extend_from_slice(&0u32.to_le_bytes()); // PTS
        b.extend_from_slice(&[0u8; 6]); // SCR
        assert_eq!(parse_illumination(&b), None);
    }

    #[test]
    fn a_header_without_pts_or_scr_shifts_where_records_start() {
        // Same record, but the header declares neither PTS nor SCR, so the
        // standard part is 2 bytes and the record begins 10 bytes earlier.
        // Assuming a fixed 12-byte standard header would misread this.
        let mut b = Vec::new();
        b.extend_from_slice(&1u64.to_le_bytes());
        b.extend_from_slice(&0u16.to_le_bytes());
        b.push(18); // 2 standard + 16 record
        b.push(0x80); // end-of-header only: no PTS, no SCR
        b.extend_from_slice(&METADATA_ID_FRAME_ILLUMINATION.to_le_bytes());
        b.extend_from_slice(&16u32.to_le_bytes());
        b.extend_from_slice(&1u32.to_le_bytes());
        b.extend_from_slice(&[0u8; 4]);
        assert_eq!(parse_illumination(&b), Some(Illumination::Lit));
    }

    #[test]
    fn a_record_that_overruns_the_buffer_is_refused_not_guessed() {
        let mut b = real_buffer(true, LIT_FLAGS);
        // Claim a record far larger than the bytes present.
        let size_at = b.len() - 12;
        b[size_at..size_at + 4].copy_from_slice(&4096u32.to_le_bytes());
        assert_eq!(parse_illumination(&b), None);
    }

    #[test]
    fn a_zero_sized_record_does_not_loop_forever() {
        let mut b = real_buffer(true, LIT_FLAGS);
        let size_at = b.len() - 12;
        b[size_at..size_at + 4].copy_from_slice(&0u32.to_le_bytes());
        assert_eq!(parse_illumination(&b), None);
    }

    #[test]
    fn a_truncated_buffer_is_refused() {
        let b = real_buffer(true, LIT_FLAGS);
        for cut in 0..b.len() {
            // No panic and no false reading for any prefix.
            let _ = parse_illumination(&b[..cut]);
        }
        assert_eq!(parse_illumination(&b[..20]), None);
    }

    #[test]
    fn several_entries_in_one_buffer_are_walked() {
        // A frame that arrived as two USB payloads: the first header carries no
        // record, the second does.
        let mut first = Vec::new();
        first.extend_from_slice(&1u64.to_le_bytes());
        first.extend_from_slice(&0u16.to_le_bytes());
        first.push(12);
        first.push(LIT_FLAGS); // Both payloads belong to the same wire frame.
        first.extend_from_slice(&0u32.to_le_bytes());
        first.extend_from_slice(&[0u8; 6]);
        let mut both = first;
        both.extend_from_slice(&real_buffer(true, LIT_FLAGS));
        assert_eq!(parse_illumination(&both), Some(Illumination::Lit));
        both[11] ^= 1; // The historical mixed-FID fixture must now be refused.
        assert_eq!(parse_illumination(&both), None);
    }

    #[test]
    fn brightest_lit_ignores_a_brighter_frame_the_camera_called_dark() {
        // The case the whole change exists for: a dark frame that happens to be
        // brightest must not be chosen as the lit one.
        let means = [90.0, 50.0, 40.0];
        let flags = [
            Some(Illumination::Dark),
            Some(Illumination::Lit),
            Some(Illumination::Lit),
        ];
        assert_eq!(brightest_lit(&means, &flags), Some(1));
    }

    #[test]
    fn brightest_lit_matches_the_old_rule_when_nothing_is_flagged() {
        let means = [10.0, 90.0, 90.0, 20.0];
        let flags = [None, None, None, None];
        // First frame holding the maximum, as the incremental scan always did.
        assert_eq!(brightest_lit(&means, &flags), Some(1));
    }

    #[test]
    fn no_metadata_selects_the_burst_maximum() {
        // The #268 invariant: with no metadata the clip demotion never
        // engages, so the chosen frame IS the burst maximum, and a dark
        // choice beside a brighter unclassified frame cannot reach the
        // diagnosis band at all.
        let means = [1.0, 34.0, 128.0, 2.0];
        let flags = [None, None, None, None];
        let clipped = [0.0, 0.0, 0.9, 0.0];
        assert_eq!(best_gate_frame(&means, &flags, Some(&clipped)), Some(2));
        assert_eq!(best_gate_frame(&means, &flags, None), Some(2));
    }

    /// #264, the caller boundary (Codex round on PR #332): a metadata-less
    /// strobing burst SELECTS its bright phase, because without illumination
    /// flags selection is the long-standing brightest scan. The chosen frame
    /// then clears the dark gate, so no dark diagnosis runs and no message
    /// can mis-advise; the strobe case self-resolves whenever a bright frame
    /// exists. The occurrences #264 records (chosen mean 28-34) are
    /// therefore bursts with NO bright frame at all, strobe warmup, which
    /// no diagnosis arm keyed on in-burst brightness can distinguish from a
    /// dead emitter; that residual is a capture-policy question, re-scoped
    /// on the issue.
    #[test]
    fn metadata_less_strobe_selects_the_bright_phase() {
        let means: Vec<f64> = [0.6, 128.0].repeat(5);
        let flags = vec![None; means.len()];
        let best_i =
            best_gate_frame(&means, &flags, None).expect("a non-empty burst has a gate frame");
        assert_eq!(means[best_i], 128.0);
        assert!(
            !(0.0..crate::ir_dark::DARK_MEAN_MAX).contains(&means[best_i])
                && means[best_i] < crate::ir_dark::SATURATED_MIN_MEAN,
            "the production caller must not route this burst to dark diagnosis"
        );
    }

    #[test]
    fn best_gate_frame_skips_a_clipped_brightest_lit_frame() {
        // The #221 case: the brightest lit frame is blown, a dimmer lit frame
        // is clean, and the gate must read the clean one.
        let means = [200.0, 150.0, 3.0];
        let flags = [
            Some(Illumination::Lit),
            Some(Illumination::Lit),
            Some(Illumination::Dark),
        ];
        let clipped = [0.30, 0.01, 0.0];
        assert_eq!(best_gate_frame(&means, &flags, Some(&clipped)), Some(1));
    }

    #[test]
    fn best_gate_frame_never_trades_a_clipped_face_for_an_emitter_off_frame() {
        // Every lit frame clips. The dark frame is the cleanest in the burst
        // and must still lose: least-clipped LIT wins.
        let means = [2.0, 220.0, 150.0];
        let flags = [
            Some(Illumination::Dark),
            Some(Illumination::Lit),
            Some(Illumination::Lit),
        ];
        let clipped = [0.0, 0.60, 0.30];
        assert_eq!(best_gate_frame(&means, &flags, Some(&clipped)), Some(2));
    }

    #[test]
    fn best_gate_frame_keeps_the_brightest_on_a_clean_burst() {
        // No frame clips, so selection matches brightest_lit exactly,
        // including first-on-tie.
        let means = [50.0, 90.0, 90.0];
        let flags = [Some(Illumination::Lit); 3];
        let clipped = [0.0, 0.0, 0.0];
        assert_eq!(best_gate_frame(&means, &flags, Some(&clipped)), Some(1));
    }

    #[test]
    fn burst_plateau_exits_a_steady_emitter_after_two_flat_frames() {
        let flags = [Some(Illumination::Lit); 10];
        let clipped = [0.0; 10];
        // Frame 0 is the best clean lit frame; two equal frames follow.
        let means = [150.0, 150.0, 150.0];
        assert!(
            burst_plateau_reached(&means, &flags[..3], Some(&clipped[..3])),
            "a steady plateau is decided after three frames"
        );
        // One frame after the best is not enough: the ambient pair still
        // wants the neighbour behind the best frame.
        assert!(!burst_plateau_reached(
            &means[..2],
            &flags[..2],
            Some(&clipped[..2])
        ));
        // A brightening burst keeps the loop going: something later could
        // still beat the current best.
        let rising = [100.0, 120.0, 145.0];
        assert!(!burst_plateau_reached(
            &rising,
            &flags[..3],
            Some(&clipped[..3])
        ));
        // Once two frames fail to improve a strong best, the answer flips.
        let settled = [100.0, 120.0, 145.0, 144.0, 100.0];
        assert!(burst_plateau_reached(
            &settled,
            &flags[..5],
            Some(&clipped[..5])
        ));
    }

    #[test]
    fn burst_plateau_never_fires_without_camera_flags_or_clip_ceilings() {
        let means = [150.0, 150.0, 150.0];
        let lit = [Some(Illumination::Lit); 3];
        let clipped = [0.0; 3];
        // No clip ceiling -> "clean" is not measurable.
        assert!(!burst_plateau_reached(&means, &lit, None));
        // No camera classification -> "lit" is not measurable.
        let unsaid = [None, None, None];
        assert!(!burst_plateau_reached(&means, &unsaid, Some(&clipped)));
        // Too few frames to have both a best and its trailing pair.
        assert!(!burst_plateau_reached(
            &[150.0, 150.0],
            &lit[..2],
            Some(&clipped[..2])
        ));
    }

    #[test]
    fn burst_plateau_ignores_clipped_and_unlit_frames_as_improvements() {
        // A brighter but CLIPPED lit frame cannot become the best, and does
        // not count as an improvement either.
        let means = [150.0, 220.0, 149.0, 148.0];
        let flags = [Some(Illumination::Lit); 4];
        let clipped = [0.0, 0.4, 0.0, 0.0];
        assert!(burst_plateau_reached(&means, &flags, Some(&clipped)));
        // A dark frame with a huge mean is not an improvement.
        let strobe_means = [180.0, 5.0, 178.0];
        let strobe_flags = [
            Some(Illumination::Lit),
            Some(Illumination::Dark),
            Some(Illumination::Lit),
        ];
        let clean = [0.0; 3];
        assert!(burst_plateau_reached(
            &strobe_means,
            &strobe_flags,
            Some(&clean)
        ));
    }

    #[test]
    fn best_gate_frame_without_clip_data_matches_brightest_lit() {
        // A format with no known ceiling reports no clipping; the scan is the
        // long-standing brightest-lit one.
        let means = [90.0, 50.0];
        let flags = [Some(Illumination::Lit), Some(Illumination::Lit)];
        assert_eq!(best_gate_frame(&means, &flags, None), Some(0));
    }

    #[test]
    fn best_gate_frame_without_camera_flags_keeps_the_brightest_scan() {
        // Unclassified burst: the cleanest frames of a strobing burst are the
        // emitter-off ones, so clip-aware selection must not run at all, even
        // when the brightest frame is heavily clipped.
        let means = [3.0, 220.0, 40.0];
        let flags = [None, None, None];
        let clipped = [0.0, 0.80, 0.0];
        assert_eq!(best_gate_frame(&means, &flags, Some(&clipped)), Some(1));
    }

    #[test]
    fn best_gate_frame_counts_the_threshold_itself_as_clean() {
        // The boundary belongs to the clean side; a frame at exactly
        // CLIPPED_FRAC_MAX outranks a dimmer spotless one.
        let means = [200.0, 150.0];
        let flags = [Some(Illumination::Lit), Some(Illumination::Lit)];
        let clipped = [CLIPPED_FRAC_MAX, 0.0];
        assert_eq!(best_gate_frame(&means, &flags, Some(&clipped)), Some(0));
    }

    #[test]
    fn best_gate_frame_breaks_a_clipping_tie_toward_the_brighter_frame() {
        // All-clipped fallback with equal clipping: brightness decides.
        let means = [90.0, 180.0];
        let flags = [Some(Illumination::Lit), Some(Illumination::Lit)];
        let clipped = [0.30, 0.30];
        assert_eq!(best_gate_frame(&means, &flags, Some(&clipped)), Some(1));
    }

    #[test]
    fn brightest_lit_falls_back_when_every_frame_is_flagged_dark() {
        // A camera in D0, or one whose emitter never fired: metadata says no
        // frame was lit, so refusing to pick one would fail the capture. Pick
        // the brightest and let the ambient gates downstream judge it.
        let means = [10.0, 90.0, 20.0];
        let flags = [Some(Illumination::Dark); 3];
        assert_eq!(brightest_lit(&means, &flags), Some(1));
    }

    #[test]
    fn brightest_lit_on_an_empty_burst_is_none() {
        assert_eq!(brightest_lit(&[], &[]), None);
    }

    #[test]
    fn ambient_partner_prefers_the_neighbour_the_camera_flagged_dark() {
        // The brighter neighbour is the flagged-dark one. Brightness alone
        // would pick the other; the camera's answer wins.
        let means = [30.0, 100.0, 5.0];
        let flags = [
            Some(Illumination::Dark),
            Some(Illumination::Lit),
            Some(Illumination::Lit),
        ];
        assert_eq!(ambient_partner(1, &means, &flags), Some(0));
    }

    #[test]
    fn ambient_partner_falls_back_to_the_darker_neighbour() {
        let means = [30.0, 100.0, 5.0];
        let flags = [None, None, None];
        assert_eq!(ambient_partner(1, &means, &flags), Some(2));
    }

    #[test]
    fn ambient_partner_at_the_burst_edges_stays_in_range() {
        let means = [100.0, 5.0];
        let flags = [None, None];
        assert_eq!(ambient_partner(0, &means, &flags), Some(1));
        assert_eq!(ambient_partner(1, &means, &flags), Some(0));
        assert_eq!(ambient_partner(0, &[42.0], &[None]), None);
    }

    /// Build a throwaway `/sys/class/video4linux` lookalike. `nodes` is a list
    /// of (node name, interface it belongs to); an interface of `None` means
    /// the node has no `device` link, like a v4l2loopback dummy.
    fn fake_sysfs(tag: &str, nodes: &[(&str, Option<&str>)]) -> std::path::PathBuf {
        let root = std::env::temp_dir().join(format!("irlume-sysfs-{tag}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        let devices = root.join("devices");
        std::fs::create_dir_all(&devices).expect("fake sysfs");
        for (node, interface) in nodes {
            let dir = root.join("class").join(node);
            std::fs::create_dir_all(&dir).expect("node dir");
            if let Some(interface) = interface {
                let target = devices.join(interface);
                std::fs::create_dir_all(&target).expect("interface dir");
                std::os::unix::fs::symlink(&target, dir.join("device")).expect("device link");
            }
        }
        root
    }

    #[test]
    fn a_node_with_no_device_link_does_not_end_the_search() {
        // The layout measured on a machine with both a real camera and three
        // v4l2loopback dummies: read_dir yields the dummies, which have no
        // `device` link at all. Aborting on the first of those made a real
        // camera's metadata node unreachable, and the capture path silently
        // fell back to brightness on hardware that could have answered.
        let root = fake_sysfs(
            "loopback",
            &[
                ("video2", Some("3-2.1:1.2")),
                ("video3", Some("3-2.1:1.2")),
                ("video8", None),
                ("video9", None),
                ("video10", None),
            ],
        );
        let found = siblings_on_same_interface("/dev/video2", &root.join("class"));
        assert_eq!(found, vec!["/dev/video3".to_string()]);
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn siblings_are_ordered_by_node_number_not_by_name() {
        // Sorting the strings puts /dev/video10 before /dev/video2, which is
        // the opposite of the documented rule and reachable on any host that
        // has reached double-digit node numbers.
        let root = fake_sysfs(
            "ordering",
            &[
                ("video4", Some("1-1:1.0")),
                ("video10", Some("1-1:1.0")),
                ("video2", Some("1-1:1.0")),
                ("video9", Some("1-1:1.0")),
            ],
        );
        let found = siblings_on_same_interface("/dev/video4", &root.join("class"));
        assert_eq!(
            found,
            vec![
                "/dev/video2".to_string(),
                "/dev/video9".to_string(),
                "/dev/video10".to_string(),
            ]
        );
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn a_node_name_with_no_number_sorts_last_rather_than_first() {
        assert_eq!(node_number("/dev/video10"), 10);
        assert_eq!(node_number("/dev/video2"), 2);
        // Not "node zero": an unexpected shape must not outrank a real node.
        assert_eq!(node_number("/dev/videoX"), u32::MAX);
        assert_eq!(node_number(""), u32::MAX);
    }

    #[test]
    fn a_second_camera_on_another_interface_is_not_a_sibling() {
        // Node numbering interleaves across cameras, so pairing by "the next
        // node number" would cross between two cameras here.
        let root = fake_sysfs(
            "twocams",
            &[
                ("video0", Some("3-5:1.0")),
                ("video1", Some("3-5:1.0")),
                ("video2", Some("3-5:1.2")),
                ("video3", Some("3-5:1.2")),
            ],
        );
        let found = siblings_on_same_interface("/dev/video2", &root.join("class"));
        assert_eq!(found, vec!["/dev/video3".to_string()]);
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn a_device_that_is_not_in_sysfs_yields_no_siblings() {
        let root = fake_sysfs("missing", &[("video0", Some("3-5:1.0"))]);
        assert!(siblings_on_same_interface("/dev/video99", &root.join("class")).is_empty());
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn the_two_metadata_fourccs_are_what_the_kernel_uses() {
        // v4l2 spells these 'UVCH' and 'UVCM' little-endian; a byte-order slip
        // here would silently request a format no driver has.
        assert_eq!(UVCH, u32::from_le_bytes(*b"UVCH"));
        assert_eq!(UVCM, u32::from_le_bytes(*b"UVCM"));
    }
}

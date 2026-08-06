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
//! 16-byte record appended to the payload header of every frame, whose first
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
const UVCH: u32 = fourcc(b"UVCH");

/// `MetadataId_FrameIllumination` from Microsoft's UVC extensions.
const METADATA_ID_FRAME_ILLUMINATION: u32 = 6;

/// Ring size for metadata buffers.
///
/// Larger than the image ring because metadata is drained opportunistically
/// between image dequeues rather than in its own loop; a few frames of slack
/// costs 10KiB per buffer and avoids losing records to a slow burst iteration.
const META_BUFFERS: u32 = 8;

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
    /// `struct v4l2_meta_format { __u32 dataformat; __u32 buffersize; }`,
    /// followed by the rest of the 200-byte union.
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
// Parsing. Pure, and the part worth testing: everything above it is ioctl
// plumbing that only real hardware can exercise.
// ---------------------------------------------------------------------------

/// One frame's worth of illumination, as the camera reported it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Illumination {
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
/// says so; Microsoft's records are concatenated after it, each an 8-byte
/// little-endian `{id, size}` followed by its body.
///
/// A buffer may hold several entries when a frame arrived as several USB
/// payloads. They describe the same frame, so the first illumination record
/// found is the answer.
///
/// Returns `None` when the buffer carries no illumination record, which is
/// normal for the first frame after `STREAMON` and must not be read as "dark".
pub(crate) fn parse_illumination(buf: &[u8]) -> Option<Illumination> {
    let mut at = 0usize;
    while at + UVC_META_BUF_HEADER <= buf.len() {
        let length = usize::from(buf[at + 10]);
        let flags = buf[at + 11];
        // A header shorter than its own two mandatory bytes is not a header.
        if length < 2 {
            return None;
        }
        let body_start = at + UVC_META_BUF_HEADER;
        let body_end = body_start.checked_add(length - 2)?;
        if body_end > buf.len() {
            return None;
        }
        if let Some(illum) = illumination_in_header(&buf[body_start..body_end], flags) {
            return Some(illum);
        }
        at = body_end;
    }
    None
}

/// Size of uvcvideo's own per-buffer header, before the UVC payload header's
/// third byte.
const UVC_META_BUF_HEADER: usize = 12;

/// Walk the Microsoft records appended after the standard UVC payload header.
///
/// `body` is the payload header from its third byte onward; `flags` is
/// `bmHeaderInfo`, whose PTS (bit 2) and SCR (bit 3) bits decide how much of
/// `body` is standard header rather than appended records.
fn illumination_in_header(body: &[u8], flags: u8) -> Option<Illumination> {
    const PTS: u8 = 1 << 2;
    const SCR: u8 = 1 << 3;
    let standard = (if flags & PTS != 0 { 4 } else { 0 }) + (if flags & SCR != 0 { 6 } else { 0 });
    let extra = body.get(standard..)?;

    let mut at = 0usize;
    while at + 8 <= extra.len() {
        let id = u32::from_le_bytes(extra[at..at + 4].try_into().ok()?);
        let size = u32::from_le_bytes(extra[at + 4..at + 8].try_into().ok()?) as usize;
        // A record must at least contain its own header, and must fit. Either
        // failure means this is not a record stream, so stop rather than
        // resynchronise onto whatever the bytes happen to look like.
        if size < 8 || at + size > extra.len() {
            return None;
        }
        if id == METADATA_ID_FRAME_ILLUMINATION && size >= 12 {
            let raw = u32::from_le_bytes(extra[at + 8..at + 12].try_into().ok()?);
            return Some(if raw & 1 != 0 {
                Illumination::Lit
            } else {
                Illumination::Dark
            });
        }
        at += size;
    }
    None
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
pub(crate) fn brightest_lit(means: &[f64], flags: &[Option<Illumination>]) -> Option<usize> {
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

/// A memory-mapped metadata buffer.
struct MappedBuffer {
    ptr: *mut libc::c_void,
    len: usize,
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
    restore_format: u32,
    streaming: bool,
}

impl IlluminationLog {
    /// Set up and start the metadata queue for the IR node at `ir_device`.
    ///
    /// Must be called before the image stream's first dequeue: uvcvideo
    /// produces no metadata at all if the image queue starts first.
    ///
    /// `None` means this camera cannot report illumination, which is a normal
    /// outcome and not an error.
    pub(crate) fn open(ir_device: &str) -> Option<Self> {
        let node = metadata_node_for(ir_device)?;
        // SAFETY: a NUL-terminated path built directly below.
        let path = std::ffi::CString::new(node.as_bytes()).ok()?;
        let fd = unsafe { libc::open(path.as_ptr(), libc::O_RDWR | libc::O_NONBLOCK) };
        if fd < 0 {
            irlume_common::dlog!(
                "{ir_device}: metadata node {node} would not open; using brightness"
            );
            return None;
        }
        let mut log = Self {
            fd,
            device: node.clone(),
            buffers: Vec::new(),
            by_timestamp: std::collections::HashMap::new(),
            restore_format: UVCH,
            streaming: false,
        };
        match log.start() {
            Ok(()) => Some(log),
            Err(why) => {
                irlume_common::dlog!(
                    "{ir_device}: no illumination metadata from {node} ({why}); using brightness"
                );
                None
            }
        }
    }

    fn start(&mut self) -> std::result::Result<(), String> {
        self.restore_format = self.get_format()?;
        let got = self.set_format(UVCM)?;
        if got != UVCM {
            // The driver coerces an unrecognised format to UVCH rather than
            // failing, so a successful ioctl proves nothing on its own.
            return Err("the device does not accept the UVCM metadata format".into());
        }
        self.request_and_map()?;
        self.stream_on()?;
        self.streaming = true;
        Ok(())
    }

    fn get_format(&self) -> std::result::Result<u32, String> {
        let mut f = zeroed_format();
        f.kind = META_CAPTURE;
        self.ioctl(
            vidioc_g_fmt(),
            &mut f as *mut _ as *mut libc::c_void,
            "G_FMT",
        )?;
        Ok(f.dataformat)
    }

    fn set_format(&self, want: u32) -> std::result::Result<u32, String> {
        let mut f = zeroed_format();
        f.kind = META_CAPTURE;
        f.dataformat = want;
        self.ioctl(
            vidioc_s_fmt(),
            &mut f as *mut _ as *mut libc::c_void,
            "S_FMT",
        )?;
        Ok(f.dataformat)
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
        self.ioctl(
            vidioc_reqbufs(),
            &mut req as *mut _ as *mut libc::c_void,
            "REQBUFS",
        )?;
        if req.count == 0 {
            return Err("the device granted no metadata buffers".into());
        }
        for index in 0..req.count {
            let mut buf = zeroed_buffer(index);
            self.ioctl(
                vidioc_querybuf(),
                &mut buf as *mut _ as *mut libc::c_void,
                "QUERYBUF",
            )?;
            // SAFETY: offset and length are the driver's own answer for this
            // buffer index; the mapping is owned by MappedBuffer from here.
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
                return Err(format!("mapping metadata buffer {index} failed"));
            }
            self.buffers.push(MappedBuffer {
                ptr,
                len: buf.length as usize,
            });
            let mut q = zeroed_buffer(index);
            self.ioctl(vidioc_qbuf(), &mut q as *mut _ as *mut libc::c_void, "QBUF")?;
        }
        Ok(())
    }

    fn stream_on(&self) -> std::result::Result<(), String> {
        let mut kind = META_CAPTURE as c_int;
        self.ioctl(
            vidioc_streamon(),
            &mut kind as *mut _ as *mut libc::c_void,
            "STREAMON",
        )
    }

    /// Drop the previous burst's records.
    ///
    /// Correlation only ever looks at the burst being captured, and a session
    /// is held across many captures in `irlume-auth`, so without this the map
    /// would grow for the life of the session. Called once before a burst
    /// rather than inside `drain`, which runs per frame.
    pub(crate) fn begin_burst(&mut self) {
        self.by_timestamp.clear();
    }

    /// Pull every metadata buffer the driver has ready, without blocking.
    ///
    /// Called between image dequeues rather than from its own thread: the two
    /// queues advance together, so a drain per image frame keeps up, and a
    /// missed record costs one frame's classification rather than a stall.
    pub(crate) fn drain(&mut self) {
        if !self.streaming {
            return;
        }
        loop {
            let mut buf = zeroed_buffer(0);
            // SAFETY: buf is a valid, correctly sized v4l2_buffer; fd is ours.
            let rc = unsafe {
                libc::ioctl(
                    self.fd,
                    vidioc_dqbuf(),
                    &mut buf as *mut _ as *mut libc::c_void,
                )
            };
            if rc < 0 {
                // EAGAIN simply means nothing is ready yet, which is the
                // ordinary way this loop ends on a non-blocking fd.
                return;
            }
            let index = buf.index as usize;
            if let Some(mapped) = self.buffers.get(index) {
                let used = (buf.bytesused as usize).min(mapped.len);
                // SAFETY: the driver has handed this buffer back to us and will
                // not touch it until it is re-queued below; `used` is within
                // the mapping.
                let bytes = unsafe { std::slice::from_raw_parts(mapped.ptr as *const u8, used) };
                if let Some(illum) = parse_illumination(bytes) {
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

    fn ioctl(
        &self,
        request: libc::c_ulong,
        argp: *mut libc::c_void,
        what: &str,
    ) -> std::result::Result<(), String> {
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
}

impl Drop for IlluminationLog {
    fn drop(&mut self) {
        if self.streaming {
            let mut kind = META_CAPTURE as c_int;
            let _ = self.ioctl(
                vidioc_streamoff(),
                &mut kind as *mut _ as *mut libc::c_void,
                "STREAMOFF",
            );
        }
        // Unmap our views, then hand the buffers back to the driver. Both are
        // needed before the format can be changed: unmapping alone leaves the
        // queue allocated and V4L2 refuses S_FMT on an allocated queue, so
        // skipping this silently left the node on UVCM for the next process
        // (measured: the format survived every capture until REQBUFS(0) was
        // added here).
        self.buffers.clear();
        let mut release = V4l2RequestBuffers {
            count: 0,
            kind: META_CAPTURE,
            memory: MEMORY_MMAP,
            capabilities: 0,
            flags: 0,
            _reserved: [0; 3],
        };
        let _ = self.ioctl(
            vidioc_reqbufs(),
            &mut release as *mut _ as *mut libc::c_void,
            "REQBUFS(0)",
        );
        // The format outlives this process, so hand the node back as found.
        if self.restore_format != 0 && self.restore_format != UVCM {
            let _ = self.set_format(self.restore_format);
        }
        if self.fd >= 0 {
            // SAFETY: fd was opened by this type and is closed exactly once.
            unsafe { libc::close(self.fd) };
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
/// image node, so the pairing is "same `device` link, different node". Matching
/// on the interface rather than on `videoN + 1` is what keeps this correct on a
/// machine with several cameras, where numbering interleaves.
fn metadata_node_for(ir_device: &str) -> Option<String> {
    // Diagnostic kill switch, added while working #187's hardware session.
    // On a camera whose four nodes share ONE USB interface (Logitech Brio),
    // the lowest-number-first sibling search below picks the RGB stream's
    // metadata node for the IR camera, and arming that queue is suspected of
    // breaking the RGB stream it belongs to (VIDIOC_QBUF EINVAL mid-burst).
    // The switch exists so that suspicion can be tested on hardware without
    // a rebuild; absence of the variable changes nothing.
    if std::env::var_os("IRLUME_NO_ILLUM_META").is_some_and(|v| v == "1") {
        irlume_common::dlog!("{ir_device}: illumination metadata disabled (IRLUME_NO_ILLUM_META)");
        return None;
    }
    let sysfs = std::path::Path::new("/sys/class/video4linux");
    let found = siblings_on_same_interface(ir_device, sysfs)
        .into_iter()
        .find(|c| offers_uvcm(c));
    if found.is_none() {
        irlume_common::dlog!(
            "{ir_device}: no sibling node offers UVCM metadata; illumination will come from brightness"
        );
    }
    found
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
fn node_number(node: &str) -> u32 {
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
    use super::*;

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
        first.push(DARK_FLAGS);
        first.extend_from_slice(&0u32.to_le_bytes());
        first.extend_from_slice(&[0u8; 6]);
        let mut both = first;
        both.extend_from_slice(&real_buffer(true, LIT_FLAGS));
        assert_eq!(parse_illumination(&both), Some(Illumination::Lit));
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

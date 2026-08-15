// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright the irlume contributors.

//! V4L2 capture for the paired RGB + IR cameras, and active-IR-emitter control.
//!
//! Hardware model (Windows-Hello-class module): one RGB sensor (`/dev/video0`)
//! and one greyscale IR sensor (`/dev/video2`), plus an 850/940nm emitter fired
//! via a UVC Extension-Unit control write (cf. linux-enable-ir-emitter).
//!
//! The auth path captures RGB and IR one at a time unless a measurement says
//! the module can sustain both: `capture_mode_decision` in irlume-auth answers
//! sequential for a pair with no stored verdict (#340), because a wrong
//! concurrent default broke an enrollment outright on the Logitech Brio
//! (#308) and dims the NexiGo N930W's RGB from mean ~120 to ~71 (below
//! YuNet's detection floor) with no error, while a wrong sequential default
//! costs ~0.7 s (ASUS) to ~1.3 s (NexiGo) per capture. Concurrent runs when
//! `camera-tune` or the enrollment probe stored
//! `capture_mode.<rgb-id>+<ir-id> = concurrent` for the pairing; both modules
//! measured deliver frames concurrently (examples/concurrency_probe.rs).
//! `IRLUME_SEQUENTIAL_CAPTURE` overrides BOTH directions: `1` forces
//! back-to-back, any other value forces concurrent. A shared-USB module that
//! HARD-fails a starved stream shows up as a capture error and the caller
//! retries that side alone; one that degrades the RGB frame silently is
//! recovered by the cross-spectrum self-heal in irlume-auth (IR-has-a-face
//! while RGB-does-not triggers an RGB-alone recapture).
//!
//! Implementation: the `v4l` crate (V4L2). RGB capture requests the first
//! uncompressed format the camera offers (YUYV, then NV12) and converts to
//! RGB8. FOOTGUN: enumerate V4L2 controls defensively; naive control queries
//! panic on some drivers. Probe, don't assume.

mod backend;
/// Versioned, backend-neutral camera data contracts.
pub mod contracts;
pub mod emitter_journal;
pub mod frame_provenance;
mod inventory;
pub mod ir_dark;
pub mod ir_emitter;
mod ir_metadata;
pub mod lease;
mod lifecycle;
mod media_graph;
// Public for exactly one item, `pending_summary`, doctor's read-only view of
// the store (#429); every record type stays crate-private so no other code
// path grows a reader of these files.
pub mod stream_record;
pub mod uvc_descriptor;

/// Serializes unit tests that mutate process-global environment variables, and
/// the RAII guard that restores them.
///
/// One lock for the whole crate, deliberately. Three modules here flip env vars
/// in tests and two of them had grown their OWN private mutex; a second mutex
/// guarding the same process-global serialises a module against itself and
/// nothing else, which passes locally and fails under load. Rust's `set_var`
/// also races any concurrent env READ anywhere in the process, so the lock has
/// to cover every mutator in the crate to mean anything.
///
/// `EnvGuard` restores the PREVIOUS value rather than unsetting: unsetting is
/// not restoring, and a test that leaves `IRLUME_STATE_DIR` cleared changes what
/// the next one resolves.
///
/// It also serialises tests that SPAWN PROCESSES, which is not obvious from the
/// name and is the cause of #251. `fork` copies the file descriptor table, and
/// an `flock` belongs to the open file description, so a child briefly holds
/// every lock its parent held at the moment of the fork. `O_CLOEXEC` closes the
/// inherited copy at `exec`, not at `fork`, so `Command::spawn` leaves a window
/// in which an unrelated test's lock is held by a child that knows nothing
/// about it. A test that then releases its lock and immediately re-takes it
/// gets `Busy` from a lock nothing appears to hold, which is why `/proc/locks`
/// looks empty a moment later. `flock_is_inherited_across_fork` pins the
/// mechanism.
#[cfg(test)]
pub(crate) mod testenv {
    pub(crate) static ENV_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

    pub(crate) fn env_lock() -> std::sync::MutexGuard<'static, ()> {
        // A panic under the lock (a failed assert) must not cascade into every
        // later env test; the environment is per-test state, not shared data.
        ENV_LOCK.lock().unwrap_or_else(|p| p.into_inner())
    }

    /// RAII env-var override: restores the previous value (or absence) on drop,
    /// so a panicking assertion cannot leak state into later tests.
    pub(crate) struct EnvGuard {
        key: &'static str,
        prev: Option<std::ffi::OsString>,
    }

    impl EnvGuard {
        pub(crate) fn set(key: &'static str, val: impl AsRef<std::ffi::OsStr>) -> Self {
            let prev = std::env::var_os(key);
            std::env::set_var(key, val);
            Self { key, prev }
        }
        pub(crate) fn unset(key: &'static str) -> Self {
            let prev = std::env::var_os(key);
            std::env::remove_var(key);
            Self { key, prev }
        }
    }

    impl Drop for EnvGuard {
        fn drop(&mut self) {
            match self.prev.take() {
                Some(v) => std::env::set_var(self.key, v),
                None => std::env::remove_var(self.key),
            }
        }
    }
}

use irlume_common::Error;
use v4l::buffer::Type;
use v4l::format::Quantization;
use v4l::video::Capture;
use v4l::{Device, Format, FourCC};

/// A single captured frame, tagged with which spectrum it came from.
pub struct Frame {
    pub width: u32,
    pub height: u32,
    pub spectrum: Spectrum,
    /// Raw bytes: RGB8 (R,G,B interleaved) for `Rgb`, GREY (8-bit) for `Ir`.
    pub data: Vec<u8>,
    /// When the pixels were taken. Callers that reason about one scene across
    /// BOTH sensors need this: the RGB and IR frames of one decision come from
    /// separate streams that can drift apart without it.
    pub captured: CaptureWindow,
}

/// The span of time a frame's pixels came from, on the monotonic clock.
///
/// Most frames are one dequeue, so `start == end`. Two are not: the denoised RGB
/// frame is a per-pixel median over a burst, and the IR frame is one chosen from
/// a burst, so their contents belong to a stretch of time rather than an instant.
/// Keeping the stretch (instead of stamping "now" at return) is what lets
/// [`CaptureWindow::gap_to`] state a real bound rather than a flattering one.
#[derive(Clone, Copy, Debug)]
pub struct CaptureWindow {
    pub start: std::time::Instant,
    pub end: std::time::Instant,
}

impl CaptureWindow {
    /// A window covering a single instant.
    pub fn at(t: std::time::Instant) -> Self {
        Self { start: t, end: t }
    }

    /// The smallest window containing both.
    pub fn union(self, other: Self) -> Self {
        Self {
            start: self.start.min(other.start),
            end: self.end.max(other.end),
        }
    }

    /// Time between the two windows: zero when they overlap, otherwise the gap
    /// between the end of the earlier and the start of the later. This is the
    /// worst case for "do these two frames show the same moment?", which is the
    /// question the cross-spectrum cues actually depend on.
    pub fn gap_to(self, other: Self) -> std::time::Duration {
        if self.start <= other.end && other.start <= self.end {
            return std::time::Duration::ZERO;
        }
        if self.end < other.start {
            other.start - self.end
        } else {
            self.start - other.end
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Spectrum {
    Rgb,
    Ir,
}

/// Burst statistics from an IR capture. `lit_mean` is the mean of the frame
/// capture chose to gate on: with camera illumination metadata and a known
/// sensor ceiling that is the brightest lit frame clipping at most 5% (#221),
/// otherwise the brightest eligible frame. `ambient_mean` is the darkest frame
/// the camera flagged dark, falling back to the burst minimum. When the emitter
/// strobes, `ambient_mean` is the scene's ambient IR level with the emitter off
/// and `lit_mean - ambient_mean` is the strobe gap; on a steady emitter the two
/// converge.
// Not Copy: `saturation_frame` owns a frame's worth of pixels, and a silent
// per-use copy of that is not something a caller should get by accident.
#[derive(Clone, Debug)]
pub struct IrCaptureStats {
    pub lit_mean: f32,
    pub ambient_mean: f32,
    /// True only when the camera itself classified BOTH a lit and a dark
    /// frame in this burst. False means `ambient_mean` is merely the burst's
    /// minimum, which on a steady emitter converges toward `lit_mean` and is
    /// NOT an emitter-off observation; callers attributing light to the room
    /// must check this first (#312 review).
    pub ambient_observed: bool,
    pub burst_frames: usize,
    /// How many burst frames the camera itself classified as lit or dark, via
    /// its UVC illumination metadata. Zero means the camera reported nothing
    /// and the two means above are the burst's brightness extremes, as they
    /// always were. Recorded so "the metadata path ran" is something callers
    /// can check rather than assume.
    pub camera_classified_frames: usize,
    /// The decoded value that means "this pixel was at or above the sensor's
    /// ceiling", or `None` when the negotiated format cannot support that
    /// claim. A caller measuring clipping (#221) must treat `None` as NOT
    /// MEASURED, never as zero clipping.
    ///
    /// Only the native 8-bit greys qualify: there a decoded 255 IS the
    /// sensor's full-scale sample. The Y16 family does not, because
    /// `grey16_shift` picks the shift from the frame's OWN maximum, so a
    /// decoded 255 means "the brightest pixel in this frame" and a dim frame
    /// full of them is ordinary.
    ///
    /// NV12 and YUYV answer `None`, and the reason this comment used to give
    /// was wrong. It said irlume does not carry the negotiated quantization.
    /// irlume does: `IrCamera::open` stores `fmt.quantization` and
    /// `clipping_white_level` already takes it.
    ///
    /// Carrying it is still not enough to compute their ceiling, and each
    /// draft of this comment has mislocated why, which is itself the lesson:
    /// `Quantization::Default` is not an effective range, V4L2 resolves it
    /// with `V4L2_MAP_QUANTIZATION_DEFAULT(is_rgb_or_hsv, colsp, ycbcr_enc)`.
    /// Since #427 `IrCamera` retains the negotiated `v4l::Format` with its
    /// colorspace, but the pinned v4l 0.14 `Format` drops the driver-echoed
    /// Y'CbCr ENCODING on conversion, and the encoding is a live input:
    /// default YUV is full range for JPEG colorspace AND for XV601/XV709
    /// encodings, limited otherwise (the Codex round on this PR caught the
    /// second draft classifying every non-JPEG case as limited, a
    /// 235-ceiling that would falsely refuse legitimate frames). The
    /// resolution is therefore still not generally computable here, and no
    /// NV12 or YUYV IR camera exists in this project's record to validate
    /// either arm against.
    ///
    /// The `None` is also load-bearing, which matters more than either.
    /// `role_from_formats` calls any node advertising either fourcc
    /// `Role::Rgb`, whatever else it advertises, so no DISCOVERED pair ever
    /// reaches an IR decode with them. The ones that do arrive by the
    /// `IRLUME_CAMERA_*` override, a saved pin, or the `/dev/video2` fallback,
    /// and there this `None` is what makes `exposure_refusal` refuse. Do not
    /// add a ceiling here without first adding something that guarantees the
    /// selected node is an emitter-lit IR source (#385).
    pub white_level: Option<u8>,
    /// The gate frame's RAW pixels, present only when the returned frame is no
    /// longer them: ambient subtraction replaces the payload, and a caller
    /// measuring clipping must not measure the replacement.
    ///
    /// Subtraction cannot restore a sample that reached the ceiling, but it
    /// does move it: a raw 255 minus an ambient 1 is 254, so a face that
    /// clipped 25% measures 0% afterwards and an exposure guard reading it
    /// would pass a frame that carries no information (#238 review). The
    /// camera's own note two screens up already said pixels saturated in the
    /// lit frame carry no reliable subtracted value; this keeps the evidence
    /// for the guard that acts on it.
    ///
    /// `None` means the returned frame IS the raw gate frame, so measure that.
    pub saturation_frame: Option<Vec<u8>>,
}

pub const DEFAULT_RGB_DEVICE: &str = "/dev/video0";
pub const DEFAULT_IR_DEVICE: &str = "/dev/video2";
const RGB_W: u32 = 640;
const RGB_H: u32 = 480;
const AE_WARMUP: usize = 6; // discard frames while auto-exposure settles

/// V4L2 privacy-control id (`V4L2_CID_PRIVACY`), a hardware shutter/kill switch.
pub const V4L2_CID_PRIVACY: u32 = 0x009a_0910;
/// `V4L2_CID_BACKLIGHT_COMPENSATION`: makes auto-exposure favor the (face)
/// subject over a bright background, fixing the backlit-window case.
pub const V4L2_CID_BACKLIGHT_COMPENSATION: u32 = 0x0098_091c;

/// The backlight-compensation value RGB sessions apply. 2 is the strongest
/// setting on both cameras measured (NexiGo N930W face mean 49→124; ASUS
/// FHD center mean 138.5→150.6, the 2026-08-12 session measurements).
const BLC_WANTED: i64 = 2;

/// Whether the backlight-compensation write should happen, and what it would
/// displace. `None` skips the write: an unreadable control is not a license
/// (the camera may not have one, EINVAL, or the observation failed, and
/// writing blind would remember a displaced value nobody measured), and a
/// control already at [`BLC_WANTED`] is another writer's state, which
/// mirrors the emitter guard's active-but-not-armed rule. Pure, so the
/// fail-safe directions are testable without a camera (#426).
fn blc_write_decision(read: std::io::Result<v4l::control::Control>) -> Option<i64> {
    match read.ok()?.value {
        v4l::control::Value::Integer(now) if now != BLC_WANTED => Some(now),
        _ => None,
    }
}

/// What a restore should write back: the displaced value, but only while the
/// control reads as holding what irlume applied. A control that moved (as of
/// that read; V4L2 has no compare-and-set, so a write racing between the
/// read and the restore cannot be excluded) carries somebody else's newer
/// choice, and restoring over it is the exact harm #426 exists to remove.
/// Pure for the same reason as the write decision. Doubles as the
/// confirmation gate in [`apply_blc`]: the predicate that authorises the
/// eventual restore must already hold immediately after the write, or the
/// write missed and is undone on the spot.
fn blc_restore_decision(
    displaced: i64,
    read: std::io::Result<v4l::control::Control>,
) -> Option<i64> {
    match read.ok()?.value {
        v4l::control::Value::Integer(now) if now == BLC_WANTED => Some(displaced),
        _ => None,
    }
}

/// Owns the one restore of a backlight-compensation write (#426). Held by
/// the session, CONSTRUCTED BEFORE the stream opens: the first version
/// restored from the session's own `Drop`, so a stream open that failed
/// after the write (REQBUFS, or the #427 format-moved refusal) returned with
/// no session and the control leaked changed, reproducing the defect the
/// change exists to close (Codex round on this PR).
struct BlcRestore<'a> {
    cam: &'a RgbCamera,
    displaced: i64,
}

impl Drop for BlcRestore<'_> {
    fn drop(&mut self) {
        // Read back before restoring: only a control still reading as
        // irlume's value carries a change of irlume's to undo. Best-effort
        // like the write; a failed restore costs the next application a
        // tuned picture, which is the pre-#426 behaviour on every session,
        // and must not disturb an authentication's teardown.
        let read = self.cam.dev.control(V4L2_CID_BACKLIGHT_COMPENSATION);
        if let Some(put_back) = blc_restore_decision(self.displaced, read) {
            if self.cam.lease.require_endpoint(&self.cam.device).is_err() {
                irlume_common::dlog!(
                    "{}: skipped backlight-compensation restore after lease invalidation",
                    self.cam.device
                );
                return;
            }
            let restored = self.cam.dev.set_control(v4l::control::Control {
                id: V4L2_CID_BACKLIGHT_COMPENSATION,
                value: v4l::control::Value::Integer(put_back),
            });
            if restored.is_err() {
                irlume_common::dlog!(
                    "{}: backlight compensation left at {BLC_WANTED}; restoring {put_back} failed",
                    self.cam.device
                );
            }
        }
    }
}

/// Apply the backlight-compensation tuning and arm its restore, or leave the
/// camera untouched. The guard is armed only when the read-back CONFIRMS the
/// device holds exactly [`BLC_WANTED`]: V4L2 permits a driver to clamp a set
/// request to the nearest valid value instead of refusing it, and the pinned
/// v4l crate discards the ioctl's returned effective value, so "set_control
/// returned Ok" is not "the device holds 2" (Codex round on this PR; a
/// camera clamping to a smaller maximum would otherwise arm a restore whose
/// condition could never hold and keep the clamped value forever). A write
/// whose result cannot be confirmed is undone on the spot, best-effort: the
/// one thing known then is that irlume just changed the control.
fn apply_blc(cam: &RgbCamera) -> Option<BlcRestore<'_>> {
    let displaced = blc_write_decision(cam.dev.control(V4L2_CID_BACKLIGHT_COMPENSATION))?;
    cam.lease.require_endpoint(&cam.device).ok()?;
    cam.dev
        .set_control(v4l::control::Control {
            id: V4L2_CID_BACKLIGHT_COMPENSATION,
            value: v4l::control::Value::Integer(BLC_WANTED),
        })
        .ok()?;
    let confirm = cam.dev.control(V4L2_CID_BACKLIGHT_COMPENSATION);
    if blc_restore_decision(displaced, confirm).is_some() {
        Some(BlcRestore { cam, displaced })
    } else {
        cam.lease.require_endpoint(&cam.device).ok()?;
        let _ = cam.dev.set_control(v4l::control::Control {
            id: V4L2_CID_BACKLIGHT_COMPENSATION,
            value: v4l::control::Value::Integer(displaced),
        });
        None
    }
}

/// Frozen-stream recovery for burst captures: after this many consecutive
/// identical frames the stream is torn down and re-opened, at most
/// `FROZEN_RESTART_BUDGET` times per burst (a fully static feed therefore
/// yields 1 + budget frames instead of hanging).
const FROZEN_RUN_BEFORE_RESTART: usize = 2;
const FROZEN_RESTART_BUDGET: usize = 4;

/// mmap ring size for every V4L2 capture stream. Four buffers is the classic
/// quad-buffer: enough that the driver never stalls waiting for a dequeue at
/// 30fps, small enough to be granted by every UVC camera we have seen.
const MMAP_BUFFERS: u32 = 4;

/// The capture adapter used by the trusted dequeue boundary.
///
/// Returning owned metadata is deliberate: v4l reuses its metadata ring, so no
/// reference may survive another dequeue.
trait CaptureDequeue {
    fn dequeue(&mut self) -> std::io::Result<(&[u8], v4l::buffer::Metadata)>;
}

impl CaptureDequeue for v4l::io::mmap::Stream<'_> {
    fn dequeue(&mut self) -> std::io::Result<(&[u8], v4l::buffer::Metadata)> {
        let (mapped, metadata) = v4l::io::traits::CaptureStream::next(self)?;
        Ok((mapped, *metadata))
    }
}

fn dequeue_validated<S, R>(
    stream: &mut S,
    layout: frame_provenance::PayloadLayout,
    mut require_endpoint: R,
) -> std::io::Result<(&[u8], frame_provenance::DequeuedBufferFacts)>
where
    S: CaptureDequeue,
    R: FnMut() -> std::io::Result<()>,
{
    require_endpoint()?;
    let (mapped, metadata) = stream.dequeue()?;
    require_endpoint()?;
    let facts = frame_provenance::DequeuedBufferFacts::from_v4l(&metadata, mapped.len())
        .map_err(std::io::Error::other)?;
    layout.validate(&facts).map_err(std::io::Error::other)?;
    Ok((&mapped[..facts.bytes_used()], facts))
}

/// A capture stream whose teardown cannot take the process down.
///
/// v4l 0.14's `Stream::drop` calls `stop()` and PANICS on any failure except
/// ENODEV (`io/mmap/stream.rs:92`). That is a real hazard here: the daemon runs
/// as root and opens a stream for every authentication, so one camera that
/// errors on STREAMOFF would panic out of a destructor, and a destructor panic
/// while another panic is unwinding aborts the whole process. The frames are
/// already dequeued by then, and nothing we return depends on STREAMOFF
/// succeeding, so the failure is worth a log line and nothing more.
///
/// Wrapping (rather than calling a "drop it safely" helper at each success
/// path) is deliberate: every `?` early return drops the stream too, and those
/// are exactly the paths a failing camera takes.
struct SafeStream<'a> {
    inner: Option<v4l::io::mmap::Stream<'a>>,
    device: String,
    lease: lease::CameraLease,
    layout: frame_provenance::PayloadLayout,
    lease_started: bool,
}

/// How long a single frame dequeue may block.
///
/// Generous next to a 30fps stream, short enough that a wedged camera surfaces
/// as an error instead of a hang. The daemon's watchdog is 90s, so this has to
/// be well inside it.
const STREAM_DEQUEUE_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(5);

/// Warm-up retry budget (see [`warm_up_stream`]): how many dequeue attempts
/// the post-resume race gets, and the pause between them. The race it covers
/// (uvcvideo re-initializing after suspend or USB re-enumeration) fails FAST,
/// with EIO/ENODEV in milliseconds, so eight tries spaced 120ms apart cover
/// roughly a second of re-init without adding meaningful wall time. `TimedOut`
/// keeps the same full budget on purpose: a camera that sits silent for two
/// windows and delivers on its third succeeded before #336 and must keep
/// succeeding after it (Codex review of PR #338), so the watchdog problem is
/// solved by REPORTING each returned window, never by shrinking this budget.
const WARMUP_TRIES: u32 = 8;
const WARMUP_GAP: std::time::Duration = std::time::Duration::from_millis(120);

/// A between-boundaries progress reporter for long camera work (#141, #336).
///
/// The daemon's watchdog decides the worker has wedged when nothing reports
/// progress for half of `WatchdogSec`, and a frameless camera legitimately
/// spends many 5s dequeue windows inside ONE capture. Each COMPLETED window is
/// reported through this callback: a dequeue that RETURNED `TimedOut` proves
/// the thread was not stuck in the kernel, while an ioctl that never returns
/// reports nothing and still looks wedged, which is exactly the distinction
/// the watchdog exists to make. `Send + Sync` because the concurrent capture
/// pair polls it from scoped threads. Callers without a watchdog pass
/// [`no_progress`].
pub type Progress = std::sync::Arc<dyn Fn() + Send + Sync>;

/// A [`Progress`] that reports nowhere, for callers without a watchdog (the
/// CLI, examples, tests).
pub fn no_progress() -> Progress {
    std::sync::Arc::new(|| {})
}

/// The longest a correctly wired capture path can wait inside ONE driver call
/// before either delivering, erroring, or reporting progress: a full dequeue
/// window plus the warm-up pause that precedes the next one. In milliseconds,
/// derived from the constants it names so an edit to either moves this bound
/// with it. `irlume-auth` builds its worst-case silent stretch on top of this,
/// and an `irlume-daemon` test holds that stretch against the `WatchdogSec` in
/// `packaging/systemd/irlumed.service` (#336), so lengthening a dequeue window
/// past what the watchdog tolerates fails the suite instead of shipping.
pub const CAPTURE_SILENT_WINDOW_WORST_MS: u64 =
    STREAM_DEQUEUE_TIMEOUT.as_millis() as u64 + WARMUP_GAP.as_millis() as u64;

/// Whether the device's current format still matches what open negotiated,
/// naming the first field that moved. Pure, so the comparison is testable
/// without a second process to race against (#427).
///
/// EVERY field of the negotiated format is compared, not just the geometry
/// the decoders read directly. The first version checked width, height and
/// fourcc and argued quantization was derived from them; the Codex round
/// refuted that from the kernel spec (a capture application can request
/// colorimetry conversion where the driver offers
/// `V4L2_PIX_FMT_FLAG_SET_CSC`), and quantization is authentication-relevant
/// here: it names the clipping ceiling (235 versus 255 in
/// `clipping_white_level`), so a racing format change that held the geometry
/// but flipped the range would either false-clip legitimate frames or, in
/// the inverse direction, suppress the exposure refusal that protects the
/// liveness cues. Stride matters the same way: the decoders treat rows as
/// tightly packed, so a changed `bytesperline` at the same geometry would
/// decode every row at the wrong offset. Comparing the rest costs nothing
/// and refuses only when the device state genuinely differs from what this
/// caller negotiated.
///
/// The enum fields compare by their wire discriminant (`as u32`) because the
/// pinned v4l crate derives no `PartialEq` for them.
fn format_moved(expect: &v4l::Format, now: &v4l::Format) -> Option<String> {
    if now.fourcc.repr != expect.fourcc.repr {
        return Some(format!(
            "fourcc is now {}, negotiated {}",
            fourcc_str(&now.fourcc.repr),
            fourcc_str(&expect.fourcc.repr)
        ));
    }
    if (now.width, now.height) != (expect.width, expect.height) {
        return Some(format!(
            "size is now {}x{}, negotiated {}x{}",
            now.width, now.height, expect.width, expect.height
        ));
    }
    if now.stride != expect.stride {
        return Some(format!(
            "stride is now {}, negotiated {}",
            now.stride, expect.stride
        ));
    }
    if now.size != expect.size {
        return Some(format!(
            "image size is now {}, negotiated {}",
            now.size, expect.size
        ));
    }
    if now.field_order as u32 != expect.field_order as u32 {
        return Some(format!(
            "field order is now {:?}, negotiated {:?}",
            now.field_order, expect.field_order
        ));
    }
    if now.colorspace as u32 != expect.colorspace as u32 {
        return Some(format!(
            "colorspace is now {:?}, negotiated {:?}",
            now.colorspace, expect.colorspace
        ));
    }
    if now.quantization as u32 != expect.quantization as u32 {
        return Some(format!(
            "quantization is now {:?}, negotiated {:?}",
            now.quantization, expect.quantization
        ));
    }
    if now.transfer as u32 != expect.transfer as u32 {
        return Some(format!(
            "transfer function is now {:?}, negotiated {:?}",
            now.transfer, expect.transfer
        ));
    }
    if now.flags.bits() != expect.flags.bits() {
        return Some(format!(
            "format flags are now {:?}, negotiated {:?}",
            now.flags, expect.flags
        ));
    }
    None
}

impl<'a> SafeStream<'a> {
    /// Open a stream on `dev` with the standard buffer ring, and verify the
    /// device still holds the format the caller negotiated.
    ///
    /// The verification exists because the negotiated format is per-device
    /// state, not per-file-handle: uvcvideo writes S_FMT to the shared
    /// streaming struct gated only on buffer ownership, and ownership begins
    /// at REQBUFS, not at open (#427; the audit in
    /// docs/research/2026-08-12-camera-handling-audit.md, Q3). Between the
    /// caller's S_FMT and the REQBUFS here, any other process can retarget
    /// the device, and the capture would then decode frames against stale
    /// width, height and fourcc assumptions. Once `with_buffers` returns,
    /// this handle owns the queue and S_FMT answers EBUSY to everyone, so a
    /// G_FMT read taken HERE is stable for the stream's whole life; the same
    /// window recurs at every reopen (recover, the frozen-stream restarts),
    /// which is why the check lives in the one function they all call.
    ///
    /// A dequeue timeout is set explicitly. v4l leaves it unset, which polls
    /// with -1 and waits forever, so a camera that stops delivering frames
    /// without erroring blocks the caller indefinitely. That matters most
    /// during emitter setup: a stall there would hang with a control changed and
    /// the restore never reached. Every wait now ends.
    fn open(
        device: &str,
        dev: &'a Device,
        expect: &v4l::Format,
        lease: lease::CameraLease,
    ) -> irlume_common::Result<Self> {
        lease
            .require_endpoint(device)
            .map_err(|error| Error::Hardware(error.to_string()))?;
        let layout = frame_provenance::PayloadLayout::new(
            expect.fourcc.repr,
            expect.width,
            expect.height,
            expect.stride,
        )
        .map_err(|error| Error::Hardware(format!("{device}: {error}")))?;
        let mut inner = v4l::io::mmap::Stream::with_buffers(dev, Type::VideoCapture, MMAP_BUFFERS)
            .map_err(|e| map_io(device, e))?;
        inner.set_timeout(STREAM_DEQUEUE_TIMEOUT);
        // Constructed before the read-back so every error path below releases
        // the queue through the guarded Drop (STREAMOFF + REQBUFS(0)), never
        // through the v4l crate's panicking one.
        let mut stream = Self {
            inner: Some(inner),
            device: device.to_string(),
            lease,
            layout,
            lease_started: false,
        };
        let now = Capture::format(dev).map_err(|e| map_io(device, e))?;
        stream
            .lease
            .require_endpoint(device)
            .map_err(|error| Error::Hardware(error.to_string()))?;
        if let Some(moved) = format_moved(expect, &now) {
            // Refusing rather than renegotiating, for the same reason the
            // emitter stands down under a foreign consumer (#169): a format
            // that moved means another application is actively configuring
            // this camera, and fighting it over shared state serves nobody.
            // The cost is one refused capture, which degrades toward the
            // password prompt.
            let who = match camera_holder(device) {
                Some(h) => format!(", likely {h}"),
                None => String::new(),
            };
            return Err(Error::Hardware(format!(
                "{device}: the stream format changed between negotiation and \
                 buffer claim ({moved}). Another application is configuring \
                 this camera{who}; refusing this capture"
            )));
        }
        stream
            .lease
            .start_stream()
            .map_err(|error| Error::Hardware(error.to_string()))?;
        stream.lease_started = true;
        Ok(stream)
    }

    fn next(&mut self) -> std::io::Result<(&[u8], frame_provenance::DequeuedBufferFacts)> {
        let Self {
            inner,
            device,
            lease,
            layout,
            ..
        } = self;
        dequeue_validated(
            inner.as_mut().expect("stream taken only in Drop"),
            *layout,
            || {
                lease
                    .require_endpoint(device)
                    .map_err(std::io::Error::other)
            },
        )
    }
}

trait ValidatedStream {
    fn next_validated(&mut self)
        -> std::io::Result<(&[u8], frame_provenance::DequeuedBufferFacts)>;
}

impl ValidatedStream for SafeStream<'_> {
    fn next_validated(
        &mut self,
    ) -> std::io::Result<(&[u8], frame_provenance::DequeuedBufferFacts)> {
        self.next()
    }
}

/// Sequence state whose lifetime is independent of its replaceable mmap stream.
struct TrackedStream<S> {
    stream: Option<S>,
    sequence: frame_provenance::SequenceTracker,
}

impl<S> TrackedStream<S> {
    fn new(stream: S) -> Self {
        Self {
            stream: Some(stream),
            sequence: frame_provenance::SequenceTracker::new(),
        }
    }

    fn stream_mut(&mut self) -> Option<&mut S> {
        self.stream.as_mut()
    }

    fn take(&mut self) -> Option<S> {
        self.stream.take()
    }

    fn install_recovered(
        &mut self,
        stream: S,
    ) -> Result<(), frame_provenance::SequenceTrackerError> {
        self.sequence.begin_new_epoch()?;
        self.stream = Some(stream);
        Ok(())
    }
}

impl<S: ValidatedStream> TrackedStream<S> {
    fn next(
        &mut self,
    ) -> std::io::Result<(
        &[u8],
        frame_provenance::DequeuedBufferFacts,
        frame_provenance::SequenceObservation,
    )> {
        let Self { stream, sequence } = self;
        let (payload, facts) = stream
            .as_mut()
            .ok_or_else(|| std::io::Error::other("capture stream missing after recovery"))?
            .next_validated()?;
        let observation = sequence
            .observe(facts.sequence_raw())
            .map_err(std::io::Error::other)?;
        Ok((payload, facts, observation))
    }
}

fn install_recovered_resources<S, M, G, E>(
    replacement: S,
    metadata: M,
    emitter_guard: G,
    install: impl FnOnce(S) -> Result<(), E>,
) -> Result<(M, G), E> {
    match std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| install(replacement))) {
        Ok(Ok(())) => Ok((metadata, emitter_guard)),
        Ok(Err(error)) => {
            // The replacement is dropped before `install` returns. Stop any
            // separately-owned metadata queue before restoring the emitter.
            drop(metadata);
            drop(emitter_guard);
            Err(error)
        }
        Err(payload) => {
            // Preserve panic semantics after enforcing the same teardown order.
            drop(metadata);
            drop(emitter_guard);
            std::panic::resume_unwind(payload);
        }
    }
}

impl Drop for SafeStream<'_> {
    fn drop(&mut self) {
        let Some(inner) = self.inner.take() else {
            return;
        };
        let device = self.device.clone();
        if std::panic::catch_unwind(std::panic::AssertUnwindSafe(move || drop(inner))).is_err() {
            irlume_common::dlog!("{device}: stream teardown failed (STREAMOFF); frames unaffected");
        }
        if self.lease_started {
            self.lease.stop_stream();
        }
    }
}

/// Colour pixel formats imply an RGB sensor; greyscale-only implies the IR
/// companion. linhello lesson: classify by advertised FourCC, never hardcode.
const COLOUR_FOURCCS: [&[u8; 4]; 5] = [b"YUYV", b"MJPG", b"RGB3", b"BGR3", b"NV12"];
const GREY_FOURCCS: [&[u8; 4]; 3] = [b"GREY", b"Y8  ", b"Y800"];
/// 16-bit grey family (16-bit LE words, LSB-aligned data per the V4L2 spec);
/// classification treats these as IR too, and capture decodes them to 8-bit.
const GREY16_FOURCCS: [&[u8; 4]; 3] = [b"Y16 ", b"Y10 ", b"Y12 "];

/// Map common io errors to actionable messages (linhello lesson: EBUSY/privacy
/// are routine and need a clear cause, not a raw errno).
fn map_io(device: &str, e: std::io::Error) -> Error {
    use std::io::ErrorKind;
    match e.raw_os_error() {
        Some(16) => {
            // 16 == EBUSY. The advice has to match what the scan actually
            // established: telling someone to close an app is useless when the
            // holder is irlume itself, and worse when the scan could not see
            // the holder at all (#187 restarted the daemon for days on the
            // strength of a sentence naming irlumed).
            Error::Hardware(match camera_holders(device) {
                Holders::Other(who) => format!(
                    "{device}: camera busy, in use by {who}. \
                     Close that app (e.g. a camera/video/conferencing app) and retry."
                ),
                Holders::SelfOnly => format!(
                    "{device}: camera busy, and the only process holding it is irlume itself \
                     (pid {}). That is an irlume bug, not an app you can close; please report \
                     it with the output of `irlume doctor`.",
                    std::process::id()
                ),
                Holders::UnknownBlind => format!(
                    "{device}: camera busy. irlume could not identify the holder, because it \
                     cannot read every process (see issue #207); `sudo fuser -v {device}` will \
                     name it. Close that app and retry."
                ),
                Holders::None => format!(
                    "{device}: camera busy, another app is using it. \
                     Close that app (e.g. a camera/video/conferencing app) and retry."
                ),
            })
        }
        _ if e.kind() == ErrorKind::PermissionDenied => Error::Hardware(format!(
            "{device}: permission denied; add your user to the 'video' group (camera) and re-login"
        )),
        // These errnos are search keys, not verdicts (#340 review round).
        // map_io has no operation context: it maps opens, S_FMT, buffer
        // setup, dequeues and controls alike, and the kernel reuses each
        // errno across paths (uvcvideo returns EINVAL for a malformed frame
        // descriptor as well as for a rejected argument, and normalizes
        // failed PROBE/COMMIT transfers to EIO, which xHCI admission answers
        // as ENOSPC). So the message hands the reader the deciding
        // instrument, the kernel log, instead of naming a culprit the errno
        // alone cannot convict. No behavior branches on either arm.
        Some(libc::EINVAL) => Error::Hardware(format!(
            "{device}: {e}. The driver rejected an argument or the device's advertised \
             format/control state; this errno alone does not distinguish a firmware \
             refusal from invalid format metadata. The matching dmesg line names the \
             failing path"
        )),
        Some(libc::EIO) | Some(libc::ENOSPC) => Error::Hardware(format!(
            "{device}: {e}. Stream setup or I/O failed; the causes this errno covers \
             include UVC negotiation failure, malformed endpoint information, device \
             reset/resume, and USB bandwidth admission. Check the matching kernel log \
             line before assigning the cause"
        )),
        _ => Error::Hardware(format!("{device}: {e}")),
    }
}

/// Best-effort: which process currently holds `device` open, for a clearer
/// camera-busy message. Scans `/proc/<pid>/fd` for a symlink to the device;
/// needs root to see other users' processes (the daemon runs as root). Returns
/// e.g. "kamoso (pid 2567)", or `None` if it can't tell.
fn camera_holder(device: &str) -> Option<String> {
    match camera_holders(device) {
        Holders::Other(who) => Some(who),
        // Only our own handle, and the scan saw everything: nothing the user
        // can close, so say what it is.
        Holders::SelfOnly => Some(format!(
            "irlume itself (pid {}), which is a bug in irlume rather than another app; \
             please report it with the output of `irlume doctor`",
            std::process::id()
        )),
        // We cannot see every process (#207), so the holder may be an app whose
        // /proc entry is unreadable. Measured 2026-08-03: with Chrome streaming
        // /dev/video0, the scan found only irlume's own fd, because Chrome's fd
        // directory was not readable. Claiming SelfOnly there would accuse
        // irlume of a bug on the strength of a blind spot.
        Holders::UnknownBlind => None,
        Holders::None => None,
    }
}

/// Who holds `device` open, separating another process from this one, and both
/// from the case where the scan could not see enough to answer.
enum Holders {
    /// Some other process has it. The one the user has to close.
    Other(String),
    /// Our own handle, on a scan that could read every process. irlume
    /// competing with itself is a defect, not something the user can act on.
    SelfOnly,
    /// Nothing found but the scan was incomplete, or only our own handle was
    /// found on such a scan. Either way the real holder may be invisible.
    UnknownBlind,
    /// Nothing found, on a scan that could read every process.
    None,
}

fn camera_holders(device: &str) -> Holders {
    let Ok(dev) = std::fs::canonicalize(device) else {
        return Holders::None;
    };
    let me = std::process::id().to_string();
    let mut saw_self = false;
    // A process whose fd directory we cannot read may be the holder. Tracking
    // that is what separates "irlume has a bug" from "irlume cannot tell".
    let mut blind = false;
    let Ok(procs) = std::fs::read_dir("/proc") else {
        return Holders::UnknownBlind;
    };
    for ent in procs.flatten() {
        let name = ent.file_name();
        let Some(pid) = name.to_str() else { continue };
        if pid.is_empty() || !pid.bytes().all(|b| b.is_ascii_digit()) {
            continue;
        }
        let fds = match std::fs::read_dir(ent.path().join("fd")) {
            Ok(fds) => fds,
            Err(e) => {
                // A process that exited between readdir and here is not a blind
                // spot; a permission refusal is.
                if e.kind() == std::io::ErrorKind::PermissionDenied {
                    blind = true;
                }
                continue;
            }
        };
        // Listing another process's fd directory can succeed while RESOLVING
        // its entries is refused: the daemon runs without CAP_SYS_PTRACE
        // (#207), and measured 2026-08-03 that is exactly what happens against
        // a browser holding the camera. Checking only the read_dir error left
        // `blind` false, so the scan concluded "nobody but us" while Chrome was
        // streaming the node.
        let mut holds = false;
        for fd in fds.flatten() {
            match std::fs::read_link(fd.path()) {
                Ok(t) => {
                    if t == dev {
                        holds = true;
                        break;
                    }
                }
                Err(e) if e.kind() == std::io::ErrorKind::PermissionDenied => blind = true,
                Err(_) => {}
            }
        }
        if !holds {
            continue;
        }
        if pid == me {
            // Keep scanning: another process holding the same node is the
            // answer that helps, and it may sort after us.
            saw_self = true;
            continue;
        }
        let comm = std::fs::read_to_string(ent.path().join("comm")).unwrap_or_default();
        let comm = comm.trim();
        return Holders::Other(if comm.is_empty() {
            format!("pid {pid}")
        } else {
            format!("{comm} (pid {pid})")
        });
    }
    holder_verdict(saw_self, blind)
}

/// What a scan that found no OTHER holder concluded, as a value.
///
/// Separated out because the interesting branch is unreachable in a test: only
/// a process that can read every `/proc` entry, in practice root, can say the
/// holder is nobody but itself. The decision is still a function of two
/// booleans, so it is the decision that gets tested (see #187, where a wrong
/// answer here cost the reporter days of restarting the daemon).
fn holder_verdict(saw_self: bool, blind: bool) -> Holders {
    match (saw_self, blind) {
        // A blind spot outranks everything: the holder may be a process this
        // scan could not read, so neither "it is us" nor "nobody" is honest.
        (_, true) => Holders::UnknownBlind,
        (true, false) => Holders::SelfOnly,
        (false, false) => Holders::None,
    }
}

/// What a video node is, by its advertised formats.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Role {
    Rgb,
    Ir,
    /// A capture node that answered and advertises neither colour nor grey,
    /// which is what a UVC metadata node looks like. A node that could not be
    /// read is NOT this: see `Unreadable`.
    Other,
}

/// A node whose format list is NOT evidence of a camera, so classifying it by
/// format would be asserting something the kernel never said (#425).
///
/// Two shapes, both from `VIDIOC_QUERYCAP`'s `device_caps` word rather than
/// from the formats:
///
/// - `V4L2_CAP_IO_MC`: the uAPI (open.rst) calls such a node MC-centric, and
///   vidioc-enum-fmt.rst says its format list describes what the IP core can
///   consume, not what any camera produces. Intel IPU6/IPU7 ISYS nodes
///   enumerate YUYV from a static table on every node, up to eight per CSI-2
///   port, so without this gate an IPU6 laptop scans as a fleet of RGB
///   cameras that all fail at STREAMON with EPIPE.
/// - Multi-planar without single-planar capture (`ipu3-cio2`, `qcom-camss`):
///   irlume's single-planar `ENUM_FMT` probe gets EINVAL there and used to
///   file these under [`Role::Other`] by accident of the probe shape. Naming
///   them keeps "irlume cannot use this" apart from "nothing to see".
///
/// Kept apart from [`Role`] for the same reason [`Unreadable`] is (#227): the
/// actions differ. `Other` is correctly ignored, `Unreadable` asks the user to
/// fix access, and this one is working hardware irlume must refuse to touch,
/// with a message naming the stack. Details and the per-driver capability
/// words are in `docs/research/2026-08-12-camera-handling-audit.md`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct McCentric {
    /// The driver name from `VIDIOC_QUERYCAP`, e.g. `isys` (Intel IPU6),
    /// `amd_isp_capture`, `qcom-camss`, `ipu3-cio2`.
    pub driver: String,
    /// `V4L2_CAP_IO_MC` was set: input/output is controlled by the media
    /// controller and the node's format list is not camera evidence.
    pub io_mc: bool,
    /// The node captures only through the multi-planar API, which irlume's
    /// capture path does not speak.
    pub mplane_only: bool,
}

impl McCentric {
    /// The cause without the path, same contract as [`Unreadable::cause`]: a
    /// caller can state one cause once over several nodes that share it. Pure
    /// over the struct so the wording is testable without MIPI hardware.
    pub fn cause(&self) -> String {
        // Both facts named when both flags are set: qcom-camss nodes carry
        // IO_MC and MPLANE together, and the message dropped the second.
        let stack = match (self.io_mc, self.mplane_only) {
            (true, true) => {
                "behind a media-controller stack (and multi-planar only); its \
                 advertised formats describe the platform's image pipeline, \
                 not a camera"
            }
            (true, false) => {
                "behind a media-controller stack; its advertised formats \
                 describe the platform's image pipeline, not a camera"
            }
            _ => {
                "captures only through the multi-planar V4L2 API, which \
                 irlume's capture path does not use"
            }
        };
        format!(
            "driver '{}', {stack}. irlume needs a UVC camera; the RGB side of \
             this device may work through libcamera/PipeWire, and its IR side \
             has no Linux support",
            self.driver
        )
    }
}

/// What `classify_node` decided about one node: a camera role read from its
/// formats, or a node whose formats must not be read as a role at all.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum NodeKind {
    Camera(Role),
    McCentric(McCentric),
}

/// Where reading a node failed. A node that could not be read is kept apart
/// from `Role::Other` all the way to the report, because the two call for
/// opposite actions: `Other` is a node correctly ignored, while this is a
/// camera whose kind is still unknown. Collapsing them told a user with a busy
/// or unreadable camera that the hardware was absent, which is the same
/// mistake `control_read_failure_means_absent` exists to prevent one function
/// below (#227).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FailedAt {
    /// `open(2)` on the node itself.
    Open,
    /// The node opened but `VIDIOC_QUERYCAP` failed, which no V4L2 node is
    /// permitted to refuse; `/dev/null` reaching this arm with ENOTTY is the
    /// ordinary non-V4L2 case.
    QueryCaps,
    /// The node opened, then would not enumerate its formats.
    EnumFormats,
}

/// A `/dev/video*` node that exists but could not be classified.
#[derive(Debug, Clone)]
pub struct Unreadable {
    pub path: String,
    pub at: FailedAt,
    /// `None` when the failure carried no OS error, which the v4l crate can
    /// produce for a malformed response rather than a syscall failure.
    pub errno: Option<i32>,
    /// The process holding the node, captured at scan time because a holder
    /// named a minute later may not be the one that caused the failure. Only
    /// looked up for EBUSY, and best-effort even then: `camera_holder` reads
    /// /proc and cannot see a holder owned by another uid (#207).
    pub holder: Option<String>,
}

impl Unreadable {
    /// The cause and its remedy, without the path, so a caller can state one
    /// cause once over the several nodes that share it. Pure over the struct,
    /// so the wording is testable without an unreadable camera to hand.
    /// Deliberately says what `map_io` says for the same errnos: a user who
    /// hits this in doctor and then again mid-capture should not get two
    /// different explanations of one condition.
    pub fn cause(&self) -> String {
        let what = match self.at {
            FailedAt::Open => "could not be opened",
            FailedAt::QueryCaps => "opened but did not answer VIDIOC_QUERYCAP",
            FailedAt::EnumFormats => "opened but would not list its formats",
        };
        let why = match self.errno {
            Some(libc::EACCES) | Some(libc::EPERM) => {
                "permission denied; add your user to the 'video' group (camera) and re-login"
                    .to_string()
            }
            Some(libc::EBUSY) => match &self.holder {
                Some(h) => format!("camera busy, in use by {h}. Close that app and retry"),
                None => {
                    "camera busy, another app is using it. Close that app and retry".to_string()
                }
            },
            Some(libc::ENODEV) | Some(libc::ENXIO) => {
                "the node is present but the device behind it is gone, which is what an \
                 unplugged or reset USB camera leaves behind"
                    .to_string()
            }
            _ => "cause unknown; the errno above is reported as the driver gave it".to_string(),
        };
        let code = match self.errno {
            Some(e) => format!("errno {e}: {}", std::io::Error::from_raw_os_error(e)),
            None => "no OS error reported".to_string(),
        };
        format!("{what} ({code}). {why}")
    }

    /// The cause with this node's path in front, for reporting one node alone.
    pub fn explain(&self) -> String {
        format!("{} {}", self.path, self.cause())
    }
}

/// The no-open half of classification (#428): the media graph says whether
/// this is a UVC function's CAPTURE node or its metadata sibling, and
/// opening `/dev/media*` is documented side-effect free where a video-node
/// open on pre-6.16 kernels powers the camera up. A metadata node answers
/// `Other` here, the same answer the open probe's EINVAL-at-ENUM_FMT arm
/// gives it, without the open.
///
/// A CAPTURE node deliberately answers `None` and takes the open probe. A
/// descriptor-derived format route was built and REMOVED in review: a video
/// node's sysfs parent names the UVC control function, not which of that
/// function's possibly several streaming interfaces backs this node, so the
/// blob cannot be attributed per node; the kernel skips formats with GUIDs
/// it does not know, so any userspace table is a subset whose omissions
/// change the enumerated set; and uvcvideo applies per-device quirks
/// (`UVC_QUIRK_FORCE_Y8` and kin) that rewrite the list the node actually
/// reports. Until all three can be reproduced faithfully, ENUM_FMT on the
/// node is the only sound format authority (Codex round on this PR).
///
/// Every other `None` is the same honest fall-through: loopback nodes have
/// no USB parent, MC-centric platform stacks keep meeting the #425
/// QUERYCAP gate, and a failed sysfs read proves nothing. One asymmetry is
/// accepted: a PADLESS node on a non-UVC media stack answers `Other` here
/// without reaching the MC-centric gate, which ignores it exactly as the
/// gate would, minus doctor naming it.
fn classify_without_open(device: &str) -> Option<NodeKind> {
    if !media_graph::node_is_capture(device)? {
        return Some(NodeKind::Camera(Role::Other));
    }
    None
}

/// Classify a single `/dev/videoN` node, keeping a failure to read the node
/// apart from a node that read as neither kind.
///
/// The primary path is `classify_without_open` above: on UVC hardware the role
/// is fully decidable from sysfs and the media graph, and a video-node open
/// on kernels before 6.16 powers the camera up (uvcvideo moved power-up
/// into the ioctl dispatcher in 6.16), which is a privacy-LED blink per
/// scan. The open probe remains for everything the no-open path cannot
/// decide.
///
/// On the open path, `VIDIOC_QUERYCAP` runs first, because on an MC-centric
/// node the format list is not evidence of anything (#425); see
/// [`McCentric`]. Defensive: enumerate FORMATS (safe), never
/// `query_controls` (panics on some UVC drivers; a hard-won linhello
/// lesson).
#[expect(clippy::missing_errors_doc, reason = "doc backlog")]
pub fn classify_node(device: &str) -> Result<NodeKind, Unreadable> {
    if let Some(kind) = classify_without_open(device) {
        return Ok(kind);
    }
    let unreadable = |at, e: std::io::Error| Unreadable {
        path: device.to_string(),
        at,
        errno: e.raw_os_error(),
        // Filled in by `scan_nodes` for a busy node; classifying one node in
        // isolation does not walk /proc.
        holder: None,
    };
    let _permit = lease::permit_for_discovery(device, std::time::Duration::from_secs(2))
        .map_err(|error| unreadable(FailedAt::Open, std::io::Error::other(error)))?;
    let dev = Device::with_path(device).map_err(|e| unreadable(FailedAt::Open, e))?;
    let caps = queried_caps(&dev).map_err(|e| unreadable(FailedAt::QueryCaps, e))?;
    if let Some(mc) = mc_centric_verdict(&caps) {
        return Ok(NodeKind::McCentric(mc));
    }
    capture_formats_answered(&dev).map_err(|e| unreadable(FailedAt::EnumFormats, e))?;
    let formats = Capture::enum_formats(&dev).map_err(|e| unreadable(FailedAt::EnumFormats, e))?;
    let fourccs: Vec<[u8; 4]> = formats.iter().map(|f| f.fourcc.repr).collect();
    Ok(NodeKind::Camera(role_from_formats(&fourccs)))
}

/// `VIDIOC_QUERYCAP`, raw. The pinned v4l crate's `Device::query_caps` cannot
/// carry this decision: its `Capabilities.capabilities` is filled from the
/// kernel's `device_caps` word but through `Flags::from_bits_truncate`, and
/// the crate defines no `IO_MC` bit, so the one flag the gate needs is
/// silently dropped (v4l 0.14.0, capability.rs:101 and the Flags list at 6-45).
/// Same direct-ioctl shape as `capture_formats_answered` below.
fn queried_caps(dev: &Device) -> std::io::Result<v4l::v4l_sys::v4l2_capability> {
    #[expect(clippy::undocumented_unsafe_blocks, reason = "doc backlog")]
    let mut caps: v4l::v4l_sys::v4l2_capability = unsafe { std::mem::zeroed() };
    // SAFETY: `dev` owns the fd for the length of this call, and `caps` is a
    // correctly sized, zeroed v4l2_capability, which is all VIDIOC_QUERYCAP
    // writes.
    let rc = unsafe {
        libc::ioctl(
            dev.handle().fd(),
            v4l::v4l2::vidioc::VIDIOC_QUERYCAP,
            &mut caps as *mut _ as *mut libc::c_void,
        )
    };
    if rc < 0 {
        return Err(std::io::Error::last_os_error());
    }
    Ok(caps)
}

/// The `device_caps` word of a QUERYCAP answer, or the whole-device word when
/// the driver predates the split. `V4L2_CAP_DEVICE_CAPS` has been mandatory
/// since kernel 3.4, so the fallback arm is for out-of-tree stragglers; using
/// the wrong word there risks reading a sibling node's capabilities, which for
/// this gate errs toward refusing, the safe direction.
fn node_device_caps(caps: &v4l::v4l_sys::v4l2_capability) -> u32 {
    if caps.capabilities & v4l::v4l_sys::V4L2_CAP_DEVICE_CAPS != 0 {
        caps.device_caps
    } else {
        caps.capabilities
    }
}

/// The NUL-terminated driver name from a QUERYCAP answer, lossily.
fn caps_driver(caps: &v4l::v4l_sys::v4l2_capability) -> String {
    let end = caps
        .driver
        .iter()
        .position(|&b| b == 0)
        .unwrap_or(caps.driver.len());
    String::from_utf8_lossy(&caps.driver[..end]).into_owned()
}

/// Decide from a QUERYCAP answer whether this node's format list may be read
/// as a camera role at all. Pure over the struct, so the per-driver capability
/// words measured in the audit are each pinned by a test without the hardware:
/// Intel IPU6 ISYS (`V4L2_CAP_IO_MC` on single-planar nodes), AMD ISP4
/// (IO_MC), Qualcomm camss (IO_MC and MPLANE), ipu3-cio2 (MPLANE only), and
/// the two UVC node shapes plus v4l2loopback, which must all pass through.
fn mc_centric_verdict(caps: &v4l::v4l_sys::v4l2_capability) -> Option<McCentric> {
    let dc = node_device_caps(caps);
    let io_mc = dc & v4l::v4l_sys::V4L2_CAP_IO_MC != 0;
    let mplane_only = dc & v4l::v4l_sys::V4L2_CAP_VIDEO_CAPTURE_MPLANE != 0
        && dc & v4l::v4l_sys::V4L2_CAP_VIDEO_CAPTURE == 0;
    if !(io_mc || mplane_only) {
        return None;
    }
    Some(McCentric {
        driver: caps_driver(caps),
        io_mc,
        mplane_only,
    })
}

/// Whether the node ANSWERED the format enumeration, separate from what it
/// answered. `Capture::enum_formats` in the pinned v4l 0.14.0 returns
/// `Ok(Vec::new())` for any error at index 0, so a node that refused to answer
/// is indistinguishable there from one that legitimately offers no capture
/// format. The kernel gives EINVAL for "no format at this index", which is both
/// the normal end of enumeration and what a non-capture node (a UVC metadata
/// node) returns at index 0; every other errno is a failed observation. Asking
/// index 0 directly is the only way to tell those apart with this crate
/// version, and telling them apart is the whole of #227.
fn capture_formats_answered(dev: &Device) -> std::io::Result<()> {
    #[expect(clippy::undocumented_unsafe_blocks, reason = "doc backlog")]
    let mut desc: v4l::v4l_sys::v4l2_fmtdesc = unsafe { std::mem::zeroed() };
    desc.index = 0;
    desc.type_ = v4l::buffer::Type::VideoCapture as u32;
    // SAFETY: `dev` owns the fd for the length of this call, and `desc` is a
    // correctly sized, zeroed v4l2_fmtdesc, which is what VIDIOC_ENUM_FMT
    // reads and writes. Same shape as the ioctl helper in ir_metadata.rs.
    let rc = unsafe {
        libc::ioctl(
            dev.handle().fd(),
            v4l::v4l2::vidioc::VIDIOC_ENUM_FMT,
            &mut desc as *mut _ as *mut libc::c_void,
        )
    };
    if rc >= 0 {
        return Ok(());
    }
    let e = std::io::Error::last_os_error();
    if enum_fmt_failure_means_no_formats(&e) {
        return Ok(());
    }
    Err(e)
}

/// Whether a failed `VIDIOC_ENUM_FMT` at index 0 means the node HAS no capture
/// format, as opposed to having formats it would not report. The kernel
/// specifies EINVAL as "no format at this index", which is both the normal end
/// of enumeration and what a non-capture node answers at index 0; every UVC
/// camera puts a metadata node on the machine that lands here, and warning
/// about those would bury the report this fix exists to produce. Every other
/// errno is a failure to observe. Same shape and the same rule as
/// `control_read_failure_means_absent`, and pure for the same reason: the
/// decision is testable without a camera that misbehaves.
fn enum_fmt_failure_means_no_formats(e: &std::io::Error) -> bool {
    e.raw_os_error() == Some(libc::EINVAL)
}

/// `classify_node` for callers that only act on a node they can use. An
/// unreadable node answers `Other` here, and so does an MC-centric one: both
/// are nodes a camera-picking caller must not open, so anything reporting to
/// a human wants `classify_node` or `scan_nodes` instead.
pub fn classify(device: &str) -> Role {
    match classify_node(device) {
        Ok(NodeKind::Camera(role)) => role,
        Ok(NodeKind::McCentric(_)) | Err(_) => Role::Other,
    }
}

/// Pure classification over a node's advertised fourccs (unit-testable without
/// hardware). 8-bit grey and the 16-bit grey family (Y16/Y10/Y12) are both IR
/// signatures: Y16-only IR nodes exist and previously classified as Other,
/// silently demoting the machine to the RGB convenience tier.
pub(crate) fn role_from_formats(fourccs: &[[u8; 4]]) -> Role {
    let mut has_colour = false;
    let mut has_grey = false;
    for cc in fourccs {
        if COLOUR_FOURCCS.contains(&cc) {
            has_colour = true;
        }
        if GREY_FOURCCS.contains(&cc) || GREY16_FOURCCS.contains(&cc) {
            has_grey = true;
        }
    }
    match (has_colour, has_grey) {
        (true, _) => Role::Rgb,
        (false, true) => Role::Ir,
        _ => Role::Other,
    }
}

/// The video nodes found in a directory, and why the answer may be short.
#[derive(Debug, Clone, Default)]
pub(crate) struct NodeListing {
    pub paths: Vec<String>,
    /// Set when the directory could not be listed, or an entry in it could
    /// not be read. An empty `paths` with this set means "could not look",
    /// which is not the same answer as "nothing there" and must not be
    /// reported as one.
    pub error: Option<String>,
}

/// Every `video*` node in `dir`, in numeric order. Reads the directory rather
/// than probing a fixed range: the old `/dev/video0..9` scan never looked at
/// `/dev/video10`, which a machine with two cameras and a couple of
/// v4l2loopback nodes reaches without being unusual (#227). Takes the
/// directory so the ordering and filtering are testable against a fake root
/// instead of whatever this machine happens to have plugged in.
pub(crate) fn video_node_paths_in(dir: &std::path::Path) -> NodeListing {
    let entries = match std::fs::read_dir(dir) {
        Ok(e) => e,
        Err(e) => {
            return NodeListing {
                paths: Vec::new(),
                error: Some(format!("{} could not be listed: {e}", dir.display())),
            }
        }
    };
    let mut nodes: Vec<(u32, String)> = Vec::new();
    let mut unreadable_entries = 0usize;
    for entry in entries {
        let Ok(entry) = entry else {
            unreadable_entries += 1;
            continue;
        };
        let Ok(name) = entry.file_name().into_string() else {
            continue;
        };
        let Some(n) = name
            .strip_prefix("video")
            .and_then(|d| d.parse::<u32>().ok())
        else {
            continue;
        };
        nodes.push((n, dir.join(&name).to_string_lossy().into_owned()));
    }
    // Numeric, not lexical: a string sort puts video10 before video9.
    nodes.sort_unstable();
    NodeListing {
        paths: nodes.into_iter().map(|(_, p)| p).collect(),
        error: (unreadable_entries > 0).then(|| {
            format!(
                "{unreadable_entries} entries in {} could not be read",
                dir.display()
            )
        }),
    }
}

pub(crate) fn video_node_paths() -> NodeListing {
    video_node_paths_in(std::path::Path::new("/dev"))
}

/// Every video node split into the ones that answered and the ones that could
/// not be read. `discover_nodes` throws the second group away, which is right
/// for callers picking a camera to open and wrong for anything reporting to a
/// person.
#[derive(Debug, Clone, Default)]
pub struct NodeScan {
    /// Nodes that answered, excluding `Role::Other`.
    pub classified: Vec<(String, Role)>,
    pub unreadable: Vec<Unreadable>,
    /// Nodes refused before format enumeration because their format list is
    /// not camera evidence (#425). Working hardware, deliberately unused;
    /// reports name these so an IPU6 laptop reads as "MIPI camera irlume
    /// cannot use", never as a fleet of RGB cameras and never as no camera
    /// with no explanation.
    pub mc_centric: Vec<(String, McCentric)>,
    /// Why this scan may be incomplete. An empty scan with this set means the
    /// nodes could not be listed, not that there are none.
    pub listing_error: Option<String>,
}

/// File one classification outcome into its `NodeScan` bucket. The arms are
/// the whole point of #425: only `Camera(Rgb|Ir)` may reach `classified`,
/// because that is the bucket every camera-picking caller consumes. Pure over
/// the outcome, so the bucketing is testable without a device per arm.
fn file_node(scan: &mut NodeScan, path: String, outcome: Result<NodeKind, Unreadable>) {
    match outcome {
        Ok(NodeKind::Camera(Role::Other)) => {}
        Ok(NodeKind::Camera(role)) => scan.classified.push((path, role)),
        Ok(NodeKind::McCentric(mc)) => scan.mc_centric.push((path, mc)),
        Err(u) => scan.unreadable.push(u),
    }
}

/// `with_holders` walks /proc for each busy node to name what holds it. That
/// is worth a report a person reads and not worth it for the camera-picking
/// callers, which run on the TUI's refresh path.
fn uvc_scan(with_holders: bool) -> NodeScan {
    let mut scan = NodeScan::default();
    let listing = video_node_paths();
    scan.listing_error = listing.error;
    for path in listing.paths {
        let outcome = classify_node(&path).map_err(|mut u| {
            if with_holders && u.errno == Some(libc::EBUSY) {
                u.holder = camera_holder(&u.path);
            }
            u
        });
        file_node(&mut scan, path, outcome);
    }
    scan
}

fn uvc_discover_nodes() -> Vec<(String, Role)> {
    uvc_scan(false).classified
}

/// Classify every video node, keeping the failures and naming what holds a
/// busy one. For reports; use `discover_nodes` to pick a camera.
pub fn scan_nodes() -> NodeScan {
    backend::scan_nodes()
}

/// Scan for each readable capture node, returning (path, role).
pub fn discover_nodes() -> Vec<(String, Role)> {
    backend::discover_nodes()
}

/// Whether a failed privacy-control read means the camera does not HAVE the
/// control, as opposed to having one that could not be read. The V4L2
/// specification assigns EINVAL to an unsupported control id, and ENOTTY means
/// the device does not implement the control ioctls at all; both are absence
/// of the feature, stable across retries. Everything else (EIO, ENODEV, ...)
/// is a failure to observe a control that may exist, which must never be
/// reported as "not engaged" (#193 review). Pure so the classification is
/// testable without hardware.
fn control_read_failure_means_absent(e: &std::io::Error) -> bool {
    matches!(e.raw_os_error(), Some(libc::EINVAL) | Some(libc::ENOTTY))
}

/// Read the privacy control, keeping three outcomes apart: `Ok(Some(engaged))`
/// when the control answered, `Ok(None)` when the camera does not have one,
/// and `Err` when the observation itself failed. The old bool-returning check
/// collapsed the third into the second, which let a transient read failure on
/// a shuttered camera license a firmware write.
fn privacy_state(dev: &Device) -> std::io::Result<Option<bool>> {
    match dev.control(V4L2_CID_PRIVACY) {
        Ok(ctrl) => Ok(Some(
            matches!(ctrl.value, v4l::control::Value::Boolean(true))
                || matches!(ctrl.value, v4l::control::Value::Integer(n) if n != 0),
        )),
        Err(e) if control_read_failure_means_absent(&e) => Ok(None),
        Err(e) => Err(e),
    }
}

/// Best-effort privacy-shutter check for the CAPTURE paths. Returns `true` only
/// when the control answered "engaged"; an unopenable device or a failed read
/// stays `false`, because the cost of failing open here is a capture of dark
/// frames and a refused authentication, which the pipeline already handles.
/// `setup_ir_emitter` deliberately does NOT use this: it writes to firmware,
/// where an unknown shutter state must refuse — see `privacy_permits_setup`.
pub fn privacy_engaged(device: &str) -> bool {
    let Ok(_permit) = lease::permit_for_endpoint(
        device,
        lease::CameraOperationKind::Diagnostics,
        std::time::Duration::from_secs(2),
    ) else {
        return false;
    };
    privacy_engaged_with_permit(device)
}

fn privacy_engaged_with_permit(device: &str) -> bool {
    let Ok(dev) = Device::with_path(device) else {
        return false;
    };
    matches!(privacy_state(&dev), Ok(Some(true)))
}

/// The decision `setup_ir_emitter` makes about one privacy observation, as a
/// value: an engaged shutter refuses, and a FAILED observation refuses too,
/// because "could not read the switch" is not "the switch is released". Only a
/// control that answered "released", or a camera that has no such control, may
/// proceed to a firmware write. Pure and used by the production path, so the
/// fail-closed rule is testable without hardware.
fn privacy_permits_setup(observed: std::io::Result<Option<bool>>) -> Result<(), String> {
    match observed {
        Ok(Some(true)) => Err("the hardware privacy shutter is engaged (the `privacy` \
             control reads 1), so the sensor returns a blank frame and discovery \
             would measure nothing; release the shutter and re-run \
             `sudo irlume ir-setup`"
            .into()),
        Ok(Some(false)) | Ok(None) => Ok(()),
        Err(e) => Err(format!(
            "could not read the hardware privacy control ({e}); refusing to write \
             to camera firmware while the shutter state is unknown"
        )),
    }
}

/// The backend classification from a `VIDIOC_QUERYCAP` answer. The V4L2
/// specification requires USB devices to report a bus string starting with
/// `usb-`, so the split is the interface's own, not a sysfs-path heuristic
/// (the kernel's sysfs rules say not to depend on the `device`/`driver` link
/// topology). Pure so both halves of the split are testable without a camera.
fn backend_from_caps(driver: String, bus: &str) -> (String, bool) {
    (driver, bus.starts_with("usb-"))
}

/// The kernel driver behind a video node and whether V4L2 reports it on USB.
/// This answers the first question of every camera bug report: is this the
/// `uvcvideo`-on-USB case irlume is built and tested for, or an IPU/MIPI or
/// other pipeline that merely looks similar? #187's diagnosis had to ask for
/// exactly this by shell script; `doctor` now reads it itself. A failure is an
/// `Err` the caller must render, never silence: an unobserved backend on a
/// diagnostic surface has to say "unknown" (#195 review).
#[expect(clippy::missing_errors_doc, reason = "doc backlog")]
pub fn node_backend(device: &str) -> std::io::Result<(String, bool)> {
    let _permit = lease::permit_for_endpoint(
        device,
        lease::CameraOperationKind::Diagnostics,
        std::time::Duration::from_secs(2),
    )
    .map_err(std::io::Error::other)?;
    let dev = Device::with_path(device)?;
    let caps = dev.query_caps()?;
    Ok(backend_from_caps(caps.driver, &caps.bus))
}

/// True iff a sysfs `device` path traces to a real hardware bus (USB/PCI) and
/// not a virtual/loopback origin. Pure so it can be unit-tested without sysfs.
fn is_physical_camera_path(p: &str) -> bool {
    (p.contains("/usb") || p.contains("/devices/pci"))
        && !p.contains("/devices/virtual")
        && !p.contains("v4l2loopback")
}

/// Walk up from `start` to the first ancestor dir holding `attr` (e.g. the USB
/// device dir that carries `idVendor`/`removable`, above the interface node).
fn find_attr_dir(start: &std::path::Path, attr: &str) -> Option<std::path::PathBuf> {
    let mut p = start.to_path_buf();
    loop {
        if p.join(attr).exists() {
            return Some(p);
        }
        p = p.parent()?.to_path_buf();
        if !p.starts_with("/sys/devices") {
            return None;
        }
    }
}

pub(crate) fn virtual_camera_allowed(device: &str) -> bool {
    std::env::var("IRLUME_TEST_ALLOW_VIRTUAL_CAMERA")
        .map(|allow| allow.split(',').any(|allowed| allowed.trim() == device))
        .unwrap_or(false)
}

/// Camera device-pinning: verify `/dev/videoN` is a real, physically-attached
/// camera before any frame is read, defeating unprivileged software frame
/// injection (v4l2loopback / OBS virtual camera). See docs/THREAT_MODEL.md.
///
/// Always enforced: the device must resolve through sysfs to a physical bus
/// (USB/PCI), never a virtual/platform node; the anti-injection gate, needs no
/// per-host config. Additionally, when `IRLUME_CAMERA_PIN` is set the USB
/// descriptor must be in the allowlist: a comma-separated set of `"vid:pid"`
/// lowercase hex (e.g. `3277:0059,046d:085e` to allow the built-in *and* an
/// external Logitech Brio); when `IRLUME_CAMERA_REQUIRE_FIXED=1` the `removable`
/// attribute must read `fixed` (rejects a hot-plugged external camera;
/// supplementary, and intentionally *off* by default so external Hello cameras
/// work; `removable` is also frequently `unknown` even for legitimate devices).
#[expect(clippy::missing_errors_doc, reason = "doc backlog")]
pub fn verify_pinned(device: &str) -> irlume_common::Result<()> {
    // Distinguish "no camera at all" from "a node that isn't physical"; the
    // anti-injection message only makes sense when something answered to the path.
    if !std::path::Path::new(device).exists() {
        return Err(Error::Hardware(format!("{device}: no camera found")));
    }
    // TEST ESCAPE: a comma-separated allowlist of exact device paths that may
    // bypass the physical-device pin. Exists only for the virtual-camera test
    // harness (v4l2loopback nodes have no physical bus by definition). The
    // daemon's environment is root-controlled via its systemd unit, so an
    // unprivileged local user cannot set this for the auth path; every use is
    // logged loudly. See docs/THREAT_MODEL.md (camera injection).
    if virtual_camera_allowed(device) {
        eprintln!(
            "irlume: WARNING: {device} accepted without a physical-device pin \
             (IRLUME_TEST_ALLOW_VIRTUAL_CAMERA)"
        );
        return Ok(());
    }
    let node = device.strip_prefix("/dev/").unwrap_or(device);
    let link = format!("/sys/class/video4linux/{node}/device");
    let real = std::fs::canonicalize(&link).map_err(|_| {
        Error::Hardware(format!(
            "{device}: no physical device in sysfs (virtual camera?); refusing to authenticate"
        ))
    })?;
    let p = real.to_string_lossy();
    if !is_physical_camera_path(&p) {
        return Err(Error::Hardware(format!(
            "{device}: '{p}' is not a physical-bus camera; refusing (anti-injection)"
        )));
    }
    let dev_dir = find_attr_dir(&real, "idVendor");
    if let Some(allow) = pin_allowlist() {
        match dev_dir.as_ref().and_then(|d| read_vidpid(d)) {
            Some(g) if allow.contains(&g) => {}
            Some(g) => {
                return Err(Error::Hardware(format!(
                    "{device}: camera {g} not in pinned set {allow:?}; refusing"
                )))
            }
            None => {
                return Err(Error::Hardware(format!(
                    "{device}: no USB descriptor to match pin {allow:?}; refusing"
                )))
            }
        }
    }
    if std::env::var("IRLUME_CAMERA_REQUIRE_FIXED")
        .map(|v| v == "1")
        .unwrap_or(false)
    {
        let removable = dev_dir
            .as_ref()
            .and_then(|d| std::fs::read_to_string(d.join("removable")).ok())
            .map(|s| s.trim().to_string());
        if removable.as_deref() != Some("fixed") {
            return Err(Error::Hardware(format!(
                "{device}: removable='{}' (want fixed); refusing hot-plugged camera",
                removable.as_deref().unwrap_or("?")
            )));
        }
    }
    Ok(())
}

/// Parse `IRLUME_CAMERA_PIN` into a lowercase `"vid:pid"` allowlist, or `None`
/// when unset/empty. Comma-separated so multiple cameras (built-in + external)
/// can be permitted. Pure (takes the raw value) so it is unit-testable.
fn parse_pin_allowlist(raw: &str) -> Option<Vec<String>> {
    let list: Vec<String> = raw
        .split(',')
        .map(|s| s.trim().to_lowercase())
        .filter(|s| !s.is_empty())
        .collect();
    (!list.is_empty()).then_some(list)
}

fn pin_allowlist() -> Option<Vec<String>> {
    parse_pin_allowlist(&std::env::var("IRLUME_CAMERA_PIN").ok()?)
}

/// `"vid:pid"` (lowercase hex) for a USB device dir, if it carries descriptors.
fn read_vidpid(dev_dir: &std::path::Path) -> Option<String> {
    let v = std::fs::read_to_string(dev_dir.join("idVendor")).ok()?;
    let p = std::fs::read_to_string(dev_dir.join("idProduct")).ok()?;
    Some(format!("{}:{}", v.trim(), p.trim()))
}

/// A stable identity for the physical camera behind `/dev/videoN`, for
/// per-enrollment device binding (anti-swap). Format: `"vid:pid"` plus
/// `":serial"` when the descriptor carries a serial (`idVendor:idProduct[:serial]`,
/// lowercase). `None` if the node has no USB descriptors (e.g. a virtual cam).
pub fn device_identity(device: &str) -> Option<String> {
    let node = device.strip_prefix("/dev/").unwrap_or(device);
    let real = std::fs::canonicalize(format!("/sys/class/video4linux/{node}/device")).ok()?;
    let dev_dir = find_attr_dir(&real, "idVendor")?;
    let vidpid = read_vidpid(&dev_dir)?;
    let id = match std::fs::read_to_string(dev_dir.join("serial")) {
        Ok(s) if !s.trim().is_empty() => format!("{vidpid}:{}", s.trim()),
        _ => vidpid,
    };
    Some(id.to_lowercase())
}

/// The sysfs USB-device dir shared by all interfaces (RGB + IR) of one physical
/// camera; two `/dev/videoN` nodes with the same id are the same camera.
fn physical_device_id(device: &str) -> Option<std::path::PathBuf> {
    let node = device.strip_prefix("/dev/").unwrap_or(device);
    let real = std::fs::canonicalize(format!("/sys/class/video4linux/{node}/device")).ok()?;
    find_attr_dir(&real, "idVendor")
}

/// The configured pair, using ONLY sources that never open a device: the
/// explicit env override, then the pair persisted in `cameras.conf` exactly as
/// saved. `None` when neither is set, because answering then would require
/// enumerating, and enumerating opens every node.
///
/// Exists for one caller shape: something that wants the pair while a daemon
/// MIGHT be mid-capture. A short socket poll timing out does not prove the
/// daemon is gone, and a busy capture is exactly what a timeout looks like, so
/// falling back to [`select_pair`] there would open the nodes at the worst
/// possible moment (#187). Identity re-resolution is deliberately skipped: it
/// probes, which is the thing being avoided.
pub fn configured_pair_no_probe() -> Option<(String, String)> {
    let nonblank_pair =
        |r: String, i: String| (!r.trim().is_empty() && !i.trim().is_empty()).then_some((r, i));
    if let (Ok(r), Ok(i)) = (
        std::env::var("IRLUME_RGB_DEVICE"),
        std::env::var("IRLUME_IR_DEVICE"),
    ) {
        if let Some(pair) = nonblank_pair(r, i) {
            return Some(pair);
        }
    }
    // One read of the whole file, so this no-probe path never combines an RGB
    // path from before a repin with an IR path from after it.
    let pin = irlume_common::config::read_camera_pin();
    match (pin.rgb, pin.ir) {
        (Some(r), Some(i)) => nonblank_pair(r, i),
        _ => None,
    }
}

/// Select the RGB+IR camera pair to authenticate with. Supports the built-in
/// Hello camera *and* external USB Hello webcams (Logitech Brio, NexiGo HelloCam)
/// without hard-coded node numbers. Precedence:
///   1. Explicit `IRLUME_RGB_DEVICE` + `IRLUME_IR_DEVICE`.
///   2. Auto-discovery: a Hello camera is one physical device exposing *both* an
///      RGB and an IR node. Ranked: a device matching `IRLUME_CAMERA_PIN` wins,
///      else a built-in (`removable=fixed`) wins, else the first pair found.
///   3. Compiled defaults (`video0`/`video2`).
pub fn select_pair() -> (String, String) {
    if let (Ok(r), Ok(i)) = (
        std::env::var("IRLUME_RGB_DEVICE"),
        std::env::var("IRLUME_IR_DEVICE"),
    ) {
        if !r.trim().is_empty() && !i.trim().is_empty() {
            return (r, i);
        }
    }
    // A user-chosen pair persisted via the daemon (TUI Cameras tab) overrides
    // auto-selection but not an explicit env override. Read the four pin keys
    // from ONE snapshot: the path and its identity are evaluated as a unit
    // below, so a repin landing mid-read must not split them across versions.
    let pin = irlume_common::config::read_camera_pin();
    if let (Some(r), Some(i)) = (pin.rgb.as_deref(), pin.ir.as_deref()) {
        if !r.trim().is_empty() && !i.trim().is_empty() {
            // The saved paths are bare /dev/videoN, which a kernel or udev
            // update can renumber, so a plain path pin can silently land on a
            // different sensor after an upgrade. When the pair was persisted
            // with its device identity (vid:pid:serial), trust the identity over
            // the number: keep the saved path only while it still resolves to
            // that camera, else re-find the node that carries the identity.
            let saved_rgb_id = nonblank(pin.rgb_id.clone());
            let saved_ir_id = nonblank(pin.ir_id.clone());
            if let Some(pair) =
                resolve_saved_pair(r, i, saved_rgb_id.as_deref(), saved_ir_id.as_deref())
            {
                return pair;
            }
        }
    }
    let allow = pin_allowlist();
    let (mut best, mut best_rank): (Option<(String, String)>, i32) = (None, -1);
    for p in list_pairs() {
        let rank = match (&allow, &p.id) {
            (Some(a), Some(v)) if a.iter().any(|w| w == v) => 3,
            _ if p.fixed => 2,
            _ => 1,
        };
        if rank > best_rank {
            best_rank = rank;
            best = Some((p.rgb, p.ir));
        }
    }
    best.unwrap_or_else(|| (DEFAULT_RGB_DEVICE.into(), DEFAULT_IR_DEVICE.into()))
}

fn device_exists(dev: &str) -> bool {
    std::path::Path::new(dev).exists()
}

/// `Some(trimmed)` for a present, non-empty config value; `None` otherwise. Lets
/// a persisted empty `rgb_id=` (written to clear a stale identity) read as absent.
fn nonblank(v: Option<String>) -> Option<String> {
    v.map(|s| s.trim().to_string()).filter(|s| !s.is_empty())
}

/// The `/dev/videoN` node whose physical camera identity matches `id` and whose
/// role is `role`, if one is present. Used to re-anchor a saved pin after a udev
/// renumber. When two cameras share a `vid:pid` with no serial the identities are
/// not unique; the first matching node wins, which is still the right sensor
/// class (RGB vs IR) even if not the exact unit.
fn find_node_by_identity(id: &str, role: Role) -> Option<String> {
    discover_nodes()
        .into_iter()
        .find(|(path, r)| *r == role && device_identity(path).as_deref() == Some(id))
        .map(|(path, _)| path)
}

/// Resolve the persisted camera pair to the paths to actually open. With no saved
/// identities (a pin written by a pre-identity version), keep the legacy
/// behaviour: trust the saved paths as long as both nodes still exist. With saved
/// identities, prefer the saved path only while it still resolves to that
/// identity, otherwise re-find the node that now carries it; returns `None` (fall
/// through to auto-discovery) when either camera can no longer be found.
fn resolve_saved_pair(
    r: &str,
    i: &str,
    r_id: Option<&str>,
    i_id: Option<&str>,
) -> Option<(String, String)> {
    let (Some(r_id), Some(i_id)) = (r_id, i_id) else {
        return (device_exists(r) && device_exists(i)).then(|| (r.to_string(), i.to_string()));
    };
    let resolve = |path: &str, want: &str, role: Role| -> Option<String> {
        if device_identity(path).as_deref() == Some(want) {
            Some(path.to_string())
        } else {
            find_node_by_identity(want, role)
        }
    };
    match (resolve(r, r_id, Role::Rgb), resolve(i, i_id, Role::Ir)) {
        (Some(r), Some(i)) => Some((r, i)),
        _ => None,
    }
}

/// Hardware capability summary, for "smart Auto": what biometric face hardware
/// is actually present. `IRLUME_FORCE_NO_IR=1` forces `ir_pair=false` (test the
/// RGB-only convenience path on an IR box, or pin a box to convenience mode).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct Caps {
    /// A physical camera exposing BOTH an RGB and an IR node (full Hello cam).
    pub ir_pair: bool,
    /// Any usable RGB camera node exists.
    pub rgb: bool,
}

/// Whether the operator explicitly disabled IR-backed authentication
/// (`IRLUME_FORCE_NO_IR=1`, the documented drop-to-convenience override in
/// docs/VERIFY.md). One reader, so a second consumer cannot drift on the
/// accepted value.
pub fn ir_forced_off() -> bool {
    std::env::var("IRLUME_FORCE_NO_IR")
        .map(|v| v == "1")
        .unwrap_or(false)
}

pub fn capabilities() -> Caps {
    let ir_pair = !ir_forced_off() && !list_pairs().is_empty();
    let rgb = ir_pair || discover_nodes().iter().any(|(_, r)| matches!(r, Role::Rgb));
    Caps { ir_pair, rgb }
}

/// A physical Hello camera exposing both an RGB and an IR node.
#[derive(Clone)]
pub struct CameraPair {
    pub rgb: String,
    pub ir: String,
    /// `idVendor:idProduct`, if readable.
    pub id: Option<String>,
    /// Built-in (`removable=fixed`) vs an external USB camera.
    pub fixed: bool,
}

/// Every physical camera that exposes both an RGB and an IR node (a Hello pair),
/// sorted built-in first. Drives the TUI camera picker.
pub fn list_pairs() -> Vec<CameraPair> {
    backend::list_pairs()
}

fn uvc_list_pairs() -> Vec<CameraPair> {
    let mut groups: std::collections::BTreeMap<std::path::PathBuf, (Vec<String>, Vec<String>)> =
        Default::default();
    for (path, role) in uvc_discover_nodes() {
        if let Some(id) = physical_device_id(&path) {
            let e = groups.entry(id).or_default();
            match role {
                Role::Rgb => e.0.push(path),
                Role::Ir => e.1.push(path),
                _ => {}
            }
        }
    }
    let mut out = Vec::new();
    for (id, (rgbs, irs)) in &groups {
        if rgbs.is_empty() || irs.is_empty() {
            continue;
        }
        let fixed = std::fs::read_to_string(id.join("removable"))
            .map(|s| s.trim() == "fixed")
            .unwrap_or(false);
        out.push(CameraPair {
            rgb: rgbs[0].clone(),
            ir: irs[0].clone(),
            id: read_vidpid(id),
            fixed,
        });
    }
    out.sort_by(|a, b| b.fixed.cmp(&a.fixed).then(a.rgb.cmp(&b.rgb)));
    out
}

/// Number of frames the auth path median-denoises over (~150ms @30fps): enough
/// that one blurry / over-exposed / transiently corrupt frame is outvoted.
const RGB_BURST: usize = 5;

struct SessionSlot<'a>(&'a std::sync::atomic::AtomicBool);

impl<'a> SessionSlot<'a> {
    fn acquire(
        active: &'a std::sync::atomic::AtomicBool,
        device: &str,
    ) -> irlume_common::Result<Self> {
        active
            .compare_exchange(
                false,
                true,
                std::sync::atomic::Ordering::AcqRel,
                std::sync::atomic::Ordering::Acquire,
            )
            .map_err(|_| Error::Hardware(format!("{device}: camera session already active")))?;
        Ok(Self(active))
    }
}

impl Drop for SessionSlot<'_> {
    fn drop(&mut self) {
        self.0.store(false, std::sync::atomic::Ordering::Release);
    }
}

/// An opened, format-negotiated RGB camera.
///
/// Exists so a caller that captures REPEATEDLY can pay the open, control write,
/// format negotiation, buffer mapping, STREAMON and auto-exposure warm-up ONCE
/// instead of per capture. Measured on the ASUS built-in: a denoised capture
/// holds the device 1.11s to collect roughly 400ms of frames, so about 700ms of
/// every call is setup. It also stops the capture LED blinking once per frame
/// grab, which is what the per-call lifecycle looks like from the outside.
///
/// Split into a device and a [`RgbSession`] because the v4l stream borrows its
/// device; one struct owning both would be self-referential. The device is the
/// long-lived half and the session is the streaming half.
pub struct RgbCamera {
    lease: lease::CameraLease,
    session_active: std::sync::atomic::AtomicBool,
    device: String,
    dev: Device,
    chosen: [u8; 4],
    width: u32,
    height: u32,
    /// The whole format the driver echoed at open, kept verbatim so sessions
    /// can verify the device still holds every field of it when they claim
    /// buffers (#427); see `format_moved` for why the geometry alone is not
    /// enough.
    negotiated: v4l::Format,
}

impl RgbCamera {
    /// Verify, open and negotiate. Does not start streaming: no buffers are
    /// allocated and the capture LED stays off until a session is opened.
    #[expect(clippy::missing_errors_doc, reason = "doc backlog")]
    pub fn open(device: &str) -> irlume_common::Result<Self> {
        if let Some(permit) =
            lease::active_permit(device).map_err(|error| Error::Hardware(error.to_string()))?
        {
            return backend::open_rgb(device, permit);
        }
        let operation = match lease::acquire_camera_operation(
            &[device],
            lease::CameraOperationKind::Capture,
            std::time::Duration::from_secs(2),
        ) {
            Ok(operation) => operation,
            Err(error @ lease::CameraLeaseError::Stale) => {
                verify_pinned(device)?;
                return Err(Error::Hardware(error.to_string()));
            }
            Err(error) => return Err(Error::Hardware(error.to_string())),
        };
        backend::open_rgb(device, operation.into_lease())
    }

    fn open_uvc(device: &str, lease: lease::CameraLease) -> irlume_common::Result<Self> {
        lease
            .require_endpoint(device)
            .map_err(|error| Error::Hardware(error.to_string()))?;
        verify_pinned(device)?;
        if privacy_engaged_with_permit(device) {
            return Err(Error::Hardware(format!(
                "{device}: hardware privacy switch is ON"
            )));
        }
        let dev = Device::with_path(device).map_err(|e| map_io(device, e))?;
        // Pick an uncompressed format the camera actually offers. Some webcams
        // advertise RGB only as MJPEG (or NV12) and reject YUYV; classify()
        // still labels them usable, so without this negotiation they would
        // detect fine then fail at capture with a cryptic "expected YUYV". YUYV
        // is preferred; NV12 is the common uncompressed fallback.
        let chosen = negotiate_rgb_format(device, &dev)?;
        let fmt = Format::new(RGB_W, RGB_H, FourCC::new(&chosen));
        let fmt = Capture::set_format(&dev, &fmt).map_err(|e| map_io(device, e))?;
        if fmt.fourcc.repr != chosen {
            return Err(Error::Hardware(format!(
                "{device}: driver gave {}, expected {}",
                fourcc_str(&fmt.fourcc.repr),
                fourcc_str(&chosen)
            )));
        }
        lease
            .require_endpoint(device)
            .map_err(|error| Error::Hardware(error.to_string()))?;
        Ok(Self {
            lease,
            session_active: std::sync::atomic::AtomicBool::new(false),
            device: device.to_string(),
            dev,
            chosen,
            width: fmt.width,
            height: fmt.height,
            negotiated: fmt,
        })
    }

    /// Start streaming. The returned session holds the buffers and the running
    /// stream until it is dropped, so keep it exactly as long as the burst of
    /// captures that needs it and no longer.
    #[expect(clippy::missing_errors_doc, reason = "doc backlog")]
    pub fn session(&self) -> irlume_common::Result<RgbSession<'_>> {
        self.session_with_progress(&no_progress())
    }

    /// [`Self::session`], reporting each completed silent warm-up window
    /// through `progress` (#336). The session KEEPS the reporter: its warm-up
    /// runs lazily on the first capture and again after [`RgbSession::recover`],
    /// both long after this call returned.
    #[expect(clippy::missing_errors_doc, reason = "doc backlog")]
    pub fn session_with_progress(
        &self,
        progress: &Progress,
    ) -> irlume_common::Result<RgbSession<'_>> {
        self.lease
            .require_endpoint(&self.device)
            .map_err(|error| Error::Hardware(error.to_string()))?;
        let session_slot = SessionSlot::acquire(&self.session_active, &self.device)?;
        // Best-effort backlight/low-light correction: tell auto-exposure to
        // expose for the face, not a bright window behind it (NexiGo N930W:
        // verified face mean 49→124; this machine's ASUS: center mean
        // 138.5→150.6, docs/research/2026-08-12-camera-session-measurements.md).
        // Written here rather than in `open` so that opening for a read-only
        // purpose (doctor's stream report) changes nothing on the camera.
        //
        // Applied through a GUARD armed before the stream opens (#426):
        // control values persist across open/close by the V4L2 spec
        // ("Control values are stored globally... do not change when the
        // device is opened or closed"), so the old fire-and-forget write
        // stayed on the camera for every later application; it was measured
        // still applied on this machine hours after the session that wrote
        // it. Guard rather than session-drop bookkeeping, because a stream
        // open that fails below must restore too, and the first version did
        // not (the Codex round's finding 1 on this PR).
        let blc_restore = apply_blc(self);
        let stream = SafeStream::open(
            &self.device,
            &self.dev,
            &self.negotiated,
            self.lease.clone(),
        )?;
        self.lease
            .require_endpoint(&self.device)
            .map_err(|error| Error::Hardware(error.to_string()))?;
        Ok(RgbSession {
            cam: self,
            stream: TrackedStream::new(stream),
            warmed: false,
            progress: progress.clone(),
            _blc_restore: blc_restore,
            _session_slot: session_slot,
        })
    }

    /// The stream this open camera negotiated. See [`negotiated_stream`].
    pub fn spec(&self) -> StreamSpec {
        StreamSpec {
            width: self.width,
            height: self.height,
            fourcc: fourcc_str(&self.chosen),
            fps: driver_fps(&self.dev),
        }
    }
}

/// The negotiated stream of a camera, for the doctor report (#223).
#[derive(Clone, Debug)]
pub struct StreamSpec {
    pub width: u32,
    pub height: u32,
    /// The negotiated pixel format's fourcc, e.g. "GREY" or "YUYV".
    pub fourcc: String,
    /// Frames per second from the driver's reported capture interval. `None`
    /// when the driver does not report one; irlume never sets a rate, so this
    /// is the default the stream would actually run at.
    pub fps: Option<f64>,
}

/// A published stream floor to compare a [`StreamSpec`] against.
pub struct StreamMinimum {
    pub width: u32,
    pub height: u32,
    pub fps: f64,
}

/// Windows Hello's published stream minimums, the envelope irlume's cue set
/// was designed around. Microsoft's UVC camera implementation guide
/// (learn.microsoft.com, "UVC camera implementation guide"): "Windows Hello
/// has a minimum requirement of 480x480@7.5fps for the RGB stream and
/// 340x340@15fps for the IR stream."
pub const HELLO_IR_MIN: StreamMinimum = StreamMinimum {
    width: 340,
    height: 340,
    fps: 15.0,
};
pub const HELLO_RGB_MIN: StreamMinimum = StreamMinimum {
    width: 480,
    height: 480,
    fps: 7.5,
};

impl StreamSpec {
    /// Whether this stream meets `min`. `Some(false)` when a dimension or a
    /// reported rate is below it; `None` when the dimensions meet it but the
    /// driver reports no rate, which is "cannot say", not "meets": collapsing
    /// an unobserved rate into a pass would make the one unreadable driver
    /// look like the one that cleared the bar.
    pub fn meets(&self, min: &StreamMinimum) -> Option<bool> {
        if self.width < min.width || self.height < min.height {
            return Some(false);
        }
        self.fps.map(|fps| fps >= min.fps)
    }
}

/// The driver's reported capture rate for `dev`, from VIDIOC_G_PARM. The
/// interval is time-per-frame, so the rate is its inverse.
fn driver_fps(dev: &Device) -> Option<f64> {
    fps_from_params(Capture::params(dev).ok()?)
}

/// [`driver_fps`]'s conversion, split out so the capability rule is testable
/// without hardware. V4L2 specifies that `timeperframe` is meaningful only
/// when the driver sets `V4L2_CAP_TIMEPERFRAME`; without the flag the fields
/// are whatever the driver left in the struct, and reading a plausible-looking
/// `1/30` there would let an unestablished rate publish as a pass. A zero on
/// either side of the fraction is equally unusable.
fn fps_from_params(p: v4l::video::capture::Parameters) -> Option<f64> {
    if !p
        .capabilities
        .contains(v4l::parameters::Capabilities::TIME_PER_FRAME)
    {
        return None;
    }
    let (num, den) = (p.interval.numerator, p.interval.denominator);
    (num != 0 && den != 0).then(|| f64::from(den) / f64::from(num))
}

/// `VIDIOC_TRY_FMT`: what `VIDIOC_S_FMT` would negotiate, without changing
/// driver state. The kernel specifies TRY_FMT as S_FMT's stateless twin (same
/// adjustment logic, no hardware preparation), which is what lets the doctor
/// report read a camera without mutating it. The pinned v4l crate exposes only
/// `set_format`, so this is the same raw-ioctl shape as the VIDIOC_ENUM_FMT
/// probe above.
fn try_format(dev: &Device, fmt: &Format) -> std::io::Result<Format> {
    #[expect(clippy::undocumented_unsafe_blocks, reason = "doc backlog")]
    let mut wire: v4l::v4l_sys::v4l2_format = unsafe { std::mem::zeroed() };
    wire.type_ = v4l::buffer::Type::VideoCapture as u32;
    wire.fmt.pix = (*fmt).into();
    // SAFETY: `dev` owns the fd for the length of this call, and `wire` is a
    // correctly sized v4l2_format with the pix union arm initialized, which is
    // what VIDIOC_TRY_FMT reads and writes.
    let rc = unsafe {
        libc::ioctl(
            dev.handle().fd(),
            v4l::v4l2::vidioc::VIDIOC_TRY_FMT,
            &mut wire as *mut _ as *mut libc::c_void,
        )
    };
    if rc < 0 {
        return Err(std::io::Error::last_os_error());
    }
    #[expect(clippy::undocumented_unsafe_blocks, reason = "doc backlog")]
    Ok(Format::from(unsafe { wire.fmt.pix }))
}

/// What the capture path would negotiate on `device`, observed read-only: the
/// same verify + privacy checks and the same candidate walks as
/// [`RgbCamera::open`] / [`IrCamera::open`], applied through `VIDIOC_TRY_FMT`
/// instead of `VIDIOC_S_FMT`, so nothing on the camera changes. No buffers,
/// no streaming, LED off. The candidate selection is shared with the real
/// open paths rather than reimplemented, so this report cannot drift from
/// what capture actually asks for (#223).
#[expect(clippy::missing_errors_doc, reason = "doc backlog")]
pub fn negotiated_stream(device: &str, role: Role) -> irlume_common::Result<StreamSpec> {
    verify_pinned(device)?;
    let _permit = lease::permit_for_endpoint(
        device,
        lease::CameraOperationKind::Diagnostics,
        std::time::Duration::from_secs(2),
    )
    .map_err(|error| Error::Hardware(error.to_string()))?;
    if privacy_engaged_with_permit(device) {
        return Err(Error::Hardware(format!(
            "{device}: hardware privacy switch is ON"
        )));
    }
    let dev = Device::with_path(device).map_err(|e| map_io(device, e))?;
    let (fmt, fourcc) = match role {
        Role::Rgb => {
            let chosen = negotiate_rgb_format(device, &dev)?;
            let fmt = try_format(&dev, &Format::new(RGB_W, RGB_H, FourCC::new(&chosen)))
                .map_err(|e| map_io(device, e))?;
            // Mirror open()'s echo check: a driver that answers with a
            // different fourcc would fail capture, so it must not report as a
            // negotiated stream here.
            if fmt.fourcc.repr != chosen {
                return Err(Error::Hardware(format!(
                    "{device}: driver gave {}, expected {}",
                    fourcc_str(&fmt.fourcc.repr),
                    fourcc_str(&chosen)
                )));
            }
            let cc = fourcc_str(&fmt.fourcc.repr);
            (fmt, cc)
        }
        Role::Ir => {
            let (fmt, _pix) = negotiate_ir_format_via(device, &dev, try_format)?;
            let cc = fourcc_str(&fmt.fourcc.repr);
            (fmt, cc)
        }
        _ => {
            return Err(Error::Hardware(format!(
                "{device}: no stream to negotiate for this role"
            )))
        }
    };
    Ok(StreamSpec {
        width: fmt.width,
        height: fmt.height,
        fourcc,
        fps: driver_fps(&dev),
    })
}

/// A running RGB stream. Every capture after the first skips the warm-up.
pub struct RgbSession<'a> {
    cam: &'a RgbCamera,
    /// `None` only transiently inside [`Self::recover`]: the broken stream
    /// must be DROPPED (STREAMOFF + buffer release) before its replacement
    /// negotiates, and a plain re-assignment builds the new value first.
    stream: TrackedStream<SafeStream<'a>>,
    warmed: bool,
    /// Per-window heartbeat for the lazy warm-up (#336); owned, not borrowed,
    /// so holding a session never freezes the caller's other borrows.
    progress: Progress,
    /// The one restore of this session's backlight-compensation write,
    /// `Some` only when irlume actually CHANGED the control and confirmed
    /// what the device holds (#426). Declared after `stream`, so the field
    /// drop order tears the stream down (STREAMOFF) before the control is
    /// put back.
    _blc_restore: Option<BlcRestore<'a>>,
    /// Reset last, after STREAMOFF and control restoration have completed.
    _session_slot: SessionSlot<'a>,
}

impl<'a> RgbSession<'a> {
    /// The live stream. `recover` is the only path that leaves the slot
    /// empty, and it either refills it or returns the error; a `None` here
    /// outside that window is a bug, reported as hardware trouble rather
    /// than a panic because this sits in the authentication path.
    fn stream(&mut self) -> irlume_common::Result<&mut SafeStream<'a>> {
        self.stream
            .stream_mut()
            .ok_or_else(|| Error::Hardware("RGB stream missing after a failed recovery".into()))
    }

    /// Rebuild this session's stream on the SAME open device after a
    /// mid-stream fault.
    ///
    /// The broken stream owns the device's buffer queue until it is torn
    /// down, so a recapture through a SECOND open answers EBUSY from our own
    /// handle. Measured on a Logitech Brio (#187 hardware session, strace
    /// 2026-08-06): `VIDIOC_QBUF` on the live stream failed EINVAL at
    /// .266366, the standalone retry's `VIDIOC_S_FMT` on a fresh open failed
    /// EBUSY at .269393, and no close ran in between. Dropping the stream
    /// first releases the queue, and the replacement renegotiates on the fd
    /// this session already holds, so nothing new opens and nothing collides.
    /// Same drop-then-reopen shape as the frozen-stream restart in the IR
    /// one-shot path.
    #[expect(clippy::missing_errors_doc, reason = "doc backlog")]
    pub fn recover(&mut self) -> irlume_common::Result<()> {
        self.cam
            .lease
            .require_endpoint(&self.cam.device)
            .map_err(|error| Error::Hardware(error.to_string()))?;
        drop(self.stream.take()); // STREAMOFF + buffer release before replacement
        let stream = SafeStream::open(
            &self.cam.device,
            &self.cam.dev,
            &self.cam.negotiated,
            self.cam.lease.clone(),
        )?;
        self.cam
            .lease
            .require_endpoint(&self.cam.device)
            .map_err(|error| Error::Hardware(error.to_string()))?;
        self.stream.install_recovered(stream).map_err(|error| {
            Error::Hardware(format!(
                "{}: could not begin the recovered sequence epoch: {error}",
                self.cam.device
            ))
        })?;
        // The fresh stream's auto-exposure starts unsettled, like any new
        // session's.
        self.warmed = false;
        Ok(())
    }

    /// Discard frames until auto-exposure has settled, once per session. A
    /// second capture on the same stream is already settled, and re-running the
    /// warm-up would throw away good frames to no purpose.
    fn warm_up(&mut self) -> irlume_common::Result<()> {
        self.cam
            .lease
            .require_endpoint(&self.cam.device)
            .map_err(|error| Error::Hardware(error.to_string()))?;
        if self.warmed {
            return Ok(());
        }
        let device = self.cam.device.clone();
        let progress = self.progress.clone();
        warm_up_stream(&device, self.stream()?, &progress)?;
        for _ in 0..AE_WARMUP {
            self.cam
                .lease
                .require_endpoint(&device)
                .map_err(|error| Error::Hardware(error.to_string()))?;
            self.stream()?.next().map_err(|e| map_io(&device, e))?; // discard while AE settles
        }
        self.warmed = true;
        Ok(())
    }

    /// Capture `n` (≥1) frames. All share the same dimensions.
    #[expect(clippy::missing_errors_doc, reason = "doc backlog")]
    pub fn burst(&mut self, n: usize) -> irlume_common::Result<Vec<Frame>> {
        self.cam
            .lease
            .require_endpoint(&self.cam.device)
            .map_err(|error| Error::Hardware(error.to_string()))?;
        self.warm_up()?;
        let (w, h) = (self.cam.width, self.cam.height);
        let device = self.cam.device.clone();
        let chosen = self.cam.chosen;
        let mut frames = Vec::with_capacity(n.max(1));
        for _ in 0..n.max(1) {
            self.cam
                .lease
                .require_endpoint(&device)
                .map_err(|error| Error::Hardware(error.to_string()))?;
            let (buf, _meta, _sequence) =
                self.stream.next().map_err(|error| map_io(&device, error))?;
            let taken = std::time::Instant::now();
            let data = match &chosen {
                b"NV12" => nv12_to_rgb(buf, w, h),
                _ => yuyv_to_rgb(buf, w, h),
            };
            self.cam
                .lease
                .require_endpoint(&device)
                .map_err(|error| Error::Hardware(error.to_string()))?;
            frames.push(Frame {
                width: w,
                height: h,
                spectrum: Spectrum::Rgb,
                data,
                captured: CaptureWindow::at(taken),
            });
        }
        Ok(frames)
    }

    /// One frame (framing guide, liveness probe).
    #[expect(clippy::missing_errors_doc, reason = "doc backlog")]
    pub fn frame(&mut self) -> irlume_common::Result<Frame> {
        self.burst(1)?
            .pop()
            .ok_or_else(|| Error::Hardware("no frames captured".into()))
    }

    /// The recognition path's denoised frame: a per-pixel temporal median over
    /// the burst, so one blurry or over-exposed frame cannot decide a match.
    #[expect(clippy::missing_errors_doc, reason = "doc backlog")]
    pub fn denoised(&mut self) -> irlume_common::Result<Frame> {
        Ok(median_frame(self.burst(RGB_BURST)?))
    }
}

/// Open `device`, let auto-exposure settle, and capture `n` (≥1) RGB frames in a
/// single streaming session (YUYV → RGB8). All frames share the same dimensions.
/// One-shot: opens and tears down a session. Callers that capture more than once
/// should hold an [`RgbCamera`] and its session instead.
#[expect(clippy::missing_errors_doc, reason = "doc backlog")]
pub fn capture_rgb_burst(device: &str, n: usize) -> irlume_common::Result<Vec<Frame>> {
    capture_rgb_burst_with_progress(device, n, &no_progress())
}

/// [`capture_rgb_burst`], reporting each completed silent warm-up window
/// through `progress` (#336). The daemon-facing paths pass a real reporter so
/// a frameless camera heartbeats through its retry budget instead of looking
/// wedged to the watchdog.
#[expect(clippy::missing_errors_doc, reason = "doc backlog")]
pub fn capture_rgb_burst_with_progress(
    device: &str,
    n: usize,
    progress: &Progress,
) -> irlume_common::Result<Vec<Frame>> {
    let cam = RgbCamera::open(device)?;
    let mut session = cam.session_with_progress(progress)?;
    let frames = session.burst(n);
    // Drop the stream before `cam`: the session borrows the device.
    drop(session);
    frames
}

/// The uncompressed RGB fourccs the capture path can decode, best first.
const DECODABLE_RGB: [&[u8; 4]; 2] = [b"YUYV", b"NV12"];

/// The first decodable format (`DECODABLE_RGB` order) the camera advertises, or
/// None if it offers only formats we cannot decode (e.g. MJPEG-only).
fn choose_rgb_format(offered: &[[u8; 4]]) -> Option<[u8; 4]> {
    DECODABLE_RGB
        .iter()
        .find(|f| offered.contains(**f))
        .map(|f| **f)
}

/// Detects an Intel IPU6/IPU7 MIPI camera complex and returns which generation
/// ("IPU6" or "IPU7"), or None. These are common on 2020+ Intel laptops (Tiger
/// Lake onward; IPU7 on Lunar Lake / Panther Lake / Arrow Lake). They expose no
/// directly-openable V4L2 capture node: the in-kernel ISYS nodes emit raw Bayer
/// plus metadata, not YUYV/GREY, so `discover_nodes` finds nothing usable and a
/// user just sees "no camera". Worse for irlume specifically, the IR / Windows
/// Hello sensor on these modules is not exposed on Linux at all (only the RGB
/// sensor, and only through a libcamera software-ISP bridge). `doctor` uses
/// this to explain the situation instead of a bare "no camera".
///
/// Detection is root-free and identical for the out-of-tree dkms driver and the
/// mainline in-kernel one (both register the same PCI-driver and module names):
/// a bound PCI device under the driver, or the module loaded, or (hardware
/// present but driver/firmware missing) a known IPU PCI device ID.
pub fn intel_ipu_present() -> Option<&'static str> {
    for (gen, drv, module) in [
        (
            "IPU7",
            "/sys/bus/pci/drivers/intel-ipu7",
            "/sys/module/intel_ipu7",
        ),
        (
            "IPU6",
            "/sys/bus/pci/drivers/intel-ipu6",
            "/sys/module/intel_ipu6",
        ),
    ] {
        if driver_has_bound_device(drv) || std::path::Path::new(module).exists() {
            return Some(gen);
        }
    }
    ipu_pci_generation()
}

/// True if a `/sys/bus/pci/drivers/<name>` directory has at least one bound PCI
/// device (a `0000:*` symlink), i.e. the driver is actually driving hardware.
fn driver_has_bound_device(driver_dir: &str) -> bool {
    std::fs::read_dir(driver_dir)
        .map(|rd| {
            rd.flatten()
                .any(|e| e.file_name().to_string_lossy().starts_with("0000:"))
        })
        .unwrap_or(false)
}

/// Scan PCI devices for a known IPU6/IPU7 device ID (vendor 0x8086), catching
/// the "hardware present but no driver bound" case, the one where the user has
/// both no camera and no working stack. IDs from the mainline ipu6/ipu7 drivers.
fn ipu_pci_generation() -> Option<&'static str> {
    let rd = std::fs::read_dir("/sys/bus/pci/devices").ok()?;
    for entry in rd.flatten() {
        let dir = entry.path();
        let vendor = std::fs::read_to_string(dir.join("vendor")).unwrap_or_default();
        if vendor.trim() != "0x8086" {
            continue;
        }
        let device = std::fs::read_to_string(dir.join("device")).unwrap_or_default();
        if let Some(gen) = ipu_generation_for_id(device.trim()) {
            return Some(gen);
        }
    }
    None
}

/// Map an Intel PCI device ID (as sysfs prints it, e.g. `0x7d19`) to the IPU
/// generation, or None. IDs from the mainline ipu6/ipu7 drivers.
fn ipu_generation_for_id(device_id: &str) -> Option<&'static str> {
    const IPU6: &[&str] = &["0x9a19", "0x4e19", "0x465d", "0x462e", "0xa75d", "0x7d19"];
    const IPU7: &[&str] = &["0x645d", "0xb05d"];
    if IPU7.contains(&device_id) {
        Some("IPU7")
    } else if IPU6.contains(&device_id) {
        Some("IPU6")
    } else {
        None
    }
}

/// A node's advertised pixel formats (fourcc), for negotiation and `doctor`.
pub fn rgb_node_formats(device: &str) -> Vec<[u8; 4]> {
    let Ok(_permit) = lease::permit_for_endpoint(
        device,
        lease::CameraOperationKind::Diagnostics,
        std::time::Duration::from_secs(2),
    ) else {
        return Vec::new();
    };
    let Ok(dev) = Device::with_path(device) else {
        return Vec::new();
    };
    Capture::enum_formats(&dev)
        .map(|v| v.into_iter().map(|d| d.fourcc.repr).collect())
        .unwrap_or_default()
}

/// Choose the format to capture in: the first `DECODABLE_RGB` entry the camera
/// advertises. If it advertises none we can decode (e.g. MJPEG-only), fail with
/// a message that names what it offers rather than a bare "expected YUYV".
fn negotiate_rgb_format(device: &str, dev: &Device) -> irlume_common::Result<[u8; 4]> {
    let offered: Vec<[u8; 4]> = Capture::enum_formats(dev)
        .map(|v| v.into_iter().map(|d| d.fourcc.repr).collect())
        .unwrap_or_default();
    // If enumeration is unavailable, keep the historical behaviour (try YUYV).
    if offered.is_empty() {
        return Ok(*b"YUYV");
    }
    if let Some(f) = choose_rgb_format(&offered) {
        return Ok(f);
    }
    let offered_str: Vec<String> = offered.iter().map(fourcc_str).collect();
    Err(Error::Hardware(format!(
        "{device}: RGB camera offers only [{}]; irlume needs an uncompressed \
         format (YUYV or NV12). MJPEG-only cameras are not supported yet.",
        offered_str.join(", ")
    )))
}

/// Printable fourcc (trailing spaces trimmed), for diagnostics.
fn fourcc_str(cc: &[u8; 4]) -> String {
    std::str::from_utf8(cc)
        .unwrap_or("????")
        .trim_end()
        .to_string()
}

/// How to turn a dequeued IR buffer into the 8-bit GREY frame the pipeline uses.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum IrPixel {
    /// GREY / Y8 / Y800: already 8-bit, used as-is.
    Grey8,
    /// Y16 / Y10 / Y12: 16-bit little-endian words, sample data LSB-aligned
    /// (per the V4L2 spec, which also allows Y16 to carry fewer than 16 real
    /// bits; a 10-bit sensor delivers 0..1023 in Y16).
    Grey16,
    /// NV12: the leading `w*h` bytes are a plain 8-bit luma plane; an IR sensor
    /// behind bridge firmware that only speaks NV12 is fully usable through it.
    Nv12Luma,
    /// YUYV: every even byte is 8-bit luma.
    YuyvLuma,
}

/// IR format preference: native 8-bit grey, then the 16-bit grey family, then
/// luma extraction from the packed colour containers. Field data (mined from
/// sibling projects): IR sensors that expose ONLY MJPG or NV12 exist, and
/// 16-bit grey IR nodes exist; a GREY-only assumption silently demotes those
/// machines to the RGB convenience tier.
const IR_CANDIDATES: [(&[u8; 4], IrPixel); 8] = [
    (b"GREY", IrPixel::Grey8),
    (b"Y8  ", IrPixel::Grey8),
    (b"Y800", IrPixel::Grey8),
    (b"Y16 ", IrPixel::Grey16),
    (b"Y10 ", IrPixel::Grey16),
    (b"Y12 ", IrPixel::Grey16),
    (b"NV12", IrPixel::Nv12Luma),
    (b"YUYV", IrPixel::YuyvLuma),
];

/// Negotiate an IR-decodable format on `dev`, mirroring [`negotiate_rgb_format`]:
/// walk [`IR_CANDIDATES`] against what the driver advertises, accept the first
/// one the driver echoes back, and fail with a message naming what it offers.
fn negotiate_ir_format(device: &str, dev: &Device) -> irlume_common::Result<(Format, IrPixel)> {
    negotiate_ir_format_via(device, dev, Capture::set_format)
}

/// The IR candidate walk with the format ioctl injected: capture applies it
/// through `VIDIOC_S_FMT` ([`negotiate_ir_format`]) while the doctor's
/// read-only probe applies the SAME walk through `VIDIOC_TRY_FMT`
/// ([`negotiated_stream`]). One walk, two ioctls, so the probe cannot drift
/// from what capture negotiates.
fn negotiate_ir_format_via(
    device: &str,
    dev: &Device,
    apply: impl Fn(&Device, &Format) -> std::io::Result<Format>,
) -> irlume_common::Result<(Format, IrPixel)> {
    let offered: Vec<[u8; 4]> = Capture::enum_formats(dev)
        .map(|v| v.into_iter().map(|d| d.fourcc.repr).collect())
        .unwrap_or_default();
    for (cc, pix) in IR_CANDIDATES {
        // If enumeration is unavailable, keep the historical behaviour and try
        // each candidate blind; otherwise only ask for formats it advertises.
        if !offered.is_empty() && !offered.contains(cc) {
            continue;
        }
        let fmt = Format::new(IR_W, IR_H, FourCC::new(cc));
        let fmt = apply(dev, &fmt).map_err(|e| map_io(device, e))?;
        if &fmt.fourcc.repr == cc {
            return Ok((fmt, pix));
        }
    }
    let offered_str: Vec<String> = offered.iter().map(fourcc_str).collect();
    Err(Error::Hardware(format!(
        "{device}: IR camera offers only [{}]; irlume decodes native grey \
         (GREY/Y8/Y800), 16-bit grey (Y16/Y10/Y12), or a luma plane \
         (NV12/YUYV). MJPEG-only IR nodes are not supported yet.",
        offered_str.join(", ")
    )))
}

/// Convert one dequeued IR buffer to the 8-bit GREY layout the pipeline uses.
/// Prefer [`IrDecoder`] inside a capture session: this entry point rescales
/// each Y16 frame independently, which is fine for a one-shot decode but makes
/// frame-to-frame brightness comparisons meaningless.
pub(crate) fn decode_ir(buf: &[u8], pix: IrPixel, w: u32, h: u32) -> Vec<u8> {
    match pix {
        IrPixel::Grey8 => buf.to_vec(),
        IrPixel::Grey16 => grey16_to_8_at(buf, grey16_shift(buf)),
        IrPixel::Nv12Luma => {
            let luma = (w as usize * h as usize).min(buf.len());
            buf[..luma].to_vec()
        }
        IrPixel::YuyvLuma => buf.iter().step_by(2).copied().collect(),
    }
}

/// The right-shift that maps this frame's 16-bit-LE samples into 8 bits. The
/// V4L2 spec keeps sample data LSB-aligned and lets the real precision be
/// anything up to 16 bits, and nothing reports which; a fixed top-byte take
/// (what a sibling project ships) reads a 10-bit-in-Y16 sensor as near-black,
/// so the effective depth is estimated from the frame's own maximum.
fn grey16_shift(buf: &[u8]) -> u32 {
    let max: u16 = buf
        .chunks_exact(2)
        .map(|p| u16::from_le_bytes([p[0], p[1]]))
        .max()
        .unwrap_or(0);
    (16 - max.leading_zeros()).saturating_sub(8)
}

/// The decoded value that means "at or above the sensor's ceiling" for a
/// negotiated IR format, or `None` when the decode cannot carry that claim.
/// See [`IrCaptureStats::white_level`] for why only the 8-bit greys qualify.
///
/// GREY is a luma-only Y' format, so its ceiling depends on the quantization
/// the driver reports: full range puts white at 255, limited range at 235. A
/// face entirely at 235 on a limited-range device would otherwise measure as
/// zero clipping and walk through the exposure gate (#238 review).
///
/// `Default` is read as full range, which is what it resolves to on every
/// module irlume supports: `v4l2-ctl --get-fmt-video` prints
/// "Quantization: Default (maps to Full Range)" for the ASUS FHD IR pin, the
/// NexiGo N930W and the Logitech BRIO, all three GREY at sRGB. Answering `None`
/// there instead would be the cautious-looking choice and would disable the
/// gate on every camera anyone actually has, which is the failure this exists
/// to prevent. If a module ever reports limited range, the 235 arm covers it.
///
/// That citation is a userspace tool's opinion, and the kernel's own mapping
/// disagrees with it: `V4L2_MAP_QUANTIZATION_DEFAULT` resolves `Default` to
/// LIMITED for Y'CbCr unless the colorspace is JPEG, and `v4l2-ctl` prints GREY
/// as full range only because its `is_rgb_or_hsv` fourcc switch ends in
/// `default: return true` with GREY absent from the list. Neither settles how
/// GREY should be classified, because the kernel does not class it explicitly.
///
/// The committed corpora carry the evidence this arm actually rests on, and it
/// is per-device rather than universal. Across
/// `docs/pad-results/2026-08-02-center-edge-corpus.jsonl` and
/// `2026-08-04-occluder-gate.jsonl`, `ir_saturated_frac` is nonzero in 75 of
/// 129 non-null readings (59 of 103, peaking at 0.547, and 16 of 26), and those
/// captures were evaluated against a 255 threshold, so decoded ASUS frames did
/// contain samples equal to 255.
///
/// That supports the 255 policy for these modules. It does NOT establish a
/// V4L2 rule for GREY in general: the corpora record no fourcc, colorspace,
/// quantization or white level per row, and a decoded 255 is consistent with
/// clipping or with metadata that does not describe what the device emits. A
/// module reporting limited-range GREY still needs the 235 arm (#385).
pub(crate) fn clipping_white_level(pix: IrPixel, quantization: Quantization) -> Option<u8> {
    match (pix, quantization) {
        (IrPixel::Grey8, Quantization::LimitedRange) => Some(235),
        (IrPixel::Grey8, Quantization::FullRange | Quantization::Default) => Some(u8::MAX),
        (IrPixel::Grey16 | IrPixel::Nv12Luma | IrPixel::YuyvLuma, _) => None,
    }
}

/// 16-bit-LE grey (Y16/Y10/Y12) → 8-bit at a given shift.
fn grey16_to_8_at(buf: &[u8], shift: u32) -> Vec<u8> {
    buf.chunks_exact(2)
        .map(|p| (u16::from_le_bytes([p[0], p[1]]) >> shift).min(255) as u8)
        .collect()
}

/// Decodes every frame of ONE capture session into 8-bit grey.
///
/// It exists to hold the Y16 shift steady. Deriving the shift from each frame's
/// own maximum rescales every frame independently, so a single bright pixel
/// appearing or leaving changes the scale even when the scene did not move. The
/// IR path then compares frame means to pick the lit strobe phase and the
/// ambient floor ([`IrCaptureStats`]), and those comparisons are only meaningful
/// on a common scale. The first frame of the session sets the shift and the rest
/// reuse it, which is what the old comment claimed ("stable within a burst") but
/// the per-frame call could not deliver.
///
/// 8-bit formats carry no scale, so they are unaffected.
pub(crate) struct IrDecoder {
    pix: IrPixel,
    /// Carried because the GREY ceiling depends on it; see
    /// [`clipping_white_level`].
    quantization: Quantization,
    shift: Option<u32>,
}

impl IrDecoder {
    pub(crate) fn new(pix: IrPixel, quantization: Quantization) -> Self {
        Self {
            pix,
            quantization,
            shift: None,
        }
    }

    /// See [`clipping_white_level`]: the decoded value that means "at or above
    /// the sensor's ceiling" for this decoder's format, or `None` when the
    /// decode cannot carry that claim.
    pub(crate) fn white_level(&self) -> Option<u8> {
        clipping_white_level(self.pix, self.quantization)
    }

    pub(crate) fn decode(&mut self, buf: &[u8], w: u32, h: u32) -> Vec<u8> {
        match self.pix {
            IrPixel::Grey16 => {
                let shift = *self.shift.get_or_insert_with(|| grey16_shift(buf));
                grey16_to_8_at(buf, shift)
            }
            other => decode_ir(buf, other, w, h),
        }
    }
}

/// Capture one AE-warmed RGB frame (fast path: framing guide, liveness probe).
#[expect(clippy::missing_errors_doc, reason = "doc backlog")]
pub fn capture_rgb(device: &str) -> irlume_common::Result<Frame> {
    let mut frames = capture_rgb_burst(device, 1)?;
    frames
        .pop()
        .ok_or_else(|| Error::Hardware("no frames captured".into()))
}

/// Capture an RGB burst and return its per-pixel temporal median, the
/// recognition path's denoise. A single motion-blurred, over-exposed, or
/// transiently corrupt frame is rejected by the median, so it can't drop a
/// genuine match below threshold (false reject). Used for auth/enroll; the
/// framing guide stays single-shot for latency.
#[expect(clippy::missing_errors_doc, reason = "doc backlog")]
pub fn capture_rgb_denoised(device: &str) -> irlume_common::Result<Frame> {
    capture_rgb_denoised_with_progress(device, &no_progress())
}

/// [`capture_rgb_denoised`] with the per-window progress reporting of
/// [`capture_rgb_burst_with_progress`] (#336).
#[expect(clippy::missing_errors_doc, reason = "doc backlog")]
pub fn capture_rgb_denoised_with_progress(
    device: &str,
    progress: &Progress,
) -> irlume_common::Result<Frame> {
    Ok(median_frame(capture_rgb_burst_with_progress(
        device, RGB_BURST, progress,
    )?))
}

/// Per-pixel temporal median across same-sized frames (sorts each byte position
/// across the burst, keeps the middle value). Returns the lone frame unchanged
/// for a degenerate burst. Private on purpose: callers must pass at least one
/// frame (`capture_rgb_burst` clamps to n.max(1)), and keeping it crate-local
/// keeps that invariant next to the only code that must uphold it.
fn median_frame(mut frames: Vec<Frame>) -> Frame {
    if frames.len() <= 1 {
        return frames.pop().expect("median_frame: empty burst");
    }
    let (w, h, spectrum) = (frames[0].width, frames[0].height, frames[0].spectrum);
    let window = frames
        .iter()
        .map(|f| f.captured)
        .reduce(CaptureWindow::union)
        .unwrap_or_else(|| CaptureWindow::at(std::time::Instant::now()));
    let len = frames.iter().map(|f| f.data.len()).min().unwrap_or(0);
    let mut out = vec![0u8; len];
    let mut col = vec![0u8; frames.len()];
    for (i, o) in out.iter_mut().enumerate() {
        for (k, f) in frames.iter().enumerate() {
            col[k] = f.data[i];
        }
        col.sort_unstable();
        *o = col[col.len() / 2];
    }
    Frame {
        width: w,
        height: h,
        spectrum,
        data: out,
        // A median pixel can come from any frame in the burst, so the result
        // belongs to the whole span, not to any one dequeue.
        captured: window,
    }
}

const IR_W: u32 = 640;
const IR_H: u32 = 400;
// Grab a short burst and keep the brightest frame (the lit strobe phase). The
// IR node caps at 15 fps, so each frame costs ~67ms; 10 frames (~0.67s) still
// catches the emitter's strobe peak (it re-fires at mid-burst) while ~halving
// the old 24-frame (~1.6s) cost. Bump back up if dark-mode genuine scores drop.
const IR_BURST: usize = 10;

/// Ambient-subtraction gates (used only when `IRLUME_IR_AMBIENT_SUBTRACT=1`).
///
/// `STROBE_MIN_GAP`: the lit frame must clear its off-frame neighbor by at
/// least this much (mean) for a genuine emitter-off exposure to exist to pair
/// against; a steady emitter has no such neighbor. Set to the sensor-noise
/// floor (8), NOT a large absolute gap: under strong ambient IR (direct sun)
/// the sensor saturates and a real strobe compresses to a gap of ~8-10, so the
/// old value of 20 blocked subtraction in exactly the sunlit bursts that need
/// it most (dataset `~/irlume-suncal`: bursts 06-08, gap 8-9, raw center/edge
/// 0.96-0.97, subtracted 1.37-1.46).
///
/// `LOW_AMBIENT_SKIP`: if the off-frame mean is below this, there is
/// essentially no ambient IR to remove (indoors the off-frame is near-black),
/// so subtracting it would only inject sensor noise; skip and keep the raw
/// lit frame.
///
/// `SUBTRACT_MIN_RESULT`: after subtracting, the result must retain at least
/// this much mean signal. When lit approx-equals ambient (the emitter added
/// little over a bright pedestal) the subtracted frame collapses to noise and
/// the face becomes undetectable (dataset bursts 09/14: subtracted face
/// vanished). Below this floor we revert to the raw lit frame rather than hand
/// downstream a blank frame.
/// Public so offline tools (`irlume suncal`) simulate the same gate instead of
/// retyping the values.
pub const STROBE_MIN_GAP: f64 = 8.0;
pub const LOW_AMBIENT_SKIP: f64 = 5.0;
pub const SUBTRACT_MIN_RESULT: f64 = 12.0;

/// Capture one IR frame (GREY 8-bit) from the IR companion node. The active-IR
/// emitter must be illuminating for a usable image; on integrated Hello modules
/// it often fires when the stream opens, otherwise `ir_emitter::enable` sends
/// the UVC-XU write on the open fd (its `known_control` table holds the
/// per-camera unit/selector/payload).
#[expect(clippy::missing_errors_doc, reason = "doc backlog")]
pub fn capture_ir(device: &str) -> irlume_common::Result<Frame> {
    Ok(capture_ir_with_stats(device)?.0)
}

/// [`capture_ir`] plus the burst statistics the plain call discards. The
/// darkest burst frame's mean is a free per-capture ambient-IR reading (the
/// input the ambient-relative gates key on), only available at capture time.
#[expect(clippy::missing_errors_doc, reason = "doc backlog")]
pub fn capture_ir_with_stats(device: &str) -> irlume_common::Result<(Frame, IrCaptureStats)> {
    capture_ir_with_stats_and_progress(device, &no_progress())
}

/// [`capture_ir_with_stats`], reporting each completed silent warm-up window
/// through `progress` (#336); see [`capture_rgb_burst_with_progress`].
#[expect(clippy::missing_errors_doc, reason = "doc backlog")]
pub fn capture_ir_with_stats_and_progress(
    device: &str,
    progress: &Progress,
) -> irlume_common::Result<(Frame, IrCaptureStats)> {
    let cam = IrCamera::open(device)?;
    let mut session = cam.session_with_progress(progress)?;
    let shot = session.capture_with_stats();
    // Drop the stream before `cam`: the session borrows the device.
    drop(session);
    shot
}

/// An opened, format-negotiated IR camera. The companion to [`RgbCamera`]; see
/// there for why a device and a session are separate types.
pub struct IrCamera {
    lease: lease::CameraLease,
    session_active: std::sync::atomic::AtomicBool,
    device: String,
    dev: Device,
    pix: IrPixel,
    /// The driver's reported quantization for the negotiated format, which is
    /// half of what names the clipping ceiling; see [`clipping_white_level`].
    quantization: Quantization,
    /// The negotiated fourcc, kept for [`Self::spec`]: `pix` names how the
    /// bytes decode, not which of several fourccs mapped to it.
    fourcc: String,
    /// The whole format the driver echoed at open, kept verbatim so sessions
    /// can verify the device still holds every field of it when they claim
    /// buffers (#427); see `format_moved` for why the geometry alone is not
    /// enough.
    negotiated: v4l::Format,
    width: u32,
    height: u32,
    card: String,
}

impl IrCamera {
    #[expect(clippy::missing_errors_doc, reason = "doc backlog")]
    pub fn open(device: &str) -> irlume_common::Result<Self> {
        if let Some(permit) =
            lease::active_permit(device).map_err(|error| Error::Hardware(error.to_string()))?
        {
            return backend::open_ir(device, permit);
        }
        let operation = match lease::acquire_camera_operation(
            &[device],
            lease::CameraOperationKind::Capture,
            std::time::Duration::from_secs(2),
        ) {
            Ok(operation) => operation,
            Err(error @ lease::CameraLeaseError::Stale) => {
                verify_pinned(device)?;
                return Err(Error::Hardware(error.to_string()));
            }
            Err(error) => return Err(Error::Hardware(error.to_string())),
        };
        backend::open_ir(device, operation.into_lease())
    }

    fn open_uvc(device: &str, lease: lease::CameraLease) -> irlume_common::Result<Self> {
        lease
            .require_endpoint(device)
            .map_err(|error| Error::Hardware(error.to_string()))?;
        verify_pinned(device)?;
        if privacy_engaged_with_permit(device) {
            return Err(Error::Hardware(format!(
                "{device}: hardware privacy switch is ON"
            )));
        }
        let dev = Device::with_path(device).map_err(|e| map_io(device, e))?;
        let (fmt, pix) = negotiate_ir_format(device, &dev)?;
        let card = dev.query_caps().map(|c| c.card).unwrap_or_default();
        lease
            .require_endpoint(device)
            .map_err(|error| Error::Hardware(error.to_string()))?;
        Ok(Self {
            lease,
            session_active: std::sync::atomic::AtomicBool::new(false),
            device: device.to_string(),
            dev,
            pix,
            quantization: fmt.quantization,
            fourcc: fourcc_str(&fmt.fourcc.repr),
            negotiated: fmt,
            width: fmt.width,
            height: fmt.height,
            card,
        })
    }

    /// The stream this open camera negotiated. See [`negotiated_stream`].
    pub fn spec(&self) -> StreamSpec {
        StreamSpec {
            width: self.width,
            height: self.height,
            fourcc: self.fourcc.clone(),
            fps: driver_fps(&self.dev),
        }
    }

    /// Start streaming and fire the emitter.
    ///
    /// Holding the session across several captures is safe on the modules we
    /// measured: after ONE control write the emitter stayed lit for 30s of
    /// continuous streaming on both (ASUS built-in at a flat level of 144, NexiGo
    /// N930W at ~37), and the control survives even stream close and process
    /// exit. See `examples/ir_refire_probe.rs`.
    ///
    /// The per-capture re-fires that used to sit below are gone (#168): they are
    /// not part of the sequence Microsoft documents, and on a module that DOES
    /// self-clear the illumination metadata from #167 now reports the dark
    /// frames rather than leaving brightness to guess. The residual risk is a
    /// module nobody here has seen going dark for a window, which costs the user
    /// a password fallback rather than the hardware.
    #[expect(clippy::missing_errors_doc, reason = "doc backlog")]
    pub fn session(&self) -> irlume_common::Result<IrSession<'_>> {
        self.session_with_progress(&no_progress())
    }

    /// [`Self::session`], reporting each completed silent warm-up window
    /// through `progress` (#336). Used transiently: the IR warm-up runs right
    /// here, and nothing in [`IrSession`] warms up again.
    #[expect(clippy::missing_errors_doc, reason = "doc backlog")]
    pub fn session_with_progress(
        &self,
        progress: &Progress,
    ) -> irlume_common::Result<IrSession<'_>> {
        self.lease
            .require_endpoint(&self.device)
            .map_err(|error| Error::Hardware(error.to_string()))?;
        let session_slot = SessionSlot::acquire(&self.session_active, &self.device)?;
        // DECLARED before the stream so it drops AFTER it. Locals drop in
        // reverse declaration order, and `warm_up_stream` below can fail: with
        // the guard declared second, that `?` dropped it first and sent the
        // restore while the stream was still live, the very mid-stream write
        // this change removes. Assigned further down, once the stream exists.
        let mode;
        let mut stream = SafeStream::open(
            &self.device,
            &self.dev,
            &self.negotiated,
            self.lease.clone(),
        )?;
        // The metadata queue has to be streaming before the image queue starts,
        // or uvcvideo produces no metadata at all (measured: zero bytes over
        // 25s when video went first). `SafeStream::open` only allocates
        // buffers; STREAMON happens on the first dequeue, which is inside
        // `warm_up_stream` below. This is the window, and it is the only one.
        let meta = ir_metadata::IlluminationLog::open(&self.device);
        // BEFORE the warm-up, because the warm-up's first dequeue is STREAMON.
        // Microsoft's sequence sets the property and THEN starts streaming, and
        // this ran the other way round: every authentication set the mode under
        // an already-running stream, the mid-stream write the rest of #168
        // removes.
        //
        // Still after `SafeStream::open`, which allocates buffers and starts
        // nothing, and after the metadata queue above, whose ordering against
        // the image queue is load-bearing and measured.
        //
        // The comment this replaces said the write had to happen "while
        // streaming" because Hello modules reset the control per open. The reset
        // is on DEVICE open, which happened in `IrCamera::open`, not here; and
        // the record above says the control survives stream close and process
        // exit on both cameras measured, so it is not stream-scoped.
        //
        // Held for the session rather than just applied: dropping `IrSession`
        // puts back the value the capture write displaced — the camera's
        // default in the ordinary case, another program's value where one was
        // deliberately set — which is the documented sequence's last step and
        // the half irlume never did.
        self.lease
            .require_endpoint(&self.device)
            .map_err(|error| Error::Hardware(error.to_string()))?;
        mode = ir_emitter::enable_with_lease(
            self.dev.handle(),
            &self.card,
            &self.device,
            self.lease.clone(),
        );
        // Survive the first-capture-after-resume race (uvcvideo still
        // re-initializing).
        warm_up_stream(&self.device, &mut stream, progress)?;
        Ok(IrSession {
            cam: self,
            stream: TrackedStream::new(stream),
            dec: IrDecoder::new(self.pix, self.quantization),
            lit: mode.lit(),
            _mode: mode,
            meta,
            _session_slot: session_slot,
        })
    }
}

/// A running IR stream with its emitter lit.
pub struct IrSession<'a> {
    cam: &'a IrCamera,
    /// `None` only transiently inside [`Self::recover`]: the broken stream
    /// must be DROPPED (STREAMOFF + buffer release) before its replacement
    /// negotiates, and a plain re-assignment builds the new value first.
    stream: TrackedStream<SafeStream<'a>>,
    dec: IrDecoder,
    lit: bool,
    /// The camera's own per-frame illumination reporting, when it has any.
    /// `None` means this camera cannot say, and brightness decides as before.
    meta: Option<ir_metadata::IlluminationLog>,
    /// Restores the face-auth control when this session ends, on every path out
    /// including an error or a panic. Declared LAST of the streaming fields, so
    /// it drops last: struct fields drop in declaration order, and both `stream`
    /// and `meta` have to stop before the control is put back. `meta` is a
    /// running V4L2 stream of its own that issues STREAMOFF from its `Drop`, so
    /// with it declared after this one the restore went out while a stream tied
    /// to the same capture was still live.
    ///
    /// Never read. It is held for its `Drop`, which is the whole point, and the
    /// dead-code lint cannot see that.
    _mode: ir_emitter::StreamMode,
    /// Reset last, after image/metadata STREAMOFF and emitter restoration.
    _session_slot: SessionSlot<'a>,
}

impl IrSession<'_> {
    /// One IR capture: a burst, the gate frame, and the burst statistics.
    ///
    /// The gate frame is a lit strobe phase, and on a source whose ceiling is
    /// known it is the brightest one clipping at most 5% of its pixels, since
    /// a blown frame both flattens the liveness cues and blinds the PAD model
    /// (#221).
    #[expect(clippy::missing_errors_doc, reason = "doc backlog")]
    pub fn capture_with_stats(&mut self) -> irlume_common::Result<(Frame, IrCaptureStats)> {
        let device = self.cam.device.as_str();
        let lease = self.cam.lease.clone();
        lease
            .require_endpoint(device)
            .map_err(|error| Error::Hardware(error.to_string()))?;
        let (w, h) = (self.cam.width, self.cam.height);
        let card = &self.cam.card;
        let lit = self.lit;
        let white_level = self.dec.white_level();
        // The state is NOT impossible, which is why this is an error and not
        // the expect it used to be: a failed `recover` (its reopen can lose a
        // format race with another application, #427, or hit transient
        // EBUSY/ENODEV) leaves the slot None for good, and the grace loop
        // retries the held session. The RGB twin already answers hardware
        // trouble here for the same reason; on the sequential branch the old
        // panic unwound out of the daemon worker.
        if self.stream.stream_mut().is_none() {
            return Err(Error::Hardware(
                "IR stream missing after a failed recovery".into(),
            ));
        }
        let stream = &mut self.stream;
        let dec = &mut self.dec;
        // The emitter may STROBE (pulse), so grab a burst and keep the brightest
        // frame, the lit strobe phase (linhello lesson). Keep every frame so the
        // optional ambient subtraction below can pair the lit frame with an
        // adjacent emitter-off one.
        // Every frame is decoded to 8-bit GREY at dequeue, so the means, the
        // subtraction, and everything downstream see one uniform layout.
        let mut frames: Vec<Vec<u8>> = Vec::with_capacity(IR_BURST);
        let mut means: Vec<f64> = Vec::with_capacity(IR_BURST);
        let mut taken: Vec<std::time::Instant> = Vec::with_capacity(IR_BURST);
        // Each frame's V4L2 buffer timestamp, the key that ties it to the
        // camera's illumination record. Measured identical across the image and
        // metadata queues for every frame of a 24-frame run; dequeue order is
        // NOT used, because the two queues are drained independently.
        let mut stamps: Vec<i64> = Vec::with_capacity(IR_BURST);
        let mut meta = self.meta.as_mut();
        // A session is reused across captures, so last burst's records are both
        // useless and unbounded growth if kept.
        if let Some(log) = meta.as_mut() {
            log.begin_burst();
        }
        // No re-fire mid-burst. The mode is set once before the stream starts,
        // which is the sequence Microsoft documents and tests: set the property,
        // start streaming, stop streaming, unset. Rewriting the control under a
        // running stream is not part of it, and nothing published says which
        // frame such a write first affects.
        //
        // The re-fire existed to make sure a lit frame landed in the burst. The
        // camera answers that directly now, per frame, through the illumination
        // metadata added in #167, so the guess is not needed to know the answer.
        for _ in 0..IR_BURST {
            lease
                .require_endpoint(device)
                .map_err(|error| Error::Hardware(error.to_string()))?;
            let (buf, bmeta, _sequence) = stream.next().map_err(|error| map_io(device, error))?;
            lease
                .require_endpoint(device)
                .map_err(|error| Error::Hardware(error.to_string()))?;
            stamps.push(bmeta.timestamp_micros());
            taken.push(std::time::Instant::now());
            // Drain every iteration, not once at the end. The metadata ring is
            // smaller than a burst, so a single drain afterwards silently loses
            // the earliest frames' records: measured 7 of 10 frames classified
            // with an end-of-burst drain, 10 of 10 draining per frame. A
            // non-blocking dequeue that finds nothing costs microseconds
            // against a 67ms frame interval.
            if let Some(log) = meta.as_mut() {
                log.drain();
            }
            let data = dec.decode(buf, w, h);
            means.push(data.iter().map(|&p| p as f64).sum::<f64>() / data.len().max(1) as f64);
            frames.push(data);
        }
        let flags: Vec<Option<ir_metadata::Illumination>> = match meta {
            Some(log) => {
                // The last frame's record can land just after its image buffer.
                log.drain();
                stamps.iter().map(|&t| log.illumination_at(t)).collect()
            }
            None => vec![None; means.len()],
        };
        let from_camera = flags.iter().filter(|f| f.is_some()).count();
        // Per-frame comparison of the two answers, for measuring how often the
        // old threshold disagreed with the camera. A disagreement is the whole
        // reason this path exists, and it can only be observed against a scene
        // that produces one, so the instrument is kept rather than reasoned about.
        if std::env::var("IRLUME_DEBUG_IR_FRAMES").is_ok() {
            for (i, (&m, f)) in means.iter().zip(&flags).enumerate() {
                let camera = match f {
                    Some(ir_metadata::Illumination::Lit) => "lit",
                    Some(ir_metadata::Illumination::Dark) => "dark",
                    None => "unsaid",
                };
                let threshold = if m >= f64::from(ir_emitter::IR_LIT_MEAN) {
                    "lit"
                } else {
                    "dark"
                };
                let verdict = match f {
                    Some(_) if camera != threshold => "DISAGREE",
                    Some(_) => "agree",
                    None => "-",
                };
                // stddev too: whether a frame is a SCENE or a substituted
                // constant is spread, not level (#197 wants the saturated
                // cover's spread measured, and this line is the instrument).
                eprintln!(
                    "[ir_frame] {i:2} mean {m:6.1}  stddev {:6.2}  camera {camera:6}  threshold(>={:.0}) {threshold:4}  {verdict}",
                    ir_dark::frame_stddev(&frames[i]),
                    ir_emitter::IR_LIT_MEAN
                );
            }
        }
        let bmin = means.iter().cloned().fold(f64::INFINITY, f64::min);
        let bmax = means.iter().cloned().fold(f64::NEG_INFINITY, f64::max);
        // The brightest CLEAN frame the CAMERA flagged lit: a clipped frame
        // compresses the centre/edge ratio toward the spoof floor and can
        // defeat IR face detection outright (#221), and the brightest frame of
        // a warming burst is the most likely to clip. Clipping is only
        // measurable when the source format names its ceiling, and lit-ness
        // only when the camera classified frames; on either fallback this is
        // the first frame holding the max mean, exactly the original
        // incremental scan.
        // `map(|w| ...)`, NOT `map(|_| ...)`. Binding the ceiling and discarding
        // it is what made this measurement disagree with the one that judges the
        // face region: presence switched the clip-aware selection on while the
        // count stayed pinned to 255 (#394).
        let clipped_fracs: Option<Vec<f64>> = white_level.map(|w| {
            frames
                .iter()
                .map(|f| ir_probe::saturated_fraction(f, w))
                .collect()
        });
        let best_i =
            ir_metadata::best_gate_frame(&means, &flags, clipped_fracs.as_deref()).unwrap_or(0);
        let mut best = Some(frames[best_i].clone());
        let mut ir_window = CaptureWindow::at(taken[best_i]);

        // Windows-Hello-style ambient subtraction. EXPERIMENTAL, opt-in. On a
        // strobing emitter the frame adjacent to the brightest is an emitter-OFF
        // exposure that captured only ambient IR. Subtracting it isolates the
        // emitter's own reflected light, the same illuminated/ambient-pair step
        // Hello uses. Its purpose is SURVIVING EXPOSURE EXTREMES: under strong ambient IR
        // (sunlight) the pedestal would otherwise wash out the emitter reflection.
        // It is not primarily a spoof control (Hello credits spoof resistance to the
        // IR wavelength plus a separate liveness stage, which is where irlume's
        // center/edge and glint cues live). Indoors the off-frame is ~0, so it is a no-op.
        //
        // The subtraction assumes the lit and off frames share an exposure; pairing
        // ADJACENT burst frames (after AE_WARMUP) keeps auto-exposure drift between
        // the pair small. Pixels where the lit frame is saturated (255) carry no
        // reliable subtracted value; the debug line reports the clipped fraction so a
        // blown exposure is visible rather than silently trusted.
        //
        // NOT a validated security control yet, two reasons it stays behind a flag:
        //   1. The liveness center/edge cue is a RATIO, which is non-monotonic
        //      under subtraction: removing an ambient frame that is brighter at the
        //      border than the center RAISES the ratio, so a subtracted frame could
        //      pass the floor a raw frame would fail. That floor must be re-tuned
        //      against subtracted frames before this can be a default.
        //   2. The IR frame also feeds dark-mode IR matching, so enrollment and
        //      auth must use the SAME setting; toggling it requires a re-enroll.
        // Both are moot while the flag is unset (the shipped default).
        let subtract = std::env::var("IRLUME_IR_AMBIENT_SUBTRACT").is_ok_and(|v| v.trim() == "1");
        let debug_ir = std::env::var("IRLUME_DEBUG_IR").is_ok();
        // Stays None unless the returned pixels stop being the raw gate frame.
        let mut saturation_frame: Option<Vec<u8>> = None;
        if subtract {
            // An adjacent frame the camera flagged dark, else the darker
            // neighbour as before. Adjacency still bounds auto-exposure drift
            // between the pair; metadata only settles which neighbour is
            // genuinely the emitter-off exposure.
            let ambient_i = ir_metadata::ambient_partner(best_i, &means, &flags);
            if let Some(ai) = ambient_i {
                let (lit_mean, amb_mean) = (means[best_i], means[ai]);
                // Subtract only when there is a real strobe gap (a genuine off-frame,
                // never a steady emitter) AND enough ambient IR to be worth removing.
                if lit_mean - amb_mean > STROBE_MIN_GAP && amb_mean >= LOW_AMBIENT_SKIP {
                    let sub = ir_probe::subtract(&frames[best_i], &frames[ai]);
                    let sub_mean = ir_probe::mean(&sub);
                    // Revert when subtraction collapses the signal: if the emitter
                    // barely cleared a bright pedestal, the result is noise and the
                    // face becomes undetectable. Keep the raw lit frame instead of
                    // handing downstream a blank one.
                    if sub_mean >= SUBTRACT_MIN_RESULT {
                        // Keep the raw gate frame BEFORE handing back the
                        // subtracted one: saturation is only measurable in the
                        // pixels that actually hit the ceiling, and subtraction
                        // moves every one of them below it. Cloned only on this
                        // branch, the one where the returned pixels stop being
                        // the raw ones.
                        saturation_frame = white_level.map(|_| frames[best_i].clone());
                        best = Some(sub);
                        // The result now carries pixels from BOTH frames.
                        ir_window = ir_window.union(CaptureWindow::at(taken[ai]));
                    }
                    if debug_ir {
                        // Reads the same ceiling the gate-frame selection above
                        // used, so the debug percentage and the decision cannot
                        // disagree.
                        //
                        // `None` prints no percentage at all rather than
                        // substituting 255. Defaulting was the wrong instinct
                        // twice over: the count is `p >= white`, so 255 passes
                        // the FEWEST pixels and under-reports, which on a
                        // diagnostic means failing to warn; and a format that
                        // names no ceiling has no clipping figure to report, so
                        // printing one states a measurement nobody took. Same
                        // rule `eye_glint_of` and `saturated_frac_of` follow
                        // next door (#394).
                        let clipped =
                            white_level.map(|w| ir_probe::saturated_fraction(&frames[best_i], w));
                        let action = if sub_mean >= SUBTRACT_MIN_RESULT {
                            "applied"
                        } else {
                            "reverted (result too dark; face would vanish)"
                        };
                        let clip_note = match clipped {
                            Some(c) if c > ir_metadata::CLIPPED_FRAC_MAX => format!(
                                "; lit clipped {:.1}% (blown exposure; subtracted frame unreliable)",
                                c * 100.0
                            ),
                            Some(c) => format!("; lit clipped {:.1}%", c * 100.0),
                            None => String::new(),
                        };
                        eprintln!(
                        "[ir] ambient-subtract {action}: lit {best_i} ({lit_mean:.0}) - ambient {ai} ({amb_mean:.0}) => mean {sub_mean:.0}{clip_note}"
                    );
                    }
                } else if debug_ir {
                    eprintln!(
                    "[ir] ambient-subtract: skipped (ambient {amb_mean:.0} < {LOW_AMBIENT_SKIP:.0} or strobe gap {:.0} <= {STROBE_MIN_GAP:.0})",
                    lit_mean - amb_mean
                );
                }
            }
        }
        // Lit and ambient levels follow the camera's own classification when it
        // gave one. `bmax` is the wrong answer precisely in the case this exists
        // to fix: a frame the camera flagged dark can hold the burst's highest
        // mean, and reporting that as the lit level would feed the ambient-relative
        // gates a strobe gap that never happened. With no metadata both fall back
        // to the burst extremes, unchanged.
        let best_mean = means.get(best_i).copied().unwrap_or(0.0);
        let (lit_level, ambient_level) = if from_camera == 0 {
            (bmax, bmin)
        } else {
            let dark_min = means
                .iter()
                .zip(&flags)
                .filter(|(_, f)| matches!(f, Some(ir_metadata::Illumination::Dark)))
                .map(|(m, _)| *m)
                .fold(f64::INFINITY, f64::min);
            (
                best_mean,
                if dark_min.is_finite() { dark_min } else { bmin },
            )
        };
        if debug_ir {
            eprintln!("[ir_emitter] card={card:?} SET_CUR ok={lit}; burst {IR_BURST} frames, per-frame mean {bmin:.1}..{bmax:.1}");
            eprintln!(
                "[ir] illumination: {from_camera}/{} frames classified by the camera; \
                 chose frame {best_i} (mean {best_mean:.1}{}), lit {lit_level:.1} / ambient {ambient_level:.1}",
                means.len(),
                match clipped_fracs.as_ref().and_then(|c| c.get(best_i)) {
                    Some(c) => format!(", clipped {:.1}%", c * 100.0),
                    None => String::new(),
                }
            );
        }
        // An unusable burst gets a DIAGNOSIS, not the old one-size hint. The
        // single "run ir-setup" line fit one of a dark frame's six causes and
        // sent users to write camera firmware for shutters, covers and range
        // problems (#185); the evidence to do better is already in hand:
        // whether irlume drove the control, the camera's own per-frame
        // illumination metadata (#167), the privacy control, and the frame's
        // mean and spread. Two bands carry a diagnosis: dark, and
        // saturated-flat, because the most common cover case is not dark at
        // all: an opaque cover under the active emitter reflects it straight
        // back and saturates the sensor (#197, measured 252.8-255.0 covered on
        // both test cameras). This range check is only a shortcut past the
        // stddev pass on ordinary scenes; `ir_dark::diagnose` re-applies the
        // real gates and answers None for anything that is a scene after all.
        // `ir-setup` discovery advice survives only on the one cause it fits;
        // the historical note about why irlume never recommends
        // linux-enable-ir-emitter's blind search lives with that message's
        // cause in `ir_dark` (#159).
        if (0.0..ir_dark::DARK_MEAN_MAX).contains(&best_mean)
            || best_mean >= ir_dark::SATURATED_MIN_MEAN
        {
            let frames_lit = flags
                .iter()
                .filter(|f| matches!(f, Some(ir_metadata::Illumination::Lit)))
                .count();
            let evidence = ir_dark::DarkEvidence {
                emitter_active: lit,
                emitter_disabled: ir_emitter::emitter_explicitly_disabled(),
                privacy_engaged: privacy_engaged(device),
                frames_lit,
                frames_classified: from_camera,
                frame_mean: best_mean,
                frame_stddev: ir_dark::frame_stddev(&frames[best_i]),
                // The brightest METADATA-LIT frame, never the overall maximum:
                // ambient light also makes bright frames, and only the
                // camera's own lit flag ties brightness to the emitter (#268).
                lit_max_mean: means
                    .iter()
                    .zip(&flags)
                    .filter(|(_, f)| matches!(f, Some(ir_metadata::Illumination::Lit)))
                    .map(|(m, _)| *m)
                    .fold(0.0f64, f64::max),
            };
            if let Some(line) = ir_dark::diagnose(&evidence)
                .and_then(|cause| ir_dark::render(card, best_mean, &cause))
            {
                eprintln!("{line}");
            }
        }
        let grey = best.ok_or_else(|| Error::Hardware("no IR frames captured".into()))?;
        Ok((
            Frame {
                width: w,
                height: h,
                spectrum: Spectrum::Ir,
                data: grey,
                // The returned pixels are the chosen burst frame's, so the window is
                // that dequeue. Ambient subtraction mixes in an ADJACENT frame, so
                // it widens to cover both.
                captured: ir_window,
            },
            IrCaptureStats {
                saturation_frame,
                lit_mean: lit_level as f32,
                ambient_mean: ambient_level as f32,
                ambient_observed: flags
                    .iter()
                    .any(|f| matches!(f, Some(ir_metadata::Illumination::Lit)))
                    && flags
                        .iter()
                        .any(|f| matches!(f, Some(ir_metadata::Illumination::Dark))),
                burst_frames: IR_BURST,
                camera_classified_frames: from_camera,
                white_level,
            },
        ))
    }

    /// Recover a broken stream in place, on the fd this session already holds.
    ///
    /// Drops the failed stream (STREAMOFF + buffer release), restores and
    /// releases the old emitter guard, then opens a fresh stream on the same
    /// device fd and re-enables the emitter. The metadata queue is reopened
    /// and the decoder is reset to its initial state. No new device open, so
    /// no EBUSY from a double-open-rejecting camera.
    ///
    /// The old guard MUST go before the fresh `enable`, the same order the
    /// frozen-stream restarts in `capture_ir_streaming` and
    /// `capture_ir_sequence` use: while it lives it holds the per-camera
    /// stream lock, and `flock` excludes per open file description, so the
    /// fresh enable in this same process answered Busy, refused to drive the
    /// emitter, and the assignment below then dropped the old guard, whose
    /// Drop wrote the displaced value back UNDER the stream that had just
    /// reopened. Recovery reported success while every later capture in the
    /// grace window returned dark IR frames.
    #[expect(clippy::missing_errors_doc, reason = "doc backlog")]
    pub fn recover(&mut self) -> irlume_common::Result<()> {
        self.cam
            .lease
            .require_endpoint(&self.cam.device)
            .map_err(|error| Error::Hardware(error.to_string()))?;
        drop(self.stream.take()); // STREAMOFF + buffer release before replacement
        self.meta = None; // drop the metadata queue
                          // A restore failure PROPAGATES, mirroring the frozen-stream restart:
                          // the guard is spent after one attempt, and an unrecorded write whose
                          // restore failed would otherwise become permanently unowned.
        self._mode.restore().map_err(|e| {
            Error::Hardware(format!(
                "{}: could not restore the emitter before recovering the stream: {e}",
                self.cam.device
            ))
        })?;
        self._mode = ir_emitter::StreamMode::inert();
        let stream = SafeStream::open(
            &self.cam.device,
            &self.cam.dev,
            &self.cam.negotiated,
            self.cam.lease.clone(),
        )?;
        let meta = ir_metadata::IlluminationLog::open(&self.cam.device);
        self.cam
            .lease
            .require_endpoint(&self.cam.device)
            .map_err(|error| Error::Hardware(error.to_string()))?;
        let mode = ir_emitter::enable_with_lease(
            self.cam.dev.handle(),
            &self.cam.card,
            &self.cam.device,
            self.cam.lease.clone(),
        );
        let lit = mode.lit();
        let (meta, mode) = install_recovered_resources(stream, meta, mode, |stream| {
            self.cam
                .lease
                .require_endpoint(&self.cam.device)
                .map_err(|error| Error::Hardware(error.to_string()))?;
            self.stream.install_recovered(stream).map_err(|error| {
                Error::Hardware(format!(
                    "{}: could not begin the recovered sequence epoch: {error}",
                    self.cam.device
                ))
            })
        })?;
        self.meta = meta;
        self._mode = mode;
        self.dec = IrDecoder::new(self.cam.pix, self.cam.quantization);
        self.lit = lit;
        Ok(())
    }
}

/// Ambient-subtraction helpers (Windows-Hello-style illuminated minus ambient).
/// `subtract` is used by `capture_ir` when `IRLUME_IR_AMBIENT_SUBTRACT=1`
/// (experimental, off by default); `capture_raw_burst`/`center_border_ratio`
/// are diagnostics for the strobe-probe example. Kept in the crate so the
/// example and the capture path share one implementation.
pub mod ir_probe {
    use super::negotiate_ir_format;
    use super::Device;
    use super::{
        ir_emitter, map_io, privacy_engaged_with_permit, verify_pinned, Error, Frame, Spectrum,
    };

    /// Mean brightness of an 8-bit greyscale buffer.
    pub fn mean(data: &[u8]) -> f64 {
        if data.is_empty() {
            0.0
        } else {
            data.iter().map(|&p| p as f64).sum::<f64>() / data.len() as f64
        }
    }

    /// Per-pixel saturating subtraction `lit - ambient`, clamped at 0. Removes the
    /// ambient IR pedestal (Hello's ambient-subtraction step) so the emitter's own
    /// reflection survives a bright-ambient exposure: light present in both frames
    /// (sunlight, a screen's own IR) cancels; the emitter-lit face does not. This
    /// is an exposure-compensation step, not a standalone spoof control. Falls back
    /// to `lit` on a size mismatch.
    pub fn subtract(lit: &[u8], ambient: &[u8]) -> Vec<u8> {
        if lit.len() != ambient.len() {
            return lit.to_vec();
        }
        lit.iter()
            .zip(ambient)
            .map(|(&l, &a)| l.saturating_sub(a))
            .collect()
    }

    /// Fraction of pixels at or above `white`, the ceiling the negotiated format
    /// actually reports. A high clipped fraction in the lit frame means the
    /// exposure is blown: those pixels lost their true emitter return, so both
    /// the raw and the ambient-subtracted frame are unreliable there. Used as a
    /// capture-quality signal, not a hard gate.
    ///
    /// `white` is a parameter rather than a hardcoded 255 because
    /// `clipping_white_level` can answer 235: a limited-range stream rails at
    /// nominal white, not at the type's maximum. Counting only `== 255` on such
    /// a stream reports every frame as pristine, which does not merely lose a
    /// signal. `Some(_)` is what switches ON #221's clip-aware gate-frame
    /// selection, so the selection would run against an all-zero measurement,
    /// pass every frame under `CLIPPED_FRAC_MAX`, and hand back the brightest
    /// lit frame, which is the blown one #221 exists to avoid. The face-region
    /// instrument `saturated_frac_in_bbox` in irlume-auth has always taken the
    /// ceiling, so the two disagreed about the same burst (#394). Named in
    /// backticks and not as an intra-doc link: irlume-camera cannot depend on
    /// irlume-auth, so the link would not resolve and CI treats that as an
    /// error.
    ///
    /// `>=` rather than `==` for the same reason the bbox instrument uses it: a
    /// sample above nominal white is out-of-range excursion, which is still not
    /// a pixel carrying a usable emitter return.
    ///
    /// KILL CONDITION for the first limited-range module anyone finds. At a 235
    /// ceiling `>=` also counts 236..=255, which BT.601/709 calls legal
    /// excursion rather than saturation, so this governs a strictly larger
    /// pixel population than the one `CLIPPED_FRAC_MAX` (0.05) was fitted on:
    /// #221's captures were taken against a 255 ceiling, where 236..=254 was
    /// ordinary signal counting for nothing. If a healthy frame from such a
    /// module puts more than 5% of its pixels above 235, `best_gate_frame`
    /// takes its `least` branch on every burst. Dump the per-frame fractions
    /// from a real limited-range device before trusting 0.05 there; do not
    /// assume the constant transfers.
    pub fn saturated_fraction(data: &[u8], white: u8) -> f64 {
        if data.is_empty() {
            return 0.0;
        }
        let clipped = data.iter().filter(|&&p| p >= white).count();
        clipped as f64 / data.len() as f64
    }

    /// Ratio of mean brightness in the center 50% box to the surrounding
    /// border. The emitter lights the near subject more than the far
    /// background, so a real emitter-lit face reads > 1; a flat, uniformly
    /// lit scene reads ~1. A proxy for how well subtraction isolates the
    /// subject.
    pub fn center_border_ratio(data: &[u8], w: u32, h: u32) -> f64 {
        if data.len() < (w * h) as usize || w < 4 || h < 4 {
            return 0.0;
        }
        let (x0, x1) = (w / 4, w * 3 / 4);
        let (y0, y1) = (h / 4, h * 3 / 4);
        let (mut c_sum, mut c_n, mut b_sum, mut b_n) = (0u64, 0u64, 0u64, 0u64);
        for y in 0..h {
            for x in 0..w {
                let p = data[(y * w + x) as usize] as u64;
                if x >= x0 && x < x1 && y >= y0 && y < y1 {
                    c_sum += p;
                    c_n += 1;
                } else {
                    b_sum += p;
                    b_n += 1;
                }
            }
        }
        let c = c_sum as f64 / c_n.max(1) as f64;
        let b = b_sum as f64 / b_n.max(1) as f64;
        if b < 1.0 {
            return 0.0;
        }
        c / b
    }

    /// [`capture_raw_burst_timed`] without the timing column, for callers that
    /// only need the frames.
    #[expect(clippy::missing_errors_doc, reason = "doc backlog")]
    pub fn capture_raw_burst(device: &str, n: usize) -> irlume_common::Result<Vec<Frame>> {
        Ok(capture_raw_burst_timed(device, n)?
            .into_iter()
            .map(|(f, _)| f)
            .collect())
    }

    /// Capture `n` raw IR frames (GREY 8-bit) with the emitter enabled, without
    /// the brightest-frame reduction `capture_ir` does, each stamped with
    /// milliseconds since the first dequeue (real delivered frame rate and
    /// strobe cadence; the driver's nominal fps is not the delivered fps under
    /// USB contention). Used to inspect the strobe pattern, prototype
    /// subtraction, and audit capture timing offline.
    #[expect(clippy::missing_errors_doc, reason = "doc backlog")]
    pub fn capture_raw_burst_timed(
        device: &str,
        n: usize,
    ) -> irlume_common::Result<Vec<(Frame, f64)>> {
        verify_pinned(device)?;
        let permit = super::lease::permit_for_endpoint(
            device,
            super::lease::CameraOperationKind::Diagnostics,
            std::time::Duration::from_secs(2),
        )
        .map_err(|error| Error::Hardware(error.to_string()))?;
        if privacy_engaged_with_permit(device) {
            return Err(Error::Hardware(format!(
                "{device}: hardware privacy switch is ON"
            )));
        }
        let dev = Device::with_path(device).map_err(|e| map_io(device, e))?;
        let (fmt, pix) = negotiate_ir_format(device, &dev)?;
        let mut dec = super::IrDecoder::new(pix, fmt.quantization);
        let (w, h) = (fmt.width, fmt.height);
        let card = dev.query_caps().map(|c| c.card).unwrap_or_default();
        // DECLARED before the stream, ASSIGNED after it opens. Locals drop in
        // reverse declaration order, so `stream` drops first and stops the
        // stream, and only then does this guard put the control back; declaring
        // it after `stream` sent the restore out while the stream was still
        // live, which is the mid-stream write this change exists to remove.
        //
        // The assignment waits for the open because writing first would touch
        // the camera for a stream that may never exist: an open that fails on
        // EBUSY, with another process already streaming, would leave this one
        // having applied the mode and then restored the default underneath the
        // other process's live stream. `SafeStream::open` only allocates
        // buffers; STREAMON happens on the first dequeue, so the set still
        // lands before streaming starts.
        let mode;
        let stream = super::SafeStream::open(device, &dev, &fmt, permit.clone())?;
        let mut stream = super::TrackedStream::new(stream);
        mode = ir_emitter::enable_with_lease(dev.handle(), &card, device, permit.clone());
        // Bound, never read: held for its `Drop`, which restores the control.
        let _ = &mode;
        let mut out = Vec::with_capacity(n);
        let t0 = std::time::Instant::now();
        for _ in 0..n {
            let (buf, _meta, _sequence) = stream.next().map_err(|error| map_io(device, error))?;
            let taken = std::time::Instant::now();
            out.push((
                Frame {
                    width: w,
                    height: h,
                    spectrum: Spectrum::Ir,
                    data: dec.decode(buf, w, h),
                    captured: super::CaptureWindow::at(taken),
                },
                t0.elapsed().as_secs_f64() * 1000.0,
            ));
        }
        Ok(out)
    }
}

/// Sparse content signature for the frozen-stream detector: up to 64 bytes
/// sampled at a fixed stride across the frame. Verbatim extraction from
/// [`capture_ir_sequence`] (the former `sig_of` closure) so the pure logic is
/// unit-testable without a camera; zero behavior change.
pub(crate) fn frame_signature(data: &[u8]) -> Vec<u8> {
    let stride = (data.len() / 64).max(1);
    data.iter().step_by(stride).take(64).copied().collect()
}

/// Frozen-stream predicate: BIT-IDENTICAL consecutive signatures on a frame
/// whose mean sits in the normal exposure band (saturated / near-black frames
/// are optical states, not a stall). Verbatim extraction of the `frozen`
/// expression in [`capture_ir_sequence`] as a test seam; zero behavior change.
pub(crate) fn frame_frozen(best_mean: f64, sig: &[u8], last_sig: Option<&[u8]>) -> bool {
    (10.0..245.0).contains(&best_mean) && last_sig == Some(sig)
}

/// Mean IR value at/above which a decoded frame is treated as an exposure
/// blow-out: a saturated frame carries no detectable face, so a streaming
/// consumer skips it rather than spend a window slot on it. Matches the upper
/// bound of [`frame_frozen`]'s normal-exposure band.
const IR_BLOWN_MEAN: f64 = 245.0;

/// One usable IR frame delivered to a [`capture_ir_streaming`] consumer, with
/// the decoded mean the caller would otherwise recompute (the strobe phase and
/// framing cues both key off it).
pub struct IrStreamFrame {
    pub frame: Frame,
    /// Decoded 8-bit mean of `frame.data`.
    pub mean: f64,
}

/// Drive a single held-open IR stream, invoking `on_frame` for each USABLE frame
/// (non-frozen, non-blown) until the consumer returns [`std::ops::ControlFlow::Break`] or
/// the `max_frames` attempt budget is spent. Returns the break value, or `None`
/// if the budget ran out first.
///
/// This is the rolling-capture core the burst helpers and the live consumers
/// share: it owns the device, the V4L2 mmap stream, the emitter re-fire, and the
/// frozen-stream restart, so a consumer only decides what to do with each frame
/// and when to stop. The consent watch can therefore return the instant it
/// sees an accepted gesture instead of always draining a fixed window, and a
/// preview can pull frames continuously; both get the same black/blown/frozen filtering.
///
/// Usable = the same set [`capture_ir_sequence`] historically kept: emitter-off
/// (dark) frames ARE delivered, because a consumer classifying the strobe needs
/// them; only frozen and blown frames are dropped.
#[expect(clippy::missing_errors_doc, reason = "doc backlog")]
pub fn capture_ir_streaming<B>(
    device: &str,
    max_frames: usize,
    mut on_frame: impl FnMut(IrStreamFrame) -> std::ops::ControlFlow<B>,
) -> irlume_common::Result<Option<B>> {
    verify_pinned(device)?;
    let permit = lease::permit_for_endpoint(
        device,
        lease::CameraOperationKind::Preview,
        std::time::Duration::from_secs(2),
    )
    .map_err(|error| Error::Hardware(error.to_string()))?;
    if privacy_engaged_with_permit(device) {
        return Err(Error::Hardware(format!(
            "{device}: hardware privacy switch is ON"
        )));
    }
    let dev = Device::with_path(device).map_err(|e| map_io(device, e))?;
    let (fmt, pix) = negotiate_ir_format(device, &dev)?;
    let mut dec = IrDecoder::new(pix, fmt.quantization);
    let (w, h) = (fmt.width, fmt.height);
    let card = dev.query_caps().map(|c| c.card).unwrap_or_default();
    // DECLARED before the stream, ASSIGNED after it opens. Locals drop in
    // reverse declaration order, so `stream` drops first and stops the
    // stream, and only then does this guard put the control back; declaring
    // it after `stream` sent the restore out while the stream was still
    // live, which is the mid-stream write this change exists to remove.
    //
    // The assignment waits for the open because writing first would touch
    // the camera for a stream that may never exist: an open that fails on
    // EBUSY, with another process already streaming, would leave this one
    // having applied the mode and then restored the default underneath the
    // other process's live stream. `SafeStream::open` only allocates
    // buffers; STREAMON happens on the first dequeue, so the set still
    // lands before streaming starts.
    let mut mode;
    let stream = SafeStream::open(device, &dev, &fmt, permit.clone())?;
    let mut stream = TrackedStream::new(stream);
    mode = ir_emitter::enable_with_lease(dev.handle(), &card, device, permit.clone());
    // Sparse content signature: BIT-IDENTICAL consecutive frames mean the stream
    // has FROZEN (measured live 2026-07-01 in dark rooms: frames lock to a
    // constant mid-grey for the rest of the window); real sensor noise never
    // repeats exactly. Saturated and near-black frames are excluded from the
    // check: those are optical states (exposure blow-out / emitter-off phase),
    // not a stall, and restarting mid-settle only prolongs the settle.
    // (Signature + predicate live in `frame_signature` / `frame_frozen`.)
    let (mut dead_run, mut restarts) = (0usize, 0usize);
    let mut last_sig: Option<Vec<u8>> = None;
    // Set once per stream, before it starts, and not per frame; the
    // frozen-stream restart below opens a new stream and applies it again,
    // which is the only re-apply left.
    //
    // This used to re-apply the control every eighth frame on the theory that
    // "some controls self-clear". At the default consent budget that is ten more
    // writes to camera firmware per watch, and `enable` is not a bare ioctl: each
    // call re-reads the USB descriptors from sysfs and takes a lock to scan the
    // undo journal on disk. Ten of those sit in the authentication path for a
    // hypothesis this project MEASURED and found false: the record in
    // `IrCamera::session` says the control survives stream close and process
    // exit on both cameras here, so there was nothing self-clearing to re-arm
    // against.
    //
    // NOT justified by the illumination metadata from #167. `capture_with_stats`
    // classifies its frames with that; this function never opens the metadata
    // queue, and an earlier version of this comment claimed the evidence anyway.
    // The residual risk is a module nobody here has seen whose control does
    // self-clear mid stream: this path would go dark for the window and cost the
    // user a password fallback. Reading the metadata queue here is how that gets
    // closed, and it is not done.
    for _ in 0..max_frames {
        let (buf, _meta, _sequence) = stream.next().map_err(|error| map_io(device, error))?;
        let taken = std::time::Instant::now();
        let data = dec.decode(buf, w, h);
        let mean = data.iter().map(|&p| p as f64).sum::<f64>() / data.len().max(1) as f64;
        let sig = frame_signature(&data);
        let frozen = frame_frozen(mean, &sig, last_sig.as_deref());
        last_sig = Some(sig);
        if frozen {
            dead_run += 1;
            if dead_run >= FROZEN_RUN_BEFORE_RESTART && restarts < FROZEN_RESTART_BUDGET {
                restarts += 1;
                dead_run = 0;
                last_sig = None;
                drop(stream.take()); // stop + release buffers before re-arming
                                     // The OLD guard restores BEFORE the reopen. Its stream is
                                     // already gone, and while the guard lives it holds the
                                     // per-camera stream lock, which would make the fresh `enable`
                                     // refuse to drive the emitter at all — the lock refuses
                                     // contested writes rather than allowing an unrecorded one
                                     // (#188, review round 4). Restoring here cannot write under
                                     // the new stream either, because it happens before the fresh
                                     // apply. Earlier versions kept the old guard armed across the
                                     // reopen and negotiated ownership afterwards; the cost of
                                     // this simpler shape is one restore/apply pair per restart,
                                     // and restarts are the exception, not the path.
                                     // A restore failure PROPAGATES rather than being logged
                                     // over: the guard is spent after one attempt, and an
                                     // UNRECORDED write whose restore failed here would otherwise
                                     // become permanently unowned — the fresh enable finds the
                                     // wanted bytes with no record to claim and leaves them
                                     // forever (review round 12). Surfacing hardware trouble
                                     // beats continuing to authenticate through it.
                mode.restore().map_err(|e| {
                    Error::Hardware(format!(
                        "{device}: could not restore the emitter before restarting \
                         a frozen stream: {e}"
                    ))
                })?;
                let replacement = SafeStream::open(device, &dev, &fmt, permit.clone())?;
                let replacement_mode =
                    ir_emitter::enable_with_lease(dev.handle(), &card, device, permit.clone());
                let ((), replacement_mode) =
                    install_recovered_resources(replacement, (), replacement_mode, |replacement| {
                        stream.install_recovered(replacement)
                    })
                    .map_err(|error| {
                        Error::Hardware(format!(
                            "{device}: could not begin the recovered sequence epoch: {error}"
                        ))
                    })?;
                mode = replacement_mode;
            }
            continue;
        }
        dead_run = 0;
        if mean >= IR_BLOWN_MEAN {
            continue;
        }
        let frame = Frame {
            width: w,
            height: h,
            spectrum: Spectrum::Ir,
            data,
            captured: CaptureWindow::at(taken),
        };
        if let std::ops::ControlFlow::Break(b) = on_frame(IrStreamFrame { frame, mean }) {
            return Ok(Some(b));
        }
    }
    Ok(None)
}

/// Capture a time-ordered SEQUENCE of IR frames in a single stream session, for
/// temporal liveness cues (per-frame head pose for the nod gesture, per-frame
/// EAR for the eye-closure calibration). Unlike [`capture_ir`], the eyes-closed
/// dip of a closure must survive, so this returns every sample rather than only
/// the brightest. Each of `samples` frames is the brightest of a `burst`-frame
/// mini-burst: `burst=1` yields raw frames (to reveal whether the emitter
/// strobes); `burst>=2` de-strobes locally while keeping enough temporal
/// resolution for a blink (the IR node is ~15 fps, so a mini-burst of 2 ≈ 133 ms).
///
/// This keeps its own burst/de-strobe loop rather than delegating to
/// [`capture_ir_streaming`], which delivers raw single frames; the consent
/// watch uses the streaming core, this stays for the `burst>=2` diagnostic path.
#[expect(clippy::missing_errors_doc, reason = "doc backlog")]
pub fn capture_ir_sequence(
    device: &str,
    samples: usize,
    burst: usize,
) -> irlume_common::Result<Vec<Frame>> {
    verify_pinned(device)?;
    let permit = lease::permit_for_endpoint(
        device,
        lease::CameraOperationKind::Diagnostics,
        std::time::Duration::from_secs(2),
    )
    .map_err(|error| Error::Hardware(error.to_string()))?;
    if privacy_engaged_with_permit(device) {
        return Err(Error::Hardware(format!(
            "{device}: hardware privacy switch is ON"
        )));
    }
    let burst = burst.max(1);
    let dev = Device::with_path(device).map_err(|e| map_io(device, e))?;
    let (fmt, pix) = negotiate_ir_format(device, &dev)?;
    let mut dec = IrDecoder::new(pix, fmt.quantization);
    let (w, h) = (fmt.width, fmt.height);
    let card = dev.query_caps().map(|c| c.card).unwrap_or_default();
    // DECLARED before the stream, ASSIGNED after it opens. Locals drop in
    // reverse declaration order, so `stream` drops first and stops the
    // stream, and only then does this guard put the control back; declaring
    // it after `stream` sent the restore out while the stream was still
    // live, which is the mid-stream write this change exists to remove.
    //
    // The assignment waits for the open because writing first would touch
    // the camera for a stream that may never exist: an open that fails on
    // EBUSY, with another process already streaming, would leave this one
    // having applied the mode and then restored the default underneath the
    // other process's live stream. `SafeStream::open` only allocates
    // buffers; STREAMON happens on the first dequeue, so the set still
    // lands before streaming starts.
    let mut mode;
    let stream = SafeStream::open(device, &dev, &fmt, permit.clone())?;
    let mut stream = TrackedStream::new(stream);
    mode = ir_emitter::enable_with_lease(dev.handle(), &card, device, permit.clone());
    // Set once per stream, before it starts, and not per frame (the
    // frozen-stream restart below re-applies on its new stream). This path also carried
    // an every-eighth-frame re-fire; it went for the same reason, and with the
    // same caveat: the justification is the MEASURED record in
    // `IrCamera::session` that the control survives streaming, not the
    // illumination metadata, which this function does not read either.
    let mut frames = Vec::with_capacity(samples);
    let max_attempts = samples * 2 + 30;
    let (mut dead_run, mut restarts) = (0usize, 0usize);
    let mut last_sig: Option<Vec<u8>> = None;
    for _ in 0..max_attempts {
        if frames.len() >= samples {
            break;
        }
        let mut best: Option<Vec<u8>> = None;
        let mut best_mean = -1.0f64;
        // The kept frame is one dequeue out of the mini-burst, so remember WHICH
        // instant it came from rather than stamping the end of the burst.
        let mut taken = std::time::Instant::now();
        for _ in 0..burst {
            let (buf, _meta, _sequence) = stream.next().map_err(|error| map_io(device, error))?;
            let at = std::time::Instant::now();
            let data = dec.decode(buf, w, h);
            let mean = data.iter().map(|&p| p as f64).sum::<f64>() / data.len().max(1) as f64;
            if mean > best_mean {
                best_mean = mean;
                best = Some(data);
                taken = at;
            }
        }
        let Some(data) = best else { continue };
        let sig = frame_signature(&data);
        let frozen = frame_frozen(best_mean, &sig, last_sig.as_deref());
        last_sig = Some(sig);
        if frozen {
            dead_run += 1;
            if dead_run >= FROZEN_RUN_BEFORE_RESTART && restarts < FROZEN_RESTART_BUDGET {
                restarts += 1;
                dead_run = 0;
                last_sig = None;
                drop(stream.take()); // stop + release buffers before re-arming
                                     // The OLD guard restores BEFORE the reopen. Its stream is
                                     // already gone, and while the guard lives it holds the
                                     // per-camera stream lock, which would make the fresh `enable`
                                     // refuse to drive the emitter at all — the lock refuses
                                     // contested writes rather than allowing an unrecorded one
                                     // (#188, review round 4). Restoring here cannot write under
                                     // the new stream either, because it happens before the fresh
                                     // apply. Earlier versions kept the old guard armed across the
                                     // reopen and negotiated ownership afterwards; the cost of
                                     // this simpler shape is one restore/apply pair per restart,
                                     // and restarts are the exception, not the path.
                                     // A restore failure PROPAGATES rather than being logged
                                     // over: the guard is spent after one attempt, and an
                                     // UNRECORDED write whose restore failed here would otherwise
                                     // become permanently unowned — the fresh enable finds the
                                     // wanted bytes with no record to claim and leaves them
                                     // forever (review round 12). Surfacing hardware trouble
                                     // beats continuing to authenticate through it.
                mode.restore().map_err(|e| {
                    Error::Hardware(format!(
                        "{device}: could not restore the emitter before restarting \
                         a frozen stream: {e}"
                    ))
                })?;
                let replacement = SafeStream::open(device, &dev, &fmt, permit.clone())?;
                let replacement_mode =
                    ir_emitter::enable_with_lease(dev.handle(), &card, device, permit.clone());
                let ((), replacement_mode) =
                    install_recovered_resources(replacement, (), replacement_mode, |replacement| {
                        stream.install_recovered(replacement)
                    })
                    .map_err(|error| {
                        Error::Hardware(format!(
                            "{device}: could not begin the recovered sequence epoch: {error}"
                        ))
                    })?;
                mode = replacement_mode;
            }
            continue;
        }
        dead_run = 0;
        if best_mean >= IR_BLOWN_MEAN {
            continue;
        }
        frames.push(Frame {
            width: w,
            height: h,
            spectrum: Spectrum::Ir,
            data,
            captured: CaptureWindow::at(taken),
        });
    }
    // A short return is a CAPTURE fault, not a quiet fact about the scene: the
    // attempt budget ran out because frames arrived frozen, blown out, or too
    // slowly. Callers read this sequence as temporal evidence, so a silent
    // shortfall reads downstream as "the user did not blink" when the truth is
    // "the camera did not deliver a window to look at". Say so; the caller
    // decides whether a partial window is still worth judging.
    if frames.len() < samples {
        irlume_common::dlog!(
            "{device}: IR sequence delivered {}/{samples} frames in {max_attempts} attempts \
             ({restarts} stream restarts); temporal evidence is incomplete",
            frames.len()
        );
    }
    Ok(frames)
}

// ---- capture-mode tuning (per-camera concurrency policy) --------------------

/// How the RGB and IR frames of one decision are captured.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CaptureMode {
    /// Both streams at once. Faster, and correct on cameras that can sustain it.
    Concurrent,
    /// One stream at a time. Slower, and the only way to get full signal out of
    /// a module whose two interfaces fight over the link they share.
    Sequential,
}

impl CaptureMode {
    /// The `cameras.conf` spelling.
    pub fn as_str(self) -> &'static str {
        match self {
            CaptureMode::Concurrent => "concurrent",
            CaptureMode::Sequential => "sequential",
        }
    }

    /// Parse a stored value; unknown text is not a mode.
    pub fn parse(s: &str) -> Option<Self> {
        match s.trim().to_ascii_lowercase().as_str() {
            "concurrent" => Some(CaptureMode::Concurrent),
            "sequential" => Some(CaptureMode::Sequential),
            _ => None,
        }
    }
}

/// One arm of the contention probe: what a capture produced, averaged.
#[derive(Clone, Copy, Debug, Default)]
pub struct PairSample {
    pub rgb_mean: f32,
    pub ir_mean: f32,
    pub total_ms: f32,
    pub rounds: usize,
    /// Attempted rounds in which a capture ERRORED rather than measured. A
    /// completed round tells how much brightness survives; a failed one tells
    /// that the arm cannot run at all, and on some hardware that is the whole
    /// answer: the BRIO's RGB open returns EINVAL whenever its IR sibling is
    /// streaming, so its concurrent arm fails every attempt (#192).
    pub failed: usize,
}

/// What the probe measured about capturing both sensors at once.
#[derive(Clone, Copy, Debug, Default)]
pub struct ContentionReport {
    pub sequential: PairSample,
    pub concurrent: PairSample,
}

/// Fraction of the sequential brightness the concurrent path must retain.
///
/// Measured 2026-07-25 on two modules. The ASUS FHD built-in retains 1.04 of its
/// RGB and 0.94 of its IR, i.e. nothing outside round-to-round spread. The
/// NexiGo HelloCam N930W retains 0.42-0.56 of its RGB while its IR is
/// unaffected, and the loss is specific to its OWN sibling interface: pairing
/// the same NexiGo RGB node with a different camera's IR node retains 0.99.
///
/// What the module actually does is stop tracking the scene. Across four runs
/// its concurrent RGB mean stayed inside 56-66 while the sequential arm ranged
/// 62 to 143 with the room lighting: 142.9 -> 59.8, 124.2 -> 64.9, 117.4 -> 66.1,
/// 61.8 -> 56.2. That is auto-exposure freezing near a fixed short exposure
/// while both interfaces stream, not a proportional dimming, which is why the
/// same camera looks healthy in a dark room and loses more than half its signal
/// in a lit one.
///
/// The floor sits between the two populations, nearer the healthy one, because
/// the cost of a wrong answer is asymmetric: needlessly capturing sequentially
/// costs latency, while capturing a face at a fraction of its real brightness
/// costs recognition.
pub const CONCURRENT_SIGNAL_FLOOR: f32 = 0.80;

/// Sequential RGB brightness below which a CLEAN result proves nothing.
///
/// The loss only shows against a scene the camera should be exposing brightly.
/// Found the hard way on 2026-07-25: the same NexiGo N930W measured 0.42-0.56
/// retention with the sequential arm at 117-143, then 0.91 an hour later in a
/// dark room with the sequential arm at 62. Since the concurrent path parks
/// brightness near 60 whatever the light ([`CONCURRENT_SIGNAL_FLOOR`]), a scene
/// that legitimately reads ~60 hides the fault completely.
///
/// So the two answers carry different weight: a measured LOSS stands on its own,
/// while "no loss" is worth only as much as the light it was found in. The value
/// sits between the brightness where the fault was visible (117 and up) and the
/// one where it was not (62).
pub const CONCLUSIVE_SCENE_BRIGHTNESS: f32 = 100.0;

impl ContentionReport {
    /// Whether this result can be believed.
    ///
    /// The two arms need different amounts of light. The IR arm brings its own:
    /// the emitter lights the scene, so an IR verdict stands in a pitch-dark
    /// room. The RGB arm does not, and in the dark BOTH of its readings collapse
    /// toward the sensor's noise floor, where a ratio between them means nothing
    /// in either direction. Measured at an RGB mean of 17, retention read 121%,
    /// 122% and 126% across runs, which is not the camera gaining signal from
    /// contention; it is arithmetic on noise.
    pub fn conclusive(&self) -> bool {
        // A concurrent arm that cannot run at all is definitive in any light:
        // the failure is an errored open, not a brightness reading, so the
        // dark-room caveat below does not apply to it.
        if self.concurrent_impossible() {
            return true;
        }
        if self.retained_ir() < CONCURRENT_SIGNAL_FLOOR {
            return true;
        }
        self.sequential.rgb_mean >= CONCLUSIVE_SCENE_BRIGHTNESS
    }

    /// True when the concurrent arm never completed a round because its
    /// captures ERRORED: this camera cannot stream both nodes at once, which
    /// decides the mode by itself. Reported separately so callers do not
    /// render the arm's empty samples as "retained 0% of brightness", which
    /// reads as dimming when nothing streamed at all (#192).
    pub fn concurrent_impossible(&self) -> bool {
        self.concurrent.rounds == 0 && self.concurrent.failed > 0
    }

    /// Share of the sequential RGB brightness the concurrent path kept. 1.0 when
    /// the sequential arm measured nothing (no evidence of a loss).
    pub fn retained_rgb(&self) -> f32 {
        retained(self.concurrent.rgb_mean, self.sequential.rgb_mean)
    }

    /// Share of the sequential IR brightness the concurrent path kept.
    pub fn retained_ir(&self) -> f32 {
        retained(self.concurrent.ir_mean, self.sequential.ir_mean)
    }

    /// The mode this camera should use. Pure, so the decision is testable
    /// without hardware.
    pub fn recommended_mode(&self) -> CaptureMode {
        // Explicit rather than left to the retention arithmetic: with zero
        // concurrent rounds the retained() guards happen to produce Sequential
        // today, but "cannot run" deciding the mode must not depend on what a
        // division does with empty samples.
        if self.concurrent_impossible() {
            return CaptureMode::Sequential;
        }
        if self.retained_rgb() < CONCURRENT_SIGNAL_FLOOR
            || self.retained_ir() < CONCURRENT_SIGNAL_FLOOR
        {
            CaptureMode::Sequential
        } else {
            CaptureMode::Concurrent
        }
    }

    /// Time the concurrent path saves per capture. Negative if it saves nothing.
    pub fn saved_ms(&self) -> f32 {
        self.sequential.total_ms - self.concurrent.total_ms
    }
}

/// Why a concurrent capture attempt failed, as far as the evidence supports.
///
/// `PairSample::failed` counts rounds that errored and says nothing about why,
/// even though the kernel returned a specific number that names the cause. The
/// doc on that field already quotes one: the BRIO's RGB open answers EINVAL
/// while its IR sibling streams. This enum is the count's missing half (#341).
///
/// The variants come from reading the current tree, not from the issue's
/// summary, which had the rule wrong. Four distinct origins exist and the errno
/// ALONE does not separate them, because two of them are `ENOSPC`:
///
/// - `usb_hcd_alloc_bandwidth`, reached from `usb_set_interface`, returns
///   `-ENOSPC` on the xHCI completion codes `COMP_BANDWIDTH_ERROR` and
///   `COMP_SECONDARY_BANDWIDTH_ERROR`. This is the host controller refusing.
/// - `uvc_probe_video` returns `-ENOSPC` when the device asks for more than its
///   own endpoint carries and `UVC_QUIRK_PROBE_MINMAX` blocks renegotiating
///   compression. Nothing about the host is involved.
///
/// What separates them is the kernel log, so [`classify_contention_failure`]
/// takes both.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ContentionCause {
    /// The host controller refused to admit the altsetting: `ENOSPC` WITH a
    /// bandwidth message. The only positively identified cause here, and the
    /// only one a reduction can address by asking the host for less.
    HostBudget,
    /// No altsetting's endpoint is large enough for the payload the DEVICE
    /// requested, confirmed by uvcvideo saying so. `-EIO` alone does NOT reach
    /// this: see the note on the trace gate below.
    DeviceRequestExceedsAltsettings,
    /// A busy or ownership conflict in the V4L2 queue or the device. Not a
    /// bandwidth question, and deliberately not narrowed to "the sibling is
    /// streaming", which `EBUSY` does not establish on its own.
    Busy,
    /// The evidence does not identify a cause. The DEFAULT, and deliberately
    /// not a synonym for "no problem".
    ///
    /// Most failures land here on purpose. `EIO` has at least four origins on
    /// this path (no adequate altsetting, a malformed or short probe response,
    /// a missing or zero-sized bulk endpoint, a normalized USB control
    /// failure), and `EINVAL` has more (wrong buffer type, unconfigured queue,
    /// too few queued buffers, a nonexistent altsetting, an invalid xHCI
    /// command or context). Naming a cause from either number alone would be
    /// asserting one member of a set (#341 follow-up research).
    Unknown,
}

/// The USB core logs this immediately before returning the host controller's
/// error from `usb_set_interface`.
///
/// Matched as a substring rather than an anchored line, because #383 was
/// exactly this: a workflow matched `/: Ir$/` against a doctor line that gained
/// a suffix, and the gate silently stopped firing for eight nights. A substring
/// survives a prefix or suffix changing; it does not survive a rewording, and
/// nothing here can. That is recorded rather than hidden: these two strings
/// couple this classifier to the kernel's wording, and a kernel that rewords
/// them degrades `HostBudget` to `DeviceOverRequestNoRenegotiation`, which is
/// wrong but not permissive, since only `HostBudget` licenses a workaround.
/// Present since the 2010 USB bandwidth-allocation rework and unchanged in the
/// current tree.
///
/// NOT specific on its own: the USB core prints it for ANY negative return from
/// `usb_hcd_alloc_bandwidth`, including `ENOMEM` while disabling link power
/// management. It is the errno that narrows it, which is why this is only ever
/// consulted together with `ENOSPC`.
const USB_CORE_NO_BANDWIDTH: &str = "Not enough bandwidth for altsetting";
/// xHCI's own message at the point it returns `-ENOSPC`, and the specific one:
/// it is printed on `COMP_BANDWIDTH_ERROR` and `COMP_SECONDARY_BANDWIDTH_ERROR`
/// and nothing else. Observed in reports from 2017 through the current tree.
const XHCI_NO_BANDWIDTH: &str = "Not enough bandwidth for new device state";
/// uvcvideo saying no altsetting fits the device's request. This is `uvc_dbg`
/// under the VIDEO class, so it is ABSENT unless an administrator set
/// uvcvideo's `trace` parameter. Treat its presence as strong evidence and its
/// absence as no evidence at all.
const UVC_NO_FAST_ENOUGH_ALT: &str = "No fast enough alt setting";

/// Name the cause of a failed concurrent capture from the kernel's own evidence.
///
/// Pure over its inputs on purpose: it needs no camera, no root and no access to
/// the kernel log, so the decision can be proven while the collection of
/// `kernel_lines` is still being designed. Collecting them is a separate
/// question, and an empty slice is a valid input meaning "no log evidence
/// available", not "no bandwidth message was logged".
///
/// `errno` is `None` when the failure was not a syscall at all (a decode
/// refusal, a preemption). That is not the same as a syscall returning zero and
/// must not be read as one.
#[must_use]
pub fn classify_contention_failure(errno: Option<i32>, kernel_lines: &[&str]) -> ContentionCause {
    let saw = |needle: &str| kernel_lines.iter().any(|l| l.contains(needle));
    let Some(errno) = errno else {
        return ContentionCause::Unknown;
    };
    // Ordered by how much the evidence establishes, strongest first. Each arm
    // needs a LOG line as well as a number, except `EBUSY`, whose name claims
    // nothing a bare errno cannot carry.
    if errno == libc::ENOSPC && (saw(XHCI_NO_BANDWIDTH) || saw(USB_CORE_NO_BANDWIDTH)) {
        return ContentionCause::HostBudget;
    }
    if errno == libc::EIO && saw(UVC_NO_FAST_ENOUGH_ALT) {
        return ContentionCause::DeviceRequestExceedsAltsettings;
    }
    if errno == libc::EBUSY {
        return ContentionCause::Busy;
    }
    // Everything else, INCLUDING bare `EIO`, bare `EINVAL` and bare `ENOSPC`.
    // Each of those numbers has several origins on this path and no log line
    // separated them, so nothing has been established.
    ContentionCause::Unknown
}

/// Whether a bandwidth reduction could address this cause.
///
/// The gate #341's research asks for. Only a cause whose mechanism is "the
/// request was too large" can be helped by making the request smaller, and only
/// a confirmed one: `Unknown` answers false, so an unclassifiable failure never
/// licenses an experiment.
///
/// Nothing calls this yet, and that is deliberate. No camera in this project's
/// record produces either addressable signature, so the reduction itself is not
/// built; the gate exists written down and tested so that whoever builds it
/// cannot skip it.
#[must_use]
pub fn reduction_may_help(cause: ContentionCause) -> bool {
    match cause {
        ContentionCause::HostBudget | ContentionCause::DeviceRequestExceedsAltsettings => true,
        ContentionCause::Busy | ContentionCause::Unknown => false,
    }
}

/// Guard against dividing by a sequential arm that captured nothing: with no
/// baseline there is no measured loss, so report full retention.
fn retained(concurrent: f32, sequential: f32) -> f32 {
    if sequential <= f32::EPSILON {
        return 1.0;
    }
    concurrent / sequential
}

/// Run the contention probe on a camera pair: `rounds` sequential captures, then
/// `rounds` concurrent ones, reporting mean frame brightness and wall time for
/// each. Fires the IR emitter repeatedly and takes a few seconds per round, so
/// it is a setup-time action, not something an authentication does.
///
/// Failed captures are skipped rather than aborting the probe: a camera that
/// errors under load is exactly what we are trying to characterize, and the
/// round counts in the report say how much evidence each arm really has.
#[expect(clippy::missing_errors_doc, reason = "doc backlog")]
pub fn measure_contention(
    rgb_dev: &str,
    ir_dev: &str,
    rounds: usize,
) -> irlume_common::Result<ContentionReport> {
    measure_contention_with_progress(rgb_dev, ir_dev, rounds, &no_progress())
}

/// [`measure_contention`], reporting between captures.
///
/// The daemon's watchdog (#141) decides a capture has wedged when the worker
/// stops reporting progress. Engine work reports through its stop-signal
/// callback; this loop does not use the Engine at all, so a long tune was
/// indistinguishable from a hang: `camera-tune --rounds 30` runs many sequential
/// and concurrent captures and can exceed the no-progress deadline, at which
/// point systemd would kill a daemon that is working perfectly. Reporting at the
/// same granularity the Engine does, between whole captures, keeps the wedge
/// detection honest while removing the false kill. The same reporter is handed
/// into every capture and session open, so the per-window warm-up heartbeat
/// (#336) covers the probe's captures too.
#[expect(clippy::missing_errors_doc, reason = "doc backlog")]
pub fn measure_contention_with_progress(
    rgb_dev: &str,
    ir_dev: &str,
    rounds: usize,
    progress: &Progress,
) -> irlume_common::Result<ContentionReport> {
    verify_pinned(rgb_dev)?;
    verify_pinned(ir_dev)?;
    measure_contention_impl(
        || capture_rgb_denoised_with_progress(rgb_dev, progress),
        || capture_ir_with_stats_and_progress(ir_dev, progress),
        held_concurrent_arm(rgb_dev, ir_dev),
        rounds,
        progress,
    )
}

/// The concurrent arm over HELD sessions: the shape a `concurrent` verdict
/// licenses `capture_scans` to run (#308) — both cameras open, both streams
/// held for the whole loop, and each round dequeuing IR on a scoped worker
/// WHILE RGB captures on this thread, which is the assess path's actual
/// concurrent schedule (Codex round: the first cut serialized the reads on
/// one thread, a schedule the consumer never runs, the same class of
/// mismatch this fix exists to end). The old arm re-opened each device per
/// round, an order the Brio tolerates while its held shape starves RGB
/// completely.
///
/// Failing to OPEN or ARM the held pair is itself the measurement (the
/// camera cannot enter the shape at all): every round is recorded as failed
/// and the composer's trailing one-at-a-time control decides whether the
/// camera was still answering, same as an all-error arm.
fn held_concurrent_arm<'d>(
    rgb_dev: &'d str,
    ir_dev: &'d str,
) -> impl FnOnce(usize, &Progress, &mut PairSample) -> irlume_common::Result<()> + 'd {
    move |rounds, progress, into| {
        let operation = lease::acquire_camera_operation(
            &[rgb_dev, ir_dev],
            lease::CameraOperationKind::Diagnostics,
            std::time::Duration::from_secs(2),
        );
        let held = operation.and_then(|operation| {
            operation
                .open_rgb(rgb_dev)
                .map_err(|error| lease::CameraLeaseError::InvalidEndpoint(error.to_string()))
                .and_then(|rgb| {
                    operation
                        .open_ir(ir_dev)
                        .map(|ir| (operation, rgb, ir))
                        .map_err(|error| {
                            lease::CameraLeaseError::InvalidEndpoint(error.to_string())
                        })
                })
        });
        let (_operation, rgb_cam, ir_cam) = match held {
            Ok(pair) => pair,
            Err(e) => {
                irlume_common::dlog!(
                    "capture-mode probe: cannot OPEN the held camera pair ({e}); \
                     recording every concurrent round as failed"
                );
                into.failed += rounds;
                return Ok(());
            }
        };
        let sessions = rgb_cam
            .session_with_progress(progress)
            .and_then(|rs| ir_cam.session_with_progress(progress).map(|is| (rs, is)));
        let (mut rs, mut is) = match sessions {
            Ok(pair) => pair,
            Err(e) => {
                irlume_common::dlog!(
                    "capture-mode probe: cannot ARM the held session pair ({e}); \
                     recording every concurrent round as failed"
                );
                into.failed += rounds;
                return Ok(());
            }
        };
        for _ in 0..rounds {
            progress();
            let t0 = std::time::Instant::now();
            let (rgb, ir) = std::thread::scope(|scope| {
                let ir_thread = scope.spawn(|| is.capture_with_stats());
                let rgb = rs.burst(RGB_BURST).map(median_frame);
                let ir = match ir_thread.join() {
                    Ok(result) => result,
                    // Re-raise into the composer's catch_unwind: a panic is a
                    // software defect, never a stored hardware verdict (#263).
                    Err(payload) => std::panic::resume_unwind(payload),
                };
                (rgb, ir)
            });
            accumulate(into, &rgb, &ir, t0.elapsed());
        }
        Ok(())
    }
}

/// [`measure_contention_with_progress`] over injected captures and an
/// injected concurrent-arm runner, so the decisions below are testable
/// without a camera (a panicking capture, an arm that always errors, a
/// trailing control that fails).
fn measure_contention_impl<R, I, H>(
    rgb_cap: R,
    ir_cap: I,
    concurrent_arm: H,
    rounds: usize,
    progress: &Progress,
) -> irlume_common::Result<ContentionReport>
where
    R: Fn() -> irlume_common::Result<Frame>,
    I: Fn() -> irlume_common::Result<(Frame, IrCaptureStats)>,
    H: FnOnce(usize, &Progress, &mut PairSample) -> irlume_common::Result<()>,
{
    let rounds = rounds.max(1);
    let mut report = ContentionReport::default();

    for _ in 0..rounds {
        progress();
        let t0 = std::time::Instant::now();
        let rgb = rgb_cap();
        let ir = ir_cap();
        accumulate(&mut report.sequential, &rgb, &ir, t0.elapsed());
    }
    // A capture that returns Err is a measured failed round. A capture that
    // PANICS is not a measurement of anything: counting it as a failed round
    // would let a software defect masquerade as "this camera cannot stream
    // both nodes" and be persisted as durable policy, so a panic aborts the
    // whole probe instead (#263 review).
    std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        concurrent_arm(rounds, progress, &mut report.concurrent)
    }))
    .map_err(|_| {
        Error::Hardware(
            "capture-mode probe: the concurrent capture arm panicked; this is \
             a software defect, not a camera measurement"
                .into(),
        )
    })??;
    // Only a dead SEQUENTIAL arm is a failed probe: one capture at a time is
    // the mode every camera must manage, so nothing was learned.
    if report.sequential.rounds == 0 {
        return Err(Error::Hardware(format!(
            "capture-mode probe: no sequential round completed on this camera \
             pair ({} of {rounds} attempts errored); even one-at-a-time capture \
             is failing, so nothing was measured",
            report.sequential.failed
        )));
    }
    // A concurrent arm that never completes a round IS a measurement, and the
    // strongest one this probe can make — the camera cannot stream both nodes
    // at once (#192; the BRIO fails every concurrent round with EINVAL on the
    // RGB open while its IR sibling streams) — but only if the camera is
    // still ANSWERING. The baseline ran before the concurrent phase, so on
    // its own it cannot rule out a camera that was unplugged, reset, or
    // stopped answering mid-probe; a trailing one-at-a-time control closes
    // that window (#263 review). One extra capture pair, only in the
    // all-error case.
    if report.concurrent.rounds == 0 {
        progress();
        if let Err(e) = rgb_cap() {
            return Err(Error::Hardware(format!(
                "capture-mode probe: all {rounds} concurrent attempts errored, \
                 and the trailing sequential RGB control then failed too ({e}); \
                 the camera stopped answering, so nothing about concurrency was \
                 measured"
            )));
        }
        if let Err(e) = ir_cap() {
            return Err(Error::Hardware(format!(
                "capture-mode probe: all {rounds} concurrent attempts errored, \
                 and the trailing sequential IR control then failed too ({e}); \
                 the camera stopped answering, so nothing about concurrency was \
                 measured"
            )));
        }
    }
    Ok(report)
}

/// Fold one probe round into a running mean.
///
/// The IR figure is the burst's `lit_mean`, NOT the returned frame's own mean.
/// They differ, and the difference was measured: the returned frame is one
/// phase of a strobe burst, so which phase of the emitter's pulse happened to
/// land in it swings the frame mean hard. Retention on one unchanged camera read
/// 94%, 137% and 83% across runs against an 80% floor, i.e. noise big enough to
/// decide the verdict. `lit_mean` is the mean of the frame capture gated on,
/// which is stable from round to round because it is drawn from the lit phase
/// rather than whichever phase the caller happened to receive. Since #221 that
/// frame is the brightest lit one under the clipping limit rather than the
/// brightest outright, so a burst that straddles the limit can shift it by a
/// frame; both are lit-phase means, which is the property this relies on.
fn accumulate(
    into: &mut PairSample,
    rgb: &irlume_common::Result<Frame>,
    ir: &irlume_common::Result<(Frame, IrCaptureStats)>,
    elapsed: std::time::Duration,
) {
    let (Ok(rgb), Ok((_, ir_stats))) = (rgb, ir) else {
        into.failed += 1;
        return;
    };
    let n = into.rounds as f32;
    let mix = |old: f32, new: f32| (old * n + new) / (n + 1.0);
    into.rgb_mean = mix(into.rgb_mean, frame_mean(&rgb.data));
    into.ir_mean = mix(into.ir_mean, ir_stats.lit_mean);
    into.total_ms = mix(into.total_ms, elapsed.as_millis() as f32);
    into.rounds += 1;
}

/// Mean of every byte in a frame.
///
/// Public because the enrolment failure probe in `irlume-auth` compares against
/// [`CONCLUSIVE_SCENE_BRIGHTNESS`] and [`CONCURRENT_SIGNAL_FLOOR`], and those
/// constants were measured against THIS statistic. A private reimplementation
/// there would be comparing one brightness definition to thresholds fitted to
/// another.
pub fn frame_mean(data: &[u8]) -> f32 {
    if data.is_empty() {
        return 0.0;
    }
    data.iter().map(|&b| b as u64).sum::<u64>() as f32 / data.len() as f32
}

/// The pre-pair `cameras.conf` key: the RGB camera's identity alone. Read-only
/// since #340's review round; see [`stored_capture_mode`] for the one migration
/// case that may still consult it.
fn capture_mode_key(identity: &str) -> String {
    format!("capture_mode.{identity}")
}

/// `cameras.conf` key holding the capture mode for one measured RGB+IR
/// pairing. Keyed by BOTH identities, not by device node and not by the RGB
/// module alone: `/dev/videoN` numbering moves across reboots and replugs, and
/// contention is a property of the pairing. The measured proof: the same
/// NexiGo RGB node that keeps 42-56% of its brightness against its own IR
/// sibling retains 0.99 against a different camera's IR (see
/// [`CONCURRENT_SIGNAL_FLOOR`]), so a verdict must not survive an IR swap.
fn capture_mode_pair_key(rgb_identity: &str, ir_identity: &str) -> String {
    format!("capture_mode.{rgb_identity}+{ir_identity}")
}

/// `cameras.conf` key recording HOW this pairing's capture mode came to be
/// stored. A SIDECAR, deliberately not part of the mode's value: an older
/// irlume reading `capture_mode.<ids>` must keep seeing exactly `sequential`
/// or `concurrent`, and [`CaptureMode::parse`] must stay a two-word grammar.
/// The repo already un-shipped one widened config value for this reason.
fn capture_mode_origin_key(rgb_identity: &str, ir_identity: &str) -> String {
    format!("capture_mode_origin.{rgb_identity}+{ir_identity}")
}

/// The `cameras.conf` key this pairing's capture mode is stored under, if both
/// nodes can be identified.
///
/// Exposed so a caller accumulating evidence about a pairing over time can key
/// that evidence by the same string the verdict is written under. Keying by
/// device path instead would let evidence gathered on one camera be spent on
/// whichever camera later occupied `/dev/video0`.
pub fn capture_mode_pair_identity(rgb_dev: &str, ir_dev: &str) -> Option<String> {
    let rgb_id = device_identity(rgb_dev)?;
    let ir_id = device_identity(ir_dev)?;
    Some(capture_mode_pair_key(&rgb_id, &ir_id))
}

/// How a stored capture mode came to be there, when irlume recorded it.
///
/// Only the automatic switch stamps this today; a verdict from `camera-tune`
/// carries no origin, which reads as "measured" by absence. That asymmetry is
/// deliberate for now: stamping the probe's writes too would change a command
/// this change does not otherwise touch.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CaptureModeOrigin {
    /// irlume switched this pairing to sequential itself, after repeated
    /// concurrent-capture RGB losses during real enrolment attempts (#100).
    /// `at_unix` is when, or `None` when the stamp carried no readable time.
    AutoSwitched { at_unix: Option<u64> },
}

/// Parse the origin sidecar's value. Pure, so the grammar is testable.
///
/// Anything unrecognized degrades to `None`, meaning "origin not recorded".
/// It can never change what mode is in force: the mode lives in its own key,
/// and this one is read only to describe it.
fn parse_capture_mode_origin(raw: &str) -> Option<CaptureModeOrigin> {
    let mut parts = raw.split_whitespace();
    if parts.next()? != "auto-switch" {
        return None;
    }
    Some(CaptureModeOrigin::AutoSwitched {
        at_unix: parts.next().and_then(|t| t.parse().ok()),
    })
}

/// The recorded origin of this pairing's stored capture mode, if any.
pub fn stored_capture_mode_origin(rgb_dev: &str, ir_dev: &str) -> Option<CaptureModeOrigin> {
    let rgb_id = device_identity(rgb_dev)?;
    let ir_id = device_identity(ir_dev)?;
    let raw =
        irlume_common::config::read_kv("cameras.conf", &capture_mode_origin_key(&rgb_id, &ir_id))?;
    parse_capture_mode_origin(&raw)
}

/// The stored capture mode for the RGB+IR pairing behind these two devices, if
/// that pairing was measured. `None` means unmeasured (the caller keeps its
/// default), an unidentifiable node, or an unreadable config; an unrecognized
/// stored value is also `None` rather than a guess.
pub fn stored_capture_mode(rgb_dev: &str, ir_dev: &str) -> Option<CaptureMode> {
    let rgb_id = device_identity(rgb_dev)?;
    let ir_id = device_identity(ir_dev)?;
    // Two Somes and equal, never None==None: a node whose sysfs identity
    // cannot be resolved must fail toward "unmeasured", not toward "same
    // module".
    let same_module = matches!(
        (physical_device_id(rgb_dev), physical_device_id(ir_dev)),
        (Some(a), Some(b)) if a == b
    );
    resolve_stored_pair_mode(
        irlume_common::config::read_kv("cameras.conf", &capture_mode_pair_key(&rgb_id, &ir_id)),
        same_module,
        || irlume_common::config::read_kv("cameras.conf", &capture_mode_key(&rgb_id)),
    )
}

/// The pair-key resolution, pure over its observations so the migration rule
/// is testable without sysfs: the pair entry decides when present; a legacy
/// RGB-only entry (written before verdicts were keyed by pair) is honored
/// ONLY when both nodes still belong to one physical USB device, the shape
/// every legacy verdict was measured on. Any other pairing counts as
/// unmeasured; a legacy entry must never vouch for an IR camera it was not
/// measured against.
fn resolve_stored_pair_mode(
    pair_entry: Option<String>,
    same_physical_device: bool,
    legacy_entry: impl FnOnce() -> Option<String>,
) -> Option<CaptureMode> {
    if let Some(raw) = pair_entry {
        return CaptureMode::parse(&raw);
    }
    if same_physical_device {
        return CaptureMode::parse(&legacy_entry()?);
    }
    None
}

/// Persist the capture mode for the RGB+IR pairing behind these two devices.
/// Writes `/etc/irlume/cameras.conf`, so it needs root. Overwrites; the
/// check-before-write callers use [`store_capture_mode_if_absent`].
///
/// Also clears any auto-switch origin stamp so a direct measurement supersedes
/// an inference. The stamp is cleared AFTER the mode is written: a crash between
/// the two renames then leaves a measured verdict still wearing an inference
/// stamp, which understates what irlume knows; the other order would leave the
/// previous verdict claiming to be a measurement, which overstates it. Same rule
/// the auto-switch writer follows in the opposite direction.
#[expect(clippy::missing_errors_doc, reason = "doc backlog")]
pub fn store_capture_mode(
    rgb_dev: &str,
    ir_dev: &str,
    mode: CaptureMode,
) -> irlume_common::Result<()> {
    let rgb_id = device_identity(rgb_dev)
        .ok_or_else(|| Error::Hardware(format!("{rgb_dev}: cannot identify the RGB camera")))?;
    let ir_id = device_identity(ir_dev)
        .ok_or_else(|| Error::Hardware(format!("{ir_dev}: cannot identify the IR camera")))?;
    irlume_common::config::write_kv(
        "cameras.conf",
        &capture_mode_pair_key(&rgb_id, &ir_id),
        mode.as_str(),
    )
    .map_err(|e| Error::Io(e.to_string()))?;
    // An empty value is the clear: `read_kv` treats an empty value as absent,
    // which is what `stored_capture_mode_origin` reads through.
    irlume_common::config::write_kv(
        "cameras.conf",
        &capture_mode_origin_key(&rgb_id, &ir_id),
        "",
    )
    .map_err(|e| Error::Io(e.to_string()))
}

/// What [`store_capture_mode_if_absent`] found when it looked.
#[derive(Debug, PartialEq, Eq)]
pub enum StoreIfAbsent {
    /// No verdict existed; `mode` was written.
    Stored,
    /// A verdict already existed and was kept untouched.
    AlreadyPresent(CaptureMode),
}

/// Persist `mode` only if the pairing still has no verdict, under the
/// cameras.conf writer lock.
///
/// Exists for the enrollment probe (#340 review): its emptiness check and its
/// write are separated by a probe of up to a minute, and the daemon's single
/// worker only serializes daemon requests, not an administrator or a
/// configuration manager editing the file in that window. Checking again
/// under the lock means an automatic probe can only ever FILL an empty
/// verdict; a verdict that appeared mid-probe wins and is returned.
#[expect(clippy::missing_errors_doc, reason = "doc backlog")]
pub fn store_capture_mode_if_absent(
    rgb_dev: &str,
    ir_dev: &str,
    mode: CaptureMode,
) -> irlume_common::Result<StoreIfAbsent> {
    let _guard = irlume_common::config::lock_exclusive("cameras.conf")
        .map_err(|e| Error::Io(e.to_string()))?;
    if let Some(existing) = stored_capture_mode(rgb_dev, ir_dev) {
        return Ok(StoreIfAbsent::AlreadyPresent(existing));
    }
    store_capture_mode(rgb_dev, ir_dev, mode)?;
    Ok(StoreIfAbsent::Stored)
}

/// What [`store_sequential_if_still_concurrent`] found when it looked.
#[derive(Debug, PartialEq, Eq)]
pub enum StoreIfConcurrent {
    /// The pairing still read `concurrent`; sequential and its origin were written.
    Stored,
    /// Something else had already changed the verdict; nothing was written.
    /// Carries what is stored now (`None` = no verdict at all).
    Superseded(Option<CaptureMode>),
}

/// Demote this pairing to sequential, but ONLY if it still reads `concurrent`.
///
/// The one writer in this crate that overwrites a MEASURED verdict, which is
/// why it re-reads under the lock instead of trusting what its caller last saw.
/// [`store_capture_mode_if_absent`] cannot express this: an absent verdict
/// already means sequential, so filling an empty key would be a no-op for the
/// caller this exists for. The evidence behind such a call is gathered across
/// several enrolment attempts, so its read and its write are separated by the
/// length of the loop — the widest check-then-write window in the codebase, and
/// exactly what `config::lock_exclusive` documents itself for. An operator who
/// ran `camera-tune` in that window measured this camera directly, and a
/// measurement outranks an inference: that is what `Superseded` reports.
///
/// The origin stamp is written FIRST and the mode SECOND, because these are two
/// renames under one lock and a crash can land between them. In that order the
/// only reachable wreckage is an origin key with no matching sequential verdict,
/// which readers ignore; the other order could leave a switched verdict that
/// nothing marks as automatic, and it would then be reported as measured.
#[expect(clippy::missing_errors_doc, reason = "doc backlog")]
pub fn store_sequential_if_still_concurrent(
    rgb_dev: &str,
    ir_dev: &str,
    origin_unix: u64,
) -> irlume_common::Result<StoreIfConcurrent> {
    let _guard = irlume_common::config::lock_exclusive("cameras.conf")
        .map_err(|e| Error::Io(e.to_string()))?;
    match stored_capture_mode(rgb_dev, ir_dev) {
        Some(CaptureMode::Concurrent) => {}
        other => return Ok(StoreIfConcurrent::Superseded(other)),
    }
    let rgb_id = device_identity(rgb_dev)
        .ok_or_else(|| Error::Hardware(format!("{rgb_dev}: cannot identify the RGB camera")))?;
    let ir_id = device_identity(ir_dev)
        .ok_or_else(|| Error::Hardware(format!("{ir_dev}: cannot identify the IR camera")))?;
    irlume_common::config::write_kv(
        "cameras.conf",
        &capture_mode_origin_key(&rgb_id, &ir_id),
        &format!("auto-switch {origin_unix}"),
    )
    .map_err(|e| Error::Io(e.to_string()))?;
    irlume_common::config::write_kv(
        "cameras.conf",
        &capture_mode_pair_key(&rgb_id, &ir_id),
        CaptureMode::Sequential.as_str(),
    )
    .map_err(|e| Error::Io(e.to_string()))?;
    Ok(StoreIfConcurrent::Stored)
}

/// Configure the IR emitter for `device` from what the camera documents about
/// itself.
///
/// Reads the USB descriptor, addresses only Microsoft's camera-control extension
/// unit, writes only a value built from the camera's own answers, verifies the
/// change follows the control before keeping it, and stops at the
/// first failed request, and once measuring begins, the first frame that does
/// not arrive. Persists what worked so later
/// captures apply it. Errors if the camera documents no control irlume can use;
/// it does not fall back to guessing (#159).
///
/// A control is only written when its current value could be read back first, so
/// anything changed can be undone.
#[expect(clippy::missing_errors_doc, reason = "doc backlog")]
pub fn setup_ir_emitter(device: &str) -> irlume_common::Result<String> {
    verify_pinned(device)?;
    let permit = lease::permit_for_endpoint(
        device,
        lease::CameraOperationKind::Setup,
        std::time::Duration::from_secs(2),
    )
    .map_err(|error| Error::Hardware(error.to_string()))?;
    // Open only long enough to read the standard V4L2 privacy control, and
    // refuse before format negotiation, streaming, or any extension-unit
    // write. An engaged shutter blanks the sensor to a flat frame (ASUS
    // 3277:0059, eight frames per state: released mean 37.0 stddev 62.68,
    // engaged a constant 144.0 stddev 0.00 with `privacy` reading 1
    // throughout), so every exploratory write would be spent measuring a
    // constant, and discovery would then report "no usable emitter control"
    // about a camera whose shutter is merely shut (#186). Every capture entry
    // point already refuses an engaged shutter; the one path that WRITES
    // firmware refuses an UNREADABLE one too, and re-checks before each
    // exploratory write below, because this early sample covers only this
    // moment. An undo record pending on this camera loses nothing: it is
    // durable, `doctor` reports it, and recovery re-runs on the next capture
    // or setup once the shutter is released — the same stance as
    // `IRLUME_IR_EMITTER=off`.
    let dev = Device::with_path(device).map_err(|e| map_io(device, e))?;
    privacy_permits_setup(privacy_state(&dev))
        .map_err(|why| Error::Hardware(format!("{device}: {why}")))?;
    // Declared before the stream and the guards below, so it is dropped LAST:
    // the guard that puts the control back lives inside `discover` (or inside
    // `found` on the success path) and has to finish before this re-raises the
    // signal that stops the process.
    let _abort_orderly = ir_emitter::AbortOnSignal::install();
    let (fmt, pix) = negotiate_ir_format(device, &dev)?;
    let mut dec = IrDecoder::new(pix, fmt.quantization);
    let (w, h) = (fmt.width, fmt.height);
    let mut stream = SafeStream::open(device, &dev, &fmt, permit.clone())?;
    let fd = dev.handle().fd();
    for _ in 0..4 {
        let _ = stream.next(); // let the sensor settle before baseline
    }
    // Mean IR brightness over a short burst (catches a strobed emitter's lit
    // phase). Measured on the DECODED 8-bit frame so the brightness scale is
    // comparable across native-grey and 16-bit/luma-extracted nodes.
    // None means the camera stopped delivering frames.
    //
    // The first failed dequeue ends the measurement. Swallowing failures and
    // carrying on multiplies the per-frame timeout by the number of frames: at
    // eighteen dequeues and five seconds each that is ninety seconds, which is
    // exactly the daemon's watchdog deadline, so a stall during setup could get
    // the daemon killed before the control it changed was restored. A fix for a
    // hang is not worth a race with systemd.
    let mut measure = || -> Option<f32> {
        // A stop signal aborts through the same path a dead stream does, which
        // is the path that puts the control back.
        //
        // Polled between frames rather than relied on to interrupt one. A
        // process-directed signal goes to an ARBITRARY thread that has it
        // unblocked, and the daemon has a watchdog, a listener and a connection
        // thread besides this worker; only the syscall in the thread the kernel
        // picks is interrupted, so dropping SA_RESTART does not guarantee this
        // frame wait ever returns EINTR (signal(7)). Checking each iteration
        // bounds the abort by one frame timeout, which this crate sets to five
        // seconds, instead of by a whole measurement.
        if ir_emitter::abort_requested() {
            return None;
        }
        // Frames already in flight were captured before the control changed, and
        // taking the brightest of the burst makes one stale frame decide the
        // answer. Discard a stream's worth before believing anything.
        for _ in 0..IR_BURST {
            if ir_emitter::abort_requested() {
                return None;
            }
            stream.next().ok()?;
        }
        let mut best: Option<f32> = None;
        for _ in 0..8 {
            if ir_emitter::abort_requested() {
                return None;
            }
            let (buf, _) = stream.next().ok()?;
            let data = dec.decode(buf, w, h);
            let m = data.iter().map(|&p| p as f64).sum::<f64>() / data.len().max(1) as f64;
            best = Some(best.map_or(m as f32, |b: f32| b.max(m as f32)));
        }
        best
    };

    let id = crate::uvc_descriptor::identity_from_fd(fd)
        .map_err(|e| Error::Hardware(format!("could not identify the camera: {e}")))?;
    // Re-read the shutter immediately before each forward write. The early
    // sample above is one moment; format negotiation, the settling frames, the
    // journal fsyncs and the baseline burst all sit between it and the first
    // SET_CUR, and the operator can engage the E-shutter anywhere in that
    // window (#193 review). The residual race is one syscall wide: V4L2 offers
    // no transaction spanning the privacy read and the extension-unit write.
    let mut privacy_allows_write = || {
        permit
            .require_endpoint(device)
            .map_err(|error| error.to_string())?;
        privacy_permits_setup(privacy_state(&dev))
    };
    permit.run_active(|| {
        match ir_emitter::discover(fd, &id, &mut measure, &mut privacy_allows_write) {
            Ok(found) => {
                let encoded = found.control().encode();
                // Confirm, publish, release, in that order. The sequence lives in
                // `finish` rather than here so it is reachable by a test.
                found.finish(&id).map_err(Error::Hardware)?;
                Ok(format!(
                    "IR emitter enabled: {encoded} on the camera's Microsoft camera-control unit, \
                 using a value built from what the camera reports about that control \
                 (saved; future captures rebuild it the same way)"
                ))
            }
            Err(e) => Err(Error::Hardware(e.to_string())),
        }
    })
}

/// What the IR camera's extension units are, for `ir-setup --dry-run`.
///
/// Read entirely from the USB descriptors, so it sends the camera nothing at
/// all. The previous version issued `GET_LEN` to all 512 unit and selector
/// combinations, which is traffic to controls the camera never claimed to have.
#[expect(clippy::missing_errors_doc, reason = "doc backlog")]
pub fn list_ir_controls(device: &str) -> irlume_common::Result<Vec<String>> {
    verify_pinned(device)?;
    ir_emitter::describe_units(device).map_err(|e| map_io(device, e))
}

/// Apply the KNOWN emitter control (env override, persisted conf, or the
/// built-in table) and report whether IR came up lit.
///
/// This never searches for an unknown control, and nothing that runs without the
/// user asking for it may ever do so. Blind extension-unit writes destroyed a
/// reporter's camera in #159: guessed `SET_CUR` payloads on an undocumented
/// vendor unit of a Lenovo ThinkPad camera left it unable to enumerate on the bus,
/// and neither a power cycle nor the laptop's reset hole brought it back.
///
/// Discovery is now an explicit, acknowledged operation (`irlume ir-setup`), not
/// a side effect of starting the daemon or enrolling a face. A dark IR frame
/// means the room is dark, or nobody is in front of the camera, or the emitter
/// needs a control this machine does not know. None of those justify writing
/// guessed values to camera firmware.
#[expect(clippy::missing_errors_doc, reason = "doc backlog")]
pub fn apply_known_ir_emitter(device: &str) -> irlume_common::Result<bool> {
    let mean_of =
        |f: &Frame| f.data.iter().map(|&p| p as f64).sum::<f64>() / f.data.len().max(1) as f64;
    // capture_ir applies the known control on open; see `ir_emitter::enable`.
    Ok(mean_of(&capture_ir(device)?) >= ir_emitter::IR_LIT_MEAN as f64)
}

/// Replicate an 8-bit greyscale buffer into interleaved RGB8 (for feeding the
/// RGB-trained detector on an IR frame).
pub fn grey_to_rgb(grey: &[u8]) -> Vec<u8> {
    let mut rgb = vec![0u8; grey.len() * 3];
    for (i, &g) in grey.iter().enumerate() {
        rgb[i * 3] = g;
        rgb[i * 3 + 1] = g;
        rgb[i * 3 + 2] = g;
    }
    rgb
}

/// Convert a YUYV (YUY2, 4:2:2) buffer to interleaved RGB8 (BT.601).
pub fn yuyv_to_rgb(yuyv: &[u8], width: u32, height: u32) -> Vec<u8> {
    let (w, h) = (width as usize, height as usize);
    let mut rgb = vec![0u8; w * h * 3];
    // Each 4 bytes (Y0 U Y1 V) encode two pixels.
    let pairs = (w * h) / 2;
    for p in 0..pairs.min(yuyv.len() / 4) {
        let i = p * 4;
        let y0 = yuyv[i] as f32;
        let u = yuyv[i + 1] as f32 - 128.0;
        let y1 = yuyv[i + 2] as f32;
        let v = yuyv[i + 3] as f32 - 128.0;
        for (k, y) in [y0, y1].into_iter().enumerate() {
            let r = y + 1.402 * v;
            let g = y - 0.344 * u - 0.714 * v;
            let b = y + 1.772 * u;
            let o = (p * 2 + k) * 3;
            rgb[o] = r.clamp(0.0, 255.0) as u8;
            rgb[o + 1] = g.clamp(0.0, 255.0) as u8;
            rgb[o + 2] = b.clamp(0.0, 255.0) as u8;
        }
    }
    rgb
}

/// Convert an NV12 (4:2:0, Y plane then interleaved UV plane) buffer to
/// interleaved RGB8 (BT.601). Each 2x2 pixel block shares one U/V pair.
pub fn nv12_to_rgb(nv12: &[u8], width: u32, height: u32) -> Vec<u8> {
    let (w, h) = (width as usize, height as usize);
    let mut rgb = vec![0u8; w * h * 3];
    let y_plane = w * h;
    // Guard against a short buffer: need the full Y plane plus a UV plane.
    if nv12.len() < y_plane + (w * h / 2) {
        return rgb;
    }
    for row in 0..h {
        for col in 0..w {
            let y = nv12[row * w + col] as f32;
            // UV plane is half-resolution in both axes; one pair per 2x2 block.
            let uv = y_plane + (row / 2) * w + (col / 2) * 2;
            let u = nv12[uv] as f32 - 128.0;
            let v = nv12[uv + 1] as f32 - 128.0;
            let o = (row * w + col) * 3;
            rgb[o] = (y + 1.402 * v).clamp(0.0, 255.0) as u8;
            rgb[o + 1] = (y - 0.344 * u - 0.714 * v).clamp(0.0, 255.0) as u8;
            rgb[o + 2] = (y + 1.772 * u).clamp(0.0, 255.0) as u8;
        }
    }
    rgb
}

/// Pull and discard one frame with a short retry, so the FIRST capture after a
/// suspend/resume (or USB re-enumeration) does not fail outright while the
/// uvcvideo device is still coming back. The daemon opens the device per
/// request, so there is no stale handle to recover; the only gap is that the
/// very first `stream.next()` can return EIO/ENODEV for a few hundred ms after
/// resume. Retry that, then let the normal AE warmup run.
///
/// Every retryable kind, `TimedOut` included, keeps the FULL retry budget: a
/// camera silent for two 5s windows that delivers on its third warmed up
/// before #336 and still does (an earlier cut of that fix capped the silent
/// tries at two and was rejected in review for exactly that regression). What
/// #336 changed instead is reporting: `progress` is invoked after EACH
/// COMPLETED `TimedOut` return, so a frameless camera spending its whole
/// budget here reports a heartbeat every window and the daemon's watchdog
/// (#141) only starves when a driver call genuinely never returns.
fn warm_up_stream(
    device: &str,
    stream: &mut SafeStream<'_>,
    progress: &Progress,
) -> irlume_common::Result<()> {
    warm_up_with(
        device,
        || stream.next().map(|_| ()),
        std::thread::sleep,
        progress,
    )
}

/// [`warm_up_stream`] over an injected dequeue and sleep, so the retry budget
/// and the per-window progress reporting are testable without a camera: the
/// silent-recovery and reporting contracts each have a unit test whose failure
/// names the regression (Codex review of PR #338).
fn warm_up_with<N, S>(
    device: &str,
    mut next: N,
    mut sleep: S,
    progress: &Progress,
) -> irlume_common::Result<()>
where
    N: FnMut() -> std::io::Result<()>,
    S: FnMut(std::time::Duration),
{
    use std::io::ErrorKind;
    for attempt in 0..WARMUP_TRIES {
        match next() {
            Ok(()) => return Ok(()),
            Err(e) => {
                // The window COMPLETED: the driver call came back, the thread
                // was never stuck, and the watchdog clock resets before the
                // caller spends unbounded time (inference, a retry's reopen)
                // on the way to the next window. Reported on the terminal try
                // too, for the same reason.
                if e.kind() == ErrorKind::TimedOut {
                    progress();
                }
                if attempt + 1 < WARMUP_TRIES
                    && matches!(
                        e.kind(),
                        ErrorKind::BrokenPipe
                            | ErrorKind::NotConnected
                            | ErrorKind::Other
                            | ErrorKind::TimedOut
                    )
                {
                    sleep(WARMUP_GAP);
                } else {
                    return Err(map_io(device, e));
                }
            }
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    struct SabotagingDequeue {
        payload: [u8; 4],
        stale: std::rc::Rc<std::cell::Cell<bool>>,
    }

    impl CaptureDequeue for SabotagingDequeue {
        fn dequeue(&mut self) -> std::io::Result<(&[u8], v4l::buffer::Metadata)> {
            self.stale.set(true);
            Ok((
                &self.payload,
                v4l::buffer::Metadata {
                    bytesused: 4,
                    ..v4l::buffer::Metadata::default()
                },
            ))
        }
    }

    #[test]
    fn dequeue_refuses_lifecycle_sabotage_after_the_blocking_call() {
        let stale = std::rc::Rc::new(std::cell::Cell::new(false));
        let mut stream = SabotagingDequeue {
            payload: [1, 2, 3, 4],
            stale: stale.clone(),
        };
        let layout =
            frame_provenance::PayloadLayout::new(*b"GREY", 2, 2, 2).expect("tight GREY layout");

        let error = dequeue_validated(&mut stream, layout, || {
            if stale.get() {
                Err(std::io::Error::other("stale camera generation"))
            } else {
                Ok(())
            }
        })
        .expect_err("post-dequeue lifecycle sabotage must fail closed");

        assert_eq!(error.kind(), std::io::ErrorKind::Other);
        assert_eq!(error.to_string(), "stale camera generation");
    }

    #[test]
    fn dequeue_returns_only_driver_initialized_payload() {
        struct FixedDequeue {
            payload: [u8; 5],
        }

        impl CaptureDequeue for FixedDequeue {
            fn dequeue(&mut self) -> std::io::Result<(&[u8], v4l::buffer::Metadata)> {
                Ok((
                    &self.payload,
                    v4l::buffer::Metadata {
                        bytesused: 4,
                        ..v4l::buffer::Metadata::default()
                    },
                ))
            }
        }

        let mut stream = FixedDequeue {
            payload: [1, 2, 3, 4, 99],
        };
        let layout = frame_provenance::PayloadLayout::new(*b"GREY", 2, 2, 2).expect("tight layout");
        let (payload, facts) =
            dequeue_validated(&mut stream, layout, || Ok(())).expect("valid dequeue");

        assert_eq!(payload, &[1, 2, 3, 4]);
        assert_eq!(facts.bytes_used(), 4);
    }

    #[test]
    fn recovery_failure_stops_streams_before_restoring_emitter() {
        #[derive(Debug)]
        struct DropMark {
            name: &'static str,
            drops: std::rc::Rc<std::cell::RefCell<Vec<&'static str>>>,
        }

        impl Drop for DropMark {
            fn drop(&mut self) {
                self.drops.borrow_mut().push(self.name);
            }
        }

        let drops = std::rc::Rc::new(std::cell::RefCell::new(Vec::new()));
        let mark = |name| DropMark {
            name,
            drops: std::rc::Rc::clone(&drops),
        };
        let result = install_recovered_resources(
            mark("image-stream"),
            mark("metadata-stream"),
            mark("emitter-restore"),
            |stream| {
                drop(stream);
                Err::<(), _>("install failed")
            },
        );

        assert!(matches!(result, Err("install failed")));
        assert_eq!(
            drops.borrow().as_slice(),
            ["image-stream", "metadata-stream", "emitter-restore"]
        );
    }

    #[test]
    fn recovery_panic_stops_streams_before_restoring_emitter() {
        #[derive(Debug)]
        struct DropMark {
            name: &'static str,
            drops: std::rc::Rc<std::cell::RefCell<Vec<&'static str>>>,
        }

        impl Drop for DropMark {
            fn drop(&mut self) {
                self.drops.borrow_mut().push(self.name);
            }
        }

        let drops = std::rc::Rc::new(std::cell::RefCell::new(Vec::new()));
        let mark = |name| DropMark {
            name,
            drops: std::rc::Rc::clone(&drops),
        };
        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let _ = install_recovered_resources(
                mark("image-stream"),
                mark("metadata-stream"),
                mark("emitter-restore"),
                |stream| -> Result<(), ()> {
                    drop(stream);
                    panic!("injected install panic");
                },
            );
        }));

        assert!(result.is_err());
        assert_eq!(
            drops.borrow().as_slice(),
            ["image-stream", "metadata-stream", "emitter-restore"]
        );
    }

    #[test]
    fn recovery_epoch_survives_untracked_warmup_dequeues() {
        struct SequenceFixture {
            payload: [u8; 1],
            sequences: std::collections::VecDeque<u32>,
        }

        impl ValidatedStream for SequenceFixture {
            fn next_validated(
                &mut self,
            ) -> std::io::Result<(&[u8], frame_provenance::DequeuedBufferFacts)> {
                let sequence = self
                    .sequences
                    .pop_front()
                    .ok_or_else(|| std::io::Error::other("fixture exhausted"))?;
                let metadata = v4l::buffer::Metadata {
                    bytesused: 1,
                    sequence,
                    ..v4l::buffer::Metadata::default()
                };
                let facts = frame_provenance::DequeuedBufferFacts::from_v4l(&metadata, 1)
                    .map_err(std::io::Error::other)?;
                Ok((&self.payload, facts))
            }
        }

        let fixture = |sequences: &[u32]| SequenceFixture {
            payload: [7],
            sequences: sequences.iter().copied().collect(),
        };
        let mut capture = TrackedStream::new(fixture(&[41]));
        let (_, _, baseline) = capture.next().expect("baseline delivery");
        assert!(!baseline.discontinuity());

        capture.take();
        capture
            .install_recovered(fixture(&[500, 7]))
            .expect("representable recovery epoch");
        capture
            .stream_mut()
            .expect("replacement stream")
            .next_validated()
            .expect("discarded warm-up dequeue");

        let (_, _, restarted) = capture.next().expect("first delivered recovery frame");
        assert_eq!(restarted.raw(), 7);
        assert_eq!(restarted.gap(), 0);
        assert!(restarted.discontinuity());
        assert_eq!(restarted.stream_epoch(), 1);
    }

    #[test]
    fn session_slot_is_exclusive_and_reopens_after_drop() {
        let active = std::sync::atomic::AtomicBool::new(false);
        let first = SessionSlot::acquire(&active, "/dev/test-camera").unwrap();
        assert!(SessionSlot::acquire(&active, "/dev/test-camera").is_err());
        drop(first);
        assert!(SessionSlot::acquire(&active, "/dev/test-camera").is_ok());

        let active = std::sync::atomic::AtomicBool::new(false);
        let _ = std::panic::catch_unwind(|| {
            let _slot = SessionSlot::acquire(&active, "/dev/test-camera").unwrap();
            panic!("synthetic session panic");
        });
        assert!(!active.load(std::sync::atomic::Ordering::Acquire));
    }

    #[test]
    fn a_rate_without_the_timeperframe_capability_is_unknown() {
        // V4L2 defines timeperframe as meaningful only under
        // V4L2_CAP_TIMEPERFRAME; without the flag the fraction is residue, and
        // a plausible 1/30 there must not publish as an established rate.
        let mut p = v4l::video::capture::Parameters::with_fps(30);
        p.capabilities = v4l::parameters::Capabilities::from(0);
        assert_eq!(fps_from_params(p), None);
        // With the flag the same fraction is a real 30fps.
        p.capabilities = v4l::parameters::Capabilities::TIME_PER_FRAME;
        assert_eq!(fps_from_params(p), Some(30.0));
        // A zero numerator or denominator is unusable even when capable.
        let mut z = v4l::video::capture::Parameters::new(v4l::Fraction::new(0, 30));
        z.capabilities = v4l::parameters::Capabilities::TIME_PER_FRAME;
        assert_eq!(fps_from_params(z), None);
    }

    #[test]
    fn hello_minimum_verdicts_cover_all_three_outcomes() {
        let spec = |w, h, fps| StreamSpec {
            width: w,
            height: h,
            fourcc: "GREY".into(),
            fps,
        };
        // The measured ASUS module shape: comfortably above the IR floor.
        assert_eq!(spec(640, 400, Some(30.0)).meets(&HELLO_IR_MIN), Some(true));
        // At the floor exactly is meeting it, not below it.
        assert_eq!(spec(340, 340, Some(15.0)).meets(&HELLO_IR_MIN), Some(true));
        // ONE dimension below fails, even with plenty of rate; 640x240 has
        // fewer face pixels than the envelope no matter its width.
        assert_eq!(spec(640, 240, Some(30.0)).meets(&HELLO_IR_MIN), Some(false));
        // A reported rate below the floor fails.
        assert_eq!(spec(640, 400, Some(10.0)).meets(&HELLO_IR_MIN), Some(false));
        // Dimensions meet, rate unreported: cannot say, which must stay
        // distinct from a pass (an unobserved rate is not an adequate one).
        assert_eq!(spec(640, 400, None).meets(&HELLO_IR_MIN), None);
        // Dimensions below with rate ALSO unreported is still a definite
        // below, not an unknown: the dimensions alone decide it.
        assert_eq!(spec(320, 240, None).meets(&HELLO_IR_MIN), Some(false));
        // The RGB floor has a fractional rate; just below it fails.
        assert_eq!(spec(640, 480, Some(7.0)).meets(&HELLO_RGB_MIN), Some(false));
        assert_eq!(spec(640, 480, Some(7.5)).meets(&HELLO_RGB_MIN), Some(true));
    }

    fn unreadable(at: FailedAt, errno: Option<i32>, holder: Option<&str>) -> Unreadable {
        Unreadable {
            path: "/dev/video4".into(),
            at,
            errno,
            holder: holder.map(str::to_string),
        }
    }

    /// The whole point of #227: the three conditions a camera node fails under
    /// must reach the reader as three different sentences, each naming the act
    /// that clears it. A permission problem that reads as absent hardware sends
    /// someone after a driver bug they do not have.
    #[test]
    fn an_unreadable_node_explains_the_cause_it_actually_hit() {
        let denied = unreadable(FailedAt::Open, Some(libc::EACCES), None).explain();
        assert!(denied.contains("/dev/video4"), "{denied}");
        assert!(denied.contains("could not be opened"), "{denied}");
        assert!(denied.contains("'video' group"), "{denied}");

        // A named holder is the difference between "something has your camera"
        // and knowing which app to close.
        let busy =
            unreadable(FailedAt::Open, Some(libc::EBUSY), Some("firefox (pid 42)")).explain();
        assert!(busy.contains("in use by firefox (pid 42)"), "{busy}");
        assert!(!busy.contains("'video' group"), "{busy}");

        // /proc could not name it (another uid, #207): still busy, no invention.
        let anon = unreadable(FailedAt::Open, Some(libc::EBUSY), None).explain();
        assert!(anon.contains("another app is using it"), "{anon}");

        let gone = unreadable(FailedAt::EnumFormats, Some(libc::ENODEV), None).explain();
        assert!(gone.contains("would not list its formats"), "{gone}");
        assert!(gone.contains("device behind it is gone"), "{gone}");

        // An errno with no mapping still reports the number rather than
        // rounding down to silence.
        let odd = unreadable(FailedAt::Open, Some(libc::EIO), None).explain();
        assert!(odd.contains("errno 5"), "{odd}");
        let none = unreadable(FailedAt::Open, None, None).explain();
        assert!(none.contains("no OS error reported"), "{none}");
    }

    /// The old scan probed /dev/video0..9 by construction, so a tenth node was
    /// invisible; archhost has one. Run against a fake root, because a test
    /// reading the real /dev proves whatever that machine happens to have
    /// plugged in and would pass on a box with three cameras and no video10.
    #[test]
    fn the_node_scan_reaches_past_nine_and_orders_numerically() {
        let root = std::env::temp_dir().join(format!("irlume-nodes-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        std::fs::create_dir_all(&root).unwrap();
        for name in [
            "video10", "video2", "video9", "video0", "videoX", "video", "audio3", "video1a",
        ] {
            std::fs::write(root.join(name), b"").unwrap();
        }

        let listing = video_node_paths_in(&root);
        let names: Vec<String> = listing
            .paths
            .iter()
            .map(|p| {
                std::path::Path::new(p)
                    .file_name()
                    .unwrap()
                    .to_string_lossy()
                    .into_owned()
            })
            .collect();
        // video10 present and last: the range cap is gone and the sort is
        // numeric, which a lexical sort would render video0, video10, video2.
        assert_eq!(names, ["video0", "video2", "video9", "video10"]);
        assert!(listing.error.is_none(), "{:?}", listing.error);

        std::fs::remove_dir_all(&root).unwrap();
    }

    /// The branch the Codex round on #229 found unreachable: a node that opens
    /// and then refuses to answer must be reported, not silently classified
    /// as `Other` and dropped. `/dev/null` is exactly that node on any Linux
    /// machine; since the #425 gate it fails at the QUERYCAP that now runs
    /// before format enumeration (ENOTTY on a non-v4l2 character device), so
    /// this needs no camera, no privilege, and no hardware in CI.
    #[test]
    fn a_node_that_answers_no_v4l2_ioctl_is_reported_not_dropped() {
        let u = classify_node("/dev/null")
            .expect_err("a device that answers no V4L2 ioctl must not classify as a role");
        assert_eq!(u.at, FailedAt::QueryCaps);
        assert_eq!(u.errno, Some(libc::ENOTTY));
        assert!(
            u.explain().contains("did not answer VIDIOC_QUERYCAP"),
            "{}",
            u.explain()
        );
    }

    /// One QUERYCAP answer per driver the audit measured, built from the
    /// capability words read out of each driver's registration site in the
    /// kernel source (docs/research/2026-08-12-camera-handling-audit.md,
    /// taxonomy section). The gate must refuse every MC-centric and
    /// MPLANE-only shape and pass every shape irlume actually drives.
    fn caps_answer(driver: &str, device_caps: u32) -> v4l::v4l_sys::v4l2_capability {
        #[expect(clippy::undocumented_unsafe_blocks, reason = "doc backlog")]
        let mut caps: v4l::v4l_sys::v4l2_capability = unsafe { std::mem::zeroed() };
        caps.driver[..driver.len()].copy_from_slice(driver.as_bytes());
        // The kernel ORs DEVICE_CAPS into the whole-device word, never into
        // device_caps itself (videodev2.h; v4l2-ioctl.c sets it centrally).
        caps.capabilities = device_caps | v4l::v4l_sys::V4L2_CAP_DEVICE_CAPS;
        caps.device_caps = device_caps;
        caps
    }

    /// The refusal table: Intel IPU6 ISYS (single-planar capture WITH IO_MC,
    /// the #425 phantom-RGB case), AMD ISP4 (IO_MC), Qualcomm camss (IO_MC
    /// and MPLANE), ipu3-cio2 (MPLANE only, no IO_MC). Each word is the
    /// registration site's, quoted in the audit doc.
    #[test]
    fn mc_centric_verdict_refuses_every_measured_mipi_shape() {
        use v4l::v4l_sys::{
            V4L2_CAP_IO_MC as IO_MC, V4L2_CAP_META_CAPTURE as META, V4L2_CAP_READWRITE as RW,
            V4L2_CAP_STREAMING as STREAMING, V4L2_CAP_VIDEO_CAPTURE as CAP,
            V4L2_CAP_VIDEO_CAPTURE_MPLANE as MPLANE,
        };
        let ipu6 = mc_centric_verdict(&caps_answer("isys", STREAMING | IO_MC | CAP | META))
            .expect("an IPU6 ISYS node must refuse format classification");
        assert!(ipu6.io_mc && !ipu6.mplane_only, "{ipu6:?}");
        assert_eq!(ipu6.driver, "isys");

        let amd = mc_centric_verdict(&caps_answer("amd_isp_capture", CAP | STREAMING | IO_MC))
            .expect("an AMD ISP4 node must refuse");
        assert!(amd.io_mc, "{amd:?}");

        let camss = mc_centric_verdict(&caps_answer("qcom-camss", MPLANE | STREAMING | RW | IO_MC))
            .expect("a camss node must refuse");
        assert!(camss.io_mc && camss.mplane_only, "{camss:?}");

        let cio2 = mc_centric_verdict(&caps_answer("ipu3-cio2", MPLANE | STREAMING))
            .expect("an ipu3-cio2 node must refuse, deliberately rather than by probe shape");
        assert!(!cio2.io_mc && cio2.mplane_only, "{cio2:?}");
    }

    /// The pass-through table: both UVC node shapes and v4l2loopback, the
    /// hardware irlume drives today, must reach format classification exactly
    /// as before the gate.
    #[test]
    fn mc_centric_verdict_passes_every_shape_irlume_drives() {
        use v4l::v4l_sys::{
            V4L2_CAP_META_CAPTURE as META, V4L2_CAP_STREAMING as STREAMING,
            V4L2_CAP_VIDEO_CAPTURE as CAP, V4L2_CAP_VIDEO_OUTPUT as OUT,
        };
        for (name, word) in [
            ("uvcvideo capture", CAP | STREAMING),
            ("uvcvideo metadata", META | STREAMING),
            ("v4l2loopback", CAP | OUT | STREAMING),
        ] {
            assert_eq!(
                mc_centric_verdict(&caps_answer("x", word)),
                None,
                "{name} must pass through to format classification"
            );
        }
    }

    /// A driver that never learned the device_caps split (pre-3.4 shape) is
    /// judged on its whole-device word: refusing on a possibly-borrowed word
    /// is the safe direction for a gate whose cost is one unusable node.
    #[test]
    fn a_querycap_without_device_caps_is_judged_on_the_whole_device_word() {
        use v4l::v4l_sys::{V4L2_CAP_IO_MC, V4L2_CAP_STREAMING, V4L2_CAP_VIDEO_CAPTURE};
        #[expect(clippy::undocumented_unsafe_blocks, reason = "doc backlog")]
        let mut caps: v4l::v4l_sys::v4l2_capability = unsafe { std::mem::zeroed() };
        caps.capabilities = V4L2_CAP_VIDEO_CAPTURE | V4L2_CAP_STREAMING | V4L2_CAP_IO_MC;
        caps.device_caps = 0; // never filled by such a driver
        assert!(mc_centric_verdict(&caps).is_some());
    }

    /// The bucketing arms of `file_node`: only `Camera(Rgb|Ir)` may reach
    /// `classified`, because that bucket feeds every camera-picking caller;
    /// an MC-centric outcome lands in its own bucket and nowhere else. This
    /// pins the scan()-side wiring of #425 without a device per arm.
    #[test]
    fn file_node_keeps_mc_centric_nodes_out_of_the_usable_bucket() {
        let mc = || McCentric {
            driver: "isys".into(),
            io_mc: true,
            mplane_only: false,
        };
        let mut scan = NodeScan::default();
        file_node(
            &mut scan,
            "/dev/video0".into(),
            Ok(NodeKind::Camera(Role::Rgb)),
        );
        file_node(
            &mut scan,
            "/dev/video1".into(),
            Ok(NodeKind::Camera(Role::Other)),
        );
        file_node(
            &mut scan,
            "/dev/video2".into(),
            Ok(NodeKind::McCentric(mc())),
        );
        file_node(
            &mut scan,
            "/dev/video3".into(),
            Err(Unreadable {
                path: "/dev/video3".into(),
                at: FailedAt::Open,
                errno: Some(libc::EACCES),
                holder: None,
            }),
        );
        assert_eq!(
            scan.classified,
            vec![("/dev/video0".to_string(), Role::Rgb)]
        );
        assert_eq!(scan.mc_centric.len(), 1);
        assert_eq!(scan.mc_centric[0].0, "/dev/video2");
        assert_eq!(scan.unreadable.len(), 1);
    }

    /// The wording contract of `McCentric::cause`, same as `Unreadable`'s: it
    /// names the driver and says what the user can and cannot expect, and the
    /// two refusal shapes get different sentences.
    #[test]
    fn mc_centric_cause_names_the_driver_and_the_stack() {
        let io_mc = McCentric {
            driver: "isys".into(),
            io_mc: true,
            mplane_only: false,
        };
        assert!(io_mc.cause().contains("isys"), "{}", io_mc.cause());
        assert!(
            io_mc.cause().contains("media-controller"),
            "{}",
            io_mc.cause()
        );
        let mplane = McCentric {
            driver: "ipu3-cio2".into(),
            io_mc: false,
            mplane_only: true,
        };
        assert!(
            mplane.cause().contains("multi-planar"),
            "{}",
            mplane.cause()
        );
    }

    /// EINVAL at index 0 is the kernel's "no format here", which every UVC
    /// metadata node answers. Treating it as a failure would put a warning
    /// against four correctly-ignored nodes on any machine with two cameras,
    /// which is how a report that finally says something useful gets ignored.
    /// Every other errno is a node that would not answer.
    #[test]
    fn only_einval_means_a_node_has_no_capture_formats() {
        let err = |n| std::io::Error::from_raw_os_error(n);
        assert!(enum_fmt_failure_means_no_formats(&err(libc::EINVAL)));
        for other in [
            libc::EBUSY,
            libc::ENOTTY,
            libc::EIO,
            libc::ENODEV,
            libc::EACCES,
        ] {
            assert!(
                !enum_fmt_failure_means_no_formats(&err(other)),
                "errno {other} is a failed observation, not an absence"
            );
        }
    }

    /// A directory that will not list must not read as a machine with no
    /// cameras. This is the same defect #227 fixes, one level up.
    #[test]
    fn a_directory_that_cannot_be_listed_is_not_an_empty_machine() {
        let missing = std::env::temp_dir().join(format!("irlume-absent-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&missing);
        let listing = video_node_paths_in(&missing);
        assert!(listing.paths.is_empty());
        let why = listing.error.expect("a listing failure must be reported");
        assert!(why.contains("could not be listed"), "{why}");
    }

    fn frame(data: &[u8]) -> Frame {
        Frame {
            width: data.len() as u32,
            height: 1,
            spectrum: Spectrum::Rgb,
            data: data.to_vec(),
            captured: CaptureWindow::at(std::time::Instant::now()),
        }
    }

    // The decision the probe exists to make, checked against the two modules we
    // actually measured on 2026-07-25 rather than invented numbers.
    #[test]
    fn capture_mode_follows_the_measured_signal_loss() {
        let report = |seq_rgb: f32, con_rgb: f32, seq_ir: f32, con_ir: f32| ContentionReport {
            sequential: PairSample {
                rgb_mean: seq_rgb,
                ir_mean: seq_ir,
                total_ms: 3595.0,
                rounds: 20,
                failed: 0,
            },
            concurrent: PairSample {
                rgb_mean: con_rgb,
                ir_mean: con_ir,
                total_ms: 2194.0,
                rounds: 20,
                failed: 0,
            },
        };

        // NexiGo HelloCam N930W: RGB collapses when its own IR sibling streams.
        let nexigo = report(117.4, 66.1, 56.2, 50.8);
        assert_eq!(nexigo.recommended_mode(), CaptureMode::Sequential);
        assert!((nexigo.retained_rgb() - 0.563).abs() < 0.01);

        // Same camera in a brighter scene: the concurrent arm barely moves
        // (59.8 vs 66.1) while the sequential arm tracks the light up to 142.9,
        // so the shortfall grows. Both runs must reach the same verdict.
        let nexigo_lit = report(142.9, 59.8, 47.5, 51.1);
        assert_eq!(nexigo_lit.recommended_mode(), CaptureMode::Sequential);
        assert!(nexigo_lit.retained_rgb() < nexigo.retained_rgb());

        // ASUS FHD built-in: no loss on either stream, so keep the fast path.
        let asus = report(104.6, 108.4, 53.1, 50.1);
        assert_eq!(asus.recommended_mode(), CaptureMode::Concurrent);

        // A loss on the IR side alone is just as disqualifying as one on RGB.
        assert_eq!(
            report(104.0, 104.0, 100.0, 40.0).recommended_mode(),
            CaptureMode::Sequential
        );

        // No baseline (the sequential arm captured nothing usable) must not read
        // as a total loss and force every camera to the slow path.
        let blind = report(0.0, 0.0, 0.0, 0.0);
        assert_eq!(blind.retained_rgb(), 1.0);
        assert_eq!(blind.recommended_mode(), CaptureMode::Concurrent);

        assert!(nexigo.saved_ms() > 1400.0 && nexigo.saved_ms() < 1402.0);

        // Scene dependence, measured the same day on the same NexiGo: bright
        // room 117.4 -> 66.1 (loss visible), dark room 61.8 -> 56.2 (loss
        // hidden). A clean result from the dark run must not be reported as
        // proof the camera is healthy; a detected loss needs no such caveat.
        assert!(nexigo.conclusive()); // RGB loss found in a lit scene
        assert!(asus.conclusive()); // clean, and lit enough to mean it
        assert!(!report(61.8, 56.2, 46.0, 45.0).conclusive()); // clean but dim
        assert!(!blind.conclusive());
        // A near-dark room makes the RGB ratio arithmetic on noise: measured at
        // an RGB mean of 17 it read 121-126% retention. Neither direction of an
        // RGB-driven verdict can be trusted there.
        assert!(!report(16.4, 20.0, 72.0, 66.0).conclusive());
        assert!(!report(16.4, 10.0, 72.0, 66.0).conclusive());
        // The IR arm carries its own light, so an IR loss stands even in the dark.
        let ir_loss_in_the_dark = report(16.4, 20.0, 72.0, 40.0);
        assert_eq!(
            ir_loss_in_the_dark.recommended_mode(),
            CaptureMode::Sequential
        );
        assert!(ir_loss_in_the_dark.conclusive());
    }

    /// Each arm needs a log line as well as a number, and this pins which.
    /// Deleting any single rule flips a case here.
    #[test]
    fn a_cause_is_named_only_when_a_log_line_supports_it() {
        let xhci = ["xhci_hcd 0000:00:14.0: Not enough bandwidth for new device state."];
        let core = ["usb 1-5: Not enough bandwidth for altsetting 1"];
        for lines in [xhci.as_slice(), core.as_slice()] {
            assert_eq!(
                classify_contention_failure(Some(libc::ENOSPC), lines),
                ContentionCause::HostBudget
            );
        }
        assert_eq!(
            classify_contention_failure(
                Some(libc::EIO),
                &["uvcvideo: No fast enough alt setting for requested bandwidth"]
            ),
            ContentionCause::DeviceRequestExceedsAltsettings
        );
        // A clamp warning is a SUCCESSFUL fix-up, not a failure cause:
        // `uvc_fixup_video_ctrl` reduces the request and carries on. Seeing one
        // in the window establishes that a clamp happened, never that it is why
        // a later call failed, so it must not name a cause on its own (#402
        // review). It must also not outrank a real EBUSY.
        let clamp =
            ["uvcvideo 1-5:1.0: UVC non compliance: Reducing max payload transfer size (3072) to fit endpoint limit (2048)."];
        assert_eq!(
            classify_contention_failure(Some(libc::EIO), &clamp),
            ContentionCause::Unknown
        );
        assert_eq!(
            classify_contention_failure(Some(libc::EBUSY), &clamp),
            ContentionCause::Busy
        );
        assert_eq!(
            classify_contention_failure(Some(libc::EBUSY), &[]),
            ContentionCause::Busy
        );
    }

    /// The assertions that stop this over-claiming, and the reason the first
    /// draft of this classifier was wrong. Every one of these numbers has
    /// several origins on this path, so a bare errno establishes nothing.
    ///
    /// `ENOSPC` is the one that matters most: it is reachable both from the
    /// host controller and from uvcvideo's own probe limit, and only the first
    /// licenses a workaround.
    #[test]
    fn a_bare_errno_names_no_cause() {
        for errno in [
            libc::ENOSPC,
            libc::EIO,
            libc::EINVAL,
            libc::EPIPE,
            libc::ENODEV,
        ] {
            assert_eq!(
                classify_contention_failure(Some(errno), &[]),
                ContentionCause::Unknown,
                "errno {errno} has more than one origin and must not name a cause alone"
            );
        }
        // Unrelated kernel chatter is not evidence either.
        let noise = [
            "usb 1-5: new high-speed USB device number 7 using xhci_hcd",
            "uvcvideo: Found UVC 1.00 device ASUS FHD webcam (13d3:56ff)",
        ];
        assert_eq!(
            classify_contention_failure(Some(libc::ENOSPC), &noise),
            ContentionCause::Unknown
        );
        // A failure that was never a syscall carries no number, and absence is
        // not a value.
        assert_eq!(
            classify_contention_failure(None, &["Not enough bandwidth for new device state."]),
            ContentionCause::Unknown
        );
    }

    /// The gate is open only for the two causes whose mechanism is "the request
    /// was too large", and never for an unidentified failure.
    #[test]
    fn only_a_too_large_request_licenses_a_bandwidth_reduction() {
        assert!(reduction_may_help(ContentionCause::HostBudget));
        assert!(reduction_may_help(
            ContentionCause::DeviceRequestExceedsAltsettings
        ));
        for refused in [ContentionCause::Busy, ContentionCause::Unknown] {
            assert!(!reduction_may_help(refused), "{refused:?} must not qualify");
        }
    }

    // The BRIO shape, measured 2026-08-04 on archhost: every concurrent
    // attempt errors (RGB open returns EINVAL while the IR sibling streams),
    // sequential rounds measure fine. An arm that cannot run is a definitive
    // Sequential in any light, and must not read as a failed probe (#192).
    #[test]
    fn a_concurrent_arm_that_only_errors_decides_sequential_conclusively() {
        let brio = ContentionReport {
            sequential: PairSample {
                rgb_mean: 16.0, // dark room; the verdict must not need light
                ir_mean: 58.0,
                total_ms: 2200.0,
                rounds: 6,
                failed: 0,
            },
            concurrent: PairSample {
                rounds: 0,
                failed: 6,
                ..Default::default()
            },
        };
        assert!(brio.concurrent_impossible());
        assert_eq!(brio.recommended_mode(), CaptureMode::Sequential);
        assert!(
            brio.conclusive(),
            "an errored arm is definitive in the dark"
        );

        // The guard discriminates: zero rounds with zero failures is the
        // nothing-attempted shape, not the cannot-run shape.
        let unattempted = ContentionReport {
            sequential: brio.sequential,
            concurrent: PairSample::default(),
        };
        assert!(!unattempted.concurrent_impossible());
    }

    fn stats(lit: f32) -> IrCaptureStats {
        IrCaptureStats {
            lit_mean: lit,
            ambient_mean: 1.0,
            ambient_observed: false,
            burst_frames: 8,
            camera_classified_frames: 0,
            white_level: None,
            saturation_frame: None,
        }
    }

    /// The tests' concurrent arm: per-call scripted captures through the SAME
    /// accumulate/round shape the production held-session arm uses, so the
    /// composer's decisions (panic abort, dead arms, trailing control) are
    /// exercised without a camera. Callers pass `&closure` twice on purpose
    /// (the same script feeds the sequential caps AND this arm), which
    /// clippy's needless-borrow lint cannot see; the tests carry the allow.
    fn scripted_arm<'a, R, I>(
        rgb: &'a R,
        ir: &'a I,
    ) -> impl FnOnce(usize, &Progress, &mut PairSample) -> irlume_common::Result<()> + 'a
    where
        R: Fn() -> irlume_common::Result<Frame>,
        I: Fn() -> irlume_common::Result<(Frame, IrCaptureStats)>,
    {
        move |rounds, progress, into| {
            for _ in 0..rounds {
                progress();
                let t0 = std::time::Instant::now();
                let r = rgb();
                let i = ir();
                accumulate(into, &r, &i, t0.elapsed());
            }
            Ok(())
        }
    }

    #[test]
    #[allow(clippy::needless_borrows_for_generic_args)]
    fn a_panicking_capture_aborts_the_probe_instead_of_becoming_a_verdict() {
        use std::sync::atomic::{AtomicUsize, Ordering};
        // Sequential IR captures succeed; every concurrent one PANICS. Counting
        // those as failed rounds would persist "this camera cannot stream both
        // nodes" over a software defect (#263 review); the probe must abort.
        let ir_calls = AtomicUsize::new(0);
        let rgb = || Ok(frame(&[100; 4]));
        let ir = || {
            if ir_calls.fetch_add(1, Ordering::SeqCst) >= 2 {
                panic!("injected defect");
            }
            Ok((frame(&[10; 4]), stats(50.0)))
        };
        let prev = std::panic::take_hook();
        std::panic::set_hook(Box::new(|_| {})); // keep the test log clean
        let got = measure_contention_impl(&rgb, &ir, scripted_arm(&rgb, &ir), 2, &no_progress());
        std::panic::set_hook(prev);
        let err = got.expect_err("a panic must abort the probe, never report");
        assert!(err.to_string().contains("panicked"), "{err}");
    }

    #[test]
    #[allow(clippy::needless_borrows_for_generic_args)]
    fn an_all_error_concurrent_arm_needs_the_trailing_control_to_pass() {
        use std::sync::atomic::{AtomicUsize, Ordering};
        // The BRIO shape, injected: sequential rounds fine, every concurrent
        // RGB open errors, and the trailing control finds the camera still
        // answering — a real contention verdict.
        let rgb_calls = AtomicUsize::new(0);
        let rgb = || {
            let n = rgb_calls.fetch_add(1, Ordering::SeqCst);
            // Calls 0-1: sequential. 2-3: concurrent (error). 4: control.
            if (2..4).contains(&n) {
                Err(Error::Hardware(
                    "EINVAL while the IR sibling streams".into(),
                ))
            } else {
                Ok(frame(&[100; 4]))
            }
        };
        let ir = || Ok((frame(&[10; 4]), stats(50.0)));
        let report = measure_contention_impl(&rgb, &ir, scripted_arm(&rgb, &ir), 2, &no_progress())
            .expect("an answering camera with an impossible concurrent arm is a verdict");
        assert!(report.concurrent_impossible());
        assert_eq!(report.recommended_mode(), CaptureMode::Sequential);
        assert_eq!(
            rgb_calls.load(Ordering::SeqCst),
            5,
            "the trailing control must actually run"
        );
    }

    /// #308: a camera pair that cannot even ENTER the held shape (open or arm
    /// fails with both streams held) is an all-failed concurrent arm, and with
    /// the trailing control answering, that is a sequential VERDICT, not a
    /// probe error. This is the Brio's held-session starvation as the
    /// composer sees it.
    #[test]
    #[allow(clippy::needless_borrows_for_generic_args)]
    fn a_pair_that_cannot_arm_held_streams_is_a_sequential_verdict() {
        let rgb = || Ok(frame(&[100; 4]));
        let ir = || Ok((frame(&[10; 4]), stats(50.0)));
        let arming_fails = |rounds: usize, _p: &Progress, into: &mut PairSample| {
            into.failed += rounds;
            Ok(())
        };
        let report = measure_contention_impl(&rgb, &ir, arming_fails, 2, &no_progress())
            .expect("an unarmable held pair with an answering camera is a verdict");
        assert!(report.concurrent_impossible());
        assert_eq!(report.recommended_mode(), CaptureMode::Sequential);
    }

    #[test]
    #[allow(clippy::needless_borrows_for_generic_args)]
    fn a_camera_that_stops_answering_fails_the_probe_not_the_verdict() {
        use std::sync::atomic::{AtomicUsize, Ordering};
        // Sequential rounds fine, then the camera dies: every later capture
        // errors, including the trailing control. That proves the camera
        // stopped answering, not that concurrency fails, and must not persist
        // a capability verdict (#263 review).
        let rgb_calls = AtomicUsize::new(0);
        let rgb = || {
            if rgb_calls.fetch_add(1, Ordering::SeqCst) >= 2 {
                Err(Error::Hardware("ENODEV".into()))
            } else {
                Ok(frame(&[100; 4]))
            }
        };
        let ir = || Ok((frame(&[10; 4]), stats(50.0)));
        let got = measure_contention_impl(&rgb, &ir, scripted_arm(&rgb, &ir), 2, &no_progress());
        let err = got.expect_err("a dead camera is a failed probe");
        assert!(err.to_string().contains("trailing"), "{err}");
    }

    /// The pair-key migration rule (#340 review): the pair entry decides; a
    /// legacy RGB-only entry is honored only for two interfaces of one
    /// physical module; any other pairing is unmeasured even when a legacy
    /// entry exists, because that entry was never measured against this IR.
    #[test]
    fn a_legacy_rgb_only_verdict_never_covers_a_different_ir_camera() {
        use std::cell::Cell;
        // Pair entry present: it decides, the legacy closure is never asked.
        let asked = Cell::new(false);
        let got = resolve_stored_pair_mode(Some("concurrent".into()), false, || {
            asked.set(true);
            Some("sequential".into())
        });
        assert_eq!(got, Some(CaptureMode::Concurrent));
        assert!(!asked.get(), "a pair entry must decide alone");
        // No pair entry, same physical module: the legacy entry migrates.
        assert_eq!(
            resolve_stored_pair_mode(None, true, || Some("concurrent".into())),
            Some(CaptureMode::Concurrent)
        );
        // No pair entry, DIFFERENT module: unmeasured, even with a legacy
        // concurrent entry on file. This is the #340 review's failure case:
        // RGB A tuned concurrent against IR B must not vouch for IR C.
        assert_eq!(
            resolve_stored_pair_mode(None, false, || Some("concurrent".into())),
            None
        );
        // Unparseable text is not a verdict on either path.
        assert_eq!(
            resolve_stored_pair_mode(Some("garbage".into()), true, || Some("concurrent".into())),
            None
        );
    }

    /// The on-disk key formats are compatibility surfaces: the pair key is
    /// what new writes produce, the bare key is what pre-pair releases wrote
    /// and migration reads.
    #[test]
    fn capture_mode_keys_keep_their_on_disk_spellings() {
        assert_eq!(
            capture_mode_pair_key("046d:085e:abc", "046d:085e:abc"),
            "capture_mode.046d:085e:abc+046d:085e:abc"
        );
        assert_eq!(
            capture_mode_key("046d:085e:abc"),
            "capture_mode.046d:085e:abc"
        );
    }

    #[test]
    fn capture_mode_parses_only_the_two_spellings() {
        assert_eq!(
            CaptureMode::parse("sequential"),
            Some(CaptureMode::Sequential)
        );
        assert_eq!(
            CaptureMode::parse(" Concurrent \n"),
            Some(CaptureMode::Concurrent)
        );
        // An unrecognized or empty value is NOT a mode: the caller keeps its own
        // default rather than acting on a value it does not understand.
        assert_eq!(CaptureMode::parse("fast"), None);
        assert_eq!(CaptureMode::parse(""), None);
        assert_eq!(
            CaptureMode::parse(CaptureMode::Sequential.as_str()),
            Some(CaptureMode::Sequential)
        );
    }

    /// The origin is a SIDECAR key, never part of the mode's value. Config keys
    /// match exactly, so the two must be distinct strings, and the mode's
    /// grammar must be untouched by the arrival of provenance: an older irlume
    /// reading this file still sees exactly `sequential` or `concurrent`.
    #[test]
    fn the_origin_key_is_a_sidecar_and_never_the_mode_value() {
        let (rgb, ir) = ("046d:085e:abc", "046d:085e:def");
        assert_eq!(
            capture_mode_origin_key(rgb, ir),
            "capture_mode_origin.046d:085e:abc+046d:085e:def"
        );
        assert_ne!(
            capture_mode_origin_key(rgb, ir),
            capture_mode_pair_key(rgb, ir)
        );
        // Neither key is the other's prefix under exact matching, so a reader
        // asking for one can never be handed the other's value.
        assert!(!capture_mode_origin_key(rgb, ir).starts_with(&capture_mode_pair_key(rgb, ir)));
        // The mode value itself did not gain a word.
        assert_eq!(CaptureMode::Sequential.as_str(), "sequential");
        assert_eq!(
            CaptureMode::parse(CaptureMode::Sequential.as_str()),
            Some(CaptureMode::Sequential)
        );
    }

    /// The origin stamp is descriptive only, so its parse fails soft: an
    /// unreadable time still says "irlume switched this", and text it does not
    /// recognize at all reports nothing rather than inventing a provenance.
    /// What it must never do is change which MODE is in force; that lives in a
    /// different key this function cannot reach.
    #[test]
    fn capture_mode_origin_parses_leniently_or_reports_nothing() {
        assert_eq!(
            parse_capture_mode_origin("auto-switch 1786320000"),
            Some(CaptureModeOrigin::AutoSwitched {
                at_unix: Some(1_786_320_000)
            })
        );
        // A stamp with no time, or an unparseable one, still records WHO.
        for raw in ["auto-switch", "auto-switch banana", "  auto-switch  "] {
            assert_eq!(
                parse_capture_mode_origin(raw),
                Some(CaptureModeOrigin::AutoSwitched { at_unix: None }),
                "{raw:?} must still report the switch"
            );
        }
        // Anything else is "origin not recorded", never a guess.
        for raw in ["", "auto", "measured 5", "sequential", "camera-tune 12"] {
            assert_eq!(
                parse_capture_mode_origin(raw),
                None,
                "{raw:?} must not be read as an origin"
            );
        }
    }

    #[test]
    fn capture_window_gap_is_zero_while_the_windows_touch() {
        use std::time::{Duration, Instant};
        let t0 = Instant::now();
        let at = |ms: u64| t0 + Duration::from_millis(ms);
        let w = |a: u64, b: u64| CaptureWindow {
            start: at(a),
            end: at(b),
        };

        // Overlapping (the shipped concurrent capture) and abutting (a
        // sequential capture, one burst then the other) both mean "same moment".
        assert_eq!(w(0, 400).gap_to(w(200, 900)), Duration::ZERO);
        assert_eq!(w(0, 400).gap_to(w(400, 1100)), Duration::ZERO);
        // Containment counts as overlap in both directions.
        assert_eq!(w(0, 900).gap_to(w(300, 400)), Duration::ZERO);
        assert_eq!(w(300, 400).gap_to(w(0, 900)), Duration::ZERO);
        // Disjoint: the gap is between the windows, not between their starts,
        // and it reads the same from either side.
        assert_eq!(w(0, 400).gap_to(w(1000, 1400)), Duration::from_millis(600));
        assert_eq!(w(1000, 1400).gap_to(w(0, 400)), Duration::from_millis(600));
        // A union spans both and therefore touches each of them.
        let u = w(0, 400).union(w(1000, 1400));
        assert_eq!(u.start, at(0));
        assert_eq!(u.end, at(1400));
    }

    #[test]
    fn median_frame_window_spans_the_whole_burst() {
        use std::time::{Duration, Instant};
        let t0 = Instant::now();
        let mut frames = vec![frame(&[10, 10]), frame(&[20, 20]), frame(&[30, 30])];
        for (i, f) in frames.iter_mut().enumerate() {
            f.captured = CaptureWindow::at(t0 + Duration::from_millis(100 * i as u64));
        }
        // A median pixel may come from any frame, so the result cannot claim a
        // single instant: it must cover first-to-last dequeue.
        let m = median_frame(frames);
        assert_eq!(m.captured.start, t0);
        assert_eq!(m.captured.end, t0 + Duration::from_millis(200));
        assert_eq!(m.data, vec![20, 20]);
    }

    #[test]
    fn median_frame_rejects_a_single_bad_frame() {
        // Four "good" frames near 100 and one wildly over-exposed (255) frame:
        // the per-pixel median ignores the outlier.
        let frames = vec![
            frame(&[100, 50, 200]),
            frame(&[101, 49, 201]),
            frame(&[255, 255, 255]), // the bad frame
            frame(&[99, 51, 199]),
            frame(&[100, 50, 200]),
        ];
        let m = median_frame(frames);
        assert_eq!(m.data, vec![100, 50, 200]);
    }

    #[test]
    fn median_frame_passes_lone_frame_through() {
        let m = median_frame(vec![frame(&[1, 2, 3])]);
        assert_eq!(m.data, vec![1, 2, 3]);
    }

    #[test]
    fn ambient_subtract_cancels_shared_pedestal_and_clamps() {
        // Ambient light present in both frames cancels; the emitter's extra
        // return survives; nothing goes negative (saturating clamp at 0).
        let lit = [200u8, 60, 10];
        let ambient = [50u8, 60, 90];
        assert_eq!(ir_probe::subtract(&lit, &ambient), vec![150, 0, 0]);
        // Size mismatch falls back to the lit frame unchanged.
        assert_eq!(ir_probe::subtract(&lit, &[1, 2]), lit.to_vec());
    }

    /// Which formats can support a clipping claim at all. A decoded 255 means
    /// "the sensor's full-scale sample" ONLY for the native 8-bit greys: the
    /// Y16 family is rescaled by a shift taken from the frame's own maximum.
    /// The YUV pair is a different case and this comment used to get it wrong:
    /// irlume does carry their raw quantization, but resolving `Default` also
    /// needs the colorspace, which `IrCamera` discards. The `None` is there
    /// mainly because no discovered pair reaches an IR decode with those
    /// fourccs, and the refusal it produces is what stops a colour node that
    /// arrives in the IR slot some other way (#385). Saying None keeps #221's
    /// corpus interpretable either way.
    #[test]
    fn only_native_8bit_grey_can_claim_a_clipping_ceiling() {
        for q in [
            Quantization::Default,
            Quantization::FullRange,
            Quantization::LimitedRange,
        ] {
            assert_eq!(clipping_white_level(IrPixel::Grey16, q), None);
            assert_eq!(clipping_white_level(IrPixel::Nv12Luma, q), None);
            assert_eq!(clipping_white_level(IrPixel::YuyvLuma, q), None);
        }
        // And the decoder reports its own format's answer, since that is what
        // the capture actually negotiated.
        assert_eq!(
            IrDecoder::new(IrPixel::Grey8, Quantization::Default).white_level(),
            Some(255)
        );
        assert_eq!(
            IrDecoder::new(IrPixel::Grey16, Quantization::Default).white_level(),
            None
        );
    }

    /// GREY's ceiling is where the DRIVER says white is. A limited-range device
    /// puts it at 235, so a face entirely at 235 is fully clipped there and
    /// would read as pristine against a hardcoded 255, walking straight through
    /// the exposure gate (#238 review).
    ///
    /// `Default` reads as full range because that is what it resolves to on
    /// every module irlume supports, measured with `v4l2-ctl --get-fmt-video`
    /// on the ASUS FHD IR pin, the NexiGo N930W and the Logitech BRIO: all
    /// three print "Default (maps to Full Range)". Answering None there would
    /// switch the gate off on every camera anyone has.
    #[test]
    fn the_grey_ceiling_follows_the_drivers_quantization() {
        assert_eq!(
            clipping_white_level(IrPixel::Grey8, Quantization::LimitedRange),
            Some(235)
        );
        assert_eq!(
            clipping_white_level(IrPixel::Grey8, Quantization::FullRange),
            Some(255)
        );
        assert_eq!(
            clipping_white_level(IrPixel::Grey8, Quantization::Default),
            Some(255)
        );
    }

    /// The reason Grey16 cannot: the shift comes from the frame's OWN maximum,
    /// so a frame whose brightest sample is far below the container ceiling
    /// still decodes that sample to 255.
    #[test]
    fn grey16_decoding_maps_a_dim_frames_maximum_to_full_scale() {
        // 10-bit content in a 16-bit container: max 1023, nowhere near 0xFFFF.
        let mut buf = Vec::new();
        for v in [0u16, 256, 512, 1023] {
            buf.extend_from_slice(&v.to_le_bytes());
        }
        let decoded = decode_ir(&buf, IrPixel::Grey16, 4, 1);
        assert_eq!(
            decoded.last().copied(),
            Some(255),
            "the frame maximum decodes to 255 even though the sensor did not clip"
        );
    }

    #[test]
    fn saturated_fraction_counts_clipped_pixels() {
        assert_eq!(
            ir_probe::saturated_fraction(&[255, 255, 0, 0], u8::MAX),
            0.5
        );
        assert_eq!(ir_probe::saturated_fraction(&[0, 1, 254], u8::MAX), 0.0);
        assert_eq!(ir_probe::saturated_fraction(&[], u8::MAX), 0.0);
    }

    /// The whole of #394: a limited-range stream rails at 235, and counting
    /// `== 255` reported it as pristine. Both readings below come from the SAME
    /// buffer, so this fails on the old signature no matter what ceiling is
    /// passed: it could only ever answer 0.0 for these pixels.
    ///
    /// The second half is what makes it a regression test rather than a
    /// tautology: at a 255 ceiling the same frame must still read clean, so a
    /// fix that simply lowered the constant is not enough to pass.
    #[test]
    fn a_frame_railed_at_nominal_white_is_clipped_only_against_its_own_ceiling() {
        let railed_at_235 = [235u8, 235, 235, 235];
        assert_eq!(
            ir_probe::saturated_fraction(&railed_at_235, 235),
            1.0,
            "a limited-range frame at nominal white is entirely clipped"
        );
        assert_eq!(
            ir_probe::saturated_fraction(&railed_at_235, u8::MAX),
            0.0,
            "the same pixels are not clipped on a full-range stream"
        );
        // Out-of-range excursion above nominal white still carries no usable
        // emitter return, so `>=` and not `==`.
        assert_eq!(ir_probe::saturated_fraction(&[236u8, 0, 0, 0], 235), 0.25);
    }

    #[test]
    fn yuyv_grey_converts_to_grey_rgb() {
        // Y=128, U=V=128 (neutral) -> mid-grey RGB.
        let yuyv = [128u8, 128, 128, 128];
        let rgb = yuyv_to_rgb(&yuyv, 2, 1);
        assert_eq!(rgb.len(), 6);
        for c in rgb {
            assert!((c as i32 - 128).abs() <= 1);
        }
    }

    #[test]
    fn rgb_format_choice_prefers_yuyv_then_nv12_else_none() {
        // YUYV wins even when listed after MJPG (real ASUS camera order).
        assert_eq!(choose_rgb_format(&[*b"MJPG", *b"YUYV"]), Some(*b"YUYV"));
        // NV12 rescues a camera that offers no YUYV.
        assert_eq!(choose_rgb_format(&[*b"MJPG", *b"NV12"]), Some(*b"NV12"));
        // YUYV still preferred over NV12 when both are present.
        assert_eq!(choose_rgb_format(&[*b"NV12", *b"YUYV"]), Some(*b"YUYV"));
        // MJPEG-only: nothing decodable, negotiation must fail (not pick MJPG).
        assert_eq!(choose_rgb_format(&[*b"MJPG"]), None);
    }

    #[test]
    fn ipu_generation_maps_ids_and_rejects_others() {
        assert_eq!(ipu_generation_for_id("0x7d19"), Some("IPU6")); // Meteor Lake
        assert_eq!(ipu_generation_for_id("0x645d"), Some("IPU7")); // Lunar Lake
        assert_eq!(ipu_generation_for_id("0xb05d"), Some("IPU7")); // Panther Lake
        assert_eq!(ipu_generation_for_id("0x1234"), None);
        assert_eq!(ipu_generation_for_id(""), None);
    }

    #[test]
    fn fourcc_str_trims_padding() {
        assert_eq!(fourcc_str(b"YUYV"), "YUYV");
        assert_eq!(fourcc_str(b"Y8  "), "Y8");
    }

    /// The buffer-claim read-back's comparison (#427): a format another
    /// process retargeted between the caller's S_FMT and this handle's
    /// REQBUFS must be named field-by-field, and an unchanged one must pass.
    /// The race itself needs a second process and real queue ownership, so
    /// the DECISION is what carries the coverage. Quantization and stride
    /// are asserted by name: the Codex round on this change showed a
    /// same-geometry quantization flip moves the clipping ceiling that the
    /// exposure refusal reads (235 versus 255), and a stride change decodes
    /// every row at the wrong offset, so those two are the fields a
    /// geometry-only guard would have waved through.
    #[test]
    fn format_moved_names_the_field_that_moved_and_passes_a_match() {
        use v4l::{Format, FourCC};
        let expect = Format::new(640, 400, FourCC::new(b"GREY"));
        assert_eq!(format_moved(&expect, &expect), None);

        let refourcc = format_moved(&expect, &Format::new(640, 400, FourCC::new(b"YUYV")))
            .expect("a changed fourcc must refuse");
        assert!(
            refourcc.contains("YUYV") && refourcc.contains("GREY"),
            "{refourcc}"
        );

        let resized = format_moved(&expect, &Format::new(1280, 720, FourCC::new(b"GREY")))
            .expect("a changed size must refuse");
        assert!(
            resized.contains("1280x720") && resized.contains("640x400"),
            "{resized}"
        );

        let mut requantized = expect;
        requantized.quantization = v4l::format::quantization::Quantization::LimitedRange;
        if requantized.quantization as u32 == expect.quantization as u32 {
            requantized.quantization = v4l::format::quantization::Quantization::FullRange;
        }
        let msg = format_moved(&expect, &requantized)
            .expect("a changed quantization must refuse: it moves the clipping ceiling");
        assert!(msg.contains("quantization"), "{msg}");

        let mut restrided = expect;
        restrided.stride = expect.stride + 64;
        let msg = format_moved(&expect, &restrided)
            .expect("a changed stride must refuse: rows would decode at wrong offsets");
        assert!(msg.contains("stride"), "{msg}");

        let mut recolored = expect;
        recolored.colorspace = v4l::format::colorspace::Colorspace::SRGB;
        if recolored.colorspace as u32 == expect.colorspace as u32 {
            recolored.colorspace = v4l::format::colorspace::Colorspace::Rec709;
        }
        let msg = format_moved(&expect, &recolored).expect("a changed colorspace must refuse");
        assert!(msg.contains("colorspace"), "{msg}");
    }

    #[test]
    fn nv12_neutral_chroma_is_grey_and_short_buffer_is_safe() {
        // 2x2 Y plane at 200, one neutral UV pair (128,128) -> near-grey 200.
        let nv12 = [200u8, 200, 200, 200, 128, 128];
        let rgb = nv12_to_rgb(&nv12, 2, 2);
        assert_eq!(rgb.len(), 2 * 2 * 3);
        for c in &rgb {
            assert!(
                (*c as i32 - 200).abs() <= 1,
                "neutral chroma should stay grey"
            );
        }
        // Chroma carries into RGB: a red-ish V lifts R above Y and drops B.
        let red = [128u8, 128, 128, 128, 128, 200];
        let out = nv12_to_rgb(&red, 2, 2);
        assert!(out[0] > out[2], "V>128 should make R exceed B");
        // A short buffer never panics; returns a zeroed frame of the right size.
        let short = [0u8; 3];
        assert_eq!(nv12_to_rgb(&short, 2, 2).len(), 2 * 2 * 3);
    }

    #[test]
    fn physical_camera_path_accepts_real_rejects_virtual() {
        // Real built-in USB camera (verified on the reference Zenbook).
        assert!(is_physical_camera_path(
            "/sys/devices/pci0000:00/0000:00:14.0/usb3/3-5/3-5:1.0"
        ));
        // A discrete/MIPI camera under PCI is still physical.
        assert!(is_physical_camera_path(
            "/sys/devices/pci0000:00/0000:00:1f.6/cam0"
        ));
        // v4l2loopback / OBS virtual cameras, the injection vector, are rejected.
        assert!(!is_physical_camera_path(
            "/sys/devices/platform/v4l2loopback-000/video4linux/video0"
        ));
        assert!(!is_physical_camera_path(
            "/sys/devices/virtual/video4linux/video0"
        ));
    }

    #[test]
    fn yuyv_full_and_zero_luma_hit_the_clamps() {
        // Y=255 neutral chroma -> white (clamped at 255); Y=0 -> black.
        let white = yuyv_to_rgb(&[255, 128, 255, 128], 2, 1);
        assert_eq!(white, vec![255; 6]);
        let black = yuyv_to_rgb(&[0, 128, 0, 128], 2, 1);
        assert_eq!(black, vec![0; 6]);
    }

    #[test]
    fn yuyv_chroma_maps_to_the_right_channels() {
        // High U (blue-difference) with neutral V: blue saturates, red stays at
        // luma, green dips below it (BT.601: b=y+1.772u, g=y-0.344u).
        let rgb = yuyv_to_rgb(&[128, 255, 128, 128], 2, 1);
        let (r, g, b) = (rgb[0], rgb[1], rgb[2]);
        assert_eq!(b, 255);
        assert_eq!(r, 128);
        assert!(g < 128, "green must dip under +U, got {g}");
        // High V (red-difference): red saturates, blue stays at luma.
        let rgb = yuyv_to_rgb(&[128, 128, 128, 255], 2, 1);
        assert_eq!(rgb[0], 255);
        assert_eq!(rgb[2], 128);
    }

    #[test]
    fn yuyv_short_buffer_converts_what_exists_and_zero_fills() {
        // 4x2 frame needs 16 YUYV bytes; give only 4 (one pixel pair). The
        // output is still full-sized, with the missing pixels left black.
        let rgb = yuyv_to_rgb(&[128, 128, 128, 128], 4, 2);
        assert_eq!(rgb.len(), 4 * 2 * 3);
        assert!(rgb[..6].iter().all(|&c| (c as i32 - 128).abs() <= 1));
        assert!(rgb[6..].iter().all(|&c| c == 0));
    }

    #[test]
    fn yuyv_odd_pixel_count_drops_the_unpaired_tail() {
        // 3x1: pairs = 3/2 = 1, so pixels 0-1 convert and pixel 2 stays black
        // even though input bytes for it exist.
        let rgb = yuyv_to_rgb(&[128, 128, 128, 128, 128, 128], 3, 1);
        assert_eq!(rgb.len(), 9);
        assert!(rgb[..6].iter().all(|&c| (c as i32 - 128).abs() <= 1));
        assert_eq!(&rgb[6..], &[0, 0, 0]);
    }

    #[test]
    fn grey_to_rgb_replicates_each_sample() {
        assert_eq!(
            grey_to_rgb(&[0, 128, 255]),
            vec![0, 0, 0, 128, 128, 128, 255, 255, 255]
        );
        assert!(grey_to_rgb(&[]).is_empty());
    }

    #[test]
    fn median_frame_even_burst_takes_upper_middle_and_min_length() {
        // Even burst: sorted [1,2,3,4] -> index 4/2 = 2 -> 3 (upper middle).
        let frames = vec![frame(&[1]), frame(&[4]), frame(&[2]), frame(&[3])];
        assert_eq!(median_frame(frames).data, vec![3]);
        // Mixed-length burst: output truncates to the shortest frame, and the
        // dimensions/spectrum come from the first frame.
        let frames = vec![frame(&[9, 9, 9]), frame(&[5, 5]), frame(&[7, 7, 7])];
        let m = median_frame(frames);
        assert_eq!(m.data, vec![7, 7]);
        assert_eq!((m.width, m.height, m.spectrum), (3, 1, Spectrum::Rgb));
    }

    #[test]
    fn ir_mean_handles_empty_and_averages() {
        assert_eq!(ir_probe::mean(&[]), 0.0);
        assert_eq!(ir_probe::mean(&[0, 255]), 127.5);
        assert_eq!(ir_probe::mean(&[10, 10, 10]), 10.0);
    }

    #[test]
    fn center_border_ratio_separates_lit_subject_from_flat_scene() {
        let (w, h) = (8u32, 8u32);
        // Emitter-lit subject: center 4x4 at 200, border at 50 -> ratio 4.
        let mut lit = vec![50u8; (w * h) as usize];
        for y in 2..6 {
            for x in 2..6 {
                lit[(y * w + x) as usize] = 200;
            }
        }
        assert!((ir_probe::center_border_ratio(&lit, w, h) - 4.0).abs() < 1e-9);
        // Uniform scene -> ~1 (no subject emphasis).
        let flat = vec![100u8; (w * h) as usize];
        assert!((ir_probe::center_border_ratio(&flat, w, h) - 1.0).abs() < 1e-9);
        // Degenerate inputs: short buffer, tiny dims, all-black border.
        assert_eq!(ir_probe::center_border_ratio(&[1, 2, 3], w, h), 0.0);
        assert_eq!(ir_probe::center_border_ratio(&flat, 2, 2), 0.0);
        assert_eq!(ir_probe::center_border_ratio(&[0u8; 64], 8, 8), 0.0);
    }

    #[test]
    fn frame_signature_is_sparse_and_content_sensitive() {
        // Short frames: the whole content is the signature.
        assert_eq!(frame_signature(&[1, 2, 3]), vec![1, 2, 3]);
        // Long frames: capped at 64 sampled bytes.
        let long = vec![7u8; 640 * 400];
        let sig = frame_signature(&long);
        assert_eq!(sig.len(), 64);
        assert!(sig.iter().all(|&b| b == 7));
        // Identical content -> identical signature; a change at a sampled
        // position (index 0 is always sampled) -> different signature.
        let mut changed = long.clone();
        changed[0] = 8;
        assert_eq!(frame_signature(&long), sig);
        assert_ne!(frame_signature(&changed), sig);
    }

    #[test]
    fn frozen_detector_fires_only_on_repeated_normal_exposure_frames() {
        let sig = frame_signature(&[99u8; 1024]);
        // First frame of a window (no previous signature): never frozen.
        assert!(!frame_frozen(99.0, &sig, None));
        // Bit-identical consecutive mid-grey frames: frozen.
        assert!(frame_frozen(99.0, &sig, Some(&sig)));
        // Same signature but saturated / near-black mean: optical state, not a
        // stall (exposure blow-out or the emitter-off strobe phase).
        assert!(!frame_frozen(250.0, &sig, Some(&sig)));
        assert!(!frame_frozen(245.0, &sig, Some(&sig)));
        assert!(!frame_frozen(5.0, &sig, Some(&sig)));
        // Boundary means inside the band still count.
        assert!(frame_frozen(10.0, &sig, Some(&sig)));
        // Different content -> live stream.
        let other = frame_signature(&[98u8; 1024]);
        assert!(!frame_frozen(99.0, &sig, Some(&other)));
    }

    #[test]
    fn map_io_translates_busy_permission_and_generic_errors() {
        // EBUSY (16) on a device nothing holds: generic busy guidance.
        let e = map_io(
            "/dev/irlume-test-missing",
            std::io::Error::from_raw_os_error(16),
        );
        let msg = e.to_string();
        assert!(msg.contains("camera busy"), "{msg}");
        assert!(msg.contains("another app is using it"), "{msg}");
        // Permission denied: the video-group hint.
        let e = map_io(
            "/dev/irlume-test-missing",
            std::io::Error::from(std::io::ErrorKind::PermissionDenied),
        );
        assert!(e.to_string().contains("'video' group"), "{e}");
        // Anything else: device-prefixed passthrough. EPROTO here, because
        // EIO grew its own signature arm (#340) and no longer passes through
        // bare.
        let e = map_io(
            "/dev/irlume-test-missing",
            std::io::Error::from_raw_os_error(libc::EPROTO),
        );
        assert_eq!(
            e.to_string(),
            format!(
                "hardware: /dev/irlume-test-missing: {}",
                std::io::Error::from_raw_os_error(libc::EPROTO)
            ),
        );
    }

    /// The stream-relevant errnos get guidance without blame (#340 review):
    /// map_io has no operation context and the kernel reuses these errnos
    /// across paths, so the message must say what the errno covers and point
    /// at the kernel log, never convict "firmware" or "the bus" on the errno
    /// alone.
    #[test]
    fn map_io_treats_ambiguous_errnos_as_search_keys_not_verdicts() {
        let einval = map_io(
            "/dev/irlume-test-missing",
            std::io::Error::from_raw_os_error(libc::EINVAL),
        )
        .to_string();
        assert!(
            einval.contains("does not distinguish a firmware refusal from invalid format metadata"),
            "{einval}"
        );
        assert!(einval.contains("dmesg"), "{einval}");
        for errno in [libc::EIO, libc::ENOSPC] {
            let msg = map_io(
                "/dev/irlume-test-missing",
                std::io::Error::from_raw_os_error(errno),
            )
            .to_string();
            assert!(msg.contains("USB bandwidth admission"), "{msg}");
            assert!(msg.contains("Check the matching kernel log line"), "{msg}");
        }
    }

    /// Holding the node ourselves is reported as OUR defect, not as an app the
    /// user should go and close.
    ///
    /// This test previously asserted the opposite, that the scan names this
    /// process, and that is exactly what shipped: measured 2026-08-03 with a
    /// browser streaming /dev/video0, irlume opened the node, `S_FMT` failed
    /// EBUSY, and the error told the user the camera was "in use by irlumed"
    /// while the real holder was Chrome. #187 spent days restarting the daemon
    /// on the strength of that sentence.
    /// The verdict a scan reaches when it found no other holder. The blind case
    /// must not resolve to either confident answer: measured 2026-08-03 with
    /// Chrome streaming /dev/video0, the scan saw only irlume's own fd because
    /// Chrome's fd directory was unreadable, and reporting that as "only us"
    /// accuses irlume of a bug on the strength of a blind spot. Before this,
    /// the same scan reported "in use by irlumed", which is what #187 acted on.
    #[test]
    fn a_blind_scan_never_resolves_to_a_confident_holder() {
        assert!(matches!(holder_verdict(true, false), Holders::SelfOnly));
        assert!(matches!(holder_verdict(false, false), Holders::None));
        assert!(matches!(holder_verdict(true, true), Holders::UnknownBlind));
        assert!(matches!(holder_verdict(false, true), Holders::UnknownBlind));
    }

    /// What the user is told for each verdict. Only a real other process is
    /// ever presented as something to close.
    #[test]
    fn only_another_process_is_presented_as_closeable() {
        let dir = std::env::temp_dir().join(format!("irlume-cam-holder-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("held");
        std::fs::write(&path, b"x").unwrap();
        let _held = std::fs::File::open(&path).unwrap();

        // This test runs unprivileged, so the scan cannot read every process
        // and must decline to name anyone rather than blame irlume.
        let who = camera_holder(path.to_str().unwrap());
        if let Some(who) = &who {
            assert!(
                !who.contains("bug in irlume"),
                "a scan with blind spots must not accuse irlume: {who}"
            );
        }

        // Nothing holds a nonexistent path.
        assert_eq!(camera_holder("/dev/irlume-test-missing"), None);
        drop(_held);
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// Another process holding the node wins over our own handle, because that
    /// is the one the user can act on. Both hold it here, which is the
    /// real-world case: irlume opens the device, `S_FMT` fails because someone
    /// else is streaming, and the scan then sees two holders.
    #[test]
    fn another_process_outranks_our_own_hold() {
        // Held for the SPAWN, not for any environment variable: the fork below
        // copies this process's whole fd table, so between fork and exec the
        // child holds every flock any concurrently-running test has open. That
        // made an unrelated stream-lock test see `Busy` from a lock nothing
        // held (#251). The crate lock is the only serialisation point that
        // covers process-global state, and the fd table is process-global.
        let _guard = crate::testenv::env_lock();
        let dir = std::env::temp_dir().join(format!("irlume-cam-two-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("held");
        std::fs::write(&path, b"x").unwrap();

        // We hold it...
        let _mine = std::fs::File::open(&path).unwrap();
        // ...and so does a child that outlives the scan.
        let mut other = std::process::Command::new("sleep")
            .arg("30")
            .stdin(std::process::Stdio::from(
                std::fs::File::open(&path).unwrap(),
            ))
            .spawn()
            .expect("spawn holder");

        let who = camera_holder(path.to_str().unwrap()).expect("holder found");
        let verdict = format!("holder was: {who}");
        let _ = other.kill();
        let _ = other.wait();
        drop(_mine);
        let _ = std::fs::remove_dir_all(&dir);

        assert!(
            who.contains(&format!("pid {}", other.id())),
            "the OTHER process is the actionable holder; {verdict}"
        );
    }

    #[test]
    fn verify_pinned_rejects_missing_and_non_sysfs_devices() {
        // `verify_pinned` reads IRLUME_TEST_ALLOW_VIRTUAL_CAMERA / IRLUME_CAMERA_*;
        // hold the same lock the env-setting tests take, and clear those vars, so
        // a concurrent setter cannot flip the verdict mid-assertion (this test
        // otherwise passes alone but flakes under full-workspace parallelism).
        let _lock = env_lock();
        let _a = EnvGuard::unset("IRLUME_TEST_ALLOW_VIRTUAL_CAMERA");
        let _b = EnvGuard::unset("IRLUME_CAMERA_PIN");
        let _c = EnvGuard::unset("IRLUME_CAMERA_REQUIRE_FIXED");
        // No node at all: the plain no-camera error, not the injection one.
        let e = verify_pinned("/dev/irlume-test-missing").unwrap_err();
        assert!(e.to_string().contains("no camera found"), "{e}");
        // An existing node with no video4linux sysfs entry (a non-camera): the
        // anti-injection refusal.
        let e = verify_pinned("/dev/null").unwrap_err();
        assert!(e.to_string().contains("no physical device in sysfs"), "{e}");
    }

    #[test]
    fn capture_entrypoints_refuse_a_missing_device_before_any_io() {
        // Every capture path front-doors through verify_pinned, so a missing
        // node fails fast with the same actionable error and no V4L2 calls.
        for r in [
            capture_rgb("/dev/irlume-test-missing")
                .err()
                .map(|e| e.to_string()),
            capture_ir("/dev/irlume-test-missing")
                .err()
                .map(|e| e.to_string()),
            capture_ir_sequence("/dev/irlume-test-missing", 1, 1)
                .err()
                .map(|e| e.to_string()),
            ir_probe::capture_raw_burst("/dev/irlume-test-missing", 1)
                .err()
                .map(|e| e.to_string()),
            setup_ir_emitter("/dev/irlume-test-missing")
                .err()
                .map(|e| e.to_string()),
            list_ir_controls("/dev/irlume-test-missing")
                .err()
                .map(|e| e.to_string()),
        ] {
            let msg = r.expect("must fail without a device");
            assert!(msg.contains("no camera found"), "{msg}");
        }
    }

    #[test]
    fn device_identity_absent_for_non_usb_nodes() {
        assert_eq!(device_identity("/dev/null"), None);
        assert_eq!(device_identity("/dev/irlume-test-missing"), None);
    }

    #[test]
    fn role_classification_covers_the_grey16_family() {
        use super::role_from_formats;
        // Native 8-bit IR node.
        assert_eq!(role_from_formats(&[*b"GREY"]), Role::Ir);
        // 16-bit grey IR nodes previously fell to Other (convenience demotion).
        assert_eq!(role_from_formats(&[*b"Y16 "]), Role::Ir);
        assert_eq!(role_from_formats(&[*b"Y10 "]), Role::Ir);
        assert_eq!(role_from_formats(&[*b"Y12 "]), Role::Ir);
        // Colour still wins (an RGB cam also advertising grey is an RGB cam).
        assert_eq!(role_from_formats(&[*b"YUYV", *b"GREY"]), Role::Rgb);
        assert_eq!(role_from_formats(&[*b"NV12"]), Role::Rgb);
        // Metadata/unknown-only nodes stay Other.
        assert_eq!(role_from_formats(&[*b"UVCM"]), Role::Other);
        assert_eq!(role_from_formats(&[]), Role::Other);
    }

    #[test]
    fn grey16_conversion_estimates_effective_depth() {
        use super::{grey16_shift, grey16_to_8_at};
        fn grey16_to_8(buf: &[u8]) -> Vec<u8> {
            grey16_to_8_at(buf, grey16_shift(buf))
        }
        // True 16-bit data: high byte survives (0xAB00 → 0xAB).
        let full: Vec<u8> = [0xCDu16, 0xAB00, 0xFFFF]
            .iter()
            .flat_map(|v| v.to_le_bytes())
            .collect();
        assert_eq!(grey16_to_8(&full), vec![0x00, 0xAB, 0xFF]);
        // 10-bit-in-Y16 (V4L2 allows lower precision, LSB-aligned): values
        // 0..1023 must map onto 0..255, not collapse to near-black.
        let ten: Vec<u8> = [0u16, 256, 512, 1023]
            .iter()
            .flat_map(|v| v.to_le_bytes())
            .collect();
        assert_eq!(grey16_to_8(&ten), vec![0, 64, 128, 255]);
        // 8-bit-or-less data passes through unshifted.
        let eight: Vec<u8> = [0u16, 128, 255]
            .iter()
            .flat_map(|v| v.to_le_bytes())
            .collect();
        assert_eq!(grey16_to_8(&eight), vec![0, 128, 255]);
        // Empty and odd-length buffers do not panic; the odd byte is ignored.
        assert!(grey16_to_8(&[]).is_empty());
        assert_eq!(grey16_to_8(&[0x40, 0x00, 0x7F]), vec![0x40]);
    }

    // The IR path picks the lit strobe frame and the ambient floor by comparing
    // frame MEANS, so every frame of one session must share a scale. Deriving
    // the shift per frame made a single bright pixel rescale the whole frame:
    // here the second frame is physically identical to the first except for one
    // hot sample, and a per-frame shift would report it as half as bright.
    #[test]
    fn ir_decoder_holds_the_y16_scale_across_a_session() {
        use super::{IrDecoder, IrPixel};
        let words = |v: &[u16]| -> Vec<u8> { v.iter().flat_map(|w| w.to_le_bytes()).collect() };
        let first = words(&[0, 256, 512, 1023]); // 10-bit: shift 2
        let with_hot_pixel = words(&[0, 256, 512, 2047]); // one 11-bit sample

        let mut session = IrDecoder::new(IrPixel::Grey16, Quantization::Default);
        let a = session.decode(&first, 2, 2);
        let b = session.decode(&with_hot_pixel, 2, 2);
        assert_eq!(a, vec![0, 64, 128, 255]);
        // Same scale: the unchanged samples decode to the SAME bytes.
        assert_eq!(&b[..3], &a[..3]);

        // A fresh session re-estimates, so a genuinely deeper feed still maps
        // onto the full range instead of clipping forever.
        let mut next = IrDecoder::new(IrPixel::Grey16, Quantization::Default);
        assert_eq!(next.decode(&with_hot_pixel, 2, 2), vec![0, 32, 64, 255]);

        // 8-bit formats carry no scale and are untouched by the session state.
        let mut grey8 = IrDecoder::new(IrPixel::Grey8, Quantization::Default);
        assert_eq!(grey8.decode(&[9, 9], 1, 2), vec![9, 9]);
    }

    #[test]
    fn decode_ir_extracts_luma_from_packed_containers() {
        use super::{decode_ir, IrPixel};
        // Grey8: byte-for-byte passthrough.
        assert_eq!(
            decode_ir(&[1, 2, 3, 4], IrPixel::Grey8, 2, 2),
            vec![1, 2, 3, 4]
        );
        // NV12 (2x2): 4 luma bytes then interleaved UV; only luma survives.
        assert_eq!(
            decode_ir(&[10, 20, 30, 40, 128, 128], IrPixel::Nv12Luma, 2, 2),
            vec![10, 20, 30, 40]
        );
        // YUYV (2 px): Y0 U Y1 V → the even bytes.
        assert_eq!(
            decode_ir(&[90, 0, 91, 0], IrPixel::YuyvLuma, 2, 1),
            vec![90, 91]
        );
        // Grey16 goes through the depth-estimating converter.
        let buf: Vec<u8> = [1023u16, 0].iter().flat_map(|v| v.to_le_bytes()).collect();
        assert_eq!(decode_ir(&buf, IrPixel::Grey16, 2, 1), vec![255, 0]);
    }

    #[test]
    fn ir_candidates_prefer_native_grey_then_grey16_then_luma() {
        use super::{IrPixel, IR_CANDIDATES};
        let order: Vec<IrPixel> = IR_CANDIDATES.iter().map(|(_, p)| *p).collect();
        let first_grey16 = order.iter().position(|p| *p == IrPixel::Grey16).unwrap();
        let last_grey8 = order.iter().rposition(|p| *p == IrPixel::Grey8).unwrap();
        let first_luma = order
            .iter()
            .position(|p| matches!(p, IrPixel::Nv12Luma | IrPixel::YuyvLuma))
            .unwrap();
        assert!(last_grey8 < first_grey16, "native grey must be tried first");
        assert!(first_grey16 < first_luma, "grey16 before luma extraction");
    }

    #[test]
    fn nonblank_treats_empty_and_whitespace_as_absent() {
        assert_eq!(nonblank(None), None);
        assert_eq!(nonblank(Some(String::new())), None);
        assert_eq!(nonblank(Some("  ".into())), None);
        assert_eq!(
            nonblank(Some(" 3277:0059:abc ".into())),
            Some("3277:0059:abc".into())
        );
    }

    #[test]
    fn resolve_saved_pair_without_ids_keeps_legacy_path_behaviour() {
        // No recorded identities (a pin written by a pre-identity version): both
        // nodes present -> trust the saved paths unchanged.
        assert_eq!(
            resolve_saved_pair("/dev/null", "/dev/zero", None, None),
            Some(("/dev/null".to_string(), "/dev/zero".to_string()))
        );
        // A missing node with no identity -> fall through to auto-discovery.
        assert_eq!(
            resolve_saved_pair("/dev/irlume-gone0", "/dev/zero", None, None),
            None
        );
    }

    #[test]
    fn resolve_saved_pair_with_unmatched_ids_falls_through() {
        // Identities recorded, but the saved nodes carry no USB descriptor
        // (device_identity -> None) and no discovered node matches the bogus
        // ids: resolve re-searches by identity, finds nothing, and returns None
        // so select_pair falls through to auto-discovery instead of opening the
        // wrong sensor. Exercises the identity branch and find_node_by_identity.
        assert_eq!(
            resolve_saved_pair(
                "/dev/null",
                "/dev/zero",
                Some("dead:beef:rgb"),
                Some("dead:beef:ir")
            ),
            None
        );
        // A bogus identity never matches a real node either.
        assert_eq!(find_node_by_identity("dead:beef:none", Role::Ir), None);
    }

    #[test]
    fn classify_unreadable_or_non_video_nodes_as_other() {
        assert_eq!(classify("/dev/irlume-test-missing"), Role::Other);
        // /dev/null opens but answers no V4L2 format ioctls.
        assert_eq!(classify("/dev/null"), Role::Other);
    }

    #[test]
    fn find_attr_dir_walks_up_only_inside_sysfs() {
        let dir = std::env::temp_dir().join(format!("irlume-attr-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let leaf = dir.join("iface");
        std::fs::create_dir_all(&leaf).unwrap();
        // Attribute in the start dir itself: found immediately.
        std::fs::write(leaf.join("idVendor"), "3277").unwrap();
        assert_eq!(find_attr_dir(&leaf, "idVendor"), Some(leaf.clone()));
        // Attribute only above a non-/sys/devices start: the walk refuses to
        // escape sysfs and gives up (anti-confusion guard).
        std::fs::write(dir.join("removable"), "fixed").unwrap();
        assert_eq!(find_attr_dir(&leaf, "removable"), None);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn read_vidpid_formats_descriptor_files() {
        let dir = std::env::temp_dir().join(format!("irlume-vidpid-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        // Missing descriptors -> None.
        assert_eq!(read_vidpid(&dir), None);
        std::fs::write(dir.join("idVendor"), "3277\n").unwrap();
        assert_eq!(read_vidpid(&dir), None); // product still missing
        std::fs::write(dir.join("idProduct"), "0059\n").unwrap();
        assert_eq!(read_vidpid(&dir), Some("3277:0059".into()));
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn select_pair_env_override_wins() {
        // The explicit env pair short-circuits discovery entirely (no device
        // scan), so this is deterministic on any machine.
        let _lock = env_lock();
        let _r = EnvGuard::set("IRLUME_RGB_DEVICE", "/dev/irlume-test-rgb");
        let _i = EnvGuard::set("IRLUME_IR_DEVICE", "/dev/irlume-test-ir");
        assert_eq!(
            select_pair(),
            ("/dev/irlume-test-rgb".into(), "/dev/irlume-test-ir".into())
        );
    }

    #[test]
    fn node_backend_errors_off_the_video_class() {
        // Missing nodes and non-V4L2 paths are observation FAILURES, reported
        // as Err for the caller to render, never a silent nothing.
        assert!(node_backend("/dev/irlume-test-missing").is_err());
        assert!(node_backend("/dev/null").is_err());
        assert!(node_backend("not-even-a-dev-path").is_err());
    }

    /// The positive split: the classification comes from the V4L2 bus string's
    /// specified `usb-` prefix, not from path text (#195 review — the first
    /// version's only test observed nothing but negatives and passed against
    /// an implementation that always answered nothing).
    #[test]
    fn backend_splits_on_the_specified_bus_prefix() {
        assert_eq!(
            backend_from_caps("uvcvideo".into(), "usb-0000:00:14.0-5"),
            ("uvcvideo".into(), true)
        );
        assert_eq!(
            backend_from_caps("intel-ipu6".into(), "platform:intel-ipu6"),
            ("intel-ipu6".into(), false)
        );
        // A bus merely CONTAINING usb is not the specified prefix.
        assert_eq!(
            backend_from_caps("gadget".into(), "platform:dummy_usb"),
            ("gadget".into(), false)
        );
    }

    #[test]
    fn privacy_engaged_is_false_without_a_camera() {
        // Missing node or a non-V4L2 node: the check degrades to "not engaged"
        // (the capture path then surfaces the real error).
        assert!(!privacy_engaged("/dev/irlume-test-missing"));
        assert!(!privacy_engaged("/dev/null"));
    }

    /// The setup decision fails CLOSED: an engaged shutter refuses, and a
    /// FAILED observation refuses too, because "could not read the switch" is
    /// not "the switch is released" (#193 review). Only an answered "released"
    /// or a camera without the control proceeds to a firmware write.
    #[test]
    fn privacy_setup_decision_fails_closed() {
        let engaged =
            privacy_permits_setup(Ok(Some(true))).expect_err("an engaged shutter must refuse");
        assert!(engaged.contains("shutter is engaged"), "{engaged}");
        let unreadable = privacy_permits_setup(Err(std::io::Error::from_raw_os_error(libc::EIO)))
            .expect_err("an unreadable shutter must refuse, not read as released");
        assert!(unreadable.contains("could not read"), "{unreadable}");
        assert!(privacy_permits_setup(Ok(Some(false))).is_ok());
        assert!(privacy_permits_setup(Ok(None)).is_ok());
    }

    /// The two backlight-compensation decisions (#426), every arm. The write
    /// only fires on an answered control holding something other than the
    /// wanted value, so an unreadable or absent control is never written
    /// blind and another writer's 2 is never adopted as irlume's to undo;
    /// the restore only fires while the control still holds irlume's value,
    /// so a mid-session change by someone else is left alone.
    #[test]
    fn backlight_compensation_decisions_cover_every_arm() {
        let ctrl = |v: i64| {
            Ok(v4l::control::Control {
                id: V4L2_CID_BACKLIGHT_COMPENSATION,
                value: v4l::control::Value::Integer(v),
            })
        };
        let err = || Err(std::io::Error::from_raw_os_error(libc::EINVAL));

        assert_eq!(
            blc_write_decision(ctrl(0)),
            Some(0),
            "a default control is written, displacing 0"
        );
        assert_eq!(
            blc_write_decision(ctrl(1)),
            Some(1),
            "a user's 1 is displaced and remembered"
        );
        assert_eq!(
            blc_write_decision(ctrl(BLC_WANTED)),
            None,
            "an already-wanted value is another writer's state"
        );
        assert_eq!(
            blc_write_decision(err()),
            None,
            "an unreadable control is not a license to write"
        );

        assert_eq!(
            blc_restore_decision(0, ctrl(BLC_WANTED)),
            Some(0),
            "our value still held: put the displaced one back"
        );
        assert_eq!(
            blc_restore_decision(0, ctrl(1)),
            None,
            "the control moved: somebody else's newer choice stays"
        );
        assert_eq!(
            blc_restore_decision(0, err()),
            None,
            "an unreadable control authorises nothing"
        );
    }

    /// Only the errnos the V4L2 specification assigns to "this control does
    /// not exist" (EINVAL for an unsupported id, ENOTTY for a device without
    /// the ioctl) read as absence; an IO failure or a vanished device must not.
    #[test]
    fn only_specified_errnos_mean_the_control_is_absent() {
        assert!(control_read_failure_means_absent(
            &std::io::Error::from_raw_os_error(libc::EINVAL)
        ));
        assert!(control_read_failure_means_absent(
            &std::io::Error::from_raw_os_error(libc::ENOTTY)
        ));
        assert!(!control_read_failure_means_absent(
            &std::io::Error::from_raw_os_error(libc::EIO)
        ));
        assert!(!control_read_failure_means_absent(
            &std::io::Error::from_raw_os_error(libc::ENODEV)
        ));
        assert!(!control_read_failure_means_absent(&std::io::Error::other(
            "no errno at all"
        )));
    }

    #[test]
    fn pin_allowlist_parses_multi_camera_set() {
        // Single camera.
        assert_eq!(
            parse_pin_allowlist("3277:0059"),
            Some(vec!["3277:0059".into()])
        );
        // Built-in + external Brio, with spacing/case normalized.
        assert_eq!(
            parse_pin_allowlist(" 3277:0059, 046D:085E "),
            Some(vec!["3277:0059".into(), "046d:085e".into()])
        );
        // Empty / unset → no pin (physical-bus check still applies).
        assert_eq!(parse_pin_allowlist(""), None);
        assert_eq!(parse_pin_allowlist("  ,  "), None);
    }

    // ---- v4l2loopback harness tests -----------------------------------
    // Env-gated: CI loads v4l2loopback, feeds the nodes with ffmpeg test
    // patterns (YUYV 640x480 / GREY 640x400), and exports the two vars.
    // Without them the tests return immediately (and are #[ignore]d anyway).
    // A THIRD node, IRLUME_TEST_SPARE_DEVICE, has NO CI-side feeder: tests
    // that need a specific pattern (static for the frozen-stream detector,
    // alternating for strobe pairing) spawn their own ffmpeg against it and
    // kill the child on drop. Spare-node tests own that node exclusively;
    // CI runs the gated suite with --test-threads=1.

    /// The loopback device pair, or a panic.
    ///
    /// Deliberately not an Option that callers skip on. These tests are
    /// `#[ignore]`d, so selecting one is a request for the harness, and a test
    /// that returns on its first line still prints `ok`. The CI lane guards
    /// them with `--min`, which counts passes, so a missing `env:` key would
    /// have turned 23 tests into no-ops while the lane stayed green forever
    /// (#361). The same argument is already written down at
    /// `irlume-core/src/tpm.rs`: a test that reports success without observing
    /// the hardware it is named for is worse than no test.
    fn loopback_pair() -> (String, String) {
        let var = |k: &str| {
            std::env::var(k).unwrap_or_else(|_| {
                panic!(
                    "{k} is unset. This test is #[ignore]d, so running it is a request for the \
                     v4l2loopback harness; it will not silently pass without one."
                )
            })
        };
        (var("IRLUME_TEST_RGB_DEVICE"), var("IRLUME_TEST_IR_DEVICE"))
    }

    /// The spare node, or a panic. Same rule as `loopback_pair` (#361): an
    /// `#[ignore]`d test that returns early still prints `ok` and still counts
    /// toward the lane's `--min` pass total.
    fn spare_device() -> String {
        std::env::var("IRLUME_TEST_SPARE_DEVICE").unwrap_or_else(|_| {
            panic!(
                "IRLUME_TEST_SPARE_DEVICE is unset. This test is #[ignore]d, so running it is a \
                 request for the v4l2loopback harness; it will not silently pass without one."
            )
        })
    }

    // The lock and the guard live in `crate::testenv` so every env-mutating
    // test in this crate contends on ONE mutex. They used to be private here,
    // which serialised this module against itself and left it racing the
    // `ir_emitter` tests that flip a different variable in the same process.
    use crate::testenv::{env_lock, EnvGuard};

    /// Extend the exact-path virtual-camera escape with `device` for the
    /// test's lifetime (`verify_pinned` refuses loopback nodes otherwise),
    /// preserving whatever allowlist the harness already exported. Caller
    /// must hold `env_lock`.
    fn allow_virtual(device: &str) -> EnvGuard {
        const KEY: &str = "IRLUME_TEST_ALLOW_VIRTUAL_CAMERA";
        let val = match std::env::var(KEY) {
            Ok(p) if !p.trim().is_empty() => format!("{p},{device}"),
            _ => device.to_string(),
        };
        EnvGuard::set(KEY, &val)
    }

    /// A self-managed ffmpeg feed into the spare loopback node. Killed and
    /// reaped on drop, so even a panicking test never leaks a feeder into the
    /// next spare-node scenario.
    struct FfmpegFeeder(std::process::Child);

    impl FfmpegFeeder {
        /// Feed `device` GREY frames from a lavfi source description (the IR
        /// node format). ffmpeg exists wherever the loopback env is set (a
        /// harness guarantee; the CI-fed nodes use the same binary).
        fn spawn(device: &str, lavfi: &str) -> Self {
            let child = std::process::Command::new("ffmpeg")
                .args([
                    "-hide_banner",
                    "-loglevel",
                    "error",
                    "-re",
                    "-f",
                    "lavfi",
                    "-i",
                    lavfi,
                    "-pix_fmt",
                    "gray",
                    "-f",
                    "v4l2",
                    device,
                ])
                .stdin(std::process::Stdio::null())
                .spawn()
                .expect("spawn ffmpeg feeder");
            let mut feeder = FfmpegFeeder(child);
            // Let it attach to the node, and fail loudly if it exited (bad
            // filter graph / device): a capture against an unfed loopback
            // node blocks indefinitely, which would present as a test hang.
            for _ in 0..20 {
                std::thread::sleep(std::time::Duration::from_millis(100));
                if let Some(status) = feeder.0.try_wait().expect("poll feeder") {
                    panic!("ffmpeg feeder exited early ({status}); lavfi source: {lavfi}");
                }
            }
            feeder
        }
    }

    impl Drop for FfmpegFeeder {
        fn drop(&mut self) {
            let _ = self.0.kill();
            let _ = self.0.wait();
        }
    }

    #[test]
    #[ignore = "needs v4l2loopback feeder nodes; set IRLUME_TEST_RGB_DEVICE/IRLUME_TEST_IR_DEVICE (CI does this)"]
    fn loopback_rgb_burst_streams_and_converts() {
        let (rgb, _) = loopback_pair();
        let frames = capture_rgb_burst(&rgb, 3).expect("rgb burst");
        assert_eq!(frames.len(), 3);
        for f in &frames {
            assert_eq!((f.width, f.height), (RGB_W, RGB_H));
            assert_eq!(f.spectrum, Spectrum::Rgb);
            assert_eq!(f.data.len(), (RGB_W * RGB_H * 3) as usize);
            let (min, max) = f
                .data
                .iter()
                .fold((u8::MAX, u8::MIN), |(lo, hi), &b| (lo.min(b), hi.max(b)));
            assert!(max > min, "a test pattern must not convert to a flat frame");
        }
    }

    /// `IrSession::recover` must hand back a session as capable as the one it
    /// replaced: stream working AND the emitter still driven. The old order
    /// ran the fresh `ir_emitter::enable` while the OLD guard still held the
    /// per-camera stream lock (`flock` excludes per open file description, so
    /// the same process refuses itself), the enable answered Busy and stayed
    /// inert, and the assignment then dropped the old guard whose Drop wrote
    /// the displaced value back under the just-reopened stream: recovery
    /// reported Ok while every later capture returned dark IR frames.
    ///
    /// On hardware whose emitter irlume drives, `lit` is the discriminator:
    /// true before, and it must still be true after. A rig that does not
    /// drive its emitter cannot discriminate, so the test insists on lit.
    #[test]
    #[ignore = "needs a REAL IR camera whose emitter irlume drives; set IRLUME_TEST_IR_DEVICE"]
    fn recover_keeps_the_emitter_driven() {
        let (_, ir) = loopback_pair();
        let cam = IrCamera::open(&ir).expect("open the IR camera");
        let mut s = cam.session().expect("open a session");
        assert!(
            s.lit,
            "this rig does not drive its emitter, so it cannot discriminate the \
             self-refusal this test exists for; run it on the ASUS/NexiGo hardware"
        );
        let (frame_before, _) = s.capture_with_stats().expect("capture before recover");
        s.recover().expect("recover on a healthy device");
        assert!(
            s.lit,
            "the emitter went dark across recover: the fresh enable refused \
             against its predecessor's lock"
        );
        let (frame_after, _) = s.capture_with_stats().expect("capture after recover");
        assert_eq!(
            (frame_before.width, frame_before.height),
            (frame_after.width, frame_after.height),
            "the recovered stream must carry the same negotiated geometry"
        );
    }

    #[test]
    #[ignore = "needs v4l2loopback feeder nodes; set IRLUME_TEST_RGB_DEVICE/IRLUME_TEST_IR_DEVICE (CI does this)"]
    fn loopback_rgb_single_and_denoised_agree_on_geometry() {
        let (rgb, _) = loopback_pair();
        let one = capture_rgb(&rgb).expect("single rgb");
        let den = capture_rgb_denoised(&rgb).expect("denoised rgb");
        for f in [&one, &den] {
            assert_eq!((f.width, f.height), (RGB_W, RGB_H));
            assert_eq!(f.data.len(), (RGB_W * RGB_H * 3) as usize);
        }
    }

    #[test]
    #[ignore = "needs v4l2loopback feeder nodes; set IRLUME_TEST_RGB_DEVICE/IRLUME_TEST_IR_DEVICE (CI does this)"]
    fn loopback_ir_capture_with_stats_and_sequence() {
        let (_, ir) = loopback_pair();
        let (frame, stats) = capture_ir_with_stats(&ir).expect("ir capture");
        assert_eq!((frame.width, frame.height), (IR_W, IR_H));
        assert_eq!(frame.spectrum, Spectrum::Ir);
        // Drivers may hand back a buffer with trailing slack (v4l2loopback
        // pads by 2 KiB); the contract is at-least-one-byte-per-pixel, and
        // the consumers guard exactly that.
        assert!(frame.data.len() >= (IR_W * IR_H) as usize);
        assert!(stats.burst_frames > 0, "burst must have captured frames");
        assert!(
            (0.0..=255.0).contains(&stats.lit_mean),
            "lit mean {} out of byte range",
            stats.lit_mean
        );

        let seq = capture_ir_sequence(&ir, 3, 2).expect("ir sequence");
        assert_eq!(seq.len(), 3);
        for f in &seq {
            assert!(f.data.len() >= (IR_W * IR_H) as usize);
        }
    }

    #[test]
    #[ignore = "needs v4l2loopback feeder nodes; set IRLUME_TEST_RGB_DEVICE/IRLUME_TEST_IR_DEVICE (CI does this)"]
    fn loopback_capabilities_classify_rgb_but_never_pair() {
        // Only meaningful when the loopback nodes sit inside discover_nodes'
        // /dev/video0..9 scan range (CI uses 8 and 9).
        let (rgb, _ir) = loopback_pair();
        if !(0..10).any(|n| rgb == format!("/dev/video{n}")) {
            return;
        }
        let caps = capabilities();
        assert!(
            caps.rgb,
            "a YUYV-fed loopback node classifies as a usable RGB camera"
        );
        // Assert the LOOPBACK nodes specifically never join a Hello pair
        // (no physical sysfs parent), rather than that no pair exists at all:
        // on the hardware CI runner a real Hello camera is attached, so the
        // global `caps.ir_pair` bit is legitimately true there.
        let (rgb, ir) = loopback_pair();
        for pair in list_pairs() {
            assert!(
                pair.rgb != rgb && pair.rgb != ir && pair.ir != rgb && pair.ir != ir,
                "virtual nodes share no physical sysfs parent, so they must never \
                 appear in a Hello pair (got rgb={} ir={})",
                pair.rgb,
                pair.ir
            );
        }
    }

    #[test]
    fn virtual_camera_escape_is_exact_path_only() {
        // The escape must match the exact device path, nothing looser.
        let _lock = env_lock();
        let _esc = EnvGuard::set("IRLUME_TEST_ALLOW_VIRTUAL_CAMERA", "/dev/null, /dev/zero");
        assert!(
            verify_pinned("/dev/null").is_ok(),
            "an exactly-listed existing node passes the escape"
        );
        let err = verify_pinned("/dev/urandom").unwrap_err().to_string();
        assert!(
            err.contains("refusing"),
            "an unlisted node must still hit the physical-device pin, got: {err}"
        );
        std::env::set_var("IRLUME_TEST_ALLOW_VIRTUAL_CAMERA", "/dev/nul");
        assert!(
            verify_pinned("/dev/null").is_err(),
            "a prefix must not satisfy the exact-path escape"
        );
    }

    #[test]
    fn select_pair_persisted_conf_and_discovery_fallback() {
        let _lock = env_lock();
        let _rgb_env = EnvGuard::unset("IRLUME_RGB_DEVICE");
        let _ir_env = EnvGuard::unset("IRLUME_IR_DEVICE");
        let dir = std::env::temp_dir().join(format!("irlume-selpair-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let _conf = EnvGuard::set("IRLUME_CONFIG_DIR", dir.to_str().unwrap());

        // With no env override, no persisted pair and no discoverable Hello
        // pair, the compiled defaults come back. Loopback nodes can never form
        // a pair (no USB descriptors in sysfs), so this holds on CI; a dev box
        // with a real Hello camera legitimately discovers its own pair
        // instead, so the fallback asserts are skipped there.
        if list_pairs().is_empty() {
            assert_eq!(
                select_pair(),
                (
                    DEFAULT_RGB_DEVICE.to_string(),
                    DEFAULT_IR_DEVICE.to_string()
                )
            );
        }

        // A persisted pair whose nodes are GONE (stale cameras.conf after a
        // USB re-shuffle) is ignored rather than trusted.
        std::fs::write(
            dir.join("cameras.conf"),
            "rgb=/dev/irlume-gone0\nir=/dev/irlume-gone1\n",
        )
        .unwrap();
        if list_pairs().is_empty() {
            assert_eq!(
                select_pair(),
                (
                    DEFAULT_RGB_DEVICE.to_string(),
                    DEFAULT_IR_DEVICE.to_string()
                )
            );
        }

        // A persisted pair whose nodes EXIST wins over discovery and defaults.
        // /dev/null and /dev/zero exist everywhere; select_pair checks only
        // existence here (classification happened when the pair was written).
        std::fs::write(dir.join("cameras.conf"), "rgb=/dev/null\nir=/dev/zero\n").unwrap();
        assert_eq!(
            select_pair(),
            ("/dev/null".to_string(), "/dev/zero".to_string())
        );

        // A blank env override must not shadow the persisted pair...
        {
            let _r = EnvGuard::set("IRLUME_RGB_DEVICE", "");
            let _i = EnvGuard::set("IRLUME_IR_DEVICE", "  ");
            assert_eq!(
                select_pair(),
                ("/dev/null".to_string(), "/dev/zero".to_string())
            );
        }
        // ...but a real one beats it, without an existence check (explicit
        // operator intent).
        let _r = EnvGuard::set("IRLUME_RGB_DEVICE", "/dev/irlume-env-rgb");
        let _i = EnvGuard::set("IRLUME_IR_DEVICE", "/dev/irlume-env-ir");
        assert_eq!(
            select_pair(),
            (
                "/dev/irlume-env-rgb".to_string(),
                "/dev/irlume-env-ir".to_string()
            )
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    #[ignore = "needs v4l2loopback feeder nodes; set IRLUME_TEST_RGB_DEVICE/IRLUME_TEST_IR_DEVICE (CI does this)"]
    fn loopback_raw_bursts_report_shape_and_monotonic_timing() {
        let (_, ir) = loopback_pair();
        let timed = ir_probe::capture_raw_burst_timed(&ir, 5).expect("timed burst");
        assert_eq!(timed.len(), 5);
        let mut prev = -1.0f64;
        for (f, ms) in &timed {
            assert_eq!((f.width, f.height), (IR_W, IR_H));
            assert_eq!(f.spectrum, Spectrum::Ir);
            assert!(f.data.len() >= (IR_W * IR_H) as usize);
            assert!(ms.is_finite() && *ms >= 0.0, "bad timestamp {ms}");
            assert!(
                *ms >= prev,
                "timestamps must be monotonic: {ms} after {prev}"
            );
            prev = *ms;
        }
        // Five distinct frames from a paced live feed cannot all be dequeued
        // at one instant: the window must have real width.
        assert!(
            timed.last().unwrap().1 > timed.first().unwrap().1,
            "a live feed must spread dequeues over time"
        );

        // The untimed variant is the same capture minus the timing column.
        let frames = ir_probe::capture_raw_burst(&ir, 3).expect("raw burst");
        assert_eq!(frames.len(), 3);
        for f in &frames {
            assert_eq!((f.width, f.height), (IR_W, IR_H));
            assert_eq!(f.spectrum, Spectrum::Ir);
            assert!(f.data.len() >= (IR_W * IR_H) as usize);
        }
        // n = 0 is a valid degenerate request: open, arm, deliver nothing.
        assert!(ir_probe::capture_raw_burst(&ir, 0)
            .expect("empty burst")
            .is_empty());
    }

    #[test]
    #[ignore = "needs v4l2loopback feeder nodes; set IRLUME_TEST_RGB_DEVICE/IRLUME_TEST_IR_DEVICE (CI does this)"]
    fn loopback_ir_stats_flag_off_returns_the_raw_brightest_frame() {
        let _lock = env_lock();
        let (_, ir) = loopback_pair();
        let _sub = EnvGuard::unset("IRLUME_IR_AMBIENT_SUBTRACT");
        let (frame, stats) = capture_ir_with_stats(&ir).expect("ir capture");
        // Stats contract: per-frame mean extremes over the fixed-size burst,
        // byte-ranged, min <= max. None of it depends on an emitter: a
        // loopback node has no UVC extension unit, so ir_emitter::enable finds
        // no control and returns false, and the burst statistics are computed
        // regardless.
        assert_eq!(stats.burst_frames, IR_BURST);
        assert!(stats.ambient_mean >= 0.0 && stats.lit_mean <= 255.0);
        assert!(
            stats.ambient_mean <= stats.lit_mean,
            "ambient (burst min {}) must not exceed lit (burst max {})",
            stats.ambient_mean,
            stats.lit_mean
        );
        // With the subtraction flag unset, the ambient-pairing block is dead
        // code and the returned frame IS the brightest raw burst frame: its
        // recomputed mean equals lit_mean (only f32 rounding apart). A
        // refactor that subtracts by default, or picks any frame other than
        // the max-mean one, breaks this.
        let mean = ir_probe::mean(&frame.data);
        assert!(
            (mean - stats.lit_mean as f64).abs() < 0.01,
            "returned frame mean {mean:.3} != lit_mean {}",
            stats.lit_mean
        );
    }

    #[test]
    #[ignore = "needs an unfed v4l2loopback node; set IRLUME_TEST_SPARE_DEVICE (CI does this)"]
    fn loopback_frozen_static_feed_starves_the_sequence_window() {
        // A bit-identical feed simulates the stalled-sensor failure the
        // detector was built for (streams observed locking to a constant
        // mid-grey). Expected arithmetic, from capture_ir_sequence: the first
        // frame is accepted (no previous signature), every repeat is frozen,
        // two frozen frames trigger a stream restart (budget 4), and each
        // restart clears last_sig so exactly one more frame is accepted. A
        // 6-sample window on a fully static feed therefore returns Ok with
        // exactly 1 + 4 = 5 frames: a SHORT window, never an error.
        let _lock = env_lock();
        let spare = spare_device();
        let _sub = EnvGuard::unset("IRLUME_IR_AMBIENT_SUBTRACT");
        let _esc = allow_virtual(&spare);
        let _feeder = FfmpegFeeder::spawn(&spare, "color=c=gray:size=640x400:rate=15");

        // The single-shot path has no frozen gate: a static feed still yields
        // a frame (this also blocks until the feeder's frames actually flow).
        let (frame, _) = capture_ir_with_stats(&spare).expect("static feed single capture");
        let mean = ir_probe::mean(&frame.data);
        assert!(
            (10.0..245.0).contains(&mean),
            "harness: the static gray feed must sit inside the frozen \
             detector's normal-exposure band, got mean {mean:.1}"
        );

        let seq = capture_ir_sequence(&spare, 6, 1).expect("sequence returns Ok, not Err");
        assert_eq!(
            seq.len(),
            5,
            "static feed: 1 initial accept + 1 per stream restart (budget 4)"
        );
        for f in &seq {
            assert_eq!((f.width, f.height), (IR_W, IR_H));
            assert_eq!(f.spectrum, Spectrum::Ir);
        }
    }

    #[test]
    #[ignore = "needs an unfed v4l2loopback node; set IRLUME_TEST_SPARE_DEVICE (CI does this)"]
    fn loopback_frameless_capture_fits_the_watchdog_budget() {
        // The #336 measurement: a frameless capture spends the FULL warm-up
        // budget, and what must fit the watchdog is not that total but the
        // longest stretch between progress reports. This measures both legs
        // the daemon arithmetic stands on: the warm-up reported every one of
        // its silent windows, and no gap between reports exceeded
        // CAPTURE_SILENT_WINDOW_WORST_MS plus slack.
        //
        // The frameless state is a STALLED PRODUCER built by this test: the
        // output side of the loopback node armed (S_FMT + REQBUFS + STREAMON),
        // exactly ONE frame queued, then silence with the tokens still held.
        // Everything below is from the pinned module source (v4l2loopback
        // 0.15.4 @0f9ee86; state machine research in
        // ~/irlume-research/2026-08-07-v4l2loopback-readiness/RESEARCH.md) and
        // was verified against the real module on the CI runner's exact
        // kernel (6.17.0-1021-azure VM harness, 2026-08-07):
        //
        // - No producer at all (or killed before the consumer's first
        //   dequeue, which is where STREAMON happens): close releases the
        //   output stream token, the consumer's STREAMON fails the token
        //   guard (v4l2loopback.c:2074-2076) with EIO instantly (41ms in the
        //   research, 7ms remeasured), and no dequeue window ever opens. CI
        //   run 31205302426 failed this test's first shape exactly there.
        // - A producer holding the token means the consumer's STREAMON
        //   passes, and a dequeue then blocks whenever nothing has been
        //   written past this opener's read position (can_read,
        //   v4l2loopback.c:1936); only the 5s poll timeout this crate sets
        //   ends the wait. Measured: a blocking consumer against that state
        //   sat the full 8s until killed.
        // - BUT dev->write_position survives for the module's lifetime, and
        //   each FRESH opener is served one catch-up frame whenever it lags
        //   (v4l2loopback.c:1972-1977). CI's spare node always has write
        //   history (the ambient-subtract test feeds it earlier in this same
        //   binary), so a fresh consumer's warm-up eats that one stale frame
        //   and the silence lands in the unreported burst loop instead.
        //   Measured on the VM: 5.0s failure, zero heartbeats.
        //
        // So the producer queues ONE frame on purpose, making every node
        // history equivalent, and the capture below runs TWICE on ONE open
        // camera: sessions on the same fd share the same opener, whose read
        // position persists across STREAMOFF/REQBUFS (neither touches it,
        // v4l2loopback.c:2113-2127, :1694-1712). The first, drain session
        // consumes the opener's one catch-up frame and fails in the burst's
        // first silent window; the second, measured session then faces a
        // fully caught-up queue, and its warm-up walks every silent window
        // reporting each one. Verified end to end on the VM harness: drain
        // ~5s, measured session all 8 heartbeats, 40.9s, gaps inside the
        // bound. If a harness ever set the module's sustain_framerate,
        // timeout, or keep_format options, frames would flow instead and the
        // is_err assertions below name the harness loudly.
        let _lock = env_lock();
        // Was a printed SKIP that still reported ok. A note in the log does not
        // reach the lane's pass count, which is what CI actually gates on (#361).
        let spare = spare_device();
        let _esc = allow_virtual(&spare);

        // The stalled producer. Held (device AND armed stream) until after
        // the capture: dropping either releases the output token and turns
        // the state back into the fast-EIO one mid-test.
        let producer = Device::with_path(&spare).expect("open the spare node's output side");
        let fmt = Format::new(IR_W, IR_H, FourCC::new(b"GREY"));
        v4l::video::Output::set_format(&producer, &fmt).expect("set the producer format");
        let mut producer_stream =
            v4l::io::mmap::Stream::with_buffers(&producer, Type::VideoOutput, 1)
                .expect("allocate the producer buffer");
        {
            use v4l::io::traits::OutputStream;
            // First next(): STREAMON (token taken), hands the buffer to fill.
            let (frame, meta) =
                OutputStream::next(&mut producer_stream).expect("arm the stalled producer");
            frame[..(IR_W * IR_H) as usize].fill(128);
            meta.bytesused = IR_W * IR_H;
            // Second next(): queues that one frame (the single write), then
            // returns the next buffer, which is never filled or queued: the
            // producer now stalls with its tokens held.
            OutputStream::next(&mut producer_stream).expect("queue the single frame");
        }

        // Consumer open + GREY negotiation succeed against the armed,
        // stalled producer, same as against a live feeder.
        let cam = IrCamera::open(&spare).expect("open the consumer side");

        // Drain session: consumes this opener's one catch-up frame in its
        // warm-up, then fails on the burst's first silent window.
        let drained = cam
            .session()
            .and_then(|mut s| s.capture_with_stats())
            .map(|_| ());
        assert!(
            drained.is_err(),
            "the drain capture must fail against a stalled producer; frames \
             are flowing (module timeout/sustain/keep_format set on this \
             node?)"
        );

        // Record the gap ending at each progress report, and the start of the
        // stretch a report closes.
        let t0 = std::time::Instant::now();
        let gaps: std::sync::Arc<std::sync::Mutex<Vec<std::time::Duration>>> =
            std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
        let progress: Progress = {
            let gaps = std::sync::Arc::clone(&gaps);
            let last = std::sync::Mutex::new(std::time::Instant::now());
            std::sync::Arc::new(move || {
                let mut last = last.lock().unwrap();
                gaps.lock().unwrap().push(last.elapsed());
                *last = std::time::Instant::now();
            })
        };
        let shot = cam
            .session_with_progress(&progress)
            .and_then(|mut s| s.capture_with_stats());
        let ms = t0.elapsed().as_millis() as u64;
        let err = match shot {
            Err(e) => e,
            Ok(_) => panic!("a frameless node must fail the capture, got a frame after {ms}ms"),
        };
        // Path assertion: the warm-up itself must have run dry, reporting one
        // heartbeat per silent window for its whole budget. Fewer reports
        // means the capture failed somewhere OTHER than the silent warm-up
        // (the error and wall time in the message say where); that run proves
        // nothing about the wiring this test exists to measure, so it fails
        // rather than passes.
        let gaps = gaps.lock().unwrap();
        assert_eq!(
            gaps.len(),
            WARMUP_TRIES as usize,
            "expected one progress report per silent warm-up window \
             (WARMUP_TRIES={WARMUP_TRIES}), saw {}; the warm-up path was not \
             the one exercised (capture failed after {ms}ms with: {err})",
            gaps.len()
        );
        // The measured leg of the daemon's watchdog arithmetic: no silent
        // stretch inside camera code may exceed the exported per-window
        // bound. 2s of slack for session setup (emitter control writes,
        // metadata queue) and scheduler jitter on a loaded runner.
        let bound_ms = CAPTURE_SILENT_WINDOW_WORST_MS + 2_000;
        let worst_ms = gaps
            .iter()
            .map(|d| d.as_millis() as u64)
            .max()
            .expect("gaps is non-empty");
        assert!(
            worst_ms <= bound_ms,
            "longest gap between progress reports was {worst_ms}ms, over the \
             {bound_ms}ms per-window bound the watchdog arithmetic (#336) is \
             built on"
        );
        // And each window must be a real wait, not an instant error loop: a
        // full poll timeout is the shape being measured.
        let window_ms = STREAM_DEQUEUE_TIMEOUT.as_millis() as u64;
        assert!(
            worst_ms >= window_ms,
            "longest gap was {worst_ms}ms, under one {window_ms}ms dequeue \
             window; this did not exercise the silent-window path"
        );
    }

    // ---- warm-up retry/reporting contract (#336, Codex round) ----------
    // Over the injected core, so both halves are pinned without a camera:
    // the FULL silent retry budget (a slow camera that delivers late must
    // keep succeeding) and the per-window heartbeat (a frameless camera must
    // never look wedged to the watchdog while its driver calls return).

    /// The regression the Codex review of PR #338 caught in the first cut of
    /// this fix: a camera silent for two full windows that delivers on its
    /// third warmed up on main and must keep warming up. Reintroducing any
    /// cap on TimedOut retries fails here.
    #[test]
    fn a_camera_delivering_on_its_third_silent_window_still_warms_up() {
        use std::io::{Error, ErrorKind};
        use std::sync::atomic::{AtomicU32, Ordering};
        let calls = std::cell::Cell::new(0u32);
        let pings = std::sync::Arc::new(AtomicU32::new(0));
        let progress: Progress = {
            let pings = std::sync::Arc::clone(&pings);
            std::sync::Arc::new(move || {
                pings.fetch_add(1, Ordering::SeqCst);
            })
        };
        let result = warm_up_with(
            "/dev/test",
            || {
                calls.set(calls.get() + 1);
                if calls.get() <= 2 {
                    Err(Error::new(ErrorKind::TimedOut, "synthetic silent window"))
                } else {
                    Ok(())
                }
            },
            |_| {},
            &progress,
        );
        assert!(
            result.is_ok(),
            "two silent windows then a frame is a WORKING camera: {result:?}"
        );
        assert_eq!(calls.get(), 3, "the third dequeue must have been made");
        assert_eq!(
            pings.load(Ordering::SeqCst),
            2,
            "each completed silent window reports exactly once"
        );
    }

    /// A fully frameless warm-up spends its whole budget and reports EVERY
    /// window, the terminal one included: the report is what resets the
    /// watchdog clock before the caller spends unbounded time (inference, a
    /// reopen) on the way to the next window. Dropping the `progress()` call
    /// in `warm_up_with`, or shrinking the TimedOut budget, fails here.
    #[test]
    fn a_frameless_warm_up_reports_every_completed_silent_window() {
        use std::io::{Error, ErrorKind};
        use std::sync::atomic::{AtomicU32, Ordering};
        let calls = std::cell::Cell::new(0u32);
        let pings = std::sync::Arc::new(AtomicU32::new(0));
        let progress: Progress = {
            let pings = std::sync::Arc::clone(&pings);
            std::sync::Arc::new(move || {
                pings.fetch_add(1, Ordering::SeqCst);
            })
        };
        let result = warm_up_with(
            "/dev/test",
            || {
                calls.set(calls.get() + 1);
                Err(Error::new(ErrorKind::TimedOut, "synthetic silent window"))
            },
            |_| {},
            &progress,
        );
        assert!(result.is_err(), "a fully frameless warm-up must fail");
        assert_eq!(
            calls.get(),
            WARMUP_TRIES,
            "TimedOut keeps the FULL retry budget; a smaller count is the \
             fail-closed regression the Codex round rejected"
        );
        assert_eq!(
            pings.load(Ordering::SeqCst),
            WARMUP_TRIES,
            "one heartbeat per completed silent window, terminal window included"
        );
    }

    /// The resume race keeps its full budget and stays silent on the
    /// reporter: its errors return in milliseconds, so there is no window to
    /// report, and asserting zero pins that only TimedOut heartbeats.
    #[test]
    fn fast_resume_errors_keep_the_full_retry_budget_without_heartbeats() {
        use std::io::{Error, ErrorKind};
        use std::sync::atomic::{AtomicU32, Ordering};
        let calls = std::cell::Cell::new(0u32);
        let pings = std::sync::Arc::new(AtomicU32::new(0));
        let progress: Progress = {
            let pings = std::sync::Arc::clone(&pings);
            std::sync::Arc::new(move || {
                pings.fetch_add(1, Ordering::SeqCst);
            })
        };
        let result = warm_up_with(
            "/dev/test",
            || {
                calls.set(calls.get() + 1);
                if calls.get() == WARMUP_TRIES {
                    Ok(())
                } else {
                    Err(Error::new(ErrorKind::NotConnected, "synthetic resume race"))
                }
            },
            |_| {},
            &progress,
        );
        assert!(
            result.is_ok(),
            "the last-try frame must warm up: {result:?}"
        );
        assert_eq!(calls.get(), WARMUP_TRIES);
        assert_eq!(
            pings.load(Ordering::SeqCst),
            0,
            "fast errors are not silent windows and must not heartbeat"
        );
    }

    #[test]
    #[ignore = "needs an unfed v4l2loopback node; set IRLUME_TEST_SPARE_DEVICE (CI does this)"]
    fn loopback_ambient_subtract_pairs_strobe_frames() {
        // Simulated strobing emitter: frames alternate dark/lit (luma 40/200
        // before any range conversion), the exact lit/off adjacency the opt-in
        // ambient subtraction pairs up.
        let _lock = env_lock();
        let spare = spare_device();
        let _esc = allow_virtual(&spare);
        let _sub = EnvGuard::set("IRLUME_IR_AMBIENT_SUBTRACT", "1");
        let _feeder = FfmpegFeeder::spawn(
            &spare,
            "color=c=black:size=640x400:rate=15,geq=lum='40+160*mod(N,2)'",
        );
        let (frame, stats) = capture_ir_with_stats(&spare).expect("strobed capture");
        // Harness sanity, asserted so a drifting feed fails loudly instead of
        // silently testing the wrong branch: the alternation must present a
        // real strobe gap above the low-ambient floor.
        let (lit, amb) = (stats.lit_mean as f64, stats.ambient_mean as f64);
        assert!(
            lit - amb > STROBE_MIN_GAP,
            "harness: strobe gap {:.1} too small to reach the subtract branch",
            lit - amb
        );
        assert!(
            amb >= LOW_AMBIENT_SKIP,
            "harness: ambient {amb:.1} under the skip floor"
        );
        // Contract: the returned frame is lit-minus-ambient, not the raw lit
        // frame. The synthetic frames are uniform, so the subtracted mean
        // equals lit_mean - ambient_mean (driver padding bytes are constant
        // and cancel; no pixel clamps because lit > ambient everywhere).
        let mean = ir_probe::mean(&frame.data);
        assert!(
            (mean - (lit - amb)).abs() < 2.0,
            "subtracted frame mean {mean:.1} != lit-ambient {:.1}",
            lit - amb
        );
        assert!(
            mean < lit - STROBE_MIN_GAP,
            "frame mean {mean:.1} still at the raw lit level {lit:.1}; subtraction was not applied"
        );
    }

    #[test]
    #[ignore = "needs v4l2loopback feeder nodes; set IRLUME_TEST_RGB_DEVICE/IRLUME_TEST_IR_DEVICE (CI does this)"]
    fn loopback_busy_error_names_a_holding_process() {
        let (_, ir) = loopback_pair();
        // Hold the node open ourselves so /proc provably contains at least one
        // holder this uid can see (the CI feeder also holds it; whichever the
        // scan finds first is fine). Read-only open, no streaming: nothing on
        // /dev/video0..9 is touched.
        let _held = std::fs::File::open(&ir).expect("open the fed IR node read-only");
        let msg = map_io(&ir, std::io::Error::from_raw_os_error(16)).to_string();
        assert!(msg.contains("camera busy"), "{msg}");
        assert!(
            msg.contains("in use by"),
            "expected the named-holder arm, got: {msg}"
        );
        assert!(msg.contains("pid "), "holder must carry a pid: {msg}");
        assert!(
            !msg.contains("another app is using it"),
            "anonymous fallback used despite a live holder: {msg}"
        );
    }

    #[test]
    #[ignore = "needs v4l2loopback feeder nodes; set IRLUME_TEST_RGB_DEVICE/IRLUME_TEST_IR_DEVICE (CI does this)"]
    fn loopback_nodes_classify_by_fed_format_with_no_identity_or_privacy() {
        let (rgb, ir) = loopback_pair();
        // Classification keys purely on the advertised FourCC: the YUYV-fed
        // node is an RGB camera, the GREY-fed node its IR companion.
        assert_eq!(classify(&rgb), Role::Rgb);
        assert_eq!(classify(&ir), Role::Ir);
        // Loopback nodes expose no V4L2_CID_PRIVACY control; the shutter check
        // degrades to "not engaged" instead of blocking capture.
        assert!(!privacy_engaged(&rgb));
        assert!(!privacy_engaged(&ir));
        // No USB descriptors anywhere up the sysfs chain: no stable identity
        // to bind an enrollment to.
        assert_eq!(device_identity(&rgb), None);
        assert_eq!(device_identity(&ir), None);
        // And WITHOUT the exact-path escape, the anti-injection pin refuses a
        // virtual node outright: the very attack the escape documents.
        let _lock = env_lock();
        let _esc = EnvGuard::unset("IRLUME_TEST_ALLOW_VIRTUAL_CAMERA");
        let err = verify_pinned(&ir).unwrap_err().to_string();
        assert!(
            err.contains("refusing"),
            "virtual node must be refused: {err}"
        );
    }

    /// Writing an empty value is what CLEARS the origin stamp, which is the
    /// assumption `store_capture_mode` now rests on.
    ///
    /// It matters because nothing cleared the stamp before: `camera-tune`
    /// wrote only the mode key, so a pairing that had been switched
    /// automatically kept reporting "switched automatically N days ago" even
    /// after the user ran the measurement doctor told them to run, and the
    /// measurement itself never showed up in a support report. The only way
    /// out was hand-editing /etc/irlume/cameras.conf (#100 review).
    ///
    /// `device_identity` reads sysfs, so `store_capture_mode` itself cannot run
    /// against a synthetic pair here; what is pinned is the mechanism it uses.
    #[test]
    fn an_empty_value_clears_the_origin_stamp() {
        let _lock = env_lock();
        let dir = std::env::temp_dir().join(format!("irlume-origin-clear-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let _conf = EnvGuard::set("IRLUME_CONFIG_DIR", dir.to_str().unwrap());

        let (rgb_id, ir_id) = ("046d:085e:abc", "046d:085e:def");
        let mode_key = capture_mode_pair_key(rgb_id, ir_id);
        let origin_key = capture_mode_origin_key(rgb_id, ir_id);

        irlume_common::config::write_kv("cameras.conf", &mode_key, "sequential").unwrap();
        irlume_common::config::write_kv("cameras.conf", &origin_key, "auto-switch 1786320000")
            .unwrap();
        assert_eq!(
            irlume_common::config::read_kv("cameras.conf", &origin_key).as_deref(),
            Some("auto-switch 1786320000"),
            "precondition: the stamp is readable before it is cleared"
        );

        irlume_common::config::write_kv("cameras.conf", &origin_key, "").unwrap();
        assert_eq!(
            irlume_common::config::read_kv("cameras.conf", &origin_key),
            None,
            "an empty value must read as absent, or the stamp outlives the measurement"
        );
        // ...and clearing the sidecar must not disturb the mode it sits beside.
        assert_eq!(
            irlume_common::config::read_kv("cameras.conf", &mode_key).as_deref(),
            Some("sequential"),
            "clearing the provenance must not change which mode is in force"
        );

        let _ = std::fs::remove_dir_all(&dir);
    }
}

#[cfg(test)]
mod session_traits {
    fn assert_send<T: Send>() {}

    /// The auth path captures RGB and IR CONCURRENTLY, moving the IR side onto a
    /// scoped thread. A session that is not `Send` would force that path back to
    /// opening a stream per capture, so this is a load-bearing property rather
    /// than an incidental one.
    #[test]
    fn sessions_can_cross_a_thread_boundary() {
        assert_send::<super::IrSession<'_>>();
        assert_send::<super::RgbSession<'_>>();
    }
}

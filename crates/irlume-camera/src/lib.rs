//! V4L2 capture for the paired RGB + IR cameras, and active-IR-emitter control.
//!
//! Hardware model (Windows-Hello-class module): one RGB sensor (`/dev/video0`)
//! and one greyscale IR sensor (`/dev/video2`), plus an 850/940nm emitter fired
//! via a UVC Extension-Unit control write (cf. linux-enable-ir-emitter).
//!
//! The auth path overlaps the RGB and IR captures on two threads: measured on
//! the ASUS built-in and the NexiGo N930W (examples/concurrency_probe.rs),
//! both deliver frames concurrently, ~0.7 s (ASUS) to ~1.3 s (NexiGo) faster
//! than back-to-back. A shared-USB module that HARD-fails a starved stream
//! shows up as a capture error and the caller retries that side alone; a
//! module that instead degrades the RGB frame silently (the NexiGo dims it
//! from mean ~120 to ~71, below YuNet's detection floor) is recovered by the
//! cross-spectrum self-heal in irlume-auth (IR-has-a-face while RGB-does-not
//! triggers an RGB-alone recapture). `IRLUME_SEQUENTIAL_CAPTURE=1` forces
//! back-to-back capture if a module misbehaves.
//!
//! Implementation: the `v4l` crate (V4L2). RGB capture requests YUYV and converts
//! to RGB8. FOOTGUN: enumerate V4L2 controls defensively; naive control queries
//! panic on some drivers. Probe, don't assume.

pub mod ir_emitter;

use irlume_common::Error;
use v4l::buffer::Type;
use v4l::io::traits::CaptureStream;
use v4l::video::Capture;
use v4l::{Device, Format, FourCC};

/// A single captured frame, tagged with which spectrum it came from.
pub struct Frame {
    pub width: u32,
    pub height: u32,
    pub spectrum: Spectrum,
    /// Raw bytes: RGB8 (R,G,B interleaved) for `Rgb`, GREY (8-bit) for `Ir`.
    pub data: Vec<u8>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Spectrum {
    Rgb,
    Ir,
}

/// Burst statistics from an IR capture: the per-frame mean extremes. When the
/// emitter strobes, `ambient_mean` (the darkest frame of the burst) is the
/// scene's ambient IR level with the emitter off, and `lit_mean -
/// ambient_mean` is the strobe gap; on a steady emitter the two converge.
#[derive(Clone, Copy, Debug)]
pub struct IrCaptureStats {
    pub lit_mean: f32,
    pub ambient_mean: f32,
    pub burst_frames: usize,
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

/// Active-IR emitter table (UVC Extension-Unit `SET_CUR`), ported from linhello.
/// archhost's **NexiGo HelloCam N930W** lives here: XU unit 4, selector 6,
/// payload below fires the ~850nm illuminator (like `linux-enable-ir-emitter`).
/// Override with `IRLUME_IR_EMITTER=unit:selector:b,b,...` or `off`.
pub const IR_EMITTER_NEXIGO_N930W: (u8, u8, [u8; 9]) = (4, 6, [1, 3, 2, 0, 0, 0, 0, 0, 0]);

/// Colour pixel formats imply an RGB sensor; greyscale-only implies the IR
/// companion. linhello lesson: classify by advertised FourCC, never hardcode.
const COLOUR_FOURCCS: [&[u8; 4]; 5] = [b"YUYV", b"MJPG", b"RGB3", b"BGR3", b"NV12"];
const GREY_FOURCCS: [&[u8; 4]; 3] = [b"GREY", b"Y8  ", b"Y800"];

/// Map common io errors to actionable messages (linhello lesson: EBUSY/privacy
/// are routine and need a clear cause, not a raw errno).
fn map_io(device: &str, e: std::io::Error) -> Error {
    use std::io::ErrorKind;
    match e.raw_os_error() {
        Some(16) => {
            let who = camera_holder(device)
                .map(|h| format!(", in use by {h}"))
                .unwrap_or_else(|| ", another app is using it".into());
            Error::Hardware(format!(
                "{device}: camera busy{who}. Close that app (e.g. a camera/video/conferencing app) and retry."
            ))
        }
        _ if e.kind() == ErrorKind::PermissionDenied => Error::Hardware(format!(
            "{device}: permission denied; add your user to the 'video' group (camera) and re-login"
        )),
        _ => Error::Hardware(format!("{device}: {e}")),
    }
}

/// Best-effort: which process currently holds `device` open, for a clearer
/// camera-busy message. Scans `/proc/<pid>/fd` for a symlink to the device;
/// needs root to see other users' processes (the daemon runs as root). Returns
/// e.g. "kamoso (pid 2567)", or `None` if it can't tell.
fn camera_holder(device: &str) -> Option<String> {
    let dev = std::fs::canonicalize(device).ok()?;
    for ent in std::fs::read_dir("/proc").ok()?.flatten() {
        let name = ent.file_name();
        let Some(pid) = name.to_str() else { continue };
        if pid.is_empty() || !pid.bytes().all(|b| b.is_ascii_digit()) {
            continue;
        }
        let Ok(fds) = std::fs::read_dir(ent.path().join("fd")) else {
            continue;
        };
        for fd in fds.flatten() {
            if std::fs::read_link(fd.path())
                .map(|t| t == dev)
                .unwrap_or(false)
            {
                let comm = std::fs::read_to_string(ent.path().join("comm")).unwrap_or_default();
                let comm = comm.trim();
                return Some(if comm.is_empty() {
                    format!("pid {pid}")
                } else {
                    format!("{comm} (pid {pid})")
                });
            }
        }
    }
    None
}

/// What a video node is, by its advertised formats.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Role {
    Rgb,
    Ir,
    /// A capture node advertising neither (metadata node) or unreadable.
    Other,
}

/// Classify a single `/dev/videoN` node by enumerating its pixel formats.
/// Defensive: enumerate FORMATS (safe), never `query_controls` (panics on some
/// UVC drivers; a hard-won linhello lesson).
pub fn classify(device: &str) -> Role {
    let Ok(dev) = Device::with_path(device) else {
        return Role::Other;
    };
    let Ok(formats) = Capture::enum_formats(&dev) else {
        return Role::Other;
    };
    let mut has_colour = false;
    let mut has_grey = false;
    for f in &formats {
        let cc = &f.fourcc.repr;
        if COLOUR_FOURCCS.contains(&cc) {
            has_colour = true;
        }
        if GREY_FOURCCS.contains(&cc) {
            has_grey = true;
        }
    }
    match (has_colour, has_grey) {
        (true, _) => Role::Rgb,
        (false, true) => Role::Ir,
        _ => Role::Other,
    }
}

/// Scan `/dev/video0..9`, returning (path, role) for each readable capture node.
pub fn discover_nodes() -> Vec<(String, Role)> {
    (0..10)
        .map(|n| format!("/dev/video{n}"))
        .filter(|p| std::path::Path::new(p).exists())
        .map(|p| {
            let role = classify(&p);
            (p, role)
        })
        .filter(|(_, r)| *r != Role::Other)
        .collect()
}

/// Best-effort privacy-shutter check. Returns `Ok(true)` if the hardware privacy
/// switch is engaged. Never panics: reads only the specific CID, not the whole
/// control set.
pub fn privacy_engaged(device: &str) -> bool {
    let Ok(dev) = Device::with_path(device) else {
        return false;
    };
    match dev.control(V4L2_CID_PRIVACY) {
        Ok(ctrl) => {
            matches!(ctrl.value, v4l::control::Value::Boolean(true))
                || matches!(ctrl.value, v4l::control::Value::Integer(n) if n != 0)
        }
        Err(_) => false, // control absent on this camera
    }
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
    if let Ok(allow) = std::env::var("IRLUME_TEST_ALLOW_VIRTUAL_CAMERA") {
        if allow.split(',').any(|d| d.trim() == device) {
            eprintln!(
                "irlume: WARNING: {device} accepted without a physical-device pin \
                 (IRLUME_TEST_ALLOW_VIRTUAL_CAMERA)"
            );
            return Ok(());
        }
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
    // auto-selection but not an explicit env override.
    if let (Some(r), Some(i)) = (
        irlume_common::config::read_kv("cameras.conf", "rgb"),
        irlume_common::config::read_kv("cameras.conf", "ir"),
    ) {
        if !r.trim().is_empty() && !i.trim().is_empty() && device_exists(&r) && device_exists(&i) {
            return (r, i);
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

/// Hardware capability summary, for "smart Auto": what biometric face hardware
/// is actually present. `IRLUME_FORCE_NO_IR=1` forces `ir_pair=false` (test the
/// RGB-only convenience path on an IR box, or pin a box to convenience mode).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Caps {
    /// A physical camera exposing BOTH an RGB and an IR node (full Hello cam).
    pub ir_pair: bool,
    /// Any usable RGB camera node exists.
    pub rgb: bool,
}

pub fn capabilities() -> Caps {
    let force_no_ir = std::env::var("IRLUME_FORCE_NO_IR")
        .map(|v| v == "1")
        .unwrap_or(false);
    let ir_pair = !force_no_ir && !list_pairs().is_empty();
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
    let mut groups: std::collections::BTreeMap<std::path::PathBuf, (Vec<String>, Vec<String>)> =
        Default::default();
    for (path, role) in discover_nodes() {
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

/// Open `device`, let auto-exposure settle, and capture `n` (≥1) RGB frames in a
/// single streaming session (YUYV → RGB8). All frames share the same dimensions.
pub fn capture_rgb_burst(device: &str, n: usize) -> irlume_common::Result<Vec<Frame>> {
    verify_pinned(device)?;
    if privacy_engaged(device) {
        return Err(Error::Hardware(format!(
            "{device}: hardware privacy switch is ON"
        )));
    }
    let dev = Device::with_path(device).map_err(|e| map_io(device, e))?;
    // Best-effort backlight/low-light correction: tell auto-exposure to expose
    // for the face, not a bright window behind it. Harmless if unsupported
    // (NexiGo N930W needs this; verified mean 49→124 + face detected).
    let _ = dev.set_control(v4l::control::Control {
        id: V4L2_CID_BACKLIGHT_COMPENSATION,
        value: v4l::control::Value::Integer(2),
    });
    let fmt = Format::new(RGB_W, RGB_H, FourCC::new(b"YUYV"));
    let fmt = Capture::set_format(&dev, &fmt).map_err(|e| map_io(device, e))?;
    if &fmt.fourcc.repr != b"YUYV" {
        return Err(Error::Hardware(format!(
            "{device}: driver gave {:?}, expected YUYV",
            std::str::from_utf8(&fmt.fourcc.repr).unwrap_or("????")
        )));
    }
    let (w, h) = (fmt.width, fmt.height);
    let mut stream = v4l::io::mmap::Stream::with_buffers(&dev, Type::VideoCapture, 4)
        .map_err(|e| map_io(device, e))?;

    for _ in 0..AE_WARMUP {
        stream.next().map_err(|e| map_io(device, e))?; // discard while AE settles
    }
    let mut frames = Vec::with_capacity(n.max(1));
    for _ in 0..n.max(1) {
        let (buf, _meta) = stream.next().map_err(|e| map_io(device, e))?;
        frames.push(Frame {
            width: w,
            height: h,
            spectrum: Spectrum::Rgb,
            data: yuyv_to_rgb(buf, w, h),
        });
    }
    Ok(frames)
}

/// Capture one AE-warmed RGB frame (fast path: framing guide, liveness probe).
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
pub fn capture_rgb_denoised(device: &str) -> irlume_common::Result<Frame> {
    Ok(median_frame(capture_rgb_burst(device, RGB_BURST)?))
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
/// it most (dataset `~/irlume-suncal`: bursts 06-08, gap 8-9, raw depth
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
const STROBE_MIN_GAP: f64 = 8.0;
const LOW_AMBIENT_SKIP: f64 = 5.0;
const SUBTRACT_MIN_RESULT: f64 = 12.0;

/// Capture one IR frame (GREY 8-bit) from the IR companion node. The active-IR
/// emitter must be illuminating for a usable image; on integrated Hello modules
/// it often fires when the stream opens, otherwise it needs a UVC-XU write (TODO,
/// see `IR_EMITTER_NEXIGO_N930W`).
pub fn capture_ir(device: &str) -> irlume_common::Result<Frame> {
    Ok(capture_ir_with_stats(device)?.0)
}

/// [`capture_ir`] plus the burst statistics the plain call discards. The
/// darkest burst frame's mean is a free per-capture ambient-IR reading (the
/// input the ambient-relative gates key on), only available at capture time.
pub fn capture_ir_with_stats(device: &str) -> irlume_common::Result<(Frame, IrCaptureStats)> {
    verify_pinned(device)?;
    if privacy_engaged(device) {
        return Err(Error::Hardware(format!(
            "{device}: hardware privacy switch is ON"
        )));
    }
    let dev = Device::with_path(device).map_err(|e| map_io(device, e))?;
    let fmt = Format::new(IR_W, IR_H, FourCC::new(b"GREY"));
    let fmt = Capture::set_format(&dev, &fmt).map_err(|e| map_io(device, e))?;
    if &fmt.fourcc.repr != b"GREY" {
        return Err(Error::Hardware(format!(
            "{device}: driver gave {:?}, expected GREY",
            std::str::from_utf8(&fmt.fourcc.repr).unwrap_or("????")
        )));
    }
    let (w, h) = (fmt.width, fmt.height);
    let mut stream = v4l::io::mmap::Stream::with_buffers(&dev, Type::VideoCapture, 4)
        .map_err(|e| map_io(device, e))?;
    // Fire the active-IR emitter on the open fd (Hello modules reset it per-open,
    // so we must do it here, while streaming, not via an external one-shot).
    let card = dev.query_caps().map(|c| c.card).unwrap_or_default();
    let lit = ir_emitter::enable(dev.handle().fd(), &card);
    // The emitter may STROBE (pulse), so grab a burst and keep the brightest
    // frame, the lit strobe phase (linhello lesson). Re-fire mid-burst in case
    // the control self-clears. Keep every frame so the optional ambient
    // subtraction below can pair the lit frame with an adjacent emitter-off one.
    let mut frames: Vec<Vec<u8>> = Vec::with_capacity(IR_BURST);
    let mut means: Vec<f64> = Vec::with_capacity(IR_BURST);
    for i in 0..IR_BURST {
        if i == IR_BURST / 2 {
            ir_emitter::enable(dev.handle().fd(), &card);
        }
        let (buf, _meta) = stream.next().map_err(|e| map_io(device, e))?;
        means.push(buf.iter().map(|&p| p as f64).sum::<f64>() / buf.len().max(1) as f64);
        frames.push(buf.to_vec());
    }
    let bmin = means.iter().cloned().fold(f64::INFINITY, f64::min);
    let bmax = means.iter().cloned().fold(f64::NEG_INFINITY, f64::max);
    // First frame holding the max mean (strictly-greater scan), matching the
    // original incremental behaviour exactly so the flag-off path is unchanged
    // (max_by would keep the LAST tie, changing the chosen frame on ties).
    let mut best_i = 0usize;
    let mut best_mean = -1.0f64;
    for (i, &m) in means.iter().enumerate() {
        if m > best_mean {
            best_mean = m;
            best_i = i;
        }
    }
    let mut best = Some(frames[best_i].clone());

    // Windows-Hello-style ambient subtraction. EXPERIMENTAL, opt-in. On a
    // strobing emitter the frame adjacent to the brightest is an emitter-OFF
    // exposure that captured only ambient IR. Subtracting it isolates the
    // emitter's own reflected light, the same illuminated/ambient-pair step
    // Hello uses. Its purpose is EXPOSURE ROBUSTNESS: under strong ambient IR
    // (sunlight) the pedestal would otherwise wash out the emitter reflection.
    // It is not primarily a spoof control (Hello credits spoof resistance to the
    // IR wavelength plus a separate liveness stage, which is where irlume's
    // depth/glint cues live). Indoors the off-frame is ~0, so it is a no-op.
    //
    // The subtraction assumes the lit and off frames share an exposure; pairing
    // ADJACENT burst frames (after AE_WARMUP) keeps auto-exposure drift between
    // the pair small. Pixels where the lit frame is saturated (255) carry no
    // reliable subtracted value; the debug line reports the clipped fraction so a
    // blown exposure is visible rather than silently trusted.
    //
    // NOT a validated security control yet, two reasons it stays behind a flag:
    //   1. The liveness DEPTH cue is center/edge RATIO, which is non-monotonic
    //      under subtraction: removing an ambient frame that is brighter at the
    //      border than the center RAISES the ratio, so a subtracted frame could
    //      pass the depth floor a raw frame would fail. The depth floor must be
    //      re-tuned against subtracted frames before this can be a default.
    //   2. The IR frame also feeds dark-mode IR matching, so enrollment and
    //      auth must use the SAME setting; toggling it requires a re-enroll.
    // Both are moot while the flag is unset (the shipped default).
    let subtract = std::env::var("IRLUME_IR_AMBIENT_SUBTRACT").is_ok_and(|v| v.trim() == "1");
    let debug_ir = std::env::var("IRLUME_DEBUG_IR").is_ok();
    if subtract {
        let neighbors = [best_i.wrapping_sub(1), best_i + 1];
        let ambient_i = neighbors
            .iter()
            .filter(|&&j| j < means.len())
            .min_by(|&&a, &&b| means[a].total_cmp(&means[b]))
            .copied();
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
                    best = Some(sub);
                }
                if debug_ir {
                    let clipped = ir_probe::saturated_fraction(&frames[best_i]);
                    let action = if sub_mean >= SUBTRACT_MIN_RESULT {
                        "applied"
                    } else {
                        "reverted (result too dark; face would vanish)"
                    };
                    eprintln!(
                        "[ir] ambient-subtract {action}: lit {best_i} ({lit_mean:.0}) - ambient {ai} ({amb_mean:.0}) => mean {sub_mean:.0}; lit clipped {:.1}%{}",
                        clipped * 100.0,
                        if clipped > 0.05 {
                            " (blown exposure; subtracted frame unreliable)"
                        } else {
                            ""
                        }
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
    if debug_ir {
        eprintln!("[ir_emitter] card={card:?} SET_CUR ok={lit}; burst {IR_BURST} frames, per-frame mean {bmin:.1}..{bmax:.1}");
    }
    // Onboarding hint for a new (e.g. external) Hello camera: dark IR with no
    // emitter fired usually means its 850nm illuminator needs a UVC-XU write we
    // don't have a table entry for. Guide the user to configure it.
    if !lit && (0.0..35.0).contains(&best_mean) {
        eprintln!(
            "[ir] {card:?}: IR is dark (mean {best_mean:.0}) with no active emitter; for an \
             external Hello camera run `linux-enable-ir-emitter configure`, then set \
             IRLUME_IR_EMITTER=unit:sel:b,b,... (or IRLUME_IR_EMITTER=off to silence)"
        );
    }
    let grey = best.ok_or_else(|| Error::Hardware("no IR frames captured".into()))?;
    Ok((
        Frame {
            width: w,
            height: h,
            spectrum: Spectrum::Ir,
            data: grey,
        },
        IrCaptureStats {
            lit_mean: bmax as f32,
            ambient_mean: bmin as f32,
            burst_frames: IR_BURST,
        },
    ))
}

/// Ambient-subtraction helpers (Windows-Hello-style illuminated minus ambient).
/// `subtract` is used by `capture_ir` when `IRLUME_IR_AMBIENT_SUBTRACT=1`
/// (experimental, off by default); `capture_raw_burst`/`center_border_ratio`
/// are diagnostics for the strobe-probe example. Kept in the crate so the
/// example and the capture path share one implementation.
pub mod ir_probe {
    use super::{ir_emitter, map_io, privacy_engaged, verify_pinned, Error, Frame, Spectrum};
    use super::{Capture, CaptureStream, Device, Format, FourCC, Type};
    use super::{IR_H, IR_W};

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
    /// is an exposure-robustness step, not a standalone spoof control. Falls back
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

    /// Fraction of pixels at the 8-bit ceiling (255). A high clipped fraction in
    /// the lit frame means the exposure is blown: those pixels lost their true
    /// emitter return, so both the raw and the ambient-subtracted frame are
    /// unreliable there. Used as a capture-quality signal, not a hard gate.
    pub fn saturated_fraction(data: &[u8]) -> f64 {
        if data.is_empty() {
            return 0.0;
        }
        let clipped = data.iter().filter(|&&p| p == 255).count();
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
    pub fn capture_raw_burst_timed(
        device: &str,
        n: usize,
    ) -> irlume_common::Result<Vec<(Frame, f64)>> {
        verify_pinned(device)?;
        if privacy_engaged(device) {
            return Err(Error::Hardware(format!(
                "{device}: hardware privacy switch is ON"
            )));
        }
        let dev = Device::with_path(device).map_err(|e| map_io(device, e))?;
        let fmt = Format::new(IR_W, IR_H, FourCC::new(b"GREY"));
        let fmt = Capture::set_format(&dev, &fmt).map_err(|e| map_io(device, e))?;
        let (w, h) = (fmt.width, fmt.height);
        let mut stream = v4l::io::mmap::Stream::with_buffers(&dev, Type::VideoCapture, 4)
            .map_err(|e| map_io(device, e))?;
        let card = dev.query_caps().map(|c| c.card).unwrap_or_default();
        ir_emitter::enable(dev.handle().fd(), &card);
        let mut out = Vec::with_capacity(n);
        let t0 = std::time::Instant::now();
        for _ in 0..n {
            let (buf, _meta) = stream.next().map_err(|e| map_io(device, e))?;
            out.push((
                Frame {
                    width: w,
                    height: h,
                    spectrum: Spectrum::Ir,
                    data: buf.to_vec(),
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

/// Capture a time-ordered SEQUENCE of IR frames in a single stream session, for
/// temporal liveness (the blink challenge). Unlike [`capture_ir`], the eyes-closed
/// dip of a blink must survive, so this returns every sample rather than only the
/// brightest. Each of `samples` frames is the brightest of a `burst`-frame
/// mini-burst: `burst=1` yields raw frames (to reveal whether the emitter
/// strobes); `burst>=2` de-strobes locally while keeping enough temporal
/// resolution for a blink (the IR node is ~15 fps, so a mini-burst of 2 ≈ 133 ms).
pub fn capture_ir_sequence(
    device: &str,
    samples: usize,
    burst: usize,
) -> irlume_common::Result<Vec<Frame>> {
    verify_pinned(device)?;
    if privacy_engaged(device) {
        return Err(Error::Hardware(format!(
            "{device}: hardware privacy switch is ON"
        )));
    }
    let burst = burst.max(1);
    let dev = Device::with_path(device).map_err(|e| map_io(device, e))?;
    let fmt = Format::new(IR_W, IR_H, FourCC::new(b"GREY"));
    let fmt = Capture::set_format(&dev, &fmt).map_err(|e| map_io(device, e))?;
    if &fmt.fourcc.repr != b"GREY" {
        return Err(Error::Hardware(format!(
            "{device}: driver gave {:?}, expected GREY",
            std::str::from_utf8(&fmt.fourcc.repr).unwrap_or("????")
        )));
    }
    let (w, h) = (fmt.width, fmt.height);
    let mut stream = Some(
        v4l::io::mmap::Stream::with_buffers(&dev, Type::VideoCapture, 4)
            .map_err(|e| map_io(device, e))?,
    );
    let card = dev.query_caps().map(|c| c.card).unwrap_or_default();
    ir_emitter::enable(dev.handle().fd(), &card);
    // Sparse content signature: BIT-IDENTICAL consecutive frames mean the stream
    // has FROZEN (measured live 2026-07-01 in dark rooms: frames lock to a
    // constant mid-grey for the rest of the window); real sensor noise never
    // repeats exactly. Saturated and near-black frames are excluded from the
    // check: those are optical states (exposure blow-out / emitter-off phase),
    // not a stall, and restarting mid-settle only prolongs the settle.
    // (Signature + predicate live in `frame_signature` / `frame_frozen`.)
    let mut frames = Vec::with_capacity(samples);
    // Attempt budget: enough spare frames to ride out the ~1 s dark-start
    // exposure settle and a stream restart without starving the window, while
    // bounding worst-case wall time (~2x window) when the camera stays sick.
    let max_attempts = samples * 2 + 30;
    let (mut dead_run, mut restarts) = (0usize, 0usize);
    let mut last_sig: Option<Vec<u8>> = None;
    for attempt in 0..max_attempts {
        if frames.len() >= samples {
            break;
        }
        // Keep the emitter lit across the whole window (some controls self-clear).
        if attempt % 8 == 0 {
            ir_emitter::enable(dev.handle().fd(), &card);
        }
        let mut best: Option<Vec<u8>> = None;
        let mut best_mean = -1.0f64;
        for _ in 0..burst {
            let (buf, _meta) = stream
                .as_mut()
                .expect("IR stream present")
                .next()
                .map_err(|e| map_io(device, e))?;
            let mean = buf.iter().map(|&p| p as f64).sum::<f64>() / buf.len().max(1) as f64;
            if mean > best_mean {
                best_mean = mean;
                best = Some(buf.to_vec());
            }
        }
        let Some(data) = best else { continue };
        let sig = frame_signature(&data);
        let frozen = frame_frozen(best_mean, &sig, last_sig.as_deref());
        last_sig = Some(sig);
        if frozen {
            dead_run += 1;
            if dead_run >= 2 && restarts < 4 {
                restarts += 1;
                dead_run = 0;
                last_sig = None;
                drop(stream.take()); // stop + release buffers before re-arming
                stream = Some(
                    v4l::io::mmap::Stream::with_buffers(&dev, Type::VideoCapture, 4)
                        .map_err(|e| map_io(device, e))?,
                );
                ir_emitter::enable(dev.handle().fd(), &card);
            }
            continue;
        }
        dead_run = 0;
        if best_mean >= 245.0 {
            // Exposure blow-out: no face is detectable in a saturated frame;
            // skip it rather than spend a window slot on it.
            continue;
        }
        frames.push(Frame {
            width: w,
            height: h,
            spectrum: Spectrum::Ir,
            data,
        });
    }
    Ok(frames)
}

/// Auto-configure the IR emitter for `device`, irlume's integrated
/// linux-enable-ir-emitter: enumerate the camera's UVC extension-unit controls,
/// try candidate payloads, and keep the one that makes the IR image bright
/// (success detected automatically from IR brightness; no phone-camera step).
/// Persists the discovered control so every later capture uses it. Returns a
/// human description, or errors if nothing worked. Non-destructive: controls
/// that don't help are restored.
pub fn setup_ir_emitter(device: &str) -> irlume_common::Result<String> {
    verify_pinned(device)?;
    let dev = Device::with_path(device).map_err(|e| map_io(device, e))?;
    let fmt = Format::new(IR_W, IR_H, FourCC::new(b"GREY"));
    let fmt = Capture::set_format(&dev, &fmt).map_err(|e| map_io(device, e))?;
    if &fmt.fourcc.repr != b"GREY" {
        return Err(Error::Hardware(format!(
            "{device}: not an IR (GREY) capture node"
        )));
    }
    let mut stream = v4l::io::mmap::Stream::with_buffers(&dev, Type::VideoCapture, 4)
        .map_err(|e| map_io(device, e))?;
    let fd = dev.handle().fd();
    for _ in 0..4 {
        let _ = stream.next(); // let the sensor settle before baseline
    }
    // Mean IR brightness over a short burst (catches a strobed emitter's lit phase).
    let mut measure = || -> f32 {
        let mut best = 0.0f32;
        for _ in 0..8 {
            if let Ok((buf, _)) = stream.next() {
                let m = buf.iter().map(|&p| p as f64).sum::<f64>() / buf.len().max(1) as f64;
                best = best.max(m as f32);
            }
        }
        best
    };
    match ir_emitter::autoconfigure(fd, &mut measure) {
        Some(ctrl) => {
            // With the emitter lit, look for a companion control that brightens
            // the IR further (an exposure/gain-like vendor XU control); persist
            // it alongside the emitter so every capture applies both.
            let boost = ir_emitter::discover_boost(fd, &ctrl, &mut measure);
            ir_emitter::save_conf_full(&ctrl, boost.as_ref()).map_err(|e| Error::Io(e.to_string()))?;
            Ok(match &boost {
                Some(b) => format!(
                    "IR emitter enabled: control {} + brightness boost {} (saved; future captures use both)",
                    ctrl.encode(), b.encode()
                ),
                None => format!(
                    "IR emitter enabled: control {} (saved; no extra brightness control found)",
                    ctrl.encode()
                ),
            })
        }
        None => Err(Error::Hardware(
            "could not auto-enable the IR emitter: no extension-unit control brightened the IR image. \
             The camera may have no software-controllable emitter, or need a vendor-specific config.".into(),
        )),
    }
}

/// Read-only list of the IR camera's UVC extension-unit controls (unit, selector,
/// size), for `ir-setup --dry-run` diagnostics. Touches no settings.
pub fn list_ir_controls(device: &str) -> irlume_common::Result<Vec<(u8, u8, usize)>> {
    verify_pinned(device)?;
    let dev = Device::with_path(device).map_err(|e| map_io(device, e))?;
    Ok(ir_emitter::list_controls(dev.handle().fd()))
}

/// Ensure the IR emitter is working: a normal IR capture first (fires the
/// known/configured emitter); only if that's dark does it run auto-setup. So a
/// camera that already works (table/conf/env) is never brute-forced. Returns
/// whether IR is bright after. `Some(true/false)` distinguishes "auto-setup ran"
/// in the bool; the caller logs accordingly. Best-effort.
pub fn ensure_ir_emitter(device: &str) -> irlume_common::Result<bool> {
    let mean_of =
        |f: &Frame| f.data.iter().map(|&p| p as f64).sum::<f64>() / f.data.len().max(1) as f64;
    if mean_of(&capture_ir(device)?) >= 40.0 {
        return Ok(true); // already working; do not touch the camera
    }
    // Dark: attempt integrated auto-setup, then re-check.
    setup_ir_emitter(device)?;
    Ok(mean_of(&capture_ir(device)?) >= 40.0)
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

#[cfg(test)]
mod tests {
    use super::*;

    fn frame(data: &[u8]) -> Frame {
        Frame {
            width: data.len() as u32,
            height: 1,
            spectrum: Spectrum::Rgb,
            data: data.to_vec(),
        }
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

    #[test]
    fn saturated_fraction_counts_clipped_pixels() {
        assert_eq!(ir_probe::saturated_fraction(&[255, 255, 0, 0]), 0.5);
        assert_eq!(ir_probe::saturated_fraction(&[0, 1, 254]), 0.0);
        assert_eq!(ir_probe::saturated_fraction(&[]), 0.0);
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
        // Anything else: device-prefixed passthrough.
        let e = map_io(
            "/dev/irlume-test-missing",
            std::io::Error::from_raw_os_error(5),
        );
        assert!(
            e.to_string()
                .starts_with("hardware: /dev/irlume-test-missing:"),
            "{e}"
        );
    }

    #[test]
    fn camera_holder_finds_our_own_open_file() {
        // Hold a file open ourselves; the /proc scan must name this process.
        let dir = std::env::temp_dir().join(format!("irlume-cam-holder-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("held");
        std::fs::write(&path, b"x").unwrap();
        let _held = std::fs::File::open(&path).unwrap();
        let who = camera_holder(path.to_str().unwrap()).expect("holder found");
        assert!(
            who.contains(&format!("pid {}", std::process::id())),
            "unexpected holder: {who}"
        );
        // Nothing holds a nonexistent path.
        assert_eq!(camera_holder("/dev/irlume-test-missing"), None);
        drop(_held);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn verify_pinned_rejects_missing_and_non_sysfs_devices() {
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
        std::env::set_var("IRLUME_RGB_DEVICE", "/dev/irlume-test-rgb");
        std::env::set_var("IRLUME_IR_DEVICE", "/dev/irlume-test-ir");
        assert_eq!(
            select_pair(),
            ("/dev/irlume-test-rgb".into(), "/dev/irlume-test-ir".into())
        );
        std::env::remove_var("IRLUME_RGB_DEVICE");
        std::env::remove_var("IRLUME_IR_DEVICE");
    }

    #[test]
    fn privacy_engaged_is_false_without_a_camera() {
        // Missing node or a non-V4L2 node: the check degrades to "not engaged"
        // (the capture path then surfaces the real error).
        assert!(!privacy_engaged("/dev/irlume-test-missing"));
        assert!(!privacy_engaged("/dev/null"));
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

    fn loopback_pair() -> Option<(String, String)> {
        Some((
            std::env::var("IRLUME_TEST_RGB_DEVICE").ok()?,
            std::env::var("IRLUME_TEST_IR_DEVICE").ok()?,
        ))
    }

    #[test]
    #[ignore = "needs v4l2loopback feeder nodes; set IRLUME_TEST_RGB_DEVICE/IRLUME_TEST_IR_DEVICE (CI does this)"]
    fn loopback_rgb_burst_streams_and_converts() {
        let Some((rgb, _)) = loopback_pair() else {
            return;
        };
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

    #[test]
    #[ignore = "needs v4l2loopback feeder nodes; set IRLUME_TEST_RGB_DEVICE/IRLUME_TEST_IR_DEVICE (CI does this)"]
    fn loopback_rgb_single_and_denoised_agree_on_geometry() {
        let Some((rgb, _)) = loopback_pair() else {
            return;
        };
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
        let Some((_, ir)) = loopback_pair() else {
            return;
        };
        let (frame, stats) = capture_ir_with_stats(&ir).expect("ir capture");
        assert_eq!((frame.width, frame.height), (IR_W, IR_H));
        assert_eq!(frame.spectrum, Spectrum::Ir);
        assert_eq!(frame.data.len(), (IR_W * IR_H) as usize);
        assert!(stats.burst_frames > 0, "burst must have captured frames");
        assert!(
            (0.0..=255.0).contains(&stats.lit_mean),
            "lit mean {} out of byte range",
            stats.lit_mean
        );

        let seq = capture_ir_sequence(&ir, 3, 2).expect("ir sequence");
        assert_eq!(seq.len(), 3);
        for f in &seq {
            assert_eq!(f.data.len(), (IR_W * IR_H) as usize);
        }
    }

    #[test]
    #[ignore = "needs v4l2loopback feeder nodes; set IRLUME_TEST_RGB_DEVICE/IRLUME_TEST_IR_DEVICE (CI does this)"]
    fn loopback_capabilities_sees_a_usable_rgb_node() {
        let Some((_rgb, _ir)) = loopback_pair() else {
            return;
        };
        let caps = capabilities();
        assert!(
            caps.rgb,
            "a YUYV-fed loopback node must classify as a usable RGB camera"
        );
    }

    #[test]
    fn virtual_camera_escape_is_exact_path_only() {
        // Distinct env vars from select_pair_env_override_wins, so no race.
        // The escape must match the exact device path, nothing looser.
        std::env::set_var("IRLUME_TEST_ALLOW_VIRTUAL_CAMERA", "/dev/null, /dev/zero");
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
        std::env::remove_var("IRLUME_TEST_ALLOW_VIRTUAL_CAMERA");
    }
}

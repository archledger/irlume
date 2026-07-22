// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright the irlume contributors.

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

/// Frozen-stream recovery for burst captures: after this many consecutive
/// identical frames the stream is torn down and re-opened, at most
/// `FROZEN_RESTART_BUDGET` times per burst (a fully static feed therefore
/// yields 1 + budget frames instead of hanging).
const FROZEN_RUN_BEFORE_RESTART: usize = 2;
const FROZEN_RESTART_BUDGET: usize = 4;

/// Below this 8-bit greyscale mean with no emitter fired, the IR sensor is
/// dark and the onboarding hint (configure your emitter) is printed; see
/// `ir_emitter::IR_LIT_MEAN` for the lit threshold on the other side.
const IR_DARK_HINT_MAX: f64 = 35.0;

/// mmap ring size for every V4L2 capture stream. Four buffers is the classic
/// quad-buffer: enough that the driver never stalls waiting for a dequeue at
/// 30fps, small enough to be granted by every UVC camera we have seen.
const MMAP_BUFFERS: u32 = 4;

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
            // 16 == EBUSY
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
    let fourccs: Vec<[u8; 4]> = formats.iter().map(|f| f.fourcc.repr).collect();
    role_from_formats(&fourccs)
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
    // Pick an uncompressed format the camera actually offers. Some webcams
    // advertise RGB only as MJPEG (or NV12) and reject YUYV; classify() still
    // labels them usable, so without this negotiation they would detect fine
    // then fail at capture with a cryptic "expected YUYV". YUYV is preferred;
    // NV12 is the common uncompressed fallback.
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
    let (w, h) = (fmt.width, fmt.height);
    let mut stream = v4l::io::mmap::Stream::with_buffers(&dev, Type::VideoCapture, MMAP_BUFFERS)
        .map_err(|e| map_io(device, e))?;

    warm_up_stream(device, &mut stream)?;
    for _ in 0..AE_WARMUP {
        stream.next().map_err(|e| map_io(device, e))?; // discard while AE settles
    }
    let mut frames = Vec::with_capacity(n.max(1));
    for _ in 0..n.max(1) {
        let (buf, _meta) = stream.next().map_err(|e| map_io(device, e))?;
        let data = match &chosen {
            b"NV12" => nv12_to_rgb(buf, w, h),
            _ => yuyv_to_rgb(buf, w, h),
        };
        frames.push(Frame {
            width: w,
            height: h,
            spectrum: Spectrum::Rgb,
            data,
        });
    }
    Ok(frames)
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
    /// bits — a 10-bit sensor delivers 0..1023 in Y16).
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
        let fmt = Capture::set_format(dev, &fmt).map_err(|e| map_io(device, e))?;
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
pub(crate) fn decode_ir(buf: &[u8], pix: IrPixel, w: u32, h: u32) -> Vec<u8> {
    match pix {
        IrPixel::Grey8 => buf.to_vec(),
        IrPixel::Grey16 => grey16_to_8(buf),
        IrPixel::Nv12Luma => {
            let luma = (w as usize * h as usize).min(buf.len());
            buf[..luma].to_vec()
        }
        IrPixel::YuyvLuma => buf.iter().step_by(2).copied().collect(),
    }
}

/// 16-bit-LE grey (Y16/Y10/Y12) → 8-bit. The V4L2 spec keeps sample data
/// LSB-aligned and lets the real precision be anything up to 16 bits, and
/// nothing reports which; a fixed top-byte take (what a sibling project ships)
/// reads a 10-bit-in-Y16 sensor as near-black. Instead, estimate the effective
/// depth from the frame's own maximum and shift the whole frame uniformly:
/// deterministic, monotone, and stable within a burst.
pub(crate) fn grey16_to_8(buf: &[u8]) -> Vec<u8> {
    let max: u16 = buf
        .chunks_exact(2)
        .map(|p| u16::from_le_bytes([p[0], p[1]]))
        .max()
        .unwrap_or(0);
    let bits = 16 - max.leading_zeros();
    let shift = bits.saturating_sub(8);
    buf.chunks_exact(2)
        .map(|p| (u16::from_le_bytes([p[0], p[1]]) >> shift).min(255) as u8)
        .collect()
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
    let (fmt, pix) = negotiate_ir_format(device, &dev)?;
    let (w, h) = (fmt.width, fmt.height);
    let mut stream = v4l::io::mmap::Stream::with_buffers(&dev, Type::VideoCapture, MMAP_BUFFERS)
        .map_err(|e| map_io(device, e))?;
    // Survive the first-capture-after-resume race (uvcvideo still re-initializing).
    warm_up_stream(device, &mut stream)?;
    // Fire the active-IR emitter on the open fd (Hello modules reset it per-open,
    // so we must do it here, while streaming, not via an external one-shot).
    let card = dev.query_caps().map(|c| c.card).unwrap_or_default();
    let lit = ir_emitter::enable(dev.handle().fd(), &card);
    // The emitter may STROBE (pulse), so grab a burst and keep the brightest
    // frame, the lit strobe phase (linhello lesson). Re-fire mid-burst in case
    // the control self-clears. Keep every frame so the optional ambient
    // subtraction below can pair the lit frame with an adjacent emitter-off one.
    // Every frame is decoded to 8-bit GREY at dequeue, so the means, the
    // subtraction, and everything downstream see one uniform layout.
    let mut frames: Vec<Vec<u8>> = Vec::with_capacity(IR_BURST);
    let mut means: Vec<f64> = Vec::with_capacity(IR_BURST);
    for i in 0..IR_BURST {
        if i == IR_BURST / 2 {
            ir_emitter::enable(dev.handle().fd(), &card);
        }
        let (buf, _meta) = stream.next().map_err(|e| map_io(device, e))?;
        let data = decode_ir(buf, pix, w, h);
        means.push(data.iter().map(|&p| p as f64).sum::<f64>() / data.len().max(1) as f64);
        frames.push(data);
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
    if !lit && (0.0..IR_DARK_HINT_MAX).contains(&best_mean) {
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
    use super::{decode_ir, negotiate_ir_format};
    use super::{ir_emitter, map_io, privacy_engaged, verify_pinned, Error, Frame, Spectrum};
    use super::{CaptureStream, Device, Type};

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
        let (fmt, pix) = negotiate_ir_format(device, &dev)?;
        let (w, h) = (fmt.width, fmt.height);
        let mut stream =
            v4l::io::mmap::Stream::with_buffers(&dev, Type::VideoCapture, super::MMAP_BUFFERS)
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
                    data: decode_ir(buf, pix, w, h),
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
    let (fmt, pix) = negotiate_ir_format(device, &dev)?;
    let (w, h) = (fmt.width, fmt.height);
    let mut stream = Some(
        v4l::io::mmap::Stream::with_buffers(&dev, Type::VideoCapture, MMAP_BUFFERS)
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
            let data = decode_ir(buf, pix, w, h);
            let mean = data.iter().map(|&p| p as f64).sum::<f64>() / data.len().max(1) as f64;
            if mean > best_mean {
                best_mean = mean;
                best = Some(data);
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
                stream = Some(
                    v4l::io::mmap::Stream::with_buffers(&dev, Type::VideoCapture, MMAP_BUFFERS)
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
    let (fmt, pix) = negotiate_ir_format(device, &dev)?;
    let (w, h) = (fmt.width, fmt.height);
    let mut stream = v4l::io::mmap::Stream::with_buffers(&dev, Type::VideoCapture, MMAP_BUFFERS)
        .map_err(|e| map_io(device, e))?;
    let fd = dev.handle().fd();
    for _ in 0..4 {
        let _ = stream.next(); // let the sensor settle before baseline
    }
    // Mean IR brightness over a short burst (catches a strobed emitter's lit
    // phase). Measured on the DECODED 8-bit frame so the brightness scale is
    // comparable across native-grey and 16-bit/luma-extracted nodes.
    let mut measure = || -> f32 {
        let mut best = 0.0f32;
        for _ in 0..8 {
            if let Ok((buf, _)) = stream.next() {
                let data = decode_ir(buf, pix, w, h);
                let m = data.iter().map(|&p| p as f64).sum::<f64>() / data.len().max(1) as f64;
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
    if mean_of(&capture_ir(device)?) >= ir_emitter::IR_LIT_MEAN as f64 {
        return Ok(true); // already working; do not touch the camera
    }
    // Dark: attempt integrated auto-setup, then re-check.
    setup_ir_emitter(device)?;
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
fn warm_up_stream(
    device: &str,
    stream: &mut v4l::io::mmap::Stream<'_>,
) -> irlume_common::Result<()> {
    use std::io::ErrorKind;
    const TRIES: u32 = 8;
    const GAP: std::time::Duration = std::time::Duration::from_millis(120);
    for attempt in 0..TRIES {
        match stream.next() {
            Ok(_) => return Ok(()),
            Err(e)
                if attempt + 1 < TRIES
                    && matches!(
                        e.kind(),
                        ErrorKind::BrokenPipe
                            | ErrorKind::NotConnected
                            | ErrorKind::Other
                            | ErrorKind::TimedOut
                    ) =>
            {
                std::thread::sleep(GAP);
            }
            Err(e) => return Err(map_io(device, e)),
        }
    }
    Ok(())
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
        use super::grey16_to_8;
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
    // A THIRD node, IRLUME_TEST_SPARE_DEVICE, has NO CI-side feeder: tests
    // that need a specific pattern (static for the frozen-stream detector,
    // alternating for strobe pairing) spawn their own ffmpeg against it and
    // kill the child on drop. Spare-node tests own that node exclusively;
    // CI runs the gated suite with --test-threads=1.

    fn loopback_pair() -> Option<(String, String)> {
        Some((
            std::env::var("IRLUME_TEST_RGB_DEVICE").ok()?,
            std::env::var("IRLUME_TEST_IR_DEVICE").ok()?,
        ))
    }

    fn spare_device() -> Option<String> {
        std::env::var("IRLUME_TEST_SPARE_DEVICE").ok()
    }

    /// Serializes tests that mutate process-global env vars (cargo runs tests
    /// on threads, and setters would otherwise race readers in other tests).
    fn env_lock() -> std::sync::MutexGuard<'static, ()> {
        static ENV_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());
        ENV_LOCK.lock().unwrap_or_else(|p| p.into_inner())
    }

    /// RAII env-var override: restores the previous value (or absence) on
    /// drop, so a panicking assertion cannot leak state into later tests.
    struct EnvGuard {
        key: &'static str,
        prev: Option<std::ffi::OsString>,
    }

    impl EnvGuard {
        fn set(key: &'static str, val: &str) -> Self {
            let prev = std::env::var_os(key);
            std::env::set_var(key, val);
            Self { key, prev }
        }
        fn unset(key: &'static str) -> Self {
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
        let Some((rgb, _ir)) = loopback_pair() else {
            return;
        };
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
        let (rgb, ir) = loopback_pair().expect("checked above");
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
        let Some((_, ir)) = loopback_pair() else {
            return;
        };
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
        let Some((_, ir)) = loopback_pair() else {
            return;
        };
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
        let Some(spare) = spare_device() else {
            return;
        };
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
    fn loopback_ambient_subtract_pairs_strobe_frames() {
        // Simulated strobing emitter: frames alternate dark/lit (luma 40/200
        // before any range conversion), the exact lit/off adjacency the opt-in
        // ambient subtraction pairs up.
        let _lock = env_lock();
        let Some(spare) = spare_device() else {
            return;
        };
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
        let Some((_, ir)) = loopback_pair() else {
            return;
        };
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
        let Some((rgb, ir)) = loopback_pair() else {
            return;
        };
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
}

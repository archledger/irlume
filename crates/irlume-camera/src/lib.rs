//! V4L2 capture for the paired RGB + IR cameras, and active-IR-emitter control.
//!
//! Hardware model (Windows-Hello-class module): one RGB sensor (`/dev/video0`)
//! and one greyscale IR sensor (`/dev/video2`), plus an 850/940nm emitter fired
//! via a UVC Extension-Unit control write (cf. linux-enable-ir-emitter).
//!
//! Capture order matters: grab RGB+detect FIRST, then IR — never concurrently —
//! because shared-USB Hello modules starve one stream if both are read at once.
//!
//! Implementation: the `v4l` crate (V4L2). RGB capture requests YUYV and converts
//! to RGB8. FOOTGUN: enumerate V4L2 controls defensively — naive control queries
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

pub const DEFAULT_RGB_DEVICE: &str = "/dev/video0";
pub const DEFAULT_IR_DEVICE: &str = "/dev/video2";
const RGB_W: u32 = 640;
const RGB_H: u32 = 480;
const AE_WARMUP: usize = 6; // discard frames while auto-exposure settles

/// V4L2 privacy-control id (`V4L2_CID_PRIVACY`) — a hardware shutter/kill switch.
pub const V4L2_CID_PRIVACY: u32 = 0x009a_0910;
/// `V4L2_CID_BACKLIGHT_COMPENSATION` — makes auto-exposure favor the (face)
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
        Some(16) => Error::Hardware(format!(
            "{device}: camera busy (EBUSY) — another process holds it; close it or wait for resume"
        )),
        _ if e.kind() == ErrorKind::PermissionDenied => Error::Hardware(format!(
            "{device}: permission denied — add your user to the camera ACL/group"
        )),
        _ => Error::Hardware(format!("{device}: {e}")),
    }
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
/// UVC drivers — a hard-won linhello lesson).
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
        if COLOUR_FOURCCS.iter().any(|c| *c == cc) {
            has_colour = true;
        }
        if GREY_FOURCCS.iter().any(|c| *c == cc) {
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
        Ok(ctrl) => matches!(ctrl.value, v4l::control::Value::Boolean(true))
            || matches!(ctrl.value, v4l::control::Value::Integer(n) if n != 0),
        Err(_) => false, // control absent on this camera
    }
}

/// Capture one AE-warmed RGB frame from a V4L2 device (YUYV → RGB8).
pub fn capture_rgb(device: &str) -> irlume_common::Result<Frame> {
    if privacy_engaged(device) {
        return Err(Error::Hardware(format!("{device}: hardware privacy switch is ON")));
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

    let mut last: Option<Vec<u8>> = None;
    for _ in 0..AE_WARMUP {
        let (buf, _meta) = stream.next().map_err(|e| map_io(device, e))?;
        last = Some(buf.to_vec());
    }
    let yuyv = last.ok_or_else(|| Error::Hardware("no frames captured".into()))?;
    let rgb = yuyv_to_rgb(&yuyv, w, h);
    Ok(Frame { width: w, height: h, spectrum: Spectrum::Rgb, data: rgb })
}

const IR_W: u32 = 640;
const IR_H: u32 = 400;
const IR_BURST: usize = 24; // grab a burst; keep the brightest (lit strobe phase)

/// Capture one IR frame (GREY 8-bit) from the IR companion node. The active-IR
/// emitter must be illuminating for a usable image; on integrated Hello modules
/// it often fires when the stream opens, otherwise it needs a UVC-XU write (TODO,
/// see `IR_EMITTER_NEXIGO_N930W`).
pub fn capture_ir(device: &str) -> irlume_common::Result<Frame> {
    if privacy_engaged(device) {
        return Err(Error::Hardware(format!("{device}: hardware privacy switch is ON")));
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
    // frame — the lit strobe phase (linhello lesson). Re-fire mid-burst in case
    // the control self-clears.
    let mut best: Option<Vec<u8>> = None;
    let mut best_mean = -1.0f64;
    let mut bmin = 255.0f64;
    let mut bmax = 0.0f64;
    for i in 0..IR_BURST {
        if i == IR_BURST / 2 {
            ir_emitter::enable(dev.handle().fd(), &card);
        }
        let (buf, _meta) = stream.next().map_err(|e| map_io(device, e))?;
        let mean = buf.iter().map(|&p| p as f64).sum::<f64>() / buf.len().max(1) as f64;
        bmin = bmin.min(mean);
        bmax = bmax.max(mean);
        if mean > best_mean {
            best_mean = mean;
            best = Some(buf.to_vec());
        }
    }
    if std::env::var("IRLUME_DEBUG_IR").is_ok() {
        eprintln!("[ir_emitter] card={card:?} SET_CUR ok={lit}; burst {IR_BURST} frames, per-frame mean {bmin:.1}..{bmax:.1}");
    }
    let grey = best.ok_or_else(|| Error::Hardware("no IR frames captured".into()))?;
    Ok(Frame { width: w, height: h, spectrum: Spectrum::Ir, data: grey })
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

/// Owns the camera devices. Lives only inside the privileged daemon.
pub struct Cameras {
    rgb_device: String,
    #[allow(dead_code)]
    ir_device: String,
}

impl Cameras {
    /// Discover and classify the RGB + IR nodes (linhello lesson: don't hardcode).
    /// Falls back to the default nodes if discovery finds nothing.
    pub fn open() -> irlume_common::Result<Self> {
        // TODO: device-trust binding (pin by topology/descriptor; reject virtual
        // cams) — the CVE-2021-34466 defense.
        let nodes = discover_nodes();
        let rgb = nodes
            .iter()
            .find(|(_, r)| *r == Role::Rgb)
            .map(|(p, _)| p.clone())
            .unwrap_or_else(|| DEFAULT_RGB_DEVICE.into());
        let ir = nodes
            .iter()
            .find(|(_, r)| *r == Role::Ir)
            .map(|(p, _)| p.clone())
            .unwrap_or_else(|| DEFAULT_IR_DEVICE.into());
        if privacy_engaged(&rgb) {
            return Err(Error::Hardware(format!(
                "{rgb}: hardware privacy switch is ON — disable it to authenticate"
            )));
        }
        Ok(Self { rgb_device: rgb, ir_device: ir })
    }

    /// Capture an AE-warmed RGB frame.
    pub fn capture_rgb(&mut self) -> irlume_common::Result<Frame> {
        capture_rgb(&self.rgb_device)
    }

    /// Fire the IR emitter, capture an IR burst, return the brightest strobe phase.
    pub fn capture_ir_burst(&mut self) -> irlume_common::Result<Frame> {
        // TODO: UVC-XU SET_CUR to fire emitter; warmup; pick brightest frame.
        todo!("IR capture + emitter (P2 liveness)")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

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
}

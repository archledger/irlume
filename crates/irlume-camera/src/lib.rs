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

fn hw<E: std::fmt::Display>(e: E) -> Error {
    Error::Hardware(e.to_string())
}

/// Capture one AE-warmed RGB frame from a V4L2 device (YUYV → RGB8).
pub fn capture_rgb(device: &str) -> irlume_common::Result<Frame> {
    let dev = Device::with_path(device).map_err(hw)?;
    let fmt = Format::new(RGB_W, RGB_H, FourCC::new(b"YUYV"));
    let fmt = Capture::set_format(&dev, &fmt).map_err(hw)?;
    if &fmt.fourcc.repr != b"YUYV" {
        return Err(Error::Hardware(format!(
            "{device}: driver gave {:?}, expected YUYV",
            std::str::from_utf8(&fmt.fourcc.repr).unwrap_or("????")
        )));
    }
    let (w, h) = (fmt.width, fmt.height);
    let mut stream =
        v4l::io::mmap::Stream::with_buffers(&dev, Type::VideoCapture, 4).map_err(hw)?;

    let mut last: Option<Vec<u8>> = None;
    for _ in 0..AE_WARMUP {
        let (buf, _meta) = stream.next().map_err(hw)?;
        last = Some(buf.to_vec());
    }
    let yuyv = last.ok_or_else(|| Error::Hardware("no frames captured".into()))?;
    let rgb = yuyv_to_rgb(&yuyv, w, h);
    Ok(Frame { width: w, height: h, spectrum: Spectrum::Rgb, data: rgb })
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
    /// Open the configured RGB+IR devices.
    pub fn open() -> irlume_common::Result<Self> {
        // TODO: device-trust binding (pin by topology/descriptor; reject virtual
        // cams) — the CVE-2021-34466 defense. For now use the default nodes.
        Ok(Self { rgb_device: DEFAULT_RGB_DEVICE.into(), ir_device: DEFAULT_IR_DEVICE.into() })
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

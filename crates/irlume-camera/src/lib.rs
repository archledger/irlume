//! V4L2 capture for the paired RGB + IR cameras, and active-IR-emitter control.
//!
//! Hardware model (Windows-Hello-class module): one RGB sensor (`/dev/video0`)
//! and one greyscale IR sensor (`/dev/video2`), plus an 850/940nm emitter fired
//! via a UVC Extension-Unit control write (cf. linux-enable-ir-emitter).
//!
//! Capture order matters: grab RGB+detect FIRST, then IR — never concurrently —
//! because shared-USB Hello modules starve one stream if both are read at once.
//!
//! Implementation: `nokhwa` with the `input-native` (V4L2) backend.
//! FOOTGUN: enumerate V4L2 controls defensively — naive control queries panic on
//! some drivers. Probe, don't assume.

/// A single captured frame, tagged with which spectrum it came from.
pub struct Frame {
    pub width: u32,
    pub height: u32,
    pub spectrum: Spectrum,
    /// Raw bytes: RGB8 for `Rgb`, GREY (8-bit) for `Ir`.
    pub data: Vec<u8>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Spectrum {
    Rgb,
    Ir,
}

/// Owns the camera devices. Lives only inside the privileged daemon.
pub struct Cameras {
    // TODO: nokhwa Camera handles for RGB + IR; device-trust binding (pin by
    // topology/descriptor so an injected USB camera can't impersonate ours —
    // this is the CVE-2021-34466 defense).
}

impl Cameras {
    /// Open and trust-bind the configured RGB+IR devices.
    pub fn open() -> irlume_common::Result<Self> {
        // TODO: classify devices by advertised FourCC (colour => Rgb, grey => Ir),
        // reject virtual cams, pin the trusted device path/topology.
        todo!("open + device-trust binding")
    }

    /// Fire the IR emitter, capture an IR burst, return the brightest strobe phase.
    pub fn capture_ir_burst(&mut self) -> irlume_common::Result<Frame> {
        // TODO: UVC-XU SET_CUR to fire emitter; warmup; pick brightest frame.
        todo!()
    }

    /// Capture an RGB frame (AE-warmed).
    pub fn capture_rgb(&mut self) -> irlume_common::Result<Frame> {
        todo!()
    }
}

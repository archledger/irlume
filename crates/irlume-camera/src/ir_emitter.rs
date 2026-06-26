//! Active-IR emitter activation for Windows-Hello-class UVC cameras.
//!
//! Hello camera modules pair a greyscale NIR sensor with an 850nm illuminator
//! that `uvcvideo` does not drive — on Windows the vendor driver pulses it via a
//! UVC Extension Unit (XU) control; on Linux nothing does, so IR frames come back
//! black. We replay that XU `SET_CUR` write (the same mechanism as
//! `linux-enable-ir-emitter`) **right after opening our own IR stream**, so the
//! emitter is lit for our capture and survives cameras that reset the control on
//! each open. Best-effort: any error degrades to RGB-only liveness.
//!
//! Ported from linhello. Config precedence: `IRLUME_IR_EMITTER=off` disables;
//! `IRLUME_IR_EMITTER=unit:sel:b,b,...` overrides; else the built-in table by
//! card name.

use std::os::raw::c_int;

const UVC_SET_CUR: u8 = 0x01;

/// `struct uvc_xu_control_query` from `linux/uvcvideo.h`.
#[repr(C)]
struct UvcXuControlQuery {
    unit: u8,
    selector: u8,
    query: u8,
    size: u16,
    data: *mut u8,
}

/// `UVCIOC_CTRL_QUERY` = `_IOWR('u', 0x21, struct uvc_xu_control_query)`.
const fn uvcioc_ctrl_query() -> libc::c_ulong {
    const DIR_RW: libc::c_ulong = 3;
    let size = core::mem::size_of::<UvcXuControlQuery>() as libc::c_ulong;
    (DIR_RW << 30) | (size << 16) | ((b'u' as libc::c_ulong) << 8) | 0x21
}

#[derive(Clone)]
struct EmitterControl {
    unit: u8,
    selector: u8,
    payload: Vec<u8>,
}

/// Built-in table, matched on the V4L card name (substring). Verified on-hardware.
fn known_control(card: &str) -> Option<EmitterControl> {
    // ASUS Zenbook S14 "Shinetech ASUS FHD webcam" (USB 3277:0059): XU unit 14 /
    // selector 6, payload [1,3,2,..] lights the emitter. Found via
    // linux-enable-ir-emitter configure 2026-06-26 (IR mean 2 -> lit).
    if card.contains("ASUS") {
        return Some(EmitterControl { unit: 14, selector: 6, payload: vec![1, 3, 2, 0, 0, 0, 0, 0, 0] });
    }
    // NexiGo HelloCam N930W (archhost): XU unit 4 / selector 6, same payload.
    if card.contains("N930W") {
        return Some(EmitterControl { unit: 4, selector: 6, payload: vec![1, 3, 2, 0, 0, 0, 0, 0, 0] });
    }
    None
}

/// Parse `IRLUME_IR_EMITTER` = `unit:selector:b,b,b,...` (decimal or `0x` hex).
fn env_control() -> Option<EmitterControl> {
    let raw = std::env::var("IRLUME_IR_EMITTER").ok()?;
    let raw = raw.trim();
    if raw.is_empty() {
        return None;
    }
    let mut parts = raw.split(':');
    let unit = parse_u8(parts.next()?)?;
    let selector = parse_u8(parts.next()?)?;
    let payload: Vec<u8> = parts.next()?.split(',').filter_map(parse_u8).collect();
    if payload.is_empty() {
        return None;
    }
    Some(EmitterControl { unit, selector, payload })
}

fn parse_u8(s: &str) -> Option<u8> {
    let s = s.trim();
    match s.strip_prefix("0x").or_else(|| s.strip_prefix("0X")) {
        Some(hex) => u8::from_str_radix(hex, 16).ok(),
        None => s.parse().ok(),
    }
}

/// Light the emitter on the open device `fd` for camera `card`, if known.
/// Returns true if the SET_CUR ioctl succeeded. Best-effort.
pub fn enable(fd: c_int, card: &str) -> bool {
    match std::env::var("IRLUME_IR_EMITTER").ok().as_deref().map(str::trim) {
        Some("off") | Some("none") => return false,
        _ => {}
    }
    let Some(ctrl) = env_control().or_else(|| known_control(card)) else {
        return false;
    };
    let mut payload = ctrl.payload.clone();
    let mut query = UvcXuControlQuery {
        unit: ctrl.unit,
        selector: ctrl.selector,
        query: UVC_SET_CUR,
        size: payload.len() as u16,
        data: payload.as_mut_ptr(),
    };
    // SAFETY: fd is a valid open UVC device fd owned by the caller; `query` and
    // its `data` buffer outlive the ioctl.
    let rc = unsafe { libc::ioctl(fd, uvcioc_ctrl_query(), &mut query as *mut UvcXuControlQuery) };
    rc >= 0
}

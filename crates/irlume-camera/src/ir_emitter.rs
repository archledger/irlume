//! Active-IR emitter activation for Windows-Hello-class UVC cameras.
//!
//! Hello camera modules pair a greyscale NIR sensor with an 850nm illuminator
//! that `uvcvideo` does not drive — on Windows the vendor driver pulses it via a
//! UVC Extension Unit (XU) control; on Linux nothing does, so IR frames come back
//! black. We replay that XU `SET_CUR` write (the same mechanism as
//! `linux-enable-ir-emitter`) **right after opening our own IR stream**.
//!
//! Config precedence (first that yields a control wins): `IRLUME_IR_EMITTER=off`
//! disables; `IRLUME_IR_EMITTER=unit:sel:b,b,...` overrides; a persisted config
//! file (written by auto-setup); else the built-in table by card name.
//!
//! [`autoconfigure`] is irlume's integrated replacement for downloading
//! `linux-enable-ir-emitter`: it enumerates the camera's XU controls and tries
//! candidate payloads, using irlume's own IR-brightness measurement to detect
//! success automatically (no "look with a phone camera" step). It restores each
//! control it touches if it didn't help, so a failed search leaves the camera
//! unchanged.
//!
//! Approach credit: EmixamPP/linux-enable-ir-emitter (MIT) — the iterative
//! XU-control discovery idea. This is an independent reimplementation over the
//! kernel UVC ioctl API (no code copied); MIT is GPLv3-compatible regardless, so
//! the technique is clean for irlume's BOM.

use std::os::raw::c_int;
use std::path::PathBuf;

const UVC_SET_CUR: u8 = 0x01;
const UVC_GET_CUR: u8 = 0x81;
const UVC_GET_LEN: u8 = 0x85;

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

#[derive(Clone, Debug, PartialEq)]
pub struct EmitterControl {
    pub unit: u8,
    pub selector: u8,
    pub payload: Vec<u8>,
}

impl EmitterControl {
    /// Serialize as `unit:selector:b,b,...` (the `IRLUME_IR_EMITTER` syntax).
    pub fn encode(&self) -> String {
        let p: Vec<String> = self.payload.iter().map(|b| b.to_string()).collect();
        format!("{}:{}:{}", self.unit, self.selector, p.join(","))
    }
}

/// Built-in table, matched on the V4L card name (substring). Verified on-hardware.
fn known_control(card: &str) -> Option<EmitterControl> {
    if card.contains("ASUS") {
        return Some(EmitterControl { unit: 14, selector: 6, payload: vec![1, 3, 2, 0, 0, 0, 0, 0, 0] });
    }
    if card.contains("N930W") {
        return Some(EmitterControl { unit: 4, selector: 6, payload: vec![1, 3, 2, 0, 0, 0, 0, 0, 0] });
    }
    // Other external Hello cameras (e.g. Logitech Brio) aren't hard-coded; run
    // auto-setup (`autoconfigure` / `irlume ir-setup`) or set IRLUME_IR_EMITTER.
    None
}

/// Persisted config path (written by auto-setup, read by [`enable`]).
fn conf_path() -> PathBuf {
    std::env::var("IRLUME_IR_EMITTER_CONF")
        .map(PathBuf::from)
        .unwrap_or_else(|_| PathBuf::from("/var/lib/irlume/ir_emitter.conf"))
}

fn load_conf() -> Option<EmitterControl> {
    let raw = std::fs::read_to_string(conf_path()).ok()?;
    parse_control(raw.trim())
}

/// Persist a discovered control so future captures use it automatically.
pub fn save_conf(ctrl: &EmitterControl) -> std::io::Result<()> {
    let path = conf_path();
    if let Some(dir) = path.parent() {
        std::fs::create_dir_all(dir)?;
    }
    std::fs::write(&path, ctrl.encode())
}

/// Parse `unit:selector:b,b,b,...` (decimal or `0x` hex bytes).
fn parse_control(raw: &str) -> Option<EmitterControl> {
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

fn env_control() -> Option<EmitterControl> {
    parse_control(&std::env::var("IRLUME_IR_EMITTER").ok()?)
}

fn parse_u8(s: &str) -> Option<u8> {
    let s = s.trim();
    match s.strip_prefix("0x").or_else(|| s.strip_prefix("0X")) {
        Some(hex) => u8::from_str_radix(hex, 16).ok(),
        None => s.parse().ok(),
    }
}

// --- low-level UVC extension-unit I/O ------------------------------------------

fn xu_query(fd: c_int, unit: u8, selector: u8, query: u8, data: &mut [u8]) -> bool {
    let mut q = UvcXuControlQuery { unit, selector, query, size: data.len() as u16, data: data.as_mut_ptr() };
    // SAFETY: fd is a valid open UVC fd owned by the caller; data outlives the call.
    unsafe { libc::ioctl(fd, uvcioc_ctrl_query(), &mut q as *mut UvcXuControlQuery) >= 0 }
}

/// Length of XU control (unit, selector) if it exists, via `GET_LEN`. Read-only.
fn get_len(fd: c_int, unit: u8, selector: u8) -> Option<usize> {
    let mut buf = [0u8; 2];
    if xu_query(fd, unit, selector, UVC_GET_LEN, &mut buf) {
        let len = u16::from_le_bytes(buf) as usize;
        (1..=64).contains(&len).then_some(len)
    } else {
        None
    }
}

fn get_cur(fd: c_int, unit: u8, selector: u8, size: usize) -> Option<Vec<u8>> {
    let mut buf = vec![0u8; size];
    xu_query(fd, unit, selector, UVC_GET_CUR, &mut buf).then_some(buf)
}

fn set_cur(fd: c_int, unit: u8, selector: u8, payload: &[u8]) -> bool {
    let mut data = payload.to_vec();
    xu_query(fd, unit, selector, UVC_SET_CUR, &mut data)
}

/// Light the emitter on the open device `fd` for camera `card`, if a config is
/// known/configured. Returns true if a SET_CUR succeeded. Best-effort.
pub fn enable(fd: c_int, card: &str) -> bool {
    match std::env::var("IRLUME_IR_EMITTER").ok().as_deref().map(str::trim) {
        Some("off") | Some("none") => return false,
        _ => {}
    }
    let Some(ctrl) = env_control().or_else(load_conf).or_else(|| known_control(card)) else {
        return false;
    };
    set_cur(fd, ctrl.unit, ctrl.selector, &ctrl.payload)
}

/// Candidate SET_CUR payloads to try for a control of `size` bytes — the common
/// Hello-emitter patterns, padded/truncated to size.
fn candidate_payloads(size: usize) -> Vec<Vec<u8>> {
    let mk = |bytes: &[u8]| {
        let mut p = vec![0u8; size];
        for (i, b) in bytes.iter().enumerate() {
            if i < size {
                p[i] = *b;
            }
        }
        p
    };
    let mut v = vec![
        mk(&[1, 3, 2]), // ASUS/NexiGo Hello pattern
        mk(&[1]),
        mk(&[1, 1]),
        mk(&[3]),
        vec![1u8; size], // all-ones
        mk(&[0, 1]),
    ];
    v.dedup();
    v
}

/// Auto-discover the emitter control: enumerate XU controls and try candidate
/// payloads, using `measure` (mean IR brightness while streaming) to detect
/// success — no human "is it flashing?" step. Restores every control it touches
/// that didn't help, so a failed search leaves the camera unchanged. Returns the
/// winning control (already left active) or None.
pub fn autoconfigure(fd: c_int, mut measure: impl FnMut() -> f32) -> Option<EmitterControl> {
    let baseline = measure(); // emitter off
    let success = |b: f32| b >= baseline + 20.0 && b >= 40.0;
    for unit in 0u8..=31 {
        for selector in 0u8..=15 {
            let Some(len) = get_len(fd, unit, selector) else { continue };
            let orig = get_cur(fd, unit, selector, len);
            let mut worked = None;
            for payload in candidate_payloads(len) {
                if !set_cur(fd, unit, selector, &payload) {
                    continue;
                }
                if success(measure()) {
                    worked = Some(payload);
                    break;
                }
            }
            match worked {
                Some(payload) => return Some(EmitterControl { unit, selector, payload }),
                None => {
                    if let Some(o) = orig {
                        let _ = set_cur(fd, unit, selector, &o); // restore (non-destructive)
                    }
                }
            }
        }
    }
    None
}

/// Read-only enumeration of the camera's XU controls (unit, selector, size), for
/// `ir-setup --dry-run` / diagnostics. Touches nothing.
pub fn list_controls(fd: c_int) -> Vec<(u8, u8, usize)> {
    let mut out = Vec::new();
    for unit in 0u8..=31 {
        for selector in 0u8..=15 {
            if let Some(len) = get_len(fd, unit, selector) {
                out.push((unit, selector, len));
            }
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn encode_parse_roundtrip() {
        let c = EmitterControl { unit: 14, selector: 6, payload: vec![1, 3, 2, 0] };
        assert_eq!(parse_control(&c.encode()), Some(c));
    }

    #[test]
    fn candidates_are_correct_size_and_include_hello_pattern() {
        let c = candidate_payloads(9);
        assert!(c.iter().all(|p| p.len() == 9));
        assert!(c.contains(&vec![1, 3, 2, 0, 0, 0, 0, 0, 0]));
    }
}

// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright the irlume contributors.

//! Active-IR emitter activation for Windows-Hello-class UVC cameras.
//!
//! Hello camera modules pair a greyscale NIR sensor with an 850nm illuminator
//! that `uvcvideo` does not drive; on Windows the vendor driver pulses it via a
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
//! Approach credit: EmixamPP/linux-enable-ir-emitter (MIT), the iterative
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

/// 8-bit greyscale mean above which an IR capture counts as emitter-lit.
/// Emitter-only illumination measures ~40-140 on validated hardware (Zenbook,
/// N930W); an unlit sensor sits below ~35 even in a bright room.
pub(crate) const IR_LIT_MEAN: f32 = 40.0;
/// Minimum mean lift over the emitter-off baseline before `autoconfigure`
/// calls a control a success; filters ambient flicker and exposure drift.
const AUTOCONF_MIN_LIFT: f32 = 20.0;
/// Minimum extra lift for a companion BOOST control to beat measurement noise.
const BOOST_MIN_LIFT: f32 = 6.0;

/// Built-in table, matched on the V4L card name (substring). Verified on-hardware.
fn known_control(card: &str) -> Option<EmitterControl> {
    if card.contains("ASUS") {
        return Some(EmitterControl {
            unit: 14,
            selector: 6,
            payload: vec![1, 3, 2, 0, 0, 0, 0, 0, 0],
        });
    }
    if card.contains("N930W") {
        return Some(EmitterControl {
            unit: 4,
            selector: 6,
            payload: vec![1, 3, 2, 0, 0, 0, 0, 0, 0],
        });
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

/// Emitter control: the FIRST line of the conf.
fn load_conf() -> Option<EmitterControl> {
    let raw = std::fs::read_to_string(conf_path()).ok()?;
    parse_control(raw.lines().next()?.trim())
}

/// Optional companion BOOST control: the SECOND line of the conf, if present.
fn load_boost() -> Option<EmitterControl> {
    let raw = std::fs::read_to_string(conf_path()).ok()?;
    parse_control(raw.lines().nth(1)?.trim())
}

/// Persist a discovered emitter control so future captures use it automatically.
pub fn save_conf(ctrl: &EmitterControl) -> std::io::Result<()> {
    save_conf_full(ctrl, None)
}

/// Persist the emitter and (optionally) a companion boost control. The boost is
/// written as a second line and is applied ALONGSIDE the emitter by [`enable`].
pub fn save_conf_full(
    emitter: &EmitterControl,
    boost: Option<&EmitterControl>,
) -> std::io::Result<()> {
    let path = conf_path();
    if let Some(dir) = path.parent() {
        std::fs::create_dir_all(dir)?;
    }
    let mut s = emitter.encode();
    if let Some(b) = boost {
        s.push('\n');
        s.push_str(&b.encode());
    }
    std::fs::write(&path, s)
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
    Some(EmitterControl {
        unit,
        selector,
        payload,
    })
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
    let mut q = UvcXuControlQuery {
        unit,
        selector,
        query,
        size: data.len() as u16,
        data: data.as_mut_ptr(),
    };
    // SAFETY: fd is a valid open UVC fd owned by the caller; data outlives the call.
    unsafe { libc::ioctl(fd, uvcioc_ctrl_query(), &mut q as *mut UvcXuControlQuery) >= 0 }
}

/// GET_LEN bounds check: a plausible XU control reports 1..=64 payload bytes;
/// anything else (0 from a phantom control, or an absurd length) is rejected.
/// Verbatim extraction from [`get_len`] as a test seam; zero behavior change.
fn valid_ctrl_len(len: usize) -> Option<usize> {
    (1..=64).contains(&len).then_some(len)
}

/// Length of XU control (unit, selector) if it exists, via `GET_LEN`. Read-only.
fn get_len(fd: c_int, unit: u8, selector: u8) -> Option<usize> {
    let mut buf = [0u8; 2];
    if xu_query(fd, unit, selector, UVC_GET_LEN, &mut buf) {
        valid_ctrl_len(u16::from_le_bytes(buf) as usize)
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
    match std::env::var("IRLUME_IR_EMITTER")
        .ok()
        .as_deref()
        .map(str::trim)
    {
        Some("off") | Some("none") => return false,
        _ => {}
    }
    let Some(ctrl) = env_control()
        .or_else(load_conf)
        .or_else(|| known_control(card))
    else {
        return false;
    };
    let ok = set_cur(fd, ctrl.unit, ctrl.selector, &ctrl.payload);
    // Apply a discovered companion brightness-boost control (conf-only) alongside
    // the emitter; best-effort, never gates the emitter result.
    if let Some(b) = load_boost() {
        let _ = set_cur(fd, b.unit, b.selector, &b.payload);
    }
    ok
}

/// Candidate SET_CUR payloads to try for a control of `size` bytes: the common
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
/// success; no human "is it flashing?" step. Returns the control+payload that
/// yields the BRIGHTEST IR (not merely the first one that clears the threshold),
/// so a camera with several viable emitter controls gets the one with the most
/// headroom above the liveness floor. Each control is tested in isolation
/// (restored to its original before the next), so measurements aren't polluted;
/// only the global winner is re-applied at the end. A failed search leaves the
/// camera unchanged.
pub fn autoconfigure<F: FnMut() -> f32>(fd: c_int, measure: &mut F) -> Option<EmitterControl> {
    let baseline = measure(); // emitter off
    let success = |b: f32| b >= baseline + AUTOCONF_MIN_LIFT && b >= IR_LIT_MEAN;
    let mut best: Option<(EmitterControl, f32)> = None;
    for unit in 0u8..=31 {
        for selector in 0u8..=15 {
            let Some(len) = get_len(fd, unit, selector) else {
                continue;
            };
            let orig = get_cur(fd, unit, selector, len);
            for payload in candidate_payloads(len) {
                if !set_cur(fd, unit, selector, &payload) {
                    continue;
                }
                let b = measure();
                if success(b) && best.as_ref().is_none_or(|(_, bb)| b > *bb) {
                    best = Some((
                        EmitterControl {
                            unit,
                            selector,
                            payload: payload.clone(),
                        },
                        b,
                    ));
                }
            }
            // Restore this control before testing the next, so each is measured
            // against the emitter-off baseline, not a lingering set control.
            if let Some(o) = orig {
                let _ = set_cur(fd, unit, selector, &o);
            }
        }
    }
    // Re-apply the brightest winner so the camera is left lit on it.
    if let Some((ctrl, _)) = &best {
        let _ = set_cur(fd, ctrl.unit, ctrl.selector, &ctrl.payload);
    }
    best.map(|(ctrl, _)| ctrl)
}

/// After the emitter is set, look for a COMPANION XU control that further
/// brightens the IR: an exposure/gain-like vendor control (e.g. the NexiGo
/// N930W's second control, unit4/sel9). With the emitter kept LIT, sweep each
/// OTHER XU control's boost candidates and keep the one that lifts mean IR
/// brightness the most above the emitter-alone level; restore the rest. Returns
/// the boost control (left applied, alongside the emitter) or None if nothing
/// helped. Non-destructive.
pub fn discover_boost<F: FnMut() -> f32>(
    fd: c_int,
    emitter: &EmitterControl,
    measure: &mut F,
) -> Option<EmitterControl> {
    let relight = |fd: c_int| {
        let _ = set_cur(fd, emitter.unit, emitter.selector, &emitter.payload);
    };
    relight(fd);
    let base = measure(); // emitter on, no boost
    let mut best: Option<(EmitterControl, f32)> = None;
    for unit in 0u8..=31 {
        for selector in 0u8..=15 {
            if unit == emitter.unit && selector == emitter.selector {
                continue; // that's the emitter itself
            }
            let Some(len) = get_len(fd, unit, selector) else {
                continue;
            };
            let orig = get_cur(fd, unit, selector, len);
            for payload in boost_candidates(len) {
                relight(fd); // keep the emitter lit during the boost sweep
                if !set_cur(fd, unit, selector, &payload) {
                    continue;
                }
                let b = measure();
                // Require a clear lift so we don't latch onto measurement noise.
                if b >= base + BOOST_MIN_LIFT && best.as_ref().is_none_or(|(_, bb)| b > *bb) {
                    best = Some((
                        EmitterControl {
                            unit,
                            selector,
                            payload: payload.clone(),
                        },
                        b,
                    ));
                }
            }
            if let Some(o) = orig {
                let _ = set_cur(fd, unit, selector, &o); // restore before the next control
            }
        }
    }
    relight(fd);
    if let Some((c, _)) = &best {
        let _ = set_cur(fd, c.unit, c.selector, &c.payload);
    }
    best.map(|(c, _)| c)
}

/// Candidate payloads for a companion BOOST control (an unknown vendor control
/// that may raise IR exposure/gain). We can't read its semantics, so sweep a few
/// magnitudes low→high; a genuine brightness control gets brighter as the value
/// rises, which `discover_boost` detects from the IR image.
fn boost_candidates(len: usize) -> Vec<Vec<u8>> {
    let full = |v: u8| vec![v; len];
    let low_bytes = |n: usize| {
        let mut p = vec![0u8; len];
        for b in p.iter_mut().take(n) {
            *b = 0xFF;
        }
        p
    };
    let mut v = vec![
        full(0xFF),
        full(0x80),
        full(0x40),
        low_bytes(1),
        low_bytes(2),
    ];
    v.dedup();
    v
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
        let c = EmitterControl {
            unit: 14,
            selector: 6,
            payload: vec![1, 3, 2, 0],
        };
        assert_eq!(parse_control(&c.encode()), Some(c));
    }

    #[test]
    fn candidates_are_correct_size_and_include_hello_pattern() {
        let c = candidate_payloads(9);
        assert!(c.iter().all(|p| p.len() == 9));
        assert!(c.contains(&vec![1, 3, 2, 0, 0, 0, 0, 0, 0]));
    }

    /// Serializes access to the process env vars these tests flip
    /// (`IRLUME_IR_EMITTER`, `IRLUME_IR_EMITTER_CONF`); cargo runs tests on
    /// parallel threads sharing one environment.
    static ENV_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

    fn env_guard() -> std::sync::MutexGuard<'static, ()> {
        ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner())
    }

    /// An fd that is open but is not a UVC device, so every XU ioctl fails
    /// (ENOTTY): exercises the query-failure paths without touching a camera.
    fn non_uvc_fd() -> std::fs::File {
        std::fs::File::open("/dev/null").expect("open /dev/null")
    }

    #[test]
    fn parse_control_accepts_decimal_and_hex() {
        assert_eq!(
            parse_control("14:6:1,3,2"),
            Some(EmitterControl {
                unit: 14,
                selector: 6,
                payload: vec![1, 3, 2],
            })
        );
        assert_eq!(
            parse_control(" 0x0E:0X06:0x01,255 "),
            Some(EmitterControl {
                unit: 14,
                selector: 6,
                payload: vec![1, 255],
            })
        );
    }

    #[test]
    fn parse_control_rejects_garbage() {
        // Empty / non-numeric / missing fields.
        assert_eq!(parse_control(""), None);
        assert_eq!(parse_control("   "), None);
        assert_eq!(parse_control("abc"), None);
        assert_eq!(parse_control("1:2"), None); // no payload section
        assert_eq!(parse_control("1:2:"), None); // empty payload
        assert_eq!(parse_control("x:2:1"), None); // bad unit
        assert_eq!(parse_control("1:y:1"), None); // bad selector
                                                  // Out-of-range unit/selector (u8 overflow) fail the whole parse.
        assert_eq!(parse_control("256:1:1"), None);
        assert_eq!(parse_control("1:300:1"), None);
        // A payload of only invalid bytes is empty -> rejected...
        assert_eq!(parse_control("1:2:300"), None);
        // ...while invalid bytes among valid ones are dropped (filter_map).
        assert_eq!(
            parse_control("1:2:1,300,2").map(|c| c.payload),
            Some(vec![1, 2])
        );
    }

    #[test]
    fn known_control_table_matches_verified_cards() {
        // ASUS built-in Hello module: XU unit 14, selector 6.
        let asus = known_control("USB Camera: ASUS FHD webcam").expect("ASUS entry");
        assert_eq!((asus.unit, asus.selector), (14, 6));
        assert_eq!(asus.payload, vec![1, 3, 2, 0, 0, 0, 0, 0, 0]);
        // NexiGo HelloCam N930W: unit 4, same selector/payload.
        let nexigo = known_control("NexiGo HelloCam N930W IR").expect("N930W entry");
        assert_eq!((nexigo.unit, nexigo.selector), (4, 6));
        assert_eq!(nexigo.payload, vec![1, 3, 2, 0, 0, 0, 0, 0, 0]);
        // Unlisted cameras get no hard-coded control (auto-setup territory).
        assert_eq!(known_control("Logitech Brio"), None);
        assert_eq!(known_control(""), None);
    }

    #[test]
    fn valid_ctrl_len_bounds() {
        // GET_LEN plausibility: 1..=64 accepted, 0 and oversize rejected.
        assert_eq!(valid_ctrl_len(0), None);
        assert_eq!(valid_ctrl_len(1), Some(1));
        assert_eq!(valid_ctrl_len(9), Some(9));
        assert_eq!(valid_ctrl_len(64), Some(64));
        assert_eq!(valid_ctrl_len(65), None);
        assert_eq!(valid_ctrl_len(usize::MAX), None);
    }

    #[test]
    fn conf_roundtrip_with_and_without_boost() {
        let _g = env_guard();
        let dir = std::env::temp_dir().join(format!("irlume-emitter-conf-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let conf = dir.join("ir_emitter.conf");
        std::env::set_var("IRLUME_IR_EMITTER_CONF", &conf);

        let emitter = EmitterControl {
            unit: 4,
            selector: 6,
            payload: vec![1, 3, 2],
        };
        let boost = EmitterControl {
            unit: 4,
            selector: 9,
            payload: vec![255, 255],
        };
        // Emitter alone: one line, no boost on load.
        save_conf(&emitter).unwrap();
        assert_eq!(load_conf(), Some(emitter.clone()));
        assert_eq!(load_boost(), None);
        // Emitter + boost: two lines, both load back exactly.
        save_conf_full(&emitter, Some(&boost)).unwrap();
        assert_eq!(
            std::fs::read_to_string(&conf).unwrap(),
            "4:6:1,3,2\n4:9:255,255"
        );
        assert_eq!(load_conf(), Some(emitter));
        assert_eq!(load_boost(), Some(boost));
        // Missing conf: both loaders return None.
        std::fs::remove_file(&conf).unwrap();
        assert_eq!(load_conf(), None);
        assert_eq!(load_boost(), None);

        std::env::remove_var("IRLUME_IR_EMITTER_CONF");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn enable_honors_off_env_and_config_precedence() {
        let _g = env_guard();
        let dir = std::env::temp_dir().join(format!("irlume-emitter-en-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        // Point the conf away from any real /var/lib/irlume install.
        std::env::set_var("IRLUME_IR_EMITTER_CONF", dir.join("none.conf"));
        let f = non_uvc_fd();
        use std::os::fd::AsRawFd;
        let fd = f.as_raw_fd();

        // `off`/`none` disable before any control lookup or ioctl.
        std::env::set_var("IRLUME_IR_EMITTER", "off");
        assert!(!enable(fd, "ASUS"));
        std::env::set_var("IRLUME_IR_EMITTER", "none");
        assert!(!enable(fd, "ASUS"));
        // A valid env control is parsed, but SET_CUR on a non-UVC fd fails.
        std::env::set_var("IRLUME_IR_EMITTER", "14:6:1,3,2");
        assert!(!enable(fd, "whatever"));
        std::env::remove_var("IRLUME_IR_EMITTER");
        // No env, no conf, unknown card: no control at all.
        assert!(!enable(fd, "Some Unknown Cam"));
        // No env, no conf, known card: the table entry is used (ioctl still fails).
        assert!(!enable(fd, "ASUS"));
        // No env, conf present: the persisted control is used (ioctl still fails).
        save_conf(&EmitterControl {
            unit: 1,
            selector: 2,
            payload: vec![7],
        })
        .unwrap();
        assert!(!enable(fd, "Some Unknown Cam"));

        std::env::remove_var("IRLUME_IR_EMITTER_CONF");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn boost_candidates_sized_and_swept_low_to_high_magnitudes() {
        let c = boost_candidates(4);
        assert!(c.iter().all(|p| p.len() == 4));
        assert!(c.contains(&vec![0xFF; 4]));
        assert!(c.contains(&vec![0x80; 4]));
        assert!(c.contains(&vec![0xFF, 0, 0, 0]));
        assert!(c.contains(&vec![0xFF, 0xFF, 0, 0]));
        // Degenerate size 1: full(0xFF) and low_bytes collapse; dedup shrinks.
        let one = boost_candidates(1);
        assert!(one.iter().all(|p| p.len() == 1));
        assert!(one.contains(&vec![0xFF]));
    }

    #[test]
    fn candidate_payloads_truncate_to_small_controls() {
        // A 1-byte control still gets the leading bytes of each pattern.
        let one = candidate_payloads(1);
        assert!(one.iter().all(|p| p.len() == 1));
        assert!(one.contains(&vec![1]));
        assert!(one.contains(&vec![3]));
        assert!(one.contains(&vec![0]));
    }

    #[test]
    fn discovery_on_a_non_uvc_fd_finds_nothing_and_stays_safe() {
        let f = non_uvc_fd();
        use std::os::fd::AsRawFd;
        let fd = f.as_raw_fd();
        // Every GET_LEN fails -> no controls enumerated.
        assert!(list_controls(fd).is_empty());
        // Autoconfigure: baseline measured exactly once, sweep finds nothing.
        let mut calls = 0u32;
        let mut measure = || {
            calls += 1;
            0.0f32
        };
        assert_eq!(autoconfigure(fd, &mut measure), None);
        assert_eq!(calls, 1, "only the emitter-off baseline is measured");
        // Boost discovery: emitter-on base measured once, nothing found.
        let emitter = EmitterControl {
            unit: 14,
            selector: 6,
            payload: vec![1, 3, 2],
        };
        let mut calls = 0u32;
        let mut measure = || {
            calls += 1;
            0.0f32
        };
        assert_eq!(discover_boost(fd, &emitter, &mut measure), None);
        assert_eq!(calls, 1, "only the emitter-alone base is measured");
    }
}

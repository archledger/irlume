// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright the irlume contributors.

//! Issue ONE extension-unit `SET_CUR`, owned by no guard.
//!
//! Test tooling, not a feature. Two jobs, both impossible from outside the
//! process otherwise (killing a daemon mid-capture cannot interpose between
//! apply and restore — they are microseconds apart, measured on the NexiGo):
//!
//!   * PARK a control at its device default before a hardware run, so
//!     discovery and the capture path actually have something to write. The
//!     daemon's own guard now restores what it displaced, so a previous run
//!     no longer leaves the control parked for the next one.
//!   * plant "another writer's" value for the #188 leftover tests: set the
//!     face-auth value from outside irlume and confirm a capture leaves it
//!     alone, or leave a value behind and confirm only a stream RECORD makes
//!     irlume claim it.
//!
//! The unit and selector must be published by the camera's descriptors —
//! the same consent rule as `IRLUME_IR_EMITTER` — but the BYTES are yours,
//! and nothing validates them. #159 is a camera that never enumerated again
//! after invented bytes reached its firmware. Send only values the device
//! itself reported: `def` asks the device and writes its own `GET_DEF`.
//!
//! Usage:
//!   cargo run -p irlume-camera --example xu_set -- <video-dev> <unit> <selector> get
//!   cargo run -p irlume-camera --example xu_set -- <video-dev> <unit> <selector> def
//!   cargo run -p irlume-camera --example xu_set -- <video-dev> <unit> <selector> <b0,b1,...>
//!
//! `get` reads GET_CUR and writes nothing at all. Bytes are decimal or 0x-hex,
//! comma-separated, and must match GET_LEN.

use irlume_camera::ir_emitter::raw;
use irlume_camera::uvc_descriptor;

fn parse_byte(s: &str) -> Result<u8, String> {
    let s = s.trim();
    if let Some(hex) = s.strip_prefix("0x").or_else(|| s.strip_prefix("0X")) {
        u8::from_str_radix(hex, 16).map_err(|e| format!("{s}: {e}"))
    } else {
        s.parse().map_err(|e| format!("{s}: {e}"))
    }
}

fn run() -> Result<(), String> {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let [device, unit, selector, value] = args.as_slice() else {
        return Err("usage: xu_set <video-dev> <unit> <selector> <get|def|b0,b1,...>".to_string());
    };
    let unit: u8 = unit.parse().map_err(|e| format!("unit {unit}: {e}"))?;
    let selector: u8 = selector
        .parse()
        .map_err(|e| format!("selector {selector}: {e}"))?;

    let dev = v4l::Device::with_path(device).map_err(|e| format!("open {device}: {e}"))?;
    let handle = dev.handle();
    let fd = handle.fd();

    // The same gate every irlume write passes: the camera must say the control
    // exists. Identity comes from the open descriptor, not the path.
    let id = uvc_descriptor::identity_from_fd(fd)
        .map_err(|e| format!("read {device}'s USB descriptors: {e}"))?;
    let published = id
        .microsoft_xu()
        .is_some_and(|ms| ms.unit_id == unit && ms.advertises(selector));
    if !published {
        return Err(format!(
            "{} does not publish unit {unit} selector {selector} on its Microsoft XU; \
             refusing to write to a control the camera never said it has",
            id.usb_id()
        ));
    }

    let len = raw::get_len(fd, unit, selector)?;
    let before = raw::get_cur(fd, unit, selector, len)?;
    if value == "get" {
        // Read-only: the one line a harness parses, and no ioctl but GETs.
        println!("{}", before.iter().map(|b| format!("{b:02x}")).collect::<String>());
        return Ok(());
    }
    let payload = if value == "def" {
        raw::get_def(fd, unit, selector, len)?
    } else {
        value
            .split(',')
            .map(parse_byte)
            .collect::<Result<Vec<u8>, String>>()?
    };
    if payload.len() != len {
        return Err(format!(
            "the control takes {len} bytes, {} given; nothing was sent",
            payload.len()
        ));
    }
    eprintln!("xu_set: unit{unit}/sel{selector} before: {before:02x?}");
    raw::set_cur(fd, unit, selector, &payload)?;
    let after = raw::get_cur(fd, unit, selector, len)?;
    eprintln!("xu_set: unit{unit}/sel{selector} wrote:  {payload:02x?}");
    eprintln!("xu_set: unit{unit}/sel{selector} after:  {after:02x?}");
    if after != payload {
        eprintln!("xu_set: note: the control did not read back what was written");
    }
    Ok(())
}

fn main() {
    if let Err(why) = run() {
        eprintln!("xu_set: {why}");
        std::process::exit(1);
    }
}

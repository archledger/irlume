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
//!   cargo run -p irlume-camera --example xu_set -- <video-dev> <unit> <selector> snapshot
//!   cargo run -p irlume-camera --example xu_set -- <video-dev> <unit> <selector> identity
//!   cargo run -p irlume-camera --example xu_set -- <video-dev> <unit> <selector> def
//!   cargo run -p irlume-camera --example xu_set -- <video-dev> <unit> <selector> <b0,b1,...>
//!   cargo run -p irlume-camera --example xu_set -- <video-dev> <unit> <selector> \
//!       <b0,b1,...> --expect-camera <identity-token>
//!
//! `get` reads GET_CUR and writes nothing at all. Bytes are decimal or 0x-hex,
//! comma-separated, and must match GET_LEN.

use irlume_camera::ir_emitter::raw;
use irlume_camera::uvc_descriptor;
use std::os::unix::fs::MetadataExt;

fn parse_byte(s: &str) -> Result<u8, String> {
    let s = s.trim();
    if let Some(hex) = s.strip_prefix("0x").or_else(|| s.strip_prefix("0X")) {
        u8::from_str_radix(hex, 16).map_err(|e| format!("{s}: {e}"))
    } else {
        s.parse().map_err(|e| format!("{s}: {e}"))
    }
}

fn identity_token(id: &uvc_descriptor::CameraIdentity, sysfs_instance: (u64, u64)) -> String {
    let descriptor_sha256 = irlume_common::sha256_hex(&id.descriptors);
    let serial = id.serial.as_deref().unwrap_or("");
    irlume_common::sha256_hex(
        format!(
            "descriptors:{descriptor_sha256}|interface:{}|serial:{}:{serial}|devpath:{}:{}|sysfs:{}:{}",
            id.interface_number,
            serial.len(),
            id.usb_devpath.len(),
            id.usb_devpath,
            sysfs_instance.0,
            sysfs_instance.1,
        )
        .as_bytes(),
    )
}

fn live_identity_token(id: &uvc_descriptor::CameraIdentity) -> Result<String, String> {
    let path = format!("/sys{}", id.usb_devpath);
    let metadata = std::fs::metadata(&path)
        .map_err(|error| format!("inspect current camera incarnation at {path}: {error}"))?;
    Ok(identity_token(id, (metadata.dev(), metadata.ino())))
}

fn snapshot_line(
    id: &uvc_descriptor::CameraIdentity,
    token: &str,
    unit: u8,
    selector: u8,
    bytes: &[u8],
) -> String {
    let bytes = bytes.iter().map(|b| format!("{b:02x}")).collect::<String>();
    format!(
        "{token} {} {} {unit} {selector} {bytes}",
        id.usb_id(),
        id.interface_number,
    )
}

fn run() -> Result<(), String> {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let (device, unit, selector, value, expected_camera) = match args.as_slice() {
        [device, unit, selector, value] => (device, unit, selector, value, None),
        [device, unit, selector, value, flag, expected] if flag == "--expect-camera" => {
            (device, unit, selector, value, Some(expected.as_str()))
        }
        _ => {
            return Err("usage: xu_set <video-dev> <unit> <selector> \
                 <get|snapshot|identity|def|b0,b1,...> [--expect-camera <identity-token>]"
                .to_string());
        }
    };
    let unit: u8 = unit.parse().map_err(|e| format!("unit {unit}: {e}"))?;
    let selector: u8 = selector
        .parse()
        .map_err(|e| format!("selector {selector}: {e}"))?;

    let operation = irlume_camera::lease::acquire_camera_operation(
        &[device.as_str()],
        irlume_camera::lease::CameraOperationKind::Setup,
        std::time::Duration::from_secs(2),
    )
    .map_err(|error| error.to_string())?;
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
    let current_camera = live_identity_token(&id)?;
    if value == "identity" {
        if expected_camera.is_some() {
            return Err("identity does not accept --expect-camera".to_string());
        }
        println!("{current_camera}");
        return Ok(());
    }
    if let Some(expected) = expected_camera {
        if current_camera != expected {
            return Err(format!(
                "camera identity changed: expected {expected}, found {current_camera}; nothing was sent"
            ));
        }
    }

    let len = raw::get_len(fd, unit, selector)?;
    let before = raw::get_cur(fd, unit, selector, len)?;
    if value == "snapshot" {
        if expected_camera.is_some() {
            return Err("snapshot does not accept --expect-camera".to_string());
        }
        println!(
            "{}",
            snapshot_line(&id, &current_camera, unit, selector, &before)
        );
        return Ok(());
    }
    if value == "get" {
        // Read-only: the one line a harness parses, and no ioctl but GETs.
        println!(
            "{}",
            before
                .iter()
                .map(|b| format!("{b:02x}"))
                .collect::<String>()
        );
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
    operation
        .lease()
        .validate()
        .map_err(|error| error.to_string())?;
    raw::set_cur(&operation, fd, unit, selector, &payload)?;
    let after = raw::get_cur(fd, unit, selector, len)?;
    eprintln!("xu_set: unit{unit}/sel{selector} wrote:  {payload:02x?}");
    eprintln!("xu_set: unit{unit}/sel{selector} after:  {after:02x?}");
    if after != payload {
        // An exit status the harnesses can key on: a camera that clamps,
        // ignores or rewrites the payload has NOT been put into the state
        // the caller asked for, and a park or plant that silently did not
        // take makes every assertion built on it vacuous.
        return Err(format!(
            "the control did not take the value: wrote {payload:02x?}, reads {after:02x?}"
        ));
    }
    Ok(())
}

fn main() {
    if let Err(why) = run() {
        eprintln!("xu_set: {why}");
        std::process::exit(1);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn identity() -> irlume_camera::uvc_descriptor::CameraIdentity {
        irlume_camera::uvc_descriptor::CameraIdentity {
            descriptors: vec![1, 2, 3, 4],
            interface_number: 1,
            vid: 0x3277,
            pid: 0x0059,
            serial: Some("camera-a".into()),
            usb_devpath: "/devices/pci/usb/camera".into(),
        }
    }

    #[test]
    fn expected_camera_token_binds_the_current_sysfs_incarnation() {
        let id = identity();
        assert_eq!(identity_token(&id, (7, 11)), identity_token(&id, (7, 11)));
        assert_ne!(identity_token(&id, (7, 11)), identity_token(&id, (7, 12)));

        let mut replacement = identity();
        replacement.serial = Some("camera-b".into());
        assert_ne!(
            identity_token(&id, (7, 11)),
            identity_token(&replacement, (7, 11))
        );
    }

    #[test]
    fn snapshot_line_binds_control_bytes_to_descriptor_identity() {
        let id = identity();
        assert_eq!(
            snapshot_line(&id, "identity-token", 14, 6, &[1, 3, 1]),
            "identity-token 3277:0059 1 14 6 010301"
        );
    }
}

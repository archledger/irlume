// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright the irlume contributors.

//! READ-ONLY fleet probe for the Microsoft camera-control extension unit:
//! which XUs each camera advertises, and the MS XU's published contract for
//! exposure / face-auth / IR-torch. Zero writes (see the camera-control
//! safety dossier); answers whether the Windows-Hello firmware-strobe path
//! is reachable per device.
//!
//! Usage: cargo run --release -p irlume-camera --example msxu_probe -- \
//!   [/dev/video0 [/dev/video2 ...]]

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let devices: Vec<String> = if args.is_empty() {
        vec!["/dev/video0".to_string(), "/dev/video2".to_string()]
    } else {
        args
    };
    for device in devices {
        match irlume_camera::ir_emitter::microsoft_xu_report(&device) {
            Ok(report) => println!("{report}"),
            Err(e) => eprintln!("{device}: {e}"),
        }
    }
}

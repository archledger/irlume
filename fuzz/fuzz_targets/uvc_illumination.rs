#![no_main]
// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright the irlume contributors.
//! The UVC MS-XU illumination metadata parser.
//!
//! uvcvideo hands the daemon whatever bytes the camera appended to its UVC
//! payload headers, and until the "Avoid partial metadata buffers" series
//! (Fixes 088ead255245, in stable from 6.12.97 on) the FIRST buffer of a
//! metadata queue that transitioned from empty to ready started mid-header.
//! A camera is external hardware on a USB port, so this is attacker-reachable
//! input to a root daemon: a panic or hang here is a local denial of service
//! against authentication. The parser must answer or return None on every
//! byte string, and burst selection must stay inside the burst and never let
//! a camera-flagged-dark frame beat a flagged-lit one while a lit one exists.
use irlume_camera::ir_metadata::{brightest_lit, parse_illumination, Illumination};
use irlume_camera::uvc_descriptor::{
    active_descriptor_view, extension_units_for_interface, CameraIdentity, MS_CAMERA_CONTROL_XU,
};
use libfuzzer_sys::fuzz_target;

// Encode the same frame-level bytes with different USB payload boundaries.
// Chunk size is bounded by bHeaderLength, not metadata item boundaries.
fn frame_bytes(items: &[u8], chunk: usize, flags: u8) -> Vec<u8> {
    let standard = usize::from(flags & 4 != 0) * 4 + usize::from(flags & 8 != 0) * 6;
    let mut frame = Vec::new();
    for part in items.chunks(chunk) {
        frame.extend_from_slice(&[0; 10]);
        frame.push((2 + standard + part.len()) as u8);
        frame.push(flags);
        frame.resize(frame.len() + standard, 0);
        frame.extend_from_slice(part);
    }
    frame
}

fn usb_configuration(value: u8, unit: u8, total: [u8; 2]) -> Vec<u8> {
    let mut descriptor = vec![9, 2, total[0], total[1], 1, value, 0, 0x80, 50];
    descriptor.extend_from_slice(&[9, 4, 0, 0, 0, 0x0e, 1, 0, 0]);
    descriptor.extend_from_slice(&[26, 0x24, 6, unit]);
    descriptor.extend_from_slice(&MS_CAMERA_CONTROL_XU);
    descriptor.extend_from_slice(&[1, 1, 1, 1, 0x20, 0]);
    descriptor
}

fuzz_target!(|data: &[u8]| {
    // Parsing is deterministic: identical bytes must classify identically,
    // whatever the ring state around them.
    assert_eq!(parse_illumination(data), parse_illumination(data));

    if data.is_empty() {
        return;
    }
    // USB configuration scope is also externally supplied data. Arbitrary
    // inputs must remain bounded and deterministic; the constructed valid
    // case checks meaning even when random input mostly fails framing.
    let arbitrary_view = active_descriptor_view(data, data[0]);
    assert_eq!(arbitrary_view, active_descriptor_view(data, data[0]));
    if let Some(view) = arbitrary_view {
        assert!(view.len() <= data.len());
        let _ = extension_units_for_interface(&view, data[0]);
    }
    let active = data[0] % 2 + 1;
    let total = [data[0], *data.get(1).unwrap_or(&0)];
    let mut usb = vec![
        18, 1, 0, 2, 0, 0, 0, 64, 0x77, 0x32, 0x59, 0, 0, 1, 0, 0, 0, 2,
    ];
    usb.extend(usb_configuration(1, 14, total));
    usb.extend(usb_configuration(2, 4, total));
    let view =
        active_descriptor_view(&usb, active).expect("valid bLength-framed USB configurations");
    let units = extension_units_for_interface(&view, 0);
    assert_eq!(
        units.len(),
        1,
        "inactive duplicate Microsoft units are not visible"
    );
    assert_eq!(units[0].unit_id, if active == 1 { 14 } else { 4 });
    assert!(units[0].advertises(6));
    assert!(
        extension_units_for_interface(&usb, 0).is_empty(),
        "unscoped input carries no selection authority"
    );
    let mut identity = CameraIdentity {
        descriptors: usb,
        active_configuration: 1,
        interface_number: 0,
        vid: 0x3277,
        pid: 0x0059,
        serial: None,
        usb_devpath: "/devices/synthetic".into(),
    };
    let first = identity.descriptor_fingerprint();
    identity.active_configuration = 2;
    assert_ne!(first, identity.descriptor_fingerprint());
    identity.active_configuration = 1;
    // Change the inactive configuration's GUID, retaining the active view.
    identity.descriptors[18 + 44 + 9 + 9 + 4] ^= 1;
    assert_ne!(first, identity.descriptor_fingerprint());
    let chunk = usize::from(data[0]) % 243 + 1;
    let flags = 0x80 | (data[0] & 0x0c);
    // Malformed as well as valid item streams must be partition-independent.
    // Limit transport expansion when the fuzzer chooses one-byte fragments.
    let items = &data[..data.len().min(4096)];
    assert_eq!(
        parse_illumination(&frame_bytes(items, 243, 0x8c)),
        parse_illumination(&frame_bytes(items, chunk, flags)),
    );

    // An independent expected-value oracle prevents "always unknown" from
    // satisfying equivalence. Opaque custom bytes may themselves look like
    // records; the only actual illumination item follows the custom item.
    let payload_len = items.len().div_ceil(8) * 8;
    let mut valid = 0x8000_0000u32.to_le_bytes().to_vec();
    valid.extend_from_slice(&((8 + payload_len) as u32).to_le_bytes());
    valid.extend_from_slice(items);
    valid.resize(8 + payload_len, 0);
    valid.extend_from_slice(&[6, 0, 0, 0, 16, 0, 0, 0]);
    valid.extend_from_slice(&u32::from(data[0] & 1).to_le_bytes());
    valid.extend_from_slice(&[0; 4]);
    let expected = Some(if data[0] & 1 != 0 {
        Illumination::Lit
    } else {
        Illumination::Dark
    });
    assert_eq!(
        parse_illumination(&frame_bytes(&valid, chunk, flags)),
        expected
    );

    // Derive a small selection problem from the bytes so the invariant runs
    // on fuzzer-shaped inputs rather than only the unit fixtures.
    let n = usize::from(data[data.len() - 1]) % 8 + 1;
    let means: Vec<f64> = (0..n).map(|i| f64::from(data[i % data.len()])).collect();
    let flags: Vec<Option<Illumination>> = (0..n)
        .map(|i| match data[(i + n) % data.len()] % 3 {
            0 => None,
            1 => Some(Illumination::Lit),
            _ => Some(Illumination::Dark),
        })
        .collect();
    if let Some(best) = brightest_lit(&means, &flags) {
        assert!(best < means.len(), "selection must stay inside the burst");
        let any_lit = flags
            .iter()
            .any(|flag| matches!(flag, Some(Illumination::Lit)));
        if any_lit {
            assert!(
                matches!(flags[best], Some(Illumination::Lit)),
                "a lit frame exists, so a dark-flagged frame must not win"
            );
        }
    }
});

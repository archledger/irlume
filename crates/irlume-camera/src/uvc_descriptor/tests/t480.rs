// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright the irlume contributors.

//! Descriptor builders for synthetic shapes, laid out byte for byte as the
//! ThinkPad T480 IR camera (USB 5986:1141) lays out the same descriptors.
//!
//! The T480 tests read the #887 reporter's own sysfs `descriptors` files,
//! `tests/fixtures/bison-5986-1141.descriptors` (the IR camera) and
//! `tests/fixtures/bison-5986-2113.descriptors` (the colour camera), as the
//! census verification rule (#575) wants: bytes a real camera emitted, like
//! `tests/fixtures/asus-3277-0059.descriptors`.
//!
//! These builders serve only the counter-cases no real camera supplies: a
//! function that differs from the synthetic attested shape
//! (`attested_shape` in the parent tests, not the real file) in the one
//! field a test names (two streams, a colour bit, a Microsoft unit without
//! selector 0x06, a truncated header), a second VideoControl function on
//! the same device, a vendor-class grabber and an extra configuration. They
//! began as a transcription of a published `lsusb -v` report (linuxhw LsUSB
//! `31A261423C`); the whole-device transcriptions are gone now that the
//! real files back the T480 tests.

/// The device descriptor.
pub(super) fn device(pid: u16, bcd_device: u16, strings: [u8; 3]) -> Vec<u8> {
    let mut bytes = vec![18, 0x01, 0x01, 0x02, 0xEF, 0x02, 0x01, 64];
    bytes.extend_from_slice(&0x5986u16.to_le_bytes());
    bytes.extend_from_slice(&pid.to_le_bytes());
    bytes.extend_from_slice(&bcd_device.to_le_bytes());
    bytes.extend_from_slice(&strings);
    bytes.push(1); // bNumConfigurations
    bytes
}

/// A configuration descriptor with the given `wTotalLength`.
pub(super) fn configuration(total: u16, interfaces: u8, i_configuration: u8) -> Vec<u8> {
    let mut bytes = vec![9, 0x02];
    bytes.extend_from_slice(&total.to_le_bytes());
    // bConfigurationValue 1, bmAttributes 0x80, MaxPower 500 mA.
    bytes.extend_from_slice(&[interfaces, 1, i_configuration, 0x80, 250]);
    bytes
}

/// A standard interface descriptor of the video class.
pub(super) fn interface(
    number: u8,
    alternate: u8,
    endpoints: u8,
    subclass: u8,
    protocol: u8,
    i: u8,
) -> Vec<u8> {
    vec![
        9, 0x04, number, alternate, endpoints, 0x0E, subclass, protocol, i,
    ]
}

/// `VC_HEADER` listing `streams`.
pub(super) fn vc_header(bcd_uvc: u16, total: u16, clock_hz: u32, streams: &[u8]) -> Vec<u8> {
    let mut bytes = vec![12 + streams.len() as u8, 0x24, 0x01];
    bytes.extend_from_slice(&bcd_uvc.to_le_bytes());
    bytes.extend_from_slice(&total.to_le_bytes());
    bytes.extend_from_slice(&clock_hz.to_le_bytes());
    bytes.push(streams.len() as u8);
    bytes.extend_from_slice(streams);
    bytes
}

/// `VC_PROCESSING_UNIT`, with the bytes after `bmControls`: `iProcessing`,
/// and `bmVideoStandards` when the descriptor carries one.
pub(super) fn processing_unit(
    id: u8,
    source: u8,
    max_multiplier: u16,
    control_size: u8,
    controls: u32,
    tail: &[u8],
) -> Vec<u8> {
    let bitmap = &controls.to_le_bytes()[..usize::from(control_size)];
    let mut bytes = vec![
        (8 + bitmap.len() + tail.len()) as u8,
        0x24,
        0x05,
        id,
        source,
    ];
    bytes.extend_from_slice(&max_multiplier.to_le_bytes());
    bytes.push(control_size);
    bytes.extend_from_slice(bitmap);
    bytes.extend_from_slice(tail);
    bytes
}

/// A GUID as `lsusb` prints it, in descriptor byte order: the first three
/// fields little-endian, the rest as written.
pub(super) fn guid(printed: &str) -> [u8; 16] {
    let hex: String = printed.chars().filter(char::is_ascii_hexdigit).collect();
    let raw: Vec<u8> = (0..16)
        .map(|at| u8::from_str_radix(&hex[2 * at..2 * at + 2], 16).unwrap())
        .collect();
    let mut bytes = [0u8; 16];
    bytes[..4].copy_from_slice(&[raw[3], raw[2], raw[1], raw[0]]);
    bytes[4..6].copy_from_slice(&[raw[5], raw[4]]);
    bytes[6..8].copy_from_slice(&[raw[7], raw[6]]);
    bytes[8..].copy_from_slice(&raw[8..]);
    bytes
}

/// `VC_EXTENSION_UNIT` with one source pin.
pub(super) fn extension_unit(
    id: u8,
    printed_guid: &str,
    num_controls: u8,
    source: u8,
    controls: &[u8],
    i_extension: u8,
) -> Vec<u8> {
    let mut bytes = vec![25 + controls.len() as u8, 0x24, 0x06, id];
    bytes.extend_from_slice(&guid(printed_guid));
    bytes.extend_from_slice(&[num_controls, 1, source, controls.len() as u8]);
    bytes.extend_from_slice(controls);
    bytes.push(i_extension);
    bytes
}

/// The VideoControl interrupt endpoint and its class-specific descriptor,
/// as 5986:1141 carries them (`wMaxTransferSize` 32).
pub(super) fn interrupt_endpoint(address: u8, interval: u8) -> Vec<u8> {
    vec![
        7, 0x05, address, 0x03, 0x10, 0x00, interval, 5, 0x25, 0x03, 0x20, 0x00,
    ]
}

/// `VS_INPUT_HEADER` for endpoint 0x81, still method 2, hardware trigger.
pub(super) fn vs_input_header(total: u16, terminal: u8, format_controls: &[u8]) -> Vec<u8> {
    let mut bytes = vec![
        13 + format_controls.len() as u8,
        0x24,
        0x01,
        format_controls.len() as u8,
    ];
    bytes.extend_from_slice(&total.to_le_bytes());
    bytes.extend_from_slice(&[0x81, 0, terminal, 2, 1, 0, 1]);
    bytes.extend_from_slice(format_controls);
    bytes
}

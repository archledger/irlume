// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright the irlume contributors.

//! ThinkPad T480 camera descriptors, TRANSCRIBED from published `lsusb -v`
//! text, not captured from a device.
//!
//! Source: linuxhw LsUSB report `31A261423C` (a ThinkPad T480 20L5CTO1WW on
//! Gentoo, kernel 5.1.8), the one report of this machine that prints raw
//! extension-unit GUIDs:
//! <https://github.com/linuxhw/LsUSB/blob/master/Notebook/Lenovo/ThinkPad/ThinkPad%20T480%2020L5CTO1WW/413C62D00DF1/GENTOO/5.1.8-GENTOO/X86_64/31A261423C>
//!
//! Each builder writes the device descriptor and the one configuration in
//! the order `lsusb` printed them, every field as printed. That lsusb did not
//! print the 5-byte class-specific interrupt endpoint that follows each
//! VideoControl interrupt endpoint; the configuration's `wTotalLength`
//! counts it, so it is added as `05 25 03 10 00` (wMaxTransferSize 16, the
//! interrupt endpoint's packet size), and a test checks every built
//! configuration against its printed `wTotalLength`.
//!
//! These stand in for real sysfs `descriptors` files until the #887
//! reporter's are attached. The census verification rule (#575) wants bytes
//! a real camera emitted, like `tests/fixtures/asus-3277-0059.descriptors`:
//! replace both builders with `tests/fixtures/bison-5986-1141.descriptors`
//! and `tests/fixtures/bison-5986-2113.descriptors` when they arrive, and
//! keep the tests that use them.

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

/// A configuration descriptor with the printed `wTotalLength`.
pub(super) fn configuration(total: u16, interfaces: u8, i_configuration: u8) -> Vec<u8> {
    let mut bytes = vec![9, 0x02];
    bytes.extend_from_slice(&total.to_le_bytes());
    // bConfigurationValue 1, bmAttributes 0x80, MaxPower 500 mA.
    bytes.extend_from_slice(&[interfaces, 1, i_configuration, 0x80, 250]);
    bytes
}

/// A Video Interface Collection association over interfaces 0 and 1.
pub(super) fn video_association(i_function: u8) -> Vec<u8> {
    vec![8, 0x0B, 0, 2, 0x0E, 0x03, 0, i_function]
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

/// A camera-sensor input terminal with a three-byte `bmControls`.
pub(super) fn camera_terminal(id: u8, controls: u32) -> Vec<u8> {
    let mut bytes = vec![18, 0x24, 0x02, id, 0x01, 0x02, 0, 0, 0, 0, 0, 0, 0, 0, 3];
    bytes.extend_from_slice(&controls.to_le_bytes()[..3]);
    bytes
}

/// `VC_PROCESSING_UNIT`, with the bytes after `bmControls` as printed:
/// `iProcessing`, and `bmVideoStandards` when the descriptor carries one.
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

/// A USB-streaming output terminal.
pub(super) fn output_terminal(id: u8, source: u8) -> Vec<u8> {
    vec![9, 0x24, 0x03, id, 0x01, 0x01, 0, source, 0]
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

/// The VideoControl interrupt endpoint and the class-specific descriptor
/// `lsusb` did not print (see the module comment).
pub(super) fn interrupt_endpoint(address: u8, interval: u8) -> Vec<u8> {
    vec![
        7, 0x05, address, 0x03, 0x10, 0x00, interval, 5, 0x25, 0x03, 0x10, 0x00,
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

/// `VS_FORMAT_UNCOMPRESSED` carrying the YUY2 GUID.
pub(super) fn format_yuy2(index: u8, frames: u8) -> Vec<u8> {
    let mut bytes = vec![27, 0x24, 0x04, index, frames];
    bytes.extend_from_slice(&guid("32595559-0000-0010-8000-00aa00389b71"));
    bytes.extend_from_slice(&[16, 1, 0, 0, 0, 0]);
    bytes
}

/// `VS_FORMAT_MJPEG` with fixed-size samples.
pub(super) fn format_mjpeg(index: u8, frames: u8) -> Vec<u8> {
    vec![11, 0x24, 0x06, index, frames, 1, 1, 0, 0, 0, 0]
}

/// One `VS_FRAME_*` descriptor with a single discrete interval.
pub(super) fn frame(
    subtype: u8,
    index: u8,
    (width, height): (u16, u16),
    bit_rate: u32,
    buffer: u32,
    interval: u32,
) -> Vec<u8> {
    let mut bytes = vec![30, 0x24, subtype, index, 0];
    bytes.extend_from_slice(&width.to_le_bytes());
    bytes.extend_from_slice(&height.to_le_bytes());
    bytes.extend_from_slice(&bit_rate.to_le_bytes());
    bytes.extend_from_slice(&bit_rate.to_le_bytes());
    bytes.extend_from_slice(&buffer.to_le_bytes());
    bytes.extend_from_slice(&interval.to_le_bytes());
    bytes.push(1);
    bytes.extend_from_slice(&interval.to_le_bytes());
    bytes
}

/// `VS_STILL_IMAGE_FRAME` for method 2.
pub(super) fn still_frame(sizes: &[(u16, u16)], compressions: &[u8]) -> Vec<u8> {
    let mut bytes = vec![
        (5 + 4 * sizes.len() + 1 + compressions.len()) as u8,
        0x24,
        0x03,
        0,
        sizes.len() as u8,
    ];
    for (width, height) in sizes {
        bytes.extend_from_slice(&width.to_le_bytes());
        bytes.extend_from_slice(&height.to_le_bytes());
    }
    bytes.push(compressions.len() as u8);
    bytes.extend_from_slice(compressions);
    bytes
}

/// `VS_COLORFORMAT`: BT.709 primaries and transfer, BT.601 matrix.
pub(super) fn colour_format() -> Vec<u8> {
    vec![6, 0x24, 0x0D, 1, 1, 4]
}

/// The isochronous alternate settings of streaming interface 1.
pub(super) fn alternates(protocol: u8, packet_sizes: &[u16]) -> Vec<u8> {
    let mut bytes = Vec::new();
    for (alternate, size) in (1u8..).zip(packet_sizes) {
        bytes.extend(interface(1, alternate, 1, 0x02, protocol, 0));
        bytes.extend_from_slice(&[7, 0x05, 0x81, 0x05]);
        bytes.extend_from_slice(&size.to_le_bytes());
        bytes.push(1);
    }
    bytes
}

/// The printed `wTotalLength` of the 5986:1141 configuration.
pub(super) const IR_1141_TOTAL: u16 = 0x019C;
/// The printed `wTotalLength` of the 5986:2113 configuration.
pub(super) const RGB_2113_TOTAL: u16 = 0x0402;

/// Bus 001 Device 002: ID 5986:1141, "Integrated IR Camera" (Bison).
///
/// VideoControl interface 0: one streaming interface (1); a Processing Unit
/// with no controls; extension units 4 (vendor), 6 (Realtek) and 8, the
/// Microsoft camera-control unit, `bNumControl` 2 and `bmControls` `22 00`
/// (selectors 0x02 exposure and 0x06 face authentication). Streaming
/// interface 1: YUY2 only, 340x340 (the default frame) and 640x480, both at
/// 30 fps.
pub(super) fn ir_1141() -> Vec<u8> {
    let mut bytes = device(0x1141, 0x3759, [3, 1, 2]);
    bytes.extend(configuration(IR_1141_TOTAL, 2, 4));
    bytes.extend(video_association(5));
    bytes.extend(interface(0, 0, 1, 0x01, 1, 5));
    bytes.extend(vc_header(0x0150, 0x0088, 15_000_000, &[1]));
    bytes.extend(camera_terminal(1, 0x0020_0000));
    bytes.extend(processing_unit(2, 1, 0, 3, 0, &[0, 0]));
    bytes.extend(output_terminal(3, 8));
    bytes.extend(extension_unit(
        4,
        "1229a78c-47b4-4094-b0ce-db07386fb938",
        2,
        2,
        &[0x00, 0x06],
        0,
    ));
    bytes.extend(extension_unit(
        6,
        "26b8105a-0713-4870-979d-da79444bb68e",
        5,
        4,
        &[0x38, 0x20, 0x04, 0x00],
        6,
    ));
    bytes.extend(extension_unit(
        8,
        "0f3f95dc-2632-4c4e-92c9-a04782f43bc8",
        2,
        6,
        &[0x22, 0x00],
        7,
    ));
    bytes.extend(interrupt_endpoint(0x83, 6));
    bytes.extend(interface(1, 0, 0, 0x02, 1, 0));
    bytes.extend(vs_input_header(0x0075, 3, &[0]));
    bytes.extend(format_yuy2(1, 2));
    bytes.extend(frame(0x05, 1, (340, 340), 55_488_000, 231_200, 333_333));
    bytes.extend(frame(0x05, 2, (640, 480), 147_456_000, 614_400, 333_333));
    bytes.extend(still_frame(&[(640, 480)], &[]));
    bytes.extend(colour_format());
    bytes.extend(alternates(
        1,
        &[0x0080, 0x0200, 0x0400, 0x0B00, 0x0C00, 0x1380, 0x1400],
    ));
    bytes
}

/// The frames both 5986:2113 formats list, in descriptor order.
const RGB_2113_SIZES: [(u16, u16); 9] = [
    (1280, 720),
    (320, 180),
    (320, 240),
    (352, 288),
    (424, 240),
    (640, 360),
    (640, 480),
    (848, 480),
    (960, 540),
];

/// Bus 001 Device 004: ID 5986:2113, "Integrated Camera" (SunplusIT).
///
/// VideoControl interface 0 (UVC 1.00): one streaming interface (1); a
/// Processing Unit whose `bmControls` 0x157f covers brightness, contrast,
/// hue, saturation, sharpness, gamma, white balance temperature, backlight
/// compensation, power-line frequency and automatic white balance, in an
/// 11-byte descriptor that ends at `iProcessing` (lsusb warned "Descriptor
/// too short"); extension units 3 (Realtek) and 4 (vendor), no Microsoft
/// unit. Streaming interface 1: MJPG and YUY2 in nine sizes each.
pub(super) fn rgb_2113() -> Vec<u8> {
    let mjpeg_rates = [
        (442_368_000, 1_843_200, 333_333),
        (27_648_000, 115_200, 333_333),
        (36_864_000, 153_600, 333_333),
        (48_660_480, 202_752, 333_333),
        (48_844_800, 203_520, 333_333),
        (110_592_000, 460_800, 333_333),
        (147_456_000, 614_400, 333_333),
        (195_379_200, 814_080, 333_333),
        (248_832_000, 1_036_800, 333_333),
    ];
    let yuy2_rates = [
        (147_456_000, 1_843_200, 1_000_000),
        (27_648_000, 115_200, 333_333),
        (36_864_000, 153_600, 333_333),
        (48_660_480, 202_752, 333_333),
        (48_844_800, 203_520, 333_333),
        (110_592_000, 460_800, 333_333),
        (147_456_000, 614_400, 333_333),
        (130_252_800, 814_080, 500_000),
        (124_416_000, 1_036_800, 666_666),
    ];
    let mut bytes = device(0x2113, 0x5422, [1, 2, 0]);
    bytes.extend(configuration(RGB_2113_TOTAL, 2, 0));
    bytes.extend(video_association(4));
    bytes.extend(interface(0, 0, 1, 0x01, 0, 4));
    bytes.extend(vc_header(0x0100, 0x006D, 48_000_000, &[1]));
    bytes.extend(camera_terminal(1, 0x0000_000E));
    bytes.extend(processing_unit(2, 1, 16384, 2, 0x157F, &[0]));
    bytes.extend(extension_unit(
        3,
        "26b8105a-0713-4870-979d-da79444bb68e",
        1,
        2,
        &[0x04, 0x00, 0x00, 0x00],
        0,
    ));
    bytes.extend(extension_unit(
        4,
        "63610682-5070-49ab-b8cc-b3855e8d221d",
        22,
        3,
        &[0xFF, 0xFF, 0x71, 0x0C],
        0,
    ));
    bytes.extend(output_terminal(5, 4));
    bytes.extend(interrupt_endpoint(0x87, 8));
    bytes.extend(interface(1, 0, 0, 0x02, 0, 0));
    bytes.extend(vs_input_header(0x02B6, 5, &[4, 0]));
    bytes.extend(format_mjpeg(1, 9));
    for (index, (size, (rate, buffer, interval))) in
        (1u8..).zip(RGB_2113_SIZES.iter().zip(mjpeg_rates))
    {
        bytes.extend(frame(0x07, index, *size, rate, buffer, interval));
    }
    bytes.extend(still_frame(&RGB_2113_SIZES, &[1, 5, 10, 20]));
    bytes.extend(colour_format());
    bytes.extend(format_yuy2(2, 9));
    for (index, (size, (rate, buffer, interval))) in
        (1u8..).zip(RGB_2113_SIZES.iter().zip(yuy2_rates))
    {
        bytes.extend(frame(0x05, index, *size, rate, buffer, interval));
    }
    bytes.extend(still_frame(&RGB_2113_SIZES, &[1]));
    bytes.extend(colour_format());
    bytes.extend(alternates(
        0,
        &[
            0x00C0, 0x0180, 0x0200, 0x0280, 0x0320, 0x03B0, 0x0A80, 0x0B20, 0x0BE0, 0x13C0, 0x13FC,
        ],
    ));
    bytes
}

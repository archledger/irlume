// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright the irlume contributors.

//! Read a camera's UVC extension units from its USB descriptors.
//!
//! irlume used to look for an IR-emitter control by writing guessed `SET_CUR`
//! payloads to every unit 0..=31 and selector 0..=15 until the IR image got
//! brighter. That destroyed a reporter's camera (#159): on a Lenovo ThinkPad camera
//! (USB 174f:11b4), guessed writes to an undocumented vendor unit left the
//! device unable to enumerate on the USB bus, and no power cycle recovered it.
//!
//! The information needed to avoid that is in the USB configuration descriptor,
//! normally readable without privileges at
//! `/sys/bus/usb/devices/*/descriptors`. It states which extension units exist,
//! what each one is (`guidExtensionCode`), and exactly which control selectors
//! each one implements (`bmControls`). irlume never read any of it.
//!
//! Sysfs can be absent, restricted, or namespaced differently inside a
//! container. That is an error, never a reason to fall back to probing: without
//! the descriptor there is no basis for writing anything, so the emitter simply
//! stays off.
//!
//! This module reads it, so the emitter path can address a documented control on
//! a unit that says it implements it, instead of guessing.
//!
//! The same descriptor also states whether a video function produces infrared
//! data: Microsoft's face-authentication control applies only to such cameras.
//! Discovery reads that statement for nodes that offer only YUYV (ADR-0031 §1),
//! from sysfs alone, and capture re-derives it from the open file descriptor.

use std::path::{Path, PathBuf};

/// `MS_CAMERA_CONTROL_XU`, the extension unit Microsoft defines for its UVC 1.5
/// extensions, in descriptor byte order.
///
/// Microsoft publishes it as `{0F3F95DC-2632-4C4E-92C9-A04782F43BC8}`, but a
/// GUID is stored with its first three components little-endian, so the bytes on
/// the wire are not the bytes as printed. Confirmed against a real descriptor:
/// searching for the printed order finds nothing, searching for the bytes below
/// finds the unit that `lsusb -v` prints with that GUID.
pub const MS_CAMERA_CONTROL_XU: [u8; 16] = [
    0xDC, 0x95, 0x3F, 0x0F, 0x32, 0x26, 0x4E, 0x4C, 0x92, 0xC9, 0xA0, 0x47, 0x82, 0xF4, 0x3B, 0xC8,
];

/// `MSXU_CONTROL_FACE_AUTHENTICATION`. Selects a streaming interface's
/// face-authentication mode, which is what drives the illuminator on the Hello
/// cameras irlume targets.
pub const MSXU_FACE_AUTHENTICATION: u8 = 0x06;

/// `MSXU_CONTROL_IR_TORCH`. Direct control of the IR lamp's power and mode.
pub const MSXU_IR_TORCH: u8 = 0x0A;

const DESC_DEVICE: u8 = 0x01;
const DESC_CONFIGURATION: u8 = 0x02;
const DESC_INTERFACE: u8 = 0x04;
const DESC_CS_INTERFACE: u8 = 0x24;
const SUBTYPE_VC_HEADER: u8 = 0x01;
const SUBTYPE_PROCESSING_UNIT: u8 = 0x05;
const SUBTYPE_EXTENSION_UNIT: u8 = 0x06;
const CLASS_VIDEO: u8 = 0x0E;
const SUBCLASS_VIDEOCONTROL: u8 = 0x01;
const SUBCLASS_VIDEOSTREAMING: u8 = 0x02;

/// Processing Unit `bmControls` bits that only a colour sensor has a use for
/// (UVC 1.5 section 3.7.2.5): hue (D2), saturation (D3), white balance
/// temperature (D6), white balance component (D7), hue auto (D11), white
/// balance temperature auto (D12) and white balance component auto (D13).
///
/// Brightness, contrast, gain, gamma, sharpness, backlight compensation and
/// power-line frequency are deliberately absent: a monochrome IR sensor can
/// reasonably offer each of them, so they say nothing about colour. The
/// ThinkPad T480 IR function advertises no Processing Unit control at all,
/// and its colour sibling advertises 0x157f, of which 0x104c is in this mask.
pub(crate) const PU_COLOUR_CONTROLS: u32 = 0x0000_38CC;
/// One `VC_EXTENSION_UNIT` descriptor.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExtensionUnit {
    pub unit_id: u8,
    pub guid: [u8; 16],
    /// `bmControls`, a little-endian bitmap: bit 0 is selector 1.
    pub bm_controls: Vec<u8>,
    /// `bNumControls`, the count the descriptor claims.
    pub num_controls: u8,
}

impl ExtensionUnit {
    pub fn is_microsoft_xu(&self) -> bool {
        self.guid == MS_CAMERA_CONTROL_XU
    }

    /// Whether the unit advertises `selector`.
    ///
    /// UVC numbers control selectors from 1, and `bmControls` bit 0 describes
    /// the first one, so selector N is bit N-1. Checked twice against real
    /// hardware: an ASUS Hello camera's Microsoft-XU reports `20 01 00 00`, and
    /// Microsoft's table puts Face Authentication (0x06) at D5 and Metadata
    /// (0x09) at D8, which is exactly the two bits set.
    ///
    /// A descriptor that sets more bits than `bNumControls` claims is
    /// self-contradictory, and this decides whether irlume writes to hardware,
    /// so such a unit advertises nothing at all rather than being read
    /// optimistically.
    pub fn advertises(&self, selector: u8) -> bool {
        if selector == 0 {
            return false; // 0x00 is MSXU_CONTROL_UNDEFINED; it has no bit.
        }
        if !self.bitmap_is_self_consistent() {
            return false;
        }
        let bit = usize::from(selector - 1);
        match self.bm_controls.get(bit / 8) {
            Some(byte) => byte & (1 << (bit % 8)) != 0,
            None => false,
        }
    }

    fn bitmap_is_self_consistent(&self) -> bool {
        let set: u32 = self.bm_controls.iter().map(|b| b.count_ones()).sum();
        set <= u32::from(self.num_controls)
    }
}

/// Extension units declared by VideoControl interface `interface_number`.
///
/// The interface number matters on composite cameras. The ASUS Hello module this
/// was developed against exposes two independent VideoControl functions on one
/// USB device: interface 0 owns units 4 and 7, interface 2 owns units 10, 11 and
/// the Microsoft-XU at 14. A unit number alone is therefore not an address, and
/// the blind sweep that treated it as one was writing to whatever answered.
///
/// Parsing walks the descriptor chain by `bLength` and only accepts an extension
/// unit while inside the requested VideoControl interface. It never scans for
/// the `0x24 0x06` byte pair directly, because those bytes occur inside other
/// descriptors' payloads.
///
/// The input must contain exactly one configuration, obtained from the active
/// descriptor view returned by this module. An unscoped multi-configuration
/// blob has no authority to select a unit. Malformed tails invalidate the whole
/// result rather than allowing a previously seen prefix to authorize a control.
pub fn extension_units_for_interface(desc: &[u8], interface_number: u8) -> Vec<ExtensionUnit> {
    let mut out = Vec::new();
    let mut in_target_vc = false;
    let mut i = 0usize;
    let mut configurations = 0;

    while i < desc.len() {
        let Some(header_end) = i.checked_add(2) else {
            return Vec::new();
        };
        let Some(header) = desc.get(i..header_end) else {
            return Vec::new();
        };
        let len = usize::from(header[0]);
        // A zero length would not advance, and anything overrunning the buffer
        // means the chain is malformed. Refuse the whole stream, not its tail.
        let Some(end) = i.checked_add(len) else {
            return Vec::new();
        };
        if len < 2 || end > desc.len() {
            return Vec::new();
        }
        let d = &desc[i..end];

        match d[1] {
            DESC_CONFIGURATION => {
                configurations += 1;
                if configurations != 1 || len < 9 || d[5] == 0 {
                    return Vec::new();
                }
                in_target_vc = false;
            }
            DESC_INTERFACE => {
                if len < 9 {
                    return Vec::new();
                }
                in_target_vc = d[2] == interface_number
                    && configurations == 1
                    && d[5] == CLASS_VIDEO
                    && d[6] == SUBCLASS_VIDEOCONTROL;
            }
            DESC_CS_INTERFACE if in_target_vc => {
                if len < 3 {
                    return Vec::new();
                }
                if d[2] == SUBTYPE_EXTENSION_UNIT {
                    let Some(unit) = parse_extension_unit(d) else {
                        return Vec::new();
                    };
                    out.push(unit);
                }
            }
            _ => {}
        }
        i = end;
    }
    out
}

/// Select only bytes belonging to the active configuration, retaining the
/// original device prefix. `bNumConfigurations` in that prefix still describes
/// the physical device; this is an observation view, not a replacement USB blob.
/// Single-configuration devices retain their exact historical descriptor bytes.
/// Exposed only for the untrusted-input fuzz harness; this pure parser does not
/// establish which configuration is active on an actual device.
#[doc(hidden)]
pub fn active_descriptor_view(raw: &[u8], active: u8) -> Option<Vec<u8>> {
    if active == 0 || raw.len() < 18 || raw[0] != 18 || raw[1] != DESC_DEVICE {
        return None;
    }
    let mut seen = [false; 256];
    let mut count = 0usize;
    let mut prefix_end = None;
    let mut selected = None;
    let mut current = None;
    let mut at = 18;
    while at < raw.len() {
        let header = raw.get(at..at.checked_add(2)?)?;
        let length = usize::from(header[0]);
        if length < 2 {
            return None;
        }
        let end = at.checked_add(length)?;
        let descriptor = raw.get(at..end)?;
        match header[1] {
            DESC_DEVICE => return None,
            DESC_CONFIGURATION => {
                if length < 9 {
                    return None;
                }
                if let Some((value, start)) = current {
                    if value == active {
                        selected = Some(start..at);
                    }
                }
                let value = descriptor[5];
                if value == 0 || seen[usize::from(value)] {
                    return None;
                }
                seen[usize::from(value)] = true;
                count += 1;
                prefix_end.get_or_insert(at);
                current = Some((value, at));
            }
            DESC_INTERFACE if length < 9 || current.is_none() => return None,
            _ => {}
        }
        // wTotalLength is explicitly not trustworthy in the Linux sysfs ABI.
        at = end;
    }
    if let Some((value, start)) = current {
        if value == active {
            selected = Some(start..raw.len());
        }
    }
    if count != usize::from(raw[17]) {
        return None;
    }
    let range = selected?;
    let mut view = raw[..prefix_end?].to_vec();
    view.extend_from_slice(&raw[range]);
    Some(view)
}

/// Layout from UVC 1.5 section 3.7.2.7:
///
/// ```text
/// 0  bLength            3  bUnitID           21     bNrInPins = p
/// 1  bDescriptorType    4  guidExtensionCode 22     baSourceID[p]
/// 2  bDescriptorSubtype 20 bNumControls      22+p   bControlSize = n
///                                            23+p   bmControls[n]
/// ```
///
/// Every offset is bounds-checked against the descriptor's own `bLength`: a
/// truncated or inconsistent descriptor yields no unit rather than a read past
/// the end or a bitmap built from neighbouring bytes.
fn parse_extension_unit(d: &[u8]) -> Option<ExtensionUnit> {
    let unit_id = *d.get(3)?;
    let guid: [u8; 16] = d.get(4..20)?.try_into().ok()?;
    let num_in_pins = usize::from(*d.get(21)?);
    let control_size_at = 22 + num_in_pins;
    let control_size = usize::from(*d.get(control_size_at)?);
    let bm_controls = d.get(control_size_at + 1..control_size_at + 1 + control_size)?;
    Some(ExtensionUnit {
        unit_id,
        guid,
        bm_controls: bm_controls.to_vec(),
        num_controls: *d.get(20)?,
    })
}

/// What one VideoControl function declares about itself, from its
/// class-specific descriptors: the streaming interfaces its header lists,
/// each Processing Unit's controls and its extension units.
///
/// Exposed only for the untrusted-input fuzz harness, which pins that
/// [`Self::extension_units`] always equals what
/// [`extension_units_for_interface`] returns for the same input.
#[doc(hidden)]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VideoControlFunction {
    /// `baInterfaceNr[]` from the function's one `VC_HEADER`, in the order
    /// the header lists them.
    pub streaming_interfaces: Vec<u8>,
    /// Each `VC_PROCESSING_UNIT`'s `bmControls`, its first four bytes read
    /// little-endian.
    pub processing_controls: Vec<u32>,
    /// Every `VC_EXTENSION_UNIT`, parsed exactly as the emitter path parses
    /// it.
    pub extension_units: Vec<ExtensionUnit>,
}

/// The VideoControl function at `interface_number`, read strictly, or `None`.
///
/// This decides a role (ADR-0031 §1) rather than authorizing a write, but it
/// is held to the same framing rules as [`extension_units_for_interface`]:
/// the walk steps by `bLength` through exactly one configuration, never
/// scans for byte pairs, and any truncated, zero-length or overrunning
/// descriptor refuses the whole answer rather than keeping a prefix. On top
/// of those it refuses a function that has no `VC_HEADER` or more than one,
/// a header too short for the interfaces it counts, a Processing Unit too
/// short for the bitmap it declares, and a header that lists an interface
/// which is not a VideoStreaming interface of the same configuration.
///
/// Like [`active_descriptor_view`], it does not read `wTotalLength`. The
/// #887 reporter's `descriptors` file for a ThinkPad T480 colour camera
/// (USB 5986:2113) carries 996 of the 1026 bytes its configuration header
/// claims, as a clean chain shorter than its header says. A published
/// capture from a unit with the same firmware version (linuxhw LsUSB
/// `31A261423C`, bcdDevice 54.22) carries all 1026, and whether that unit's
/// firmware or the capture path dropped the rest is not known. The device
/// writes both the header and the chain, so a length check would prove
/// nothing a device could not also fake, and it would refuse a real IR
/// camera whose file comes up short the same way. A chain is judged on the
/// descriptors it holds; one cut inside a descriptor is still malformed.
///
/// `extension_units_for_interface` is left as it is on purpose: it decides
/// which bytes irlume may write to a camera (#159), and a parser shared with
/// a new consumer is a parser whose next change can move that decision.
/// This walker reuses only its unit parsing, and a test and the fuzz target
/// pin that both return the same units.
///
/// A well-formed configuration with no VideoControl interface numbered
/// `interface_number` is also `None` here; [`video_control_walk`] keeps that
/// case apart for the role check.
#[doc(hidden)]
pub fn video_control_function(desc: &[u8], interface_number: u8) -> Option<VideoControlFunction> {
    match video_control_walk(desc, interface_number)? {
        VideoControlWalk::Function(function) => Some(function),
        VideoControlWalk::NotVideoControl => None,
    }
}

/// What a strict walk of one configuration found at an interface number.
///
/// `None` from [`video_control_walk`] is malformed framing or an
/// inconsistent function. A walk that consumed the whole configuration
/// without meeting a VideoControl interface with that number says so
/// separately, because the descriptor is then well formed and the node is
/// simply not behind a UVC VideoControl interface (a vendor-class video
/// grabber, for example), and the census reports the two differently.
enum VideoControlWalk {
    Function(VideoControlFunction),
    NotVideoControl,
}

/// The walk behind [`video_control_function`], with the "no such
/// VideoControl interface" outcome kept apart from malformed input.
fn video_control_walk(desc: &[u8], interface_number: u8) -> Option<VideoControlWalk> {
    let mut in_target_vc = false;
    let mut found_target_vc = false;
    let mut configurations = 0;
    let mut declared_interfaces = 0usize;
    let mut vc_block_closed = false;
    let mut entity_ids = std::collections::BTreeSet::new();
    let mut endpoint_count = None;
    let mut endpoint_addresses = std::collections::BTreeSet::new();
    let mut headers = 0usize;
    let mut uvc_version = None;
    let mut streaming_interfaces = Vec::new();
    let mut processing_controls = Vec::new();
    let mut extension_units = Vec::new();
    let mut videostreaming = [false; 256];
    let mut interface_alternates = std::collections::BTreeSet::new();
    let mut i = 0usize;

    while i < desc.len() {
        let header = desc.get(i..i.checked_add(2)?)?;
        let len = usize::from(header[0]);
        let end = i.checked_add(len)?;
        if len < 2 || end > desc.len() {
            return None;
        }
        let d = &desc[i..end];

        match d[1] {
            DESC_CONFIGURATION => {
                configurations += 1;
                if configurations != 1 || len < 9 || d[5] == 0 {
                    return None;
                }
                declared_interfaces = usize::from(d[4]);
                in_target_vc = false;
            }
            DESC_INTERFACE => {
                if len < 9 {
                    return None;
                }
                if endpoint_count.is_some_and(|count| count != endpoint_addresses.len()) {
                    return None;
                }
                endpoint_count = Some(usize::from(d[4]));
                endpoint_addresses.clear();
                if configurations != 1 || !interface_alternates.insert((d[2], d[3])) {
                    return None;
                }
                let video = configurations == 1 && d[5] == CLASS_VIDEO;
                if video && d[6] == SUBCLASS_VIDEOSTREAMING && d[3] == 0 && d[2] != interface_number
                {
                    videostreaming[usize::from(d[2])] = true;
                }
                in_target_vc = video && d[2] == interface_number && d[6] == SUBCLASS_VIDEOCONTROL;
                // A VideoControl function has one default alternate. Never
                // combine a header or PU from one alternate with an XU from
                // another, including a duplicate default interface.
                if in_target_vc && (d[3] != 0 || found_target_vc) {
                    return None;
                }
                found_target_vc |= in_target_vc;
                vc_block_closed = false;
            }
            DESC_CS_INTERFACE if in_target_vc => {
                if len < 3 || vc_block_closed {
                    return None;
                }
                if d[2] != SUBTYPE_VC_HEADER && headers != 1 {
                    return None;
                }
                // UVC terminals and units share one entity-ID namespace.
                if matches!(d[2], 2..=7) {
                    let id = *d.get(3)?;
                    if id == 0 || !entity_ids.insert(id) {
                        return None;
                    }
                }
                match d[2] {
                    SUBTYPE_VC_HEADER => {
                        headers += 1;
                        let version = u16::from_le_bytes([*d.get(3)?, *d.get(4)?]);
                        if !matches!(version, 0x0100 | 0x0110 | 0x0150) {
                            return None;
                        }
                        uvc_version = Some(version);
                        let count = usize::from(*d.get(11)?);
                        streaming_interfaces = d.get(12..12 + count)?.to_vec();
                    }
                    SUBTYPE_PROCESSING_UNIT => {
                        // `iProcessing` follows `bmControls` in every UVC
                        // version. UVC 1.1 and later also require the final
                        // `bmVideoStandards` byte.
                        let size = usize::from(*d.get(7)?);
                        let minimum = if uvc_version? >= 0x0110 { 10 } else { 9 };
                        if len < minimum + size {
                            return None;
                        }
                        processing_controls.push(processing_unit_controls(d)?);
                    }
                    2 => {
                        // USB input terminals are eight bytes; camera and
                        // media-transport inputs carry variable control data.
                        let terminal = u16::from_le_bytes([*d.get(4)?, *d.get(5)?]);
                        let minimum = match terminal {
                            0x0201 => 15 + usize::from(*d.get(14)?),
                            0x0202 => {
                                let controls = usize::from(*d.get(8)?);
                                10 + controls + usize::from(*d.get(9 + controls)?)
                            }
                            _ => 8,
                        };
                        if len < minimum {
                            return None;
                        }
                    }
                    3 => {
                        if len < 9 {
                            return None;
                        }
                    }
                    4 => {
                        if len < 6 + usize::from(*d.get(4)?) {
                            return None;
                        }
                    }
                    7 => {
                        // Both bmControls and bmControlsRuntime have the
                        // declared bControlSize (UVC 1.5 Encoding Unit).
                        if uvc_version? != 0x0150 || len < 7 + 2 * usize::from(*d.get(6)?) {
                            return None;
                        }
                    }
                    SUBTYPE_EXTENSION_UNIT => {
                        // bLength is 24 + bNrInPins + bControlSize, closed
                        // by `iExtension`. The emitter's parser is left as
                        // it is; this walk decides a role, so a unit cut
                        // short is refused.
                        let pins = usize::from(*d.get(21)?);
                        let size = usize::from(*d.get(22 + pins)?);
                        if len < 24 + pins + size {
                            return None;
                        }
                        extension_units.push(parse_extension_unit(d)?);
                    }
                    _ => return None,
                }
            }
            0x05 => {
                if len < 7
                    || endpoint_count.is_none()
                    || d[2] & 0x0f == 0
                    || d[2] & 0x70 != 0
                    || !endpoint_addresses.insert(d[2])
                {
                    return None;
                }
                if in_target_vc {
                    vc_block_closed = true;
                }
            }
            _ if in_target_vc => vc_block_closed = true,
            _ => {}
        }
        i = end;
    }

    if endpoint_count.is_some_and(|count| count != endpoint_addresses.len()) {
        return None;
    }
    let interface_count = interface_alternates
        .iter()
        .map(|(number, _)| number)
        .collect::<std::collections::BTreeSet<_>>()
        .len();
    if interface_count != declared_interfaces {
        return None;
    }
    if !found_target_vc {
        return Some(VideoControlWalk::NotVideoControl);
    }
    if headers != 1 {
        return None;
    }
    if streaming_interfaces
        .iter()
        .any(|number| !videostreaming[usize::from(*number)])
    {
        return None;
    }
    Some(VideoControlWalk::Function(VideoControlFunction {
        streaming_interfaces,
        processing_controls,
        extension_units,
    }))
}

/// `bmControls` of one `VC_PROCESSING_UNIT` (UVC 1.5 section 3.7.2.5):
///
/// ```text
/// 0 bLength  3 bUnitID  4 bSourceID  5 wMaxMultiplier  7 bControlSize = n
///                                                      8 bmControls[n]
/// ```
///
/// UVC 1.0 devices end the descriptor after `iProcessing`, later versions
/// add `bmVideoStandards`; neither is read, so the only length that matters
/// is the bitmap's own. The bitmap is little-endian and UVC defines no
/// control above D18, so only its first four bytes are kept. A descriptor
/// too short for the bitmap it declares yields `None`.
fn processing_unit_controls(d: &[u8]) -> Option<u32> {
    let size = usize::from(*d.get(7)?);
    let bitmap = d.get(8..8 + size)?;
    Some(
        bitmap
            .iter()
            .take(4)
            .enumerate()
            .fold(0u32, |bits, (at, byte)| bits | u32::from(*byte) << (8 * at)),
    )
}

/// Why a VideoControl function does not attest that its stream is infrared
/// (ADR-0031 §1). Each variant names the clause that failed, because the
/// census and doctor print it as the evidence for keeping a node RGB.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum IrFunctionRefusal {
    /// No descriptor could be read for the node: it has no USB parent (a
    /// loopback or platform node), sysfs is absent or restricted, or the
    /// active configuration changed during the read.
    Unreadable,
    /// The descriptor file holds no complete active configuration, the
    /// descriptor chain is truncated or inconsistent, the function has no
    /// single `VC_HEADER`, or its header lists an interface that is not
    /// VideoStreaming.
    Malformed,
    /// The descriptor is well formed, but the node's USB interface is not a
    /// UVC VideoControl interface of the active configuration, as for a
    /// video grabber that uvcvideo does not drive. Kept apart from
    /// [`Self::Malformed`] so the census never calls a sound descriptor
    /// malformed.
    NotVideoControl,
    /// The function lists this many streaming interfaces instead of one, so
    /// its claims cannot be attributed to one node (clause b).
    StreamingInterfaces(usize),
    /// The function has no Microsoft camera-control unit (clause c).
    NoMicrosoftXu,
    /// The function has more than one Microsoft camera-control unit, which
    /// makes the unit ambiguous, as it is for the emitter path (clause c).
    AmbiguousMicrosoftXu,
    /// The Microsoft unit does not advertise selector 0x06 within
    /// `bNumControls` (clause c).
    NoFaceAuthentication,
    /// A Processing Unit advertises these colour controls (clause d).
    ColourProcessing(u32),
}

impl std::fmt::Display for IrFunctionRefusal {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Unreadable => formatter.write_str("no readable USB descriptor"),
            Self::Malformed => formatter.write_str("the USB descriptor is malformed"),
            Self::NotVideoControl => {
                formatter.write_str("its USB interface is not a UVC VideoControl interface")
            }
            Self::StreamingInterfaces(count) => {
                write!(
                    formatter,
                    "its video function lists {count} streams, not one"
                )
            }
            Self::NoMicrosoftXu => formatter.write_str("no Microsoft camera-control unit"),
            Self::AmbiguousMicrosoftXu => {
                formatter.write_str("more than one Microsoft camera-control unit")
            }
            Self::NoFaceAuthentication => formatter
                .write_str("its Microsoft camera-control unit has no face-authentication control"),
            Self::ColourProcessing(bits) => write!(
                formatter,
                "colour controls advertised (Processing Unit bits 0x{bits:04x})"
            ),
        }
    }
}

/// What an attested VideoControl function stated (ADR-0031 §1): the
/// Microsoft unit carrying the face-authentication control and the one
/// streaming interface the claim belongs to.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct IrFunctionEvidence {
    pub(crate) msxu_unit: u8,
    pub(crate) streaming_interface: u8,
}

/// Whether the VideoControl function at `vc_interface` of the active
/// descriptor view `view` attests an infrared stream (ADR-0031 §1, clauses
/// b to d; clause a, the node's formats, is the caller's).
///
/// Microsoft's UVC 1.5 extensions (section 2.2.2.6) define the
/// face-authentication control as applicable only to cameras that produce
/// infrared data. Its presence alone is not enough: the claim describes a
/// function, so it is attributed to a node only when the function has one
/// streaming interface; a colour function that carries the unit anyway is
/// caught by its colour controls; and a unit whose bitmap contradicts its
/// own `bNumControls` advertises nothing, as for the emitter path. Pure over
/// the bytes, so every clause is testable without a camera.
pub(crate) fn ir_function_evidence(
    view: &[u8],
    vc_interface: u8,
) -> Result<IrFunctionEvidence, IrFunctionRefusal> {
    let function = match video_control_walk(view, vc_interface) {
        Some(VideoControlWalk::Function(function)) => function,
        Some(VideoControlWalk::NotVideoControl) => return Err(IrFunctionRefusal::NotVideoControl),
        None => return Err(IrFunctionRefusal::Malformed),
    };
    let streaming_interface = match function.streaming_interfaces.as_slice() {
        [only] => *only,
        other => return Err(IrFunctionRefusal::StreamingInterfaces(other.len())),
    };
    let mut microsoft = function
        .extension_units
        .iter()
        .filter(|unit| unit.is_microsoft_xu());
    let unit = match (microsoft.next(), microsoft.next()) {
        (Some(only), None) => only,
        (None, _) => return Err(IrFunctionRefusal::NoMicrosoftXu),
        (Some(_), Some(_)) => return Err(IrFunctionRefusal::AmbiguousMicrosoftXu),
    };
    if !unit.advertises(MSXU_FACE_AUTHENTICATION) {
        return Err(IrFunctionRefusal::NoFaceAuthentication);
    }
    let colour = function
        .processing_controls
        .iter()
        .fold(0, |bits, controls| bits | controls)
        & PU_COLOUR_CONTROLS;
    if colour != 0 {
        return Err(IrFunctionRefusal::ColourProcessing(colour));
    }
    Ok(IrFunctionEvidence {
        msxu_unit: unit.unit_id,
        streaming_interface,
    })
}

/// [`ir_function_evidence`] for the function behind `video_device`, from
/// sysfs alone.
///
/// This is the only attestation discovery, the census and the doctor use:
/// it reads the USB device's `descriptors` file and opens nothing under
/// `/dev`, so classifying a node never streams a frame or touches the
/// camera's controls (ADR-0029 §1, §9). Any failure to read is a refusal,
/// which keeps the node RGB.
pub(crate) fn ir_function_evidence_for_node(
    video_device: &str,
) -> Result<IrFunctionEvidence, IrFunctionRefusal> {
    let iface_dir = interface_dir(video_device).map_err(|_| IrFunctionRefusal::Unreadable)?;
    let dev_dir = ancestor_with(&iface_dir, "descriptors").ok_or(IrFunctionRefusal::Unreadable)?;
    ir_function_evidence_from_dirs(&iface_dir, &dev_dir)
}

/// [`ir_function_evidence_for_node`] once the node's USB interface and
/// device directories are known.
///
/// Reading and parsing fail differently on purpose: a missing or restricted
/// file, or a configuration change during the read, is
/// [`IrFunctionRefusal::Unreadable`], while a file that was read but holds
/// no complete active configuration is [`IrFunctionRefusal::Malformed`].
/// The census prints the refusal as the reason a node stayed RGB, and a
/// descriptor that was read is not "unreadable".
fn ir_function_evidence_from_dirs(
    iface_dir: &Path,
    dev_dir: &Path,
) -> Result<IrFunctionEvidence, IrFunctionRefusal> {
    let (raw, configuration, vc_interface) =
        raw_descriptors_from_dirs(iface_dir, dev_dir).map_err(|_| IrFunctionRefusal::Unreadable)?;
    let view = active_descriptor_view(&raw, configuration).ok_or(IrFunctionRefusal::Malformed)?;
    ir_function_evidence(&view, vc_interface)
}

/// The USB `idVendor:idProduct` behind `video_device`.
///
/// A camera is identified by what the USB bus says it is, not by the V4L card
/// string. `card.contains("ASUS")` matched any camera with that word in its
/// name and wrote nine bytes to it.
#[expect(clippy::missing_errors_doc, reason = "doc backlog")]
pub fn usb_ids(video_device: &str) -> std::io::Result<(u16, u16)> {
    let dir = usb_device_dir(video_device)?;
    let vid = read_hex_u16(&dir.join("idVendor"))
        .ok_or_else(|| bad(format!("{} has no idVendor", dir.display())))?;
    let pid = read_hex_u16(&dir.join("idProduct"))
        .ok_or_else(|| bad(format!("{} has no idProduct", dir.display())))?;
    Ok((vid, pid))
}

fn read_hex_u16(path: &Path) -> Option<u16> {
    u16::from_str_radix(std::fs::read_to_string(path).ok()?.trim(), 16).ok()
}

/// The active USB descriptor view and VideoControl interface number backing
/// `video_device` (for example `/dev/video2`).
///
/// uvcvideo binds a video node to its VideoControl interface, so the interface
/// number comes straight from sysfs and no descriptor-level association is
/// needed: `/dev/video0` resolves to `3-5:1.0` and `/dev/video2` to `3-5:1.2` on
/// the two-function camera above.
///
/// An unreadable descriptor is an error, never a reason to fall back to probing.
#[expect(clippy::missing_errors_doc, reason = "doc backlog")]
pub fn usb_context(video_device: &str) -> std::io::Result<(Vec<u8>, u8)> {
    let iface_dir = interface_dir(video_device)?;
    let dev_dir = ancestor_with(&iface_dir, "descriptors")
        .ok_or_else(|| bad("no USB descriptor parent for the interface".into()))?;
    let (descriptors, configuration, interface_number) =
        descriptor_context_from_dirs(&iface_dir, &dev_dir)?;
    let view = active_descriptor_view(&descriptors, configuration)
        .ok_or_else(|| bad("invalid active USB descriptor view".into()))?;
    Ok((view, interface_number))
}

/// Everything needed to decide whether a control may be written, resolved from
/// the open file descriptor that will receive the write.
///
/// Taking a path here instead would let the descriptor that authorises a write
/// and the device that receives it be two different cameras: a path can be
/// re-pointed by a replug between the check and the ioctl, and nothing stops a
/// caller passing an `fd` and a path that disagree. A file descriptor names a
/// kernel object. `/sys/dev/char/<major>:<minor>` turns that back into the exact
/// sysfs node, so the answer describes the device being written to.
pub struct CameraIdentity {
    /// Complete cached USB descriptor blob, including inactive configurations.
    /// All of these bytes remain identity evidence. Use descriptor_fingerprint
    /// to bind that evidence to the separately observed active configuration.
    pub descriptors: Vec<u8>,
    /// bConfigurationValue observed and checked against the fd's interface.
    pub active_configuration: u8,
    pub interface_number: u8,
    pub vid: u16,
    pub pid: u16,
    /// The USB serial string, when the device publishes one.
    ///
    /// NOT a unique physical identity, and must not be trusted as one: the ASUS
    /// module this project develops against reports `200901010001`, a batch
    /// number of the kind webcam vendors repeat across every unit they ship.
    /// It narrows a match; it does not settle one.
    pub serial: Option<String>,
    /// Resolved sysfs path of the USB DEVICE, `/devices/...` with no `/sys`
    /// prefix and no interface suffix.
    ///
    /// The only identifier here that distinguishes two identical units attached
    /// at the same time, because it names the port rather than the model. It is
    /// stable across reboots for a fixed port and changes when the device is
    /// moved to another one, which is the right way round for a record that has
    /// to survive a power loss.
    ///
    /// It is NOT a physical-device identity. The kernel calls it the device's
    /// key "at that point in time": the same path is reused by whatever is
    /// plugged into that port next. So a path match says "the same place", never
    /// "the same camera", and anything authorising a write on a path match alone
    /// is trusting a port.
    pub usb_devpath: String,
}

/// USB connection facts whose change invalidates a concurrency measurement.
#[derive(Debug)]
pub(crate) struct UsbConnectionFacts {
    pub(crate) controller_devpath: String,
    /// Exact sysfs `speed` value in thousandths of a megabit per second.
    pub(crate) speed_millimbps: u64,
    pub(crate) driver: String,
}

/// Persistent camera identity and connection facts resolved from one live fd.
pub(crate) struct FdCameraContext {
    pub(crate) identity: CameraIdentity,
    pub(crate) connection: UsbConnectionFacts,
}

#[expect(clippy::missing_errors_doc, reason = "doc backlog")]
pub fn identity_from_fd(fd: std::os::raw::c_int) -> std::io::Result<CameraIdentity> {
    let (iface_dir, dev_dir) = fd_usb_dirs(fd)?;
    identity_from_dirs(&iface_dir, &dev_dir)
}

/// Resolve qualification identity and link facts from the fd that will stream.
///
/// Missing controller, speed, or driver evidence is an error. Concurrent
/// authority must never be scoped by an invented default.
pub(crate) fn identity_and_connection_from_fd(
    fd: std::os::raw::c_int,
) -> std::io::Result<FdCameraContext> {
    let (iface_dir, dev_dir) = fd_usb_dirs(fd)?;
    Ok(FdCameraContext {
        identity: identity_from_dirs(&iface_dir, &dev_dir)?,
        connection: connection_facts_from_dirs(&dev_dir, &iface_dir, &crate::hostfs::sys_root())?,
    })
}

fn fd_usb_dirs(fd: std::os::raw::c_int) -> std::io::Result<(PathBuf, PathBuf)> {
    let (major, minor) = device_numbers(fd)?;
    usb_dirs_for_numbers(major, minor)
}

/// Metadata-only observation for a non-authoritative time-budget hint.
/// Unlike the fd collector, this never opens the video node or issues ioctls.
/// Path/stat/sysfs races are acceptable only because capture revalidates its
/// own fd-derived contract; this observation must never authorize capture.
pub(crate) fn identity_and_connection_for_budget_hint(
    path: &str,
) -> std::io::Result<(CameraIdentity, UsbConnectionFacts)> {
    use std::os::unix::fs::{FileTypeExt, MetadataExt};
    let metadata = std::fs::metadata(path)?;
    if !metadata.file_type().is_char_device() {
        return Err(bad("budget hint requires a character-device path".into()));
    }
    let (iface_dir, dev_dir) =
        usb_dirs_for_numbers(libc::major(metadata.rdev()), libc::minor(metadata.rdev()))?;
    Ok((
        identity_from_dirs(&iface_dir, &dev_dir)?,
        connection_facts_from_dirs(&dev_dir, &iface_dir, &crate::hostfs::sys_root())?,
    ))
}

/// The USB identity alone (descriptors, ids, serial, device path) for a
/// character-device path, from sysfs, without the link diagnostics that
/// [`identity_and_connection_for_budget_hint`] also requires: a location
/// (ADR-0030 §5) needs the identity and nothing about the link. Never
/// authorizes capture.
pub(crate) fn identity_for_location(path: &str) -> std::io::Result<CameraIdentity> {
    use std::os::unix::fs::{FileTypeExt, MetadataExt};
    let metadata = std::fs::metadata(path)?;
    if !metadata.file_type().is_char_device() {
        return Err(bad(
            "a camera location requires a character-device path".into()
        ));
    }
    let (iface_dir, dev_dir) =
        usb_dirs_for_numbers(libc::major(metadata.rdev()), libc::minor(metadata.rdev()))?;
    identity_from_dirs(&iface_dir, &dev_dir)
}

fn usb_dirs_for_numbers(major: u32, minor: u32) -> std::io::Result<(PathBuf, PathBuf)> {
    let node =
        std::fs::canonicalize(crate::hostfs::sys_dev_char_root().join(format!("{major}:{minor}")))?;

    let iface_dir = ancestor_with(&node, "bInterfaceNumber").ok_or_else(|| {
        bad(format!(
            "no USB interface above {} (not a UVC device?)",
            node.display()
        ))
    })?;
    let dev_dir = ancestor_with(&iface_dir, "descriptors")
        .ok_or_else(|| bad(format!("no USB descriptors above {}", iface_dir.display())))?;

    Ok((iface_dir, dev_dir))
}

fn identity_from_dirs(iface_dir: &Path, dev_dir: &Path) -> std::io::Result<CameraIdentity> {
    identity_from_dirs_with(iface_dir, dev_dir, || {})
}

fn identity_from_dirs_with(
    iface_dir: &Path,
    dev_dir: &Path,
    after_read: impl FnOnce(),
) -> std::io::Result<CameraIdentity> {
    let (descriptors, configuration, interface_number) =
        descriptor_context_from_dirs(iface_dir, dev_dir)?;
    let identity = CameraIdentity {
        descriptors,
        active_configuration: configuration,
        interface_number,
        vid: read_hex_u16(&dev_dir.join("idVendor"))
            .ok_or_else(|| bad(format!("{} has no idVendor", dev_dir.display())))?,
        pid: read_hex_u16(&dev_dir.join("idProduct"))
            .ok_or_else(|| bad(format!("{} has no idProduct", dev_dir.display())))?,
        serial: read_optional_serial(dev_dir)?,
        // `dev_dir` came from `canonicalize`, so it is already the resolved
        // physical path. Stripping `/sys` makes the value the kernel's own
        // `DEVPATH` for this device, which is what `udevadm info -q path` prints
        // and therefore what a person comparing a record against their machine
        // will have in front of them.
        //
        // The leading slash is put back deliberately. `strip_prefix` removes the
        // component and leaves a RELATIVE path, so this recorded
        // `devices/pci0000:00/...` while every other source of the same string
        // says `/devices/pci0000:00/...`. A hardware run is what showed it: the
        // record on disk did not match the path printed beside it.
        usb_devpath: dev_dir
            .strip_prefix(crate::hostfs::sys_root())
            .map(|p| std::path::Path::new("/").join(p))
            .unwrap_or_else(|_| dev_dir.to_path_buf())
            .to_string_lossy()
            .into_owned(),
    };
    after_read();
    if configuration_from_dirs(iface_dir, dev_dir)? != (configuration, interface_number) {
        return Err(bad(
            "USB configuration changed while collecting identity".into()
        ));
    }
    Ok(identity)
}

fn descriptor_context_from_dirs(
    iface_dir: &Path,
    dev_dir: &Path,
) -> std::io::Result<(Vec<u8>, u8, u8)> {
    let (raw, configuration, interface) = raw_descriptors_from_dirs(iface_dir, dev_dir)?;
    active_descriptor_view(&raw, configuration).ok_or_else(|| {
        bad("USB descriptors do not contain one complete active configuration".into())
    })?;
    Ok((raw, configuration, interface))
}

/// The device's whole `descriptors` file with the active configuration and
/// the interface number, read between two reads of the configuration so a
/// change during the read is an error. The bytes are not parsed here.
fn raw_descriptors_from_dirs(
    iface_dir: &Path,
    dev_dir: &Path,
) -> std::io::Result<(Vec<u8>, u8, u8)> {
    let (configuration, interface) = configuration_from_dirs(iface_dir, dev_dir)?;
    let raw = std::fs::read(dev_dir.join("descriptors"))?;
    if configuration_from_dirs(iface_dir, dev_dir)? != (configuration, interface) {
        return Err(bad(
            "USB configuration changed while reading descriptors".into()
        ));
    }
    Ok((raw, configuration, interface))
}

/// Read the active configuration and require the fd-resolved interface to
/// belong to it. USB core names interfaces `<device>:<configuration>.<number>`
/// using decimal numbers; bInterfaceNumber itself is a hexadecimal attribute.
pub(crate) fn configuration_from_dirs(
    iface_dir: &Path,
    dev_dir: &Path,
) -> std::io::Result<(u8, u8)> {
    let decimal = |raw: &str| -> Option<u8> {
        let raw = raw.trim();
        (!raw.is_empty() && raw.bytes().all(|byte| byte.is_ascii_digit()))
            .then(|| raw.parse().ok())
            .flatten()
    };
    let active_path = dev_dir.join("bConfigurationValue");
    let raw = std::fs::read_to_string(&active_path)?;
    let active = decimal(&raw).filter(|value| *value != 0).ok_or_else(|| {
        bad(format!(
            "{} has no valid active configuration",
            active_path.display()
        ))
    })?;
    let interface = read_hex_u8(&iface_dir.join("bInterfaceNumber")).ok_or_else(|| {
        bad(format!(
            "{} has an unreadable bInterfaceNumber",
            iface_dir.display()
        ))
    })?;
    let device_name = dev_dir
        .file_name()
        .and_then(|name| name.to_str())
        .ok_or_else(|| bad("USB device has no directory name".into()))?;
    let suffix = iface_dir
        .file_name()
        .and_then(|name| name.to_str())
        .and_then(|name| name.strip_prefix(&format!("{device_name}:")))
        .and_then(|name| name.split_once('.'));
    if iface_dir.parent() != Some(dev_dir)
        || suffix
            .and_then(|(configuration, number)| Some((decimal(configuration)?, decimal(number)?)))
            != Some((active, interface))
    {
        return Err(bad(
            "USB interface does not belong to the active configuration".into(),
        ));
    }
    Ok((active, interface))
}

pub(crate) fn validate_fd_configuration(fd: std::os::raw::c_int) -> std::io::Result<()> {
    let (interface, device) = fd_usb_dirs(fd)?;
    configuration_from_dirs(&interface, &device).map(|_| ())
}

fn connection_facts_from_dirs(
    dev_dir: &Path,
    iface_dir: &Path,
    sysfs_root: &Path,
) -> std::io::Result<UsbConnectionFacts> {
    let root_hub = dev_dir
        .ancestors()
        .find(|candidate| {
            candidate.join("busnum").is_file()
                && candidate
                    .file_name()
                    .and_then(|name| name.to_str())
                    .is_some_and(|name| {
                        name.strip_prefix("usb").is_some_and(|suffix| {
                            !suffix.is_empty() && suffix.bytes().all(|b| b.is_ascii_digit())
                        })
                    })
        })
        .ok_or_else(|| bad(format!("no USB root hub above {}", dev_dir.display())))?;
    let controller = root_hub.parent().ok_or_else(|| {
        bad(format!(
            "USB root hub {} has no controller",
            root_hub.display()
        ))
    })?;
    let controller_devpath = devpath_below(sysfs_root, controller)?;

    let speed_path = dev_dir.join("speed");
    let speed_raw = std::fs::read_to_string(&speed_path)
        .map_err(|error| bad(format!("could not read {}: {error}", speed_path.display())))?;
    let speed_millimbps = parse_speed_millimbps(speed_raw.trim()).ok_or_else(|| {
        bad(format!(
            "{} contains an invalid USB speed {:?}",
            speed_path.display(),
            speed_raw.trim()
        ))
    })?;

    let driver_path = iface_dir.join("driver");
    let driver_target = std::fs::read_link(&driver_path)
        .map_err(|error| bad(format!("could not read {}: {error}", driver_path.display())))?;
    let driver = driver_target
        .file_name()
        .and_then(|name| name.to_str())
        .filter(|name| !name.is_empty())
        .ok_or_else(|| bad(format!("{} has no driver name", driver_path.display())))?
        .to_owned();

    Ok(UsbConnectionFacts {
        controller_devpath,
        speed_millimbps,
        driver,
    })
}

fn devpath_below(sysfs_root: &Path, path: &Path) -> std::io::Result<String> {
    let relative = path.strip_prefix(sysfs_root).map_err(|_| {
        bad(format!(
            "{} is outside sysfs root {}",
            path.display(),
            sysfs_root.display()
        ))
    })?;
    Ok(Path::new("/").join(relative).to_string_lossy().into_owned())
}

fn parse_speed_millimbps(raw: &str) -> Option<u64> {
    let (whole, fraction) = raw.split_once('.').map_or((raw, ""), |parts| parts);
    if whole.is_empty()
        || !whole.bytes().all(|byte| byte.is_ascii_digit())
        || fraction.len() > 3
        || !fraction.bytes().all(|byte| byte.is_ascii_digit())
    {
        return None;
    }
    let whole = whole.parse::<u64>().ok()?;
    let mut fraction_value = if fraction.is_empty() {
        0
    } else {
        fraction.parse::<u64>().ok()?
    };
    for _ in fraction.len()..3 {
        fraction_value = fraction_value.checked_mul(10)?;
    }
    let value = whole.checked_mul(1_000)?.checked_add(fraction_value)?;
    (value > 0).then_some(value)
}

impl CameraIdentity {
    /// The observed active configuration, when it exists in the complete blob.
    pub(crate) fn configuration_value(&self) -> Option<u8> {
        active_descriptor_view(&self.descriptors, self.active_configuration)
            .map(|_| self.active_configuration)
    }

    /// Configuration-bound digest retaining every published descriptor byte.
    ///
    /// A valid single-configuration device keeps its historical plain SHA-256.
    /// Otherwise hash a fixed domain, the one-byte configuration value, and the
    /// complete blob. Filtering inactive bytes here would weaken device identity.
    pub fn descriptor_fingerprint(&self) -> String {
        if self.descriptors.get(17) == Some(&1) && self.configuration_value().is_some() {
            return irlume_common::sha256_hex(&self.descriptors);
        }
        let mut material = b"irlume-usb-configuration-v1\0".to_vec();
        material.push(self.active_configuration);
        material.extend_from_slice(&self.descriptors);
        irlume_common::sha256_hex(&material)
    }

    pub fn extension_units(&self) -> Vec<ExtensionUnit> {
        active_descriptor_view(&self.descriptors, self.active_configuration)
            .map(|view| extension_units_for_interface(&view, self.interface_number))
            .unwrap_or_default()
    }

    /// The Microsoft camera-control unit, if this camera has exactly one.
    ///
    /// Two would make a bare unit number ambiguous again, so that is treated as
    /// "no usable unit" rather than picking whichever came first.
    pub fn microsoft_xu(&self) -> Option<ExtensionUnit> {
        let units = self.extension_units();
        let mut ms = units.into_iter().filter(ExtensionUnit::is_microsoft_xu);
        match (ms.next(), ms.next()) {
            (Some(only), None) => Some(only),
            _ => None,
        }
    }

    /// [`ir_function_evidence`] for this identity's function, bound to the
    /// file descriptor the identity was read from.
    ///
    /// Capture uses this rather than the role discovery cached: an
    /// `IRLUME_IR_DEVICE` override, a saved pin or the fallback path can
    /// open a node discovery never classified, and a path can be re-pointed
    /// by a replug between discovery and the open. The fd names the device
    /// that will stream.
    pub(crate) fn ir_function_evidence(&self) -> Result<IrFunctionEvidence, IrFunctionRefusal> {
        let view = active_descriptor_view(&self.descriptors, self.active_configuration)
            .ok_or(IrFunctionRefusal::Malformed)?;
        ir_function_evidence(&view, self.interface_number)
    }

    pub fn usb_id(&self) -> String {
        format!("{:04x}:{:04x}", self.vid, self.pid)
    }
}

fn device_numbers(fd: std::os::raw::c_int) -> std::io::Result<(u32, u32)> {
    // SAFETY: fstat writes into a zeroed stat owned here; fd is the caller's.
    let mut st: libc::stat = unsafe { std::mem::zeroed() };
    #[expect(clippy::undocumented_unsafe_blocks, reason = "doc backlog")]
    if unsafe { libc::fstat(fd, &mut st) } != 0 {
        return Err(std::io::Error::last_os_error());
    }
    let rdev = st.st_rdev;
    Ok((libc::major(rdev), libc::minor(rdev)))
}

/// The device's USB serial, distinguishing "publishes none" from "could not read
/// it".
///
/// `.ok()` on the read collapsed those two, and the difference decides whether
/// one camera's recorded bytes may be written into another. A record created
/// while the read failed stores `serial: None`, and `None` on the record side is
/// deliberately permissive — it has to be, because a camera that genuinely
/// publishes no serial must still be recoverable, and the NexiGo HelloCam this
/// was validated against publishes none. So an identical unit swapped into the
/// same USB port would satisfy `(None, Some(_))` and be authorized to receive
/// the first camera's undo bytes, on matching descriptors and a reused port path
/// alone. Failing the read closed keeps that authorization from ever being
/// created.
///
/// An ABSENT attribute is `None`, because sysfs simply does not publish `serial`
/// for a device with no iSerial descriptor, and that is the common case rather
/// than a fault.
///
/// An EMPTY attribute is also `None`, which is where this deliberately diverges
/// from the review that found the collapse: it proposed treating empty as an
/// error. Empty carries the same information as absent — the device names no
/// unit — and no camera here publishes one, so making it fatal would refuse
/// hardware nobody has tested against on the strength of a guess. The hole being
/// closed is the failed READ, not the empty value.
fn read_optional_serial(dev_dir: &Path) -> std::io::Result<Option<String>> {
    let path = dev_dir.join("serial");
    match std::fs::read_to_string(&path) {
        Ok(value) => {
            let value = value.trim();
            Ok((!value.is_empty()).then(|| value.to_owned()))
        }
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(e) => Err(bad(format!("could not read {}: {e}", path.display()))),
    }
}

fn ancestor_with(start: &Path, marker: &str) -> Option<PathBuf> {
    let mut dir = Some(start);
    while let Some(d) = dir {
        if d.join(marker).exists() {
            return Some(d.to_path_buf());
        }
        dir = d.parent();
    }
    None
}

pub(crate) fn interface_dir(video_device: &str) -> std::io::Result<PathBuf> {
    let node = Path::new(video_device)
        .file_name()
        .ok_or_else(|| bad(format!("{video_device} is not a device node path")))?;
    std::fs::canonicalize(crate::hostfs::video_class_root().join(node).join("device"))
}

/// Walk up to the USB device directory, the one carrying `descriptors`.
fn usb_device_dir(video_device: &str) -> std::io::Result<PathBuf> {
    let iface_dir = interface_dir(video_device)?;
    let mut dir = iface_dir.as_path();
    loop {
        if dir.join("descriptors").is_file() {
            return Ok(dir.to_path_buf());
        }
        dir = dir
            .parent()
            .ok_or_else(|| bad(format!("no USB descriptors above {}", iface_dir.display())))?;
    }
}

fn read_hex_u8(path: &Path) -> Option<u8> {
    let raw = std::fs::read_to_string(path).ok()?;
    u8::from_str_radix(raw.trim(), 16).ok()
}

fn bad(msg: String) -> std::io::Error {
    std::io::Error::new(std::io::ErrorKind::InvalidData, msg)
}

#[cfg(test)]
mod tests {
    mod t480;

    #[test]
    fn budget_hint_metadata_rejects_non_usb_paths_without_opening_them() {
        use std::os::unix::fs::{symlink, MetadataExt};

        // /dev/null is a character device, so the refusal must come from the
        // sysfs walk. The fixture lists it the way every kernel does: its
        // /sys/dev/char entry resolves to /sys/devices/virtual/mem/null,
        // which has no USB interface above it, so the lookup reaches the
        // ancestor walk and is refused there rather than at a missing entry.
        let rdev = std::fs::metadata("/dev/null").unwrap().rdev();
        let char_entry = format!("{}:{}", libc::major(rdev), libc::minor(rdev));
        let roots = crate::hostfs::test::fixture_with(|_, sys| {
            std::fs::create_dir_all(sys.join("devices/virtual/mem/null")).unwrap();
            std::fs::create_dir_all(sys.join("dev/char")).unwrap();
            symlink(
                "../../devices/virtual/mem/null",
                sys.join("dev/char").join(&char_entry),
            )
            .unwrap();
        });
        let Err(refused) = super::identity_and_connection_for_budget_hint("/dev/null") else {
            panic!("/dev/null must not yield a USB identity");
        };
        let refused = refused.to_string();
        let null_node = roots.sys().join("devices/virtual/mem/null");
        assert!(
            refused.contains(&format!("no USB interface above {}", null_node.display())),
            "/dev/null must be refused by the ancestor walk from its sysfs node: {refused}"
        );
        assert!(
            super::identity_and_connection_for_budget_hint("/dev/irlume-missing-budget-hint")
                .is_err()
        );
        let path =
            std::env::temp_dir().join(format!("irlume-budget-regular-{}", std::process::id()));
        std::fs::write(&path, b"not a camera").unwrap();
        assert!(super::identity_and_connection_for_budget_hint(path.to_str().unwrap()).is_err());
        std::fs::remove_file(path).unwrap();
    }

    #[test]
    fn connection_facts_bind_controller_speed_and_driver_without_bus_numbers() {
        use std::os::unix::fs::symlink;

        let root =
            std::env::temp_dir().join(format!("irlume-usb-connection-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        let sys = root.join("sys");
        let controller = sys.join("devices/pci0000:00/0000:00:14.0");
        let root_hub = controller.join("usb3");
        let device = root_hub.join("3-2");
        let interface = device.join("3-2:1.0");
        let driver = sys.join("bus/usb/drivers/uvcvideo");
        std::fs::create_dir_all(&interface).unwrap();
        std::fs::create_dir_all(&driver).unwrap();
        std::fs::write(root_hub.join("busnum"), "3\n").unwrap();
        std::fs::write(device.join("speed"), "5000\n").unwrap();
        symlink(&driver, interface.join("driver")).unwrap();

        let facts = super::connection_facts_from_dirs(&device, &interface, &sys).unwrap();
        assert_eq!(facts.controller_devpath, "/devices/pci0000:00/0000:00:14.0");
        assert_eq!(facts.speed_millimbps, 5_000_000);
        assert_eq!(facts.driver, "uvcvideo");
        assert!(!facts.controller_devpath.contains("busnum"));

        std::fs::write(device.join("speed"), "1.5\n").unwrap();
        let low_speed = super::connection_facts_from_dirs(&device, &interface, &sys).unwrap();
        assert_eq!(low_speed.speed_millimbps, 1_500);
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn missing_connection_evidence_is_an_error_not_a_permissive_default() {
        let root = std::env::temp_dir().join(format!(
            "irlume-usb-connection-missing-{}",
            std::process::id()
        ));
        let _ = std::fs::remove_dir_all(&root);
        let sys = root.join("sys");
        let controller = sys.join("devices/platform/controller");
        let root_hub = controller.join("usb1");
        let device = root_hub.join("1-1");
        let interface = device.join("1-1:1.0");
        std::fs::create_dir_all(&interface).unwrap();
        std::fs::write(root_hub.join("busnum"), "1\n").unwrap();

        let error = super::connection_facts_from_dirs(&device, &interface, &sys)
            .expect_err("missing speed and driver must fail closed");
        assert!(error.to_string().contains("speed"), "{error}");
        let _ = std::fs::remove_dir_all(&root);
    }

    /// A serial that could not be READ is not the same as a camera that has
    /// none, and the difference decides whether one camera's undo bytes may be
    /// written into another.
    ///
    /// `.ok()` collapsed the two. A record created during a failed read stored
    /// `serial: None`, and `None` on the record side is deliberately permissive
    /// because a camera that publishes no serial must still be recoverable. So
    /// an identical unit swapped into the same USB port matched on descriptors
    /// and port alone. A test over `CameraIdentity { serial: None }` cannot see
    /// this: it has to be exercised at the filesystem boundary.
    #[test]
    fn a_serial_that_cannot_be_read_is_an_error_not_an_absent_serial() {
        let root = std::env::temp_dir().join(format!("irlume-serial-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);

        // No `serial` attribute at all: the ordinary case for a device with no
        // iSerial descriptor, and the NexiGo this was validated against.
        let absent = root.join("absent");
        std::fs::create_dir_all(&absent).expect("scratch");
        assert_eq!(
            super::read_optional_serial(&absent).expect("an absent serial is not an error"),
            None
        );

        // Present and readable.
        let present = root.join("present");
        std::fs::create_dir_all(&present).expect("scratch");
        std::fs::write(present.join("serial"), " 200901010001\n").expect("write");
        assert_eq!(
            super::read_optional_serial(&present).expect("readable"),
            Some("200901010001".to_string())
        );

        // Present and empty carries the same information as absent: the device
        // names no unit.
        let empty = root.join("empty");
        std::fs::create_dir_all(&empty).expect("scratch");
        std::fs::write(empty.join("serial"), "  \n").expect("write");
        assert_eq!(super::read_optional_serial(&empty).expect("readable"), None);

        // Present and UNREADABLE. A directory where the attribute belongs makes
        // the read fail with EISDIR, which is neither NotFound nor success, and
        // is the shape of every transient sysfs failure this guards against.
        let broken = root.join("broken");
        std::fs::create_dir_all(broken.join("serial")).expect("scratch");
        let e = super::read_optional_serial(&broken)
            .expect_err("a serial that cannot be read must NOT read as absent");
        assert!(
            e.to_string().contains("could not read"),
            "the error must name what failed, got: {e}"
        );

        let _ = std::fs::remove_dir_all(&root);
    }
    use super::*;

    /// Captured from the ASUS Hello camera (USB 3277:0059) this was developed
    /// against, so the parser is exercised against bytes a real camera emitted
    /// rather than bytes written to match the parser.
    const ASUS: &[u8] = include_bytes!("../tests/fixtures/asus-3277-0059.descriptors");

    struct UsbFixture {
        root: PathBuf,
        device: PathBuf,
        interface: PathBuf,
        /// Identity collection resolves the sysfs root (the recorded devpath
        /// is prefixed with it), so the fixture carries the host roots its
        /// test thread reads: the empty camera-less trees, never the host's.
        _roots: crate::hostfs::test::FixtureGuard,
    }

    impl UsbFixture {
        fn new(label: &str, configuration: u8, interface: u8, descriptors: &[u8]) -> Self {
            let _roots = crate::hostfs::test::empty_fixture();
            let root =
                std::env::temp_dir().join(format!("irlume-ms02-{label}-{}", std::process::id()));
            let _ = std::fs::remove_dir_all(&root);
            let device = root.join("3-5");
            let interface_path = device.join(format!("3-5:{configuration}.{interface}"));
            std::fs::create_dir_all(&interface_path).unwrap();
            std::fs::write(
                interface_path.join("bInterfaceNumber"),
                format!("{interface:02x}\n"),
            )
            .unwrap();
            std::fs::write(
                device.join("bConfigurationValue"),
                format!("{configuration}\n"),
            )
            .unwrap();
            std::fs::write(device.join("idVendor"), "3277\n").unwrap();
            std::fs::write(device.join("idProduct"), "0059\n").unwrap();
            std::fs::write(device.join("descriptors"), descriptors).unwrap();
            Self {
                root,
                device,
                interface: interface_path,
                _roots,
            }
        }

        fn identity(&self) -> std::io::Result<CameraIdentity> {
            identity_from_dirs(&self.interface, &self.device)
        }
    }

    impl Drop for UsbFixture {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.root);
        }
    }

    fn configuration(value: u8, guid: [u8; 16]) -> Vec<u8> {
        // USB configuration, VC interface 0, XU unit 14 advertising FaceAuth.
        let mut bytes = vec![9, 2, 44, 0, 1, value, 0, 0x80, 50];
        bytes.extend_from_slice(&[9, 4, 0, 0, 0, 0x0e, 1, 0, 0]);
        bytes.extend_from_slice(&[26, 0x24, 6, 14]);
        bytes.extend_from_slice(&guid);
        bytes.extend_from_slice(&[1, 1, 1, 1, 0x20, 0]);
        bytes
    }

    fn usb_descriptors(configurations: &[Vec<u8>]) -> Vec<u8> {
        let mut bytes = vec![
            18,
            1,
            0,
            2,
            0,
            0,
            0,
            64,
            0x77,
            0x32,
            0x59,
            0,
            0,
            1,
            0,
            0,
            0,
            configurations.len() as u8,
        ];
        for configuration in configurations {
            bytes.extend_from_slice(configuration);
        }
        bytes
    }

    #[test]
    fn inactive_configuration_never_supplies_the_microsoft_unit() {
        let raw = usb_descriptors(&[
            configuration(1, [0x42; 16]),
            configuration(2, MS_CAMERA_CONTROL_XU),
        ]);
        let fixture = UsbFixture::new("inactive", 1, 0, &raw);
        assert!(fixture.identity().unwrap().microsoft_xu().is_none());
    }

    #[test]
    fn inactive_duplicate_does_not_hide_the_active_microsoft_unit() {
        let raw = usb_descriptors(&[
            configuration(1, MS_CAMERA_CONTROL_XU),
            configuration(2, MS_CAMERA_CONTROL_XU),
        ]);
        let fixture = UsbFixture::new("duplicate", 1, 0, &raw);
        let unit = fixture
            .identity()
            .unwrap()
            .microsoft_xu()
            .expect("one active Microsoft unit");
        assert_eq!(unit.unit_id, 14);
        assert!(unit.advertises(MSXU_FACE_AUTHENTICATION));
    }

    #[test]
    fn configuration_observations_have_distinct_persistent_fingerprints() {
        let raw = usb_descriptors(&[
            configuration(1, MS_CAMERA_CONTROL_XU),
            configuration(2, MS_CAMERA_CONTROL_XU),
        ]);
        let first = UsbFixture::new("fingerprint-one", 1, 0, &raw)
            .identity()
            .unwrap();
        let second = UsbFixture::new("fingerprint-two", 2, 0, &raw)
            .identity()
            .unwrap();
        assert_ne!(
            crate::emitter_journal::fingerprint(&first),
            crate::emitter_journal::fingerprint(&second)
        );
        assert_eq!(
            first.descriptors, second.descriptors,
            "retain the entire physical descriptor evidence"
        );
        assert_ne!(
            first.descriptor_fingerprint(),
            second.descriptor_fingerprint()
        );
    }

    #[test]
    fn configuration_binding_retains_inactive_descriptor_identity_evidence() {
        let first = usb_descriptors(&[
            configuration(1, MS_CAMERA_CONTROL_XU),
            configuration(2, [0x42; 16]),
        ]);
        let second = usb_descriptors(&[
            configuration(1, MS_CAMERA_CONTROL_XU),
            configuration(2, [0x33; 16]),
        ]);
        let fixture = UsbFixture::new("whole-identity", 1, 0, &first);
        let first = fixture.identity().unwrap();
        std::fs::write(fixture.device.join("descriptors"), second).unwrap();
        let second = fixture.identity().unwrap();
        assert_eq!(first.usb_devpath, second.usb_devpath);
        assert_eq!(first.active_configuration, second.active_configuration);
        assert_eq!(first.extension_units(), second.extension_units());
        assert_ne!(
            crate::emitter_journal::fingerprint(&first),
            crate::emitter_journal::fingerprint(&second),
            "adding configuration scope must not discard existing whole-device identity evidence"
        );
    }

    #[test]
    fn configuration_must_be_readable_nonzero_and_match_the_bound_interface() {
        let raw = usb_descriptors(&[
            configuration(1, MS_CAMERA_CONTROL_XU),
            configuration(2, MS_CAMERA_CONTROL_XU),
        ]);
        let fixture = UsbFixture::new("configuration-read", 1, 0, &raw);
        for value in ["", "0\n", "-1\n", "256\n", "garbage", "2\n"] {
            std::fs::write(fixture.device.join("bConfigurationValue"), value).unwrap();
            assert!(
                fixture.identity().is_err(),
                "must refuse active configuration {value:?}"
            );
        }
        std::fs::remove_file(fixture.device.join("bConfigurationValue")).unwrap();
        assert!(fixture.identity().is_err());
    }

    #[test]
    fn configuration_truncated_chain_does_not_authorize_a_valid_prefix() {
        let mut raw = usb_descriptors(&[configuration(1, MS_CAMERA_CONTROL_XU)]);
        raw.extend_from_slice(&[9, 2, 44]);
        let fixture = UsbFixture::new("truncated", 1, 0, &raw);
        assert!(fixture.identity().is_err());
    }

    #[test]
    fn configuration_single_camera_preserves_the_existing_descriptor_bytes() {
        let fixture = UsbFixture::new("single-asus", 1, 2, ASUS);
        assert_eq!(fixture.identity().unwrap().descriptors, ASUS);
        assert_eq!(
            fixture.identity().unwrap().descriptor_fingerprint(),
            irlume_common::sha256_hex(ASUS)
        );
        let raw = usb_descriptors(&[configuration(10, MS_CAMERA_CONTROL_XU)]);
        let fixture = UsbFixture::new("decimal", 10, 0, &raw);
        assert_eq!(fixture.identity().unwrap().descriptors, raw);
        assert!(fixture.identity().unwrap().microsoft_xu().is_some());
    }

    #[test]
    fn configuration_total_length_never_selects_or_skips_a_configuration() {
        let mut inactive = configuration(1, [0x42; 16]);
        inactive[2..4].copy_from_slice(&u16::MAX.to_le_bytes());
        let mut active = configuration(2, MS_CAMERA_CONTROL_XU);
        active[2..4].copy_from_slice(&0u16.to_le_bytes());
        let raw = usb_descriptors(&[inactive, active.clone()]);
        let fixture = UsbFixture::new("total-length", 2, 0, &raw);
        let id = fixture.identity().unwrap();
        assert_eq!(id.descriptors, raw);
        assert_eq!(
            active_descriptor_view(&raw, 2).unwrap(),
            [raw[..18].to_vec(), active].concat()
        );
        assert_eq!(id.configuration_value(), Some(2));
        assert_eq!(id.microsoft_xu().unwrap().unit_id, 14);
        assert!(
            extension_units_for_interface(&raw, 0).is_empty(),
            "unscoped raw input must not guess which configuration is active"
        );
    }

    #[test]
    fn configuration_duplicate_missing_and_truncated_layouts_refuse() {
        let duplicate = usb_descriptors(&[
            configuration(1, MS_CAMERA_CONTROL_XU),
            configuration(1, MS_CAMERA_CONTROL_XU),
        ]);
        assert!(active_descriptor_view(&duplicate, 1).is_none());
        let raw = usb_descriptors(&[
            configuration(1, MS_CAMERA_CONTROL_XU),
            configuration(2, MS_CAMERA_CONTROL_XU),
        ]);
        assert!(active_descriptor_view(&raw, 3).is_none());
        assert!(active_descriptor_view(&raw, 0).is_none());
        let mut at = 0;
        while at < raw.len() {
            let end = at + usize::from(raw[at]);
            for cut in at + 1..end {
                assert!(
                    active_descriptor_view(&raw[..cut], 1).is_none(),
                    "incomplete descriptor at {cut}"
                );
            }
            at = end;
        }
        for (offset, value) in [(18, 0), (18, 2), (19, DESC_DEVICE), (23, 0)] {
            let mut broken = raw.clone();
            broken[offset] = value;
            assert!(active_descriptor_view(&broken, 1).is_none());
        }
    }

    #[test]
    fn configuration_change_or_disappearance_during_collection_refuses_identity() {
        let raw = usb_descriptors(&[
            configuration(1, MS_CAMERA_CONTROL_XU),
            configuration(2, MS_CAMERA_CONTROL_XU),
        ]);
        let fixture = UsbFixture::new("changed", 1, 0, &raw);
        let result = identity_from_dirs_with(&fixture.interface, &fixture.device, || {
            std::fs::write(fixture.device.join("bConfigurationValue"), "2\n").unwrap();
        });
        assert!(result.is_err());
        std::fs::write(fixture.device.join("bConfigurationValue"), "1\n").unwrap();
        let result = identity_from_dirs_with(&fixture.interface, &fixture.device, || {
            std::fs::remove_file(fixture.device.join("bConfigurationValue")).unwrap();
        });
        assert!(result.is_err());
        std::fs::write(fixture.device.join("bConfigurationValue"), "1\n").unwrap();
        std::fs::write(fixture.interface.join("bInterfaceNumber"), "01\n").unwrap();
        assert!(
            fixture.identity().is_err(),
            "interface attribute must match its fd-derived path"
        );
    }

    #[test]
    fn configuration_scoped_records_cannot_restore_in_another_configuration() {
        let raw = usb_descriptors(&[
            configuration(1, MS_CAMERA_CONTROL_XU),
            configuration(2, [0x42; 16]),
        ]);
        let mut fixture = UsbFixture::new("record-scope", 1, 0, &raw);
        let first = fixture.identity().unwrap();
        let original = "010001000000000000";
        let applied = "010002000000000000";
        let pending: crate::emitter_journal::PendingWrite = serde_json::from_value(serde_json::json!({
            "schema_version": 1, "engine_version": "fixture", "descriptor_sha256": crate::emitter_journal::fingerprint(&first),
            "usb_id": first.usb_id(), "interface_number": 0, "unit": 14, "selector": 6,
            "len": 9, "original": original, "attempted": applied, "restore_attempts": 0,
            "usb_devpath": first.usb_devpath,
        })).unwrap();
        let stream: crate::stream_record::StreamWrite = serde_json::from_value(serde_json::json!({
            "schema_version": 1, "engine_version": "fixture", "descriptor_sha256": crate::emitter_journal::fingerprint(&first),
            "usb_id": first.usb_id(), "interface_number": 0, "unit": 14, "selector": 6,
            "state": "applied", "applied": applied, "displaced": original, "restore_attempts": 0,
            "usb_devpath": first.usb_devpath,
        })).unwrap();
        let current = crate::emitter_journal::from_hex(applied).unwrap();
        assert!(crate::emitter_journal::record_applies(&pending, &first).is_ok());
        assert!(crate::stream_record::record_claims(&stream, &first, 14, 6, &current).is_ok());
        fixture.interface = fixture.device.join("3-5:2.0");
        std::fs::create_dir(&fixture.interface).unwrap();
        std::fs::write(fixture.interface.join("bInterfaceNumber"), "00\n").unwrap();
        std::fs::write(fixture.device.join("bConfigurationValue"), "2\n").unwrap();
        let second = fixture.identity().unwrap();
        assert_eq!(first.usb_devpath, second.usb_devpath);
        assert!(second.microsoft_xu().is_none());
        assert!(crate::emitter_journal::record_applies(&pending, &second).is_err());
        assert!(crate::stream_record::record_claims(&stream, &second, 14, 6, &current).is_err());
        assert!(
            !crate::emitter_journal::identity_authorizes(
                &irlume_common::sha256_hex(&raw),
                &first.usb_devpath,
                None,
                &first
            ),
            "legacy unscoped multi-configuration records must not acquire restore authority"
        );
    }

    #[test]
    fn configuration_parser_rejects_malformed_tails_and_opaque_payload_matches() {
        let mut view = usb_descriptors(&[configuration(1, MS_CAMERA_CONTROL_XU)]);
        view.extend_from_slice(&[2, DESC_CS_INTERFACE]);
        assert!(extension_units_for_interface(&view, 0).is_empty());
        let mut view = usb_descriptors(&[configuration(1, MS_CAMERA_CONTROL_XU)]);
        view.push(0);
        assert!(extension_units_for_interface(&view, 0).is_empty());
        // Bytes resembling configuration/interface headers inside an unknown
        // descriptor are payload, never a reason to restart the chain walk.
        let mut active = configuration(1, MS_CAMERA_CONTROL_XU);
        active.extend_from_slice(&[8, 0xff, 9, 2, 44, 0, 1, 2]);
        let view = usb_descriptors(&[active]);
        assert_eq!(extension_units_for_interface(&view, 0).len(), 1);
    }

    #[test]
    fn finds_the_microsoft_xu_on_the_interface_that_owns_it() {
        let units = extension_units_for_interface(ASUS, 2);
        let ids: Vec<u8> = units.iter().map(|u| u.unit_id).collect();
        assert_eq!(ids, vec![11, 10, 14]);

        let ms: Vec<&ExtensionUnit> = units.iter().filter(|u| u.is_microsoft_xu()).collect();
        assert_eq!(ms.len(), 1);
        assert_eq!(ms[0].unit_id, 14);
        assert_eq!(ms[0].bm_controls, vec![0x20, 0x01, 0x00, 0x00]);
    }

    /// The whole point of scoping by interface. Interface 0 is a second, separate
    /// VideoControl function on the same physical camera, and it has no
    /// Microsoft-XU. A unit number is meaningless without it.
    #[test]
    fn the_other_videocontrol_function_has_different_units_and_no_microsoft_xu() {
        let units = extension_units_for_interface(ASUS, 0);
        let ids: Vec<u8> = units.iter().map(|u| u.unit_id).collect();
        assert_eq!(ids, vec![4, 7]);
        assert!(!units.iter().any(|u| u.is_microsoft_xu()));
    }

    #[test]
    fn an_interface_that_is_not_videocontrol_yields_nothing() {
        // Interface 1 is VideoStreaming, interface 4 is audio.
        assert!(extension_units_for_interface(ASUS, 1).is_empty());
        assert!(extension_units_for_interface(ASUS, 4).is_empty());
    }

    /// Microsoft puts Face Authentication at D5 and Metadata at D8. The camera
    /// reports exactly those two, and reports `bNumControls` = 2 to match.
    #[test]
    fn advertised_selectors_match_the_published_control_table() {
        let units = extension_units_for_interface(ASUS, 2);
        let ms = units.iter().find(|u| u.is_microsoft_xu()).unwrap();

        assert!(ms.advertises(MSXU_FACE_AUTHENTICATION));
        assert!(ms.advertises(0x09)); // MSXU_CONTROL_METADATA
        assert_eq!(
            ms.bm_controls.iter().map(|b| b.count_ones()).sum::<u32>(),
            2
        );

        // The one this camera does NOT implement. Writing to it would be the old
        // behaviour: addressing a selector the device never claimed.
        assert!(!ms.advertises(MSXU_IR_TORCH));
        assert!(!ms.advertises(0x01));
        assert!(!ms.advertises(0));
    }

    #[test]
    fn a_selector_beyond_the_bitmap_is_not_advertised() {
        let unit = ExtensionUnit {
            unit_id: 1,
            guid: MS_CAMERA_CONTROL_XU,
            bm_controls: vec![0xFF],
            num_controls: 8,
        };
        assert!(unit.advertises(8)); // last bit of the only byte
        assert!(!unit.advertises(9)); // past the end, not "assume yes"
    }

    /// A descriptor claiming one control while setting several bits is
    /// contradicting itself, and this decides whether irlume writes to the
    /// hardware. It advertises nothing rather than the optimistic reading.
    #[test]
    fn a_bitmap_claiming_more_controls_than_bnumcontrols_advertises_nothing() {
        let honest = ExtensionUnit {
            unit_id: 14,
            guid: MS_CAMERA_CONTROL_XU,
            bm_controls: vec![0x20, 0x01],
            num_controls: 2,
        };
        assert!(honest.advertises(MSXU_FACE_AUTHENTICATION));

        let lying = ExtensionUnit {
            num_controls: 1,
            ..honest.clone()
        };
        assert!(!lying.advertises(MSXU_FACE_AUTHENTICATION));
        assert!(!lying.advertises(0x09));
    }

    #[test]
    fn the_guid_is_matched_in_descriptor_byte_order_not_as_printed() {
        // The printed order must NOT appear anywhere in a real descriptor.
        let printed: [u8; 16] = [
            0x0F, 0x3F, 0x95, 0xDC, 0x26, 0x32, 0x4C, 0x4E, 0x92, 0xC9, 0xA0, 0x47, 0x82, 0xF4,
            0x3B, 0xC8,
        ];
        assert!(!ASUS.windows(16).any(|w| w == printed));
        assert!(ASUS.windows(16).any(|w| w == MS_CAMERA_CONTROL_XU));
    }

    #[test]
    fn malformed_descriptors_stop_the_walk_instead_of_looping_or_overrunning() {
        assert!(extension_units_for_interface(&[], 0).is_empty());
        // bLength 0 would never advance the cursor.
        assert!(extension_units_for_interface(&[0x00, 0x04, 0x00], 0).is_empty());
        // bLength runs past the end of the buffer.
        assert!(extension_units_for_interface(&[0x40, 0x04, 0x00], 0).is_empty());
        // A truncated extension unit inside a valid VideoControl interface.
        let mut buf = vec![
            9,
            DESC_INTERFACE,
            0,
            0,
            0,
            CLASS_VIDEO,
            SUBCLASS_VIDEOCONTROL,
            0,
            0,
        ];
        buf.extend_from_slice(&[6, DESC_CS_INTERFACE, SUBTYPE_EXTENSION_UNIT, 14, 0, 0]);
        assert!(extension_units_for_interface(&buf, 0).is_empty());
    }

    /// The recorded device path is the kernel's own `DEVPATH`, leading slash and
    /// all.
    ///
    /// `strip_prefix` leaves a RELATIVE path, so this recorded
    /// `devices/pci0000:00/...` while `udevadm info -q path` prints
    /// `/devices/pci0000:00/...` for the same device. Both sides of the match
    /// computed it the same way, so nothing broke, which is exactly why only a
    /// transcript from real hardware showed it: the record on disk did not look
    /// like the path printed next to it.
    #[test]
    fn a_recorded_device_path_looks_like_the_kernels_own() {
        let sys = std::path::Path::new("/sys/devices/pci0000:00/0000:00:14.0/usb3/3-5");
        let devpath = sys
            .strip_prefix("/sys")
            .map(|p| std::path::Path::new("/").join(p))
            .unwrap_or_else(|_| sys.to_path_buf())
            .to_string_lossy()
            .into_owned();
        assert_eq!(devpath, "/devices/pci0000:00/0000:00:14.0/usb3/3-5");
        assert!(
            devpath.starts_with('/'),
            "a relative path here is not a DEVPATH"
        );
    }

    /// Every descriptor in the real chain must be consumed exactly, with no
    /// trailing slop, or the walk is mis-stepping through the buffer.
    #[test]
    fn the_walk_consumes_the_whole_real_descriptor_chain() {
        let mut i = 0usize;
        while i + 2 <= ASUS.len() {
            let len = usize::from(ASUS[i]);
            assert!(len >= 2, "zero-length descriptor at {i}");
            assert!(i + len <= ASUS.len(), "descriptor at {i} overruns");
            i += len;
        }
        assert_eq!(i, ASUS.len());
    }

    /// The ThinkPad T480 IR camera (USB 5986:1141): the #887 reporter's
    /// sysfs `descriptors` file, one complete configuration.
    const T480_IR: &[u8] = include_bytes!("../tests/fixtures/bison-5986-1141.descriptors");

    /// The ThinkPad T480 colour camera (USB 5986:2113): the #887 reporter's
    /// file from the same machine. Its configuration header claims a
    /// `wTotalLength` of 1026, and the file carries 996 bytes: the MJPEG
    /// format counts nine frame descriptors and the file holds eight
    /// (960x540 is missing). The sixth YUYV frame (640x360, file offset
    /// 669) also carries `bFrameIndex` 5 instead of 6, so index 5 appears
    /// twice. linuxhw LsUSB `31A261423C`, from a unit with the same
    /// bcdDevice 54.22 and `wTotalLength`, lists all nine MJPEG frames and
    /// numbers the YUYV frames 1 to 9, so both differences belong to this
    /// file; whether its unit's firmware or the capture path produced them
    /// is not known. The file is a clean descriptor chain shorter than the
    /// `wTotalLength` it carries.
    const T480_RGB: &[u8] = include_bytes!("../tests/fixtures/bison-5986-2113.descriptors");

    /// Both T480 files walk by `bLength` to their last byte with no slop,
    /// and each single configuration is its own active view. The colour
    /// camera file's configuration is 30 bytes shorter than its header
    /// says, a fact about this file (see [`T480_RGB`]), pinned here so a
    /// replacement file that differs is noticed.
    #[test]
    fn t480_descriptor_files_walk_cleanly_and_are_their_own_active_view() {
        for (label, bytes, total) in [("5986:1141", T480_IR, 412), ("5986:2113", T480_RGB, 1026)] {
            assert_eq!(u16::from_le_bytes([bytes[20], bytes[21]]), total, "{label}");
            let mut at = 0usize;
            while at < bytes.len() {
                let len = usize::from(bytes[at]);
                assert!(len >= 2 && at + len <= bytes.len(), "{label} at {at}");
                at += len;
            }
            assert_eq!(at, bytes.len(), "{label}");
            assert_eq!(
                active_descriptor_view(bytes, 1).as_deref(),
                Some(bytes),
                "{label}"
            );
        }
        assert_eq!(T480_IR.len(), 18 + 412);
        assert_eq!(T480_RGB.len(), 18 + 996);
    }

    /// Each builder the synthetic counter-cases use lays its descriptor out
    /// exactly as the real 5986:1141 file does, and each counter-case
    /// differs from [`attested_shape`] only in the field it names.
    #[test]
    fn the_counter_case_builders_match_the_real_t480_bytes() {
        assert!(T480_IR.starts_with(&t480::device(0x1141, 0x3759, [3, 1, 2])));
        for piece in [
            t480::configuration(0x019C, 2, 4),
            t480::interface(0, 0, 1, SUBCLASS_VIDEOCONTROL, 1, 5),
            t480::vc_header(0x0150, 0x0088, 15_000_000, &[1]),
            t480::processing_unit(2, 1, 0, 3, 0, &[0, 0]),
            t480::extension_unit(8, MSXU, 2, 6, &[0x22, 0x00], 7),
            t480::interrupt_endpoint(0x83, 6),
            t480::interface(1, 0, 0, SUBCLASS_VIDEOSTREAMING, 1, 0),
            t480::vs_input_header(0x0075, 3, &[0]),
        ] {
            assert!(
                T480_IR.windows(piece.len()).any(|window| window == piece),
                "{piece:02x?}"
            );
        }
    }

    /// ADR-0031 §1 against a camera's real bytes: the ASUS module's IR
    /// function (VideoControl interface 2) streams GREY, so its role never
    /// depended on this rule, but its descriptor is the shape the rule
    /// attests, and its RGB function (interface 0) is not.
    #[test]
    fn asus_ir_function_is_attested_and_its_rgb_function_is_not() {
        assert_eq!(
            ir_function_evidence(ASUS, 2),
            Ok(IrFunctionEvidence {
                msxu_unit: 14,
                streaming_interface: 3,
            })
        );
        assert_eq!(
            ir_function_evidence(ASUS, 0),
            Err(IrFunctionRefusal::NoMicrosoftXu)
        );
        assert_eq!(
            video_control_function(ASUS, 0).unwrap().processing_controls,
            [0x177F],
            "the RGB function advertises hue, saturation and white balance"
        );
        // Its streaming, audio and absent interfaces are sound descriptors
        // that simply are not a VideoControl interface.
        for not_videocontrol in [1, 3, 4, 5, 9] {
            assert_eq!(
                ir_function_evidence(ASUS, not_videocontrol),
                Err(IrFunctionRefusal::NotVideoControl),
                "interface {not_videocontrol}"
            );
        }
    }

    /// #887: the ThinkPad T480 IR camera offers only YUYV, and its
    /// descriptor names it an IR function: one stream, the Microsoft unit 8
    /// with face authentication (`22 00`, two controls), no colour controls.
    /// Unit 4, a vendor unit whose `00 06` would read as selectors 0x0A and
    /// 0x0B, is not the Microsoft unit and plays no part.
    #[test]
    fn t480_bison_1141_is_attested() {
        assert_eq!(
            ir_function_evidence(T480_IR, 0),
            Ok(IrFunctionEvidence {
                msxu_unit: 8,
                streaming_interface: 1,
            })
        );
        let function = video_control_function(T480_IR, 0).expect("a well-formed UVC 1.5 function");
        assert_eq!(function.streaming_interfaces, [1]);
        assert_eq!(function.processing_controls, [0]);
        let microsoft: Vec<&ExtensionUnit> = function
            .extension_units
            .iter()
            .filter(|unit| unit.is_microsoft_xu())
            .collect();
        assert_eq!(microsoft.len(), 1);
        assert_eq!(microsoft[0].unit_id, 8);
        assert_eq!(microsoft[0].num_controls, 2);
        assert_eq!(microsoft[0].bm_controls, [0x22, 0x00]);
        assert!(microsoft[0].advertises(MSXU_FACE_AUTHENTICATION));
        assert!(microsoft[0].advertises(0x02));
        assert!(!microsoft[0].advertises(MSXU_IR_TORCH));
        let vendor = &function.extension_units[0];
        assert_eq!((vendor.unit_id, vendor.is_microsoft_xu()), (4, false));
        assert_eq!(vendor.bm_controls, [0x00, 0x06]);
    }

    /// The T480's colour camera has no Microsoft unit, and its colour
    /// controls would refuse it on their own.
    ///
    /// The reporter's file holds a configuration shorter than its own
    /// `wTotalLength` (see [`T480_RGB`]), and the walk judges it on the
    /// descriptors it holds: no walker in this module reads `wTotalLength`,
    /// so a chain that ends cleanly at a descriptor boundary is not
    /// malformed, while a descriptor cut in the middle still is. The same
    /// holds for an IR function, which stays attested with its header
    /// overstating its length by the same 30 bytes, so a file that comes up
    /// short does not cost a real IR camera its role.
    #[test]
    fn t480_2113_is_not() {
        assert_eq!(
            ir_function_evidence(T480_RGB, 0),
            Err(IrFunctionRefusal::NoMicrosoftXu)
        );
        let function =
            video_control_function(T480_RGB, 0).expect("a well-formed UVC 1.00 function");
        assert_eq!(function.streaming_interfaces, [1]);
        assert_eq!(function.processing_controls, [0x157F]);
        assert_eq!(0x157F & PU_COLOUR_CONTROLS, 0x104C);
        assert_eq!(
            function
                .extension_units
                .iter()
                .map(|unit| (unit.unit_id, unit.is_microsoft_xu()))
                .collect::<Vec<_>>(),
            [(3, false), (4, false)]
        );

        let mut overstated = T480_IR.to_vec();
        overstated[20..22].copy_from_slice(&(412u16 + 30).to_le_bytes());
        assert_eq!(
            ir_function_evidence(&overstated, 0),
            ir_function_evidence(T480_IR, 0)
        );
        let mut cut = T480_RGB.to_vec();
        cut.pop();
        assert_eq!(
            ir_function_evidence(&cut, 0),
            Err(IrFunctionRefusal::Malformed)
        );
    }

    const MSXU: &str = "0f3f95dc-2632-4c4e-92c9-a04782f43bc8";

    /// One extension unit for [`function`]: (unit, printed GUID,
    /// `bNumControls`, `bmControls`).
    type Unit<'a> = (u8, &'a str, u8, &'a [u8]);

    /// A one-configuration device whose VideoControl interface 0 lists
    /// `streams` in its header, followed by a VideoStreaming interface for
    /// each of `videostreaming`. Built from pieces laid out as the real
    /// 5986:1141 file lays them out, with [`attested_shape`] as the default,
    /// so each counter-case differs from that synthetic shape, not from the
    /// real file, only in the field it names.
    fn function(
        streams: &[u8],
        videostreaming: &[u8],
        processing: &[u32],
        units: &[Unit<'_>],
    ) -> Vec<u8> {
        let mut bytes = t480::device(0x1141, 0x3759, [3, 1, 2]);
        let interface_count = videostreaming
            .iter()
            .copied()
            .chain([0])
            .collect::<std::collections::BTreeSet<_>>()
            .len();
        bytes.extend(t480::configuration(0, interface_count as u8, 0));
        bytes.extend(t480::interface(0, 0, 1, SUBCLASS_VIDEOCONTROL, 1, 0));
        bytes.extend(t480::vc_header(0x0150, 0, 15_000_000, streams));
        for (index, controls) in processing.iter().enumerate() {
            bytes.extend(t480::processing_unit(
                2 + index as u8,
                1,
                0,
                3,
                *controls,
                &[0, 0],
            ));
        }
        for (unit, guid, count, bitmap) in units {
            bytes.extend(t480::extension_unit(*unit, guid, *count, 2, bitmap, 0));
        }
        bytes.extend(t480::interrupt_endpoint(0x83, 6));
        for number in videostreaming {
            bytes.extend(t480::interface(
                *number,
                0,
                0,
                SUBCLASS_VIDEOSTREAMING,
                1,
                0,
            ));
            bytes.extend(t480::vs_input_header(0, 3, &[0]));
        }
        bytes
    }

    fn attested_shape() -> Vec<u8> {
        function(&[1], &[1], &[0], &[(8, MSXU, 2, &[0x22, 0x00])])
    }

    #[test]
    fn the_synthetic_attested_shape_is_attested() {
        assert_eq!(
            ir_function_evidence(&attested_shape(), 0),
            Ok(IrFunctionEvidence {
                msxu_unit: 8,
                streaming_interface: 1,
            })
        );
        // No Processing Unit at all is no colour control at all.
        let bare = function(&[1], &[1], &[], &[(8, MSXU, 2, &[0x22, 0x00])]);
        assert!(ir_function_evidence(&bare, 0).is_ok());
    }

    /// Clause b: a function with two streams cannot say which node its
    /// face-authentication claim is about (#428, #704).
    #[test]
    fn two_streams_are_not_attributable_to_one_node() {
        let two = function(&[1, 2], &[1, 2], &[0], &[(8, MSXU, 2, &[0x22, 0x00])]);
        assert_eq!(
            ir_function_evidence(&two, 0),
            Err(IrFunctionRefusal::StreamingInterfaces(2))
        );
        let none = function(&[], &[1], &[0], &[(8, MSXU, 2, &[0x22, 0x00])]);
        assert_eq!(
            ir_function_evidence(&none, 0),
            Err(IrFunctionRefusal::StreamingInterfaces(0))
        );
    }

    /// Clause d: each colour control alone refuses, and the controls a
    /// monochrome sensor may carry do not.
    ///
    /// The expected answer for each bit comes from this list, written out
    /// from the Processing Unit `bmControls` layout in UVC 1.5 section
    /// 3.7.2.5 (D2 hue, D3 saturation, D6 white balance temperature, D7 white
    /// balance component, D11 hue auto, D12 white balance temperature auto,
    /// D13 white balance component auto), not from `PU_COLOUR_CONTROLS`, so a
    /// change to the mask that drops or adds a bit fails here.
    #[test]
    fn each_colour_control_alone_refuses_and_the_others_do_not() {
        const UVC_COLOUR_BITS: [u32; 7] = [2, 3, 6, 7, 11, 12, 13];
        for d in 0..19u32 {
            let bit = 1u32 << d;
            let shape = function(&[1], &[1], &[bit], &[(8, MSXU, 2, &[0x22, 0x00])]);
            let got = ir_function_evidence(&shape, 0);
            if UVC_COLOUR_BITS.contains(&d) {
                assert_eq!(
                    got,
                    Err(IrFunctionRefusal::ColourProcessing(bit)),
                    "{bit:#x}"
                );
            } else {
                assert!(got.is_ok(), "{bit:#x}: {got:?}");
            }
        }
        // Brightness, contrast, gain, backlight and power-line frequency.
        let monochrome = function(&[1], &[1], &[0x0703], &[(8, MSXU, 2, &[0x22, 0x00])]);
        assert!(ir_function_evidence(&monochrome, 0).is_ok());
        // A colour bit on a second Processing Unit counts as much as on the first.
        let second = function(&[1], &[1], &[0, 0x08], &[(8, MSXU, 2, &[0x22, 0x00])]);
        assert_eq!(
            ir_function_evidence(&second, 0),
            Err(IrFunctionRefusal::ColourProcessing(0x08))
        );
    }

    /// Clause c: the Microsoft unit must carry selector 0x06, advertised
    /// within its own `bNumControls`, and must be the only one.
    #[test]
    fn the_microsoft_unit_must_advertise_face_authentication_honestly() {
        // A ThinkPad P16s Gen 2 colour function: selectors 2, 3 and 9.
        let p16s = function(&[1], &[1], &[0], &[(8, MSXU, 3, &[0x06, 0x01])]);
        assert_eq!(
            ir_function_evidence(&p16s, 0),
            Err(IrFunctionRefusal::NoFaceAuthentication)
        );
        let overclaimed = function(&[1], &[1], &[0], &[(8, MSXU, 1, &[0x22, 0x00])]);
        assert_eq!(
            ir_function_evidence(&overclaimed, 0),
            Err(IrFunctionRefusal::NoFaceAuthentication)
        );
        let two = function(
            &[1],
            &[1],
            &[0],
            &[(8, MSXU, 2, &[0x22, 0x00]), (9, MSXU, 2, &[0x22, 0x00])],
        );
        assert_eq!(
            ir_function_evidence(&two, 0),
            Err(IrFunctionRefusal::AmbiguousMicrosoftXu)
        );
        let vendor_only = function(
            &[1],
            &[1],
            &[0],
            &[(4, "1229a78c-47b4-4094-b0ce-db07386fb938", 2, &[0x22, 0x00])],
        );
        assert_eq!(
            ir_function_evidence(&vendor_only, 0),
            Err(IrFunctionRefusal::NoMicrosoftXu)
        );
    }

    /// Truncation anywhere refuses the whole answer, as it does for the
    /// emitter parser: no prefix may attest.
    #[test]
    fn processing_unit_tail_matches_the_declared_uvc_version() {
        let header_at = 18 + 9 + 9;
        let pu_at = header_at + 13;
        for version in [0x0100u16, 0x0110, 0x0150] {
            let mut whole = attested_shape();
            whole[header_at + 3..header_at + 5].copy_from_slice(&version.to_le_bytes());
            assert!(ir_function_evidence(&whole, 0).is_ok());
            let length = usize::from(whole[pu_at]);
            whole[pu_at] -= 1;
            whole.remove(pu_at + length - 1);
            if version == 0x0100 {
                assert!(ir_function_evidence(&whole, 0).is_ok());
            } else {
                assert_eq!(
                    ir_function_evidence(&whole, 0),
                    Err(IrFunctionRefusal::Malformed)
                );
            }
        }
    }

    #[test]
    fn a_video_control_alternate_cannot_supply_another_alternates_unit() {
        let whole = attested_shape();
        let unit_at = whole
            .windows(16)
            .position(|w| w == t480::guid(MSXU))
            .unwrap()
            - 4;
        for alternate in [0, 1] {
            let mut split = whole.clone();
            split.splice(
                unit_at..unit_at,
                t480::interface(0, alternate, 1, SUBCLASS_VIDEOCONTROL, 1, 0),
            );
            assert_eq!(
                ir_function_evidence(&split, 0),
                Err(IrFunctionRefusal::Malformed)
            );
        }
    }

    #[test]
    fn an_extension_unit_before_the_control_header_is_malformed() {
        let mut bytes = function(&[1], &[1], &[], &[(8, MSXU, 2, &[0x22, 0x00])]);
        let header_at = 18 + 9 + 9;
        let header: Vec<_> = bytes.drain(header_at..header_at + 13).collect();
        let unit_end = header_at + usize::from(bytes[header_at]);
        bytes.splice(unit_end..unit_end, header);
        assert_eq!(
            ir_function_evidence(&bytes, 0),
            Err(IrFunctionRefusal::Malformed)
        );
    }

    #[test]
    fn the_stream_must_be_a_distinct_interfaces_default_alternate() {
        let whole = attested_shape();
        let header_at = 18 + 9 + 9;
        let stream_at = whole
            .windows(9)
            .rposition(|d| d[0] == 9 && d[1] == DESC_INTERFACE && d[6] == SUBCLASS_VIDEOSTREAMING)
            .unwrap();
        for (number, alternate) in [(0, 0), (0, 1), (1, 1)] {
            let mut desc = whole.clone();
            desc[header_at + 12] = number;
            desc[stream_at + 2] = number;
            desc[stream_at + 3] = alternate;
            assert_eq!(
                ir_function_evidence(&desc, 0),
                Err(IrFunctionRefusal::Malformed)
            );
        }
    }

    #[test]
    fn duplicate_interface_alternate_pairs_are_malformed() {
        let whole = attested_shape();
        let alternate = t480::interface(1, 1, 0, SUBCLASS_VIDEOSTREAMING, 1, 0);
        let mut valid_alternate = whole.clone();
        valid_alternate.extend(&alternate);
        assert!(ir_function_evidence(&valid_alternate, 0).is_ok());
        let mut duplicate_alternate = valid_alternate;
        duplicate_alternate.extend(&alternate);
        assert_eq!(
            ir_function_evidence(&duplicate_alternate, 0),
            Err(IrFunctionRefusal::Malformed)
        );
        for class in [CLASS_VIDEO, 0xff] {
            let mut duplicate = t480::interface(1, 0, 0, SUBCLASS_VIDEOSTREAMING, 1, 0);
            duplicate[5] = class;
            let mut desc = whole.clone();
            desc.extend(duplicate);
            assert_eq!(
                ir_function_evidence(&desc, 0),
                Err(IrFunctionRefusal::Malformed)
            );
        }
    }

    #[test]
    fn units_after_an_endpoint_do_not_contribute_ir_evidence() {
        let whole = attested_shape();
        let xu_at = whole
            .windows(16)
            .position(|w| w == t480::guid(MSXU))
            .unwrap()
            - 4;
        let mut bytes = whole;
        let endpoint_at = xu_at + usize::from(bytes[xu_at]);
        let endpoint: Vec<_> = bytes.drain(endpoint_at..endpoint_at + 12).collect();
        bytes.splice(xu_at..xu_at, endpoint);
        assert_eq!(
            ir_function_evidence(&bytes, 0),
            Err(IrFunctionRefusal::Malformed)
        );
    }

    #[test]
    fn terminals_and_units_cannot_reuse_entity_ids() {
        let whole = attested_shape();
        let xu_at = whole
            .windows(16)
            .position(|w| w == t480::guid(MSXU))
            .unwrap()
            - 4;
        for id in [0, 2] {
            let mut bytes = whole.clone();
            bytes[xu_at + 3] = id;
            assert_eq!(
                ir_function_evidence(&bytes, 0),
                Err(IrFunctionRefusal::Malformed)
            );
        }
        let mut bytes = whole;
        // A complete USB input terminal with the XU's ID.
        bytes.splice(xu_at..xu_at, [8, DESC_CS_INTERFACE, 2, 8, 0, 2, 0, 0]);
        assert_eq!(
            ir_function_evidence(&bytes, 0),
            Err(IrFunctionRefusal::Malformed)
        );
    }

    #[test]
    fn the_configuration_counts_interfaces_without_counting_alternates() {
        let whole = attested_shape();
        for count in [0, 1, 3] {
            let mut bytes = whole.clone();
            bytes[18 + 4] = count;
            assert_eq!(
                ir_function_evidence(&bytes, 0),
                Err(IrFunctionRefusal::Malformed)
            );
        }
        let mut bytes = whole;
        bytes.extend(t480::interface(1, 1, 0, SUBCLASS_VIDEOSTREAMING, 1, 0));
        assert!(ir_function_evidence(&bytes, 0).is_ok());
    }

    #[test]
    fn every_interface_alternate_keeps_its_declared_endpoint_count() {
        let whole = attested_shape();
        let endpoint_at = whole
            .windows(7)
            .rposition(|d| d[0] == 7 && d[1] == 5)
            .unwrap();
        for address in [0, 0x80, 0x91] {
            let mut bytes = whole.clone();
            bytes[endpoint_at + 2] = address;
            assert_eq!(
                ir_function_evidence(&bytes, 0),
                Err(IrFunctionRefusal::Malformed)
            );
        }
        for count in [0, 2] {
            let mut bytes = whole.clone();
            bytes[18 + 9 + 4] = count;
            assert_eq!(
                ir_function_evidence(&bytes, 0),
                Err(IrFunctionRefusal::Malformed)
            );
        }
        let stream_at = whole
            .windows(9)
            .rposition(|d| d[0] == 9 && d[1] == DESC_INTERFACE)
            .unwrap();
        let mut missing = whole.clone();
        missing[stream_at + 4] = 1;
        assert_eq!(
            ir_function_evidence(&missing, 0),
            Err(IrFunctionRefusal::Malformed)
        );
        let mut repeated = whole;
        repeated[18 + 9 + 4] = 2;
        repeated.splice(stream_at..stream_at, t480::interrupt_endpoint(0x83, 6));
        assert_eq!(
            ir_function_evidence(&repeated, 0),
            Err(IrFunctionRefusal::Malformed)
        );
    }

    #[test]
    fn unused_entity_fields_still_require_complete_descriptors() {
        let whole = attested_shape();
        let at = 18 + 9 + 9 + 13;
        let entities = [
            vec![8, DESC_CS_INTERFACE, 2, 4, 1, 1, 0, 0],
            vec![
                18,
                DESC_CS_INTERFACE,
                2,
                4,
                1,
                2,
                0,
                0,
                0,
                0,
                0,
                0,
                0,
                0,
                3,
                0,
                0,
                0,
            ],
            vec![12, DESC_CS_INTERFACE, 2, 4, 2, 2, 0, 0, 1, 0, 1, 0],
            vec![9, DESC_CS_INTERFACE, 3, 4, 1, 1, 0, 2, 0],
            vec![7, DESC_CS_INTERFACE, 4, 4, 1, 2, 0],
            vec![13, DESC_CS_INTERFACE, 7, 4, 2, 0, 3, 0, 0, 0, 0, 0, 0],
        ];
        for entity in entities {
            let mut valid = whole.clone();
            valid.splice(at..at, entity.clone());
            assert!(ir_function_evidence(&valid, 0).is_ok(), "{entity:?}");
            for length in 3..entity.len() {
                let mut short = entity[..length].to_vec();
                short[0] = length as u8;
                let mut bytes = whole.clone();
                bytes.splice(at..at, short);
                assert_eq!(
                    ir_function_evidence(&bytes, 0),
                    Err(IrFunctionRefusal::Malformed),
                    "{entity:?}, length {length}"
                );
            }
        }
    }

    #[test]
    fn unknown_control_versions_and_entity_layouts_do_not_attest() {
        let whole = attested_shape();
        let header_at = 18 + 9 + 9;
        for version in [0x0100u16, 0x0110] {
            let mut bytes = whole.clone();
            bytes[header_at + 3..header_at + 5].copy_from_slice(&version.to_le_bytes());
            bytes.splice(
                header_at + 13..header_at + 13,
                [13, DESC_CS_INTERFACE, 7, 4, 2, 0, 3, 0, 0, 0, 0, 0, 0],
            );
            assert_eq!(
                ir_function_evidence(&bytes, 0),
                Err(IrFunctionRefusal::Malformed)
            );
        }
        for version in [0u16, 0x0101, 0x0111, 0x0151, 0x0200] {
            let mut bytes = whole.clone();
            bytes[header_at + 3..header_at + 5].copy_from_slice(&version.to_le_bytes());
            assert_eq!(
                ir_function_evidence(&bytes, 0),
                Err(IrFunctionRefusal::Malformed)
            );
        }
        let mut bytes = whole;
        bytes.splice(
            header_at + 13..header_at + 13,
            [4, DESC_CS_INTERFACE, 0xff, 4],
        );
        assert_eq!(
            ir_function_evidence(&bytes, 0),
            Err(IrFunctionRefusal::Malformed)
        );
    }

    #[test]
    fn a_truncated_header_unit_or_tail_is_malformed() {
        let whole = attested_shape();
        let header_at = 18 + 9 + 9;
        assert_eq!(whole[header_at + 2], SUBTYPE_VC_HEADER);

        // The header counts one interface but ends before listing it.
        let mut short_header = whole.clone();
        short_header[header_at] = 12;
        short_header.remove(header_at + 12);
        assert_eq!(
            ir_function_evidence(&short_header, 0),
            Err(IrFunctionRefusal::Malformed)
        );

        // The Processing Unit declares three bitmap bytes and carries two.
        let pu_at = header_at + 13;
        assert_eq!(whole[pu_at + 2], SUBTYPE_PROCESSING_UNIT);
        let mut short_pu = whole.clone();
        short_pu[pu_at] = 10;
        short_pu.drain(pu_at + 10..pu_at + 13);
        assert_eq!(
            ir_function_evidence(&short_pu, 0),
            Err(IrFunctionRefusal::Malformed)
        );

        // A Processing Unit whose bLength stops right after bmControls,
        // leaving out iProcessing.
        let pu_len = usize::from(whole[pu_at]);
        let control_size = usize::from(whole[pu_at + 7]);
        let mut no_i_processing = whole.clone();
        no_i_processing[pu_at] = (8 + control_size) as u8;
        no_i_processing.drain(pu_at + 8 + control_size..pu_at + pu_len);
        assert_eq!(
            ir_function_evidence(&no_i_processing, 0),
            Err(IrFunctionRefusal::Malformed)
        );

        // A Microsoft unit whose bLength stops right after bmControls,
        // leaving out iExtension, with the face-authentication bit set.
        let guid_at = whole
            .windows(16)
            .position(|window| window == t480::guid(MSXU))
            .expect("the Microsoft unit");
        let xu_at = guid_at - 4;
        assert_eq!(whole[xu_at + 2], 0x06);
        let xu_len = usize::from(whole[xu_at]);
        let mut no_i_extension = whole.clone();
        no_i_extension[xu_at] = (xu_len - 1) as u8;
        no_i_extension.remove(xu_at + xu_len - 1);
        assert_eq!(
            ir_function_evidence(&no_i_extension, 0),
            Err(IrFunctionRefusal::Malformed)
        );

        // A tail that stops mid-descriptor, or leaves one stray byte.
        let mut short_tail = T480_IR.to_vec();
        short_tail.pop();
        assert_eq!(
            ir_function_evidence(&short_tail, 0),
            Err(IrFunctionRefusal::Malformed)
        );
        let mut stray = T480_IR.to_vec();
        stray.push(0);
        assert_eq!(
            ir_function_evidence(&stray, 0),
            Err(IrFunctionRefusal::Malformed)
        );

        // Two headers make the function's stream list ambiguous.
        let mut two_headers = whole.clone();
        let header = whole[header_at..header_at + 13].to_vec();
        two_headers.splice(header_at..header_at, header);
        assert_eq!(
            ir_function_evidence(&two_headers, 0),
            Err(IrFunctionRefusal::Malformed)
        );
    }

    /// The header must list a VideoStreaming interface of the same
    /// configuration: listing the control interface itself, or one that
    /// does not exist, is a malformed function, not a stream.
    #[test]
    fn a_listed_interface_that_is_not_videostreaming_is_malformed() {
        for listed in [0u8, 3] {
            let shape = function(&[listed], &[1], &[0], &[(8, MSXU, 2, &[0x22, 0x00])]);
            assert_eq!(
                ir_function_evidence(&shape, 0),
                Err(IrFunctionRefusal::Malformed),
                "interface {listed}"
            );
        }
    }

    /// A face-authentication unit belongs to its own function: a second
    /// VideoControl function on the device cannot lend it to the first.
    #[test]
    fn a_face_authentication_unit_on_another_interface_attests_nothing_here() {
        let mut bytes = function(&[1], &[1], &[0], &[]);
        bytes[18 + 4] = 4;
        bytes.extend(t480::interface(2, 0, 1, SUBCLASS_VIDEOCONTROL, 1, 0));
        bytes.extend(t480::vc_header(0x0150, 0, 15_000_000, &[3]));
        bytes.extend(t480::extension_unit(14, MSXU, 2, 2, &[0x22, 0x00], 0));
        bytes.extend(t480::interrupt_endpoint(0x84, 6));
        bytes.extend(t480::interface(3, 0, 0, SUBCLASS_VIDEOSTREAMING, 1, 0));
        assert_eq!(
            ir_function_evidence(&bytes, 0),
            Err(IrFunctionRefusal::NoMicrosoftXu)
        );
        assert_eq!(
            ir_function_evidence(&bytes, 2),
            Ok(IrFunctionEvidence {
                msxu_unit: 14,
                streaming_interface: 3,
            })
        );
    }

    /// The fd-bound attestation reads the descriptor of the identity it was
    /// resolved from, scoped to the active configuration and the bound
    /// interface.
    #[test]
    fn the_camera_identity_attests_from_its_own_descriptor() {
        let fixture = UsbFixture::new("t480-ir", 1, 0, T480_IR);
        assert_eq!(
            fixture.identity().unwrap().ir_function_evidence(),
            Ok(IrFunctionEvidence {
                msxu_unit: 8,
                streaming_interface: 1,
            })
        );
        let streaming = UsbFixture::new("t480-vs", 1, 1, T480_IR);
        assert_eq!(
            streaming.identity().unwrap().ir_function_evidence(),
            Err(IrFunctionRefusal::NotVideoControl),
            "a streaming interface is not a VideoControl function"
        );
        let rgb = UsbFixture::new("t480-rgb", 1, 0, T480_RGB);
        assert_eq!(
            rgb.identity().unwrap().ir_function_evidence(),
            Err(IrFunctionRefusal::NoMicrosoftXu)
        );
    }

    /// A node with no USB parent (a loopback feeder, `/dev/null`, a path
    /// that does not exist) has no descriptor, and no descriptor is no
    /// attestation.
    #[test]
    fn node_evidence_fails_closed_without_a_usb_parent() {
        let _fixture = crate::hostfs::test::empty_fixture();
        for node in ["/dev/null", "/dev/irlume-no-such-node"] {
            assert_eq!(
                ir_function_evidence_for_node(node),
                Err(IrFunctionRefusal::Unreadable),
                "{node}"
            );
        }
    }

    /// A descriptor file that was read but does not hold one complete
    /// active configuration is malformed, not unreadable: the census prints
    /// the refusal as the reason, and "no readable USB descriptor" would
    /// send a reporter looking for a permissions problem. A file that is
    /// missing, or a configuration that cannot be read, stays unreadable.
    #[test]
    fn a_descriptor_file_that_was_read_but_is_malformed_is_not_unreadable() {
        let sound = UsbFixture::new("887-sound", 1, 0, T480_IR);
        assert!(ir_function_evidence_from_dirs(&sound.interface, &sound.device).is_ok());

        let mut miscounted = T480_IR.to_vec();
        miscounted[17] = 2;
        let mut zero_length = T480_IR.to_vec();
        zero_length.extend_from_slice(&[0, 0]);
        let mut duplicate = T480_IR.to_vec();
        duplicate[17] = 2;
        duplicate.extend(t480::configuration(0, 2, 0));
        for (label, bytes) in [
            ("887-miscounted", miscounted),
            ("887-zero-length", zero_length),
            ("887-duplicate", duplicate),
        ] {
            let fixture = UsbFixture::new(label, 1, 0, &bytes);
            assert_eq!(
                ir_function_evidence_from_dirs(&fixture.interface, &fixture.device),
                Err(IrFunctionRefusal::Malformed),
                "{label}"
            );
        }

        let missing = UsbFixture::new("887-missing", 1, 0, T480_IR);
        std::fs::remove_file(missing.device.join("descriptors")).unwrap();
        assert_eq!(
            ir_function_evidence_from_dirs(&missing.interface, &missing.device),
            Err(IrFunctionRefusal::Unreadable)
        );
        let unconfigured = UsbFixture::new("887-unconfigured", 1, 0, T480_IR);
        std::fs::write(unconfigured.device.join("bConfigurationValue"), "\n").unwrap();
        assert_eq!(
            ir_function_evidence_from_dirs(&unconfigured.interface, &unconfigured.device),
            Err(IrFunctionRefusal::Unreadable)
        );
    }

    /// A video node on USB that uvcvideo does not drive, such as a
    /// vendor-class analogue grabber offering only YUYV, sits behind an
    /// interface that is not a UVC VideoControl interface. Its descriptor is
    /// well formed, and the refusal says what it is instead of calling it
    /// malformed.
    #[test]
    fn a_well_formed_interface_that_is_not_videocontrol_is_named_as_such() {
        // A Fushicai USBTV007 (1b71:3002) shape: one configuration whose
        // interface 0 is vendor class 0xFF with one bulk endpoint.
        let mut grabber = vec![
            18, 0x01, 0x00, 0x02, 0, 0, 0, 64, 0x71, 0x1B, 0x02, 0x30, 0x00, 0x01, 1, 2, 0, 1,
        ];
        grabber.extend(t480::configuration(0, 1, 0));
        grabber.extend_from_slice(&[9, DESC_INTERFACE, 0, 0, 1, 0xFF, 0, 0, 0]);
        grabber.extend_from_slice(&[7, 0x05, 0x81, 0x02, 0x00, 0x02, 0]);
        assert_eq!(active_descriptor_view(&grabber, 1), Some(grabber.clone()));
        assert_eq!(
            ir_function_evidence(&grabber, 0),
            Err(IrFunctionRefusal::NotVideoControl)
        );
        let fixture = UsbFixture::new("887-grabber", 1, 0, &grabber);
        assert_eq!(
            ir_function_evidence_from_dirs(&fixture.interface, &fixture.device),
            Err(IrFunctionRefusal::NotVideoControl)
        );
        // Framing that breaks before the walk can tell stays malformed.
        let mut broken = grabber.clone();
        broken.push(0);
        assert_eq!(
            ir_function_evidence(&broken, 0),
            Err(IrFunctionRefusal::Malformed)
        );
    }

    /// The census prints these as "not IR by USB descriptor: ...".
    #[test]
    fn refusals_name_the_clause_that_failed() {
        for (refusal, text) in [
            (IrFunctionRefusal::Unreadable, "no readable USB descriptor"),
            (
                IrFunctionRefusal::Malformed,
                "the USB descriptor is malformed",
            ),
            (
                IrFunctionRefusal::NotVideoControl,
                "its USB interface is not a UVC VideoControl interface",
            ),
            (
                IrFunctionRefusal::StreamingInterfaces(2),
                "its video function lists 2 streams, not one",
            ),
            (
                IrFunctionRefusal::NoMicrosoftXu,
                "no Microsoft camera-control unit",
            ),
            (
                IrFunctionRefusal::AmbiguousMicrosoftXu,
                "more than one Microsoft camera-control unit",
            ),
            (
                IrFunctionRefusal::NoFaceAuthentication,
                "its Microsoft camera-control unit has no face-authentication control",
            ),
            (
                IrFunctionRefusal::ColourProcessing(0x104C),
                "colour controls advertised (Processing Unit bits 0x104c)",
            ),
        ] {
            assert_eq!(refusal.to_string(), text);
        }
    }

    /// The role walker and the emitter's parser read extension units the
    /// same way, on three real devices' bytes and on every interface. The
    /// fuzz target asserts the same on arbitrary input.
    #[test]
    fn video_control_function_xus_match_the_emitter_parser() {
        let mut short = T480_IR.to_vec();
        short.pop();
        for (label, bytes) in [
            ("ASUS", ASUS.to_vec()),
            ("5986:1141", T480_IR.to_vec()),
            ("5986:2113", T480_RGB.to_vec()),
            ("truncated", short),
        ] {
            for interface in 0..=5u8 {
                let emitter = extension_units_for_interface(&bytes, interface);
                match video_control_function(&bytes, interface) {
                    Some(function) => {
                        assert_eq!(function.extension_units, emitter, "{label} {interface}");
                    }
                    // On these inputs the walker refuses only what the
                    // emitter parser also finds nothing in: interfaces that
                    // are not VideoControl, and the truncated chain.
                    None => assert!(
                        emitter.is_empty(),
                        "{label} {interface}: the walker refused a function the emitter parsed"
                    ),
                }
            }
        }
        assert_eq!(
            video_control_function(ASUS, 2).unwrap().extension_units,
            extension_units_for_interface(ASUS, 2),
        );
        assert_eq!(
            video_control_function(T480_IR, 0)
                .unwrap()
                .extension_units
                .iter()
                .map(|unit| unit.unit_id)
                .collect::<Vec<_>>(),
            [4, 6, 8]
        );
    }
}

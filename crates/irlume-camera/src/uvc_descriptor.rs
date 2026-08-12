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

const DESC_INTERFACE: u8 = 0x04;
const DESC_IAD: u8 = 0x0B;
const DESC_CS_INTERFACE: u8 = 0x24;
const SUBTYPE_EXTENSION_UNIT: u8 = 0x06;
const CLASS_VIDEO: u8 = 0x0E;
const SUBCLASS_VIDEOCONTROL: u8 = 0x01;
const SUBCLASS_VIDEOSTREAMING: u8 = 0x02;
/// VideoStreaming class-specific subtypes that declare a format (UVC 1.5
/// table 3-1): uncompressed and frame-based carry a `guidFormat` at bytes
/// 5..21; MJPEG has no GUID and IS the format.
const VS_FORMAT_UNCOMPRESSED: u8 = 0x04;
const VS_FORMAT_MJPEG: u8 = 0x06;
const VS_FORMAT_FRAME_BASED: u8 = 0x10;

/// The format GUIDs a Hello-class camera's streaming interfaces advertise,
/// paired with the fourcc uvcvideo would report for each, COPIED from the
/// kernel's own table (`include/linux/usb/uvc.h` definitions,
/// `drivers/media/common/uvc.c` mappings) so a descriptor-classified node and
/// an ENUM_FMT-classified node answer identically (#428). Byte order is
/// descriptor wire order, the same convention as [`MS_CAMERA_CONTROL_XU`].
///
/// The greyscale family matters most and has FOUR members mapping to GREY:
/// Y8, Y800, D3DFMT_L8, and KSMEDIA_L8_IR, the Windows Hello IR format. The
/// last two differ only in byte 4 (0x00 against 0x02), and the ASUS camera
/// this project develops against advertises KSMEDIA_L8_IR, so a table
/// missing it would classify this very laptop's IR camera as format-unknown.
/// Matching is whole-GUID: the standard 12-byte tail does NOT cover
/// KSMEDIA_L8_IR, whose Data2 is 0x0002.
const GUID_FOURCCS: [([u8; 16], [u8; 4]); 11] = [
    (guid_std(*b"YUY2"), *b"YUYV"),
    (guid_std(*b"NV12"), *b"NV12"),
    (guid_std(*b"UYVY"), *b"UYVY"),
    (guid_std(*b"Y800"), *b"GREY"),
    (guid_std(*b"Y8  "), *b"GREY"),
    (guid_std(*b"Y10 "), *b"Y10 "),
    (guid_std(*b"Y12 "), *b"Y12 "),
    (guid_std(*b"Y16 "), *b"Y16 "),
    // D3DFMT_L8: Data1 0x00000032, standard tail.
    (guid_data1(0x0000_0032, 0x0000), *b"GREY"),
    // KSMEDIA_L8_IR: same Data1, Data2 0x0002.
    (guid_data1(0x0000_0032, 0x0002), *b"GREY"),
    // BGR3 uses its own GUID, not the standard tail (kernel header).
    (
        [
            0x7d, 0xeb, 0x36, 0xe4, 0x4f, 0x52, 0xce, 0x11, 0x9f, 0x53, 0x00, 0x20, 0xaf, 0x0b,
            0xa7, 0x70,
        ],
        *b"BGR3",
    ),
];

/// A standard-tail format GUID: four fourcc bytes, Data2 zero, then the
/// fixed `1000-8000-00aa00389b71` tail, in wire order.
const fn guid_std(fourcc: [u8; 4]) -> [u8; 16] {
    guid_data1(u32::from_le_bytes(fourcc), 0x0000)
}

/// A format GUID from its Data1 dword and Data2 word, standard tail.
const fn guid_data1(data1: u32, data2: u16) -> [u8; 16] {
    let d1 = data1.to_le_bytes();
    let d2 = data2.to_le_bytes();
    [
        d1[0], d1[1], d1[2], d1[3], d2[0], d2[1], 0x10, 0x00, 0x80, 0x00, 0x00, 0xAA, 0x00, 0x38,
        0x9B, 0x71,
    ]
}

/// The fourcc uvcvideo would report for a streaming-format GUID, or `None`
/// for a format the table does not carry (vendor formats; the caller falls
/// back to the open probe when nothing at all is recognised).
fn fourcc_for_guid(guid: &[u8; 16]) -> Option<[u8; 4]> {
    GUID_FOURCCS
        .iter()
        .find(|(g, _)| g == guid)
        .map(|(_, cc)| *cc)
}

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
pub fn extension_units_for_interface(desc: &[u8], interface_number: u8) -> Vec<ExtensionUnit> {
    let mut out = Vec::new();
    let mut in_target_vc = false;
    let mut i = 0usize;

    while i + 2 <= desc.len() {
        let len = usize::from(desc[i]);
        // A zero length would not advance, and anything overrunning the buffer
        // means the chain is malformed. Either way, stop rather than guess.
        if len < 2 || i + len > desc.len() {
            break;
        }
        let d = &desc[i..i + len];

        match d[1] {
            DESC_INTERFACE if len >= 7 => {
                in_target_vc = d[2] == interface_number
                    && d[5] == CLASS_VIDEO
                    && d[6] == SUBCLASS_VIDEOCONTROL;
            }
            DESC_CS_INTERFACE if in_target_vc && len >= 3 && d[2] == SUBTYPE_EXTENSION_UNIT => {
                if let Some(unit) = parse_extension_unit(d) {
                    out.push(unit);
                }
            }
            _ => {}
        }
        i += len;
    }
    out
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

/// The pixel formats a camera FUNCTION advertises, read from its descriptor
/// blob alone, as the fourccs uvcvideo would report for them (#428).
///
/// A UVC function is one VideoControl interface plus its VideoStreaming
/// interfaces. The grouping comes from the Interface Association Descriptor
/// covering `vc_interface` when the device publishes IADs (the composite
/// two-function ASUS module does, one per camera); a device without one gets
/// the specification's layout instead, where a function's streaming
/// interfaces follow their VideoControl contiguously until the next
/// VideoControl interface begins.
///
/// Only formats the GUID table recognises are returned. An empty answer
/// means "this blob names nothing irlume knows", and the caller must treat
/// that as no evidence rather than as a camera with no formats: a
/// vendor-format-only device still classifies through the open probe.
pub(crate) fn function_fourccs(desc: &[u8], vc_interface: u8) -> Vec<[u8; 4]> {
    // First pass: the IAD covering the VideoControl interface, if any.
    let mut group: Option<(u8, u8)> = None; // (first, count)
    let mut i = 0usize;
    while i + 2 <= desc.len() {
        let len = usize::from(desc[i]);
        if len < 2 || i + len > desc.len() {
            break;
        }
        let d = &desc[i..i + len];
        if d[1] == DESC_IAD && len >= 8 && d[2] <= vc_interface && vc_interface < d[2] + d[3] {
            group = Some((d[2], d[3]));
        }
        i += len;
    }

    // Second pass: formats on the streaming interfaces of this function.
    let mut out = Vec::new();
    let mut in_function_vs = false;
    let mut past_vc = false;
    let mut i = 0usize;
    while i + 2 <= desc.len() {
        let len = usize::from(desc[i]);
        if len < 2 || i + len > desc.len() {
            break;
        }
        let d = &desc[i..i + len];
        match d[1] {
            DESC_INTERFACE if len >= 7 => {
                let (num, class, sub) = (d[2], d[5], d[6]);
                let in_group = match group {
                    Some((first, count)) => num >= first && num < first + count,
                    // No IAD: the spec's contiguous layout. Streaming
                    // interfaces count once their VideoControl has been
                    // seen, and any LATER VideoControl ends the function.
                    None => {
                        if class == CLASS_VIDEO && sub == SUBCLASS_VIDEOCONTROL {
                            past_vc = num == vc_interface;
                        }
                        past_vc
                    }
                };
                in_function_vs = in_group && class == CLASS_VIDEO && sub == SUBCLASS_VIDEOSTREAMING;
            }
            DESC_CS_INTERFACE if in_function_vs && len >= 3 => match d[2] {
                VS_FORMAT_UNCOMPRESSED | VS_FORMAT_FRAME_BASED if len >= 21 => {
                    let mut guid = [0u8; 16];
                    guid.copy_from_slice(&d[5..21]);
                    if let Some(cc) = fourcc_for_guid(&guid) {
                        out.push(cc);
                    }
                }
                VS_FORMAT_MJPEG => out.push(*b"MJPG"),
                _ => {}
            },
            _ => {}
        }
        i += len;
    }
    out
}

/// [`function_fourccs`] for a live node: the sysfs descriptor blob and the
/// node's VideoControl interface number, no device open. `None` when the
/// node has no USB descriptors (not a UVC camera: a loopback node, a
/// platform stack) or when the blob names no format irlume recognises;
/// either way the caller's open probe remains the authority.
pub(crate) fn streaming_fourccs(video_device: &str) -> Option<Vec<[u8; 4]>> {
    let (desc, vc_interface) = usb_context(video_device).ok()?;
    let fourccs = function_fourccs(&desc, vc_interface);
    if fourccs.is_empty() {
        None
    } else {
        Some(fourccs)
    }
}

/// The USB configuration descriptors and VideoControl interface number backing
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
    let interface_number = read_hex_u8(&iface_dir.join("bInterfaceNumber")).ok_or_else(|| {
        bad(format!(
            "{} has no bInterfaceNumber; not a USB interface",
            iface_dir.display()
        ))
    })?;
    let descriptors = usb_device_dir(video_device)?.join("descriptors");
    Ok((std::fs::read(descriptors)?, interface_number))
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
    pub descriptors: Vec<u8>,
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

#[expect(clippy::missing_errors_doc, reason = "doc backlog")]
pub fn identity_from_fd(fd: std::os::raw::c_int) -> std::io::Result<CameraIdentity> {
    let (major, minor) = device_numbers(fd)?;
    let node = std::fs::canonicalize(format!("/sys/dev/char/{major}:{minor}"))?;

    let iface_dir = ancestor_with(&node, "bInterfaceNumber").ok_or_else(|| {
        bad(format!(
            "no USB interface above {} (not a UVC device?)",
            node.display()
        ))
    })?;
    let interface_number = read_hex_u8(&iface_dir.join("bInterfaceNumber")).ok_or_else(|| {
        bad(format!(
            "{} has an unreadable bInterfaceNumber",
            iface_dir.display()
        ))
    })?;

    let dev_dir = ancestor_with(&iface_dir, "descriptors")
        .ok_or_else(|| bad(format!("no USB descriptors above {}", iface_dir.display())))?;

    Ok(CameraIdentity {
        descriptors: std::fs::read(dev_dir.join("descriptors"))?,
        interface_number,
        vid: read_hex_u16(&dev_dir.join("idVendor"))
            .ok_or_else(|| bad(format!("{} has no idVendor", dev_dir.display())))?,
        pid: read_hex_u16(&dev_dir.join("idProduct"))
            .ok_or_else(|| bad(format!("{} has no idProduct", dev_dir.display())))?,
        serial: read_optional_serial(&dev_dir)?,
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
            .strip_prefix("/sys")
            .map(|p| std::path::Path::new("/").join(p))
            .unwrap_or_else(|_| dev_dir.clone())
            .to_string_lossy()
            .into_owned(),
    })
}

impl CameraIdentity {
    pub fn extension_units(&self) -> Vec<ExtensionUnit> {
        extension_units_for_interface(&self.descriptors, self.interface_number)
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
    std::fs::canonicalize(
        PathBuf::from("/sys/class/video4linux")
            .join(node)
            .join("device"),
    )
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

    /// The real camera's two functions classify from the blob alone (#428):
    /// the RGB function (VideoControl interface 0) advertises MJPEG plus
    /// YUY2, the IR function (interface 2) exactly the 8-bit IR format, and
    /// the two must never see each other's formats or the composite module
    /// collapses into one mislabeled camera.
    #[test]
    fn the_real_blob_classifies_both_functions_by_their_own_formats() {
        assert_eq!(
            function_fourccs(ASUS, 0),
            vec![*b"MJPG", *b"YUYV"],
            "the RGB function's streaming formats"
        );
        assert_eq!(
            function_fourccs(ASUS, 2),
            vec![*b"GREY"],
            "the IR function's one format, KSMEDIA_L8_IR mapped as uvcvideo maps it"
        );
    }

    /// The IR format the real camera advertises is KSMEDIA_L8_IR, whose
    /// GUID differs from D3DFMT_L8 only in byte 4 and whose Data2 makes the
    /// standard 12-byte tail NOT match. The wire bytes must appear in the
    /// fixture and the table must map them; a tail-keyed matcher, or a
    /// table with only D3DFMT_L8, silently loses this laptop's IR camera
    /// (the first session write-up made exactly that misreading).
    #[test]
    fn ksmedia_l8_ir_is_matched_by_whole_guid_in_wire_order() {
        let ksmedia = guid_data1(0x0000_0032, 0x0002);
        assert!(
            ASUS.windows(16).any(|w| w == ksmedia),
            "the fixture must carry the KSMEDIA_L8_IR GUID in wire order"
        );
        assert_eq!(fourcc_for_guid(&ksmedia), Some(*b"GREY"));
        let d3d = guid_data1(0x0000_0032, 0x0000);
        assert_ne!(ksmedia, d3d, "byte 4 separates the two L8 GUIDs");
        assert!(
            !ASUS.windows(16).any(|w| w == d3d),
            "this camera does not advertise D3DFMT_L8; only the table entry \
             covers cameras that do"
        );
    }

    /// A device with no Interface Association Descriptors gets the
    /// specification's contiguous layout: a function's streaming interfaces
    /// follow their VideoControl until the next VideoControl begins. Two
    /// back-to-back functions must still split correctly.
    #[test]
    fn without_iads_streaming_interfaces_bind_to_the_preceding_videocontrol() {
        let mut blob = Vec::new();
        // interface 0: VideoControl of function A
        blob.extend_from_slice(&[
            9,
            DESC_INTERFACE,
            0,
            0,
            0,
            CLASS_VIDEO,
            SUBCLASS_VIDEOCONTROL,
            0,
            0,
        ]);
        // interface 1: VideoStreaming of function A, YUY2
        blob.extend_from_slice(&[
            9,
            DESC_INTERFACE,
            1,
            0,
            0,
            CLASS_VIDEO,
            SUBCLASS_VIDEOSTREAMING,
            0,
            0,
        ]);
        let mut fmt = vec![27, DESC_CS_INTERFACE, VS_FORMAT_UNCOMPRESSED, 1, 1];
        fmt.extend_from_slice(&guid_std(*b"YUY2"));
        fmt.extend_from_slice(&[16, 1, 0, 0, 0, 0]);
        blob.extend_from_slice(&fmt);
        // interface 2: VideoControl of function B ends function A
        blob.extend_from_slice(&[
            9,
            DESC_INTERFACE,
            2,
            0,
            0,
            CLASS_VIDEO,
            SUBCLASS_VIDEOCONTROL,
            0,
            0,
        ]);
        // interface 3: VideoStreaming of function B, Y8
        blob.extend_from_slice(&[
            9,
            DESC_INTERFACE,
            3,
            0,
            0,
            CLASS_VIDEO,
            SUBCLASS_VIDEOSTREAMING,
            0,
            0,
        ]);
        let mut fmt = vec![27, DESC_CS_INTERFACE, VS_FORMAT_UNCOMPRESSED, 1, 1];
        fmt.extend_from_slice(&guid_std(*b"Y8  "));
        fmt.extend_from_slice(&[8, 1, 0, 0, 0, 0]);
        blob.extend_from_slice(&fmt);

        assert_eq!(function_fourccs(&blob, 0), vec![*b"YUYV"]);
        assert_eq!(function_fourccs(&blob, 2), vec![*b"GREY"]);
    }
}

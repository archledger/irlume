// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright the irlume contributors.

//! Ask the media controller which of a camera's video nodes is the capture
//! node, without opening any video node (#428).
//!
//! A UVC function registers TWO `/dev/video*` nodes per streaming interface,
//! a frame-capture node and a metadata node, and both bind the same USB
//! interface, so the descriptor blob cannot tell them apart. The media graph
//! can: uvcvideo links only the capture node's entity into the UVC chain and
//! gives it its pad, while the metadata entity is registered padless and
//! linkless (`uvc_entity.c`, `uvc_metadata.c`; measured on the ASUS pair in
//! `docs/research/2026-08-12-camera-session-measurements.md`).
//!
//! Opening `/dev/media*` is the one probe the kernel documents as free of
//! side effects: "The function has no side effects; the device configuration
//! remain unchanged" (media-func-open.rst), and `media_device_open` in
//! mc-device.c is a bare `return 0`. This is what makes the whole no-open
//! classification honest; a video-node open on pre-6.16 kernels powers the
//! camera up and can blink its LED.
//!
//! The graph is read with `MEDIA_IOC_G_TOPOLOGY`, the two-call protocol from
//! media-ioc-g-topology.rst: a zeroed call returns the element counts, the
//! second call fills caller-allocated arrays, and a topology that changed in
//! between answers ENOSPC rather than overflowing, so the dance retries.

use std::os::fd::AsRawFd as _;
use std::path::Path;

/// `MEDIA_IOC_G_TOPOLOGY` = `_IOWR('|', 0x04, struct media_v2_topology)`.
/// The media ioctl type byte is `'|'`, not the V4L2 `'V'`, which is why the
/// builder in `ir_metadata.rs` cannot be reused as-is.
const fn media_iowr(nr: libc::c_ulong, size: usize) -> libc::c_ulong {
    const DIR_RW: libc::c_ulong = 3;
    (DIR_RW << 30) | ((size as libc::c_ulong) << 16) | ((b'|' as libc::c_ulong) << 8) | nr
}

fn media_ioc_g_topology() -> libc::c_ulong {
    media_iowr(0x04, core::mem::size_of::<MediaV2Topology>())
}

/// `MEDIA_INTF_T_V4L_VIDEO`: the interface type of a `/dev/video*` devnode.
const MEDIA_INTF_T_V4L_VIDEO: u32 = 0x0000_0200;
/// The link-type field is the top nibble of the flags word, and DATA_LINK is
/// its ZERO value, so link kinds are told apart by mask-and-compare, never by
/// testing a bit.
const MEDIA_LNK_FL_LINK_TYPE: u32 = 0xf << 28;
const MEDIA_LNK_FL_INTERFACE_LINK: u32 = 1 << 28;

// The C structs from include/uapi/linux/media.h. They are declared packed
// there, but every field already sits at its natural alignment (the
// topology's u64s land at offsets 0, 16, 32, 48, 64), so plain `repr(C)`
// reproduces the layout without Rust's packed-field reference restrictions.
// The size assertions are the guard that matters: the struct size is encoded
// in the ioctl request number, and a wrong size makes every call answer
// ENOTTY, which reads exactly like a kernel without the media API (the same
// trap `ir_metadata.rs` documents for V4l2Format).

#[repr(C)]
#[derive(Clone, Copy)]
struct MediaV2Topology {
    topology_version: u64,
    num_entities: u32,
    reserved1: u32,
    ptr_entities: u64,
    num_interfaces: u32,
    reserved2: u32,
    ptr_interfaces: u64,
    num_pads: u32,
    reserved3: u32,
    ptr_pads: u64,
    num_links: u32,
    reserved4: u32,
    ptr_links: u64,
}
const _: () = assert!(core::mem::size_of::<MediaV2Topology>() == 72);

#[repr(C)]
#[derive(Clone, Copy)]
pub(crate) struct MediaV2Entity {
    pub(crate) id: u32,
    pub(crate) name: [u8; 64],
    pub(crate) function: u32,
    pub(crate) flags: u32,
    reserved: [u32; 5],
}
const _: () = assert!(core::mem::size_of::<MediaV2Entity>() == 96);

#[repr(C)]
#[derive(Clone, Copy)]
pub(crate) struct MediaV2Interface {
    pub(crate) id: u32,
    pub(crate) intf_type: u32,
    pub(crate) flags: u32,
    reserved: [u32; 9],
    /// The C side is a union sized by `__u32 raw[16]`; for a devnode
    /// interface, `raw[0]` is the major and `raw[1]` the minor
    /// (`media_v2_intf_devnode`).
    pub(crate) raw: [u32; 16],
}
const _: () = assert!(core::mem::size_of::<MediaV2Interface>() == 112);

#[repr(C)]
#[derive(Clone, Copy)]
pub(crate) struct MediaV2Pad {
    pub(crate) id: u32,
    pub(crate) entity_id: u32,
    pub(crate) flags: u32,
    pub(crate) index: u32,
    reserved: [u32; 4],
}
const _: () = assert!(core::mem::size_of::<MediaV2Pad>() == 32);

#[repr(C)]
#[derive(Clone, Copy)]
pub(crate) struct MediaV2Link {
    pub(crate) id: u32,
    pub(crate) source_id: u32,
    pub(crate) sink_id: u32,
    pub(crate) flags: u32,
    reserved: [u32; 6],
}
const _: () = assert!(core::mem::size_of::<MediaV2Link>() == 40);

fn zeroed_entity() -> MediaV2Entity {
    MediaV2Entity {
        id: 0,
        name: [0; 64],
        function: 0,
        flags: 0,
        reserved: [0; 5],
    }
}

fn zeroed_interface() -> MediaV2Interface {
    MediaV2Interface {
        id: 0,
        intf_type: 0,
        flags: 0,
        reserved: [0; 9],
        raw: [0; 16],
    }
}

fn zeroed_pad() -> MediaV2Pad {
    MediaV2Pad {
        id: 0,
        entity_id: 0,
        flags: 0,
        index: 0,
        reserved: [0; 4],
    }
}

fn zeroed_link() -> MediaV2Link {
    MediaV2Link {
        id: 0,
        source_id: 0,
        sink_id: 0,
        flags: 0,
        reserved: [0; 6],
    }
}

/// Whether the video node at `major:minor` is a CAPTURE node in this graph:
/// its devnode interface links to an entity that owns at least one pad.
///
/// Pads rather than `MEDIA_ENT_FL_DEFAULT` carry the decision, because the
/// entity `flags` word is documented valid only from media_version 4.19
/// while pads have no such gate, and the two agree on the hardware measured
/// (capture entity: one pad and the DEFAULT flag; metadata entity: neither).
/// `None` when the node does not appear in this graph at all, which sends
/// the caller back to the open probe rather than guessing.
pub(crate) fn node_is_capture_in(
    interfaces: &[MediaV2Interface],
    links: &[MediaV2Link],
    pads: &[MediaV2Pad],
    major: u32,
    minor: u32,
) -> Option<bool> {
    let iface = interfaces.iter().find(|i| {
        i.intf_type == MEDIA_INTF_T_V4L_VIDEO && i.raw[0] == major && i.raw[1] == minor
    })?;
    let entity_id = links
        .iter()
        .find(|l| {
            l.flags & MEDIA_LNK_FL_LINK_TYPE == MEDIA_LNK_FL_INTERFACE_LINK
                && l.source_id == iface.id
        })?
        .sink_id;
    Some(pads.iter().any(|p| p.entity_id == entity_id))
}

/// [`node_is_capture_in`] against the live graph that owns `video_device`.
///
/// `None` whenever the answer cannot be established without guessing: no
/// media device beside the node's USB interface in sysfs, an unreadable
/// `dev` file, or a topology that will not settle. Every `None` falls back
/// to the caller's open probe, so this path can only ever REMOVE opens,
/// never change a classification.
pub(crate) fn node_is_capture(video_device: &str) -> Option<bool> {
    let node = Path::new(video_device).file_name()?.to_str()?;
    // "81:2" from sysfs; no /dev stat, no open.
    let devno = std::fs::read_to_string(format!("/sys/class/video4linux/{node}/dev")).ok()?;
    let (major, minor) = devno.trim().split_once(':')?;
    let (major, minor) = (major.parse::<u32>().ok()?, minor.parse::<u32>().ok()?);

    // The media device registers as a plain subdirectory of the SAME USB
    // interface directory the video node's `device` link resolves to, so the
    // owning /dev/mediaN needs no iterate-and-ask search (measured:
    // 3-5:1.0/media0, 3-5:1.2/media1).
    let iface_dir = crate::uvc_descriptor::interface_dir(video_device).ok()?;
    let media_name = std::fs::read_dir(&iface_dir).ok()?.find_map(|e| {
        let name = e.ok()?.file_name();
        let name = name.to_str()?;
        name.starts_with("media").then(|| name.to_string())
    })?;

    let media = std::fs::OpenOptions::new()
        .read(true)
        .open(format!("/dev/{media_name}"))
        .ok()?;
    let (interfaces, links, pads) = read_topology(media.as_raw_fd())?;
    node_is_capture_in(&interfaces, &links, &pads, major, minor)
}

/// The two-call G_TOPOLOGY dance, retried when the graph changes between the
/// count call and the fill call (the documented ENOSPC contract). Three
/// tries covers a hotplug landing mid-read; a graph still moving after that
/// is a graph to classify later.
fn read_topology(
    fd: libc::c_int,
) -> Option<(Vec<MediaV2Interface>, Vec<MediaV2Link>, Vec<MediaV2Pad>)> {
    for _ in 0..3 {
        let mut top = MediaV2Topology {
            topology_version: 0,
            num_entities: 0,
            reserved1: 0,
            ptr_entities: 0,
            num_interfaces: 0,
            reserved2: 0,
            ptr_interfaces: 0,
            num_pads: 0,
            reserved3: 0,
            ptr_pads: 0,
            num_links: 0,
            reserved4: 0,
            ptr_links: 0,
        };
        // SAFETY: fd is an open media node owned by the caller for the length
        // of this call, and `top` is a correctly sized, zeroed
        // media_v2_topology; with every ptr_* zero the kernel only writes the
        // counts (media-ioc-g-topology.rst).
        let rc = unsafe {
            libc::ioctl(
                fd,
                media_ioc_g_topology(),
                &mut top as *mut _ as *mut libc::c_void,
            )
        };
        if rc < 0 {
            return None;
        }

        // Entities are fetched too, not because the decision reads them, but
        // because asking for a consistent snapshot of everything is what the
        // protocol shape expects; the cost is bytes.
        let mut entities = vec![zeroed_entity(); top.num_entities as usize];
        let mut interfaces = vec![zeroed_interface(); top.num_interfaces as usize];
        let mut pads = vec![zeroed_pad(); top.num_pads as usize];
        let mut links = vec![zeroed_link(); top.num_links as usize];
        top.ptr_entities = entities.as_mut_ptr() as u64;
        top.ptr_interfaces = interfaces.as_mut_ptr() as u64;
        top.ptr_pads = pads.as_mut_ptr() as u64;
        top.ptr_links = links.as_mut_ptr() as u64;

        // SAFETY: the four pointers name live, correctly sized arrays whose
        // lengths match the counts in `top`, and they outlive the call; the
        // kernel fills them or answers ENOSPC when the graph moved.
        let rc = unsafe {
            libc::ioctl(
                fd,
                media_ioc_g_topology(),
                &mut top as *mut _ as *mut libc::c_void,
            )
        };
        if rc >= 0 {
            return Some((interfaces, links, pads));
        }
        if std::io::Error::last_os_error().raw_os_error() != Some(libc::ENOSPC) {
            return None;
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The measured Zenbook graph, reduced to the decision's inputs: a
    /// capture entity (id 1) with one pad and a devnode interface link, and
    /// a padless, linkless metadata entity whose devnode interface still
    /// exists and still links (the kernel links every registered node's
    /// interface; what the metadata entity lacks is pads).
    fn measured_shape() -> (Vec<MediaV2Interface>, Vec<MediaV2Link>, Vec<MediaV2Pad>) {
        let mut cap_iface = zeroed_interface();
        cap_iface.id = 100;
        cap_iface.intf_type = MEDIA_INTF_T_V4L_VIDEO;
        cap_iface.raw[0] = 81;
        cap_iface.raw[1] = 0;
        let mut meta_iface = zeroed_interface();
        meta_iface.id = 101;
        meta_iface.intf_type = MEDIA_INTF_T_V4L_VIDEO;
        meta_iface.raw[0] = 81;
        meta_iface.raw[1] = 1;

        let mut cap_link = zeroed_link();
        cap_link.source_id = 100;
        cap_link.sink_id = 1;
        cap_link.flags = MEDIA_LNK_FL_INTERFACE_LINK;
        let mut meta_link = zeroed_link();
        meta_link.source_id = 101;
        meta_link.sink_id = 4;
        meta_link.flags = MEDIA_LNK_FL_INTERFACE_LINK;
        // A DATA link whose ids could shadow the lookup if the type mask
        // were tested as a bit instead of compared: source 100 like the
        // capture interface's id.
        let mut data_link = zeroed_link();
        data_link.source_id = 100;
        data_link.sink_id = 9;
        data_link.flags = 0; // MEDIA_LNK_FL_DATA_LINK is the zero value

        let mut cap_pad = zeroed_pad();
        cap_pad.entity_id = 1;

        (
            vec![cap_iface, meta_iface],
            vec![data_link, cap_link, meta_link],
            vec![cap_pad],
        )
    }

    /// The decision over the measured shape: the padded, linked entity's
    /// node is capture; the padless entity's node is not; a node absent
    /// from the graph is no answer at all, never a guess.
    #[test]
    fn capture_metadata_and_absent_nodes_answer_differently() {
        let (interfaces, links, pads) = measured_shape();
        assert_eq!(
            node_is_capture_in(&interfaces, &links, &pads, 81, 0),
            Some(true),
            "the capture node's entity owns a pad"
        );
        assert_eq!(
            node_is_capture_in(&interfaces, &links, &pads, 81, 1),
            Some(false),
            "the metadata node's entity is padless"
        );
        assert_eq!(
            node_is_capture_in(&interfaces, &links, &pads, 81, 7),
            None,
            "a node this graph does not know is not this graph's to classify"
        );
    }

    /// A link of any other kind that reuses an interface's id number must
    /// not satisfy the interface-link lookup. DATA_LINK is the ZERO value of
    /// the type nibble, and a hypothetical future kind with the nibble at 3
    /// shares a bit with INTERFACE_LINK, so only mask-and-compare separates
    /// the kinds; a bit test passes the data-link case by accident and the
    /// future-kind case not at all, which is the mutant this test kills.
    #[test]
    fn only_an_exact_interface_link_answers_the_lookup() {
        let (interfaces, mut links, pads) = measured_shape();
        // Remove the real interface link; the shadowing data link stays, and
        // a link of a future kind (type nibble 3, sharing bit 28) joins it.
        links.retain(|l| {
            l.flags & MEDIA_LNK_FL_LINK_TYPE != MEDIA_LNK_FL_INTERFACE_LINK || l.source_id != 100
        });
        let mut future_kind = zeroed_link();
        future_kind.source_id = 100;
        future_kind.sink_id = 4; // the PADLESS entity: a false match flips the answer
        future_kind.flags = 3 << 28;
        links.push(future_kind);
        assert_eq!(
            node_is_capture_in(&interfaces, &links, &pads, 81, 0),
            None,
            "without its interface link the node has no entity; neither a \
             data link nor a future link kind sharing bit 28 may stand in"
        );
    }
}

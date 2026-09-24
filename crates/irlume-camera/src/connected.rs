// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright the irlume contributors.

//! Camera-free RGB+IR pairs over the passive inventory (ADR-0029 §1).
//!
//! A pair is one physical camera whose capture nodes all have a role at the
//! camera's current connection generation, exactly one RGB and one IR among
//! them. Roles come only from classifications discovery already ran; the
//! census's media graph read places metadata nodes without opening a video
//! node. Nothing here opens, classifies or reads sysfs.

use irlume_common::live_camera::{CameraInventoryReason, CameraInventoryState};

use crate::inventory::UsbDeviceFacts;
use crate::Role;

/// One connected physical camera with exactly one RGB and one IR capture
/// node, both classified at its current connection generation. The node
/// paths and `identity` are root-only facts: a daemon reply to a non-root
/// peer carries neither (ADR-0030 §4).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ConnectedPair {
    /// The RGB capture node.
    pub rgb: String,
    /// The IR capture node.
    pub ir: String,
    /// The binding identity both nodes share, `vid:pid[:serial]`
    /// lowercased, byte for byte what [`device_identity`](crate::device_identity)
    /// reports for either node. Read in the same census as the generation.
    /// The serial is device text: compare it raw, blank control characters
    /// before showing it (ADR-0029 §7), and never send it to a non-root
    /// peer (ADR-0030 §4).
    pub identity: String,
    /// `vid:pid`, lowercase hex.
    pub vid_pid: String,
    /// The descriptor carries a serial. Without one, units of the same model
    /// share `identity` and only the connection tells them apart.
    pub serial_present: bool,
    /// Built in (`removable=fixed`) rather than external.
    pub fixed: bool,
    /// The USB location (`<bus>-<port>[.<port>…]`), share-safe (ADR-0030
    /// §5); tells two connected units of one model apart.
    pub port_chain: Option<String>,
    /// The inventory's instance id for this unit; meaningful only with
    /// [`ConnectedPairs::supervisor_id`].
    pub instance_id: String,
    /// The connection generation within `instance_id`. It advances when the
    /// inventory re-proves the camera at the same USB path, after a `change`
    /// event or when a census reads different evidence there; a replug, a
    /// renumbered node, a re-enumeration or a lifecycle monitor failure
    /// retires the instance and gives a new `instance_id` altogether.
    pub generation: u64,
}

/// A connected camera with at least one capture node that has no role at
/// its current connection generation yet.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct UnclassifiedCamera {
    /// The inventory's instance id for this unit, as in [`ConnectedPair`].
    pub instance_id: String,
    /// The connection generation the missing roles belong to.
    pub generation: u64,
    /// The capture nodes without a role, sorted.
    pub endpoints: Vec<String>,
}

/// The camera-free pairing view of one inventory publication; see
/// [`connected_pairs`](crate::connected_pairs).
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct ConnectedPairs {
    /// The inventory's publication state. Only `Current` means the view is
    /// complete; `Refreshing` hides cameras whose continuity is being
    /// re-proven, and `Unavailable` and `Uninitialized` list nothing.
    pub state: CameraInventoryState,
    /// Why the inventory is unavailable, when it is.
    pub reason: Option<CameraInventoryReason>,
    /// The inventory incarnation; `None` before the first census.
    pub supervisor_id: Option<String>,
    /// The inventory publication revision, as in
    /// [`camera_inventory_snapshot`](crate::camera_inventory_snapshot).
    /// Recording a role does not advance it.
    pub revision: u64,
    /// In inventory order (USB topology path); never ranked.
    pub pairs: Vec<ConnectedPair>,
    /// Cameras that may still become pairs once their capture nodes are
    /// classified, in inventory order.
    pub unclassified: Vec<UnclassifiedCamera>,
}

/// One inventory entry as the pairing rule sees it.
pub(crate) struct PairingInput<'a> {
    pub(crate) topology_path: &'a str,
    pub(crate) serial: Option<&'a str>,
    pub(crate) usb_device: Option<&'a UsbDeviceFacts>,
    pub(crate) endpoints: &'a [String],
    pub(crate) metadata_endpoints: &'a [String],
    pub(crate) instance_id: &'a str,
    pub(crate) generation: u64,
}

#[derive(Debug, PartialEq, Eq)]
pub(crate) enum Pairing {
    Pair(ConnectedPair),
    Unclassified(UnclassifiedCamera),
    NotAPair,
}

/// The pairing rule of ADR-0029 §1 over one camera: its capture nodes are
/// its endpoints minus the metadata nodes; every one needs a role from
/// `role_of`, and exactly one RGB and one IR make a pair. Pure.
pub(crate) fn pair_camera(
    input: &PairingInput<'_>,
    role_of: impl Fn(&str) -> Option<Role>,
) -> Pairing {
    // Without USB descriptors a camera can never become a pair, so it is
    // not unclassified either.
    let Some(usb_device) = input.usb_device else {
        return Pairing::NotAPair;
    };
    let mut rgb = Vec::new();
    let mut ir = Vec::new();
    let mut unclassified = Vec::new();
    for endpoint in input
        .endpoints
        .iter()
        .filter(|endpoint| !input.metadata_endpoints.contains(*endpoint))
    {
        match role_of(endpoint) {
            Some(Role::Rgb) => rgb.push(endpoint.as_str()),
            Some(Role::Ir) => ir.push(endpoint.as_str()),
            Some(Role::Other) => {}
            None => unclassified.push(endpoint.clone()),
        }
    }
    // Before the role count: a camera is not a pair while a capture node
    // that might be a second IR node is still unknown.
    if !unclassified.is_empty() {
        unclassified.sort();
        return Pairing::Unclassified(UnclassifiedCamera {
            instance_id: input.instance_id.to_owned(),
            generation: input.generation,
            endpoints: unclassified,
        });
    }
    let ([rgb], [ir]) = (rgb.as_slice(), ir.as_slice()) else {
        return Pairing::NotAPair;
    };
    Pairing::Pair(ConnectedPair {
        rgb: (*rgb).to_owned(),
        ir: (*ir).to_owned(),
        identity: crate::binding_identity(usb_device.vid_pid(), input.serial),
        vid_pid: usb_device.vid_pid().to_lowercase(),
        serial_present: input.serial.is_some(),
        fixed: usb_device.fixed(),
        port_chain: crate::usb_port_chain(input.topology_path),
        instance_id: input.instance_id.to_owned(),
        generation: input.generation,
    })
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;

    use super::*;

    const TOPOLOGY: &str = "/devices/pci0000:00/0000:00:14.0/usb3/3-2";
    const INSTANCE: &str = "11111111111111111111111111111111";
    const GENERATION: u64 = 3;

    fn video(numbers: &[u32]) -> Vec<String> {
        numbers.iter().map(|n| format!("/dev/video{n}")).collect()
    }

    fn camera<'a>(
        usb_device: Option<&'a UsbDeviceFacts>,
        serial: Option<&'a str>,
        endpoints: &'a [String],
        metadata_endpoints: &'a [String],
    ) -> PairingInput<'a> {
        PairingInput {
            topology_path: TOPOLOGY,
            serial,
            usb_device,
            endpoints,
            metadata_endpoints,
            instance_id: INSTANCE,
            generation: GENERATION,
        }
    }

    fn roles(recorded: &[(&'static str, Role)]) -> impl Fn(&str) -> Option<Role> {
        let recorded: BTreeMap<&str, Role> = recorded.iter().copied().collect();
        move |endpoint| recorded.get(endpoint).copied()
    }

    fn unclassified(endpoints: &[u32]) -> Pairing {
        Pairing::Unclassified(UnclassifiedCamera {
            instance_id: INSTANCE.into(),
            generation: GENERATION,
            endpoints: video(endpoints),
        })
    }

    #[test]
    fn brio_four_node_layout_pairs_its_two_capture_nodes() {
        let brio = UsbDeviceFacts::new("046d:085e".into(), false);
        let (endpoints, metadata) = (video(&[0, 1, 2, 3]), video(&[1, 3]));
        let input = camera(Some(&brio), Some("ABC123"), &endpoints, &metadata);
        assert_eq!(
            pair_camera(
                &input,
                roles(&[("/dev/video0", Role::Rgb), ("/dev/video2", Role::Ir)])
            ),
            Pairing::Pair(ConnectedPair {
                rgb: "/dev/video0".into(),
                ir: "/dev/video2".into(),
                identity: "046d:085e:abc123".into(),
                vid_pid: "046d:085e".into(),
                serial_present: true,
                fixed: false,
                port_chain: Some("3-2".into()),
                instance_id: INSTANCE.into(),
                generation: GENERATION,
            })
        );
    }

    #[test]
    fn an_rgb_only_camera_is_not_a_pair() {
        let usb = UsbDeviceFacts::new("1111:2222".into(), false);
        let (endpoints, metadata) = (video(&[0, 1]), video(&[1]));
        let input = camera(Some(&usb), None, &endpoints, &metadata);
        assert_eq!(
            pair_camera(&input, roles(&[("/dev/video0", Role::Rgb)])),
            Pairing::NotAPair
        );
    }

    #[test]
    fn a_capture_node_without_a_role_leaves_the_camera_unclassified_not_paired() {
        let usb = UsbDeviceFacts::new("046d:085e".into(), false);
        let (endpoints, metadata) = (video(&[0, 1, 2, 3]), video(&[1, 3]));
        let input = camera(Some(&usb), None, &endpoints, &metadata);
        assert_eq!(
            pair_camera(&input, roles(&[("/dev/video0", Role::Rgb)])),
            unclassified(&[2])
        );
    }

    #[test]
    fn an_unclassified_capture_node_keeps_a_complete_pair_unclassified() {
        // The node without a role may be a second IR node.
        let usb = UsbDeviceFacts::new("046d:085e".into(), false);
        let endpoints = video(&[0, 2, 4]);
        let input = camera(Some(&usb), None, &endpoints, &[]);
        assert_eq!(
            pair_camera(
                &input,
                roles(&[("/dev/video0", Role::Rgb), ("/dev/video2", Role::Ir)])
            ),
            unclassified(&[4])
        );
    }

    #[test]
    fn two_capture_nodes_of_one_role_are_not_a_pair() {
        let usb = UsbDeviceFacts::new("1111:2222".into(), false);
        let endpoints = video(&[0, 2, 4]);
        let input = camera(Some(&usb), None, &endpoints, &[]);
        assert_eq!(
            pair_camera(
                &input,
                roles(&[
                    ("/dev/video0", Role::Rgb),
                    ("/dev/video2", Role::Rgb),
                    ("/dev/video4", Role::Ir),
                ])
            ),
            Pairing::NotAPair
        );
        assert_eq!(
            pair_camera(
                &input,
                roles(&[
                    ("/dev/video0", Role::Rgb),
                    ("/dev/video2", Role::Ir),
                    ("/dev/video4", Role::Ir),
                ])
            ),
            Pairing::NotAPair
        );
        // A capture node that is neither colour nor grey does not spoil a pair.
        let Pairing::Pair(pair) = pair_camera(
            &input,
            roles(&[
                ("/dev/video0", Role::Rgb),
                ("/dev/video2", Role::Ir),
                ("/dev/video4", Role::Other),
            ]),
        ) else {
            panic!("one RGB, one IR and one other capture node make a pair");
        };
        assert_eq!(
            (pair.rgb.as_str(), pair.ir.as_str()),
            ("/dev/video0", "/dev/video2")
        );
    }

    #[test]
    fn a_role_on_a_metadata_node_is_never_read() {
        let usb = UsbDeviceFacts::new("046d:085e".into(), false);
        let (endpoints, metadata) = (video(&[0, 1]), video(&[1]));
        let input = camera(Some(&usb), None, &endpoints, &metadata);
        assert_eq!(
            pair_camera(
                &input,
                roles(&[("/dev/video0", Role::Rgb), ("/dev/video1", Role::Ir)])
            ),
            Pairing::NotAPair
        );
    }

    #[test]
    fn a_node_the_media_graph_could_not_place_needs_a_role() {
        let usb = UsbDeviceFacts::new("046d:085e".into(), false);
        let endpoints = video(&[0, 1]);
        let input = camera(Some(&usb), None, &endpoints, &[]);
        assert_eq!(
            pair_camera(&input, roles(&[("/dev/video0", Role::Rgb)])),
            unclassified(&[1])
        );
    }

    #[test]
    fn a_camera_without_usb_descriptors_is_neither_paired_nor_unclassified() {
        let (endpoints, metadata) = (video(&[0, 1, 2, 3]), video(&[1, 3]));
        let input = camera(None, None, &endpoints, &metadata);
        assert_eq!(
            pair_camera(
                &input,
                roles(&[("/dev/video0", Role::Rgb), ("/dev/video2", Role::Ir)])
            ),
            Pairing::NotAPair
        );
        assert_eq!(pair_camera(&input, roles(&[])), Pairing::NotAPair);
    }

    #[test]
    fn pair_identity_is_the_binding_identity_of_its_descriptor() {
        let (endpoints, metadata) = (video(&[0, 1, 2, 3]), video(&[1, 3]));
        let classified = [("/dev/video0", Role::Rgb), ("/dev/video2", Role::Ir)];

        let module = UsbDeviceFacts::new("3277:0059".into(), true);
        let input = camera(Some(&module), None, &endpoints, &metadata);
        let Pairing::Pair(pair) = pair_camera(&input, roles(&classified)) else {
            panic!("a classified four-node camera is a pair");
        };
        assert_eq!(pair.identity, "3277:0059");
        assert!(!pair.serial_present);
        assert!(pair.fixed);

        let upper = UsbDeviceFacts::new("046D:085E".into(), false);
        let input = camera(Some(&upper), None, &endpoints, &metadata);
        let Pairing::Pair(pair) = pair_camera(&input, roles(&classified)) else {
            panic!("a classified four-node camera is a pair");
        };
        assert_eq!(pair.vid_pid, "046d:085e");
        assert_eq!(pair.identity, "046d:085e");
    }
}

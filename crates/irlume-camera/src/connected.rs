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
use crate::{Role, UsbLocation};

/// One side of a [`SplitPair`]: the capture node and the descriptor facts of
/// the USB device behind it. Both sides of a split pair are ordinary
/// single-camera observations, so this is the same shape
/// [`ConnectedPair`] carries, kept in one type so no field of one side can
/// be read as a field of the other.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CameraNode {
    /// This side's capture node. Root-only: a daemon reply to a non-root
    /// peer carries neither side's path (ADR-0030 §4).
    pub path: String,
    /// The binding identity of the device behind this node, as
    /// [`crate::binding_identity`] formats it. A split pair has no single
    /// identity, so each side keeps its own. Never sent to a non-root peer.
    pub identity: String,
    /// `vid:pid`, lowercase hex.
    pub vid_pid: String,
    /// This side's descriptor carries a serial. Without one, units of the
    /// same model share `identity` and only the connection tells them apart.
    pub serial_present: bool,
    /// This side is built in (`removable=fixed`) rather than external.
    /// Carried for display and selection ranking, not authorization: whether
    /// a side is built in changes what physical access a substitution needs,
    /// not whether the recorded facts can detect one, so `fixed` is never
    /// required to resolve (ADR-0032 §2).
    pub fixed: bool,
    /// The controller-qualified USB location (ADR-0032 §2): host controller
    /// plus relative port chain, share-safe (ADR-0030 §5).
    ///
    /// A plain [`UsbLocation`], never an `Option`: a split-pair side always
    /// has a location, because [`resolve_side`] refuses any side whose
    /// location is unrecorded or mismatched before a [`CameraNode`] is ever
    /// built. That makes "located" a type-level invariant instead of a
    /// runtime check, so [`SplitPair::binding_key`] has no fallback that
    /// could fold an unlocated side into a collision.
    pub location: UsbLocation,
    /// The inventory instance id for this side. A split pair spans two.
    pub instance_id: String,
    /// This side's generation within its `instance_id`. The two sides
    /// advance independently: a replug of either retires only that side.
    pub generation: u64,
}

/// A user-pinned RGB+IR pair whose two nodes are on **two different USB
/// devices** — the ThinkPad T480's Bison IR (`5986:1141`) and SunplusIT RGB
/// (`5986:2113`) modules, on separate ports of `0000:00:14.0` (ADR-0032).
///
/// This is deliberately a *separate type* from [`ConnectedPair`], which
/// stays one physical camera (ADR-0029 §1). Every invariant that rests on
/// that — the lease's per-instance key, `camera_binding`'s pair identity,
/// the secondary-camera store, ADR-0030 §4 redaction — holds unchanged for
/// `ConnectedPair`, because nothing implicit ever produces this: a split
/// pair exists only where an administrator pinned it. The daemon's baseline
/// trust in "one USB device is one camera" is physics; crossing a device
/// boundary is a mandate, and a mandate is recorded, not inferred.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SplitPair {
    /// The RGB side, on its own USB device.
    pub rgb: CameraNode,
    /// The IR side, on its own USB device.
    pub ir: CameraNode,
    /// The inventory incarnation both sides were published under. A pair
    /// spanning two incarnations is a republication race, not a pair, so
    /// the builder only ever fills this from one publication.
    pub supervisor_id: String,
}

impl SplitPair {
    /// A stable key for this pair: the RGB half first, then the IR half,
    /// each an identity plus its controller-qualified location, NUL-separated
    /// throughout.
    ///
    /// The key is **role-labelled, not a set**. Discovery order must not
    /// matter, so the builder assigns each side by role rather than by
    /// enumeration order, and the key follows the roles: `RGB=A, IR=B` and
    /// `RGB=B, IR=A` are different pairs, because a pair authorizes a
    /// complete role-labelled pair (ADR-0024 §2), not two devices. Swapping
    /// which side is RGB therefore changes the key.
    ///
    /// The NUL separators close two independent ambiguities, and the reason
    /// they can is stated precisely: NUL never appears *in these values*,
    /// because they arrive as kernel sysfs text, which carries no NUL bytes.
    /// (UTF-16 as an encoding can represent U+0000; what excludes it here is
    /// the transport, not the encoding.) The daemon already leans on the same
    /// property where it domain-separates a hash with `b"irlume-attempt-unit\0"`.
    ///
    /// * a serial may itself contain `:`, so `("a:b", "c")` and `("a", "b:c")`
    ///   fold together under a naive join;
    /// * a serial-less module shares its `identity` with every other unit of
    ///   its model, so two genuinely different pairs would still share a key
    ///   built from identities alone. Identity therefore names *which model*;
    ///   the controller-qualified location names *which location*.
    ///
    /// This key binds a credential to descriptor identity plus USB location
    /// and role. It does not prove the same physical unit returned: a
    /// replacement unit with the same descriptor identity, plugged into the
    /// same controller port and assigned the same node path, satisfies every
    /// recorded fact and is indistinguishable (ADR-0032 §2).
    pub fn binding_key(&self) -> String {
        // No fallback: both halves always carry a real location
        // (`CameraNode::location` is total), so there is no empty component
        // to collide.
        format!(
            "{}\0{}\0{}\0{}",
            self.rgb.identity,
            self.rgb.location.key_string(),
            self.ir.identity,
            self.ir.location.key_string()
        )
    }
}

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
    /// Pairs whose two nodes are on two different USB devices, in pin order:
    /// the first pin that claims a camera keeps it, so position is the
    /// administrator's priority. Empty unless an administrator pinned each
    /// one (ADR-0032); discovery alone never fills it, so the default
    /// publication is exactly the single-camera view of `pairs`.
    ///
    /// A camera listed in `pairs` never also appears here: a same-device
    /// RGB+IR pair is a [`ConnectedPair`] and stays one.
    pub split_pairs: Vec<SplitPair>,
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

use std::collections::BTreeSet;

/// An administrator's recorded intent to pair two named capture nodes that
/// discovery found on two different USB devices (ADR-0032). The values are
/// what `set-cameras` persists; nothing else in the daemon may create one.
///
/// Each side is anchored to **identity, path and USB location** together,
/// because no one of them suffices. `/dev/videoN` is renumbered across boots,
/// so the path alone is a hint the administrator typed; identity alone is
/// shared by every serial-less unit of a model. Together they still admit a
/// silent retarget: two serial-less units of one model, pinned when the unit
/// on one port held `/dev/video2`, can come back with the unit on another
/// port holding `/dev/video2` — identity and path both still match, and
/// neither is the unit that was pinned. The recorded controller-qualified
/// location is what makes the pin name a USB location rather than a model.
/// It does not prove the same physical unit returned; see ADR-0032 §2 for
/// the stated boundary.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SplitPin {
    /// The binding identity of the RGB side, as
    /// [`crate::binding_identity`] formats it: `vid:pid[:serial]`.
    pub rgb_identity: String,
    /// The node path the pin named for the RGB side.
    pub rgb_path: String,
    /// The controller-qualified USB location the RGB side was on when the
    /// pin was written. **Required, and matched, not merely recorded**
    /// (ADR-0032 §2): a side with no readable location is refused, because
    /// identity alone names a model rather than a unit and an unrecorded
    /// location would let two interchangeable same-model units swap node
    /// names behind the pin.
    pub rgb_location: Option<UsbLocation>,
    /// The binding identity of the IR side.
    pub ir_identity: String,
    /// The node path the pin named for the IR side.
    pub ir_path: String,
    /// The controller-qualified USB location the IR side was on when the pin
    /// was written, required and matched as for `rgb_location`.
    pub ir_location: Option<UsbLocation>,
}

/// One side of a candidate split pair, as the builder sees it: the same
/// facts [`pair_camera`] reads, already classified.
#[derive(Clone)]
pub(crate) struct SplitCandidate<'a> {
    pub(crate) input: &'a PairingInput<'a>,
    /// The inventory incarnation this camera was published under.
    pub(crate) supervisor_id: &'a str,
    /// Every capture node of this camera and the role each holds at this
    /// camera's current generation, already filtered of metadata nodes.
    pub(crate) roles: Vec<(&'a str, Role)>,
}

impl<'a> SplitCandidate<'a> {
    /// This camera's binding identity, as the pairing rule would report it,
    /// or the empty string when its device carries no descriptors — which
    /// is also how a candidate fails to match a pin.
    pub(crate) fn identity(&self) -> String {
        self.input
            .usb_device
            .map(|usb| crate::binding_identity(usb.vid_pid(), self.input.serial))
            .unwrap_or_default()
    }

    /// This camera's controller-qualified USB location, or `None` when its
    /// topology path yields no readable controller or port chain. Two units
    /// of one serial-less model share an identity and are told apart only
    /// by this.
    pub(crate) fn location(&self) -> Option<UsbLocation> {
        crate::usb_controller_location(self.input.topology_path)
    }

    /// This camera as a [`CameraNode`] for the recorded path and the
    /// verified location. Both come from a successful [`resolve_side`]:
    /// the path is the pin's recorded one and the location is the one just
    /// matched, so what was verified is what is built, and a later change
    /// to [`Self::identity`] or [`Self::location`] cannot silently diverge
    /// from what the resolver compared. Taking the location as a
    /// [`UsbLocation`] (rather than re-reading an `Option`) is what keeps
    /// [`CameraNode::location`] total: there is no fallback to forget.
    pub(crate) fn node(&self, path: &str, location: UsbLocation) -> CameraNode {
        CameraNode {
            path: path.to_owned(),
            identity: self.identity(),
            vid_pid: self
                .input
                .usb_device
                .map_or("", |usb| usb.vid_pid())
                .to_lowercase(),
            serial_present: self.input.serial.is_some(),
            fixed: self.input.usb_device.is_some_and(UsbDeviceFacts::fixed),
            location,
            instance_id: self.input.instance_id.to_owned(),
            generation: self.input.generation,
        }
    }

    /// Build a candidate from an inventory entry and its current-generation
    /// roles. The capture-node filter is exactly [`pair_camera`]'s —
    /// endpoints minus metadata nodes — so the two views of "what is a
    /// capture node" cannot drift; Step 3 calls this instead of hand-filling
    /// `roles`. A capture node without a role makes the whole candidate
    /// `None`, mirroring `pair_camera`'s unclassified rule: an unknown node
    /// might be a second node of the wanted role, and a pin must not resolve
    /// while that is open.
    #[cfg_attr(
        not(test),
        expect(
            dead_code,
            reason = "no production caller until ADR-0032 step 3 wires pins into publication"
        )
    )]
    pub(crate) fn classified(
        input: &'a PairingInput<'a>,
        supervisor_id: &'a str,
        role_of: impl Fn(&str) -> Option<Role>,
    ) -> Option<Self> {
        let mut roles = Vec::new();
        for endpoint in input
            .endpoints
            .iter()
            .filter(|endpoint| !input.metadata_endpoints.contains(*endpoint))
        {
            roles.push((endpoint.as_str(), role_of(endpoint.as_str())?));
        }
        Some(Self {
            input,
            supervisor_id,
            roles,
        })
    }
}

/// The split pairs an administrator's pins authorize, one outcome per pin,
/// in pin order.
///
/// The pin is the authorization, so **no pin means no split pair**: the
/// default publication is exactly the single-camera view of
/// [`ConnectedPairs::pairs`], which is what a host with a split camera and
/// no `set-cameras` still sees (#887). A pin is honored only when every one
/// of these holds:
///
/// * both sides are live capture nodes published under the **same**
///   `supervisor_id` — spanning two incarnations is a republication race,
///   not a pair;
/// * each side's device carries USB descriptors, so both are
///   descriptor-attested as ADR-0031 requires;
/// * the RGB side holds exactly one `Role::Rgb` node, the IR side exactly
///   one `Role::Ir`, and neither holds the opposite role, so a camera that
///   is already an ordinary [`ConnectedPair`] is never also half of a split
///   pair;
/// * the two sides are **different instances** — a same-device pair is an
///   ordinary [`ConnectedPair`] and must not be duplicated here;
/// * the pin's recorded path for each side still names a capture node of
///   that side, so a stale `/dev/videoN` cannot silently retarget the pin
///   onto a node the administrator never chose;
/// * each side carries a recorded controller-qualified USB location that the
///   candidate currently reports unchanged (ADR-0032 §2). Absent on either
///   side, that side is refused rather than resolved against whichever unit
///   happens to hold the recorded node name.
///
/// Two sides that share an `identity` and a location are refused as the
/// same unit observed twice; identical modules on different ports are
/// distinguished by location (ADR-0030 §5), and two pin entries that
/// cannot be told apart are not paired at all.
///
/// A camera is claimed by the first pair that uses it: pins are honored in
/// pin order, and a later pin reusing either side of a pair already built is
/// refused with the earlier pin implied — not just an identical duplicate,
/// which two pins for `RGB A + IR B` would be, but any overlap: pins for
/// `RGB A + IR B` and `RGB A + IR C` would otherwise hand A to two pairs
/// and leave the enrollment binding unable to say which pair a credential
/// belongs to. Pin order is the administrator's priority order, so the first
/// pin wins rather than both being refused.
///
/// Every refusal names its rule in the returned [`PinOutcome`], because an
/// empty list after a reboot is undiagnosable: the administrator needs to
/// know whether the path was renumbered, the port moved, or a stray
/// candidate from another incarnation suppressed every pin.
///
/// This builder is where a [`SplitPair`] is *decided*. It says nothing about
/// whether the pair is still live — that is the lease's re-check, against both
/// sides' `instance_id` and `generation`.
#[cfg_attr(
    not(test),
    expect(
        dead_code,
        reason = "no production caller until ADR-0032 step 3 wires pins into publication"
    )
)]
pub(crate) fn pinned_split_pairs(
    candidates: &[SplitCandidate<'_>],
    pins: &[SplitPin],
) -> Vec<PinOutcome> {
    // The pool must be one publication before any pin is considered: a pool
    // bridging two inventory incarnations is an inventory bug, and honoring
    // a pin across that gap would pair a camera with a republication of
    // itself. Checked once for the whole pool rather than per pin, since
    // this is a property of the inventory and not of any one pin.
    match pool_state(candidates) {
        PoolState::Singular => {}
        PoolState::Empty => {
            return pins
                .iter()
                .map(|_| PinOutcome::Refused(PinRefusal::PoolEmpty))
                .collect();
        }
        PoolState::SpansIncarnations => {
            return pins
                .iter()
                .map(|_| PinOutcome::Refused(PinRefusal::PoolSpansIncarnations))
                .collect();
        }
    }
    // Every camera already committed to a pair. A camera is one physical unit
    // and cannot be half of two pairs; see the doc above for why the first
    // pin wins.
    let mut claimed: BTreeSet<&str> = BTreeSet::new();
    let mut outcomes = Vec::with_capacity(pins.len());
    for pin in pins {
        outcomes.push(resolve_pin(candidates, pin, &mut claimed));
    }
    outcomes
}

/// What one pin resolved to. Step 3 publishes the `Paired` halves and reports
/// the `Refused` reasons; until then, tests match on these to prove *which*
/// rule fired, which an empty list could never do.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum PinOutcome {
    /// Boxed: a `SplitPair` holds two full `CameraNode`s, an order of
    /// magnitude larger than any refusal, and outcomes travel in a `Vec`.
    Paired(Box<SplitPair>),
    Refused(PinRefusal),
}

impl PinOutcome {
    /// The authorized pair, if this pin resolved to one. Step 3 publishes
    /// through this; until then only tests call it.
    #[cfg_attr(
        not(test),
        expect(
            dead_code,
            reason = "no production caller until ADR-0032 step 3 wires pins into publication"
        )
    )]
    pub(crate) fn paired(&self) -> Option<&SplitPair> {
        match self {
            Self::Paired(pair) => Some(pair),
            Self::Refused(_) => None,
        }
    }
}

/// Why a pin was not honored. Every rule in [`pinned_split_pairs`] that can
/// refuse has a variant, so "my pin stopped working" names the rule instead
/// of an empty list.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum PinRefusal {
    /// The pool holds no candidates at all: a healthy camera-free inventory,
    /// not an error, but nothing for any pin to resolve against.
    PoolEmpty,
    /// The pool spans more than one inventory incarnation. Pairing across a
    /// republication would pair a camera with a republication of itself, so
    /// every pin is refused, including pins that name only the homogeneous
    /// majority.
    PoolSpansIncarnations,
    /// The RGB side did not resolve, for the recorded reason. Sides resolve
    /// in role order — RGB first, then IR — so a pin whose both sides are
    /// broken reports only the RGB refusal on this run; fixing it surfaces
    /// the IR refusal on the next. One failure at a time is the deliberate
    /// tradeoff for a first cut: reporting both would need the IR lookup to
    /// run against a pool the RGB side already failed, which answers a
    /// question Step 3 never asks.
    RgbSide(SideRefusal),
    /// The IR side did not resolve, for the recorded reason. Reported only
    /// when the RGB side resolved; see `RgbSide` for why the order is fixed.
    IrSide(SideRefusal),
    /// Both sides resolved to one instance: an ordinary `ConnectedPair`,
    /// which must not also be listed as a split one. A backstop for pool
    /// construction handing two entries for one camera; a same-device pair
    /// whose roles are both classified is normally refused earlier, by
    /// `OppositeRole` on each side.
    SameDevice,
    /// The resolved sides share an identity and a controller-qualified
    /// location: one ambiguous unit observed twice, not two sides.
    SameUnitTwice,
    /// Either side is already half of a pair an earlier pin built. The
    /// outcome's position names the losing pin; the earlier pin keeps its
    /// pair.
    SideAlreadyClaimed,
}

/// Why one side of a pin did not resolve. `.max()` in `resolve_side` uses
/// the derived `Ord`, ranked by declaration order below — reordering this
/// list changes which reason a pin reports when several candidates fail
/// differently. `AmbiguousMatch` is never passed to `.max()` (it is
/// returned directly when more than one full match is found), so its
/// position here does not affect resolution.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub(crate) enum SideRefusal {
    /// The pin's own identity string is empty. Checked before the
    /// candidate loop runs at all; the loop's own fallback default
    /// (`NoCandidateWithIdentity`) can never produce this variant.
    EmptyIdentity,
    /// The pin's identity is non-empty, but no currently-connected
    /// candidate reports it — including a descriptor-less camera, which
    /// always reports the empty identity and so can never equal a
    /// non-empty pin identity. Says only that nothing matched right now:
    /// it does not distinguish a typo in the pin from hardware that is
    /// simply not connected.
    NoCandidateWithIdentity,
    /// No same-identity candidate holds exactly one node of the wanted role:
    /// none does, or one holds two. A pin cannot say which node of two it
    /// meant.
    RoleAmbiguous,
    /// A same-identity candidate holds the opposite attested role. Checked
    /// before role ambiguity in `resolve_side`, so this fires even on a
    /// candidate whose wanted-role assignment would also have been
    /// ambiguous — it says only that an opposite-role node exists, not
    /// that the wanted role itself resolved cleanly.
    OppositeRole,
    /// The role resolves, but the recorded path names no node of that role:
    /// the node was renumbered, or the pin never named this unit. This is
    /// the re-anchor signal for Step 3: distinct from "unit absent", and
    /// repaired by recording the new path rather than by re-enrolling.
    PathMismatch,
    /// Identity, path and role resolve, but the recorded location does not:
    /// the unit moved ports, or the side was never locatable. An unrecorded
    /// location on either side authorizes nothing (ADR-0032 §2).
    LocationMismatch,
    /// Two or more indistinguishable full matches: same identity, path, role
    /// and controller-qualified location on distinct entries. Returned
    /// directly by `resolve_side`, never through `best.max(...)` —
    /// refusing to guess which of two identical observations the pin meant.
    AmbiguousMatch,
}

/// Whether the candidate pool is one publication. The incarnation itself is
/// not carried: both sides of any pair built from the pool share it (checked
/// by the caller), so resolving sides read it off their own candidate rather
/// than off the pool verdict.
enum PoolState {
    /// Every candidate was published under one incarnation.
    Singular,
    /// No candidates at all.
    Empty,
    /// Candidates from more than one incarnation.
    SpansIncarnations,
}

/// Classify the pool once, so the per-pin loop never re-derives it.
fn pool_state(candidates: &[SplitCandidate<'_>]) -> PoolState {
    if candidates.is_empty() {
        return PoolState::Empty;
    }
    let first = candidates[0].supervisor_id;
    if candidates
        .iter()
        .all(|candidate| candidate.supervisor_id == first)
    {
        PoolState::Singular
    } else {
        PoolState::SpansIncarnations
    }
}

/// One side of a pin, resolved: the candidate plus the controller-qualified
/// USB location that matched. The location is the verified value — `Some` on
/// both pin and candidate and equal — captured at match time, so downstream
/// code never re-derives an `Option` it would have to default.
struct ResolvedSide<'a, 'b> {
    candidate: &'b SplitCandidate<'a>,
    location: UsbLocation,
}

/// Resolve one pin against a homogeneous pool, claiming its sides on success.
/// Every refusal path returns the rule that fired.
fn resolve_pin<'a, 'b>(
    candidates: &'b [SplitCandidate<'a>],
    pin: &SplitPin,
    claimed: &mut BTreeSet<&'b str>,
) -> PinOutcome {
    let rgb = match resolve_side(
        candidates,
        &pin.rgb_identity,
        &pin.rgb_path,
        &pin.rgb_location,
        Role::Rgb,
    ) {
        Ok(side) => side,
        Err(reason) => return PinOutcome::Refused(PinRefusal::RgbSide(reason)),
    };
    let ir = match resolve_side(
        candidates,
        &pin.ir_identity,
        &pin.ir_path,
        &pin.ir_location,
        Role::Ir,
    ) {
        Ok(side) => side,
        Err(reason) => return PinOutcome::Refused(PinRefusal::IrSide(reason)),
    };
    // A same-device pair is an ordinary ConnectedPair; do not also list
    // it as a split one. Normally unreachable — see `PinRefusal::SameDevice`
    // — because each side would already have refused on `OppositeRole`.
    if rgb.candidate.input.instance_id == ir.candidate.input.instance_id {
        return PinOutcome::Refused(PinRefusal::SameDevice);
    }
    // Same unit seen twice is one ambiguous unit, not a split pair.
    if same_unit(rgb.candidate, ir.candidate) {
        return PinOutcome::Refused(PinRefusal::SameUnitTwice);
    }
    if [
        rgb.candidate.input.instance_id,
        ir.candidate.input.instance_id,
    ]
    .iter()
    .any(|instance| claimed.contains(instance))
    {
        return PinOutcome::Refused(PinRefusal::SideAlreadyClaimed);
    }
    claimed.extend([
        rgb.candidate.input.instance_id,
        ir.candidate.input.instance_id,
    ]);
    // Both sides were resolved out of one homogeneous pool (checked by the
    // caller), so either side's incarnation is the pool's.
    PinOutcome::Paired(Box::new(SplitPair {
        rgb: rgb.candidate.node(&pin.rgb_path, rgb.location),
        ir: ir.candidate.node(&pin.ir_path, ir.location),
        supervisor_id: rgb.candidate.supervisor_id.to_owned(),
    }))
}

/// Resolve one side of a pin: the candidate with this identity whose single
/// node of `role` is the recorded path at the recorded controller-qualified
/// location. On failure, the furthest progress wins, so the reason names the
/// closest the pin came: an unknown identity never gets as far as a path
/// check.
///
/// A pin side is never `Role::Other`: only attested capture roles can be
/// halves of a pair.
fn resolve_side<'a, 'b>(
    candidates: &'b [SplitCandidate<'a>],
    identity: &str,
    path: &str,
    location: &Option<UsbLocation>,
    role: Role,
) -> Result<ResolvedSide<'a, 'b>, SideRefusal> {
    // A pin identity is never empty — `binding_identity` always yields at
    // least `vid:pid` — and a camera with no USB descriptors reports the
    // empty identity, so requiring a non-blank identity is what enforces
    // descriptor attestation (ADR-0031 §1): a descriptor-less camera can
    // never satisfy a pin, because it can never match a real one.
    if identity.is_empty() {
        return Err(SideRefusal::EmptyIdentity);
    }
    let opposite = match role {
        Role::Rgb => Role::Ir,
        Role::Ir => Role::Rgb,
        Role::Other => return Err(SideRefusal::RoleAmbiguous),
    };
    // A controller-qualified location is required on both sides and must be
    // equal (ADR-0032 §2); see `SideRefusal::LocationMismatch` for why an
    // absent location never matches. The bus number plays no part: it is not
    // stored in [`UsbLocation`] at all, so a renumbering cannot mismatch.
    let recorded = location.as_ref();
    let mut full_matches = Vec::new();
    let mut best = SideRefusal::NoCandidateWithIdentity;
    for candidate in candidates
        .iter()
        .filter(|c| c.input.usb_device.is_some() && c.identity() == identity)
    {
        let role_nodes: Vec<_> = candidate
            .roles
            .iter()
            .filter(|(_, held)| *held == role)
            .collect();
        if candidate.roles.iter().any(|(_, held)| *held == opposite) {
            best = best.max(SideRefusal::OppositeRole);
            continue;
        }
        if role_nodes.len() != 1 {
            best = best.max(SideRefusal::RoleAmbiguous);
            continue;
        }
        if role_nodes[0].0 != path {
            best = best.max(SideRefusal::PathMismatch);
            continue;
        }
        match (recorded, candidate.location().as_ref()) {
            (Some(recorded), Some(current)) if recorded == current => {
                full_matches.push((candidate, recorded.clone()));
            }
            _ => {
                best = best.max(SideRefusal::LocationMismatch);
            }
        }
    }
    match full_matches.as_slice() {
        [(candidate, location)] => Ok(ResolvedSide {
            candidate,
            location: location.clone(),
        }),
        [] => Err(best),
        _ => Err(SideRefusal::AmbiguousMatch),
    }
}

/// Whether two resolved sides are one ambiguous unit observed twice: same
/// descriptor identity on the same controller-qualified location, however
/// different their instance ids are. No physical topology produces this; it
/// is the census disagreeing with itself.
fn same_unit(a: &SplitCandidate<'_>, b: &SplitCandidate<'_>) -> bool {
    a.identity() == b.identity() && a.location() == b.location()
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

#[cfg(test)]
mod split_pair {
    use std::sync::OnceLock;

    use super::*;
    use crate::RootHubDomain;

    const RGB_INSTANCE: &str = "22222222222222222222222222222222";
    const IR_INSTANCE: &str = "33333333333333333333333333333333";
    const SUPERVISOR: &str = "aaaa";
    const RGB_USB: &str = "5986:2113";
    const IR_USB: &str = "5986:1141";
    const SERIAL: &str = "200901010001";
    const CONTROLLER: &str = "0000:00:14.0";

    fn loc(controller: &str, domain: RootHubDomain, ports: &[u8]) -> UsbLocation {
        UsbLocation {
            controller: controller.into(),
            domain,
            ports: ports.to_vec(),
        }
    }

    /// Hub product files for every topology path the fixtures use, so
    /// `SplitCandidate::location()` resolves through `hostfs::sys_root`
    /// exactly as on hardware. Held for the test body; thread-local like all
    /// hostfs fixtures, so parallel tests do not interfere. Covers the T480
    /// controller's USB2 and SuperSpeed hubs, the second controller from the
    /// cross-controller test, and one hub with an unrecognized product.
    fn usb_hubs() -> crate::hostfs::test::FixtureGuard {
        crate::hostfs::test::fixture_with(|_, sys| {
            let hub = |controller: &str, hub: &str, product: &str| {
                let dir = sys.join(
                    ["devices", "pci0000:00", controller, hub]
                        .iter()
                        .collect::<std::path::PathBuf>(),
                );
                std::fs::create_dir_all(&dir).unwrap();
                std::fs::write(dir.join("idProduct"), product).unwrap();
            };
            hub("0000:00:14.0", "usb1", "0002");
            hub("0000:00:14.0", "usb2", "0003");
            hub("0000:00:14.0", "usb3", "0002");
            hub("0000:0d:00.3", "usb1", "0002");
            hub("0000:00:1a.0", "usb1", "0009");
        })
    }

    /// One module's capture nodes and its metadata nodes; the census reads
    /// both for the T480's two modules and `PairingInput` borrows them, so
    /// they live in a `OnceLock` for the whole test run.
    type Nodes = (Vec<String>, Vec<String>, Vec<String>, Vec<String>);

    /// The T480's two modules as the census sees them: RGB `5986:2113` on
    /// port 8 and IR `5986:1141` on port 5, both under the one xHCI
    /// controller `0000:00:14.0`. One capture node and one metadata node
    /// each. Returns borrowed statics so the returned inputs outlive the
    /// call.
    fn t480() -> (PairingInput<'static>, PairingInput<'static>) {
        static USB: OnceLock<(UsbDeviceFacts, UsbDeviceFacts)> = OnceLock::new();
        static ENDPOINTS: OnceLock<Nodes> = OnceLock::new();
        let (rgb_usb, ir_usb) = USB.get_or_init(|| {
            (
                UsbDeviceFacts::new(RGB_USB.into(), true),
                UsbDeviceFacts::new(IR_USB.into(), true),
            )
        });
        let (rgb, rgb_meta, ir, ir_meta) = ENDPOINTS.get_or_init(|| {
            (
                vec!["/dev/video2".to_owned(), "/dev/video3".to_owned()],
                vec!["/dev/video3".to_owned()],
                vec!["/dev/video0".to_owned(), "/dev/video1".to_owned()],
                vec!["/dev/video1".to_owned()],
            )
        });
        (
            PairingInput {
                topology_path: "/devices/pci0000:00/0000:00:14.0/usb1/1-8",
                serial: Some(SERIAL),
                usb_device: Some(rgb_usb),
                endpoints: rgb,
                metadata_endpoints: rgb_meta,
                instance_id: RGB_INSTANCE,
                generation: 3,
            },
            PairingInput {
                topology_path: "/devices/pci0000:00/0000:00:14.0/usb1/1-5",
                serial: Some(SERIAL),
                usb_device: Some(ir_usb),
                endpoints: ir,
                metadata_endpoints: ir_meta,
                instance_id: IR_INSTANCE,
                generation: 3,
            },
        )
    }

    fn candidates<'a>(
        rgb: &'a PairingInput<'a>,
        ir: &'a PairingInput<'a>,
    ) -> Vec<SplitCandidate<'a>> {
        vec![
            SplitCandidate {
                input: rgb,
                supervisor_id: SUPERVISOR,
                roles: vec![("/dev/video2", Role::Rgb)],
            },
            SplitCandidate {
                input: ir,
                supervisor_id: SUPERVISOR,
                roles: vec![("/dev/video0", Role::Ir)],
            },
        ]
    }

    fn pin() -> SplitPin {
        SplitPin {
            rgb_identity: "5986:2113:200901010001".into(),
            rgb_path: "/dev/video2".into(),
            rgb_location: Some(loc(CONTROLLER, RootHubDomain::Usb2, &[8])),
            ir_identity: "5986:1141:200901010001".into(),
            ir_path: "/dev/video0".into(),
            ir_location: Some(loc(CONTROLLER, RootHubDomain::Usb2, &[5])),
        }
    }

    /// The pairs the outcomes authorized, in pin order. Goes through
    /// [`PinOutcome::paired`], so this helper also proves the accessor Step 3
    /// will publish through.
    fn paired(outcomes: &[PinOutcome]) -> Vec<&SplitPair> {
        outcomes.iter().filter_map(PinOutcome::paired).collect()
    }

    /// The baseline the whole design rests on: with a pin that names the
    /// two sides, each side is still a camera of its own and neither
    /// becomes a `ConnectedPair`. `pair_camera` is the ordinary rule and is
    /// exercised above; here the point is that a pinned split pair is the
    /// *only* thing that spans the two devices.
    #[test]
    fn the_t480_pair_is_never_a_connected_pair() {
        let _hubs = usb_hubs();
        let (rgb, ir) = t480();
        for input in [&rgb, &ir] {
            // Classified, but each module holds only one role: a connected
            // pair needs one RGB *and* one IR, so neither module is one.
            let one_role = |endpoint: &str| match endpoint {
                "/dev/video2" => Some(Role::Rgb),
                "/dev/video0" => Some(Role::Ir),
                _ => Some(Role::Other),
            };
            assert_eq!(
                pair_camera(input, one_role),
                Pairing::NotAPair,
                "a camera with only one of the two roles is not a pair"
            );
        }
        let candidates = candidates(&rgb, &ir);
        assert_eq!(
            pinned_split_pairs(&candidates, &[pin()]),
            vec![PinOutcome::Paired(Box::new(SplitPair {
                rgb: CameraNode {
                    path: "/dev/video2".into(),
                    identity: "5986:2113:200901010001".into(),
                    vid_pid: "5986:2113".into(),
                    serial_present: true,
                    fixed: true,
                    location: loc(CONTROLLER, RootHubDomain::Usb2, &[8]),
                    instance_id: RGB_INSTANCE.into(),
                    generation: 3,
                },
                ir: CameraNode {
                    path: "/dev/video0".into(),
                    identity: "5986:1141:200901010001".into(),
                    vid_pid: "5986:1141".into(),
                    serial_present: true,
                    fixed: true,
                    location: loc(CONTROLLER, RootHubDomain::Usb2, &[5]),
                    instance_id: IR_INSTANCE.into(),
                    generation: 3,
                },
                supervisor_id: SUPERVISOR.into(),
            }))]
        );
    }

    /// The default publication: no pin, no split pair. This is the property
    /// #887's reporter depends on — a host with a split camera and no
    /// `set-cameras` still gets the safe single-camera view.
    #[test]
    fn no_pin_means_no_split_pair() {
        let _hubs = usb_hubs();
        let (rgb, ir) = t480();
        assert!(pinned_split_pairs(&candidates(&rgb, &ir), &[]).is_empty());
    }

    /// A pin naming an identity that is not connected authorizes nothing,
    /// and the outcome names the missing IR side rather than an empty list.
    #[test]
    fn a_pin_for_an_absent_camera_is_not_honored() {
        let _hubs = usb_hubs();
        let (rgb, ir) = t480();
        let mut absent = pin();
        absent.ir_identity = "5986:2222:deadbeef".into();
        assert_eq!(
            pinned_split_pairs(&candidates(&rgb, &ir), &[absent]),
            vec![PinOutcome::Refused(PinRefusal::IrSide(
                SideRefusal::NoCandidateWithIdentity
            ))],
        );
    }

    /// The sides advance generations independently, so a split pair keeps
    /// both. A replug of one side must not move the other's generation, and
    /// the two sides are two distinct cameras.
    #[test]
    fn the_two_sides_carry_their_own_generation() {
        let _hubs = usb_hubs();
        let (rgb, ir) = t480();
        // The IR module was replugged: its generation advances alone.
        let ir = PairingInput {
            generation: 9,
            ..ir
        };
        let outcomes = pinned_split_pairs(&candidates(&rgb, &ir), &[pin()]);
        let [PinOutcome::Paired(pair)] = outcomes.as_slice() else {
            panic!("a pinned pair resolves");
        };
        assert_eq!(
            (pair.rgb.generation, pair.ir.generation),
            (3, 9),
            "a replug of one side must not move the other's generation"
        );
        assert_ne!(
            pair.rgb.instance_id, pair.ir.instance_id,
            "the two sides are two distinct cameras"
        );
    }

    /// An unclassified side has no role, so there is nothing to attest and
    /// the pin is not honored. The camera still shows as `unclassified`
    /// through the ordinary path.
    #[test]
    fn an_unclassified_side_is_not_paired_across_devices() {
        let _hubs = usb_hubs();
        let (rgb, ir) = t480();
        let candidates = vec![
            SplitCandidate {
                input: &rgb,
                supervisor_id: SUPERVISOR,
                roles: vec![("/dev/video2", Role::Rgb)],
            },
            SplitCandidate {
                input: &ir,
                supervisor_id: SUPERVISOR,
                // The IR node has no role at its current generation yet.
                roles: vec![],
            },
        ];
        assert_eq!(
            pinned_split_pairs(&candidates, &[pin()]),
            vec![PinOutcome::Refused(PinRefusal::IrSide(
                SideRefusal::RoleAmbiguous
            ))],
            "an IR side with no classified node refuses on RoleAmbiguous"
        );
    }

    /// A camera with two nodes of the pinned role is ambiguous: a pin
    /// cannot say which it meant, so guessing is refused.
    #[test]
    fn an_ambiguous_side_is_not_paired() {
        let _hubs = usb_hubs();
        let (rgb, ir) = t480();
        static TWO_RGB_NODES: OnceLock<Vec<String>> = OnceLock::new();
        let two_rgb_nodes = TWO_RGB_NODES.get_or_init(|| {
            vec![
                "/dev/video2".to_owned(),
                "/dev/video4".to_owned(),
                "/dev/video3".to_owned(),
            ]
        });
        let rgb = PairingInput {
            endpoints: two_rgb_nodes,
            metadata_endpoints: &["/dev/video3".to_owned()],
            ..rgb
        };
        let candidates = vec![
            SplitCandidate {
                input: &rgb,
                supervisor_id: SUPERVISOR,
                roles: vec![("/dev/video2", Role::Rgb), ("/dev/video4", Role::Rgb)],
            },
            SplitCandidate {
                input: &ir,
                supervisor_id: SUPERVISOR,
                roles: vec![("/dev/video0", Role::Ir)],
            },
        ];
        assert_eq!(
            pinned_split_pairs(&candidates, &[pin()]),
            vec![PinOutcome::Refused(PinRefusal::RgbSide(
                SideRefusal::RoleAmbiguous
            ))],
            "two nodes of the pinned role refuse on RoleAmbiguous"
        );
    }

    /// Two nodes of one device are an ordinary `ConnectedPair`; the pin
    /// must not produce a second, overlapping representation of it. The
    /// realistic shape is one candidate holding both roles, as a real
    /// same-device RGB+IR module does — not two devices sharing an instance
    /// id, which the inventory never produces.
    #[test]
    fn a_same_device_pair_is_never_also_a_split_pair() {
        let _hubs = usb_hubs();
        let (rgb, ir) = t480();
        // A single module with one RGB and one IR capture node. `pair_camera`
        // pairs it, which proves the fixture is genuinely a ConnectedPair
        // shape and not a degenerate input.
        static BOTH_NODES: OnceLock<Vec<String>> = OnceLock::new();
        let both_nodes =
            BOTH_NODES.get_or_init(|| vec!["/dev/video2".to_owned(), "/dev/video3".to_owned()]);
        let module = PairingInput {
            endpoints: both_nodes,
            metadata_endpoints: &[],
            ..rgb
        };
        let both_roles = |endpoint: &str| match endpoint {
            "/dev/video2" => Some(Role::Rgb),
            "/dev/video3" => Some(Role::Ir),
            _ => Some(Role::Other),
        };
        assert!(
            matches!(pair_camera(&module, both_roles), Pairing::Pair(_)),
            "one RGB plus one IR node is an ordinary pair"
        );
        // A pin naming that RGB node together with another device's IR node
        // must not draft the module's RGB half into a split pair.
        let pool = vec![
            SplitCandidate {
                input: &module,
                supervisor_id: SUPERVISOR,
                roles: vec![("/dev/video2", Role::Rgb), ("/dev/video3", Role::Ir)],
            },
            SplitCandidate {
                input: &ir,
                supervisor_id: SUPERVISOR,
                roles: vec![("/dev/video0", Role::Ir)],
            },
        ];
        assert_eq!(
            pinned_split_pairs(&pool, &[pin()]),
            vec![PinOutcome::Refused(PinRefusal::RgbSide(
                SideRefusal::OppositeRole
            ))],
            "a camera that already holds both roles is not a split side"
        );
    }

    /// Spanning two inventory incarnations is a republication race, not a
    /// pair, even when the pin names both sides exactly. Refusing the whole
    /// pool is a property of the inventory, so it is decided before any pin
    /// is read: one non-homogeneous candidate suppresses every pin.
    #[test]
    fn two_inventory_incarnations_do_not_make_a_pair() {
        let _hubs = usb_hubs();
        let (rgb, ir) = t480();
        let candidates = vec![
            SplitCandidate {
                input: &rgb,
                supervisor_id: SUPERVISOR,
                roles: vec![("/dev/video2", Role::Rgb)],
            },
            SplitCandidate {
                input: &ir,
                supervisor_id: "bbbb",
                roles: vec![("/dev/video0", Role::Ir)],
            },
        ];
        assert_eq!(
            pinned_split_pairs(&candidates, &[pin()]),
            vec![PinOutcome::Refused(PinRefusal::PoolSpansIncarnations)],
            "a non-homogeneous pool refuses before any pin is read"
        );
        // A pool with a completable pair under one incarnation plus one stray
        // candidate under another still refuses everything: the pool-wide
        // check fires before any pin is read, so even the pair that would
        // otherwise resolve is suppressed. Without the pool check, this pin
        // would pair across the republication gap.
        let with_stray = vec![
            SplitCandidate {
                input: &rgb,
                supervisor_id: SUPERVISOR,
                roles: vec![("/dev/video2", Role::Rgb)],
            },
            SplitCandidate {
                input: &ir,
                supervisor_id: SUPERVISOR,
                roles: vec![("/dev/video0", Role::Ir)],
            },
            SplitCandidate {
                input: &rgb,
                supervisor_id: "bbbb",
                roles: vec![("/dev/video2", Role::Rgb)],
            },
        ];
        assert_eq!(
            pinned_split_pairs(&with_stray, &[pin()]),
            vec![PinOutcome::Refused(PinRefusal::PoolSpansIncarnations)],
            "one stray candidate from another incarnation suppresses every pin"
        );
    }

    /// An empty pool is a healthy camera-free inventory, not a reason to
    /// panic or to look harder. Each pin still gets an outcome, so callers
    /// can tell "no cameras" from "cameras that did not match".
    #[test]
    fn an_empty_pool_yields_no_split_pair() {
        let _hubs = usb_hubs();
        assert_eq!(
            pinned_split_pairs(&[], &[pin()]),
            vec![PinOutcome::Refused(PinRefusal::PoolEmpty)],
        );
    }

    /// A stale `/dev/videoN` in a pin cannot retarget it: the path must
    /// still name a capture node of the pinned identity and role. This is
    /// the re-anchor signal for Step 3, distinct from "unit absent".
    #[test]
    fn a_renumbered_node_does_not_honor_a_stale_path() {
        let _hubs = usb_hubs();
        let (rgb, ir) = t480();
        let mut stale = pin();
        stale.ir_path = "/dev/video9".into();
        assert_eq!(
            pinned_split_pairs(&candidates(&rgb, &ir), &[stale]),
            vec![PinOutcome::Refused(PinRefusal::IrSide(
                SideRefusal::PathMismatch
            ))],
            "a pin whose path is gone must wait for identity re-anchoring"
        );
    }

    /// The binding key is role-labelled and collision-free where plain
    /// concatenation is not: a serial may contain `:`, so `a:b`+`c` and
    /// `a`+`b:c` fold together under a naive join.
    #[test]
    fn the_binding_key_does_not_fold_two_serials_into_one() {
        // Two distinct instances, as a real split pair has. Ports are real
        // locations here; what this test isolates is the identity component,
        // and location separation has its own test below.
        let side = |identity: &str, instance_id: &str| CameraNode {
            path: "/dev/video0".into(),
            identity: identity.into(),
            vid_pid: "5986:1141".into(),
            serial_present: true,
            fixed: true,
            location: loc(CONTROLLER, RootHubDomain::Usb2, &[5]),
            instance_id: instance_id.into(),
            generation: 1,
        };
        let one = SplitPair {
            rgb: side("a:b", RGB_INSTANCE),
            ir: side("c", IR_INSTANCE),
            supervisor_id: SUPERVISOR.into(),
        };
        let two = SplitPair {
            rgb: side("a", RGB_INSTANCE),
            ir: side("b:c", IR_INSTANCE),
            supervisor_id: SUPERVISOR.into(),
        };
        assert_ne!(one.binding_key(), two.binding_key());
        assert_eq!(one.binding_key(), one.binding_key());
        assert!(!one.binding_key().contains("a:b:c"));
        // Role-labelled: moving the two halves into each other's role is a
        // different key, because the key follows the roles and not the two
        // devices as an unordered set.
        let swapped = SplitPair {
            rgb: one.ir.clone(),
            ir: one.rgb.clone(),
            supervisor_id: SUPERVISOR.into(),
        };
        assert_ne!(one.binding_key(), swapped.binding_key());
    }

    /// One unresolvable pin does not stop another: pins are honored
    /// independently, in pin order.
    #[test]
    fn one_bad_pin_does_not_hide_a_good_one() {
        let _hubs = usb_hubs();
        let (rgb, ir) = t480();
        let mut bad = pin();
        bad.rgb_identity = "5986:0000:0000".into();
        let outcomes = pinned_split_pairs(&candidates(&rgb, &ir), &[bad, pin()]);
        assert_eq!(outcomes.len(), 2, "one outcome per pin, refused or paired");
        assert_eq!(
            outcomes[0],
            PinOutcome::Refused(PinRefusal::RgbSide(SideRefusal::NoCandidateWithIdentity)),
            "the bad pin names the rule it broke"
        );
        let [_, PinOutcome::Paired(pair)] = outcomes.as_slice() else {
            panic!("the good pin is still authorized");
        };
        assert_eq!(pair.ir.path, "/dev/video0");
    }

    /// A camera is one physical unit and cannot be half of two pairs. Pins
    /// for `RGB A + IR B` and `RGB A + IR C` overlap on A; the first wins and
    /// the second is refused, so no enrollment binding is ever ambiguous
    /// about which pair a credential belongs to.
    #[test]
    fn one_camera_cannot_be_half_of_two_split_pairs() {
        let _hubs = usb_hubs();
        let (rgb, ir) = t480();
        static USB: OnceLock<UsbDeviceFacts> = OnceLock::new();
        static SECOND_IR_NODES: OnceLock<Vec<String>> = OnceLock::new();
        let other_ir_usb = USB.get_or_init(|| UsbDeviceFacts::new(IR_USB.into(), true));
        let second_ir_nodes = SECOND_IR_NODES.get_or_init(|| vec!["/dev/video6".to_owned()]);
        let other_ir = PairingInput {
            topology_path: "/devices/pci0000:00/0000:00:14.0/usb1/1-9",
            serial: Some("200901010002"),
            usb_device: Some(other_ir_usb),
            endpoints: second_ir_nodes,
            metadata_endpoints: &[],
            instance_id: "44444444444444444444444444444444",
            generation: 3,
        };
        let pool = vec![
            SplitCandidate {
                input: &rgb,
                supervisor_id: SUPERVISOR,
                roles: vec![("/dev/video2", Role::Rgb)],
            },
            SplitCandidate {
                input: &ir,
                supervisor_id: SUPERVISOR,
                roles: vec![("/dev/video0", Role::Ir)],
            },
            SplitCandidate {
                input: &other_ir,
                supervisor_id: SUPERVISOR,
                roles: vec![("/dev/video6", Role::Ir)],
            },
        ];
        let second = SplitPin {
            rgb_identity: "5986:2113:200901010001".into(),
            rgb_path: "/dev/video2".into(),
            rgb_location: Some(loc(CONTROLLER, RootHubDomain::Usb2, &[8])),
            ir_identity: "5986:1141:200901010002".into(),
            ir_path: "/dev/video6".into(),
            ir_location: Some(loc(CONTROLLER, RootHubDomain::Usb2, &[9])),
        };
        // Either order: the overlapping pin loses, the first one wins, and
        // the loser names SideAlreadyClaimed rather than vanishing.
        let outcomes = pinned_split_pairs(&pool, &[pin(), second.clone()]);
        let [PinOutcome::Paired(first), PinOutcome::Refused(PinRefusal::SideAlreadyClaimed)] =
            outcomes.as_slice()
        else {
            panic!("first pin pairs, overlapping second is refused: {outcomes:?}");
        };
        assert_eq!(first.ir.path, "/dev/video0");
        let outcomes = pinned_split_pairs(&pool, &[second, pin()]);
        let [PinOutcome::Paired(first), PinOutcome::Refused(PinRefusal::SideAlreadyClaimed)] =
            outcomes.as_slice()
        else {
            panic!("first pin still wins when listed first: {outcomes:?}");
        };
        assert_eq!(first.ir.path, "/dev/video6");
    }

    /// Two serial-less RGB modules of one model, each paired with a
    /// serial-less IR module of another, are two real pairs on different
    /// controller ports. Their identities alone are identical, so the key has
    /// to carry the USB location too or one credential would resolve to the
    /// wrong hardware.
    #[test]
    fn the_binding_key_separates_two_serial_less_pairs_on_different_ports() {
        let side = |identity: &str, controller: &str, domain: RootHubDomain, port: u8| CameraNode {
            path: format!("/dev/video{port}"),
            identity: identity.into(),
            vid_pid: identity.into(),
            // No serial: units of one model share the identity.
            serial_present: false,
            fixed: true,
            location: loc(controller, domain, &[port]),
            instance_id: "55555555555555555555555555555555".into(),
            generation: 1,
        };
        let one = SplitPair {
            rgb: side("5986:2113", CONTROLLER, RootHubDomain::Usb2, 8),
            ir: side("5986:1141", CONTROLLER, RootHubDomain::Usb2, 5),
            supervisor_id: SUPERVISOR.into(),
        };
        let two = SplitPair {
            rgb: side("5986:2113", CONTROLLER, RootHubDomain::Usb2, 9),
            ir: side("5986:1141", CONTROLLER, RootHubDomain::Usb2, 6),
            supervisor_id: SUPERVISOR.into(),
        };
        assert_ne!(
            one.binding_key(),
            two.binding_key(),
            "two physical pairs of the same models must not share a key"
        );
        // Role-labelled: moving the two halves into each other's role is a
        // different key, because the key follows the roles and not the two
        // devices as an unordered set.
        let swapped = SplitPair {
            rgb: two.ir.clone(),
            ir: two.rgb.clone(),
            supervisor_id: SUPERVISOR.into(),
        };
        assert_ne!(swapped.rgb.path, two.rgb.path, "the halves really moved");
        assert_ne!(
            two.binding_key(),
            swapped.binding_key(),
            "RGB=A, IR=B and RGB=B, IR=A are different authorizations"
        );
    }

    /// Descriptor attestation is a documented condition of a split pair, so
    /// a camera the census could not read descriptors for can never be
    /// attested into one — not even by a pin whose identity is empty, which is
    /// what such a camera reports.
    #[test]
    fn a_descriptor_less_camera_is_never_attested_into_a_split_pair() {
        let _hubs = usb_hubs();
        static NODES: OnceLock<Vec<String>> = OnceLock::new();
        static RGB_NODES: OnceLock<Vec<String>> = OnceLock::new();
        static RGB_USB_FACTS: OnceLock<UsbDeviceFacts> = OnceLock::new();
        let nodes = NODES.get_or_init(|| vec!["/dev/video0".to_owned()]);
        // The IR module is present but its USB device dir carries no
        // descriptors, so it has no identity to pin.
        let descriptor_less = PairingInput {
            topology_path: "/devices/pci0000:00/0000:00:14.0/usb1/1-5",
            serial: None,
            usb_device: None,
            endpoints: nodes,
            metadata_endpoints: &[],
            instance_id: IR_INSTANCE,
            generation: 3,
        };
        let rgb_endpoints = RGB_NODES.get_or_init(|| vec!["/dev/video2".to_owned()]);
        let rgb_usb = RGB_USB_FACTS.get_or_init(|| UsbDeviceFacts::new(RGB_USB.into(), true));
        let rgb = PairingInput {
            topology_path: "/devices/pci0000:00/0000:00:14.0/usb1/1-8",
            serial: Some(SERIAL),
            usb_device: Some(rgb_usb),
            endpoints: rgb_endpoints,
            metadata_endpoints: &[],
            instance_id: RGB_INSTANCE,
            generation: 3,
        };
        let pool = vec![
            SplitCandidate {
                input: &rgb,
                supervisor_id: SUPERVISOR,
                roles: vec![("/dev/video2", Role::Rgb)],
            },
            SplitCandidate {
                input: &descriptor_less,
                supervisor_id: SUPERVISOR,
                roles: vec![("/dev/video0", Role::Ir)],
            },
        ];
        // A pin naming the empty identity is what a descriptor-less camera
        // would have to be matched by, and it must not be honored.
        let empty = SplitPin {
            rgb_identity: "5986:2113:200901010001".into(),
            rgb_path: "/dev/video2".into(),
            rgb_location: Some(loc(CONTROLLER, RootHubDomain::Usb2, &[8])),
            ir_identity: String::new(),
            ir_path: "/dev/video0".into(),
            ir_location: Some(loc(CONTROLLER, RootHubDomain::Usb2, &[5])),
        };
        assert_eq!(
            pinned_split_pairs(&pool, &[empty]),
            vec![PinOutcome::Refused(PinRefusal::IrSide(
                SideRefusal::EmptyIdentity
            ))],
            "an empty pin identity can never match a camera"
        );
        // And a well-formed pin does not rescue it either.
        assert_eq!(
            pinned_split_pairs(&pool, &[pin()]),
            vec![PinOutcome::Refused(PinRefusal::IrSide(
                SideRefusal::NoCandidateWithIdentity
            ))],
            "a descriptor-less camera reports no identity to match"
        );
    }

    /// `EmptyIdentity` and `NoCandidateWithIdentity` are genuinely different
    /// refusals: an empty pin identity fails before any candidate is
    /// examined, while a non-empty but unmatched identity fails only after
    /// the candidate loop finds nothing. Exercises `resolve_side` directly
    /// rather than through `pinned_split_pairs`, so the two variants are
    /// checked at the point they are actually produced.
    #[test]
    fn resolve_side_distinguishes_empty_identity_from_no_match() {
        let _hubs = usb_hubs();
        let (rgb, _ir) = t480();
        let pool = vec![SplitCandidate {
            input: &rgb,
            supervisor_id: SUPERVISOR,
            roles: vec![("/dev/video2", Role::Rgb)],
        }];
        assert_eq!(
            resolve_side(
                &pool,
                "",
                "/dev/video2",
                &Some(loc(CONTROLLER, RootHubDomain::Usb2, &[8])),
                Role::Rgb
            )
            .map(|_| ())
            .unwrap_err(),
            SideRefusal::EmptyIdentity,
            "an empty pin identity fails before the candidate loop runs"
        );
        assert_eq!(
            resolve_side(
                &pool,
                "5986:0000:0000", // non-empty; resolve_side checks emptiness only, not format
                "/dev/video2",
                &Some(loc(CONTROLLER, RootHubDomain::Usb2, &[8])),
                Role::Rgb
            )
            .map(|_| ())
            .unwrap_err(),
            SideRefusal::NoCandidateWithIdentity,
            "a non-empty identity matching nothing fails in the loop, not before it"
        );
    }

    /// A pin must name a physical unit, not a model. Two serial-less units of
    /// one model are told apart by controller-qualified location alone, and
    /// `/dev/videoN` is renumbered across boots: pinned while the unit on
    /// port 8 held `/dev/video2`, the same pin can afterwards find
    /// `/dev/video2` sitting on the unit at port 9, with identity and node
    /// path both still matching. The recorded location is what stops that
    /// retarget, so the pair is refused rather than silently moved onto
    /// hardware the administrator never chose.
    #[test]
    fn a_pin_does_not_follow_a_renumbered_node_to_another_unit() {
        let _hubs = usb_hubs();
        let (_, ir) = t480();
        static USB: OnceLock<UsbDeviceFacts> = OnceLock::new();
        static IR_USB_FACTS: OnceLock<UsbDeviceFacts> = OnceLock::new();
        static PINNED_NODES: OnceLock<Vec<String>> = OnceLock::new();
        static OTHER_NODES: OnceLock<Vec<String>> = OnceLock::new();
        let usb = USB.get_or_init(|| UsbDeviceFacts::new(RGB_USB.into(), true));
        // The IR module keeps its own port; only the two RGB units collide.
        let ir = PairingInput {
            topology_path: "/devices/pci0000:00/0000:00:14.0/usb1/1-5",
            usb_device: Some(IR_USB_FACTS.get_or_init(|| UsbDeviceFacts::new(IR_USB.into(), true))),
            ..ir
        };
        // Before the reboot: the pinned unit is on port 8 with /dev/video2.
        // After it: port 8 holds /dev/video5 and port 9 holds /dev/video2.
        // Both are serial-less, so both report the same identity.
        let pinned_unit = PairingInput {
            topology_path: "/devices/pci0000:00/0000:00:14.0/usb1/1-8",
            serial: None,
            usb_device: Some(usb),
            endpoints: PINNED_NODES.get_or_init(|| vec!["/dev/video5".to_owned()]),
            metadata_endpoints: &[],
            instance_id: RGB_INSTANCE,
            generation: 3,
        };
        let other_unit = PairingInput {
            topology_path: "/devices/pci0000:00/0000:00:14.0/usb1/1-9",
            serial: None,
            usb_device: Some(usb),
            endpoints: OTHER_NODES.get_or_init(|| vec!["/dev/video2".to_owned()]),
            metadata_endpoints: &[],
            instance_id: "44444444444444444444444444444444",
            generation: 3,
        };
        // The other unit is listed first, so a match that ignored the
        // location would find it first and win.
        let pool = vec![
            SplitCandidate {
                input: &other_unit,
                supervisor_id: SUPERVISOR,
                roles: vec![("/dev/video2", Role::Rgb)],
            },
            SplitCandidate {
                input: &pinned_unit,
                supervisor_id: SUPERVISOR,
                roles: vec![("/dev/video5", Role::Rgb)],
            },
            SplitCandidate {
                input: &ir,
                supervisor_id: SUPERVISOR,
                roles: vec![("/dev/video0", Role::Ir)],
            },
        ];
        // The pin as written before the reboot.
        let before = SplitPin {
            rgb_identity: RGB_USB.into(),
            rgb_path: "/dev/video2".into(),
            rgb_location: Some(loc(CONTROLLER, RootHubDomain::Usb2, &[8])),
            ir_identity: "5986:1141:200901010001".into(),
            ir_path: "/dev/video0".into(),
            ir_location: Some(loc(CONTROLLER, RootHubDomain::Usb2, &[5])),
        };
        // After the renumbering the pinned unit is nowhere near the recorded
        // node, so no pair is authorized. Critically, it is NOT resolved onto
        // the unit at port 9 that inherited /dev/video2.
        assert_eq!(
            pinned_split_pairs(&pool, &[before.clone()]),
            vec![PinOutcome::Refused(PinRefusal::RgbSide(
                SideRefusal::LocationMismatch
            ))],
            "a pin must not follow its node name onto a different unit"
        );
        // Repointed at where the pinned unit actually is, it resolves to that
        // unit and not to the one that took its old node name.
        let repointed = SplitPin {
            rgb_path: "/dev/video5".into(),
            ..before
        };
        let outcomes = pinned_split_pairs(&pool, &[repointed]);
        let [PinOutcome::Paired(pair)] = outcomes.as_slice() else {
            panic!("repointed pin resolves: {outcomes:?}");
        };
        assert_eq!(
            (pair.rgb.location.clone(), pair.rgb.path.as_str()),
            (loc(CONTROLLER, RootHubDomain::Usb2, &[8]), "/dev/video5"),
            "the pin resolves to the unit at the location it recorded"
        );
    }

    /// A pin that recorded no location for a side refuses that side outright
    /// (ADR-0032 §2). An unrecorded location is not a wildcard for any
    /// location: pairing an unlocatable unit with whichever unit happens to
    /// hold the recorded node name would be a retarget with no way to notice
    /// it, so the side must be re-pinned once its location is known.
    #[test]
    fn a_pin_with_no_recorded_location_refuses_a_located_unit() {
        let _hubs = usb_hubs();
        let (rgb, ir) = t480();
        let mut unlocated = pin();
        unlocated.rgb_location = None;
        assert_eq!(
            pinned_split_pairs(&candidates(&rgb, &ir), &[unlocated]),
            vec![PinOutcome::Refused(PinRefusal::RgbSide(
                SideRefusal::LocationMismatch
            ))],
            "an unrecorded location is not a wildcard for any location"
        );
    }

    /// Two same-model, serial-less units that *both* report no readable USB
    /// location are interchangeable as far as identity and node path go, so
    /// an absent location must not count as agreement (ADR-0032 §2). The IR
    /// side here is locatable, so the pair can complete: the test turns on
    /// whether the RGB side resolves, and it must not resolve onto whichever
    /// unit holds the recorded node name.
    #[test]
    fn two_unlocated_same_model_units_are_not_interchangeable() {
        let _hubs = usb_hubs();
        let (_, ir) = t480();
        static USB: OnceLock<UsbDeviceFacts> = OnceLock::new();
        static NODES: OnceLock<(Vec<String>, Vec<String>)> = OnceLock::new();
        let usb = USB.get_or_init(|| UsbDeviceFacts::new(RGB_USB.into(), true));
        // Neither topology path ends in `<bus>-<port>` under a PCI parent,
        // so neither RGB unit has a location. Both are serial-less, so both
        // report `vid:pid` and nothing more: nothing but the node name tells
        // them apart.
        let (first_nodes, second_nodes) = NODES.get_or_init(|| {
            (
                vec!["/dev/video2".to_owned()],
                vec!["/dev/video7".to_owned()],
            )
        });
        let first = PairingInput {
            topology_path: "/devices/platform/soc/fea00000.usb",
            serial: None,
            usb_device: Some(usb),
            endpoints: first_nodes,
            metadata_endpoints: &[],
            instance_id: RGB_INSTANCE,
            generation: 3,
        };
        let second = PairingInput {
            topology_path: "/devices/platform/soc/feb00000.usb",
            serial: None,
            usb_device: Some(usb),
            endpoints: second_nodes,
            metadata_endpoints: &[],
            instance_id: "44444444444444444444444444444444",
            generation: 3,
        };
        let locatable = |input: &PairingInput<'static>| {
            SplitCandidate {
                input,
                supervisor_id: SUPERVISOR,
                roles: vec![],
            }
            .location()
            .is_some()
        };
        assert_eq!(
            (locatable(&first), locatable(&second), locatable(&ir)),
            (false, false, true),
            "neither RGB unit has a readable location; the IR side does"
        );
        // The pin as written while `first` held /dev/video2. Its RGB location
        // was never readable, so the pin cannot name which unit it meant.
        let before = SplitPin {
            rgb_identity: RGB_USB.into(),
            rgb_path: "/dev/video2".into(),
            rgb_location: None,
            ir_identity: "5986:1141:200901010001".into(),
            ir_path: "/dev/video0".into(),
            ir_location: Some(loc(CONTROLLER, RootHubDomain::Usb2, &[5])),
        };
        let pool = || {
            vec![
                SplitCandidate {
                    input: &first,
                    supervisor_id: SUPERVISOR,
                    roles: vec![("/dev/video2", Role::Rgb)],
                },
                SplitCandidate {
                    input: &second,
                    supervisor_id: SUPERVISOR,
                    roles: vec![("/dev/video7", Role::Rgb)],
                },
                SplitCandidate {
                    input: &ir,
                    supervisor_id: SUPERVISOR,
                    roles: vec![("/dev/video0", Role::Ir)],
                },
            ]
        };
        // The IR side is locatable and would match, so anything that stops
        // the pair here stopped it on the RGB side's unrecorded location.
        assert_eq!(
            pinned_split_pairs(&pool(), &[before.clone()]),
            vec![PinOutcome::Refused(PinRefusal::RgbSide(
                SideRefusal::LocationMismatch
            ))],
            "a side with no recorded location is refused, not resolved against \
             whichever unit holds the recorded node name"
        );
        // Swapping the node assignments changes nothing about that answer: a
        // pin that cannot say which unit it meant must not start saying so
        // because the names moved.
        let swapped = SplitPin {
            rgb_path: "/dev/video7".into(),
            ..before
        };
        assert_eq!(
            pinned_split_pairs(&pool(), &[swapped]),
            vec![PinOutcome::Refused(PinRefusal::RgbSide(
                SideRefusal::LocationMismatch
            ))],
            "the refusal is about the missing location, not the node name"
        );
    }

    /// Enumeration order is not part of the pair. The builder assigns each
    /// side by role rather than by position, so the same pin over the same
    /// candidates in either order builds the same pair with the same key.
    /// What matters is which side is RGB — see the role test above — and not
    /// which the census happened to list first.
    #[test]
    fn pool_enumeration_order_does_not_change_the_pair_key() {
        let _hubs = usb_hubs();
        let (rgb, ir) = t480();
        let forward = candidates(&rgb, &ir);
        let backward = vec![forward[1].clone(), forward[0].clone()];
        // `paired()` is the accessor Step 3 will publish through, so this
        // test goes through it rather than destructuring.
        let forward_outcomes = pinned_split_pairs(&forward, &[pin()]);
        let backward_outcomes = pinned_split_pairs(&backward, &[pin()]);
        let (forward_pairs, backward_pairs) =
            (paired(&forward_outcomes), paired(&backward_outcomes));
        let ([forward_pair], [backward_pair]) =
            (forward_pairs.as_slice(), backward_pairs.as_slice())
        else {
            panic!("the same pin resolves under either enumeration order");
        };
        assert_eq!(
            (
                forward_pair.rgb.path.as_str(),
                forward_pair.ir.path.as_str()
            ),
            ("/dev/video2", "/dev/video0"),
            "the builder assigns sides by role, not by position"
        );
        assert_eq!(
            forward_pair.binding_key(),
            backward_pair.binding_key(),
            "the same physical pair has the same key however it was listed"
        );
    }

    /// A replacement unit that presents every recorded fact of the unit it
    /// replaced — same descriptor identity, same controller port, same node
    /// path — is indistinguishable by anything a pin may record (ADR-0032
    /// §2). The pin still resolves, because the recorded facts still match:
    /// this test pins the actual guarantee (descriptor identity plus USB
    /// location and node) rather than the impossible one (same physical
    /// unit). A different instance id is the only thing that changed, and
    /// instance ids are not part of what a pin names.
    #[test]
    fn a_replacement_unit_with_the_same_recorded_facts_is_not_detected() {
        let _hubs = usb_hubs();
        let (rgb, ir) = t480();
        let pool = candidates(&rgb, &ir);
        let replacement = PairingInput {
            instance_id: "99999999999999999999999999999999",
            generation: 1,
            ..rgb
        };
        let replacement_pool = vec![
            SplitCandidate {
                input: &replacement,
                supervisor_id: SUPERVISOR,
                roles: vec![("/dev/video2", Role::Rgb)],
            },
            pool[1].clone(),
        ];
        let outcomes = pinned_split_pairs(&replacement_pool, &[pin()]);
        let [PinOutcome::Paired(pair)] = outcomes.as_slice() else {
            panic!("a unit presenting every recorded fact resolves, replacement or not");
        };
        assert_eq!(pair.rgb.instance_id, "99999999999999999999999999999999");
    }

    /// One serial-less unit observed as two inventory entries — same identity,
    /// same controller-qualified location, distinct instances — is one
    /// ambiguous unit, not two sides of a pair. The entries hold complementary
    /// roles, so each side resolves on its own and only the `same_unit` guard
    /// sees that the two halves cannot be told apart. No physical topology
    /// produces this; it is the census disagreeing with itself.
    #[test]
    fn one_unit_observed_twice_is_not_a_split_pair() {
        let _hubs = usb_hubs();
        static USB: OnceLock<UsbDeviceFacts> = OnceLock::new();
        static NODES: OnceLock<(Vec<String>, Vec<String>)> = OnceLock::new();
        let usb = USB.get_or_init(|| UsbDeviceFacts::new("5986:2222".into(), true));
        let (rgb_nodes, ir_nodes) = NODES.get_or_init(|| {
            (
                vec!["/dev/video2".to_owned()],
                vec!["/dev/video3".to_owned()],
            )
        });
        // One serial-less module on port 8 of the T480 controller, seen as
        // two entries with distinct instances: the first holds the RGB node,
        // the second the IR node.
        let first = PairingInput {
            topology_path: "/devices/pci0000:00/0000:00:14.0/usb1/1-8",
            serial: None,
            usb_device: Some(usb),
            endpoints: rgb_nodes,
            metadata_endpoints: &[],
            instance_id: RGB_INSTANCE,
            generation: 3,
        };
        let second = PairingInput {
            topology_path: "/devices/pci0000:00/0000:00:14.0/usb1/1-8",
            serial: None,
            usb_device: Some(usb),
            endpoints: ir_nodes,
            metadata_endpoints: &[],
            instance_id: "44444444444444444444444444444444",
            generation: 3,
        };
        let pool = vec![
            SplitCandidate {
                input: &first,
                supervisor_id: SUPERVISOR,
                roles: vec![("/dev/video2", Role::Rgb)],
            },
            SplitCandidate {
                input: &second,
                supervisor_id: SUPERVISOR,
                roles: vec![("/dev/video3", Role::Ir)],
            },
        ];
        let pin = SplitPin {
            rgb_identity: "5986:2222".into(),
            rgb_path: "/dev/video2".into(),
            rgb_location: Some(loc(CONTROLLER, RootHubDomain::Usb2, &[8])),
            ir_identity: "5986:2222".into(),
            ir_path: "/dev/video3".into(),
            ir_location: Some(loc(CONTROLLER, RootHubDomain::Usb2, &[8])),
        };
        assert_eq!(
            pinned_split_pairs(&pool, &[pin]),
            vec![PinOutcome::Refused(PinRefusal::SameUnitTwice)],
            "identical identity and location on two instances is one unit, not a pair"
        );
    }

    /// Two entries that match a side indistinguishably — same identity, path,
    /// role and controller-qualified location on distinct instances — refuse
    /// rather than let the resolver take the first. `find` would silently
    /// pick one; exactly-one is the consistent rule alongside `sole_node`'s
    /// refusal to guess which of two nodes a pin meant.
    #[test]
    fn two_indistinguishable_matches_for_one_side_are_not_guessed() {
        let _hubs = usb_hubs();
        let (rgb, ir) = t480();
        let mirror = PairingInput {
            instance_id: "44444444444444444444444444444444",
            generation: 9,
            ..rgb
        };
        let pool = vec![
            SplitCandidate {
                input: &rgb,
                supervisor_id: SUPERVISOR,
                roles: vec![("/dev/video2", Role::Rgb)],
            },
            SplitCandidate {
                input: &mirror,
                supervisor_id: SUPERVISOR,
                roles: vec![("/dev/video2", Role::Rgb)],
            },
            SplitCandidate {
                input: &ir,
                supervisor_id: SUPERVISOR,
                roles: vec![("/dev/video0", Role::Ir)],
            },
        ];
        assert_eq!(
            pinned_split_pairs(&pool, &[pin()]),
            vec![PinOutcome::Refused(PinRefusal::RgbSide(
                SideRefusal::AmbiguousMatch
            ))],
            "two full matches for one side refuse instead of taking the first"
        );
    }

    /// `SplitCandidate::classified` filters metadata nodes with exactly
    /// `pair_camera`'s expression, so a role recorded on a metadata node can
    /// never become a split side even when the roles map names it.
    #[test]
    fn classified_ignores_roles_on_metadata_nodes() {
        let _hubs = usb_hubs();
        let (rgb, ir) = t480();
        // The metadata node carries a role in the map, as a stale or buggy
        // classifier could record. The constructor must drop it, exactly as
        // the pairing rule does.
        let role_of = |endpoint: &str| match endpoint {
            "/dev/video2" => Some(Role::Rgb),
            "/dev/video3" => Some(Role::Ir),
            "/dev/video0" => Some(Role::Ir),
            _ => None,
        };
        let rgb_candidate =
            SplitCandidate::classified(&rgb, SUPERVISOR, role_of).expect("RGB side classifies");
        let ir_candidate =
            SplitCandidate::classified(&ir, SUPERVISOR, role_of).expect("IR side classifies");
        assert_eq!(
            (
                rgb_candidate.roles.as_slice(),
                ir_candidate.roles.as_slice()
            ),
            (
                &[("/dev/video2", Role::Rgb)][..],
                &[("/dev/video0", Role::Ir)][..],
            ),
            "metadata-node roles are filtered, not classified"
        );
        // And the filtered candidates still resolve.
        let outcomes = pinned_split_pairs(&[rgb_candidate, ir_candidate], &[pin()]);
        assert!(
            matches!(outcomes.as_slice(), [PinOutcome::Paired(_)]),
            "constructor-built candidates resolve like hand-built ones"
        );
    }

    /// A bus renumbering with no physical change does not break a pin. The
    /// location excludes the kernel-assigned bus number by construction
    /// (ADR-0032 §2), so the same controller and the same relative ports
    /// under a new bus resolve identically — including to an identical
    /// binding key. The renumbered hub keeps its USB2 product: only the bus
    /// number moved, not the physical hub, so the domain is unchanged.
    #[test]
    fn a_bus_renumbering_with_no_physical_change_still_resolves() {
        let _hubs = usb_hubs();
        let (rgb, ir) = t480();
        let renumbered = PairingInput {
            topology_path: "/devices/pci0000:00/0000:00:14.0/usb3/3-8",
            ..rgb
        };
        let forward = candidates(&rgb, &ir);
        let renumbered_pool = vec![
            SplitCandidate {
                input: &renumbered,
                supervisor_id: SUPERVISOR,
                roles: vec![("/dev/video2", Role::Rgb)],
            },
            SplitCandidate {
                input: &ir,
                supervisor_id: SUPERVISOR,
                roles: vec![("/dev/video0", Role::Ir)],
            },
        ];
        let bus1_outcomes = pinned_split_pairs(&forward, &[pin()]);
        let bus2_outcomes = pinned_split_pairs(&renumbered_pool, &[pin()]);
        let (from_bus1, from_bus2) = (paired(&bus1_outcomes), paired(&bus2_outcomes));
        let ([before], [after]) = (from_bus1.as_slice(), from_bus2.as_slice()) else {
            panic!("the same hardware resolves under either bus number");
        };
        assert_eq!(
            before.binding_key(),
            after.binding_key(),
            "a bus renumbering changes neither the pair nor its key"
        );
    }

    /// Two controllers that coincidentally enumerate the same relative port
    /// chain are different locations. A pin for a unit on one controller
    /// must not resolve against a unit at the same port number on another —
    /// the case the bare `<bus>-<port>` string could not tell apart and the
    /// controller-qualified location resolves correctly by construction.
    #[test]
    fn same_relative_ports_on_two_controllers_are_different_locations() {
        let _hubs = usb_hubs();
        let (_, ir) = t480();
        static USB: OnceLock<UsbDeviceFacts> = OnceLock::new();
        static NODES: OnceLock<(Vec<String>, Vec<String>)> = OnceLock::new();
        let usb = USB.get_or_init(|| UsbDeviceFacts::new(RGB_USB.into(), true));
        let (first_nodes, second_nodes) = NODES.get_or_init(|| {
            (
                vec!["/dev/video2".to_owned()],
                vec!["/dev/video4".to_owned()],
            )
        });
        // Two serial-less units of one model at port 8: one under the T480
        // controller, one under another controller that enumerated the same
        // relative number. The decoy is listed first, so a comparison that
        // ignored the controller would find it first and win.
        let pinned_unit = PairingInput {
            topology_path: "/devices/pci0000:00/0000:00:14.0/usb1/1-8",
            serial: None,
            usb_device: Some(usb),
            endpoints: first_nodes,
            metadata_endpoints: &[],
            instance_id: RGB_INSTANCE,
            generation: 3,
        };
        let decoy_unit = PairingInput {
            topology_path: "/devices/pci0000:00/0000:0d:00.3/usb1/1-8",
            serial: None,
            usb_device: Some(usb),
            endpoints: second_nodes,
            metadata_endpoints: &[],
            instance_id: "44444444444444444444444444444444",
            generation: 3,
        };
        let pool = vec![
            SplitCandidate {
                input: &decoy_unit,
                supervisor_id: SUPERVISOR,
                roles: vec![("/dev/video2", Role::Rgb)],
            },
            SplitCandidate {
                input: &pinned_unit,
                supervisor_id: SUPERVISOR,
                roles: vec![("/dev/video2", Role::Rgb)],
            },
            SplitCandidate {
                input: &ir,
                supervisor_id: SUPERVISOR,
                roles: vec![("/dev/video0", Role::Ir)],
            },
        ];
        // Both RGB candidates hold /dev/video2 with the pinned identity, so
        // only the controller tells them apart. The decoy must not win by
        // being listed first.
        let pin = SplitPin {
            rgb_identity: RGB_USB.into(),
            rgb_path: "/dev/video2".into(),
            rgb_location: Some(loc(CONTROLLER, RootHubDomain::Usb2, &[8])),
            ir_identity: "5986:1141:200901010001".into(),
            ir_path: "/dev/video0".into(),
            ir_location: Some(loc(CONTROLLER, RootHubDomain::Usb2, &[5])),
        };
        let outcomes = pinned_split_pairs(&pool, &[pin]);
        let [PinOutcome::Paired(pair)] = outcomes.as_slice() else {
            panic!("the pin resolves to the unit on the recorded controller");
        };
        assert_eq!(
            pair.rgb.location,
            loc(CONTROLLER, RootHubDomain::Usb2, &[8]),
            "the controller, not list order, selects the unit"
        );
    }

    /// A hub product the domain map does not recognize refuses the side
    /// instead of guessing a domain, panicking, or falling back to
    /// controller-plus-ports. The fixture hub at `0000:00:1a.0` reports
    /// `0009`: well-formed sysfs, unknown protocol. Uses the shared hub
    /// fixture like every other location test — no hardware, no udev daemon.
    #[test]
    fn an_unrecognized_hub_product_refuses_instead_of_guessing_a_domain() {
        let (_, ir) = t480();
        static USB: OnceLock<UsbDeviceFacts> = OnceLock::new();
        static NODES: OnceLock<Vec<String>> = OnceLock::new();
        let usb = USB.get_or_init(|| UsbDeviceFacts::new(RGB_USB.into(), true));
        let nodes = NODES.get_or_init(|| vec!["/dev/video2".to_owned()]);
        let unknown_hub = PairingInput {
            topology_path: "/devices/pci0000:00/0000:00:1a.0/usb1/1-4",
            serial: Some(SERIAL),
            usb_device: Some(usb),
            endpoints: nodes,
            metadata_endpoints: &[],
            instance_id: RGB_INSTANCE,
            generation: 3,
        };
        let _hubs = usb_hubs();
        let pool = vec![
            SplitCandidate {
                input: &unknown_hub,
                supervisor_id: SUPERVISOR,
                roles: vec![("/dev/video2", Role::Rgb)],
            },
            SplitCandidate {
                input: &ir,
                supervisor_id: SUPERVISOR,
                roles: vec![("/dev/video0", Role::Ir)],
            },
        ];
        let pin = SplitPin {
            rgb_identity: "5986:2113:200901010001".into(),
            rgb_path: "/dev/video2".into(),
            rgb_location: Some(loc(CONTROLLER, RootHubDomain::Usb2, &[8])),
            ir_identity: "5986:1141:200901010001".into(),
            ir_path: "/dev/video0".into(),
            ir_location: Some(loc(CONTROLLER, RootHubDomain::Usb2, &[5])),
        };
        // Identity, path and role all match; only the domain is
        // unresolvable. The refusal names the location rule, and nothing
        // panics on the unknown product.
        assert_eq!(
            pinned_split_pairs(&pool, &[pin]),
            vec![PinOutcome::Refused(PinRefusal::RgbSide(
                SideRefusal::LocationMismatch
            ))],
            "an unrecognized hub product refuses on LocationMismatch"
        );
    }
}

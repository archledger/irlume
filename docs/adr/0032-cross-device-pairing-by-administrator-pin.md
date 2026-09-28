# ADR-0032: Cross-device RGB+IR pairing by administrator pin

## Status

Proposed 2026-09-28, revised 2026-09-28 in response to maintainer review
(PR #937, review 5340620155). Amends ADR-0029 §1 by adding a second pairing
class: a `ConnectedPair` remains one physical camera, and a new `SplitPair`
is the only structure permitted to span two. Depends on ADR-0007 (descriptor
identity, and the finding at ADR-0007 lines 97-105 that USB bus and device
numbers are diagnostic only, allocated dynamically, and are not persistent
identity), ADR-0024 §2 (a pair is authorized as a complete role-labelled
pair), ADR-0029 §1, ADR-0030 §4 and §5, and ADR-0031 §1. Changes nothing in
ADR-0031 §4: a YUYV luma exposure ceiling stays refused, and §7 says why
pairing does not change that — but see the Phasing section for why that
refusal must not be relied on as a safety net for anything else.

The ThinkPad T480 of #887 is the first hardware this applies to. Its IR module
(5986:1141) and its colour module (5986:2113) are two USB devices on separate
ports, and every layer that pairs cameras treats one USB device as one camera.

## Context

ADR-0029 §1 pairs a camera when one physical camera's capture nodes hold
exactly one RGB role and one IR role. The rule is per inventory entry, so two
devices cannot combine: a split host is not a pair at any layer. Today it is
refused with a reason that names the cause (ADR-0030 §4, `SpansPhysicalCameras`),
and that refusal is correct as written. A machine with a working IR sensor
simply cannot authenticate.

Widening `ConnectedPair` is not the fix. That type carries one `identity`, one
`vid_pid`, one `serial_present`, one `fixed`, one `port_chain`, one
`instance_id` and one `generation`. The lease keys on `CameraInstanceId`;
`camera_binding` and the secondary store bind a credential to a pair identity
(ADR-0024 §2); a non-root peer sees neither node path nor either identity
(ADR-0030 §4). All of that assumes one physical camera per pair, and all of it
would have to become conditional if a pair could quietly be two devices.

What is missing is a second class of pair, reachable only by an explicit
administrator record. The daemon's baseline trust in "one USB device is one
camera" is physical. Crossing a device boundary is not physical, so it is a
mandate, and a mandate is recorded rather than inferred.

The hard part is not the recording. It is deciding which facts about a camera
make a pin name one *unit* rather than one *model*, because `/dev/videoN` is
renumbered across boots, a serial is not always unique, and — as this revision
corrects — even the USB bus number a location string starts with is not the
durable part of that location.

## Decision

### 1. A split pair is a separate type, never a widened `ConnectedPair`

`SplitPair` is a new type holding two `CameraNode` values, one per side, each
carrying that side's path, identity, `vid_pid`, `serial_present`, `fixed`,
controller-qualified location (§2), `instance_id` and `generation`. Discovery
never produces one. `pair_camera` and `ConnectedPair` are unchanged, so every
invariant that rests on "one physical camera per pair" continues to hold for
every existing path without conditionals.

`ConnectedPairs` gains a `split_pairs` list. It is empty unless a pin says
otherwise, so a host with a split camera and no pin still sees exactly the
single-camera view it saw before.

### 2. What may authorize a pin

A pin records, per side: the binding identity, the node path the
administrator named, and the USB location. A side of that pin is resolved
only when **all** of the following hold.

1. The pin's identity is non-empty and equals the candidate's. A
   descriptor-less camera reports the empty identity and can never be
   resolved, which is what enforces descriptor attestation here (ADR-0031 §1).
2. The pin's recorded path still names a capture node of that side holding the
   wanted role.
3. The pin recorded a USB location for that side, and the candidate currently
   reports **the same** one. A location absent on either side authorizes
   nothing.

**Location is controller-qualified, not a bare port string.** The original
form of this ADR treated `crate::usb_port_chain`'s `<bus>-<port>[.<port>…]`
string — built from the *diagnostic* USB bus number — as the durable,
unit-discriminating fact. That is wrong on this codebase's own evidence:
ADR-0007 states plainly that "USB bus and device numbers are diagnostic only.
They are allocated dynamically and are not persistent identity," and the
daemon already carries the correct alternative elsewhere —
`irlume-daemon/src/diagnostics.rs` and `irlume-cli/src/support_report.rs` both
keep a durable `controller: SafeLabel` (the host controller's PCI address,
e.g. `"0000:0d:00.3"`) separate from the volatile `usb_bus: u16` and the
relative `usb_port_chain: Vec<u8>`.

ADR-0032's "USB location" is therefore redefined as the pair **(controller,
relative port chain)**: the host controller's PCI address, plus the sequence
of port numbers under that controller, with the kernel-assigned bus number
excluded entirely. This is what a pin records and what the resolver compares.
The existing `<bus>-<port>` string (`crate::usb_port_chain`) is demoted to a
display value only — still share-safe (ADR-0030 §5), still useful in a TUI or
log line, but never compared for pin resolution. A future accessor (working
name `crate::usb_controller_location`) returns the `(controller,
Vec<u8>)` pair from the same sysfs walk `usb_port_chain` already does.

The facts available for naming a unit are:

| fact | stable across a reboot | distinguishes units on different ports | usable alone in a pin |
|---|---|---|---|
| `identity`, `vid:pid[:serial]` | yes | no: a serial is optional, and where one is present it can be a batch serial that several units of a model share | no |
| node path, `/dev/videoN` | no | no | no |
| `usb_bus` (the diagnostic bus number) | **no** — ADR-0007: dynamically allocated, not persistent identity | no, by itself | no |
| `controller` (host controller PCI address) | yes | yes, between controllers | no, alone — several ports share one controller |
| relative port chain (`Vec<u8>`, no bus number) | yes, under one controller | yes, among concurrently connected units on that controller | no, alone — two controllers can coincidentally share port numbers |
| `(controller, relative port chain)` together | yes | yes, among concurrently connected units, and across controllers | **yes** |
| `descriptor_token` | yes | no, it fingerprints model and firmware | no |
| `instance_id` | no | yes | no |

Only the controller-qualified pair is both boot-stable and able to
discriminate units that are connected at the same time, including two units
that happen to sit at the same relative port number under two different
controllers — a case the bare port string could not tell apart and the
controller-qualified location resolves correctly by construction. Identity is
not a discriminator either: a serial is optional, and where one is present it
can be a batch serial that several units of a model share.

So identity is a *precondition* and controller-qualified location is the
*discriminator*. A side with no recorded location is refused, even when the
other side is fully identified: refusing on either side is what stops a pin
resolving against whichever unit happens to hold the recorded node name.

The guarantee this buys is stated exactly, because it is narrower than the
words "unit-discriminating" suggest. The rule binds a pin to **descriptor
identity plus controller-qualified USB location and selected node**. It does
not prove the same physical unit returned. A replacement module with the same
descriptor identity, plugged into the same controller port and assigned the
same node path, satisfies every recorded fact and is indistinguishable from
the unit it replaced. Detecting that substitution would require a per-unit
secret, a genuinely unique serial, or an enrollment-time hardware
fingerprint, none of which this hardware offers. If replacement detection is
required for some deployment, these facts are insufficient, and §5 treats
that case as out of scope rather than as solved.

The cost is stated rather than hidden: a camera whose sysfs path yields no
readable controller or port chain can never be a side of a split pair, and
that includes non-USB capture nodes. Split pairing is about two USB devices
on known controllers, so this is the intended boundary, and it fails closed.

### 2a. Scope: sequential-only, one administrator record holding many pins

Two scope questions the original text left implicit are stated outright:

* **Initial support is sequential-only.** This ADR specifies no concurrent
  dual-controller capture contract: nothing here promises that the RGB and IR
  sides of a split pair can be opened and streamed at the same instant, only
  that the daemon can identify and authorize the pair. Whatever capture
  ordering the lease already imposes on two devices applies unchanged; a
  true concurrent-capture guarantee, if ever needed, is a separate ADR.
* **`set-cameras` holds an ordered collection of pins, not one.** The
  resolver in §5 already assumes this — "a camera is claimed by the first
  pair that uses it," pins are "honored independently, in pin order" — so the
  configuration format is explicit here rather than left to be inferred from
  the resolver's behavior: it is a list, administrator-ordered, and that
  order is the tie-breaking priority when two pins overlap on a camera.

### 3. Moving a side to another controller port requires re-pinning

A pin records a controller-qualified location, so a unit that moves to a
different port — on the same controller or a different one — no longer
matches, and the pair is refused until `set-cameras` records the new
location. There is no serial-based exemption, because a serial is not what
makes a side unique (§2).

This is deliberate. A pin is the administrator's statement about which
hardware to use; a change of USB topology is a physical change, and a second
unit of the same model arriving at the old port is exactly the event a pin
exists to make visible. Built-in modules do not move ports, so the common case
is unaffected. A bus renumbering with no physical change — the case ADR-0007
warns about — must **not** trigger this: see the acceptance tests.

### 4. Pair binding survives a replug, and nothing is rebound automatically

A pin records no `instance_id` and no `generation`, deliberately: recording
them would make the pin expire on every reboot, which is the failure mode
§2's location rule exists to prevent.

A replug mints a new `instance_id` and resets the generation. A clean return
to the same controller port changes neither the descriptor identity nor the
controller-qualified location, so the binding key for the pair is unchanged —
including across a bus renumbering, since the bus number is excluded from
that location by construction (§2). But a replug **may change the node
path**: the kernel can renumber `/dev/videoN` on re-enumeration, and §2 rule 2
then refuses to resolve until the pin's recorded path is updated. Automatic
resolution therefore holds only when the recorded node path still matches.
This is deliberate: the pin must not follow a node name onto hardware it
never named, so a renumbered unit waits for `set-cameras` to record its new
path rather than being quietly re-attached. Because the binding key carries
the unit facts and not the path, that re-pointing needs no re-enrollment.

What the replug does retire is the *proof*: the pair must be re-proved under
the lease against the new instance ids and generations on both sides before
anything is opened. A credential is never re-bound to a different key because
a pair stopped matching. That follows ADR-0024 §5: no automatic movement to
another pair after a mismatch, and no pooling of evidence across pairs. Note
the boundary of that promise, from §2: a replacement unit presenting the same
recorded facts is not a different key, and nothing here detects it.

The binding for a split pair follows ADR-0024 §2's complete role-labelled
pair: the two sides' unit keys, in **role order** (the RGB key first, then
the IR key, never sorted). Discovery order must not matter, and the builder
guarantees it by assigning each side by role rather than by enumeration
order, so the same physical pair builds the same key however the census
listed it. But `RGB=A, IR=B` and `RGB=B, IR=A` are different
authorizations, because the credential authorizes roles through a pair, not a
set of two devices. ADR-0024's rule that enrolling pairs A and B never
authorizes a hybrid applies unchanged, and is the reason a pair key is
compared whole rather than side by side.

### 5. What fails closed

* **Either side absent.** No pair, and the request is refused before any device
  is opened. The side that is present is *not* usable on its own for a split
  credential: a split pair has no single-camera path, as an unenrolled pair is
  not a usable pair (ADR-0029).
* **Either side's generation advanced.** Re-prove both sides under the lease.
  If either no longer presents the same unit key, refuse rather than
  re-resolve.
* **A pool spanning two inventory incarnations.** Refuse every pin. Pairing
  across a republication would pair a camera with a republication of itself.
* **Two sides that cannot be told apart.** Refuse. Identical halves observed
  twice are one ambiguous unit.
* **A camera already claimed.** A camera is claimed by the first pair that uses
  it; a later pin reusing either side is refused, so no camera is ever half of
  two pairs and no enrollment binding is ambiguous.
* **One unresolvable pin among several.** It alone is refused. Pins are
  honored independently, in pin order (§2a).
* **A bus renumbering with no physical change.** Must not be refused: the
  controller-qualified location (§2) excludes the bus number, so this is not
  a location mismatch.

### 6. Redaction and the wire

**`CameraCandidate` stays exactly as it is today: role-free.** The original
text of this section proposed sending a split pair's two sides to a non-root
peer "as `CameraCandidate` endpoints... carrying their pair roles." That is
not implementable: `CandidateWire` in `crates/irlume-common/src/live_camera.rs`
is `#[serde(deny_unknown_fields)]` over exactly `instance_id`, `generation`
and `endpoint_paths`, and the existing test
`live_camera_wire_rejects_unsafe_names_zero_generation_and_invented_roles`
specifically asserts that an injected `role` field fails to decode. Extending
that type would break every decoder that relies on today's contract, old and
new alike, since `deny_unknown_fields` rejects the payload in both
directions.

Split-pair role and location information therefore travels over **a new,
separate reply that only a client which sends a new, distinct request ever
receives.** `CameraCandidate`/`CandidateWire` is never touched: every client
that continues to send the ordinary inventory request gets exactly the
ordinary reply, byte for byte, whether or not the daemon has any split pairs
configured. A client that wants split-pair information must opt in with a new
request variant; the daemon answers that request with a new wire type —
role-labelled `CameraCandidate`-shaped endpoints with pair roles attached —
that old clients simply never ask for and therefore never see. This is a
stronger backward-compatibility guarantee than relying on unknown-field
tolerance: an old client's behavior is provably unchanged, because it never
receives a payload it wasn't built to parse.

Neither side's real node path, neither side's identity, and neither side's
serial crosses the non-root boundary in either the old or the new reply
(ADR-0030 §4); only endpoint tokens do, exactly as for an ordinary pair. The
controller-qualified location's `controller` and port-chain components remain
share-safe and may be sent (ADR-0030 §5), on the same terms the old
`port_chain` display string always was.

Whether the two sides sit on one USB device or two is therefore never named
on the old wire at all, and on the new wire only to a client that explicitly
asked. Root receives the full `SplitPair`, both real paths, both identities
and both serials, exactly as it receives them for a `ConnectedPair`.

### 7. Pairing never creates an exposure ceiling

ADR-0031 §4 stands unchanged. `clipping_white_level(IrPixel::YuyvLuma, ...)`
stays `None` under `only_native_8bit_grey_can_claim_a_clipping_ceiling`. A USB
descriptor is a device-supplied claim, not proof of sensor modality, and
crossing a device boundary is evidence of nothing at all. Enabling split
pairing is not a route to a YUYV exposure ceiling, and a split pair's IR side
is qualified exactly as a same-device IR side is.

**This refusal must not be read as a safety net for anything else.** It stops
a YUYV IR side from claiming a clipping ceiling; it says nothing about, and
does not block, a split pair whose IR side is native GREY. See Phasing for
why that distinction is load-bearing.

## Consequences

* A pin becomes a new trust primitive: the only thing in the daemon that
  authorizes a relationship physics does not imply. It is therefore root-only
  configuration, written by `set-cameras`, and nothing else may create one.
* `set-cameras` must record both identities, both paths and both
  controller-qualified locations for a cross-device pair, as an ordered
  collection of pins (§2a), and must keep warning when it saves one.
* A single-device pin and every `ConnectedPair` path are unaffected.
* `docs/PLATFORMS.md` gains the ThinkPad T480 as the first supported split
  pair, and a host that has one still needs the separate exposure work in
  ADR-0031 §4 before face authentication is released on it. Pairing and
  exposure are independent, and neither substitutes for the activation gate
  in Phasing.
* Any side without a recorded controller-qualified location cannot
  participate in a split pair, regardless of serial (§2). This is a real
  restriction, chosen over the retarget it prevents.
* Two units of the same model on the same controller port cannot both be
  connected, so §5's "cannot be told apart" case is a descriptor ambiguity
  rather than a topology one in practice.
* The guarantee is bounded, and the bound is on the record. A binding key
  proves descriptor identity plus controller-qualified location and role, not
  that the same physical unit returned. A replacement unit with the same
  descriptor identity at the same controller port under the same node name is
  indistinguishable, and §2 requires that to be stated rather than implied.
  Deployments that need replacement detection must bring a per-unit fact this
  ADR does not have.
* `CameraCandidate`/`CandidateWire` gains no field and no behavior change for
  any existing client. Split-pair information is additive, opt-in, and lives
  entirely on a new wire contract (§6).

## Rejected alternatives

* **Widen `ConnectedPair` to span devices.** Rejected: it would void the
  single-camera invariants the lease, `camera_binding`, the secondary store and
  ADR-0030 §4 all rest on, and would turn a physical assumption into a
  configurable one everywhere at once.
* **Trust identity alone.** Rejected: serials repeat across units of a model,
  which this repository's own evidence records, and a serial-less unit's
  identity names a model.
* **Trust the node path alone.** Rejected: renumbered across boots, which is
  the retarget this ADR exists to close.
* **Compare the raw `<bus>-<port>` string as the durable location.**
  Rejected: ADR-0007 already established USB bus numbers as diagnostic-only
  and dynamically allocated; using the bus number as part of the
  discriminator reintroduces exactly the churn ADR-0007 warned about, and
  fails to distinguish two controllers that coincidentally enumerate the same
  relative port number under different diagnostic bus numbers on different
  boots.
* **Treat an unrecorded location as a wildcard.** Rejected: it reintroduces the
  retarget for exactly the hardware that has no other discriminator.
* **Let a serial-bearing side skip the location check.** Rejected: batch
  serials are the documented reason a serial does not name a unit, so a serial
  is not an exemption.
* **Infer a pair from hub or port adjacency.** Rejected: an inference is not an
  authorization, and adjacency does not survive a reboot.
* **Let a replug silently re-bind a credential to a different binding key.**
  Rejected by ADR-0024 §5's no-automatic-movement rule. Note the boundary
  from §2: replacement hardware presenting the same recorded facts is not a
  different key, and remains undetectable.
* **Detect replacement hardware from descriptor facts.** Out of scope: as §2
  records, a replacement unit presenting the same descriptor identity at the
  same location under the same node name is indistinguishable, and no
  combination of the facts a pin may record closes that gap.
* **Add a `role` field to the existing `CameraCandidate` wire type.**
  Rejected: `CandidateWire` is `#[serde(deny_unknown_fields)]` and is
  specifically tested to reject an invented role field
  (`live_camera_wire_rejects_unsafe_names_zero_generation_and_invented_roles`);
  extending it would break every existing decoder rather than only the ones
  that opt in.
* **Rely on the ADR-0031 §4 YUYV exposure refusal as the activation gate for
  split-pair enrollment/authentication.** Rejected: that refusal is
  pixel-format-specific and does not fire for a native-GREY IR side, so it
  would leave a real exposure window between Steps 4 and 5 rather than close
  it. See Phasing.

## Acceptance tests

* No pin, no split pair: a host with a split camera and no `set-cameras`
  publishes the single-camera view, byte for byte.
* A pin whose sides are two same-model serial-less units whose node
  assignments swap resolves to **no** pair, even when both sides report no
  location. No recorded location on either side authorizes nothing.
* The same pin resolves only after the administrator records the location the
  unit is actually at, and then names that unit and not the one that inherited
  its old node name.
* A pin naming an identity that is not connected, a side with no descriptors,
  or a side with two nodes of the wanted role is refused.
* A pool spanning two inventory incarnations refuses every pin, including a pin
  naming only the homogeneous majority.
* Overlapping, non-identical pins produce one pair; the second is refused in
  either order, and pin order (§2a) decides the winner.
* Two serial-less pairs of the same models on different controller ports have
  different binding keys.
* `RGB=A, IR=B` and `RGB=B, IR=A` have different binding keys, because the key
  is role-labelled. The same candidates in the opposite enumeration order
  build the same pair with the same key.
* A replug of one side at the same controller port leaves the binding key
  unchanged, while the pair requires re-proof against the new instance ids and
  generations. If the renumber moved the node path, the pin does not resolve
  until `set-cameras` records the new path, and the re-pointing needs no
  re-enrollment.
* **A bus renumbering with no physical change does not break a pin:** the same
  controller and the same relative port chain, under a new kernel-assigned bus
  number, still resolves.
* **Two controllers that coincidentally enumerate the same relative port
  chain are different locations:** a pin for a unit on one controller must
  not resolve against a unit at the same port number on a different
  controller.
* A replacement unit presenting the same recorded identity at the same
  controller port with the same node path is not distinguished. This is
  stated as a residual limitation, with a test pinning the current behavior
  rather than the impossible one.
* A split pair never yields a YUYV clipping ceiling.
* **An old client's ordinary inventory request, against a daemon with one or
  more configured split pairs, returns byte-for-byte the pre-ADR-0032 reply
  shape:** `CandidateWire` gains no field, and the old client never receives,
  and therefore never has to decode, anything about split pairs.
* A new client's opt-in request receives role-labelled endpoints for each
  split pair's two sides, with neither side's real path, identity or serial,
  exactly as an ordinary pair's tokenized endpoints are redacted today.
* **Split-pair enrollment and authentication remain refused end-to-end until
  Step 5's binding enforcement is implemented and tested**, including for a
  split pair whose IR side is native GREY — the fixture that proves the gate
  does not depend on the YUYV refusal firing.

## Phasing

1. This ADR, landing alone as `docs(adr): ADR-0032 cross-device pairing by
   administrator pin`.
2. The data model and the pin resolver, with `split_pairs` still published
   empty, so nothing can acquire a pair yet.
3. `set-cameras` records the two identities, both controller-qualified
   locations and both paths as an ordered collection of pins (§2a), and the
   inventory publishes `split_pairs` from the live configuration.
4. Split-aware `acquire_operation`: both instance keys acquired together in a
   deterministic order, both validated against one live publication, both
   released if either validation fails, with the single-device path preserved
   unchanged.
5. Split-aware `camera_binding`, secondary store and `resolve_saved_pair`.

### Activation gate

Steps 2 through 4 land the data model, resolver, publication and split-aware
lease acquisition. **None of them may be exercised end-to-end**: split-pair
enrollment and authentication must remain refused by an explicit gate until
Step 5's split-aware `camera_binding`, secondary-store and
`resolve_saved_pair` enforcement is implemented and tested. Today,
enrollment acquires the configured endpoints and `current_binding` stores
only device-identity strings; neither is split-pair-aware, so a split pair
that clears Step 4's lease acquisition could otherwise be enrolled and
authenticated with a binding that does not actually enforce the pair as a
whole.

The ADR-0031 §4 YUYV exposure refusal is **not** an acceptable substitute for
this gate (§7): it is pixel-format-specific, and a split pair whose IR side
reports native GREY is not held by it at all. Step 4's acceptance tests must
therefore include a native-GREY split fixture that proves the activation gate
holds on its own terms, independent of any device format that happens to
refuse for an unrelated reason. Steps 3 through 5 complete the split-pair
data model, resolver, publication, lease acquisition and binding plumbing;
none of them, including Step 4 in isolation, enables T480 face authentication,
which additionally needs both the activation gate's Step 5 enforcement and the
separate YUYV exposure work of ADR-0031 §4.

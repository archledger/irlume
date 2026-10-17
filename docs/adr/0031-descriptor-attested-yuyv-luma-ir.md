# ADR-0031: Descriptor-attested YUYV-luma IR endpoints

## Status

Accepted 2026-09-27 for §1, §2, §3 and §5, which land with the change that
fixes the classification half of #887. §4, a sensor ceiling for YUYV luma,
was recorded then as pending, with what the reporter measured on the
ThinkPad T480. Amended 2026-10-13 and 2026-10-14: §4 is implemented per
burst, on a split pair under the machine owner's experimental opt-in
(ADR-0032) only. There, an attested YUYV IR burst gets a clipping ceiling
of 235 on the raw decode when it passes the judgment of Amendment
2026-10-13, and such a burst from a camera with no illumination records
also supplies its frames' active-IR evidence (Amendment 2026-10-14). Every
other YUYV IR burst is still refused as exposure unmeasurable. Amended
2026-10-17 (#1069): on an IR node closed to the seat user (the packaged udev
rule, measured on the node itself per burst), that burst proof no longer
needs the opt-in's confinement; `irlume doctor` reports the node's state. The reporter's T480 enrolled on
the implementation (PR #1064); confirmed grants on it and qualification on
more units remain open. Depends on ADR-0029 §1 and §9
(camera-free classification; selection never opens a device it will not
use). Changes nothing in ADR-0023 §3 (profiles still cannot classify),
ADR-0024's pair authorization, ADR-0019 or the exposure refusal of #358 and
#371.

## Context

irlume decides a video node's role from the pixel formats `VIDIOC_ENUM_FMT`
lists (`role_from_formats`): a colour format makes the node `Role::Rgb`,
greyscale alone makes it `Role::Ir`, and colour wins. YUYV counts as colour,
so a node that offers only YUYV is always an RGB camera.

#887 reports the first IR camera on record that streams in that container:
the ThinkPad T480's "Integrated IR Camera" (USB 5986:1141). It offers one
format, YUYV, at 340x340 (the descriptor's default frame) and 640x480, both
at 30 fps; its frames carry luma with flat chroma (§4). On that machine
irlume lists the IR node as a UVC RGB camera, and RGB-only operation takes
the first RGB node in numeric order (`select_rgb`), which there is usually
the IR node at `/dev/video0` rather than the colour camera (USB 5986:2113)
at `/dev/video2`.

Treating "offers only YUYV" as IR would be wrong in the other direction, and
that direction matters more: a node classified `Role::Ir` can complete a
pair and move a machine to the secure tier, which releases credentials, and
`Role::Ir` is evidence of a pixel format, not of infrared sensing (#403).
Fourteen of the forty most-reported UVC webcams in the linuxhw LsUSB
collection offer only YUY2, and the CI's v4l2loopback RGB feeder is a
YUYV-only node.

The USB descriptor carries a standards-based statement that the formats do
not. Microsoft's UVC 1.5 extensions define an extension unit,
`MS_CAMERA_CONTROL_XU` `{0F3F95DC-2632-4C4E-92C9-A04782F43BC8}`, and say of
its `FACE_AUTHENTICATION` control (selector 0x06, section 2.2.2.6) that it
is only applicable to cameras that can produce infrared data. In the
published descriptor of 5986:1141 (linuxhw LsUSB report 31A261423C, a T480
on Gentoo), and in the reporter's own, the video function has one
streaming interface, a Microsoft unit (unit 8) whose `bmControls` is
`22 00` (selectors 0x02 and 0x06, with `bNumControls` 2), and a Processing
Unit with no controls. The paired colour camera 5986:2113 has no Microsoft
unit and a Processing Unit advertising hue, saturation and white balance
(`bmControls` 0x157f). A ThinkPad P16s Gen 2 colour function carries a
Microsoft unit without selector 0x06, so the unit's presence alone is not
the signal; the selector is.

#428 removed a descriptor-derived *format* route because a node's sysfs
parent names the VideoControl function, not which of the function's
streaming interfaces backs the node. That objection is about attribution,
and it does not arise for a function with exactly one streaming interface:
the function's claim can only be about that interface's node.

Two further blockers sit behind classification on the T480 and are outside
this ADR's implementation:

- The IR and RGB cameras are two USB devices. A pair is one physical camera
  (ADR-0029 §1, #403), and the camera lease resolves a request only when one
  inventory entry holds every requested node, so every RGB and IR operation
  there failed with "camera endpoint is not in the supervisor inventory".
- YUYV and NV12 luma have no sensor ceiling (`clipping_white_level` answers
  `None`), so `exposure_refusal` refuses every credential-releasing attempt
  as "IR exposure unmeasurable" (#358, #371). #385 recorded that `None` as
  what refuses a colour node that reaches the IR slot through the
  environment override, a saved pin or the fallback path.

A third defect is in frame-size selection. irlume asks every IR node for
640x400, and uvcvideo returns the advertised frame with the smallest
non-overlapping area against the request: on the T480, 640x480 (distance
51,200) wins over 340x340 (distance 140,400). The reporter measured the
640x480 mode as near black (frame means about 1 to 4) and the 340x340 mode
as alternating lit and dark frames (about 121 and 17) from the camera's own
emitter strobe.

## Decision

### 1. The IR role from the USB descriptor, for YUYV-only nodes

A capture node whose formats give `Role::Rgb` is classified `Role::Ir` when
all four of these hold:

- **(a) Formats.** `VIDIOC_ENUM_FMT` on the node lists exactly `{YUYV}`. A
  node that also offers MJPG, NV12, RGB3, BGR3 or a grey format keeps the
  answer its formats give.
- **(b) One stream.** The VideoControl function uvcvideo binds the node to
  (its interface in the active configuration) has exactly one
  `VC_HEADER`, that header's `bInCollection` is 1, and the listed interface
  is a distinct VideoStreaming interface (class 0x0E, subclass 0x02) with
  a default alternate in the same configuration.
- **(c) Face authentication.** The function has exactly one
  `MS_CAMERA_CONTROL_XU`, and that unit advertises selector 0x06 within
  `bNumControls`. A bitmap that sets more bits than `bNumControls` claims
  advertises nothing, as it already does for the emitter path.
- **(d) No colour processing.** No Processing Unit of the function sets any
  of the `bmControls` bits in 0x38CC: hue (D2), saturation (D3), white
  balance temperature (D6), white balance component (D7) and their
  automatic variants (D11, D12, D13). A function without a Processing Unit
  passes.

The only new input is the USB device's sysfs `descriptors` file, read only
for a node whose formats are exactly `{YUYV}`. No extension-unit request is
sent, no frame is captured, and no name or `vid:pid` table is consulted. The
descriptor walk steps by `bLength` through one configuration and refuses
truncation, overruns and the structural inconsistencies checked below.
A Processing Unit or extension unit whose `bLength` ends before its
closing string index (`iProcessing`, `iExtension`) counts as truncated.
For UVC 1.1 and later, a Processing Unit must also carry the final
`bmVideoStandards` byte, as documented in Microsoft's
[UVC 1.0 and 1.1 differences](https://learn.microsoft.com/en-us/windows-hardware/drivers/stream/differences-between-uvc-1-0-and-uvc-1-1).
The target VideoControl interface must occur once at alternate zero;
duplicate or nonzero alternates cannot supply evidence for it.
Its header precedes every other class-specific VideoControl descriptor.
Each interface-number/alternate-setting pair occurs at most once.
The configuration's interface count matches distinct interface numbers,
not alternate settings. The control descriptors form one block before
the endpoints, and terminals and units have unique nonzero entity IDs.
Each interface alternate carries its declared endpoint count, with no
repeated endpoint address. Every recognized control entity has its full
mandatory layout, even when its fields do not contribute to the role.
Only UVC 1.0, 1.1 and 1.5 control layouts are recognized; an unknown
version or entity subtype does not attest. Terminal and selector sizes
follow the [Linux UVC descriptor definitions](https://github.com/torvalds/linux/blob/master/include/uapi/linux/usb/video.h);
the Encoding Unit carries both control arrays described in
[Microsoft's USBView layout](https://github.com/microsoft/Windows-driver-samples/blob/main/usb/usbview/h264.h).
The Encoding Unit is accepted only in UVC 1.5. Interface endpoints cannot
name endpoint zero or set reserved address bits.
An endpoint on the target VideoControl interface is interrupt IN.

The VideoControl header's own total and the source references of every
terminal and unit are checked too (Amendment 2026-09-27 below, #913). This
is not a complete USB/UVC validator, and
even a fully consistent descriptor is a device-supplied modality claim.
YUYV credential release remains refused while §4 is pending. (Amended
2026-10-13 and 2026-10-14: §4 is implemented; on a split pair under the
experimental opt-in, a burst that passes its judgment can release
credentials, and every other YUYV burst is still refused.)

The configuration header's `wTotalLength` is not used: a device writes both
that number and the chain, so the walk judges the descriptors the file
holds. (The reporter's first 5986:2113 file came up 30 bytes short of its
header, which prompted this; the file sysfs gives on that machine turned out
to match its header, and the short copy was a clipped paste.)
Every failure, an unreadable or absent descriptor included, keeps the node
`Role::Rgb`. The extension-unit parser that authorizes emitter writes
(#159) is not changed; the new walker shares its unit parsing, and a test
and the fuzz target pin that both return the same units.

`irlume camera census` and `irlume doctor` print, for a `{YUYV}`-only
camera row, the attestation or refusal when it agrees with the scanned role.
A contradictory descriptor reread is omitted, and a paired IR node whose
formats could not be rechecked has unverified secure IR support. A dummy
node such as a v4l2loopback feeder has no USB descriptor, and its row
carries no such line. The refusal keeps three failures apart: a descriptor
that could not be read, a descriptor file that is malformed (including one
without a complete active configuration), and a node whose USB interface
is not a UVC VideoControl interface, so a readable, well-formed descriptor
is never reported as unreadable or malformed. The census
classes (`uvc_ir`, `uvc_rgb`) and the doctor's section header do not change,
because `scripts/ir-node-from-doctor.sh` and the machine API depend on them.
While §4 is pending, a YUYV IR sensor that completes a pair is reported as
supported with limits rather than at the secure tier, since every
credential-releasing attempt on it refuses. (Amended 2026-10-13 and
2026-10-14: the census still reports it so; credential release is possible
only for a burst that passes §4's judgment on a split pair under the
experimental opt-in.)

### 2. `VIDIOC_ENUM_FMT` stays the format authority

The descriptor attests a role and nothing else. The formats a node offers
still come from `VIDIOC_ENUM_FMT` on the node, for the reasons #428 gives:
the kernel skips formats it cannot map and applies per-device quirks, so a
descriptor-derived list is not what the node reports.

### 3. Pairing is unchanged

A pair is still one physical camera (ADR-0029 §1). An attested node pairs
only with an RGB node on the same USB device; the T480's IR node is a
standalone IR sensor, and its colour camera stays at the RGB-only
convenience tier. Two consequences are made visible without changing that
rule:

- A lease request whose nodes each belong to a different inventory entry is
  refused with an error that says the RGB and IR nodes are on different USB
  devices, with the device count and no node paths or identities
  (ADR-0030 §4), instead of naming an unknown endpoint.
- `set-cameras` warns, and does not refuse, when the two nodes are on
  different USB devices, since such a pin keeps working for the paths that
  do not lease both nodes.

Pairing across USB devices needs its own ADR, amending ADR-0029 §1,
ADR-0024 and ADR-0007.

### 4. A sensor ceiling for attested YUYV luma (per burst since Amendment 2026-10-13)

Amended 2026-10-13 and 2026-10-14: the paragraph below describes §4 as it
was accepted. `clipping_white_level` still answers `None` for YUYV luma, but
a judged burst now names a ceiling and can supply active-IR evidence; see
those amendments for the conditions as implemented.

`clipping_white_level` keeps answering `None` for YUYV luma, attested or
not, so every credential-releasing attempt on a YUYV IR stream is refused as
exposure unmeasurable. A later change may give an attested YUYV stream a
ceiling only when all of the following hold, each bound to the opened file
descriptor and the frames being judged rather than to the cached role:

- the §1 attestation, re-derived from the open file descriptor, so the
  environment override, a saved pin and the fallback path cannot bypass it;
- an effective range that resolves to limited: explicit limited range, or
  the default with a non-JPEG colorspace and an encoding other than XV601
  or XV709, read through a raw `VIDIOC_G_FMT` because the pinned v4l crate
  drops the Y'CbCr encoding;
- footroom: no frame with more than 0.5% of its pixels below raw luma 15;
- flat chroma: in each frame, the U and V bytes span a few codes at most
  (2 on the T480, below), latched for the session so a later flat frame
  cannot clear a violation;
- an observed emitter alternation on the burst being judged
  (`D1OpticalEvidence` in `ir_emitter.rs`);
- a decode that expands limited range to full range, so the ceiling after
  expansion is 255.

Amendment 2026-10-06 below fixes the metadata domain and preliminary
footroom and chroma bounds for these conditions, refuses XV601 and XV709
under either quantization, and adds no ceiling. Amendment 2026-10-07
binds the first two conditions to the open file descriptor, again without
a ceiling. A second amendment of that date latches the footroom and
chroma conditions for the session and fixes the expansion, still without
a ceiling. Amendment 2026-10-13 implements the ceiling for each burst that
meets these conditions, and replaces the last one: the decode stays raw and
the ceiling is 235.

Measured on the T480 (5986:1141) by @maurerr, the reporter of #887:

- The node offers YUYV only, at 340x340 and 640x480, both at 30 fps. The
  640x400 request irlume made before §5 lands on 640x480, the near-black
  mode; §5 requests 340x340.
- Quantization is limited range (`VIDIOC_G_FMT` reports the default, which
  maps to limited, with a BT.601 encoding). Luma never falls below 16, and
  bright pixels stop at 235, never 255: every lit frame of a capture with a
  palm close to the lens reached 235.
- The camera's emitter strobes on alternate frames.
- Lit frames have chroma of exactly 128. Dark frames have a constant 137 to
  138, and one dark frame, the first dark frame of one capture, read 115 to
  117. A chroma test for closeness to 128 would refuse every dark frame, so
  a chroma gate must test flatness within a frame instead.
- Auto-exposure ramps over the first frames of a capture. After the first
  frame, lit-frame means climbed from 39 to 57 over 30 frames with a face at
  the usual distance and from 139 to 229 with a palm about 5 cm from the
  lens, and a capture that skipped no frames showed lit means near 121 for
  its first four frames before they fell to about 55. A statistic taken from
  one window depends on where in the ramp it lands.

The ceiling stayed unbuilt, and #385's item 2 with it, until a change
implemented these conditions against the measurement (Amendment
2026-10-13).

### 5. The IR frame size for attested YUYV

An IR open of an attested YUYV node requests the smallest discrete YUYV
frame size the node advertises that is at least 340x340 (`HELLO_IR_MIN`,
Windows Hello's IR stream minimum), taking the first one listed when two
have the same area, and 640x400 when none qualifies or the sizes cannot be
enumerated. Stepwise sizes are ignored. The attestation for this request is
re-derived at open from the file descriptor, with the rule of §1. GREY, the
Y16 family, NV12 and unattested YUYV keep requesting 640x400, so the ASUS
(640x400), NexiGo N930W (640x360) and Logitech BRIO (340x340) negotiate
exactly as before and their stored qualification contracts stay valid. The
doctor's read-only stream probe applies the same walk, and the capture
qualification contract records the size that was actually requested rather
than the 640x400 constant.

## Consequences

Amended 2026-10-13 and 2026-10-14: the bullets below are the consequences
as accepted, before §4 was implemented. YUYV luma now has a ceiling for
each burst that passes §4's judgment, and such a burst from a camera without
illumination records supplies its own active-IR evidence; the T480 enrolls
as a split pair (ADR-0032), and only bursts that fail the judgment refuse as
exposure unmeasurable.

- On the T480, `/dev/video0` is listed as an unpaired UVC IR sensor with
  its descriptor evidence, `/dev/video2` stays the RGB camera, and RGB-only
  operation no longer picks the IR camera. An RGB-only enrollment made on
  the IR camera has to be made again. IR capture from `/dev/video0` asks for
  340x340. Face authentication with IR on that machine still refuses: its
  cameras are on two USB devices (§3), and YUYV luma has no ceiling (§4).
- A USB device with an attested YUYV IR function beside an RGB function
  would now pair automatically and move to the secure tier, where every
  credential-releasing attempt refuses as exposure unmeasurable until §4.
  That fails closed; no such device is on record.
- Descriptor contents are claims the firmware makes. A device that forges
  its descriptor is out of scope, as it already is for a node that
  advertises GREY. Clause (d) keeps a face-authentication unit copied onto
  a colour function from attesting it, and while §4 is pending a false
  positive costs availability, never a grant.
- One sysfs read per `{YUYV}`-only node per scan and per IR open; no
  device is opened beyond the existing format enumeration.
- Known gaps: an IR camera that offers MJPG beside YUYV (the Chicony
  04f2:b613 module some T480s carry), NV12-only IR nodes, a VideoControl
  function shared by several streams (#704), and an IR function whose
  Microsoft unit does not advertise selector 0x06. The reporter's
  descriptor carries that bit; for an IR camera that lacks it, the fallback
  is an exact `vid:pid` table following the `known_control` and
  `MIPI_BRIDGE_IDS` precedent, still behind §1's other clauses, recorded as
  an amendment here.

## Rejected alternatives

- **"Offers only YUYV" means IR.** It would reclassify ordinary YUY2-only
  webcams and the CI's loopback RGB feeder, and could pair two of them into
  a secure-tier pair (#403).
- **Matching "IR" in the product or interface name.** Names are shown and
  never matched on (ADR-0029 §7, §9); "RGB-IR Camera" also appears as a
  product string.
- **Classifying from frame content during discovery.** It opens the camera,
  lights its LED and may fire its emitter during camera-free discovery
  (ADR-0029 §1, §9; #428).
- **A consented, root-run measurement command with a stored record.** It
  needs a new command, a consent flow, a record store and a
  reclassification path, and a stored record can go stale where the frames
  being judged cannot. Kept as the fallback if descriptors prove
  insufficient.
- **The kernel's `UVC_QUIRK_FORCE_Y8`.** It rewrites YUYV as GREY at twice
  the width, for modules that send packed 8-bit grey; the T480 sends real
  YUYV with flat chroma bytes (§4).
- **A `cameras.d` profile that reclassifies the node.** ADR-0023 §3 forbids
  profiles from classifying endpoints; this rule is production code in the
  camera crate, keyed on a standards bit rather than on a device list.

## Acceptance tests

| Boundary | Required result |
|---|---|
| Descriptor rule | The ASUS 3277:0059 IR function (interface 2) is attested and its RGB function (interface 0) is not; the T480 5986:1141 function is attested and 5986:2113 is not, from the reporter's descriptor files, the 5986:2113 file refused only for its missing Microsoft unit, and an IR function whose header overstates its length by 30 bytes still attested; two streams, each colour bit alone, a Microsoft unit without selector 0x06 or with more bits than `bNumControls`, two Microsoft units, a truncated header, Processing Unit, extension unit (including one that stops before its string index) or tail, a listed interface that is not VideoStreaming, a `VC_HEADER` total other than its control block, a source that is zero, missing, the entity itself, an Output Terminal or on a cycle, a Selector or Extension Unit without an input, a face-authentication unit on another interface, a node interface that is not a VideoControl interface, a descriptor file without one complete active configuration, and a node without a USB parent are each refused with the named reason; the Logitech BRIO and NexiGo N930W graphs (fan-out, two Output Terminals, units nothing reads, sources listed after the entity that reads them) keep their answers |
| Parser agreement | The new walker and the emitter's extension-unit parser return the same units for every interface of the ASUS and both T480 fixtures, and for the BRIO and NexiGo functions, and the fuzz target asserts it on arbitrary input |
| Classification | `[YUYV]` with the attestation is `Role::Ir` and without it `Role::Rgb`; MJPG+YUYV, YUYV+RGB3, NV12, NV12+YUYV and YUYV+GREY stay what their formats say whatever the attestation; the descriptor is not consulted for GREY, Y16, metadata or empty format lists |
| Frame size | GREY and Y16 ignore the size list and request 640x400; unattested YUYV requests 640x400; attested YUYV requests 340x340 from `{640x480, 340x340}` in either order, 400x400 from `{400x480, 400x400}`, 640x400 from an empty or too-small list, and the first of two equal areas; a replica of uvcvideo's nearest-size rule shows 640x400 landing on 640x480; the candidate walk hands the format ioctl the size it chose |
| Qualification | The IR stream contract records the requested size it is given, not 640x400, and the open IR camera builds it from the request it made |
| Capture binding | IR negotiation reads the attestation from the open file descriptor, never from the node path; an ignored hardware test opens an attested YUYV IR camera and checks the 340x340 request and echo |
| Census | An attested node is `uvc_ir`, unpaired, supported with limits, with the descriptor line; an unattested YUYV node names its refusal; a GREY IR node, an MJPG+YUYV node and a loopback YUYV node carry no descriptor line, whatever descriptor answer their facts hold |
| No probe | Discovery and the census decide the role only through the sysfs reader; the doctor's IR stream line reuses the capture walk, whose fd-bound attestation is also a read (`fstat` and sysfs on the file descriptor the probe already holds); nothing on those paths streams frames for it |
| Lease | Nodes on two inventory entries refuse with the split-device error; one entry holding both nodes still leases |

The T480 tests read the `descriptors` files @maurerr supplied on #887
(`crates/irlume-camera/tests/fixtures/bison-5986-1141.descriptors` and
`bison-5986-2113.descriptors`, #575), which are also fuzz seeds; builders
laid out like the 5986:1141 bytes remain only for the synthetic
counter-cases. The source-graph tests also read a Logitech BRIO and a
NexiGo N930W from a maintainer machine
(`logitech-046d-085e.descriptors`, `nexigo-3443-c803.descriptors`).

## Amendment 2026-09-27: VideoControl header total and source graph

#913, required before §4. Two checks join §1's structural list. A failure
of either refuses the function as malformed and keeps the node `Role::Rgb`.

- **The VideoControl header's own total.** `VC_HEADER`'s `wTotalLength`
  must equal the length of the header and the terminals and units after
  it, which §1 already requires to form one block before the endpoints
  (UVC 1.1 and 1.5 Table 3-3: "the combined length of this descriptor
  header and all Unit and Terminal descriptors"). The interrupt endpoint,
  a SuperSpeed companion and the class-specific endpoint descriptor are
  not counted. Linux uvcvideo does not read this field. The
  configuration's `wTotalLength` stays unread, for the reason §1 gives.
- **Sources.** Every source a terminal or unit names (the Output
  Terminal's `bSourceID`, a Selector or Extension Unit's
  `baSourceID[bNrInPins]`, a Processing or Encoding Unit's `bSourceID`)
  must be another entity of the same function, nonzero and not an Output
  Terminal, and the references form no cycle. Every Selector and
  Extension Unit has at least one input. UVC 1.5 §2.3 gives every unit
  one or more input pins and an Output Terminal none to read from, and
  disallows loops; §3.7.2 reserves ID 0. With these, the inputs of every
  entity lead back to an Input Terminal, so a Microsoft unit disconnected
  from its function does not attest it. `bAssocTerminal` is an
  association, not a source, and is not checked.
- **What stays allowed.** References are resolved once the whole block
  has been read, since §3.7.2 leaves the order free and real functions
  refer ahead: the T480 IR camera and the ASUS IR function list their
  Output Terminal before the units it reads, and a NexiGo N930W lists its
  Output Terminal first and its Input Terminal fourth. Fan-out, more than
  one Output Terminal and units whose output nothing reads are allowed: a
  Logitech BRIO feeds two Output Terminals and eight extension units, its
  Microsoft unit among them, from one Processing Unit. The Microsoft unit
  is therefore not required to lie between an Input and an Output
  Terminal.

Checked against the fixtures, the BRIO and the NexiGo, and 196,736
VideoControl functions (6,139 device, firmware and interface combinations)
in the linuxhw LsUSB corpus. No function with a Microsoft unit or an IR
name there fails either check. Colour cameras do: 6 combinations with a
different header total, 17 with a zero or missing source and 140 with an
Output Terminal as a source. They stay `Role::Rgb`, and one that offers
only YUYV now names a malformed descriptor instead of its earlier refusal.
The streaming interface's `bTerminalLink` naming an Output Terminal of the
function is not checked; the fixtures, the BRIO and the NexiGo satisfy it.

## Amendment 2026-10-06: preliminary §4 metadata and frame-content bounds

#887. §4 stays pending: `clipping_white_level` still answers `None` for
YUYV luma, and every credential-releasing attempt on a YUYV IR stream
still refuses. This amendment fixes, for the later change §4 describes,
the metadata domain and the per-frame bounds that a pure camera-crate
helper (`crates/irlume-camera/src/yuyv_exposure.rs`) checks on synthetic
input. Nothing calls the helper yet. The bounds are preliminary and
uncalibrated: they come from the UAPI and from the T480 measurements
recorded in §4, and attended acceptance on the T480 can change them.

- **Metadata read.** The helper judges raw `VIDIOC_G_FMT` values of a
  single-planar capture YUYV format, and only when the node advertises
  `V4L2_CAP_EXT_PIX_FORMAT` and `priv` holds `V4L2_PIX_FMT_PRIV_MAGIC`;
  otherwise the extended fields are undefined and the range is
  unresolved.
- **Supported domain.** The colorspace is one of SMPTE170M, 470_SYSTEM_M,
  470_SYSTEM_BG, SRGB, OPRGB, JPEG, REC709, DCI_P3, BT2020 and SMPTE240M,
  the ones `videodev2.h` documents a default Y'CbCr encoding for. The
  encoding is DEFAULT, resolved by that table, or one of 601, 709, XV601,
  XV709, BT2020 and SMPTE240M. The quantization is DEFAULT, FULL_RANGE or
  LIM_RANGE. Everything else leaves the range unresolved and refuses: an
  unknown value of any of the three, colorspace DEFAULT (no format field
  resolves it, and the frame size is not used to guess), the deprecated
  BT878 colorspace and SYCC encoding, the RAW colorspace, BT2020_CONST_LUM
  and the HSV encodings. No raw value is converted to an enum.
- **Limited range.** Explicit LIM_RANGE, or DEFAULT with any colorspace
  but JPEG, which is how `V4L2_MAP_QUANTIZATION_DEFAULT` resolves Y'CbCr.
  FULL_RANGE, and DEFAULT with JPEG, are full range and refused.
- **Extended gamut.** XV601 and XV709 are refused under either
  quantization, explicit LIM_RANGE included. xvYCC is limited range that
  allows values outside it, so 235 is not its ceiling. This widens the
  second condition of §4, which excluded them only from the default. Under
  DEFAULT or LIM_RANGE they stay nominally limited, not full range; an
  explicit FULL_RANGE, which the UAPI never pairs with xvYCC, refuses as
  full range like any other encoding.
- **JPEG.** Explicit LIM_RANGE with the JPEG colorspace is refused:
  `videodev2.h` defines JPEG as sRGB with BT.601 encoding at full range,
  so the tuple contradicts itself.
- **Footroom.** A frame fails when more than 0.5% of its pixels have raw
  luma below 15. Both Y bytes of every macropixel in the frame's
  `2 * width * height` image bytes count, and payload bytes after the
  image never do. In integers this is `below_15 > pixels / 200`; raw 15
  does not count.
- **Flat chroma.** A frame fails when its U and V bytes together span
  more than 2 codes, `max(U, V) - min(U, V) > 2` over the whole frame.
  Flatness is judged within one frame, with no test for closeness to 128
  and no comparison between frames. §4 records a span of 2 on the T480,
  so this bound has no margin.

Passing these is not a ceiling and not a grant. The helper's combined
verdict has no way to state the first condition of §4, the attestation
re-derived from the open file descriptor, so it refuses whatever the
metadata and frames show; that evidence belongs to the later fd-bound
change. The session latch, the current-burst emitter alternation and the
limited-to-full expansion stay unimplemented, and which frames feed the
latch and how expansion rounds stay open for the changes that implement
them. Synthetic tests in the helper's module check each case above.

## Amendment 2026-10-07: fd-bound format evidence

#887. §4 stays pending: `clipping_white_level` still answers `None` for
YUYV luma, and every credential-releasing attempt on a YUYV IR stream
still refuses. This amendment binds §4's first two conditions to the open
file descriptor (`crates/irlume-camera/src/yuyv_fd.rs`).

- **Binding.** An IR open whose negotiation is descriptor-attested YUYV
  (§5) binds evidence once the format and frame interval are final. On the
  open fd, in order: `fstat` names the node; `VIDIOC_ENUM_FMT` is read until
  EINVAL ends the list, and any other errno, an answer for another index or
  buffer type, or more than 64 entries leaves it incomplete; the complete
  list must be YUYV alone; the §1 attestation is re-derived from the fd's
  USB descriptor; and `VIDIOC_QUERYCAP` and a single-planar `VIDIOC_G_FMT`
  are copied field by field. Every field the v4l crate's format keeps (type,
  fourcc, size, field, stride, image size, colorspace, the flag bits it
  knows, quantization and transfer function) must equal the negotiated
  readback. The fields it
  drops (the Y'CbCr encoding, `priv` and flag bits it does not know) and
  the `V4L2_CAP_EXT_PIX_FORMAT` capability are frozen as read, and the
  2026-10-06 amendment judges the range from them.
- **Rechecks.** The node and the whole frozen tuple are read again at each
  boundary where the negotiated format is already compared (#427): before
  and after the buffer claim, after a stream's first dequeue, and on every
  reopen after recovery. A moved field, another node or a failed read
  refuses that capture as stream state drift. At the first dequeue any
  refusal from these rechecks, raw evidence or the wrapper format and
  interval snapshot alike, ends warm-up, which retries other dequeue
  failures, so a later clean read cannot heal it.
- **Without evidence.** A camera whose binding fails has no evidence and
  captures exactly as before; only the ceiling, which no YUYV stream has,
  needs it. IR paths outside an `IrCamera` (emitter setup and the raw and
  sequence probes) carry none, as they judge no exposure.
- **Journal.** With `IRLUME_LOG=debug`, the open logs the frozen tuple and
  its range verdict, or why binding refused, for attended qualification.
- **Evidence.** Synthetic tests cover each refusal and each compared field.
  On real kernels, the v4l2loopback CI lane and an attended run on archhost
  (Linux 7.2.8, uvcvideo; Logitech BRIO 046d:085e and NexiGo N930W
  3443:c803) found the raw tuple equal to the format's readback, the
  extended fields defined, every list ended by EINVAL, and the tuple
  unchanged through real IR sessions with a capture, a recovery reopen and
  the recovered stream's first dequeue, while a second fd read 1,097
  identical `VIDIOC_G_FMT` answers. Neither camera's nodes are YUYV alone,
  so both refuse binding; the T480's own node still needs attended
  qualification.

Binding is not a ceiling and not a grant. The session latch, the burst's
emitter alternation and the limited-to-full expansion remain.

## Amendment 2026-10-07: session content latch and fixed expansion

#887. §4 stays pending: `clipping_white_level` still answers `None` for
YUYV luma, and every credential-releasing attempt on a YUYV IR stream
still refuses. This amendment settles what the 2026-10-06 amendment left
open: which frames feed the latch, and how expansion rounds.

- **Scope.** An `IrSession` whose camera holds fd-bound format evidence
  keeps one content latch (`crates/irlume-camera/src/yuyv_exposure.rs`)
  for the session's life. GREY, the Y16 family, NV12, unattested YUYV and
  an attested camera whose binding refused have no evidence and no latch.
- **Frames judged.** Every frame the stream delivers to a capture's burst
  is inspected before it is decoded: up to 10 per capture, including
  frames the gate selection passes over and the ambient partner. A frame
  the stream refuses after its dequeue (the rate floor, or a sequence,
  timestamp or rate-window fault), or whose endpoint recheck then fails,
  is neither inspected nor decoded, and its capture fails. Warm-up, the
  startup flush, the delivered-rate fill and its probe, the refill after
  a recovery, the paired concurrent fill and the paired tail drains
  discard their frames undecoded and are not inspected; the latch does
  not claim them.
- **Per frame.** Footroom and flat chroma as the 2026-10-06 amendment
  defines them, on raw bytes before any expansion, over the frame's
  `2 * width * height` image bytes. A payload of any other length latches
  a refusal of its own, and its image bytes are still judged: uvcvideo
  sizes an uncompressed frame at `bpp * width * height / 8`, which is the
  image at the `2 * width` stride the layout requires, and flags a buffer
  of any other length as an error (Linux v7.2 `uvc_driver.c` L299-301,
  `uvc_video.c` L214-218 and L1535-1541). A frame whose format has no
  tight YUYV layout, or whose raw luma sum overflows, also latches a
  refusal.
- **Delivery faults.** A buffer flagged `V4L2_BUF_FLAG_ERROR`, which
  uvcvideo delivers by default (`nodrop` is 1, v7.2 `uvc_driver.c` L35,
  `uvc_queue.c` L359-366), exposes no payload: in a burst it fails its
  capture, while the warm-up and the rate fills skip it and carry on. A
  frame the kernel drops leaves only a sequence gap. Neither can be
  inspected. The latch only refuses, so a gap or discontinuity never
  exempts the frames around it. Requiring a gap-free burst belongs to the
  burst proof and the ceiling.
- **Lifetime.** A violation latches at the frame that shows it, even when
  that capture later fails, and holds through later captures, `recover()`
  and a privacy teardown until the session ends. A new session starts
  with an empty latch, which is the absence of a refusal, not proof.
  A one-shot IR capture opens a session of its own, so its latch covers a
  single burst. The sequential capture schedule, the default when none is
  stored, captures IR that way outside a sequential batch; a held
  concurrent pair and a sequential batch keep one IR session across their
  captures. Whether a violation should outlive a capture, per request or
  per device, is for the ceiling change to decide.
- **Output.** The latch answers a refusal or nothing: no ceiling, no
  clipping level, and nothing consumes it yet. With `IRLUME_LOG=debug`
  the frame that first latches each reason logs the reason's name,
  without pixel values.
- **Expansion.** Limited to full luma is fixed: `0` for `Y <= 16`, `255`
  for `Y >= 235`, and `round((Y - 16) * 255 / 219)` between, which never
  lands on a half because 219 is odd. It equals FFmpeg n9.0.2's
  limited-to-full conversion of YUYV luma on all 256 codes; the 298/256
  approximation and libyuv's BT.601 constants read 8 and 10 codes one
  low. `E(234) = 254`, and `E(Y) = 255` exactly when `Y >= 235`. The
  function is pure and unwired: decoding YUYV through it now would move
  IR face detection, the gate frame and the enrollment preflight's lit
  test (raw face means from 40 to about 50 would read dark), changing
  denial kinds and the RGB-only enrollment choice while credential
  release still refuses. The ceiling change wires it after the latch and
  the burst proof, and keeps the content checks and the optical means on
  raw bytes.

Synthetic tests check the latch and every input of the expansion.
Source-shape tests pin that each burst frame reaches the latch before
decode, with no condition and nothing between dequeue and decode that
skips it, and that only the session's construction builds the latch and
no code holding the session reassigns or clears it, so later captures,
`recover()` and a privacy teardown keep it. The v4l2loopback CI lane
checks the latch on a real kernel with evidence frozen from the GREY-fed
node: warm-up and the rate fill leave it empty, each burst frame latches
`uninspectable` alone, and recovery keeps its count and verdict for the
recovered stream's burst. No real-kernel lane streams attested YUYV, so
the T480 still needs attended qualification. The burst's emitter
alternation and the ceiling remain.

## Amendment 2026-10-13: the ceiling, judged per burst

#887. This amendment implements §4. A burst of an IR session whose camera
holds fd-bound format evidence (Amendment 2026-10-07) gets a clipping ceiling
of 235 on the raw luma decode, for that burst alone, when all of these hold
once the burst has ended (`YuyvContentLatch::burst_ceiling` in
`crates/irlume-camera/src/yuyv_exposure.rs`):

- the frozen format resolves to eligible limited range (Amendment
  2026-10-06);
- the session's content latch holds no refusal: no frame offered in the
  session so far, this burst's included, broke the footroom, chroma,
  payload-length or readability rule;
- the latch judged exactly the burst's frames: its count rose by the number
  of frames the burst decoded;
- the camera's illumination records for those frames, where it has any, do
  not break D1 parity (`D1MetadataEvidence::contradicts_d1`: at least four
  classified records and a parity conflict);
- the burst's raw luma means, keyed by raw V4L2 sequence and never by index,
  prove D1 alternation by the setup proof's rules, unchanged
  (`D1OpticalEvidence::proves_d1`): at least three frames in each phase, a
  phase-median difference of at least 20, at least three supported bright and
  three supported dark frames, at least three consistent adjacent pairs and
  none conflicting, at most one missing sequence, and no repeated or backward
  step.

Anything else leaves the burst's ceiling `None`, so credential release
refuses it as exposure unmeasurable, as before. `clipping_white_level` still
answers `None` for YUYV luma: the format alone never names a ceiling.

- **No expansion.** This replaces §4's last condition and the fixed
  expansion of the second 2026-10-07 amendment, which is removed unused. The
  decode stays raw, as for limited-range GREY, whose ceiling
  `clipping_white_level` already answers at 235; #385's item 2 asked the same
  of YUYV. Clipping measures the same pixels either way: the expansion
  reached 255 exactly when raw luma was 235 or more. Expanding would move
  only the other readers of the frame, as that amendment recorded: §4's
  face-distance lit means of 39 to 57 would read 27 to 48, mostly below the
  enrollment preflight's lit bar of 40 (`IR_LIT_MEAN`), and IR face detection
  and the gate frame would see a scale the T480's measurements were not
  taken on.
- **When.** The ceiling is decided after the burst, once the illumination
  records are drained, and before the gate-frame selection, the paired
  saturation evidence, the ambient subtraction and the capture's statistics
  read it. Before the burst only the format's ceiling exists; YUYV has none,
  so the plateau exit never ends a YUYV burst early, and the proof sees every
  frame up to the 10-frame cap.
- **Scope.** Per burst. A proven burst never qualifies the next, and a
  latched violation leaves every later burst of the session without a
  ceiling. Held sessions, the sequential batch, one-shot captures and a
  recovered stream all reach the same capture method. GREY, the Y16 family,
  NV12, unattested YUYV and an attested camera whose binding refused keep
  their format's answer.
- **Journal.** With `IRLUME_LOG=debug`, each judged burst logs its ceiling
  or the reason it has none, by name; an unjudged burst also logs the two
  frame counts. No pixel value is logged.
- **Evidence.** Synthetic tests check each condition, the threshold boundary
  (a lift of 20.0 qualifies, 19.9 does not), the sequence rules, the
  illumination veto, the per-burst scope and the journal text, and a
  source-shape test pins where the ceiling is bound. A burst shaped like §4's
  T480 frames, lit frames of flat chroma 128 at the lowest face-distance lit
  mean (39) and dark frames of raw luma 16 to 20 and chroma 137, qualifies by
  one point; at a lit mean of 37 it does not. Replayed over the three
  ten-frame bursts recorded on 2026-09-07 from the ASUS FHD webcam's IR camera
  (GREY, so this ceiling does not apply to it), the unchanged optical rules
  prove alternation on both bursts whose emitter write succeeded (phase
  differences 38.7 and 30.6, no conflicting pair) and refuse the one whose
  write failed (2.0).

Not established: how the T480's own bursts fare at face distance in
ordinary lighting, whether their lift clears 20 after warm-up, and how often
a burst refuses. That needs attended qualification on the T480, which may
move the preliminary bounds. Mandatory PAD and every threshold are
unchanged. (Amended 2026-10-14: the reporter's T480 enrolled ten scans on
this implementation before the emitter condition of Amendment 2026-10-14,
so its bursts did clear the lift of 20 there; what remains open is
repeatability under the current conditions, how often a burst refuses, and
confirmed grants.)

## Amendment 2026-10-14: active-IR evidence from a judged burst

#887. Production pairing, ordinary and split, accepts an IR frame only with
active-IR illumination provenance (`IlluminationProvenance::ActiveIr`), and
until now only the camera's own per-frame illumination record supplied it.
The T480's IR camera has none, so after Amendment 2026-10-13 its bursts got
a ceiling and its frames were still refused: on the reporter's T480, split
enrollment stopped at the first frame with "split IR frame lacks active
illumination provenance" right after a burst logged its 235 ceiling.

This amendment adds one source of that evidence, two conditions to the
burst's qualification, and one limit on where a YUYV burst is judged at
all:

- **Only on a split pair under the experimental opt-in.** The judgment of
  Amendment 2026-10-13, ceiling included, runs only for an IR session whose
  lease is a split pair while the owner's experimental split opt-in is
  latched (`optical_provenance_admitted`; ADR-0032, amendment 2026-10-13).
  The ordinary sequential route and the IR-only route do not require
  active-IR provenance, so a ceiling there would bypass the confinement the
  limitation below needs. Elsewhere every YUYV burst stays without a ceiling
  and refuses as exposure unmeasurable, as before §4 was implemented.

- **The stream's emitter is active.** Either the session's emitter guard
  reports the configured control active for this stream, whether irlume
  wrote it or found it already set (`StreamMode::lit`), or the camera's own
  Face Authentication control reads back its device-default D1 value
  (`VerifiedDefaultMode`). That second source is the read-only proof
  `read_capture_default` already made under `IRLUME_LOG_EMITTER_WRITES`: on
  the open device, the control is advertised and synchronous, its current
  value equals the D1 value derived from its own GET_DEF and GET_MAX and is
  the default, and a second GET_CUR reads the same; nothing is written. Its
  D1 entry must also name the one streaming interface the node's descriptor
  attests, on the attested Microsoft unit. Either source is read again from
  the camera right before each burst and right after it
  (`StreamMode::still_active`: the configured control still holds what the
  guard applied, or the Face Authentication control still reads the
  verified value, twice), so a control changed by a device reset or another
  program between bursts qualifies no later burst. Microsoft's UVC 1.5 extensions (section 2.2.2.6)
  make GET_CUR the camera's statement of each IR streaming interface's mode,
  D1 being alternating frame illumination. Only an attested YUYV IR session
  asks for this proof, at open and at recovery, and nothing but its burst
  qualification reads it; it never runs after a configured or known control,
  an explicit `IRLUME_IR_EMITTER=off`, a foreign owner or an unchecked
  recovery. A burst from a stream with neither refuses (`the emitter is not
  active for this stream`), so an alternation from any other light source
  qualifies nothing. The T480's Face Authentication control defaults to D0
  (GET_DEF and GET_CUR 01 01 01, with D0 and D1 advertised, 01 01 03), so the
  read-only default proof declines it, and `irlume ir-setup` cannot save it
  ("before 41, after 53, needs +20"). Its D1 mode is selected for now by the
  documented override, `IRLUME_IR_EMITTER=8:6:1,1,2,0,0,0,0,0,0` (unit 8,
  selector 6, D1 on streaming interface 1, the value discovery derives from
  those reported values), which is checked against the open camera's
  descriptor and applied under the same stream guard as a configured
  control, restoring the original when the stream ends. The built-in table
  (`known_control`) gains the T480 only once that write, its read-back, the
  optical result with D1 selected and the restore are recorded on the
  hardware (#887). The read-only default proof serves an attested YUYV
  camera whose control already defaults to D1.
- **Records agree with the optics.** Besides not breaking D1 parity, every
  illumination record the camera does supply must name the optically
  bright frames lit. Records that alternate in the opposite phase refuse
  the burst.

When a burst met every condition of Amendment 2026-10-13 and these
(`QualifiedBurst`) and the camera supplied no illumination record for any
of its frames, each frame's provenance comes
from the burst's proven alternation: active IR for the frames whose raw V4L2
sequence parity is the bright phase, ambient for the others
(`provenance_illumination` in `crates/irlume-camera/src/lib.rs`). Nothing
else changes:

- A camera with any record for the burst keeps its records; the two sources
  never mix, and records that break the alternation's parity already deny
  the ceiling.
- Only provenance reads the derived marks. The gate-frame selection, the
  paired saturation evidence and the camera-reported statistics
  (`camera_classified_frames`, `camera_lit_frames`, `ambient_observed`) keep
  reading the camera's records, so they still say the camera classified
  nothing.
- The selected frame carries its own phase. If the selection lands on a
  dark-phase frame, it is ambient and the pair is still refused.
- GREY, the Y16 family, NV12, unattested YUYV and an attested camera whose
  binding refused derive nothing, as no burst of theirs qualifies.

Evidence for the decision:

- **Windows does the same.** In its alternating-illumination mode Windows
  Hello reads `MF_CAPTURE_METADATA_FRAME_ILLUMINATION` on every IR frame, and
  the UVC 1.5 extensions let the camera provide it "through a Device MFT or
  by including a MetadataId_FrameIllumination attribute in the metadata
  payload" (Microsoft, "Microsoft extensions to USB Video Class 1.5
  specification", section 2). A host-side component, not only camera
  firmware, may supply the frame's illumination state.
- **The T480 cannot supply records on Linux.** Linux v7.2 enables Microsoft
  per-frame metadata only when the camera's Microsoft extension unit
  implements the Metadata control, selector 9
  (`drivers/media/usb/uvc/uvc_metadata.c`, `uvc_meta_detect_msxu`;
  `include/linux/usb/uvc.h`). The T480 IR camera's unit advertises
  `bmControls` `0x22`, selectors 2 and 6 only (docs/DEBUGGING.md).
- **The proof is no looser than records here.** Over the three ten-frame
  bursts recorded from the ASUS FHD webcam's IR camera on 2026-09-07, the
  optical bright phase matched the camera's lit and dark records on all 30
  frames. In the burst whose emitter write failed, the camera still
  reported alternating lit frames while the lift was 2.0, and the optical
  proof refuses it.

**Limitation, and why the opt-in.** The reads around a burst cannot see an
emitter-control change made and undone within it by another program with
access to the camera. Linux v7.2 uvcvideo applies no V4L2 priority to
extension-unit queries (`uvc_v4l2.c`, `uvc_ioctl_default` passes
`UVCIOC_CTRL_QUERY` straight to `uvc_xu_ctrl_query`), and a camera without
illumination records has no per-frame account that would show it. So the
whole judgment is confined to the experimental split opt-in, whose warning
names it; a stronger, per-frame evidence source is tracked in #1069.
(Amended 2026-10-17: on a node the seat user cannot open, the reads are
complete and the confinement relaxes; see the amendment of that date.)

The content bounds stay as they are. An earlier ThinkPad IR camera
(Chicony 04f2:b5cf, J. Henstridge, "ThinkPad Infrared Camera", 2017)
advertised YUYV while streaming packed 10-bit grey, which no flat-chroma
frame can carry; the chroma bound of Amendment 2026-10-06 is what refuses
such a stream. The reporter's T480 run set no content latch.

Synthetic tests check the derivation for both parities, the record and
length guards, an inactive emitter, records inverted against the optics,
and that frame provenance reads the derived marks while the selection does
not. Attended qualification on the T480 remains open.

## Amendment 2026-10-17: a node the seat user cannot open completes the proof

#1069 asked for one stronger per-frame evidence source, with data, so the
2026-10-14 confinement can relax, or for the limitation to be recorded as
permanent. The source chosen is the node's own access state: while no
unprivileged program can open the IR capture node, none can change the
emitter control between the reads around a burst, and the burst's proven
alternation is the whole story. The three options of the issue, each checked
against primary sources:

- **Node access (chosen).** The package ships
  `packaging/udev/72-irlume-ir-nodes.rules`, which removes the `uaccess` tag
  from the nodes of the descriptor-attested YUYV IR cameras without
  illumination records and assigns them to root alone (`0600`): the
  `NO_RECORDS_YUYV_IR` table in `crates/irlume-camera/src/uvc_descriptor.rs`
  (today the T480's 5986:1141 module alone, an IR-only USB device, so the
  device-wide match touches no RGB node). The rule sorts after
  `70-uaccess.rules`, which adds the tag, and before `73-seat-late.rules`,
  which applies it as an ACL (udev 217 for `TAG-=`, udev 247 for the `:=`
  assignments that keep a later rule from widening the node again). The group
  is root, not `video`: irlume's own `EACCES` advice tells users to join
  `video`, so a seat user there would silently keep full access to a
  root:video node (review round 1 on #1109). Verified against systemd's
  sources: the uaccess builtin rewrites the node's whole ACL when it runs,
  and logind re-triggers that rewrite on a seat switch only for devices still
  tagged, so a node the rule covers can carry a stale seat ACL until its next
  plug or boot. And permissions are checked at open(2): a descriptor opened
  before the rule applied stays usable, so application is the next plug or
  boot of the camera, never `udevadm trigger` (same round; a full closure
  would need a per-burst fd census, which needs CAP_SYS_PTRACE irlumed
  deliberately does not have, the #207 precedent, or a forced re-enumeration,
  which disconnects the camera mid-use; both are rejected as
  disproportionate). irlume therefore never trusts the rule's presence: the
  capture path reads the node's current owner, group, mode and access ACL on
  each burst (`crates/irlume-camera/src/node_access.rs`), and admits the
  optical proof only when the node is actually closed (root-owned, root
  group, no group or world permission, no ACL entry naming another user or
  group, and no effective group-object permission: a writable GROUP_OBJ entry
  would let a non-root process whose supplementary groups include gid 0 open
  the node; review round 2 on #1109) and the node's udev database record no
  longer carries the `uaccess` tag among its current tags (the record's `Q:`
  lines; its `G:` lines are the historical union and keep a removed tag
  forever - systemd `device_update_db` and `device_remove_tag`, review round
  4 on #1109). The tag's absence is what a rule removing
  it records; a hand-set permission change keeps the tag, so logind re-grants
  the seat ACL at the next seat switch, and such a change proves nothing
  about descriptors opened before it - manual hardening needs the same plug
  or boot boundary (review round 3 on #1109). Any read error is not hardened. `irlume doctor` reports the state
  per device (`ir-node-access`), covering also the scan's unreadable bucket:
  a successfully hardened node is exactly one the seat user's scan cannot
  open (same round), so a still-shared node keeps the 2026-10-14 confinement
  and the row names the remedy (plug or boot after install, or an
  administrator closing the node). The `camera-nodes` capability check counts
  that deliberately hardened node (refused on permissions, in the table,
  itself reading hardened), since the daemon opens it as root - otherwise a
  hardened host's `doctor --check` would fail because hardening succeeded
  (review round 5 on #1109). The kernel side stands as recorded above:
  `UVCIOC_CTRL_QUERY` carries no V4L2 priority, and only the capture node
  carries it (the metadata node's fops have no `.vidioc_default`; a
  `/dev/media` node speaks a different ioctl space), so closing the capture
  node closes the window.
- **Driven pattern (rejected).** Driving the emitter in a sequence irlume
  chooses and requiring the optics to follow would need the mode-change
  effect latency per camera module (Microsoft's sequence sets the mode
  before streaming, UVC 1.5 extensions section 2.2.2.6; mid-stream effect is
  firmware-defined and unmeasured for every module in this class), keeps the
  node shared for reads and streaming, and yields a probabilistic rather
  than a hard boundary.
- **Firmware records (census, no new source).** Cameras whose Microsoft
  unit advertises the Metadata control already supply per-frame illumination
  records and never had the limitation: measured on 2026-10-17, the ASUS
  3277:0059 (unit 14) and Logitech BRIO (unit 12) advertise selectors 6 and
  9, the NexiGo 3443:c803's IR function (unit 4) does too, and the T480's
  5986:1141 (unit 8) advertises 2 and 6 only, matching its committed
  descriptor fixture.

Admission keeps its shape: the judgment still runs only for a split pair's
IR session. `optical_provenance_admitted` now admits when the lease is a
split pair and either the owner's experimental opt-in is latched (as before)
or the session's IR node reads hardened at the burst. Nothing else moves: a
camera with illumination records keeps them, the sequential and IR-only
routes still require no active-IR provenance and get no ceiling, and root is
out of scope as always. The T480's known_control
entry and attended qualification stay with #887.

Acceptance: the node-access predicate's unit tests (base ACL, named user,
named group, world permission, group permission, the effective
group-object permission with and without MASK, an incomplete base ACL,
malformed ACL, missing node, the udev database record's tag lines by
content and against a fixture directory, the record-name rdev split,
ownership and mode on real files), the descriptor-fixture pin of
`NO_RECORDS_YUYV_IR` (attested shape, face-authentication present, Metadata
absent, IR-only device, the colour sibling refused), the packaging parity
check that pins the shipped rule to the table in every lane and its sort
order against systemd's files, the doctor row tests (classified and
unreadable buckets, per-device worst, wording), and the capture-path
source pins updated for the new admission.

# ADR-0031: Descriptor-attested YUYV-luma IR endpoints

## Status

Accepted 2026-09-27 for §1, §2, §3 and §5, which land with the change that
fixes the classification half of #887. §4, a sensor ceiling for YUYV luma,
is recorded here and pending: §4 records what the reporter measured on the
ThinkPad T480, and the ceiling is not implemented, so every YUYV IR frame
stays refused as exposure unmeasurable. Depends on ADR-0029 §1 and §9
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
YUYV credential release remains refused while §4 is pending.

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
credential-releasing attempt on it refuses.

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

### 4. A sensor ceiling for attested YUYV luma (pending, not implemented)

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
a ceiling.

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

The ceiling stays unbuilt, and #385's item 2 with it, until a change
implements these conditions against the measurement.

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
  refuses that capture as stream state drift. At the first dequeue the
  refusal also ends warm-up, which retries other dequeue failures, so a
  later clean read cannot heal it.
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

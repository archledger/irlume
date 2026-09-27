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
  is a VideoStreaming interface (class 0x0E, subclass 0x02) of the same
  configuration.
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
descriptor walk is strict: it steps by `bLength` through one configuration,
and anything truncated, overrunning or inconsistent fails the attestation.
It does not read `wTotalLength`: the reporter's 5986:2113 `descriptors`
file carries 996 of the 1026 bytes its configuration header claims (linuxhw
31A261423C, from a unit with the same bcdDevice 54.22, carries all 1026, and
whether the reporter's unit or the capture path dropped the rest is not
known), and a device writes both numbers, so the walk judges the
descriptors the file holds.
Every failure, an unreadable or absent descriptor included, keeps the node
`Role::Rgb`. The extension-unit parser that authorizes emitter writes
(#159) is not changed; the new walker shares its unit parsing, and a test
and the fuzz target pin that both return the same units.

`irlume camera census` and `irlume doctor` print, for every `{YUYV}`-only
camera row, either the attestation or the clause that refused it. A dummy
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
| Descriptor rule | The ASUS 3277:0059 IR function (interface 2) is attested and its RGB function (interface 0) is not; the T480 5986:1141 function is attested and 5986:2113 is not, from the reporter's descriptor files, with the 5986:2113 file's configuration 30 bytes shorter than its `wTotalLength` refused only for its missing Microsoft unit; two streams, each colour bit alone, a Microsoft unit without selector 0x06 or with more bits than `bNumControls`, two Microsoft units, a truncated header, Processing Unit or tail, a listed interface that is not VideoStreaming, a face-authentication unit on another interface, a node interface that is not a VideoControl interface, a descriptor file without one complete active configuration, and a node without a USB parent are each refused with the named reason |
| Parser agreement | The new walker and the emitter's extension-unit parser return the same units for every interface of the ASUS and both T480 fixtures, and the fuzz target asserts it on arbitrary input |
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
counter-cases.

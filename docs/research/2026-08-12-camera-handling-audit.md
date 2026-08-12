# Camera handling audited against the sources

Date: 2026-08-12. Repo state: main `37c254c`. Method: source reading over the
primary references (kernel uAPI docs, `drivers/media/usb/uvc`,
`drivers/media/v4l2-core`, videobuf2, libcamera, linux-enable-ir-emitter, the
Intel IPU6 repos), with every load-bearing quote re-verified against a sparse
checkout of torvalds/linux master (drivers/media, uapi headers, media docs;
HEAD `f5bbbfe`) and a clone of gitlab.com/libcamera/libcamera before it
entered this report. Code facts come from reading `crates/irlume-camera` at
`37c254c`. Kernel line numbers are master as of the date above.

Everything here is source-reading. Nothing was run against any camera; the
hardware-verification list is at the end.

## Q1. Enumerating without opening: possible, and the EBUSY premise was wrong

Two findings, one of which corrects a belief this project has carried since #187.

**A probe `open()` cannot cause EBUSY on uvcvideo.** The uAPI is explicit
(`Documentation/userspace-api/media/v4l/open.rst`): "Merely opening a V4L2
device does not grant exclusive access", and EBUSY attaches to buffer
ownership: the filehandle that calls REQBUFS "becomes the owner of the device"
and only then do other handles get EBUSY. On master, `uvc_v4l2_open()` is a
pure allocation with ENOMEM as its only error. The EBUSY measured in the #187
hardware session came from `VIDIOC_S_FMT` against an allocated queue
(`uvc_ioctl_s_fmt` checks `vb2_is_busy`, uvc_v4l2.c:446), which matches the
strace in the `RgbSession::recover` comment; the conclusion "opening to probe
contends" was an overgeneralisation from that trace.

**The probe open did have a different side effect, now gone.** Up to v6.15,
`uvc_v4l2_open()` called `usb_autopm_get_interface` and started the status
URB, so every classify pass powered the camera up; that is what flashes
privacy LEDs. Ricardo Ribalda's granular-power series changed it: in v6.16
the power-up moved into the ioctl dispatcher's "The following IOCTLs need to
turn on the camera" list, and neither `VIDIOC_QUERYCAP` nor `VIDIOC_ENUM_FMT`
is on it (ENUM_FMT answers from format tables parsed out of the USB
descriptors at probe time). So on current kernels `classify_node` is already
contention-free and power-free; on the kernels Debian stable ships it still
blips the camera per scan.

The contention-free classification path, if we want one that works on every
kernel:

- Capture vs metadata: udev already knows. `60-persistent-v4l.rules` runs
  `v4l_id` once at plug time; it prints `ID_V4L_CAPABILITIES=:capture:` for a
  capture node and an empty list for a metadata node, because v4l_id has no
  branch for `V4L2_CAP_META_CAPTURE`. Reading udev properties opens nothing.
- Grouping nodes per physical camera: `/dev/media*` topology. The media docs
  guarantee in writing that opening a media node "has no side effects; the
  device configuration remain unchanged", and `media_device_open()` in
  mc-device.c is a bare `return 0`. uvcvideo registers a media device
  whenever `CONFIG_MEDIA_CONTROLLER` is on and flags the default capture node
  `MEDIA_ENT_FL_DEFAULT`.
- IR vs RGB without ENUM_FMT: only one route exists, the sysfs USB
  `descriptors` blob (a stable kernel ABI since 2.6.26). It contains the
  VideoStreaming format GUIDs, and the driver's own GUID table
  (`drivers/media/common/uvc.c`) maps `UVC_GUID_FORMAT_Y8` to
  `V4L2_PIX_FMT_GREY` and so on; uvcvideo builds its format list from those
  same bytes and never asks the device. irlume already parses that blob in
  `uvc_descriptor.rs` for the emitter XU, so the parser exists; it would need
  the VS-interface format descriptors added.
- Sysfs's video4linux directory is a dead end: the complete attribute set is
  `name`, `dev_debug`, `index` (v4l2-dev.c:88), the name string is identical
  for a camera's capture and metadata nodes, and nothing exports device_caps.

What this buys: `scan_nodes` and `doctor` stop opening nodes they will not
use, which on pre-6.16 kernels stops the LED blip and the wasted power-ups,
and #187's workaround (taking camera facts from the daemon's Health) gets a
principled replacement rather than an apology. What it does not buy: any
change to real streaming contention, which was never about opens.

## Q2. The emitter write: the kernel checks structure, never values

The `UVCIOC_CTRL_QUERY` path (`uvc_xu_ctrl_query`, uvc_ctrl.c:3033) enforces
exactly three things: the unit must exist in the parsed descriptors (ENOENT),
the buffer size must equal the device's own GET_LEN answer (ENOBUFS, the
kernel issues GET_LEN itself on first touch), and GET_INFO must have marked
the control settable (EBADRQC). The payload bytes then go to the device raw;
no clamping exists on this path. A STALL surfaces as an errno mapped from the
device's error code: EBUSY "not ready", EACCES "wrong state", ERANGE, EINVAL,
EIO. "The ioctl succeeded" therefore never means "the value was safe", it
means "the device swallowed it".

**Persistence is unspecified, and the kernel restores nothing.** Neither the
UVC class doc nor Microsoft's MS-XU page says whether SET_CUR state survives
power loss; both volatile and NVRAM-backed behaviour exist in the field.
`uvc_ctrl_restore_values` (the resume restore) covers only controls with
`ctrl->modified` set and the `UVC_CTRL_FLAG_RESTORE` flag; raw XU writes set
neither, twice over. So irlume's design conclusions hold from source: the
journal must capture before-values because the kernel keeps no copy, and
re-applying per session is correct because nothing else will.

**The brick class is real and has a shape.** linux-enable-ir-emitter's issue
tracker documents cameras re-enumerating under the Sunplus controller's
fallback identity (SPCA2085/2087) after blind SET_CUR probing of vendor
units, one recovering only via the vendor's Windows firmware reflash, plus a
ThinkPad camera that came back as a different VID:PID entirely. Every
documented casualty, including irlume's own #159, came from exhaustive
SET_CUR searches of undocumented vendor units. Microsoft's documented MS-XU
selector table (0x01 through 0x0E) contains no firmware-update control, which
is why the descriptor-gated, named-control-only policy irlume adopted after
#159 is the correct and only defence. Two additions worth making:

- A failed restore write should permanently skip that control (the
  linux-enable-ir-emitter blacklist precedent); irlume currently leaves the
  record claimable for the next session, which retries the restore. That is
  right for a transient failure and wrong for a control that has stopped
  taking writes.
- The user-facing recovery advice for a stuck emitter control is a full
  shutdown, not a reboot: power removal is what clears volatile firmware
  state, and linux-enable-ir-emitter documents shutdown-then-boot as the
  recovery that works.

**No cleaner interface exists.** uvcvideo maps nothing to `V4L2_CID_FLASH_*`
(zero flash/torch hits in the driver); the flash control class is implemented
by CSI sensor and LED-controller drivers. Windows maps MS-XU IR Torch to a
KSPROPERTY; Linux has no equivalent. XU writes stay.

**Concurrency:** the query runs under the chain's ctrl_mutex, which
serialises it against other control accesses but not against streaming;
control transfers ride endpoint 0 while frames ride the streaming endpoint.
No privilege beyond opening the node is required, so any process in the
`video` group can move the emitter control mid-stream. irlume's re-apply and
its read-back-before-restore already assume this; they are load-bearing, not
paranoia. One recent kernel wrinkle: two Logitech privacy-adjacent XU pairs
are blocked with EACCES unless a module parameter overrides; the MS-XU GUID
is not affected.

## Q3. Sharing: the vb2 owner is the only real gate

- Multiple opens are supported by specification; exclusivity begins at buffer
  allocation. `vb2_queue_is_busy` compares the owner filehandle; owner is
  assigned at REQBUFS with count > 0 and released at REQBUFS(0).
- The negotiated format is per-device state, not per-filehandle:
  `uvc_ioctl_s_fmt` writes `stream->cur_format` guarded only by
  `vb2_is_busy`. Between irlume's S_FMT (in `IrCamera::open`) and its
  REQBUFS (in `session()`), another process can retarget the format under
  us, and the session would then decode frames on stale width/height/fourcc
  assumptions. The window is real; the fix is one G_FMT after buffer
  allocation, refusing on mismatch.
- `VIDIOC_S_PRIORITY` gates only state-changing ioctls
  (`v4l2_prio_check`: EBUSY when a higher-priority handle exists) and cannot
  express "yield the camera". Setting BACKGROUND on irlume's handle would
  make irlume's own S_CTRL/S_FMT fail whenever any other app merely holds
  the node open, since fresh opens get DEFAULT which is higher. Do not use
  the priority API in either direction; the vb2 owner plus
  `/run/lock/irlume-emitter-*.lock` remain the mechanism.
- The spec explicitly delegates stream sharing to "a proxy application in
  user space"; that proxy is PipeWire, and PipeWire's V4L2 path is just
  another client of the same vb2 rules, so irlume's existing EBUSY handling
  covers it (see Q6).

## Q4. Cleanup: audited in code, sound, two small holes

Every capture path tears down by RAII, verified by reading each Drop impl:

- `SafeStream` drop runs the v4l 0.14.0 chain: STREAMOFF, munmap, REQBUFS(0),
  wrapped in `catch_unwind` because the crate panics on any errno except
  ENODEV. Hole one: a non-ENODEV failure in STREAMOFF followed by one in
  REQBUFS is a panic during unwind, which aborts the daemon. Low likelihood
  (a wedged device usually vanishes as ENODEV), nonzero, and worth a
  fork-or-patch note rather than immediate work.
- The metadata node (`IlluminationLog`) does STREAMOFF, munmap, REQBUFS(0) by
  hand, with a measured comment for why REQBUFS(0) is mandatory (the UVCM
  format otherwise sticks to the node for the next process).
- The emitter guard (`StreamMode`) restores the displaced value with a
  read-back check on every exit path including panic, journaled on disk
  before the SET_CUR. Q2's findings confirm each design decision from source.
- Cameras open per auth attempt and drop at its end; nothing holds a device
  or a buffer queue while idle, so irlume owns the vb2 queue only while it
  is actually capturing. The #424 cancel path unwinds through per-frame
  `should_stop` checks into the same drops.
- Hole two (pre-existing, now sourced): the unrestored
  `V4L2_CID_BACKLIGHT_COMPENSATION` write, Q7 below.

## Q5. Privacy: the current rule is confirmed correct, one upgrade available

`V4L2_CID_PRIVACY` is the documented control; uvcvideo maps it from
`CT_PRIVACY_CONTROL` on the camera terminal and, separately, from a privacy
GPIO (`UVC_GUID_EXT_GPIO_CONTROLLER`), the latter forced read-only because
its info entry lacks SET_CUR. The errno split irlume already implements is
the documented one: EINVAL means the id is invalid ("no such control"), and
an implemented control can still fail transiently with EBUSY, EACCES, EIO,
ETIMEDOUT or EPROTO from the USB layer. So `control_read_failure_means_absent`
(EINVAL | ENOTTY) and the fail-closed rule in `privacy_permits_setup` survive
contact with the source unchanged.

Upgrade: both privacy mappings carry `UVC_CTRL_FLAG_AUTO_UPDATE`, and a
shutter change arrives as `V4L2_EVENT_CTRL` through the status interrupt or
GPIO IRQ. The daemon could subscribe instead of sampling the control at
capture time; a shutter engaged mid-capture would then surface as an event
rather than a run of dark frames. Optional; the sampling is not wrong.

## Q6. libcamera: wrong tool for UVC, design seam for later

- In-tree pipeline handlers today: imx8-isi, ipu3, mali-c55, rkisp1, rpi,
  simple, uvcvideo, vimc, virtual. No ipu6 handler; IPU6 rides `simple` with
  software ISP (libcamera 0.3.2+), RGB only, enabled laptop-by-laptop
  (Fedora change page), with real per-frame CPU cost.
- The uvcvideo handler implements no 3A and exposes no XU path (zero
  UVCIOC references in it, checked in the clone), so irlume's emitter cannot
  fire through libcamera. For UVC, libcamera subtracts and adds nothing.
- libcamera exclusivity is `lockf(F_TLOCK)` on the media device fd, with its
  own doc comment conceding it "isn't enforced by the media device itself".
  A raw-V4L2 process is invisible to it; contention still resolves at vb2.
  If irlume ever streams via libcamera it enters that lockf domain and a
  busy PipeWire node makes acquire() fail EBUSY, a clean detectable failure.
- Bindings: libcamera-rs is self-described experimental over an unstable
  pre-1.0 C++ ABI; distro versions span 0.0.3 (Debian 12) to 0.7.2 (Arch).
  A hard dependency is a packaging tax across all five lanes.
- Verdict, matching the #341 ordering already on the issue: keep direct V4L2
  for UVC unconditionally; keep the capture-trait seam clean enough that a
  backend can slot in; first zero-code experiment on real IPU6 hardware is
  Fedora's `libcamerify` compat shim; a native backend only if that fails,
  compile-time and runtime optional.

## Q7. Exposure and control stickiness: one live defect

The control document is unambiguous: "Control values are stored globally,
they do not change when switching ... They also do not change e. g. when the
device is opened or closed". Driver side, the only kernel-initiated restore
is uvcvideo re-applying the host's last-set values after reset-resume for
controls flagged RESTORE.

**The defect:** `RgbCamera::session_with_progress` writes
`V4L2_CID_BACKLIGHT_COMPENSATION = 2` best-effort and nothing restores it.
By the documented rule that value persists for every later application on
the machine until something else writes it; a video call after a face auth
runs with irlume's backlight preference. The emitter path earned a whole
guard type for exactly this class of write; this one predates that
discipline. Fix shape: read the current value first, write only on
difference, restore on session drop; or drop the write on cameras where
measurement shows it does nothing. The NexiGo measurement (mean 49 to 124)
that justified the write should decide which cameras keep it.

Rules for any future exposure tuning, from the same sources: set
`V4L2_CID_EXPOSURE_AUTO = V4L2_EXPOSURE_MANUAL` before writing
`EXPOSURE_ABSOLUTE` (uvcvideo marks the slave control inactive in every
other mode, and the doc says the effect of writing it under auto is
undefined); APERTURE_PRIORITY means auto exposure time, and is the "AE on"
most webcams implement; both AE mode and exposure time carry RESTORE, so a
manual mode survives suspend whether we want it to or not; and the polite
citizen pattern is save-before-tune, restore-on-drop, AE mode ordered
first, since even the kernel's own restore admits the ordering matters.

## Per-type taxonomy: every way a laptop camera attaches, and the safe behaviour

Read from the mainline tree (HEAD `f5bbbfe`), the Intel out-of-tree repos
(`ipu6-drivers` master `c09fa9a`, `ipu6-camera-bins`, `ipu6-camera-hal`,
`icamerasrc` slim_api), and the community sources named inline. Verified spot-checks: the IPU6 caps and enum_fmt table, the MC-centric
doc rule, the cio2/camss MPLANE caps, the AMD ISP4 driver name and caps, the
MSXU probe write, and the FORCE_Y8 quirk were all re-read in the local clone.

**UVC.** What irlume handles today, in both shapes: one USB device carrying
RGB and IR VideoStreaming interfaces (Zenbook, NexiGo; four nodes per module
counting metadata), or two USB devices with separate VID:PIDs (ThinkPads'
"Integrated Camera" plus "Integrated IR Camera"). Some IR parts lie about
their format; `UVC_QUIRK_FORCE_Y8` exists for those, and fourcc-based
classification stays correct because the quirk rewrites the fourcc before we
see it. UVC 1.5 changes the probe/commit layout, which the kernel sizes for
us, and bcdUVC is not trustworthy (the driver force-downgrades liars), but XU
writes take their size from GET_LEN and are version-independent. Worth
knowing: on Hello-class cameras the KERNEL now writes an MSXU control at
probe time to switch metadata on (`uvc_metadata.c`, citing the Microsoft
doc), so an XU SET_CUR on these devices is normal traffic, not an anomaly.
This class is also the only one in the taxonomy with a documented persistent
brick vector (vendor XU writes, Q2).

**Intel IPU6** (Tiger Lake through Meteor Lake MIPI). The `isys` driver
spawns up to eight capture nodes per CSI-2 port behind a media-controller
graph; sensors probe via the ACPI bridge; iVSC owns power and privacy on
Hello-era machines. A plain V4L2 daemon can reach raw Bayer only after
media-ctl wiring; processed frames need libcamera softISP or Intel's
proprietary stack. **The defect this section exists for:**
`ipu6_isys_vidioc_enum_fmt` answers from a static table (YUYV, RGB565, GREY,
Y10, Y16, all Bayer) whenever `mbus_code` is 0, regardless of the attached
sensor, and the nodes are single-planar `V4L2_CAP_VIDEO_CAPTURE`, so
irlume's `classify_node` sees YUYV and calls every one of those nodes an RGB
camera. Auth would select a phantom node, S_FMT would succeed (state-only),
and STREAMON would fail EPIPE on the unwired pipeline; `scan_nodes` drowns
in cameras that do not exist. No hardware harm is possible (open is inert,
sensor-to-CSI links are immutable, CSI-to-capture links start disabled,
power is kernel/firmware owned), but doctor and auth are wrong on the
fastest-growing laptop class. The gate is one QUERYCAP field: the uAPI says
a device reporting `V4L2_CAP_IO_MC` "is MC-centric", and for MC-centric
devices the video node's format list is not evidence about the camera.
Classify IO_MC nodes as a distinct refuse-with-message role.

**IPU6 IR specifically:** not reachable on Linux. The Hello-era IR sensor
(OV01A1S) has no mainline driver (the bridge lists its ACPI id, nothing
matches it); the out-of-tree driver emits IR dressed as `SGRBG10` Bayer; and
no emitter interface exists in mainline, the out-of-tree stack, or the HAL.
`ipu6-camera-bins` is binary-redistribution-only with a no-reverse-
engineering clause, so GPL-3.0 irlume can never link or ship it; the HAL
(Apache-2.0) hard-depends on those bins; `icamerasrc` is the GStreamer
element over the HAL. Face auth on MIPI-IR machines is impossible today and
refusing loudly, naming the stack, is the honest behaviour.

**Intel IPU3** (Surface-class): `ipu3-cio2` nodes are MPLANE-only, so
irlume's single-planar probe gets EINVAL and files them under `Role::Other`
already; safe by accident, made deliberate by matching the driver name. This
is the one MIPI platform with a real mainline IR story (ov7251 on Surfaces,
Y10 packed as `IPU3_Y10`), which makes it the eventual test bed if a MIPI
IR tier ever matters.

**AMD ISP4** (Ryzen AI laptops, merged for 7.2): driver `amd_isp_capture`,
`V4L2_CAP_IO_MC` set, but a hardware ISP producing NV12/YUYV with an
immutable pre-wired link, so plain V4L2 capture plausibly works with no
graph setup. Under today's code it classifies RGB and might even stream;
under the IO_MC gate it refuses. Right call: refuse now, note it as an
allowlist candidate once someone tests on real hardware. Nothing IR-related
exists in the driver.

**Qualcomm camss** (Snapdragon X laptops): MPLANE plus IO_MC, raw output,
per-model bring-up still in progress, no IR evidence. Already invisible to
irlume's probe; the gate makes it explicit.

**IPU7** (Lunar/Panther Lake): staging since 6.17, mirrors the IPU6
arrangement, plus an extra out-of-tree vision driver in the ACPI chain. The
IO_MC gate covers it unchanged. **atomisp** is ISP2-era staging hardware
with no Hello-class fleet; nothing to do. **iVSC** is not a camera and never
appears as a capture node; irlume cannot open it by accident.

The one-line summary of the whole section: outside UVC vendor-XU writes,
no driver examined exposes a persistent or damaging write path from
userspace; MIPI sensor state is volatile registers reset by runtime power
cycling. The risks on non-UVC hardware are misclassification and shared-
state vandalism, both closed by the IO_MC gate plus refusing to touch
`/dev/media*` links or `/dev/v4l-subdev*` on machines irlume does not
understand.

## Action list

Filed as issues on 2026-08-12:

1. #425: gate classification on `V4L2_CAP_IO_MC` and refuse MC-centric
   nodes with a message naming the stack; make the MPLANE ignore deliberate
   (taxonomy, defect on IPU6/IPU7 machines).
2. #426: restore or drop the backlight-compensation write (Q7, defect).
3. #427: G_FMT verification after buffer allocation (Q3, format retarget
   window).
4. #428: contention-free enumeration via udev properties + media topology +
   descriptor-parsed formats, replacing per-scan opens; includes correcting
   #187's premise in that issue's record (Q1).
5. #429: emitter follow-ups, permanent skip on failed restore write +
   shutdown-not-reboot guidance in doctor (Q2).

Recorded here rather than filed:

6. Double-panic abort window in SafeStream teardown (Q4): both STREAMOFF and
   REQBUFS(0) failing with an errno other than ENODEV panics during unwind
   and aborts the daemon. Low likelihood; a wedged USB device usually
   surfaces as ENODEV.
7. Never use V4L2 priority (it would make irlume's own control writes fail
   whenever another application merely holds the node); never add a
   `V4L2_CID_FLASH_*` path for UVC; privacy event subscription is an
   optional upgrade over sampling.

## Not verified on hardware

Everything above is documentation and source reading (master, plus the
v6.15/v6.16 boundary diffed by tag). Not tested: the udev property content on
a real metadata node, the media topology on the Zenbook or NexiGo, the
backlight-compensation persistence on any camera we own, and the Fedora 44 /
Debian stable kernel behaviour where it may differ from master (the old
uvc_acquire_privileges path produces the same EBUSY outcomes but was not
re-read on a stable branch). Those checks belong to a dedicated hardware
session.

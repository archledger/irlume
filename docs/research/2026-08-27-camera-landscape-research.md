# Camera landscape research for irlume capture, emitter, and control engineering

Date: 2026-08-27
Method: exhaustive web pass over primary sources (Microsoft specifications, kernel
source, project repositories and issue trackers, OEM support forums), cross-checked
against irlume's own fleet evidence. Every factual claim carries a source link or an
internal evidence pointer.

## Executive summary

The Windows Hello camera ecosystem is the reference design almost every IR-capable
webcam on the market targets, and it is specified end to end in public: a Microsoft
USB Video Class 1.5 extension unit (MS-XU) defines a face authentication control, an
IR torch control, and a metadata control, and Microsoft's hardware docs fix the
accuracy bars (FAR below 1/100,000) and the trust architecture (Enhanced Sign-in
Security: VBS, TPM 2.0, SDEV ACPI tables, factory sensor certificates). irlume's
emitter stack already speaks this protocol; this research confirms its payloads are
literally spec-shaped and maps what remains to adopt deliberately.

Three structural facts bound the Linux side. First, everything userspace can do is
funneled through uvcvideo's extension-unit ioctl, and the kernel already carries a
large per-device quirk taxonomy that explains most "weird camera" behavior. Second,
the laptop market is migrating to MIPI CSI-2 sensors behind Intel IPU6/IPU7 and
equivalents (Synaptics SVP7500 designs expose no UVC device at all), which no UVC
emitter tool can reach and which irlume currently cannot support. Third, Apple
silicon MacBooks (Asahi) have ISP-attached RGB-only cameras and no IR hardware
anywhere in the line, so they are out of scope for face authentication by
construction rather than by software gap.

The sections below give the deep dive on Windows Hello, the Linux kernel and emitter
ecosystem, a taxonomy of built-in and external cameras with their failure modes, OEM
control software, ChromeOS and Asahi, and a closing section of engineering
implications for irlume.

## 1. Windows Hello deep dive

### 1.1 Why near infrared is the design center

Microsoft's design doc is explicit that NIR was chosen after the Kinect-era lesson:
ambient-light recognition forces brightness and exposure manipulation that injects
artifacts, while NIR images are consistent across environments and defeat the
cheapest spoofing vectors (photos and LCD screens do not emit or reflect 850nm IR
the way a face does). Enrollment stores representations, never images, and the
match threshold rises automatically when multiple users are enrolled on a machine.
Accuracy bars: false acceptance below 0.001 percent (1/100,000), true positive
above 95 percent, false rejection below 5 percent, single-user.
Source: https://learn.microsoft.com/en-us/windows-hardware/design/device-experiences/windows-hello-face-authentication

### 1.2 The MS-XU 1.5 extension unit protocol

Microsoft's extension to UVC 1.5 is an extension unit with GUID
MS_CAMERA_CONTROL_XU `{0F3F95DC-2632-4C4E-92C9-A04782F43BC8}`. The control
selector table that matters to irlume:

| Selector | Value | Meaning |
|---|---|---|
| MSXU_CONTROL_FACE_AUTHENTICATION | 0x06 | streaming modes for face auth |
| MSXU_CONTROL_METADATA | 0x09 | per-frame metadata items |
| MSXU_CONTROL_IR_TORCH | 0x0A | direct IR lamp power and mode |
| MSXU_CONTROL_CAMERA_EXTRINSICS | 0x07 | per-endpoint extrinsics |
| MSXU_CONTROL_CAMERA_INTRINSICS | 0x08 | pinhole intrinsics |

Source: https://learn.microsoft.com/en-us/windows-hardware/drivers/stream/uvc-extensions-1-5

**Face Authentication Control semantics.** The payload is `bNumEntries` followed
by one `(bInterfaceNumber, bmControlFlags)` byte pair per video streaming
interface. Per interface exactly one of D0 (general purpose), D1, D2 (face auth
modes; a stream advertises D1 or D2, never both) is set. GET_MAX enumerates
capability; GET_DEF and GET_CUR report the chosen mode; SET_CUR selects it.
Decoding irlume's built-in payload `[1, 3, 2, 0, 0, 0, 0, 0, 0]`: one entry,
streaming interface 0x03, flags D1, face-auth mode. It is a textbook spec-conformant
SET_CUR, which also explains why the same shape lights both the Shinetech
(3277:0059, unit 14) and the NexiGo c803 (unit 4) modules.

**IR Torch Control.** Modes off, on, and temporary torch with prorated intensity;
the specification requires the torch default to be an ACTIVE mode. irlume's
discovery code already refuses to treat the control default as "off" for exactly
this reason (ir_emitter.rs, the "Nothing here assumes what off looks like"
comment), and this research confirms the spec basis.

**Metadata Control.** Carries per-frame metadata items, including illumination
data. The daemon already consumes MS-XU illumination metadata on the BRIO
(/dev/video5 on the thinkpad fleet host, "illumination metadata closed after N
classified frames"), so irlume is de facto speaking this control too.

### 1.3 Enhanced Sign-in Security (ESS)

ESS isolates the biometric path with Virtualization Based Security, TPM 2.0, an
OEM-configured SDEV ACPI table describing the biometric hardware, and for
fingerprint sensors a Microsoft-issued factory certificate; face sensors require
ESS-compatible drivers and firmware. System requirements:
https://learn.microsoft.com/en-us/windows-hardware/design/device-experiences/windows-hello-enhanced-sign-in-security

This is the trust model irlume's tiering parallels (TPM-sealed secrets, PCR
policies, measured boot); the SDEV idea, a firmware-signed description of the
sensor chain, is the closest industry analog to irlume's signed PCR policies
(Tier 1 and 2), and a useful vocabulary when documenting why a boot chain matters.

### 1.4 External camera policy

Windows allows forbidding external Hello cameras entirely via
`HKLM\Software\Microsoft\Windows\CurrentVersion\Authentication\LogonUI\FaceLogon\ShouldForbidExternalCameras`,
hardened after CVE-2021-34466 (July 2021 patches). irlume has no equivalent switch
today; see implications.
Source: the face authentication design doc, External camera security section.

### 1.5 Windows Biometric Framework

WBF is the OS service architecture (sensor adapters, engine adapters, storage) that
Hello plugs into; face is one sensor class among fingerprint and others.
Source: https://learn.microsoft.com/en-us/windows/win32/secbiomet/biometric-framework-overview

## 2. The Linux kernel and UVC layer

### 2.1 Extension unit access from userspace

uvcvideo exposes XU controls two ways: mapped onto V4L2 controls (enumerable, for
generic apps) and raw `UVCIOC_CTRL_QUERY` requests for uvcvideo-aware programs.
irlume uses the raw path, which is the only one that can speak the full UVC control
request set (GET_INFO, GET_LEN, GET_MIN/MAX/RES/DEF/CUR, SET_CUR) needed for safe
emitter discovery.
Source: https://docs.kernel.org/userspace-api/media/drivers/uvcvideo.html

### 2.2 The quirk taxonomy

`drivers/media/usb/uvc/uvc_driver.c` carries per-USB-ID quirks that explain most
camera misbehavior irlume's issue tracker sees: `UVC_QUIRK_PROBE_MINMAX`
(probe/commit lies about limits), `UVC_QUIRK_FIX_BANDWIDTH` (bandwidth
miscalculation, dual-camera hosts), `UVC_QUIRK_FORCE_Y8` (advertise Y8 to a camera
that only half supports it, the unbranded IR module path), `UVC_QUIRK_NO_RESET_RESUME`
(suspend or reset, pick one), `UVC_QUIRK_RESTRICT_FRAME_RATE`,
`UVC_QUIRK_RESTORE_CTRLS_ON_INIT` (controls lost across open, e.g. certain Chicony
units), `UVC_QUIRK_INVALID_DEVICE_SOF`, `UVC_QUIRK_MJPEG_NO_EOF`, and
`UVC_QUIRK_BUILTIN_ISIGHT` (Apple internal iSight on x86 Macs). Reading this table
before debugging any "my camera misbehaves" report is the fastest triage step.
Source: https://raw.githubusercontent.com/torvalds/linux/master/drivers/media/usb/uvc/uvc_driver.c
General UVC troubleshooting: https://www.ideasonboard.org/uvc/faq/

### 2.3 Fleet evidence that belongs in this layer

From irlume's own testing: qemu's emulated xhci corrupts USB3 isochronous video
(payloads dequeue short), which presents as an application bug but is a host
limitation; the BRIO refuses to run its IR emitter on a USB2/EHCI link at all; and
unplugged or replugged cameras change video node numbering, so everything must key
on identity (USB ID plus descriptor), never on /dev/videoN.

## 3. The emitter ecosystem (linux-enable-ir-emitter)

The reference userspace tool outside irlume is EmixamPP/linux-enable-ir-emitter. Its
README confirms several boundaries irlume shares:

- It configures UVC cameras only. Its automatic search historically wrote guessed
  payloads across units and selectors behind an interactive firmware-corruption
  warning; irlume removed exactly this class of search after the #159 camera damage
  and replaced it with descriptor-checked discovery (ir_emitter.rs module docs).
- The tool's model is configure once (writes a per-camera TOML), then `run` before
  each camera-using program, with an `--fd` pass-through for integrators. irlume's
  model instead persists the discovered control in its own config and applies it at
  capture, which removes the wrapper requirement.
- **The MIPI wall, in the tool's own words**: Meteor Lake-era and later laptops
  with Synaptics SVP7500 designs expose only a vendor-specific USB interface
  carrying an I2C tunnel; uvcvideo binds nothing, users see "no camera found", and
  the tool is explicit that this is out of UVC scope, pointing at
  https://github.com/jibsta210/svp7500-camera-fix-pack as a working stack.
Source: https://github.com/EmixamPP/linux-enable-ir-emitter

## 4. Built-in webcam taxonomy

**USB UVC modules** (the class irlume supports today): Chicony (VID 04f2, the
thinkpad and ASUS fleet units, and the #449 reporter's 60fps NexiGo N930W pairs a
Chicony-branded module), Shinetech (3277:0059, ASUS Zenbook), Sunplus-family and
Sonix modules behind house brands (NexiGo, Mi, generic). Vendor ID registry:
https://devicehunt.com/view/type/usb/vendor/04F2 . Behavior varies at the descriptor
level, not the brand level: same-product different-revision units ship different USB
IDs and different extension unit layouts (irlume issue #449: 3443:c803 versus
3443:930d, one validated, one still awaiting on-device evidence).

**MIPI CSI-2 behind an ISP** (the class irlume cannot reach): Intel IPU3 on older
thinkpads, IPU6/IPU7 from Meteor Lake onward, plus RKISP and equivalents. On Linux
these require libcamera and a matching IPA/HAL (Ubuntu ships libcamhal-ipu6 and
friends; users otherwise see no V4L2 device at all). The Ubuntu thread documents
the install set; the leie README documents the SVP7500 no-UVC case.
Source: https://discourse.ubuntu.com/t/intel-mipi-laptop-camera-not-working-24-04/63403

**Apple (Asahi)**: FaceTime HD cameras on Apple Silicon are ISP-attached sensors,
not UVC. Asahi's support table lists the webcam working via linux-asahi across
M1, M1 Pro/Max, and (with 2026 patches) M3 lines. No MacBook ever shipped an IR
face camera; face authentication on that hardware is out of scope by construction.
Sources: https://asahilinux.org/docs/platform/feature-support/m1/ and
https://www.phoronix.com/news/Asahi-Linux-M3-Release-Soon

**Privacy shutters and kill switches**: Lenovo ships physical ThinkShutter and
electronic e-shutter variants (Legion lines), and users routinely mistake a closed
shutter for camera failure (support threads exist for exactly this confusion).
HP and Dell ship equivalents. irlume's discovery already re-checks the shutter
immediately before each forward write; the support-doc evidence says the failure
mode is common enough to keep that check and to mention shutters in enrollment
messaging.
Source: https://forums.lenovo.com/t5/Gaming-Laptops/Integrated-Camera-says-its-blocked-or-shut-off-and-e-shutter-doesn-t-seem-to-work/m-p/10007161

## 5. OEM camera module specifications

What the manufacturers actually document, per OEM:

| OEM | Spec-sheet language (examples) | Notes |
|---|---|---|
| Lenovo (PSREF) | X1 Carbon Gen 9: "HD 720p", "HD 720p + IR hybrid", both with privacy shutter; Gen 10 adds "FHD 1080p + IR discrete, with privacy shutter, MIPI, fixed focus, Computer Vision" and "FHD 1080p + IR hybrid" | the hybrid versus discrete distinction (see below); flagship lines moved to MIPI with presence detection; recent ThinkPads all ship shutters |
| Dell (Latitude owner's manuals) | 5540 and 5440: IR still image 0.23MP, IR video 640x360 at 30fps, IR diagonal FOV 86.6 degrees, RGB FOV 78.6 to 80 degrees; 5330: "Human presence detection" | Dell publishes exact IR resolution and field of view, the most precise public numbers of the four |
| HP (EliteBook specs) | EliteBook 8 G1i: "5MP and IR camera" with "Image Signal Processing (ISP) and AI Presence Detection"; HP Presence software manages effects | the 5MP-plus-IR combination is the current business-class trend |
| ASUS | Zenbook 14 OLED: "Hello Infrared (IR) camera" marketed as a headline feature | the fleet's Zenbook S 14 Shinetech module (3277:0059) is exactly this class |
| Framework | No IR camera option to date; fingerprint reader instead; the community thread attributes the choice to IR sensitivity concerns and carries a long-running request (7.3k views) | the notable holdout; users cite the Brio's two-sensor design as the proven pattern |

Sources: https://psref.lenovo.com/syspool/Sys/PDF/ThinkPad/ThinkPad_X1_Carbon_Gen_9/ThinkPad_X1_Carbon_Gen_9_Spec.PDF ,
https://psref.lenovo.com/Product/ThinkPad/ThinkPad_X1_Carbon_Gen_10 ,
https://www.dell.com/support/manuals/en-us/latitude-15-5540-laptop/latitude-5540-owners-manual/camera ,
https://www.dell.com/support/manuals/en-us/latitude-13-5330-laptop/latitude_5330_ss/camera ,
https://support.hp.com/vn-en/document/ish_12121345-12121550-16 ,
https://www.asus.com/us/laptops/for-home/zenbook/asus-zenbook-14-ux3405/ ,
https://community.frame.work/t/windows-hello-ir-camera-support-for-framework-laptops/80590

**The module vendors behind the OEM badges:**

- Chicony (VID 04f2), the workhorse: Lenovo and ASUS integrated modules across
  generations (registry shows b008 "Asus Integrated 0.3M UVC Webcam", b61e on the
  Lenovo S340, b624, and the b6d9 and b7bf units that appear in irlume's hardware
  reports). https://devicehunt.com/view/type/usb/vendor/04F2
- Shinetech (3277): ASUS Zenbook units (the 0059 in the fleet).
- Sunplus-family (3443): house brands, including the NexiGo HelloCam variants
  split across c803 and 930d (#449).
- Realtek (0bda): PC camera controllers with a USB 2.0 interface line.
  https://www.realtek.com/Download/List?cate_id=595
- Sonix: the controller behind Dell G-series cameras ("Sonix Technology" device
  entries; OEM driver requests mention NPU-adjacent features).
  https://www.dell.com/community/en/conversations/inspiron/g15-5535-request-for-sonix-camera-driver-npu-support-site-only-lists-realtek/6955a0c472c11a30abce5ca3
- Synaptics: the SVP7500 MIPI designs on Meteor Lake-era machines, the no-UVC
  class from section 3.

**Cross-cutting spec facts:**

1. Hybrid versus discrete IR: hybrid is one module streaming RGB and IR together;
   discrete is a separate IR camera. The distinction maps directly onto irlume's
   capture-schedule decision (a hybrid module is the starved-RGB risk class that
   camera-tune measures; a discrete pair streams independently).
2. The IR resolution class is small and stable: 640x360 at 30fps with roughly 86
   degree FOV (Dell's numbers) against the Microsoft Hello minimum of 340x340 at
   15fps, which irlume's doctor already encodes.
3. The MIPI migration is feature-driven: the flagship options pair it with
   "Computer Vision" or presence detection (walk-away lock, wake on approach).
   Those features are OEM software on Windows; on Linux the same hardware is the
   class UVC tooling cannot reach, so the Linux gap is widest exactly where the
   hardware is newest.
4. Presence detection normalizes a camera that watches continuously while the
   session is live, which coexists with physical shutters in the same spec sheets.
   That is a policy conversation irlume should have explicitly (it stays
   request-scoped today) rather than inherit by accident.

## 6. External USB webcams

- **Logitech Brio family**: on Windows, Hello requires selecting the dedicated
  "Brio for Windows Hello" camera entry (the module exposes separate interfaces
  for media and for face auth); users regularly report Hello breakage after
  firmware updates and platform changes. On Linux the emitter needs per-device
  configuration (leie or irlume ir-setup), refuses USB2 links (fleet evidence,
  EHCI), and the metadata node appears as an extra /dev/videoN.
  Sources: https://hub.sync.logitech.com/brio/post/can-i-use-brio-brio-4k-webcam-with-windows-hello-jHuWzqvZKvqCaxg ,
  https://learn.microsoft.com/en-us/answers/questions/3233757/windows-hello-could-not-turn-on-the-camera ,
  https://www.reddit.com/r/LogitechG/comments/pj54t4/brio_4k_stream_windows_hello_not_working/
- **Intel RealSense F200/SR300**: the original depth-based Hello cameras,
  deprecated and widely broken on modern Windows; their failure mode (driver
  abandonment after ecosystem change) is the cautionary tale for relying on
  depth-specialized hardware.
  Source: https://support.realsenseai.com/hc/en-us/articles/360022951533-Windows-10-Issues-with-Intel-RealSense-Cameras-SR300-and-F200
- **NexiGo HelloCam**: 30fps (c803) and 60fps (930d) variants are different
  devices to the emitter stack; #449 tracks the 60fps unit. NexiGo modules also
  starve their own RGB interface under concurrent capture (measured 56 percent
  brightness retention in the camera-tune docs), which is why irlume measures
  capture qualification per pair instead of assuming concurrent is safe.

## 7. Manufacturer control software

On Windows the OEM tools (Logitech G Hub and Logi Tune, Lenovo Vantage, Dell and
HP equivalents) are the surface users know; they control exposure, FOV, IR modes
on some modules, and privacy states. None of them exist on Linux; the functional
gaps are covered piecemeal by v4l2-ctl, uvcdynctrl (XU mapping), libuvc, and
leie for emitters. irlume therefore IS the manufacturer control software for its
hardware scope on Linux, which is the standing justification for its careful,
descriptor-checked control surface rather than a thin wrapper over vendor tools.

## 8. ChromeOS

ChromeOS requires external webcams to be plain UVC 1.0+ devices working with the
in-tree uvcvideo driver, USB 2.0 and above, and a hardware activity indicator that
truthfully reports capture with no software control over it. The camera stack is
the cros-camera service over Android-style HAL3 (arc-camera), which is where CrOS
parked its own UVC quirk handling.
Sources: https://developers.google.com/chromeos/peripherals/cc-webcams-v1 ,
https://chromium.googlesource.com/chromiumos/platform/arc-camera/+/HEAD/hal/usb/camera_hal.cc

ChromeOS itself has no face unlock; Google's IR face unlock work (Project Toscana,
under-display IR on future Pixels) is Android-phone-side, useful only as a trend
signal that IR face auth is expanding, not contracting.
Source: https://www.androidauthority.com/google-project-toscana-3641601/

## 9. The howdy ecosystem's lessons

Howdy's long tail of camera issues matches irlume's: IR streams not recognized
(its issue #6 is the archetype), emitters that FLASH rather than stay lit (unlit
frames defeat frame-based capture; howdy users switch capture backends to
ffmpeg-style grabbing), and a persistent public misperception that any 2D-IR-only
system is trivially spoofable. irlume's answers to the first two (identity-keyed
capture, in-burst optical D1 correlation against emitter phase) are ahead of the
ecosystem; the third is a documentation and PAD-publishing problem, already
addressed by docs/PAD_SELFTEST.md and FAIRNESS.md.
Source: https://github.com/boltgolt/howdy/issues/6

## 10. Ecosystem issue-tracker mining

What the other projects' open and recently closed trackers say about cameras
(all checked 2026-08-27):

**linux-enable-ir-emitter** (issues):
- #299 (closed): "IR emitter constantly flickers when device is opened". Cameras
  whose emitters pulse rather than hold steady; under the wrapper model every
  program open is a fresh apply, so the flicker is user-visible. irlume's
  in-daemon apply per capture plus its in-burst optical correlation already treat
  emitter phase as a measured fact rather than an assumption.
- #283 (open): "Using with howdy: sometimes fails with exit code 1". The
  run-before-program integration seam is fragile; irlume avoids the wrapper
  pattern entirely by applying at capture inside the daemon.
- #297 (closed): the MIPI/IPU scope note summarized in section 3.
Source: https://github.com/EmixamPP/linux-enable-ir-emitter/issues

**howdy** (issues):
- #543 (open): IR emitters not working on Dell Inspiron 5567. #269 (open): IR
  emitters not turning on on Lenovo S740. #1020 (closed): ThinkPad T480 new IR
  camera not working. A standing open tail of per-device emitter failures, the
  same class as irlume #449.
- #822 (closed): "Howdy unlocked my PC (Ubuntu 22.04) using an image". A phone
  selfie shown to the camera unlocked the machine; the reporter's own test. This
  is the defining security incident of the ecosystem's default posture (no
  presentation-attack detection) and the concrete citation for why irlume ships
  two PAD models on by default.
Source: https://github.com/boltgolt/howdy/issues

**libuvc** (issues):
- #299 (open): ENOMEM on Android when starting a stream, caused by large
  isochronous transfer buffers. Isochronous buffer sizing is a universal pain,
  the userspace mirror of the kernel's bandwidth quirks.
- #300 (open): NULL dereference in uvc_scan_streaming, a descriptor-driven crash
  on an odd camera; a reminder that parsing untrusted descriptors is a parsing
  problem (irlume keeps its descriptor reader separate and fuzzed).
- #284 (open): "Project status?", the maintenance question for anything building
  on libuvc. irlume's v4l2-sys-mit bindings and raw ioctl path avoid the
  dependency.
Source: https://github.com/libuvc/libuvc/issues

**uvcvideo upstream (torvalds/linux, current media tree commits)**:
- Active work clusters on hardware timestamping ("Relax the constraints for
  interpolating the hw clock", "Fix dev_sof filtering in hw timestamp", "Do not
  add clock samples with small sof delta", "Use hw timestamping if the clock
  buffer is full") and on metadata delivery ("Avoid partial metadata buffers").
  Both areas intersect irlume directly: pairing-skew measurement depends on
  frame timing, and MS-XU metadata is the illumination channel. Skew-sensitive
  capture qualification should be re-validated across major kernel upgrades,
  which is already fleet practice after #518.
Source: `git log drivers/media/usb/uvc/` via
https://github.com/torvalds/linux/commits/master/drivers/media/usb/uvc

## 11. Engineering implications for irlume

1. **Discovery can be fully spec-driven.** The Face Authentication Control payload
   structure is specified (bNumEntries, interface, D1/D2). Discovery can construct
   spec-conformant candidates from GET_MAX answers rather than replaying validated
   blobs, which is the principled path to covering unvalidated USB IDs like
   3443:930d without per-device table entries. The built-in table then shrinks to
   a compatibility-record role.
2. **Consume IR Torch where advertised.** Some modules expose 0x0A; discovery
   already tries it first. The spec's default-ACTIVE rule stays encoded.
3. **Standardize on MS-XU metadata illumination** wherever a metadata node
   exists (BRIO already parsed opportunistically); it is the only cross-vendor
   ambient signal with a spec behind it.
4. **Detect and speak honestly about the MIPI class.** A machine where the camera
   is IPU6/SVP7500 presents "no UVC camera"; doctor and detect should say
   "this camera is behind an ISP that Linux exposes through libcamera, which
   irlume does not support yet" instead of a generic not-found. Detection signal:
   camera absent from uvcvideo while dmesg or /sys shows ipu6, svp, or a
   vendor-specific USB interface with an I2C tunnel.
5. **An external-camera policy switch** mirroring ShouldForbidExternalCameras
   (config: forbid external cameras for auth) would match Microsoft's posture
   post-CVE-2021-34466 for policy-sensitive deployments.
6. **The ESS vocabulary for docs**: describe irlume's TPM tiers using the SDEV
   analogy (firmware-attested sensor chain) when documenting why boot chain state
   gates credential release.
7. **Quirk-first triage**: link uvc_driver.c's quirk table from DEBUGGING.md's
   camera section so reporters and maintainers check kernel-level explanations
   before blaming capture code.
8. **Accuracy bars for public comparison**: the Hello numbers (FAR below 1/100,000,
   TPR above 95 percent, multi-user threshold raising) are the reference points
   FAIRNESS.md should be read against when users ask "is it as good as Hello".
9. **Cite the incident, not the abstraction**: howdy #822 (a phone photo
   unlocking the machine) is the concrete reason PAD ships enabled; keep it
   linked from the FAQ and FAIRNESS.md so the posture is grounded in the
   ecosystem's documented failure, not in adjectives.
10. **Kernel-upgrade skew watch**: upstream uvcvideo is actively changing
    timestamping and metadata delivery; keep the post-kernel-upgrade capture
    qualification run in the fleet checklist.

## Open questions

- Whether SVP7500-class cameras can ever expose their IR sensor through a
  mainline path (the fix-pack repo is vendor-specific); watch libcamera and
  ipu6 development.
- Whether under-display IR (Project Toscana lineage) reaches laptops, which would
  add a new emitter behavior class (duty cycling invisible to the eye).
- Real-world frequency of cameras advertising D2 rather than D1 face-auth mode;
  irlume's discovery should record which mode a module accepted and report it in
  the evidence chain when promoting USB IDs to the built-in table.

## Sources

Primary specifications and kernel source:

- MS-XU 1.5 specification (selector table, Face Authentication, IR Torch, Metadata):
  https://learn.microsoft.com/en-us/windows-hardware/drivers/stream/uvc-extensions-1-5
- Windows Hello face authentication design (NIR rationale, accuracy bars, external
  camera registry, CVE-2021-34466):
  https://learn.microsoft.com/en-us/windows-hardware/design/device-experiences/windows-hello-face-authentication
- Enhanced Sign-in Security (VBS, TPM 2.0, SDEV, sensor certificates):
  https://learn.microsoft.com/en-us/windows-hardware/design/device-experiences/windows-hello-enhanced-sign-in-security
- Biometric hardware requirements:
  https://learn.microsoft.com/en-us/windows-hardware/design/device-experiences/windows-hello-biometric-requirements
- Windows Biometric Framework overview:
  https://learn.microsoft.com/en-us/windows/win32/secbiomet/biometric-framework-overview
- uvcvideo userspace API (XU access mechanisms):
  https://docs.kernel.org/userspace-api/media/drivers/uvcvideo.html
- uvcvideo driver source with the quirk table:
  https://raw.githubusercontent.com/torvalds/linux/master/drivers/media/usb/uvc/uvc_driver.c
- Linux UVC FAQ: https://www.ideasonboard.org/uvc/faq/

Ecosystem and platforms:

- linux-enable-ir-emitter (UVC scope, MIPI/IPU6 note, integration model):
  https://github.com/EmixamPP/linux-enable-ir-emitter
- SVP7500 camera fix pack: https://github.com/jibsta210/svp7500-camera-fix-pack
- Ubuntu IPU6 libcamera stack thread:
  https://discourse.ubuntu.com/t/intel-mipi-laptop-camera-not-working-24-04/63403
- Asahi M1 feature support (webcam status):
  https://asahilinux.org/docs/platform/feature-support/m1/
- Asahi M3 webcam patches reporting:
  https://www.phoronix.com/news/Asahi-Linux-M3-Release-Soon
- ChromeOS Compatible webcams spec v1.3 (UVC 1.0+, activity LED mandate):
  https://developers.google.com/chromeos/peripherals/cc-webcams-v1
- CrOS camera HAL: https://chromium.googlesource.com/chromiumos/platform/arc-camera/+/HEAD/hal/usb/camera_hal.cc
- Project Toscana (Pixel IR face unlock):
  https://www.androidauthority.com/google-project-toscana-3641601/

Hardware and OEM:

- Chicony VID 04F2 registry: https://devicehunt.com/view/type/usb/vendor/04F2
- Lenovo e-shutter confusion thread:
  https://forums.lenovo.com/t5/Gaming-Laptops/Integrated-Camera-says-its-blocked-or-shut-off-and-e-shutter-doesn-t-seem-to-work/m-p/10007161
- Logitech Brio Hello usage and breakage:
  https://hub.sync.logitech.com/brio/post/can-i-use-brio-brio-4k-webcam-with-windows-hello-jHuWzqvZKvqCaxg ,
  https://learn.microsoft.com/en-us/answers/questions/3233757/windows-hello-could-not-turn-on-the-camera ,
  https://www.reddit.com/r/LogitechG/comments/pj54t4/brio_4k_stream_windows_hello_not_working/ ,
  https://community.frame.work/t/windows-hello-support-with-logitech-brio/77325
- RealSense F200/SR300 deprecation:
  https://support.realsenseai.com/hc/en-us/articles/360022951533-Windows-10-Issues-with-Intel-RealSense-Cameras-SR300-and-F200
- Howdy IR recognition archetype issue:
  https://github.com/boltgolt/howdy/issues/6

Internal evidence (this repository and fleet):

- ir_emitter.rs module and discovery docs (descriptor-checked writes, journal,
  restore-on-no-effect, IR Torch default note)
- Issue #159 (blind emitter search camera damage) and issue #449 (930d versus c803)
- Fleet reports: thinkpad Omarchy session 2026-08-27 (BRIO USB3, GREY-only IR
  heuristic, metadata node), archhost VM session 2026-08-25 (qemu xhci isochronous
  corruption, BRIO USB2 emitter refusal)

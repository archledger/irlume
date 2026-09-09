# Windows Hello camera-control dossier (primary-source research)

Date: 2026-08-22
Provenance: delegated research agent, primary sources fetched and verified
this session (Microsoft Learn, USB-IF UVC 1.5, Linux kernel docs,
linux-enable-ir-emitter). Evidence labels: [DOCUMENTED] stated at the cited
source; [MEASURED] irlume fleet numbers; [INFERENCE] reasoned.

## Correction after the ThinkPad study (2026-09-08)

The original August interpretation confused an IR stream's control interface
with the complete authentication pipeline. Microsoft explicitly documents RGB
and IR input for Hello anti-spoofing; the September 4 ThinkPad/BRIO trace also
observed both streams. An IR-specific control does not prove that RGB is unused.
The corrected conclusions below supersede that interpretation. Irlume's optional
IR-only proposal therefore needs its own qualification and is not Hello parity.
[Current Microsoft privacy guidance](https://learn.microsoft.com/en-us/windows-hardware/drivers/stream/camera-privacy-controls#shutters-with-multiple-cameras-on-a-panel).

## Published hardware requirements, not local certification results

- Average authentication duration **< 2 s**, re-auth **< 2 s** [FACE-AUTH].
- Stream **startup < 500 ms** for the face-auth IR stream (HLK gate) [BRINGUP].
- Sustained **15 fps minimum while strobing** (lit AND ambient), ≥320x320,
  L8/NV12 [BRINGUP]. Local NexiGo measurements of 14.73-14.79 fps are
  measurements on Irlume's Linux path. They do not establish a Windows HLK
  result or the device's certification status.
- FAR < 0.001%, TAR > 95% [BIOREQ].

## Documented face-authentication illumination modes

The documented face-authentication modes support device-controlled alternating
illumination or background subtraction, with the metadata contract below
[DDI, MSXU]. This describes the interface; it does not establish every control
write made by a particular Windows driver during authentication:

- `FACEAUTH_MODE_ALTERNATIVE_FRAME_ILLUMINATION`: "alternate IR strobe on/off
  for each frame captured", illumination flag mandatory on each sample.
- `FACEAUTH_MODE_BACKGROUND_SUBTRACTION`: camera delivers
  ambient-subtracted frames, no metadata.

The mode contract does not establish that Windows performs no per-attempt
control writes. Compare actual device traces before attributing a performance
difference to Irlume's session setup or restore behavior.

## The Microsoft extension unit (MSXU)

`MS_CAMERA_CONTROL_XU`, GUID `{F3F95DC-2632-4C4E-92C9-A04782F43BC8}`
[MSXU §2.2.2]. Selectors: Focus 0x01, **Exposure 0x02** (asynchronous:
completion via UVC 1.5 control-change interrupt), EV Comp 0x03, WB 0x04,
**Face Authentication 0x06** (per-stream-interface mode bits D0/D1/D2),
Extrinsics 0x07, Intrinsics 0x08, Metadata 0x09, **IR Torch 0x0A**
(OFF/ON/ALTERNATING + vendor power level; defaults apply "before streaming
begins"). The face-auth control addresses ONLY IR streaming interfaces; the
worked example omits the RGB interface entirely.

Linux exposure: `V4L2_META_FMT_UVC` ('UVCH') = host ts + USB SOF + payload
header per frame; `V4L2_META_FMT_UVC_MSXU_1_5` ('UVCM') adds the Microsoft
metadata including per-frame illumination [K-UVC, K-MSXU].

A descriptor/capability read can establish whether the XU is advertised.
`SET_CUR` changes device state; it is not a read-only probe. An advertised XU
alone does not prove working illumination metadata, successful restore, or that
capture selection can be removed. Validate those behaviors on the particular
camera before changing Irlume's existing control and frame-selection path.
See [camera-control safety](2026-08-22-camera-control-safety-dossier.md).

## RGB participates in Hello authentication

An IR face-authentication stream has IR-specific controls and illumination
metadata. The complete Hello pipeline also uses RGB for anti-spoofing. Its
proprietary fusion and synchronization rules are not established by these
public interfaces. Irlume's cross-spectrum timing and PAD policies therefore
need their own evidence; describing them as a proven superset of Hello was
unsupported. [Microsoft privacy guidance](https://learn.microsoft.com/en-us/windows-hardware/drivers/stream/camera-privacy-controls#shutters-with-multiple-cameras-on-a-panel).

## Documented startup requirements and interfaces

1. Stream startup < 500 ms in the cited HLK test.
2. IR sensor registration as `KSCATEGORY_SENSOR_CAMERA`; optional
   `SkipCameraEnumeration` hides it from legacy camera-app enumeration.
   This does not establish absence of contention.
3. FrameServer architecture for brokered capture.
4. INF-declared device capabilities.
5. The IR Torch interface defines a pre-stream default mode. Actual control
   writes and latency effects require device traces.
6. ESS: hypervisor-isolated frame path (not portable).

Possible Linux experiments include session lifetime and startup-cost measurement.
The cited Windows interfaces do not endorse Irlume keeping streams armed during
other work. Queue freshness, ownership, cancellation and emitter restoration
must remain tested requirements for any such optimization.

## Multi-camera synchronization

The inspected public interfaces describe camera profiles and
extrinsics/intrinsics [PROFILES, MSXU]; they do not establish the proprietary
matcher's permitted skew or prove that every rig lacks hardware synchronization.
Irlume's paired-window skew limit remains grounded in its own measurements.

## Sources

- FACE-AUTH: https://learn.microsoft.com/en-us/windows-hardware/design/device-experiences/windows-hello-face-authentication
- BRINGUP: https://learn.microsoft.com/en-us/windows-hardware/drivers/stream/windows-hello-camera-driver-bring-up-guide
- DDI: https://learn.microsoft.com/en-us/windows-hardware/drivers/stream/ksproperty-cameracontrol-extended-faceauth-mode
- META: https://learn.microsoft.com/en-us/windows-hardware/drivers/stream/mf-capture-metadata
- MSXU: https://learn.microsoft.com/en-us/windows-hardware/drivers/stream/uvc-extensions-1-5
- ESS: https://learn.microsoft.com/en-us/windows-hardware/design/device-experiences/windows-hello-enhanced-sign-in-security
- BIOREQ: https://learn.microsoft.com/en-us/windows-hardware/design/device-experiences/windows-hello-biometric-requirements
- PROFILES: https://learn.microsoft.com/en-us/windows-hardware/drivers/stream/camera-profiles
- UVC15: https://www.usb.org/document_library/video-class-v15-document-set
- K-UVC: https://raw.githubusercontent.com/torvalds/linux/master/Documentation/userspace-api/media/v4l/metafmt-uvc.rst
- K-MSXU: https://raw.githubusercontent.com/torvalds/linux/master/Documentation/userspace-api/media/v4l/metafmt-uvc-msxu-1-5.rst
- LEIE: https://github.com/EmixamPP/linux-enable-ir-emitter

Corrections en route: howett.net hosts no Hello IR research (verified); the
LinHello GitHub org is gone (0 public repos); the living tool is
linux-enable-ir-emitter.

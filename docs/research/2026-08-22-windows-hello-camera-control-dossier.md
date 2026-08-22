# Windows Hello camera-control dossier (primary-source research)

Date: 2026-08-22
Provenance: delegated research agent, primary sources fetched and verified
this session (Microsoft Learn, USB-IF UVC 1.5, Linux kernel docs,
linux-enable-ir-emitter). Evidence labels: [DOCUMENTED] stated at the cited
source; [MEASURED] irlume fleet numbers; [INFERENCE] reasoned.

## Headline numbers (Microsoft's own bar)

- Average authentication duration **< 2 s**, re-auth **< 2 s** [FACE-AUTH].
- Stream **startup < 500 ms** for the face-auth IR stream (HLK gate) [BRINGUP].
- Sustained **15 fps minimum while strobing** (lit AND ambient), ≥320x320,
  L8/NV12 [BRINGUP]. (The NexiGo N930W IR at 14.73-14.79 fps measured would
  fail this outright — it is a below-certification-bar device, which reframes
  its 0.4% rate-floor margin as a hardware qualification fact, not a tuning
  nuisance.)
- FAR < 0.001%, TAR > 95% [BIOREQ].

## The core mechanism: firmware-per-frame strobe

Hello never times the emitter against frames from the host. The driver sets
ONE mode; the camera alternates the IR strobe every frame at full rate and
tags every frame lit/unlit in metadata [DDI, MSXU]:

- `FACEAUTH_MODE_ALTERNATIVE_FRAME_ILLUMINATION`: "alternate IR strobe on/off
  for each frame captured", illumination flag mandatory on each sample.
- `FACEAUTH_MODE_BACKGROUND_SUBTRACTION`: camera delivers
  ambient-subtracted frames, no metadata.

No emitter write sits on the per-authentication hot path. This is the single
biggest structural difference from irlume's D1-write-per-session model.

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

**Action for irlume (cheap, read-only): probe the fleet for this XU.** If
present on a camera: SET_CUR face-auth/torch mode moves the strobe into
firmware (deleting D1 write/restore from the hot path), and the MSXU
metadata node gives a deterministic per-frame lit bit (replacing
brightest-of-burst heuristics). Selector 0x02 is a documented manual-exposure
path. Absent → current path unchanged. Subject to the XU safety guardrails
(docs/research/2026-08-22-camera-control-safety-dossier.md).

## RGB is not part of Hello auth

The recognition pipeline is described entirely on IR input; the MSXU
face-auth control cannot even address the RGB interface; illumination
metadata must never appear on RGB samples [FACE-AUTH, MSXU, META]. Windows
has no cross-spectrum skew problem because it never pairs spectra. Irlume's
joint RGB PAD is a deliberate superset (print-species coverage); ADR-0014 is
what keeps it reachable on sequential hardware.

## Startup-latency techniques (documented)

1. < 500 ms hard budget to first frame.
2. IR sensor registered as `KSCATEGORY_SENSOR_CAMERA` + enumeration-hiding
   (`SkipCameraEnumeration`): always-present node, no app contention.
3. FrameServer-shareable auth pin: brokered, persistent pipeline.
4. Static INF-declared capabilities (no runtime discovery).
5. Torch defaults armed before streaming.
6. ESS: hypervisor-isolated frame path (not portable).

Linux analogs we can act on: held/pre-armed sessions (the broker model),
autosuspend management, and MSXU probing. Pre-arm STREAMON-during-RGB-phase
is the Windows-endorsed direction (broker holds the pipeline warm).

## Multi-camera synchronization

No hardware sync, no documented skew tolerance. Pairing is software-only via
camera profiles (CONCURRENCYINFO hints); geometric correspondence comes from
MSXU extrinsics/intrinsics per rig [PROFILES, MSXU]. Our paired-window skew
gate has no Microsoft counterpart to calibrate against; ADR-0014's
derivation stands on our own measurements.

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

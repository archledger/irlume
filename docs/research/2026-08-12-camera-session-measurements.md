# Camera session measurements, 2026-08-12 (Zenbook, user READY)

Instrument: v4l2-ctl 1.30 / udevadm / media-ctl on Fedora 44, kernel
7.1.8-200.fc44, ASUS built-in UVC pair (video0/1 RGB + metadata, video2/3 IR
+ metadata). All reads before any write; every write below is named.

## #426: backlight compensation

- **The defect, live**: before this session touched anything,
  `backlight_compensation` on /dev/video0 read **2** with driver default
  **0** (min 0, max 2). Nothing but irlume writes that control here, so
  this is irlume's unrestored write from an earlier session sitting on the
  camera for every other application. Persistence across process exit is
  thereby demonstrated on real hardware, matching the documented rule.
- The IR node (/dev/video2) has NO backlight-compensation control; the
  write exists only on the RGB session path.
- **Effect on this camera** (user seated, ordinary room light; YUYV
  640x480, 40 frames per run, mean luma of the last 8 after AE settle,
  sampled every 4th pixel):
  - blc=0: center-region mean 138.5, full-frame mean 100.8
  - blc=2: center-region mean 150.6, full-frame mean 118.0
  - A real, modest lift here (+12 center); the NexiGo's recorded
    justification (face mean 49 to 124) remains the strong case.
- NexiGo (minihost) unreachable during the session (Tailscale timeout, no
  LAN route); its control state was not read. Not needed for the decision:
  effect is recorded in-repo, persistence proven here.
- ThinkPad X13 Yoga Gen 4 (read over SSH, same session): its built-in
  camera reports min 0, max 2, **default 1**, current 1. A restore that
  wrote the driver default instead of the displaced value would be wrong on
  that camera; the displaced-value rule is right on all three by
  construction.
- **Decision: keep the write, restore the displaced value on session end**
  (same displaced-value rule as the emitter guard: put back what was
  there, never the driver default, and only when the control still holds
  what irlume wrote).
- Session end state: the control was reset to the driver default (0) by
  hand, since the pre-session value 2 was itself irlume's leftover. The
  PACKAGED daemon will re-write 2 on its next RGB session until a release
  carries the fix.

## #428: contention-free classification, verified on real nodes

Every prediction from the audit's source reading held on hardware, with no
video node opened for any of it:

- **udev**: `ID_V4L_CAPABILITIES` reads `:capture:` on video0/video2 and a
  bare `:` on video1/video3 (v4l_id has no META_CAPTURE branch), so
  capture-vs-metadata needs zero opens.
- **QUERYCAP words** (via v4l2-ctl, which does open, used here only to
  confirm the words): capture nodes 0x04200001, metadata nodes 0x04a00000,
  no IO_MC on any UVC node, so the merged #425 gate passes them through.
- **Media topology**: /dev/media0 groups the RGB pair, /dev/media1 the IR
  pair; the capture node carries entity `flags 1` (MEDIA_ENT_FL_DEFAULT)
  and sits in the UVC chain; metadata nodes are padless and linkless.
- **Descriptors blob** (`/sys/.../descriptors`, stable ABI): the RGB VS
  interface advertises MJPEG + YUY2; the IR VS interface advertises GUID
  `32000000-0200-1000-8000-00aa00389b71`, which is **KSMEDIA_L8_IR**, the
  Windows Hello IR format GUID, mapped by the kernel's own table
  (`drivers/media/common/uvc.c`) to V4L2_PIX_FMT_GREY. The first write-up
  of this session misread it as D3DFMT_L8, whose byte 4 is 0x00 where
  this GUID carries 0x02; copying the kernel header's definitions rather
  than eyeballing hex is what caught it. An irlume descriptor-based
  classifier must carry the whole L8 family (Y8, Y800, D3DFMT_L8,
  KSMEDIA_L8_IR), or this laptop's own IR camera would classify as
  format-unknown.

These are the measured basis for #428's implementation and #426's fix.

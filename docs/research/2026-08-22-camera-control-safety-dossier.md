# Camera-control safety dossier (can irlume brick the user's camera?)

Date: 2026-08-22
Provenance: delegated research agent, primary sources (USB-IF UVC 1.1 spec,
Linux kernel source + docs, kernel bugzilla, howdy/linux-enable-ir-emitter
trackers). [D] = documented incident/behavior; [T] = theoretical, no
documented incident found.

## Bottom line

**No verified permanent brick from a standard UVC SET_CUR was found
anywhere.** The only documented damage class is blind/brute-force writes to
VENDOR extension units. Standard PU/CT controls (exposure, brightness,
backlight comp) are the most-exercised control surface in consumer Linux
(every browser/OBS/guvcview writes them daily) with zero located permanent-
damage incidents. Irlume's current design (read-before-write, restore
guards, emitter journal, restore-on-drop) matches or exceeds every
documented community pattern; the kernel's own control-restore does NOT
cover raw XU writes, so our journal/restore is the only restore those get.

## Documented failure modes and recovery

| Failure | Recovery | Source |
|---|---|---|
| Brute-force XU scanning corrupts firmware | none from userspace; vendor re-flash | linux-enable-ir-emitter's explicit informed-consent warning |
| XU value stuck (e.g., emitter on, control unresettable) | **cold shutdown, NOT reboot** (embedded cams keep VBUS across warm reboot) | linux-enable-ir-emitter README |
| Control transfer timeout/STALL wedged (-110/-32) | USB re-enumeration (replug/bus reset) | kernel bugs 14406, 216810 |
| Out-of-range values crash buggy devices | replug | kernel bug 12824 |
| Emitter stuck semi-on after capture | reopen/reprobe | howdy issues 19, 1058, 884 |
| Controls lost after reset-resume | kernel restores flagged standard controls only | uvc_ctrl.c; bug 209597 |

## Control-class safety table

| Class | Verdict |
|---|---|
| Standard PU/CT via V4L2 IDs (exposure mode/priority/time, gain, brightness, backlight comp), clamped to GET_MIN/GET_MAX | **Safe** |
| Format/interval negotiation (PROBE/COMMIT) | **Safe** (kernel-mediated) |
| Known Hello emitter XU on whitelisted vid:pid, full protocol | **Conditional** — the one control with a documented cousin-class failure |
| Any other vendor XU selector/GUID | **Never blind** |
| XU payload > GET_LEN or multi-write burst sequences | **Never** (firmware-load signature) |
| Any write during autosuspend transition without a power ref | **Never** (hold the fd first) |

## Guardrails for the planned work (pre-arm, manual exposure, long sessions)

1. Whitelist vendor XU use by vid:pid: GUID + unit + selector + expected
   length + semantics pinned; refuse unknown firmware.
2. Hold the device node open across the whole session (power reference,
   autosuspend exclusion).
3. GET_INFO (SET supported?) then GET_LEN (exact match) before any XU write;
   abort on mismatch, never pad.
4. GET_CUR and save pre-write value; journal (we already do).
5. Single write, no retry storm; on -110/-32 stop and treat as wedged.
6. Readback-verify; mismatch = wedged, not "write harder".
7. Manual exposure lock: safe class; restore AE MODE before exposure time on
   drop (kernel's own restore ordering).
8. Pre-arm: negotiate and buffer only — do NOT enable the emitter until an
   attempt starts (idle pre-armed session = zero emitter duty, zero XU
   writes).
9. Long sessions: fine per kiosk/signage practice; add a wall-clock cap and
   a journal-derived emitter-on-seconds/day bound (no vendor publishes a
   duty spec).

## Emitter LED risk

No documented overheating/degradation incident for Hello-style cameras; the
dominant Linux ecosystem model already holds emitters on for whole capture
sessions (linux-enable-ir-emitter, howdy) with years of field use. Windows
pulses per capture. Theoretical risks (junction temp, LED lifetime, sensor
heat-soak) are bounded by auth-session lengths.

## Recovery ladder (documented order)

1. Re-SET_CUR the saved value, verify readback.
2. Close node → autosuspend → reopen (re-inits many wedged state machines).
3. USB re-enumeration (unbind/rebind, usbreset); re-issue XU restore after.
4. Replug (external) or **full shutdown with power removed, not reboot**.
5. Vendor re-flash (nothing in irlume should ever reach it).

## Sources

- USB Video Class 1.1 spec: https://www.usb.org/sites/default/files/USB_Video_Class_1_1_090711.zip
- Kernel uvcvideo docs (XU protocol, UVCIOC_CTRL_QUERY): https://docs.kernel.org/6.1/userspace-api/media/drivers/uvcvideo.html
- uvc_ctrl.c / uvc_driver.c / uvcvideo.h (restore paths, quirks, 5 s control
  timeout): https://github.com/torvalds/linux/blob/master/drivers/media/usb/uvc/
- linux-enable-ir-emitter (corruption warning, cold-boot recovery):
  https://github.com/EmixamPP/linux-enable-ir-emitter
- Kernel bugs: 12824, 14406, 216810, 209597 (bugzilla.kernel.org)
- Howdy emitter issues: 19, 884, 1058 (github.com/boltgolt/howdy)
- Field reports (autosuspend/streaming): RPi forum 285604, openSUSE 144563,
  Manjaro 131684

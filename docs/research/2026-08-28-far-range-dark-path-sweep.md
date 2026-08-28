# Far-range dark-path sweep: where IR face detection stops, and why

Date: 2026-08-28. Agent: opencode. Session: closing the "far-range dark-path
observation" follow-up from the SecureDark stage-3 session (the recorded n=1:
"far-range auth-path IR faces=0 vs 100% offline detection, needs controlled
distance sweep").

## Question

At what distance does the dark-path (IR-only) authentication stop finding a
face, is the live auth path's failure the same distance an independent
capture+detect probe fails at (selection defect, #264 territory), and what
physically binds the limit?

## Setup

- Host: archhost, irlume 0.11.2-1, daemon-owned cameras, diagnostic tracing
  on for the session.
- Camera: Logitech BRIO pair (rgb /dev/video4, ir /dev/video6, IR 340x340
  GREY), enrollment bound to this camera (10 scans; the on-host profile
  predates the NexiGo, which is why the BRIO pair was used).
- Room: dark (RGB frames mean 16, faces=0 throughout; the RGB side of the
  sweep never sees a face, so every dark round exercises the ir/dark path).
- Subject distances from the lens, stride-measured (about 10 cm accuracy).
- Two instruments per round:
  1. LIVE: `irlume auth test --events=jsonl` (the full daemon path: burst
     capture, gate-frame selection, illumination metadata, dark-path
     liveness, matching) with journal per-stage lines.
  2. DIRECT: `sudo IRLUME_DEV=1 irlume liveness --det <yunet> --rgb
     /dev/video4 --ir /dev/video6`, which captures its own fresh frame,
     drives the emitter itself, and runs the detector, bypassing the
     daemon's burst selection entirely.

## Results

| distance | live IR faces (top-det) | direct IR faces (top-det) | dark outcome |
|---|---|---|---|
| 0.5 m | 1 (0.94) | not run | granted, main arm 0.737 vs 0.685 |
| 1.0 m | 1 (0.94) | 1 (0.937) | granted, centroid arm 0.665 vs 0.635 (main 0.679 missed 0.685 by 0.006) |
| 1.1 m | 1 (0.93) | 1 (0.929) | granted, main arm 0.740 vs 0.685 |
| 1.25 m | 0 (two attempts) | 0 (frame mean 150.1) | not-live: "no face in RGB; present your face" |
| 1.5 m | 0 (two attempts) | 0 (frame mean 150.6) | not-live, password fallback |
| 1.5 m, LIT control | 1 (0.94) | n/a | granted via RGB 0.685 vs 0.600; cross-spectrum liveness Live |

Every failing round failed closed: no crash, no stall, no grant; the events
stream answered `not-live` and the journal carried the per-stage reason.

## Findings

1. **The n=1 anomaly did not reproduce as a selection defect.** At every
   distance the live auth path and the independent direct probe agreed
   exactly (faces=1 at 0.5-1.1 m, faces=0 at 1.25-1.5 m). Nothing observable
   supports "the auth path loses a face that a straight capture+detect finds".
   The original n=1 remains unexplained but is now bracketed by a controlled
   sweep that shows no such divergence on this camera.
2. **The dark-path detection boundary is 1.1-1.25 m on the BRIO**, and the
   lit control pins the cause: at 1.5 m WITH ambient light the SAME IR sensor
   found the face (0.94). So the limit is not sensor resolution or face size;
   it is the active-IR illumination range. In darkness the only illumination
   is irlume's emitter, and the face's return falls with distance (the
   landmark-relief PAD study already recorded the 1/r^2 falloff dominating at
   range), while the frame does not get darker overall (mean 150 at 1.5 m vs
   107-125 nearer: nearby room surfaces catch the emitter light, so the face
   region loses contrast rather than the frame losing pixels).
3. **Practical guidance, worth reflecting in LIMITATIONS.md language**: in a
   dark room, sit within roughly arm-and-a-half (about 1.1 m) of a BRIO-class
   camera for face unlock; beyond that irlume correctly answers "no face" and
   falls back to the password. The lit path has no such bound at these
   distances.

## Session side-findings (recorded, tracked separately)

- **The ASUS Zenbook host cannot participate in dark-path testing**: its
  firmware auto-engages the hardware privacy shutter in darkness (the daemon
  logs the privacy refusal), consistent with the ADR-0016 auto-shutter
  disclosure. Any dark-session plan should use archhost-class hardware.
- **AppArmor gap**: the shipped `irlumed` profile denies `file_lock` on
  `/etc/irlume/cameras.conf.lock`, so `set-cameras` persists nothing on the
  enforcing host (live switch works, restart reverts). Filed as issue #580
  with the audit line; same class as #573.

## Sources

- The sweep itself: journal and events evidence above, captured 2026-08-28.
- docs/pad-results/2026-08-04-landmark-relief.md (the 1/r^2 IR falloff note).
- ADR-0016 (ASUS auto-shutter disclosure).
- Shared-memory checkpoint for the SecureDark stage-3 n=1 observation.

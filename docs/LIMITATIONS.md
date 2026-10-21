# Honest limitations

What irlume does not do, and the measurements behind each statement. The
summary lives on the [README](../README.md); this is the detail.

- **The daemon does not open any camera at startup.** The startup
  IR-emitter verification used to open the IR camera, light the emitter,
  and grab one frame on every daemon start, with no user action anywhere;
  since #603 it is deferred to the first authentication, which re-applies
  the known emitter control as part of every capture's open path and
  surfaces a dark emitter through the auth-path diagnostics. One capture
  without a user action remains, and it is conditional: when the stored
  capture qualification no longer matches the live cameras (a kernel
  upgrade, USB replug, or driver update), a background requalification
  probe re-measures the pair for up to a minute, IR emitter firing,
  starting 60 seconds after the daemon does; it yields to any
  authentication via the camera lease and the same measurement is
  available on demand with `irlume camera-tune`. Camera discovery and
  classification are query-only: no streaming, no frames, no emitter
  writes.
- **Face unlock does not work on the XFCE lock screen (xfce4-screensaver),
  by design.** The screensaver pre-starts its PAM conversation the moment
  the lock engages and auto-answers module prompts without user action, so
  a consent-gated module like pam_irlume fires the camera the instant the
  lock opens, with no keystroke and with any typed input, correct password
  included; the dialog also never displays the module's prompt text, and it
  refuses to submit an empty field, which rules out the on-demand
  empty-Enter gesture too. Measured on Manjaro XFCE with instrumented
  runs: the face attempt starts at lock-open, denies cleanly when the
  camera is covered (the password then unlocks), and the privacy rule
  "typing your password never triggers a camera" cannot be upheld on this
  dialog. Every other surface on XFCE works (LightDM greeter on-demand,
  `sudo`, polkit). The screensaver inherits its conversation style from
  GNOME-screensaver; any prompt-based PAM module (challenge-response, one
  time codes) misfires the same way there, which is reported upstream.
- **A glossy printed photo defeats the built-in gate.** The
  [2026-06-30 self-test](pad-results/2026-06-30-ir-liveness-selftest.md)
  accepted a life-size vinyl print in 69 of 70 presentations. The cue is a
  brightness ratio on a 2D infrared sensor, and a print held at an angle produces
  the same falloff a face does, so no threshold accepts the user and rejects the
  print. The shipped default-on PAD pair (ADR-0013) refused the
  same print at p_fake 0.941 to 1.000, including when it was enhanced with an
  infrared-absorbing patch. The weights are bundled, checksummed, and verified
  at daemon startup; their publishers document neither the training data nor a
  way to reproduce the models, which is disclosed at startup and in
  [models/README.md](../models/README.md) ([ADR-0001](adr/0001-liveness-pad-strategy.md),
  amended by ADR-0013).
  Every miss falls safely to the password.
- **Bright infrared behind you rejects a genuine face.** The gate infers shape
  from how the emitter's light falls, and open sky or a hot lamp floods it. In a
  430-sample field session it was reliable below ambient ~120 on the 0-255 IR
  scale and rejected 129 of 129 genuine samples above ~170. The rejection names
  the condition and the fix.
- **A dim room can make the shipped RGB PAD cue refuse a genuine face.** The
  ViT RGB cue (ADR-0013) is deny-only and denies when the median of the last
  five scores reaches 0.55. Single genuine frames already reach that line (on
  the m96 crop the recorded desk-light maximum is 0.551 and the LFW q99 is
  0.565); the five-frame median suppresses most of that tail. Anything that
  raises every frame's score erodes it quickly: on the recorded LFW scores of
  the 423 identities with five or more photos, adding 0.05 to every frame puts
  5% of five-frame groups at or over the line when the frames are drawn
  independently and 12% when they are five photos of one person, and adding
  0.08 puts 37% to 40% there. A reported T480 split-pair attempt in a dim room
  was refused at a median of 0.578 while the cross-spectrum cues stayed live,
  and granted with the light on (0.428 to 0.507). The refusal names the cue
  and fails closed: add light on your face, or use your password. irlume does
  not brighten the screen as a fill light, as Windows Hello's optional
  low-light sign-in does (Microsoft has removed that setting for now and
  schedules its return from November 2026). Offline, darkening the image
  lowered the score and added grain raised it, by a median of 0.04 to 0.05 on
  LFW but by 0.07 or more for 47 to 61 of 200 faces, the size of that unit's
  dim-room shift; whether that is what happened on that unit stays open in
  #1155 ([measurement](research/2026-10-21-vit-dim-room-cue-evaluation.md)).
- **Legacy eye-policy state still blocks face authentication.** Clear stored
  `require_eyes_open=true` with `irlume profiles eyes-open off`. Head-gesture
  settings have been retired; see [migration notes](HEAD-GESTURE-REMOVAL.md).
- **RGB-only laptops get screen unlock only**, never `sudo`, login, or the
  keyring. By design.
- **An RGB camera and an IR camera on separate USB devices pair only as an
  experimental split pair.** Some laptops, the ThinkPad T480 among them
  (#887), expose the colour camera and the IR camera as two USB devices.
  irlume pairs RGB and IR within one physical camera
  ([ADR-0031](adr/0031-descriptor-attested-yuyv-luma-ir.md) §3), so such a
  machine runs the RGB-only tier, and enrollment and authentication with both
  cameras refuse and say that the two nodes are on different USB devices,
  unless the machine owner authorizes the pair and opts in to split camera
  pairs ([COMMANDS.md](COMMANDS.md) "Experimental opt-in", ADR-0032).
- **IR cameras that stream luma in NV12 are refused, and YUYV-only IR cameras
  are judged per burst.** NV12 carries no sensor ceiling irlume can measure,
  so every face attempt on it falls back to the password as "IR exposure
  unmeasurable". A YUYV-only IR camera whose USB descriptor declares it (the
  T480's 5986:1141) is classified as IR, and its format names no ceiling
  either. Only as the IR side of a split pair under the experimental opt-in
  does a burst get one, 235 on the raw luma, and only when the format read
  from the open camera is limited range, no frame of the session has broken
  the footroom or flat-chroma bounds, the stream's emitter is active, and
  the burst itself shows the emitter alternating (ADR-0031 §4, amendments
  2026-10-13 and 2026-10-14). Such a camera reports no per-frame
  illumination, so that burst's alternation also marks its lit frames, and
  other programs with access to the camera can disturb that inference. The
  packaged `72-irlume-ir-nodes.rules` closes that window for these cameras
  by keeping their nodes to root alone (applies at the next plug or boot;
  a descriptor opened before it applies stays usable, so a trigger is not
  enough); on a node that reads closed, and only then, the proof no longer needs the
  opt-in's confinement, and `irlume doctor` reports the node's state
  (ADR-0031 §4, amendment 2026-10-17, #1069). Every
  other YUYV burst refuses the same way as NV12. The emitter counts as active
  when a built-in or saved control is held by the stream guard, or the
  camera's own face-authentication control reads its default alternating
  mode. The T480's `5986:1141` now has a built-in control validated by the
  reporter's write/read-back/optical/restore run, with a face grant
  (ADR-0031, amendment 2026-10-20, #887); no manual emitter override is needed.
  Broader hardware qualification remains open, and the reporter's dim-room
  RGB PAD refusals are unchanged. An IR camera that offers MJPG, alone or
  beside YUYV, is not supported.
- **The NexiGo HelloCam N930W measured here (`3443:c803`) streams IR close
  to the delivered-rate floor.** Every capture checks that each stream
  delivers at least 97% of its role's floor, 14.55 fps for IR, as evidence of
  a healthy link (`crates/irlume-camera/src/rate_gate.rs`). Once settled,
  this unit's IR side delivers 14.73 to 14.79 fps, about 1.2 to 1.7% above
  that: on minihost
  ([startup flush measurement](research/2026-08-22-startup-flush-fleet-measurement.md))
  and, as the IR side of a split pair, 14.76 fps on archhost (#1063). Other
  cameras sold as the N930W, such as `3443:930d` units, are different designs
  and were not measured ([PLATFORMS.md](PLATFORMS.md)). A capture that dips
  below the floor refuses with `delivered rate below floor`: an
  authentication then falls back to the password, and an enrollment ends with
  that error and saves nothing, so an existing enrollment stays as it was. On
  the attended split rig one of three enrollment attempts failed that way and
  the next capture passed. `irlume camera diagnostics --json` shows the
  measured rate for each side. The tolerance is not lowered for one camera:
  it is already fitted to this one, a lower tolerance would also pass
  degraded links on every other camera, and camera profiles carry no tuning
  fields in schema v1 ([ADR-0023](adr/0023-camera-profile-layer.md)).
- **Not lab-certified.** Self-tested against ISO/IEC 30107-3, with no iBeta pass.
  Demographic tuning ([FAIRNESS.md](FAIRNESS.md)) is ongoing.
- **Root on the live machine is the trust boundary.** The daemon holds decrypted
  embeddings in RAM during a match, unlike Hello's VBS enclave. Disk theft is
  covered: templates copied to another machine fail to decrypt
  ([tested](SECURITY_AT_REST.md)). On the original machine the TPM seal binds
  the boot chain, not the root filesystem, so what protects the sealed secrets
  there is full-disk encryption unlocked by a passphrase or PIN, or a verified
  root whose root hash is bound, with a pcrlock policy that covers the boot
  loader (PCR 4); a pcrlock policy alone does not
  ([SECURITY_AT_REST](SECURITY_AT_REST.md), layer 3).

Every claim here maps to something you can run yourself: [docs/VERIFY.md](VERIFY.md).

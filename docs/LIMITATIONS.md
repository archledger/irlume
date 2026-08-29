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
- **The optional head gesture is experimental, not a privileged confirmation
  substitute.** Repeated nodding approves a gesture-gated request and a head
  shake declines it, but incidental motion and a hand-held print have triggered
  the detector in measured trials. It defaults off and is not
  population-qualified. Privileged face auth always requires hidden literal
  `yes` first; automatic passive PAD remains the separate anti-spoof boundary
  ([ADR-0010](adr/0010-conventional-face-intent-confirmation.md)).
- **Legacy eye-policy state blocks rather than weakens.** For one release,
  stored `require_eyes_open=true` blocks face authentication, while
  `consent_gesture=closure` blocks an explicitly gesture-gated request. Both
  provide migration instructions. Use `irlume profiles eyes-open off` to clear
  the stored blocker; remove `consent_gesture` or set it to `nod`.
- **RGB-only laptops get screen unlock only**, never `sudo`, login, or the
  keyring. By design.
- **Not lab-certified.** Self-tested against ISO/IEC 30107-3, with no iBeta pass.
  Demographic tuning ([FAIRNESS.md](FAIRNESS.md)) is ongoing.
- **Root on the live machine is the trust boundary.** The daemon holds decrypted
  embeddings in RAM during a match, unlike Hello's VBS enclave. Disk theft is
  covered: templates copied to another machine fail to decrypt
  ([tested](SECURITY_AT_REST.md)).

Every claim here maps to something you can run yourself: [docs/VERIFY.md](VERIFY.md).

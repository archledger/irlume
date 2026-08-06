# Honest limitations

What irlume does not do, and the measurements behind each statement. The
summary lives on the [README](../README.md); this is the detail.

- **A glossy printed photo defeats the built-in gate.** The
  [2026-06-30 self-test](pad-results/2026-06-30-ir-liveness-selftest.md)
  accepted a life-size vinyl print in 69 of 70 presentations. The cue is a
  brightness ratio on a 2D infrared sensor, and a print held at an angle produces
  the same falloff a face does, so no threshold accepts the user and rejects the
  print. `irlume setup` offers a trained deny-only cue (`flir`) that refused the
  same print at p_fake 0.941 to 1.000, including when it was enhanced with an
  infrared-absorbing patch. irlume does not ship or warrant those weights,
  because their publisher documents neither the training data nor a way to
  reproduce the model ([ADR-0001](adr/0001-liveness-pad-strategy.md)).
  Every miss falls safely to the password.
- **Bright infrared behind you rejects a genuine face.** The gate infers shape
  from how the emitter's light falls, and open sky or a hot lamp floods it. In a
  430-sample field session it was reliable below ambient ~120 on the 0-255 IR
  scale and rejected 129 of 129 genuine samples above ~170. The rejection names
  the condition and the fix.
- **Passive blink liveness misses glasses-wearers**, because IR lens reflections
  hide the eyelid.
- **RGB-only laptops get screen unlock only**, never `sudo`, login, or the
  keyring. By design.
- **Not lab-certified.** Self-tested against ISO/IEC 30107-3, with no iBeta pass.
  Demographic tuning ([FAIRNESS.md](FAIRNESS.md)) is ongoing.
- **Root on the live machine is the trust boundary.** The daemon holds decrypted
  embeddings in RAM during a match, unlike Hello's VBS enclave. Disk theft is
  covered: templates copied to another machine fail to decrypt
  ([tested](SECURITY_AT_REST.md)).

Every claim here maps to something you can run yourself: [docs/VERIFY.md](VERIFY.md).

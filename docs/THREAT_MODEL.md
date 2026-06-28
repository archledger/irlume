# Threat model & security requirements

Goal: **meet or beat Windows Hello.** Targets follow NIST SP 800-63B-4 even if
formal certification stays optional.

## Targets

- **FMR ≤ 1×10⁻⁴** across all demographic groups, at a single **fixed** threshold
  (per ISO/IEC 19795-1). AuraFace's score scale differs from buffalo_l — derive
  the threshold from a genuine/impostor ROC; do not port linhello's 0.60.
  **Measured status:** AuraFace shows a ~10× per-group FAR spread; a single
  threshold meeting FMR ≤ 1×10⁻⁴ for every group needs ≈0.69. The gap is bounded
  by a conservative fixed threshold + mandatory fallback, never by relaxing FAR.
  See [`FAIRNESS.md`](FAIRNESS.md) for the per-group table and policy.
- **PAD mandatory**; target **IAPAR < 0.07** (ISO/IEC 30107-3 Clause 13).
- **Biometric is one MFA factor only**, with a mandatory non-biometric fallback.
- No network calls in the auth loop; templates/secrets local, root-owned 0600.

## Known Windows Hello bypass classes → our defenses

| Bypass | Root cause | irlume defense |
|---|---|---|
| **CVE-2021-34466** (CyberArk) — inject a spoofed IR frame from a fake USB camera | Hello trusts any USB device as camera root-of-trust; descriptors unauthenticated | **Device pinning** (topology + descriptor + `fixed`) — defeats *software* virtual-camera injection; a malicious *hardware* USB device needs crypto attestation (out of scope). See [Camera trust](#camera-trust--device-pinning). |
| Same — real IR + arbitrary RGB ("SpongeBob") passes | Only IR validated, RGB ignored | **Cross-spectrum RGB↔IR spatial overlap**: face must align in both streams |
| Weak frame-transition liveness | Trivial transition check | **Active IR-strobe response** + **bright-pupil retro-reflection** + **NIR skin** |

## Camera trust — device pinning

Before any frame is read, the daemon verifies the camera is the *expected
physical device*, to defeat **unprivileged software frame injection**
(`v4l2loopback`, OBS virtual camera, and similar userspace stream sources). The
check is an **allowlist** (the device must match the pin), not a blocklist —
this is robust regardless of how a virtual source is constructed.

For each target `/dev/videoN`, resolve `/sys/class/video4linux/videoN/device`
and require all of:

1. **Physical bus origin** — the resolved path traces to a real bus
   (`…/pci0000:00/…/usbX/…`), not a virtual/platform node. (Verified on the
   reference Zenbook: RGB `…/usb3/3-5/3-5:1.0`, IR `…:1.2`.)
2. **Pinned descriptor** — `idVendor`/`idProduct` match the enrolled values
   (reference unit: `3277:0059`, Shinetech/ASUS FHD webcam). Stored per-host in
   config, since these are device-specific.
3. **Fixed removability** — the USB device's `removable` attribute reads `fixed`
   (built-in), rejecting a camera hot-plugged into an external port. *Caveat:*
   `removable` is derived from ACPI/hub data and is often `unknown` even for
   legitimate devices, so it is a supplementary signal, not a sole gate — the
   descriptor + topology pin is the primary check.

**Threats mitigated:** userspace virtual-camera injection (the realistic remote/
malware vector).
**NOT mitigated:** (a) a **root** attacker — who can rewrite sysfs or load a
kernel module, but also needs no spoof since they can bypass PAM directly, so
this is the correct trust boundary; (b) a **malicious USB hardware device**
(CVE-2021-34466 class) — it presents a real USB path and can forge any
descriptor, so topology/descriptor pinning cannot stop it. Closing that vector
requires cryptographic camera attestation, which is **out of scope for V1.0**.

## Liveness (algorithmic, no trained weights)

Physically-grounded cues, hard gate (any failure rejects):

- **NIR skin reflectance** (>1.2 µm melanin-independent → skin-tone fair).
- **Bright-pupil retro-reflection** (~90% @850 nm, coaxial emitter).
- **Cross-spectrum RGB↔IR overlap** (anti-injection).
- **Active IR-strobe response**.
- **Corneal glint** — *supporting only* (standalone-glint liveness was refuted).

**Honest caveat:** a pure hand-crafted gate is unproven at certification-grade
error rates (the best published NIR-PAD used a trained CNN). Treat the gate as a
research milestone: self-test against ISO/IEC 30107-3 attack classes; if cues
can't reach iBeta Level 2, train a model on **own IR-rig** data (license-clean).
The decision to stay single-frame (no rPPG / no licensed PAD CNN) and the accepted
3D-mask / active-IR-spoof residual risk are recorded in
[`adr/0001-liveness-pad-strategy.md`](adr/0001-liveness-pad-strategy.md).

## Storage

Seal a random release secret (or the login password) in the **TPM**, gated by
**PCR policy**; release only on a successful live+match. Never store a
recoverable face image. Embeddings zeroized after use.

## Side channels

- **Constant-time match decision.** The cosine/threshold comparison must not
  branch or vary in timing on the similarity value, so an attacker cannot probe
  response time to learn how close a presented face is to an enrolled template
  (which would enable hill-climbing toward a match). Compare against the
  threshold without early-out; keep the decision value-independent.
- **No score leakage.** Auth responses to unprivileged callers expose only
  grant/deny + a coarse reason — never the raw similarity score or per-template
  distances.
- **Memory hygiene.** Raw frames, chips, and embeddings are zeroized
  (`zeroize`/`secrecy`) immediately after use; nothing biometric is logged.

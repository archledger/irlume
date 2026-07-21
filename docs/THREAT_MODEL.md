# Threat model & security requirements

Goal: **meet or beat Windows Hello.** Targets follow NIST SP 800-63B-4 even if
formal certification stays optional.

## Targets

- **FMR ≤ 1×10⁻⁴** across all demographic groups, at a single **fixed** threshold
  (per ISO/IEC 19795-1). AuraFace's score scale differs from buffalo_l: derive
  the threshold from a genuine/impostor ROC; do not port a threshold measured
  on another stack (e.g. buffalo_l's customary 0.60).
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
| **CVE-2021-34466** (CyberArk): inject a spoofed IR frame from a fake USB camera | Hello trusts any USB device as camera root-of-trust; descriptors unauthenticated | **Device pinning** (topology + descriptor + `fixed`) defeats *software* virtual-camera injection; a malicious *hardware* USB device needs crypto attestation (out of scope). See [Camera trust](#camera-trust-device-pinning). |
| Same, but real IR + arbitrary RGB ("SpongeBob") passes | Only IR validated, RGB ignored | **Cross-spectrum RGB↔IR spatial overlap**: face must align in both streams |
| Weak frame-transition liveness | Trivial transition check | **IR reflectance floor** + **depth (center/edge) ratio** + **cross-spectrum overlap** |

## Camera trust: device pinning

Before any frame is read, the daemon verifies the camera is the *expected
physical device*, to defeat **unprivileged software frame injection**
(`v4l2loopback`, OBS virtual camera, and similar userspace stream sources). The
check is an **allowlist** (the device must match the pin), not a blocklist;
it holds regardless of how a virtual source is constructed.

For each target `/dev/videoN`, resolve `/sys/class/video4linux/videoN/device`
and require all of:

1. **Physical bus origin**: the resolved path traces to a real bus
   (`…/pci0000:00/…/usbX/…`), not a virtual/platform node. (Verified on the
   reference Zenbook: RGB `…/usb3/3-5/3-5:1.0`, IR `…:1.2`.)
2. **Pinned descriptor**: `idVendor`/`idProduct` match the enrolled values
   (reference unit: `3277:0059`, Shinetech/ASUS FHD webcam). Supplied per-host via the
   `IRLUME_CAMERA_PIN` environment allowlist on the daemon unit, since these
   are device-specific.
3. **Fixed removability**: the USB device's `removable` attribute reads `fixed`
   (built-in), rejecting a camera hot-plugged into an external port. *Caveat:*
   `removable` is derived from ACPI/hub data and is often `unknown` even for
   legitimate devices, so it is a supplementary signal, not a sole gate; the
   descriptor + topology pin is the primary check.

**Threats mitigated:** userspace virtual-camera injection (the realistic remote/
malware vector).
**NOT mitigated:** (a) a **root** attacker, who can rewrite sysfs or load a
kernel module, but also needs no spoof since they can bypass PAM directly, so
this is the correct trust boundary; (b) a **malicious USB hardware device**
(CVE-2021-34466 class), which presents a real USB path and can forge any
descriptor, so topology/descriptor pinning cannot stop it. Closing that vector
requires cryptographic camera attestation, which is **out of scope for V1.0**.

**Implemented:** `irlume-camera::verify_pinned`, called at the head of every
`capture_rgb`/`capture_ir`. The physical-bus check is always on (no config);
`IRLUME_CAMERA_PIN="vid:pid"` and `IRLUME_CAMERA_REQUIRE_FIXED=1` add descriptor
and removability pinning per host. One deliberate exception exists for the CI
test harness: `IRLUME_TEST_ALLOW_VIRTUAL_CAMERA` names exact device paths
(v4l2loopback nodes) that may skip the physical-bus check, and every use is
logged. It weakens nothing in production: the daemon's environment comes from
its root-owned systemd unit, so setting it requires the same root the pin does
not defend against, and a unit test pins the escape to exact-path matches.

## Liveness: algorithmic single-frame gate (no trained weights)

The default gate uses no trained weights. (The opt-in passive-blink stage
below, [ADR-0002](adr/0002-challenge-response-liveness.md), does run a trained
model, MediaPipe FaceMesh, for eye landmarks; it is a landmarker, not a spoof
classifier, and is Apache-2.0, so the clean-BOM claim holds.)

Physically-grounded cues, hard gate (any failure rejects):

- **IR reflectance floor**: emitter-lit skin brightness (with a per-user
  depth-calibrated floor for opt-in re-enrollments).
- **Depth (center/edge) ratio**: a real face is closer to the emitter at the
  nose than at the cheeks; flat media are not.
- **Cross-spectrum RGB↔IR overlap** (anti-injection).
- **Frontality** (yaw/pitch bounds from landmarks).
- **Corneal glint**: *supporting only* (standalone-glint liveness was refuted).

*(Explored but not shipped as gates: bright-pupil retro-reflection and active
IR-strobe response; the capture path picks the brightest strobe frame but no
strobe-response check is enforced.)*

**Caveat:** a pure hand-crafted gate is unproven at certification-grade
error rates (the best published NIR-PAD used a trained CNN). Treat the gate as a
research milestone: self-test against ISO/IEC 30107-3 attack classes (methodology
+ `irlume padcapture`/`padreport` tooling in [`PAD_SELFTEST.md`](PAD_SELFTEST.md));
if cues can't reach iBeta Level 2, train a model on **own IR-rig** data (license-clean).
The decision to stay single-frame (no rPPG / no licensed PAD CNN) and the accepted
3D-mask / active-IR-spoof residual risk are recorded in
[`adr/0001-liveness-pad-strategy.md`](adr/0001-liveness-pad-strategy.md).

**CONFIRMED BREACH (2026-06-30):** the self-test found that a **life-size glossy
vinyl print** (graduation banner) defeats the gate at **98.6% APCER**: vinyl
reflects 850 nm (defeating `face_in_ir`) and a large flat print mimics the
brightness-ratio depth cue (banner depth 1.02–1.58 *overlaps and exceeds* genuine
1.37–1.40, so no threshold separates them). Screen replays and matte-paper prints
were still fully rejected. This is a demonstrated instance of the accepted
IR-approximating-spoof residual risk. The mitigation, **passive-blink
challenge-response** (a static print cannot blink), is implemented and
validated ([ADR-0002](adr/0002-challenge-response-liveness.md); measured APCER
0% / BPCER 0%) but ships **opt-in and off by default**, so the default posture
still carries this gap until a user enables the blink challenge.
Full write-up: [`pad-results/2026-06-30-ir-liveness-selftest.md`](pad-results/2026-06-30-ir-liveness-selftest.md).

## Storage

Seal a random release secret (or the login password) in the **TPM**, gated by
**PCR policy**; release only on a successful live+match. Sealing picks the
strongest policy the machine supports: a signed `PolicyAuthorize` over
systemd's PCR-11 signature where a UKI publishes one (Tier 1; kernel updates
need no re-seal), `PolicyAuthorizeNV` against a provisioned systemd-pcrlock NV
index (Tier 2; after a firmware or Secure Boot update the admin re-runs
`systemd-pcrlock make-policy` and the seal keeps working), or a literal
`PolicyPCR` over PCR 7 (Tier 3; a Secure Boot change requires a re-arm). The
higher tiers (signed and pcrlock) are round-trip verified at seal time, so a
policy that cannot unseal on the current boot is never trusted; the literal
PCR-7 fallback binds to PCR values just read from the live TPM, so it unseals
on the current boot by construction. Never store a recoverable face image;
decrypted template plaintext and keys are zeroized.

**Fingerprint keyring unlock** ([ADR-0003](adr/0003-fingerprint-keyring-unlock.md))
releases the sealed login password on *root peer + login-service-class*, without
a daemon-verified biometric: the fingerprint (`pam_fprintd`) authenticated
first. At-rest protection is preserved (a stolen disk can't unseal). Residual,
accepted: a **live root attacker** in a login context can obtain the password.
That is no new capability (root can already read the running keyring), and root is the
trust boundary throughout. The face/IR path is strictly stronger here (it
requires a daemon-verified live biometric even against root).

**Fingerprint presentation attacks: scope.** The fingerprint path's
anti-spoofing is whatever the sensor and `fprintd` provide, which for common
match-on-host readers is **none**. irlume's IR liveness gates (emitter
ratio/glint/depth cues, eyes-open, blink challenge) apply to the **face path
only** and do not transfer. For reference, Windows Hello certification
*requires* fingerprint anti-spoofing; irlume's fingerprint companion makes no
equivalent claim. Treat it as convenience-tier against a determined attacker
with a fabricated print.

## Side channels

- **No early-out in matching.** Every enrolled scan is scored: fixed-length
  cosine over the full embedding, fold-max across all templates, no early
  exit. Response time therefore does not reveal how close a probe came or
  which template it approached. The grant/deny outcome itself is observable
  by design; what keeps timing from becoming a hill-climbing oracle is that
  the deny path runs the same fusion/fallback stages regardless of how close
  the score was, and the score never reaches unprivileged callers (next
  bullet).
- **Score exposure is authorization-gated.** `Authenticate` (which returns the
  similarity score) is answered only for root peers (the PAM stacks) or the
  account owner probing themselves; any other local peer is refused outright,
  so there is no cross-user hill-climbing oracle. Scores are logged to the
  root-only journal, never to unprivileged callers.
- **Memory hygiene.** Secrets are zeroized where the exposure is real: sealed
  keys, decrypted template plaintext, passwords, and the IPC wire buffers that
  may carry them (`zeroize`). Camera frames and embeddings are transient
  process memory, dropped after use but not explicitly wiped, inside the
  same root daemon that holds the decrypted templates anyway. Nothing
  biometric is logged.

## Intent, throttling, and privilege elevation

- **Face never fires passively.** The camera powers on only when the user
  submits an empty password field and presses Enter; typing a password never
  starts a scan. In FIDO terms, that deliberate gesture is the User Presence /
  intent signal and the face match is User Verification. This is the same shape
  as macOS Touch ID for `sudo`, where the deliberate fingerprint touch is both
  the intent act and the verification. It is the specific gap that a passive
  face-auth tool has for privilege elevation (a face silently approving `sudo`
  just by being in frame, cf. Howdy issue #1079); irlume does not have it,
  because presence alone triggers nothing. face-`sudo` therefore requires no
  extra challenge beyond the gesture and the default IR liveness gate: adding
  one would impose latency and false rejects on a factor whose fallback (the
  password) is always one keystroke away.
- **Consecutive-failure throttle.** After a run of failed face attempts (5 by
  default, `IRLUME_RATE_LIMIT`), the daemon stops firing the camera on the
  gesture for a cooldown (30s, `IRLUME_RATE_COOLDOWN_SECS`) and PAM falls
  straight to the password; a grant resets it, and an empty frame (nobody
  present) never counts. This satisfies the NIST SP 800-63B-4 §3.2.3 intent
  (an attacker cannot cheaply grind presentation attacks against the gate)
  deliberately as a *throttle*, not the standard's hard biometric-disable
  tier: irlume's password is always the fallback and there is no account
  lockout, so disabling face until "another factor" would only re-offer the
  password the throttled user is already typing. State is per-user and
  in-memory; a daemon restart clears it because the password, not a lockout,
  is the security floor. Every mainstream authenticator (Face ID, Android,
  Windows Hello) likewise uses ~5 failures then falls to a non-biometric
  factor rather than locking the account.

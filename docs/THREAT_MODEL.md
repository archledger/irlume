# Threat model & security requirements

Goal: **meet or beat Windows Hello.** Targets follow NIST SP 800-63B-4 even if
formal certification stays optional.

## Targets

- **FMR ≤ 1×10⁻⁴** across all demographic groups, at a single **fixed** threshold
  (per ISO/IEC 19795-1). AuraFace's score scale differs from buffalo_l — derive
  the threshold from a genuine/impostor ROC; do not port linhello's 0.60.
- **PAD mandatory**; target **IAPAR < 0.07** (ISO/IEC 30107-3 Clause 13).
- **Biometric is one MFA factor only**, with a mandatory non-biometric fallback.
- No network calls in the auth loop; templates/secrets local, root-owned 0600.

## Known Windows Hello bypass classes → our defenses

| Bypass | Root cause | lumen defense |
|---|---|---|
| **CVE-2021-34466** (CyberArk) — inject a spoofed IR frame from a fake USB camera | Hello trusts any USB device as camera root-of-trust; descriptors unauthenticated | **Device-trust binding**: pin the camera by topology/descriptor; reject unknown devices |
| Same — real IR + arbitrary RGB ("SpongeBob") passes | Only IR validated, RGB ignored | **Cross-spectrum RGB↔IR spatial overlap**: face must align in both streams |
| Weak frame-transition liveness | Trivial transition check | **Active IR-strobe response** + **bright-pupil retro-reflection** + **NIR skin** |

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

## Storage

Seal a random release secret (or the login password) in the **TPM**, gated by
**PCR policy**; release only on a successful live+match. Never store a
recoverable face image. Embeddings zeroized after use.

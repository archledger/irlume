# Architecture

## Privilege separation

```
 ┌────────────┐   ┌──────────┐         Unix socket           ┌─────────────────────┐
 │ login/sudo │──▶│pam_irlume │──┐    /run/irlume.sock          │       irlumed        │
 │ sshd / DM  │   │  (.so)   │  ├──────────────────────────▶ │   (privileged)      │
 └────────────┘   └──────────┘  │    SO_PEERCRED authz        │                     │
                  ┌──────────┐  │                             │  owns: camera, IR   │
                  │ irlume CLI│──┘                             │  emitter, ONNX      │
                  └──────────┘                                │  models, templates, │
                   UNTRUSTED clients                          │  TPM. Raw frames    │
                                                              │  never leave here.  │
                                                              └─────────────────────┘
```

- **Untrusted clients** (`pam_irlume.so`, `irlume` CLI) hold no secrets and touch
  no hardware in production paths — they only send `Request`s and read
  `Response`s. (The `IRLUME_DEV=1` benchmark/capture tools open the camera
  directly by design; they are diagnostics, not auth paths.)
- **`irlumed`** is the sole owner of the camera/IR/models/templates/TPM. This is
  the Linux analogue of Windows Hello ESS's isolated camera→matcher pathway: the
  login/display-manager process tree never sees raw image data.
- **Trust boundary:** `irlumed` reads `SO_PEERCRED` on every connection. Only
  root or the target user may enroll/delete that user's profiles. (We use a raw
  Unix socket + explicit peer check rather than D-Bus policy — the concrete
  hardening over the `visage` reference design.)

## Authentication flow

1. Client sends `Authenticate { user, service }` (root or the account owner
   only; the service name drives tier/operation-class gating).
2. `irlumed`: capture RGB (+detect) → capture IR burst → align to ArcFace 112×112
   → AuraFace embed → **liveness gate** (hard) → **matcher** at fixed threshold.
3. On `live && score ≥ threshold`: return `AuthResult { granted: true, .. }`.
   Credential release is a **separate, root-peer-only request**
   (`UnsealPassword`), used by the login stack to open the keyring — a plain
   `Authenticate` never touches the TPM seal.
4. On any failure/timeout: `granted: false` (or an error) → PAM falls through
   to password (mandatory non-biometric fallback, per NIST SP 800-63B-4).

## Why these choices

See [THREAT_MODEL.md](THREAT_MODEL.md) for the Windows Hello bypass classes
(CVE-2021-34466 IR injection; ESS device-trust) each defense maps to.

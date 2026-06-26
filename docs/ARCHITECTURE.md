# Architecture

## Privilege separation

```
 ┌────────────┐   ┌──────────┐         Unix socket           ┌─────────────────────┐
 │ login/sudo │──▶│pam_lumen │──┐    /run/lumen.sock          │       lumend        │
 │ sshd / DM  │   │  (.so)   │  ├──────────────────────────▶ │   (privileged)      │
 └────────────┘   └──────────┘  │    SO_PEERCRED authz        │                     │
                  ┌──────────┐  │                             │  owns: camera, IR   │
                  │ lumen CLI│──┘                             │  emitter, ONNX      │
                  └──────────┘                                │  models, templates, │
                   UNTRUSTED clients                          │  TPM. Raw frames    │
                                                              │  never leave here.  │
                                                              └─────────────────────┘
```

- **Untrusted clients** (`pam_lumen.so`, `lumen` CLI) hold no secrets and touch
  no hardware. They only send `Request`s and read `Response`s.
- **`lumend`** is the sole owner of the camera/IR/models/templates/TPM. This is
  the Linux analogue of Windows Hello ESS's isolated camera→matcher pathway: the
  login/display-manager process tree never sees raw image data.
- **Trust boundary:** `lumend` reads `SO_PEERCRED` on every connection. Only
  root or the target user may enroll/delete that user's profiles. (We use a raw
  Unix socket + explicit peer check rather than D-Bus policy — the concrete
  hardening over the `visage` reference design.)

## Authentication flow

1. Client sends `Authenticate { user }`.
2. `lumend`: capture RGB (+detect) → capture IR burst → align to ArcFace 112×112
   → AuraFace embed → **liveness gate** (hard) → **matcher** at fixed threshold.
3. On `live && score ≥ threshold`: unseal the user's TPM-bound secret and return
   `AuthResult { granted: true, .. }`.
4. On any failure/timeout: return an error → PAM falls through to password
   (mandatory non-biometric fallback, per NIST SP 800-63B-4).

## Why these choices

See [THREAT_MODEL.md](THREAT_MODEL.md) for the Windows Hello bypass classes
(CVE-2021-34466 IR injection; ESS device-trust) each defense maps to.

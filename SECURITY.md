# Security Policy

irlume is biometric authentication software: a bug here can mean unauthorized
login.

## Status

**Pre-1.0, not yet suitable for production.** There is no long-term-support
branch; security fixes land on `main` and ship in the next release.

## Supported versions

| Version | Supported |
|---|---|
| `main` / latest release | ✅ |
| the [nightly channel](docs/PLATFORMS.md#nightly-channel) (builds of `main`) | ✅ |
| older pre-1.0 tags | ❌ |

## Component risk tiers

| Tier | Components | Why |
|---|---|---|
| **Critical** | `irlume-pam` (auth path), `irlume-daemon` (privileged) | A flaw grants login or root |
| **High** | `irlume-vision` (inference + match), `irlume-liveness` (PAD), bundled model integrity | Bypass of recognition or anti-spoofing |
| **Medium** | `irlume-camera` (device/IR control), `irlume-core` (TPM/storage), packaging/systemd units | Trust boundary + secret handling |
| **Medium** | `irlume-gkr-unlock`, `irlume-kwallet-init`, `irlume-password-verify` (privileged helpers) | Run elevated during login/unlock flows |
| **Low** | `irlume-cli` (unprivileged client), `irlume-auth` (engine library, exercised by the daemon's tests), `irlume-common` (IPC schema), `irlume-fingerprint` (fingerprint tooling wrapper), `kcm/irlume-kcm` (Plasma System Settings module: unprivileged view over the machine API + TUI launcher; no privileged helper) | Client-side or library surfaces behind the above |

## Threat model (summary)

Full detail in [`docs/THREAT_MODEL.md`](docs/THREAT_MODEL.md). Primary concerns:

- **Authentication bypass**: `PAM_SUCCESS` without a genuine live match; FFI
  unsoundness in the PAM module. The module never grants on error: any error,
  timeout, or unavailable daemon returns `PAM_IGNORE` (a neutral result, never
  `SUCCESS`), so the stack falls through to the password.
- **Presentation/injection attacks**: printed/screen/3D-mask spoofs and the
  Windows Hello-class USB IR-frame injection (CVE-2021-34466). Defended by the
  algorithmic IR liveness gate, device-trust binding, and cross-spectrum RGB↔IR
  consistency.
- **Biometric data leakage**: templates/embeddings are sensitive. They are
  zeroized where the exposure is real (keys, secrets, IPC buffers); frames/embeddings are transient daemon memory, never logged, and the unlock secret is TPM-sealed (not the
  template).
- **Side channels**: the match comparison is value-independent in timing so a
  similarity score cannot be inferred from response time.
- **Model integrity**: model weights are pinned by SHA-256 (committed in
  `models/SHA256SUMS`; `scripts/fetch-models.sh` verifies each release-hosted
  weight against its hash before use) and ship inside the distro packages,
  whose own integrity checking covers them; only the permissive, audited BOM is
  shipped. At startup the daemon compares model digests with the release
  manifest (`models/SHA256SUMS`, embedded at build time). Unknown digests warn
  and proceed to the loader by default; this manifest policy does not enforce
  release weights. Individual loaders can still reject them.
  `IRLUME_MODELS_STRICT=1` makes missing, unreadable or unrecognized detection,
  recognition, mesh or Blaze weights startup-fatal. A present optional IR
  adapter follows the same verification policy; an absent adapter is excluded.
  Warn-first is the default to allow deliberate custom model paths and
  self-trained adapters. Strict is the hardened choice; it refuses to start
  with a present adapter whose digest is not in the release manifest.
  PAD cues are handled separately: disabled cues skip checksum checking and
  loading; missing cues are unavailable; read errors, strict checksum rejection
  and load errors leave the cue unavailable without terminating the daemon.
  Face grants requiring that cue fall back to the password
  ([ADR-0019](docs/adr/0019-fail-closed-pad-availability.md)).
  Loader errors are separate from checksum policy: load failures of the
  detector, recognizer, or a present Blaze model or IR adapter are
  startup-fatal.
  Outside strict mode, a missing or failed mesh disables rescue alignment
  while the daemon continues.

## Reporting a vulnerability

**Do not open a public issue for security bugs.** Instead:

- Use GitHub **Private Vulnerability Reporting** on this repository, or
- Email **archledger236@gmail.com**.

Please include affected version/commit, a description, and a reproduction if
possible.

## Process & timelines

- **Acknowledgement:** within 48 hours.
- **Assessment:** within 7 days.
- **Fix target:** 30 days for Critical/High severity.
- **Disclosure:** coordinated, with a 90-day window. Reporters are credited in
  the release notes (opt-in).
- **CVE IDs:** requested through GitHub Security Advisories (GitHub is a CVE
  Numbering Authority for repository vulnerabilities), so a confirmed
  vulnerability gets a CVE and a published advisory alongside the fix release,
  and the fix is named in that release's notes.

## Scope

In scope: anything that bypasses authentication, leaks biometric data, escalates
privilege, or defeats the liveness gate. Out of scope: attacks requiring a
pre-compromised root account, physical destruction, or social engineering of the
enrolled user.

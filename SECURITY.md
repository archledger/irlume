# Security Policy

irlume is biometric authentication software: a bug here can mean unauthorized
login. We take reports seriously and ask researchers to disclose responsibly.

## Status

**Pre-1.0, not yet suitable for production.** There is no long-term-support
branch; security fixes land on `main` and ship in the next release.

## Supported versions

| Version | Supported |
|---|---|
| `main` / latest release | ✅ |
| older pre-1.0 tags | ❌ |

## Component risk tiers

| Tier | Components | Why |
|---|---|---|
| **Critical** | `irlume-pam` (auth path), `irlume-daemon` (privileged) | A flaw grants login or root |
| **High** | `irlume-vision` (inference + match), `irlume-liveness` (PAD), bundled model integrity | Bypass of recognition or anti-spoofing |
| **Medium** | `irlume-camera` (device/IR control), `irlume-core` (TPM/storage), packaging/systemd units | Trust boundary + secret handling |
| **Low** | `irlume-cli` | Unprivileged client |

## Threat model (summary)

Full detail in [`docs/THREAT_MODEL.md`](docs/THREAT_MODEL.md). Primary concerns:

- **Authentication bypass** — `PAM_SUCCESS` without a genuine live match; FFI
  unsoundness in the PAM module. The module fails **closed**: any error, timeout,
  or unavailable daemon returns failure so the stack falls through to password.
- **Presentation/injection attacks** — printed/screen/3D-mask spoofs and the
  Windows Hello-class USB IR-frame injection (CVE-2021-34466). Defended by the
  algorithmic IR liveness gate, device-trust binding, and cross-spectrum RGB↔IR
  consistency.
- **Biometric data leakage** — templates/embeddings are sensitive. They are
  zeroized after use, never logged, and the unlock secret is TPM-sealed (not the
  template).
- **Side channels** — the match comparison is value-independent in timing so a
  similarity score cannot be inferred from response time.
- **Model integrity** — bundled model weights are checksum-verified
  (`models/SHA256SUMS`) before use; only the permissive, audited BOM is shipped.

## Reporting a vulnerability

**Do not open a public issue for security bugs.** Instead:

- Use GitHub **Private Vulnerability Reporting** on this repository, or
- Email **archledger236@gmail.com** (PGP key: _TBD_).

Please include affected version/commit, a description, and a reproduction if
possible.

## Process & timelines

- **Acknowledgement:** within 48 hours.
- **Assessment:** within 7 days.
- **Fix target:** 30 days for Critical/High severity.
- **Disclosure:** coordinated, with a 90-day window. Reporters are credited in
  the release notes (opt-in).

## Scope

In scope: anything that bypasses authentication, leaks biometric data, escalates
privilege, or defeats the liveness gate. Out of scope: attacks requiring a
pre-compromised root account, physical destruction, or social engineering of the
enrolled user.

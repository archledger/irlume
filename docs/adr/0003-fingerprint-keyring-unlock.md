# ADR-0003: Fingerprint → TPM keyring unlock

**Status:** Accepted — implemented 2026-07-03.
**Context:** the login-keyring stays locked after a fingerprint login.

## Problem

GNOME Keyring's `login` keyring is encrypted with the user's **login password**;
it auto-unlocks only when a PAM module hands that password to
`pam_gnome_keyring` as `PAM_AUTHTOK`. A **password** login does this via
`pam_unix`. A **fingerprint** login (`pam_fprintd`) authenticates the user but
produces *no password* — and its `success=N` jump skips `pam_unix` entirely — so
the keyring never gets a password and stays locked. The first app that needs a
secret (a browser, etc.) then prompts the user to type it. This is stock
`fprintd` behaviour on every distro, not an irlume defect; irlume only surfaces
it by making fingerprint the login method.

Windows Hello does not have this gap: a fingerprint match releases credentials
from the TPM-backed Hello container. irlume already does the equivalent for the
**face/IR** path (`UnsealPassword` — face match → TPM-unseal → `PAM_AUTHTOK`).
This ADR extends that to fingerprint.

## Decision

Add `pam_irlume.so keyring`, wired at the **post-auth landing** of the greeter /
lock-screen stack (after `@include common-auth`, before `pam_gnome_keyring`). It
runs only when a trusted factor has already succeeded in this transaction:

- If `PAM_AUTHTOK` is **set** (password typed, or the face `unseal` line already
  provided it) → do nothing; the keyring unlocks from it.
- If `PAM_AUTHTOK` is **empty** (a fingerprint login) → request `UnsealKeyring`
  from the daemon and set the returned password as `PAM_AUTHTOK`.

Always returns `PAM_IGNORE` — keyring unlock is best-effort and never fails or
blocks a login.

The daemon's `UnsealKeyring` releases the sealed login password on:

1. **root peer** (`SO_PEERCRED` uid 0) — the login stack runs as root; and
2. a **login / lock-screen service class** (`biopolicy::classify` ∈
   {`ScreenUnlock`, `Login`}) — never `sudo`, elevation, remote, or unknown; and
3. a **sealed password exists** (`keyring arm` was run).

Crucially it does **not** perform a biometric check: the daemon cannot re-verify
a fingerprint (`fprintd` owns the sensor), and `pam_fprintd` has already
authenticated the user before `pam_irlume keyring` is reached.

Enable it by arming the keyring (`irlume keyring arm`) and wiring the greeter
(`irlume login enable --apply`, which now emits the `keyring` line). It is a
no-op until armed, and it is **independent of the camera tier** — a convenience
(RGB-only) laptop with a fingerprint reader gets keyring unlock, because the
trusted factor is the fingerprint, not the camera.

## Security analysis

**What is preserved.** At-rest protection is unchanged: the password is
TPM-sealed, so a **stolen disk / backup image cannot unseal it** (needs the live
TPM). Verified by the same cross-machine test as the face path
([SECURITY_AT_REST.md](../SECURITY_AT_REST.md)).

**The residual (documented, accepted).** `UnsealKeyring` releases the password to
*any root peer* in a login-class PAM context — it does not, and cannot, prove a
fingerprint actually occurred (a root process can call the daemon directly,
bypassing PAM, and forge the service string). So a **live root attacker can
obtain the sealed password.** This does **not** expand root's power: a live-root
attacker on the running machine can already read the unlocked keyring, ptrace
`gnome-keyring`, or keylog the next login. **Root remains the trust boundary** —
consistent with the rest of irlume's threat model and with Windows Hello, whose
container is likewise compromisable by a live administrator.

The service-class gate (2) is defence-in-depth, not a barrier against root: it
stops the `keyring` line from releasing the credential if mis-wired into a
non-login stack (e.g. `sudo`), but a direct caller can forge the service name.

**Strictly weaker than the face path** in one way: the face `UnsealPassword`
requires a daemon-verified **live biometric**, so even a live-root attacker
can't unseal without presenting a real face. Fingerprint keyring unlock can't
match that without the daemon owning the sensor.

## Alternatives considered

- **Empty-password keyring** (seahorse) — auto-unlocks but stores secrets
  unencrypted at rest. Rejected as the default; a worse security posture than
  this.
- **Daemon-side fprintd verify** (daemon claims the reader over D-Bus and
  verifies the fingerprint itself before unsealing) — would be as strong as the
  face path against live root (a root attacker couldn't fake a swipe to the
  daemon). Rejected *for now*: it means the daemon owns fingerprint auth (async
  D-Bus in a currently-sync daemon, replacing `pam_fprintd`), a large change.
  **Recorded as the future hardening** that closes the live-root residual.

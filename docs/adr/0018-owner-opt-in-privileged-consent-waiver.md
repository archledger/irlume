# ADR-0018: Owner opt-in waiver of the privileged typed confirmation

**Status:** Proposed
**Date:** 2026-08-29
**Amends:**
[ADR-0010](0010-conventional-face-intent-confirmation.md),
[ADR-0011](0011-single-field-privileged-auth-input.md)
**Implementation:** `privileged_face_consent` in `settings.conf`, PR #605

## Context

ADR-0010 requires a hidden typed `yes` before privileged face
authentication (sudo, polkit), and ADR-0011 fixes the single-field design
with "Empty Enter must not start the camera". The default is unchanged and
stays as those ADRs decided it.

Two facts motivated an owner-controlled exception. First, the act the
confirmation demands is already performed deliberately when the wiring is
created: `login enable --with-sudo/--with-polkit` is a separate,
owner-run step, so a machine whose owner took it has already chosen
privileged face authentication once. Second, users who want the
Windows-Hello experience, hands-free at every prompt, report the
per-attempt word as the remaining friction, and the machine's owner is
the right party to decide that trade for their own box.

Standing consent is not new in the system: the greeter and lock recipes
arm on an explicit empty-field Enter, and a shell may arm a dedicated
lane continuously. What none of those do is carry the grant to root
without an act, which is why the waiver below is opt-in, off by default,
and machine-scoped.

## Decision

`privileged_face_consent` in `/etc/irlume/settings.conf` (default on, the
confirmation required; `IRLUME_PRIVILEGED_FACE_CONSENT` overrides, env
wins). Set to `0` by the machine's owner, it waives the per-attempt word
on privileged services: a face attempt starts when the PAM prompt
appears, the way a lock-screen attempt does.

The daemon remains the authority. The PAM module skips its prompt only
after reading the same key the daemon will re-read before honoring the
waiver attestation, so a root PAM client cannot self-waive a
confirmation the machine's policy still requires. An absent, unset, or
unreadable setting means the confirmation stands: a policy that cannot
be read waived nothing.

Opting in accepts, and the documentation states: with `pam_irlume` first
and `sufficient`, every privileged prompt opens the camera, including
prompts typed by someone else at the machine and prompts raised from
scripts. Passive presentation-attack defense and the password fallback
are unaffected; a failed scan still falls back to the password, never a
lockout.

## Consequences

- The ADR-0011 clause "Empty Enter must not start the camera" remains
  true for every default installation and for every surface irlume wires
  itself; the waiver applies only to privileged services on machines
  whose owner set the key.
- The literal `yes` and the single-field password flow are unchanged and
  remain available on opted-in machines (the prompt is simply not
  shown first).
- ADR-0010's requirement stands as the default; this ADR enumerates the
  one exception and names who may elect it: the machine's owner, in
  root-writable configuration, re-read by the daemon on every use.
- `irlume support` and the settings table document the key and its
  default; the TUI does not expose it, matching the posture of the other
  advanced keys.

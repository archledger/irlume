# ADR-0011: Use one hidden field for privileged face intent or password

**Status:** Accepted
**Date:** 2026-08-19

## Context

[ADR-0010](0010-conventional-face-intent-confirmation.md) requires a hidden
literal `yes` before privileged face authentication. Its first implementation
treated every non-`yes` value as disposable intent input. Live KDE Plasma 6.7.4
testing found that a password entered in that field was discarded, so the user
had to type the same password into a second field before `pam_unix` could
authenticate. A random first value followed by the real password also
succeeded, confirming that only the second value reached the password module.

The field must remain echo-off. It must accept either explicit face intent or
the ordinary password without making irlume validate passwords itself. Empty
Enter must not start the camera.

Linux-PAM defines `PAM_AUTHTOK` for passing the current authentication token
between stacked authentication modules. `pam_get_authtok` returns a cached
token or prompts and caches one; `pam_unix` obtains its password through that
API. Linux-PAM wipes the temporary conversation response after caching it.

The pinned `pamsm 0.5.5` binding exposes get/set operations but cannot clear
`PAM_AUTHTOK`. Its custom `conv` wrapper also does not own and release secret
responses according to the PAM conversation contract, so it must not become
the password transport.

## Decision

Present one informational line before the normal localized hidden password
field:

```text
Type yes to use face authentication
```

Collect the field through `pam_get_authtok`, not the custom conversation
response. Preserve the existing bounded `yes` classifier.

- A non-empty non-`yes` token remains cached. `pam_irlume` returns
  `PAM_IGNORE`, and the downstream password module validates that same token
  without prompting again.
- An empty token is cleared and falls through, so the downstream module owns
  the password prompt and no camera request occurs.
- A `yes` token is cleared before any daemon request. Only after successful
  clearing may irlume send the existing typed intent attestation and acquire a
  camera.
- A pre-existing cached token is never interpreted as fresh face intent;
  irlume falls through without displaying its offer or contacting the daemon.
- Cancellation, conversation errors, and unsupported clients remain
  camera-free password fallback.
- Failure to clear a token aborts that PAM transaction before camera work. A
  fresh authorization request retains the password path; ambiguous token state
  is never reused as face intent.

Carry a minimal, checksum-pinned local patch of `pamsm 0.5.5` that adds a safe
`clear_authtok` operation backed by `pam_set_item(PAM_AUTHTOK, NULL)`. Preserve
the upstream license and provenance, keep the delta isolated, and remove the
local patch when an equivalent audited upstream release is available.

The daemon request and attestation contract do not change.

## Alternatives considered

### Copy the custom conversation response into `PAM_AUTHTOK`

This is the smallest functional diff, but `pamsm 0.5.5` does not release that
conversation response. Extending the path from the word `yes` to real passwords
would retain password bytes until the helper process exits. Rejected.

### Reach through `pamsm::Pam`'s private representation

The type is currently transparent over a PAM handle, so irlume could use unsafe
layout access and call `pam_set_item` itself. Rejected because it depends on a
private dependency representation at an authentication boundary.

### Keep the second password prompt

This preserves the current security behavior but makes the first field look
like a password field that discards valid passwords. Rejected after live KDE
testing.

## Consequences

- KDE and terminal users can type either `yes` or their password once.
- Empty Enter and all error paths remain camera-free.
- A failed face attempt reaches a fresh password prompt because `yes` was
  removed before camera work.
- Password bytes use Linux-PAM's token lifecycle and are never sent to irlumed,
  stored in irlume transaction data, or logged.
- The source tree temporarily carries a small audited dependency patch.
- The literal `yes` remains a reserved face-intent response. A user whose
  actual password matches an accepted spelling can still use it at the password
  prompt after face fallback or on a fresh password-only attempt.

The detailed implementation and verification contract is in the
[single-field privileged authentication design](../superpowers/specs/2026-08-19-single-field-privileged-auth-input-design.md).

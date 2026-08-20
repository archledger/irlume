# Single-field privileged authentication input design

Date: 2026-08-19

Status: implemented at `9fdfcb09d16fefbbe89815c7d2c7ad98c3a8ef01`;
software verification and installed rollout pending

Related decisions:

- [ADR-0010: Require conventional confirmation for privileged face authentication](../../adr/0010-conventional-face-intent-confirmation.md)
- [ADR-0011: Use one hidden field for privileged face intent or password](../../adr/0011-single-field-privileged-auth-input.md)

Observed evidence: Fedora 44 KDE Plasma 6.7.4 with Linux-PAM 1.7.2 and the
exact product candidate `392d15132322e2bde29559a23540ce9fbeb25f43`.

## Problem

The implemented privileged flow uses a custom echo-off PAM conversation to
collect `yes`. Every other response returns `PAM_IGNORE` without becoming
`PAM_AUTHTOK`. Live Plasma testing proved the resulting mismatch:

1. entering the real password in irlume's first hidden field did not
   authenticate;
2. Plasma displayed a second hidden field;
3. entering the real password there authenticated through `pam_unix`;
4. a random first value followed by the real password produced the same result;
5. neither password-only attempt contacted irlumed or opened the camera.

The safety boundary works, but the field contract does not. The field must
accept either explicit face intent or the ordinary password in one submission.

## Sources and binding constraint

Linux-PAM documents `PAM_AUTHTOK` as the token passed between stacked
authentication modules. Its `pam_get_authtok` implementation returns an
existing token first; otherwise it prompts, copies the response into
`PAM_AUTHTOK`, wipes the temporary response, and releases it. `pam_unix` calls
`pam_get_authtok` before password verification.

- [Linux-PAM 1.7.2 `pam_get_authtok` implementation](https://github.com/linux-pam/linux-pam/blob/v1.7.2/libpam/pam_get_authtok.c)
- [Linux-PAM 1.7.2 `pam_unix` authentication implementation](https://github.com/linux-pam/linux-pam/blob/v1.7.2/modules/pam_unix/pam_unix_auth.c)
- [Linux-PAM 1.7.2 release](https://github.com/linux-pam/linux-pam/releases/tag/v1.7.2)
- [`pamsm 0.5.5` `PamLibExt` API](https://docs.rs/pamsm/0.5.5/pamsm/trait.PamLibExt.html)

`pamsm 0.5.5` exposes `get_authtok`, `get_cached_authtok`, and `set_authtok`,
but no operation that sets the item to NULL. Its `conv` implementation returns
a borrowed `CStr` while dropping the response-array pointer, although the PAM
conversation contract makes the caller responsible for releasing both. The
existing `yes` prompt is small and process-bounded; expanding that mechanism to
passwords is not acceptable.

## Scope

Change only privileged-service PAM input handling and the minimum dependency
surface needed to clear `PAM_AUTHTOK`.

Keep unchanged:

- privileged service classification;
- the typed `PamConversation` request attestation;
- root-peer and pre-camera daemon enforcement;
- login, greeter, lock, and keyring flows;
- optional default-off head gestures;
- passive PAD, face matching, camera policy, and daemon protocol;
- installed PAM wiring and control stanzas.

## User-visible contract

For sudo, su, runuser, doas, and polkit, emit one `PAM_TEXT_INFO` message with
exactly:

```text
Type yes to use face authentication
```

Then request the normal localized PAM authentication token. Do not replace the
client's password label with an irlume-specific sentence. Input remains hidden.

The one field has three outcomes:

| Input | Result |
|---|---|
| Accepted `yes` spelling | Clear token, then offer one face attempt |
| Non-empty non-`yes` | Leave token cached for the downstream password provider |
| Empty Enter | Clear token, fall through, and never contact the daemon |

Cancellation or conversation failure never contacts the daemon.

The existing bounded confirmation spelling remains compatible: ASCII, at most
16 bytes, equal to `yes` after ASCII trim and case folding. Those accepted
spellings are reserved for face intent in the first field. Every other byte
sequence—including long and non-ASCII passwords—is password input rather than
invalid intent input.

## PAM state machine

Run after the current user, remote-session, mode, and service checks:

1. Read `PAM_AUTHTOK` without prompting.
2. If a non-empty cached token already exists, return `PAM_IGNORE`. It came from
   another module, not this fresh user action, so it cannot attest face intent.
3. Emit the exact `PAM_TEXT_INFO`. If the client cannot converse, return
   `PAM_IGNORE` without a daemon request.
4. Call `pam_get_authtok(PAM_AUTHTOK, NULL)` through `pamsm`. Linux-PAM owns
   prompting, localization, caching, temporary-response wiping, and release.
5. Classify the cached bytes without copying them into logs, Rust strings,
   daemon requests, or PAM module data.
6. For non-empty password input, leave `PAM_AUTHTOK` intact and return
   `PAM_IGNORE`. Fedora `pam_unix`, SSSD `forward_pass`, and equivalent
   downstream providers receive the same token through PAM.
7. For empty input, clear `PAM_AUTHTOK`; on success return `PAM_IGNORE`. On clear
   failure return `PAM_ABORT` before camera work.
8. For `yes`, clear `PAM_AUTHTOK`; only successful clearing produces
   `IntentAttestation::PamConversation` and permits one existing face request.
   Clear failure returns `PAM_ABORT` before camera work.
9. A face denial, timeout, policy refusal, or unavailable daemon returns the
   existing fallback result. Since `yes` is absent, the downstream provider may
   issue a fresh password prompt.
10. Face success retains the existing PAM control behavior. Optional head
    gesture remains an additional gate only.

No branch authenticates a password inside irlume.

## Dependency patch

Carry the exact source of `pamsm 0.5.5` in a clearly attributed third-party
directory and select it with Cargo's local patch mechanism. Make one behavioral
addition to `PamLibExt`:

```rust
fn clear_authtok(&self) -> PamResult<()>;
```

Its implementation calls `pam_set_item(pamh, PAM_AUTHTOK, NULL)`. Preserve the
upstream GPL-3.0 license, original source, version, and checksum/provenance in a
small README. Keep irlume's call site on the public method; do not inspect the
private `Pam` representation.

The patch is temporary dependency debt, not a new irlume abstraction. Record
the upstream reference if one is submitted separately, and remove the local
copy after an audited release exposes an equivalent operation.

## Error and secret handling

- Token-clear failure is an ambiguous PAM state and aborts the current
  privileged transaction. It cannot start face authentication.
- A new transaction restores ordinary password availability.
- Do not print prompt responses, byte lengths, hashes, classifier branches that
  distinguish password shape, or token-setting failures containing input.
- Do not clone password bytes into `String`, `Vec`, transaction data, daemon
  protocol values, diagnostics, or tests.
- Linux-PAM owns the cached copy and resets authentication tokens before the
  application regains control.
- Test passwords are fixed dummy values and must never appear in captured test
  output or committed snapshots.

## Test-first requirements

### Pure classifier

- accepted `yes` spellings still confirm;
- empty is the explicit empty branch;
- non-empty non-`yes`, long, and non-ASCII bytes are password branches;
- no type used for password-bearing results implements `Debug` or display.

### Patched binding

- `clear_authtok` maps successful NULL `pam_set_item` to success;
- PAM errors propagate without substitution;
- the public API does not expose the raw handle.

### PAM wrapper

- exact `PAM_TEXT_INFO` is emitted once before the hidden token prompt;
- `yes` clears the token and sends exactly one attested request;
- a dummy password reaches a downstream `pam_exec.so expose_authtok` verifier
  without a second conversation and without a daemon request;
- a wrong dummy password is attempted downstream, never sent to irlumed, and a
  fresh retry can accept another token;
- empty Enter clears the token, reaches password fallback, and sends no request;
- face denial after `yes` reaches a fresh password prompt rather than testing
  `yes` as a password;
- cancellation, info-message error, token-get error, and token-clear error are
  camera-free;
- a pre-cached token displays no face offer and sends no request;
- login, lock, unseal, keyring, and remote cases retain their current behavior;
- test stdout/stderr and journals contain none of the dummy secret values.

### Full gates

Run the existing PAM wrapper suite, full workspace tests, strict all-target
Clippy, rustdoc with warnings denied, release build, packaging parity, machine
contract checks, mixed-version directions, formatting, and diff checks. Verify
that every distribution source archive includes the attributed local patch.

## Live KDE acceptance

After a separately approved exact-OID install, revoke temporary polkit grants
before each harmless `pkexec /usr/bin/true` attempt:

1. `yes` displays the informational line, starts one face attempt, and succeeds
   through `pam_irlume`.
2. The real password entered once succeeds through `pam_unix`; irlumed has no
   journal entry.
3. A wrong password is rejected without camera work; the next real-password
   attempt needs one entry.
4. Empty Enter followed by Cancel is unauthorized and produces no daemon entry.
5. `yes` with face unavailable or denied presents a fresh password path without
   testing `yes` as a Unix password.

User observation is required for wording, field count, and retry layout. PAM
audit and daemon journals prove the backend factor and camera ordering only.

## Rollback

The currently installed candidate remains recoverable from
`/home/wisbfime/irlume-system-backups/2026-08-19-kde-intent-392d151` until the
new candidate passes live acceptance. A new install must add its own exact
binary hashes and preserve that earlier snapshot. On any prompt regression,
password failure, camera-before-`yes`, token-clear error, or service-health
failure, restore the last verified installed files and restart both irlume
units.

## Review status

The user selected the exact informational text, reproduced the double-entry
defect, validated empty-Enter safety, and approved the single-field token design
plus the minimal pinned `pamsm` patch. The implementation and real PAM-wrapper
proof are committed at the OID above; full software verification and installed
KDE acceptance remain separate gates.

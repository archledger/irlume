# Shared-greeter request-purpose correction (MS-04)

Date: September 20, 2026. Baseline: `a6805faa`.

## Reproduced failure

The RGB-only daemon gate classified a greeter request as screen unlock whenever
the selected user's `/run/user/<uid>` directory existed. That directory can
exist because of lingering services or another login. It describes account
state, not the purpose of this PAM transaction.

A camera-free regression now runs the actual daemon dispatcher and response
delivery against the real PAM module, Linux PAM and pam_wrapper over private
Unix sockets. It uses real SO_PEERCRED and the production retry store, replacing
only session facts and the biometric backend result under `cfg(test)`. The
baseline granted all four modeled cold-login cases with a runtime directory:
GDM and COSMIC, each in on-demand and face-first modes. Missing-directory
controls refused. No camera or enrolled biometric was used; the successful
biometric/PAD result was synthetic.

This proves the policy/PAM fallback interaction, not a live desktop bypass or a
weakness in matching/PAD. `UnsealUnavailable` can fall back to `Authenticate`;
refusing credential release is therefore insufficient to enforce login policy.

## Provider evidence and implementation decision

### COSMIC

Inspected upstream revision `0b0d2925ffa18ffb9a7f7175f90097bb502fbf43`:

- [main.rs](https://github.com/pop-os/cosmic-greeter/blob/0b0d2925ffa18ffb9a7f7175f90097bb502fbf43/src/main.rs#L34-L38)
  selects the greeter for the `cosmic-greeter` account and the locker for other
  current users.
- [locker.rs](https://github.com/pop-os/cosmic-greeter/blob/0b0d2925ffa18ffb9a7f7175f90097bb502fbf43/src/locker.rs#L128-L142)
  creates a PAM context for `cosmic-greeter` directly in the locker process.
- The [locked-event path](https://github.com/pop-os/cosmic-greeter/blob/0b0d2925ffa18ffb9a7f7175f90097bb502fbf43/src/locker.rs#L883-L960)
  starts that PAM work on a thread for the locker's current user.

This allows a conservative process-bound admission rule without a new
client-provided purpose claim. The selected user's UID must match the kernel
peer UID. A pinned proc directory and start time retain that process identity.
The fixed system bus's login1 `GetSessionByPID` must identify an active, local,
user-class x11/wayland session with that UID and a nonempty seat. The logind
owner, session object/ID, creation timestamp and relevant session properties
must still match before grant preparation and again before socket delivery.

The [login1 API](https://www.freedesktop.org/software/systemd/man/latest/org.freedesktop.login1.html)
defines GetSessionByPID, User `(uo)`, Seat `(so)`, and the boolean/string/timestamp
properties used by the reader. This API supplies session facts, not a generic
unlock-purpose attestation. It is used only with the source-established COSMIC
in-process PAM path. Another user's session or an arbitrary session belonging to
the account is never a substitute for the requesting process's session.

No logind, no session for this PID, malformed data, a remote/TTY/greeter session,
process exit or a changed session means password fallback. No environment
variable selects the D-Bus address. The method exchanges share an 800 ms budget;
the existing authentication window is rechecked after blocking validation.
This is not a claim that all kernel/socket operations have a hard real-time bound.

### GDM

Inspected upstream revision `65623d9abba3082d4f92aae7aa34551845ca5810`:

- [gdm-manager.c](https://github.com/GNOME/gdm/blob/65623d9abba3082d4f92aae7aa34551845ca5810/daemon/gdm-manager.c#L1081-L1140)
  obtains the caller's session/UID and distinguishes a login screen while opening
  reauthentication channels.
- [gdm-session-worker.c](https://github.com/GNOME/gdm/blob/65623d9abba3082d4f92aae7aa34551845ca5810/daemon/gdm-session-worker.c#L3140-L3167)
  constructs a separate reauthentication session and carries the caller's session.
- The [PAM setup](https://github.com/GNOME/gdm/blob/65623d9abba3082d4f92aae7aa34551845ca5810/daemon/gdm-session-worker.c#L1349-L1360)
  sets a caller-session environment marker and initializes PAM_TTY to the login
  VT. Neither the worker PID alone nor that TTY establishes unlock purpose.

Irlume's current request protocol has no qualified way to bind this provider's
caller-session context. It therefore refuses RGB-only GDM verification, including
GDM unlock, rather than substituting an account-wide session heuristic. Adding
GDM support requires a provider-specific, authenticated transaction contract and
its own tests. A session ID or boolean supplied by an arbitrary client is not
sufficient authority.

## Scope and tests

Dedicated locker service policy and IR-backed authentication are unchanged.
The shared context binding is retained only by its request and response; it is
not serialized, persisted or reused for later requests. Existing authorization,
PAD requirements, deadlines, cancellation and retry accounting remain active.

The real daemon/PAM matrix covers cold/ambiguous contexts, a bound local COSMIC
unlock, dedicated KDE controls, wrong selected user, explicit remote context,
unavailable session facts, changed logind owner, replaced session, cancellation,
and loss of context after a response has been prepared but before it is written.
A private synthetic password provider verifies both usable correct-password
fallback and wrong-password refusal. Separate tests cover D-Bus property
decoding, malformed/missing facts and process exit.

The review follow-up also replays the complete matrix inside a fresh user/PID/
mount namespace with a real `/run/user/0` directory on a private tmpfs. The child
asserts its namespace identity and the directory's existence before exercising
the production dispatcher. The host filesystem stays read-only apart from the
child's private `/tmp` and `/run`. This pins the original filesystem condition
without relying on the runner's login state or creating a host runtime directory.
Temporarily restoring the old runtime-directory promotion made this test fail
on the GDM on-demand cold-login case. Removing that mutation restored the pass;
the old heuristic is not part of the submitted change.

Run the cross-component regression with a freshly built PAM module:

```sh
cargo build -p irlume-pam --locked
scripts/run-tests-guarded.sh \
  --require shared_greeter_real_daemon_and_pam_refuse_cold_login_with_runtime \
  --require shared_greeter_real_daemon_and_pam_preserve_bound_unlock_and_password \
  --require shared_greeter_real_daemon_and_pam_recheck_before_grant_and_delivery \
  --require shared_greeter_real_daemon_and_pam_with_real_runtime_directory \
  -- cargo test -p irlume-daemon --locked -- --ignored shared_greeter_real_daemon --test-threads=1
```

The host needs pam_wrapper, PAM development headers, a C compiler and bubblewrap
with user namespaces available. Missing prerequisites fail the explicitly
requested tests; they do not silently skip.
CI enforces the four named tests. Default workspace runs leave them ignored.
All service files, socket paths and password fixtures are private to the test;
the installed PAM stack and real credentials are not touched.

## Remaining qualification

### Frontend initiation correction, 2026-09-21

At the pinned COSMIC revision, both
[locker Submit](https://github.com/pop-os/cosmic-greeter/blob/0b0d2925ffa18ffb9a7f7175f90097bb502fbf43/src/locker.rs#L1087-L1101)
and [greeter Auth](https://github.com/pop-os/cosmic-greeter/blob/0b0d2925ffa18ffb9a7f7175f90097bb502fbf43/src/greeter.rs#L1512-L1518)
discard empty input. The earlier policy fixture supplied empty input directly;
it did not prove that the frontend could initiate that request.

The module now uses a hidden password-or-`yes` prompt for the exact
`cosmic-greeter` on-demand active-probe path. Cached passwords are not consent,
and the explicit selection is consumed before daemon work. The policy fixture
supplies `yes` for that prompt while retaining all authorization assertions.
Additional real-PAM tests model the pinned empty-submit filter, explicit choice,
cached tokens, correct/wrong passwords, cancellation and fresh fallback.
The daemon's process/session binding is unchanged.

### Desktop qualification

These tests do not establish COSMIC's live process placement on every distro.
Desktop components launched outside a logind session may be refused even when
another graphical session exists. The [Fedora 44/COSMIC 1.8.0 check](2026-09-21-cosmic-frontend.md)
observed exactly that user-manager placement. It verified prompt initiation and
password fallback, without biometric grants. Qualify actual face unlock before
claiming fleet support. GDM's RGB-only
unlock path remains intentionally unavailable pending its separate provider
contract. Attended hardware and desktop validation remains outstanding.

# Conventional face-intent confirmation design

Date: 2026-08-19

Status: approved design, awaiting implementation plan

Related decision: [ADR-0010: Require conventional confirmation for privileged face authentication](../../adr/0010-conventional-face-intent-confirmation.md)

Research basis: [Temporal head-gesture recognizer validation](../../research/2026-08-19-temporal-head-gesture-recognizer-validation.md)

## Decision

irlume will require a conventional PAM conversation response before every
high-privilege face-authentication attempt. The user must type `yes` and press
Enter. Any other response selects the password/fingerprint fallback without
starting the camera.

Head gesture becomes optional and default-off. On high-privilege services it
may only add a second gate after conventional confirmation; it can never replace
the conventional response. Login, greeter, lock, and credential-release policy
remain separate and default to no head gesture.

## Motivation

NIST SP 800-63B-4 says passive face capture does not necessarily establish
authentication intent and gives a software or physical button as an explicit
mechanism. The completed irlume research found that the existing head classifier
can interpret ordinary look-around as approval or decline, while the available
single-participant corpus cannot validate a universal replacement.

Linux-PAM already supplies one cross-client conversation interface. irlume's
pinned `pamsm 0.5.5` exposes the standard PAM conversation styles, and polkit
authentication agents delegate native authentication through PAM. A literal
confirmation can therefore cover terminal and graphical privileged services
without a global input listener or desktop-specific plugins.

Sources:

- [NIST SP 800-63B-4, section 3.2.8](https://tsapps.nist.gov/publication/get_pdf.cfm?pub_id=959882)
- [Linux-PAM source](https://github.com/linux-pam/linux-pam)
- [polkit authentication-agent documentation](https://polkit.pages.freedesktop.org/polkit/polkit-agents.html)
- [polkit Authority interface](https://polkit.pages.freedesktop.org/polkit/eggdbus-interface-org.freedesktop.PolicyKit1.Authority.html)

## Goals

1. Require explicit user input for sudo, su, doas, runuser, and polkit face
   authentication before any camera opens.
2. Preserve immediate password/fingerprint fallback on refusal, cancellation,
   unsupported conversations, or errors.
3. Enforce confirmation at both the PAM module and daemon trust seams.
4. Keep head gesture optional, default-off, and additional-only for privileged
   services.
5. Preserve login, lock, keyring, PAD, camera, face-matching, rate-limit, and
   biopolicy behavior outside the intent change.
6. Remain fail-closed across mixed PAM/daemon versions.
7. Remove qualification machinery that no longer supports a release gate.

## Non-goals

- Do not claim that a PAM attestation is cryptographic proof of a physical
  keypress.
- Do not add a global keyboard listener or direct input-device access.
- Do not modify KDE, GNOME, or third-party polkit authentication agents.
- Do not require an extra irlume prompt for login, greeter, or lock-screen face
  authentication.
- Do not make head gesture population-qualified or default-on.
- Do not retune or replace the optional head classifier in this change.
- Do not change passive PAD or face-recognition policy.
- Do not install a candidate PAM stack until isolated and real-client tests
  pass and the user separately approves installation.

## Alternatives considered

### Desktop-specific confirmation buttons

Custom KDE, GNOME, text-agent, and terminal integrations could offer a native
button in each client.

Rejected because irlume does not own those clients, coverage would remain
incomplete, packaging and compatibility would multiply, and terminal PAM
services still need a separate path.

### Global hotkey or input listener

The daemon could listen for one key regardless of PAM client.

Rejected because it would require input-device privileges, seat/session
attribution, remote-session handling, and a new attack surface. It also
duplicates the standard PAM conversation interface.

### Treating the command or dialog as sufficient intent

Invoking sudo or displaying a polkit dialog already reflects some context.

Rejected because the threat being mitigated is an application initiating an
authentication request while the user happens to face the camera. Polkit's own
documentation says interactive authorization should stem from user action;
display alone is not a response.

## Service policy

| Surface | Conventional confirmation | Head gesture |
|---|---|---|
| `sudo`, `sudo-i`, `su`, `su-l`, `runuser`, `runuser-l`, `doas` | Mandatory, not configurable | Optional additional gate, default off |
| `polkit-1` | Mandatory, not configurable | Optional additional gate, default off |
| Login/greeter | Existing login submission; no extra irlume prompt | Optional, default off |
| Lock screen | No extra prompt | Optional, default off |
| Cold keyring/credential release | Existing greeter submission; no extra prompt | Optional, default off |
| Remote/unknown | Face path denied as today | Irrelevant |

The conventional confirmation requirement is derived from the shared normalized
PAM service table. A hand-written PAM line cannot bypass it by omitting a module
argument.

## PAM confirmation module

Add one private, pure response classifier and one thin conversation wrapper in
`irlume-pam`:

```rust
enum IntentConfirmation {
    Confirmed,
    Fallback,
}

fn classify_intent_response(response: Option<&[u8]>) -> IntentConfirmation;

fn confirm_face_intent(
    pamh: &Pam,
    service: ServiceKind,
) -> IntentConfirmation;
```

`classify_intent_response` is the test seam. It accepts only input that:

- is at most 16 bytes;
- is ASCII;
- equals `yes` after ASCII whitespace trimming and case folding.

No response, empty input, `no`, any other text, oversized input, non-ASCII
input, cancellation, a missing PAM conversation callback, or a conversation
error yields `Fallback`.

The prompt is one line, exactly:

```text
Face authentication: type yes and press Enter (input hidden), or press Enter for password:
```

It uses `PAM_PROMPT_ECHO_OFF`. Echo-off is load-bearing: a user who reflexively
types their password at the first PAM prompt must not expose it on a terminal or
screen. That mistaken response is discarded and falls through to the ordinary
password prompt. The response is read only for this decision,
never copied into `PAM_AUTHTOK`, PAM transaction data, logs, daemon messages, or
diagnostics.

## PAM authentication flow

For the ordinary verify/unseal module modes:

1. Resolve user and reject remote sessions as today.
2. Parse the module mode.
3. Preserve password-first handling. If a non-empty `PAM_AUTHTOK` already
   exists, return `PAM_IGNORE` before confirmation or camera work.
4. Resolve the PAM service from the shared table.
5. If the service requires conventional confirmation, invoke the prompt once.
6. On `Fallback`, return `PAM_IGNORE`; do not contact the daemon.
7. On `Confirmed`, send one face-authentication request carrying the typed
   confirmation attestation.
8. A high-privilege transaction wired with `wait` is refused to fallback. One
   confirmation never authorizes a retry loop.
9. If an explicit optional head gesture is enabled, the daemon applies it only
   after conventional confirmation. Otherwise no head-consent watch runs.
10. Preserve success, keyring delivery, polkit gesture-decline, and PAM control
    semantics after those gates.

For high privilege, `no` means “do not use face”; password fallback remains
available. Closing/cancelling the polkit dialog remains the authentication
agent's way to cancel the whole authorization request.

## Daemon request contract

Extend only the `Authenticate` request additively:

```rust
pub enum IntentAttestation {
    PamConversation,
}

Authenticate {
    user: String,
    service: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    intent_confirmation: Option<IntentAttestation>,
}
```

The attestation means: a trusted root PAM module reports that this request was
preceded by the specified conversation. It is not a signature and cannot prove
physical input against a malicious root process. Root is already inside the
daemon's trust model for PAM and credential release.

It also does not protect against a compromised PAM conversation provider that
silently answers `yes`. The design trusts the ordinary terminal or desktop
authentication agent to present and collect the prompt, just as PAM trusts that
provider for password prompts. Protecting a compromised polkit agent, display
manager, or root process is outside this mechanism's threat model.

At the daemon pre-camera gate:

- normalize and classify `service`;
- if it is high privilege, require `PamConversation`;
- require the peer uid to be root for that attestation;
- reject absent, malformed, untrusted-peer, or high-privilege `service=None`
  requests before queueing a worker or acquiring a camera;
- keep existing authorization, biopolicy, and operation-class gates after it.

Unprivileged clients cannot self-assert confirmation. Root-only developer tests
may exercise the field, but no production CLI command exposes a bypass flag.

## Mixed-version behavior

The change follows expand/contract compatibility:

1. Add the optional field and new-daemon enforcement together.
2. New PAM with an old daemon prompts first; the old daemon ignores the unknown
   field and may still require its legacy default head gesture. This is stricter,
   not weaker.
3. Old PAM with a new daemon sends no field; high-privilege face auth is refused
   before camera work and PAM falls back to password.
4. New PAM with a new daemon uses conventional confirmation and optional
   additional gesture policy.
5. Do not remove the optional wire field in this release line.

Unit and mixed-binary tests pin both reader directions.

Machine API contract 1 does not change. Conventional confirmation is a fixed
service policy, not mutable machine state; CLI and TUI render it from the same
shared service table the PAM module and daemon enforce. No new machine JSON
field or contract version is introduced.

## Head-gesture policy migration

Conventional confirmation is mandatory and has no settings or environment
override.

Head gesture defaults change:

- absent `service_gesture.<service>` means off for every service;
- explicit `service_gesture.<service>=1` remains enabled and becomes an
  additional gate on high-privilege services;
- explicit `=0` remains off;
- `IRLUME_POLKIT_GESTURE=1` and `polkit_gesture=1` remain explicit additional
  opt-ins;
- the old implicit-on polkit/elevation default is removed;
- credential-release and greeter/lock defaults remain off.

The existing key names remain for one-version compatibility. They are not
renamed to confirmation settings and cannot disable confirmation.

User-facing state becomes:

```text
Face confirmation: keyboard required
Additional head gesture: off | on (experimental)
```

Enabling head gesture warns that it is not population-qualified and may reject
valid attempts. Disabling it needs no risk warning because conventional
confirmation remains mandatory. Legacy eye blockers and tombstones retain their
already-approved migration window.

## Optional gesture safety

For high privilege:

- confirmation must succeed first;
- an optional nod can satisfy only the additional gesture gate;
- a false gesture approval cannot bypass missing confirmation;
- a shake keeps the existing typed decline behavior;
- no gesture or a false rejection falls through to password/fingerprint.

For login and lock, gesture remains a user-enabled experimental convenience.
Documentation must not describe it as population-qualified or equivalent to the
mandatory privileged confirmation.

## Developer-tool cleanup

The four-host live gesture matrix no longer supports a release gate. Remove:

- `scripts/hardware/run-head-gesture-matrix.sh`;
- `scripts/hardware/validate-head-gesture-matrix.py`;
- `scripts/hardware/test-validate-head-gesture-matrix.py`;
- `scripts/hardware/head-gesture-matrix-adapter.sh`;
- `scripts/hardware/test-head-gesture-matrix-adapter.py`;
- `gesturecap identity` and `gesturecap attempt`, which existed only for that
  matrix;
- current script/help/CI references to those tools.

Keep `gesturecap capture` and `gesturecap replay` as the small pose-only research
surface. Preserve dated research, plans, reports, commit history, and external
evidence; do not rewrite historical documents as current instructions.

Passive PAD, camera qualification, recovery, and package parity tooling remain.

## Test-first implementation order

1. Pure response parser and shared service confirmation policy.
2. PAM prompt/no-prompt behavior with no daemon request on fallback.
3. Additive common wire field and both mixed-reader directions.
4. Daemon root-attestation pre-camera gate.
5. PAM-to-daemon confirmation integration and optional gesture composition.
6. TUI/CLI policy wording and config migration.
7. Delete obsolete matrix and adapter surfaces.
8. Current documentation and ADR updates.

Every behavior begins with a failing test against the previous implementation.

## Required tests

### Pure and common

- exact/case-folded/trimmed `yes` confirms;
- empty, `no`, junk, non-ASCII, NUL-incompatible, and oversized responses fall
  back;
- every privileged service requires confirmation and no login/lock service does;
- old `Authenticate` JSON defaults confirmation to absent;
- a new request round-trips the typed attestation;
- an old reader ignores the additive field.

### PAM wrapper

- `yes` sends exactly one attested request;
- Enter, incorrect input, cancellation, and conversation error send no request
  and reach password fallback;
- a password accidentally entered at the confirmation prompt remains hidden,
  is never cached or logged, and reaches a fresh password prompt;
- a cached password prompts for neither confirmation nor camera;
- high-privilege `wait` sends no request;
- sudo, su, doas, runuser, and polkit receive the prompt;
- login, lock, keyring-only, reseal, and remote paths do not;
- optional gesture is evaluated only after `yes`;
- polkit gesture decline retains `PAM_ABORT`; ordinary fallback remains
  `PAM_IGNORE`.

### Daemon

- missing confirmation refuses every privileged spelling before worker/camera;
- non-root attestation is refused;
- root attestation reaches ordinary auth dispatch;
- `service=None` cannot claim privileged confirmation;
- non-privileged requests remain unchanged;
- refusal is typed and visible in diagnostics without recording prompt text.

### UI/configuration

- every gesture default is off;
- explicit old `=1` values become additional-only;
- confirmation cannot be disabled by settings or environment;
- TUI/CLI never describe optional gesture as the primary privileged control;
- enabling experimental gesture warns; disabling does not claim reduced
  security.

## Verification and rollout

Before any installed PAM change:

1. Pass unit, integration, pam_wrapper, machine-contract, full workspace,
   strict all-target Clippy, rustdoc, release build, packaging parity,
   formatting, shell/Python syntax, and diff gates.
2. Build one signed exact-OID candidate and verify identical artifacts in
   isolated Fedora, Ubuntu, and Arch checkouts.
3. Using isolated PAM stacks, verify:
   - terminal sudo/su/doas prompt rendering;
   - KDE/GNOME and text polkit prompt rendering;
   - Enter reaches password without camera request;
   - `yes` permits exactly one face attempt;
   - cancellation and unsupported conversations fall back;
   - optional head gesture cannot bypass confirmation.
4. Verify old/new PAM-daemon combinations in both directions.
5. Preserve password/fingerprint recovery at every stage.
6. Stop on any prompt invisibility, duplicate request, fallback failure,
   attestation bypass, camera-before-confirmation, or mixed-version regression.
7. Request separate user approval before installing or editing a host PAM stack.

Head gesture no longer needs a population-level release matrix because it is
default-off and cannot replace privileged confirmation. Its optional behavior
retains unit and pose-replay coverage without a security qualification claim.

## Consequences

- Privileged face authentication gains a reliable, accessible, explicit user
  action before camera activation.
- Password users press Enter once before the existing password prompt.
- Face users type `yes`, adding modest friction but removing ambient approval.
- Optional gesture false positives cannot bypass conventional confirmation;
  false rejects preserve fallback.
- Old PAM modules safely lose privileged face convenience with a new daemon
  until upgraded.
- The codebase loses a large live-matrix harness whose qualification claim no
  longer matches product policy.
- Gesture research may continue through small pose-only capture/replay tools
  without blocking the conventional-confirmation release.

## Review status

The user approved each design section and chose to skip an independent
cross-model review. A direct adversarial self-review was completed instead. It
identified and corrected the password-disclosure risk of an echo-on prompt,
made the attestation trust boundary explicit, pinned mixed-version and machine
API behavior, and made prompt rendering and fallback tests release gates.

This document is approved as a design only. Product implementation, isolated
real-client validation, and any installed PAM-stack change remain separate
steps. Installed PAM files must not change without the explicit approval in the
rollout section.

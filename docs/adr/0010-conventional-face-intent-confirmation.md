# ADR-0010: Require conventional confirmation for privileged face authentication

**Status:** Accepted; single-field prompt mechanics refined by [ADR-0011](0011-single-field-privileged-auth-input.md)
**Date:** 2026-08-19

## Context

[ADR-0009](0009-head-gesture-only-consent.md) made head gesture the default
intent control for privileged face authentication. Hardware validation then
found ordinary look-around motion classified as both approval and decline.
[Research](../research/2026-08-19-temporal-head-gesture-recognizer-validation.md)
rejected the proposed position-phase replacement and found that the available
single-participant corpus cannot validate a universal security control.

NIST SP 800-63B-4 says passive face capture does not necessarily establish
authentication intent and gives a software or physical button as an explicit
mechanism. Linux-PAM supplies a conventional conversation interface across
terminal and graphical clients.

## Decision

Require a literal echo-off PAM confirmation before every sudo, su, doas,
runuser, or polkit face attempt. Only bounded ASCII `yes` confirms. Any other
response, cancellation, unsupported conversation, or error skips face auth and
preserves password/fingerprint fallback.

The PAM module sends an additive typed attestation with the daemon request. A
new daemon accepts that attestation for privileged service names only from a
root peer and refuses missing or untrusted confirmation before camera work. The
attestation records the trusted PAM module's assertion; it is not cryptographic
proof against root or a compromised PAM conversation provider.

Head gesture becomes default-off and optional. For privileged services it may
only add a second gate after conventional confirmation and can never replace
it. Login, lock, and credential-release defaults remain gesture-off.

Mixed versions fail closed: a new PAM module with an old daemon may require
both mechanisms, while an old PAM module with a new daemon falls back to
password because it cannot attest confirmation.

Remove the four-host live gesture matrix runner, validator, detector adapter,
their tests, and matrix-only `gesturecap` commands. Keep pose-only capture and
replay for optional research, and preserve historical evidence.

The full implementation contract is the
[conventional face-intent confirmation design](../superpowers/specs/2026-08-19-conventional-face-intent-confirmation-design.md).

## Alternatives considered

- **Desktop-specific buttons:** rejected because irlume does not own every PAM
  client and terminal services still need another path.
- **Global input listener:** rejected because it requires input-device
  privileges and trustworthy seat/session attribution.
- **Command/dialog as sufficient intent:** rejected because an application can
  initiate a request while the user is merely present at the camera.

## Consequences

- Privileged face auth requires one explicit conventional response.
- Password users press Enter to bypass face and continue normally.
- Optional head gestures cannot weaken the mandatory gate.
- Head gesture is no longer described or qualified as the default privileged
  security control.
- PAM, daemon, CLI/TUI, documentation, packaging tests, and mixed-version tests
  must migrate together.
- Installed PAM stacks remain untouched until exact-OID isolated validation
  passes and the user separately approves installation.

## Review status

The user approved the design and chose to skip an independent cross-model
review. A direct adversarial self-review corrected the original echo-on prompt
to echo-off, documented the PAM/root trust boundary, and added fail-closed
mixed-version and fallback requirements. This ADR authorizes an implementation
plan; it does not authorize modifying an installed PAM stack.

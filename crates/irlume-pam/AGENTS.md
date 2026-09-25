# AGENTS.md: irlume-pam

The root [AGENTS.md](../../AGENTS.md) applies. `pam_irlume.so` is loaded into
login, sudo, polkit and greeter processes: a bug here grants a login or locks a
person out. It is critical-tier ([SECURITY.md](../../SECURITY.md)); the
`src/lib.rs` header documents the modes and arguments.

## Safety rules

- Every path that is not a confirmed grant returns `PAM_IGNORE`: errors,
  timeouts, no-match, an unavailable or older daemon, odd replies, remote
  sessions, a refused or failed unseal. Never `PAM_AUTH_ERR`; the password is
  the floor (SECURITY.md "Threat model (summary)").
- Two paths return `PAM_ABORT` on purpose; keep them and add no other: a
  consumed `yes` or empty intent token that `clear_authtok` cannot clear
  (`IntentConfirmation::Abort`, from `resolve_intent_input` or
  `confirm_cosmic_face`), so it never reaches the password module; and an older
  daemon's explicit polkit decline (`declined_by_gesture` and `is_polkit_consent`
  in `try_verify`), which `abort=die` in `POLKIT_VERIFY_STANZA` makes one failed attempt.
- In `authenticate`, `PAM_SUCCESS` only for a daemon grant, and in unseal mode
  only when the secret reached its consumer (`code_for`, `Released`,
  `only_a_real_delivery_continues_the_stack`). `setcred` is a constant `SUCCESS`.
- Keep every entry point inside `firewall`, which maps a panic to
  `PAM_IGNORE`; unwinding into libpam aborts sudo or the greeter.
- Decide `PAM_SUCCESS` only in explicit arms: a match on an irlume enum that can
  yield `SUCCESS` has no catch-all (`code_for` on `Released`), and a `_ =>` arm
  on a daemon reply returns only `PAM_IGNORE` (`try_verify`). A catch-all that
  answered `SUCCESS` is how #365 happened.
- The module holds no camera, models, templates or images and decides nothing:
  it maps each daemon reply to a PAM code ([docs/ARCHITECTURE.md](../../docs/ARCHITECTURE.md) "Privilege separation").
  Two bounded paths send more than one request, and both stay: `wait` retries
  `try_verify` or `try_unseal` until a match or `WAIT_BUDGET` (20 s), and with
  `facefirst` or `ondemand` an `UnsealUnavailable` (release refused before any
  face attempt) falls back to one identity-only `try_verify`. A denial,
  transport error or failed delivery never buys another attempt.
- It runs in setuid stacks with the caller's environment: read socket and
  helper paths only through `irlume_common::client::secure_env` (`socket_path`,
  `secure_helper_path`). Anything else that environment can change, such as
  `privileged_face_consent_required()`, must be re-checked by the daemon.
- Remote sessions never engage the camera: `is_remote_session` checks
  `PAM_RHOST`, remote-desktop service names and `SSH_*` (residual risk in
  [docs/THREAT_MODEL.md](../../docs/THREAT_MODEL.md)).
- Privileged intent: only a hidden `yes` selects a face attempt: ASCII, at most
  16 bytes, compared after trimming whitespace and ignoring case
  (`classify_intent_input`; its test pins ` YES ` and tab-wrapped `yEs`). Other
  non-empty input stays the password for the next module, and empty input never
  starts the camera (ADR-0010, ADR-0011). With `privileged_face_consent=0` the
  attempt starts at the prompt instead, and the daemon re-checks that key before
  honoring `IntentAttestation::PolicyWaived` (ADR-0018).
- Secrets (`PAM_AUTHTOK`, released tokens) stay in `SecretBytes` or
  `Zeroizing` and are never logged. A GNOME keyring token never rides
  `PAM_AUTHTOK` (`GKR_TOKEN_STASH_KEY`).
- Service names are classified, from a named source, in
  `crates/irlume-common/src/pam_service.rs` ([its AGENTS.md](../irlume-common/AGENTS.md)).
- Stacks using the module arguments (`unseal`, `wait`, `reseal`, `keyring`,
  `kr`, `facefirst`, `ondemand`) are written by `crates/irlume-cli/src/pamwire.rs`
  and `pamwire/stanzas.rs`, and on NixOS by `nix/module.nix`, which picks its
  own controls; a change to an argument's meaning or to the allowed controls
  updates both and runs `nix flake check --no-build --show-trace` beside the
  CLI wiring tests. Face lines are `sufficient`, `[success=1 default=ignore]`
  or, on polkit consent prompts, `POLKIT_VERIFY_STANZA` (`sufficient` plus
  `abort=die`); keyring and `reseal` lines are `optional`; never `required` or `requisite`.

## Testing

- Unit tests: `cargo test --locked -p irlume-pam`. `tests/pamwrap.rs` drives
  the real `.so` through a real PAM stack with pamtester and pam_wrapper,
  against an in-process fake daemon at `IRLUME_SOCKET`; no root, no daemon.
  - Fedora: `dnf install pam_wrapper pamtester`. Debian and Ubuntu:
    `apt-get install libpam-wrapper pamtester`. Elsewhere set
    `PAM_WRAPPER_SO=/path/to/libpam_wrapper.so`.
  - Run as CI does:
    `./scripts/run-tests-guarded.sh --min 16 -- cargo test -p irlume-pam --locked -- --include-ignored --test-threads=1`
  - Without the tools the tests print "skipping" and pass without testing
    anything (the COSMIC ones fail). Check `command -v pamtester` before you
    report them as passing. `nix develop` has neither tool; the COSMIC tests
    also compile a C driver (`cc`, libpam headers).
- The fake daemon must send the real wire text
  ([daemon AGENTS.md](../irlume-daemon/AGENTS.md)).
- Shared-greeter tests run the real daemon with this module; they compile a C
  driver, find pam_wrapper only at distro paths (not `PAM_WRAPPER_SO`) and need
  `/usr/bin/bwrap`:
  ```sh
  cargo build -p irlume-pam --locked
  cargo test -p irlume-daemon --locked -- --ignored shared_greeter_real_daemon --test-threads=1
  ```
- Some tests read `src/lib.rs` as text (for example
  `try_verify_prompts_one_action_line_from_the_reply_situation`); keep the
  markers they search for, or update the test in the same change.
- pamtester cannot drive `setcred` or a real display manager's conversation;
  that needs maintainer hardware validation, so say so in the PR.
- Never install the module or edit `/etc/pam.d` on your machine to try it.

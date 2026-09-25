# AGENTS.md: irlume-pam

The root [AGENTS.md](../../AGENTS.md) applies. `pam_irlume.so` is loaded into
login, sudo, polkit, greeter and lock-screen processes: a bug here grants a
login or locks a person out. It is critical-tier
([SECURITY.md](../../SECURITY.md)); the `src/lib.rs` header and the comments in
`authenticate` document the modes and arguments.

## Safety rules

- Apart from the two `PAM_ABORT` paths below and `setcred`'s constant
  `SUCCESS`, every path that is not a confirmed grant returns `PAM_IGNORE`:
  errors, timeouts, no-match, an unavailable or older daemon, odd replies,
  remote sessions, a failed unseal, or a refused one with no identity
  fallback. Never `PAM_AUTH_ERR`; the password is the floor (SECURITY.md
  "Threat model (summary)").
- Two paths return `PAM_ABORT` on purpose; keep them and add no other: a
  consumed `yes` or empty intent token that `clear_authtok` cannot clear
  (`IntentConfirmation::Abort`, from `resolve_intent_input` or
  `confirm_cosmic_face`), so it never reaches the password module; and an older
  daemon's explicit polkit decline (`declined_by_gesture` and
  `is_polkit_consent` in `try_verify`), which `abort=die` in
  `POLKIT_VERIFY_STANZA` makes one failed attempt.
- In `authenticate`, `PAM_SUCCESS` only for a daemon grant. In unseal mode that
  is a release whose secret reached its consumer (`code_for`, `Released`,
  `only_a_real_delivery_continues_the_stack`) or the identity-only fallback
  below, which delivers nothing; a lock screen running as the user unlocks
  that way.
- Keep every implemented entry point inside `firewall`, which maps a panic to
  `PAM_IGNORE`; without it the pinned pamsm dispatcher returns the panic as
  `PAM_ABORT`, a third abort path.
- Decide `PAM_SUCCESS` only in explicit arms: a match on an irlume enum that can
  yield `SUCCESS` has no catch-all (`code_for` on `Released`), and a `_ =>` arm
  on a daemon reply returns only `PAM_IGNORE` (`try_verify`). A catch-all that
  answered `SUCCESS` is how #365 happened.
- The module holds no camera, models, templates or images and decides no
  grant: it maps each daemon reply to a PAM code
  ([docs/ARCHITECTURE.md](../../docs/ARCHITECTURE.md) "Privilege separation").
  Three bounded paths send more than one request, and all stay: `wait` retries
  `try_verify` or `try_unseal` until a match or until an attempt ends after
  `WAIT_BUDGET` (20 s); with `facefirst` or `ondemand` an `UnsealUnavailable`
  (release refused before any face attempt) falls back to one identity-only
  `try_verify`; a denial, transport error or failed delivery never does
  (`wait` retries those until the budget runs out); and the `reseal` session
  line can send `ResealPassword` and then an `UnsealKeyring` query
  (`try_reseal_session`, `deliver_gnome_token`).
- It runs in setuid stacks with the caller's environment: read socket and
  helper paths only through `irlume_common::client::secure_env` (`socket_path`,
  `secure_helper_path`). Anything else that environment can change, such as
  `privileged_face_consent_required()`, must be re-checked by the daemon.
- `is_remote_session` keeps the camera off for known remote signals: a
  non-local `PAM_RHOST`, the names in `is_remote_desktop_service`, and
  `SSH_CONNECTION` or `SSH_TTY` in the calling process's environment. Known
  blind spots include remote control of the genuine local seat and a GNOME
  Remote Desktop headless login through `gdm-password` without `PAM_RHOST`
  (its comment in `src/lib.rs`).
- Privileged intent: only a hidden `yes` selects a face attempt: ASCII, at most
  16 bytes, compared after trimming whitespace and ignoring case
  (`classify_intent_input`; its test pins ` YES ` and `\tyEs\r\n`). Other
  non-empty input stays the password for the next module, and empty input never
  starts the camera (ADR-0010, ADR-0011). With `privileged_face_consent=0` the
  attempt starts at the prompt instead, and the daemon re-checks that key before
  honoring `IntentAttestation::PolicyWaived` (ADR-0018).
- Every copy the module makes of a secret (`PAM_AUTHTOK`, released secrets)
  must be zeroized: hold it in `SecretBytes`, in pamsm's `PamSecretBytes` for
  the PAM-data stashes, or in `Zeroizing` (the `set_authtok` `CString` from
  `secret_cstring`, which also wipes the copy a rejected one leaves). Never
  log one. A GNOME keyring token never rides
  `PAM_AUTHTOK` (`GKR_TOKEN_STASH_KEY`).
- Service kinds are classified, from a named source, in
  `crates/irlume-common/src/pam_service.rs`
  ([its AGENTS.md](../irlume-common/AGENTS.md)). `src/lib.rs` also matches
  names itself: `is_remote_desktop_service` (the camera-off deny-list) and
  `cosmic-greeter` (the COSMIC choice prompt). A remote service the module
  must stand down for goes in that deny-list.
- Stacks using the module arguments (`unseal`, `wait`, `reseal`, `keyring`,
  `kr`, `facefirst`, `ondemand`) are written by
  `crates/irlume-cli/src/pamwire.rs` and
  `crates/irlume-cli/src/pamwire/stanzas.rs` (every argument but `wait`), on
  NixOS by `nix/module.nix` (`unseal ondemand`, with its own controls), and on
  test boxes by `scripts/deploy-keyring-unlock.sh` (`wait`, `unseal`,
  `reseal`). A change to an argument's meaning or to the allowed controls
  updates all three and runs `nix flake check --no-build --show-trace` beside
  the CLI wiring tests. Face lines are `sufficient`,
  `[success=1 default=ignore]` or, on polkit consent prompts and the Omarchy
  lock (`omarchy-lock-password`), `POLKIT_VERIFY_STANZA` (`sufficient` plus
  `abort=die`); keyring and `reseal` lines are `optional`; never `required` or
  `requisite`.

## Testing

- Unit tests: `cargo test --locked -p irlume-pam`. The tests in
  `tests/pamwrap.rs` and `tests/pamwrap/cosmic.rs` are `#[ignore]`d (run them
  with `--include-ignored`, as below). They drive the real `.so` through a real
  PAM stack with pamtester and pam_wrapper, against an in-process fake daemon
  at `IRLUME_SOCKET`; no root, no daemon.
  - Fedora: `dnf install pam_wrapper pamtester`. Debian and Ubuntu:
    `apt-get install libpam-wrapper pamtester`. Elsewhere set
    `PAM_WRAPPER_SO=/path/to/libpam_wrapper.so`.
  - Run as CI does:
    `./scripts/run-tests-guarded.sh --min 16 -- cargo test -p irlume-pam --locked -- --include-ignored --test-threads=1`
  - The pamtester and COSMIC runners remove `SSH_CONNECTION`, `SSH_TTY` and
    `PAM_RHOST` from what they pass on (`remove_remote_env`), so the suite runs
    the same over SSH; set a marker on purpose with `run_with_env`.
  - Without pamtester or libpam_wrapper.so each `tests/pamwrap.rs` test returns
    early and passes (libtest hides its "skipping" note); only the COSMIC
    tests fail, so a filtered run that leaves them out tests no PAM stack. Check
    `command -v pamtester` and the wrapper path before you report a pass.
    `nix develop` has neither tool; the COSMIC tests also compile a C driver
    (`cc`, libpam headers).
- The fake daemon must send the real wire text
  ([daemon AGENTS.md](../irlume-daemon/AGENTS.md)).
- Shared-greeter tests run the real daemon with this module; they compile a C
  driver, find pam_wrapper only at distro paths (not `PAM_WRAPPER_SO`), load
  the real engine (models and ONNX Runtime, see the root AGENTS.md) and need
  `/usr/bin/bwrap` with unprivileged user namespaces
  (`bash scripts/ci-bubblewrap.sh --check`). CI wraps the test command in
  `./scripts/run-tests-guarded.sh` with one `--require` per test, since a
  filter that matches nothing exits 0:
  ```sh
  cargo build -p irlume-pam --locked
  cargo test -p irlume-daemon --locked -- --ignored shared_greeter_real_daemon --test-threads=1
  ```
- One test, `try_verify_prompts_one_action_line_from_the_reply_situation`,
  reads `src/lib.rs` as text; keep the markers it searches for in and just
  after `try_verify`, or update the test in the same change.
- pamtester cannot drive `setcred` or a real display manager's conversation;
  that needs maintainer hardware validation, so say so in the PR.
- Never install the module or edit `/etc/pam.d` on your machine to try it.

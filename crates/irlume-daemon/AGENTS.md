# AGENTS.md: irlume-daemon

The root [AGENTS.md](../../AGENTS.md) applies; this adds socket protocol and
posture rules for `irlumed`, a critical-tier component ([SECURITY.md](../../SECURITY.md)).
`src/main.rs` is about 18k lines: search for the names below.

## Wire compatibility

An old daemon keeps running through a package upgrade, so new clients meet old
daemons and the reverse ([packaging/README.md](../../packaging/README.md);
the `Request::ListProfiles` doc in `crates/irlume-common/src/lib.rs`).

- Never rename, remove or retype a field or variant of an existing `Request`
  or `Response`, or turn a unit variant into a struct variant. Add as below.
- A new optional request field is `#[serde(default)]`. Its default must keep
  the old behaviour or fail closed for a client that omits it (as
  `have_password` and `wallet_salt_checked` do), and an old daemon that drops
  the field must stay safe. Otherwise add a variant (why `IdentifyFor` exists).
- An old daemon answers an unknown request `Response::Error("bad request")`;
  clients fall back to an older request or say the daemon is older ("needs a
  newer irlumed; restart it after the upgrade").
- A new request may answer with a new `Response` variant; an existing request
  sends one only to a client that opted in with a `#[serde(default)]` flag
  (`structured_errors`). `UnsealUnavailable` (#682) is a past exception: do
  not copy it.
- New reply fields are `#[serde(default)]`, usually with `skip_serializing_if`,
  and the default must be right for an older daemon's reply: `Option<T>` for
  "did not say", or a `default = "fn"` that cannot mislead
  (`RecoveryStatus.key_present`), never a bare number or bool whose default
  is a wrong answer (`Enrolled.room`, #290). A new field breaks every struct
  literal of its type in other crates' tests (#817).
- A new value in an existing reply enum reaches a released client only through
  a fallback that client already has: a `#[serde(other)] Unknown` arm that
  shipped in an earlier release (adding both in one change protects only new
  clients), or the `wire_compatible` pattern of `IrOnlyReadiness`, where the
  old field carries a value old clients know and the precise one travels in a
  new field. Only `OutcomeCause`, `OperationErrorCode`, `IrOnlyReadiness`,
  `IrScope`, `IrTargetIssue`, `LiveStage` and `LiveOperationKind` have the
  `Unknown` arm; other reply enums, such as `KeyringSecretKind`, have none.
- Never add a field to a `#[serde(deny_unknown_fields)]` wire type
  (`EnrollmentDecision` in `crates/irlume-common/src/lib.rs`, the `*Wire` types
  in `crates/irlume-common/src/live_camera.rs`): an older peer rejects the whole
  message. Add a new variant or request instead. The `LiveStatus` and
  `SupportSnapshot` decoders also reject any other `live_schema` or
  `support_schema` and any value over their `MAX_*` bounds: bumping a schema
  or raising a bound breaks every released client.
- A new reply field that reaches a non-root peer carries no `/dev` path or
  serial; use handles and `vid:pid` (ADR-0030 §4 and its "Wire boundary"
  acceptance test).

## Posture tables

These matches name every `Request` variant with no wildcard, so a new variant
does not compile until its posture is chosen. Never add `_ =>`.

| Function | File | Decides |
|---|---|---|
| `posture` | `src/main.rs` | privilege (`AnyPeer`, `RootOrTarget`, `RootOnly`), target user, `EnrollmentEffect` |
| `classify` | `src/arbiter.rs` | `Auth`, `Camera`, `Plain` or `Status` |
| `approval_operation` | `src/operation_authorization.rs` | polkit action or `None`; adding trust needs one |
| `request_kind` | `src/live.rs` | live-status kind and whether it mutates |
| `diagnostic_operation_class` | `src/main.rs` | diagnostic trace class |
| `dispatch_scoped_session_inner` | `src/main.rs` | the worker's handler arm |

`Status` requests are answered on the connection thread and must not reach the
TPM, a camera or the engine there. File reads are fine
(`/etc/irlume/settings.conf` for `PreferencesStatus`, the attempt record for
`LastAttempts`, envelope paths and metadata, recovery store checks), and
`RetryReset` runs the password helper and writes retry state there. When
`dispatch_status` returns `None` (a `ListProfiles` whose enrollment summary is
not published, or is stale), the request queues to the worker, which does the
real load (a TPM unseal, maybe a template-key reseal) and publishes the
summary. Keep that fallthrough: answering the miss with an error made every
listing fail, since nothing ever reached the worker to publish. Camera work is
`Camera`, refused while an authentication is pending.

## Recipe: add a daemon request

A request is a new authorization surface: the latest account-scoped ones had an
ADR first (ADR-0030 §5 `LastAttempts`, §2 `IdentifyFor`); beyond a
root-or-account read, ask.

1. Add the variant to `Request` in `crates/irlume-common/src/lib.rs`; its doc
   comment states the privilege and that an older daemon answers
   `Error("bad request")`. Reuse a `Response` variant where one fits.
2. Add a two-way wire test in irlume-common, like
   `identify_for_names_its_account_and_is_unknown_to_an_older_daemon`.
3. Build, answer every posture table, and add a sample to `request_catalog!` in
   the `src/main.rs` tests (user-bearing ones via its `u()`; `alternative_shapes`
   if `posture` reads a field); its tests then check approval and user screening.
4. Check what the compiler does not force. A `Status` request is answered in
   `dispatch_status_with_diagnostics` or an early branch of `serve_peer`
   (`TraceSubscribe`, `RetryStatus`, `RetryReset`). To answer while models
   load, a `Status` request joins the pre-readiness `matches!` list in
   `serve_peer` (as `LastAttempts` does); other requests need a
   `dispatch_before_engine` arm, where a face request files its
   `DaemonStarting` attempt. Face attempts need `AttemptContext::for_request`
   and `peer_may_file_for`. Choose the `EnrollmentEffect`: `AddsTrust` for
   anything that adds trusted templates (`approval_operation` must then name
   an action; `every_trust_adding_request_needs_os_approval_for_a_non_root_peer`
   checks it), `Mutates` for other rewrites of the enrollment or of the key it
   is sealed under (both drop the published summary), else `Reads`. A request
   that needs approval joins the list in
   `os_approval_covers_exactly_the_enrollment_and_recovery_changes`.
5. Clients: `daemon_request` in `crates/irlume-cli/src/main.rs` (380 s list if
   it waits on polkit), docs/COMMANDS.md for a new command, and the TUI and
   `--json` output per [its AGENTS.md](../irlume-cli/AGENTS.md).
6. Tests: a refused peer turned away before queueing (`peer(NOBODY)`) and a
   dispatch test on `engine()` and `sandbox()`. `RootOrTarget` resolves through
   NSS and `SAMPLE_USER` (carol) does not exist, so test the allowed peer as the
   running account (`users::name_for_uid(libc::geteuid())`, `peer(uid)`). Update
   CHANGELOG, and THREAT_MODEL.md or SECURITY_AT_REST.md when trust or stored data change.
7. A new path, device or capability also needs both AppArmor profiles (and the
   rule in `APPARMOR_RUNTIME_RULES` of `scripts/check-packaging-parity.sh`),
   the SELinux policy in `packaging/selinux/` (that script does not check it),
   and `packaging/systemd/irlumed.service` plus the sandbox `nix/module.nix`
   mirrors by hand, with exposure at or below 37 (CI job "systemd units"). A
   new polkit action needs its policy file in `packaging/polkit/`, installed
   by every distro lane and `nix/package.nix`, and an `AUTH_PAYLOAD` entry in
   that script.

## Tests in this crate

- Take `env_lock()` (`test_support::env_read()` if the test only resolves
  users), then `engine()`, and declare the guard before `sandbox()` so the
  sandbox drops under it. `engine()` uses nonexistent devices and `IRLUME_FORCE_NO_IR=1`.
- `every_test_that_resolves_a_user_holds_the_env_lock` scans its `include_str!`
  file list: a test calling `pregate(`, `serve(` or another listed reader holds
  `env_lock()`, `env_read()` or `enrollment_summary_test_lock()` (which is
  `env_lock()`: never take both). List a new module there; each listed file
  must contain a `#[test]`.
- Process-wide state crosses tests: the enrollment summary cache (`sandbox()`
  clears it), `engine()`, the per-uid camera-probe interval. Use a unique
  `sandbox(tag)`. Prefer `with_serve`; join a `serve` on a bare `thread::spawn`
  through a handle named `server` (`server.join()` is what the scan matches).
- `with_serve` runs the real `serve` over a socket pair (`with_serve_as_peer_and_diagnostics`
  for a chosen peer); `dispatch(req, &peer(uid), &mut engine())` skips the socket.
- Write enrollments with `write_enrollment`, never `storage::save` (host TPM).
- Mocks copy exact wire text: engine errors are `Response::Error(e.to_string())`
  with the `Error` Display prefix; posture refusals come from `not_authorized`
  and `pregate`, not `Error::NotAuthorized`.
- The ignored `shared_greeter_real_daemon*` tests need pam_wrapper, a C
  compiler (one also bubblewrap) and `cargo build -p irlume-pam --locked`
  first. CI runs them with
  `-- --ignored shared_greeter_real_daemon --test-threads=1`.
- Logs follow `deny_score` and `deny_reason`; device text uses `journal_safe`.

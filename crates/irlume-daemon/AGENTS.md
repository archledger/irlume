# AGENTS.md: irlume-daemon

The root [AGENTS.md](../../AGENTS.md) applies; this adds socket protocol and
posture rules for `irlumed`, a critical-tier component ([SECURITY.md](../../SECURITY.md)).
`src/main.rs` is about 18k lines: search for the names below.

## Wire compatibility

An old daemon keeps running through a package upgrade, so new clients meet old
daemons and the reverse ([packaging/README.md](../../packaging/README.md);
the `Request::ListProfiles` doc in `crates/irlume-common/src/lib.rs`).

- Never change the shape of an existing `Request` or `Response` variant.
- A new optional request field is `#[serde(default)]`, and only if an old daemon
  that drops it stays safe. Otherwise add a variant (why `IdentifyFor` exists).
- An old daemon answers an unknown request `Response::Error("bad request")`;
  clients say it "needs a newer irlumed; restart it after the upgrade".
- A new request may answer with a new `Response` variant; an existing request
  sends one only to a client that opted in with a `#[serde(default)]` flag
  (`structured_errors`). New reply fields use `#[serde(default, skip_serializing_if = ...)]`;
  new reply enum values need `#[serde(other)] Unknown` or a `wire_compatible`
  widening. A new field breaks every struct literal of its type in other
  crates' tests (#817).
- Never add a field to a `#[serde(deny_unknown_fields)]` wire type
  (`EnrollmentDecision` in `crates/irlume-common/src/lib.rs`, the `*Wire` types
  in `crates/irlume-common/src/live_camera.rs`): an older peer rejects the whole
  message. Add a new variant or request instead.
- Non-root peers never receive `/dev` paths or serials; use handles and
  `vid:pid` (ADR-0030 acceptance test "Wire boundary").

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

`Status` requests are answered on the connection thread only from memory, and
never touch TPM, camera or engine there. When `dispatch_status` returns `None`
(a `ListProfiles` whose enrollment summary is not published, or is stale), the
request queues to the worker, which does the real load (a TPM unseal, maybe a
template-key reseal) and publishes the summary. Keep that fallthrough:
answering the miss with an error made every listing fail, since nothing ever
reached the worker to publish. Camera work is `Camera`, refused while an
authentication is pending.

## Recipe: add a daemon request

A request is a new authorization surface: account-scoped ones had an ADR first
(ADR-0030 §5 `LastAttempts`, §2 `IdentifyFor`); beyond a root-or-account read, ask.

1. Add the variant to `Request` in `crates/irlume-common/src/lib.rs`; its doc
   comment states the privilege and that an older daemon answers
   `Error("bad request")`. Reuse a `Response` variant where one fits.
2. Add a two-way wire test in irlume-common, like
   `identify_for_names_its_account_and_is_unknown_to_an_older_daemon`.
3. Build, answer every posture table, and add a sample to `request_catalog!` in
   the `src/main.rs` tests (user-bearing ones via its `u()`; `alternative_shapes`
   if `posture` reads a field); its tests then check approval and user screening.
4. Check what the compiler does not force: a `Status` request is answered in
   `dispatch_status_with_diagnostics`; one that must answer while models load
   needs an arm in `dispatch_before_engine` (reached from `serve_peer`); face
   attempts need `AttemptContext::for_request` and `peer_may_file_for`. Anything
   that rewrites an enrollment is `EnrollmentEffect::Mutates`.
5. Clients: `daemon_request` in `crates/irlume-cli/src/main.rs` (380 s list if
   it waits on polkit), docs/COMMANDS.md for a new command, and the TUI per
   [its AGENTS.md](../irlume-cli/AGENTS.md).
6. Tests: a refused peer turned away before queueing (`peer(NOBODY)`) and a
   dispatch test on `engine()` and `sandbox()`. `RootOrTarget` resolves through
   NSS and `SAMPLE_USER` (carol) does not exist, so test the allowed peer as the
   running account (`users::name_for_uid(libc::geteuid())`, `peer(uid)`). Update
   CHANGELOG, and THREAT_MODEL.md or SECURITY_AT_REST.md when trust or stored data change.
7. A new path, device or capability also needs both AppArmor profiles, the
   SELinux policy and the `irlumed.service` sandbox in `packaging/`
   (`scripts/check-packaging-parity.sh`), with exposure at or below 37.

## Tests in this crate

- Take `env_lock()` (`test_support::env_read()` if the test only resolves
  users), then `engine()`, and declare the guard before `sandbox()` so the
  sandbox drops under it. `engine()` uses nonexistent devices and `IRLUME_FORCE_NO_IR=1`.
- `every_test_that_resolves_a_user_holds_the_env_lock` scans its `include_str!`
  file list: a test calling `pregate(`, `serve(` or another listed reader holds
  `env_lock()`, `env_read()` or `enrollment_summary_test_lock()` (which is
  `env_lock()`: never take both). List a new source file there.
- Process-wide state crosses tests: the enrollment summary cache (`sandbox()`
  clears it), `engine()`, the per-uid camera-probe interval. Use a unique
  `sandbox(tag)`; join any `serve` started on a bare `thread::spawn`.
- `with_serve` runs the real `serve` over a socket pair (`with_serve_as_peer_and_diagnostics`
  for a chosen peer); `dispatch(req, &peer(uid), &mut engine())` skips the socket.
- Write enrollments with `write_enrollment`, never `storage::save` (host TPM).
- Mocks copy exact wire text: engine errors are `Response::Error(e.to_string())`
  with the `Error` Display prefix; posture refusals come from `not_authorized`
  and `pregate`, not `Error::NotAuthorized`.
- `shared_greeter_real_daemon*` tests need `cargo build -p irlume-pam --locked`
  first. Logs follow `deny_score` and `deny_reason`; device text uses `journal_safe`.

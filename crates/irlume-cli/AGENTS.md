# AGENTS.md: irlume-cli

The root [AGENTS.md](../../AGENTS.md) applies; this adds rules for the `irlume`
CLI, TUI and machine API. `src/tui.rs` is about 24k lines, tests from about
line 11650: search for the names below.

## CLI

- `src/main.rs` parses argv by hand (`flag`, `flag_present` accept `--x v` and
  `--x=v`); commands are documented in [docs/COMMANDS.md](../../docs/COMMANDS.md).
- `DEV_CMDS` need `IRLUME_DEV=1` and are never an auth path. The capture ones
  open the camera directly; `eval`, `normprobe`, `padreport`, `suncal` and
  `selftest align` read saved files or synthetic data. `selftest liveness` is
  ungated because the TUI runs it, and goes through the daemon; keep its camera
  access there. A new
  call site that opens or enumerates a video node fails
  `tests/camera_authority.rs` unless marked `// deliberate camera probe:` or
  `// the one permitted probe`; the daemon is the camera authority while it runs.
- `src/pamwire.rs` and `src/pamwire/stanzas.rs` write the `irlume login` PAM
  stacks; the allowed controls are in [the PAM AGENTS.md](../irlume-pam/AGENTS.md).
  Apply, verify and rollback live in `src/logintx.rs`.

## Machine API (`--json`)

Contract 1 is public ([docs/MACHINE-API.md](../../docs/MACHINE-API.md)): one
JSON document on stdout except `-events` streams, fields only added, no
`--contract` means 1. `src/machine.rs` is deliberately narrower than the socket
protocol. The KCM consumes it and the `tui --page` slugs (`PAGE_NAMES` in
`src/tui/launch.rs`): never rename them.

1. Change output in `src/machine.rs`.
2. Describe it in `schemas/machine-api-v1.schema.json` and MACHINE-API.md;
   `--strict` conformance fails on any undescribed property.
3. A new `doctor` check id goes in MACHINE-API.md's `| Check id |` table
   (`every_doctor_check_id_is_documented_and_every_documented_id_exists`).
4. Do not regenerate `schemas/fixtures/`: `scripts/capture-machine-fixtures.py`
   needs a running installed daemon and is run before a release (its
   docstring). Say in the PR that the fixtures need a re-capture.
5. Run the conformance commands from the root AGENTS.md.

## TUI rules

[ADR-0030](../../docs/adr/0030-tui-interaction-model.md) section 1 and
[docs/TUI.md](../../docs/TUI.md) are the rules; new code follows them even
where older page text breaks them.

- Enter opens and never mutates; Esc closes the innermost thing and never
  quits. Every side effect has its own letter; writes and root actions go
  through the confirmation dialog (`ConfirmAct`).
- Global keys are fixed (docs/TUI.md "Keys that mean the same thing on every
  page"): `1`-`9`, Tab, Shift-Tab, arrows, `j`, `k`, `g`, `G`, `h`, `v`, `?`,
  `q`, `M`, `A`, `L`, `r` (refresh only), `i` (Test Recognition only), Home,
  End, PageUp, PageDown, F2, F3, F4, F6. `on_key` takes them before any page
  arm, so page letters (verbs) never reuse them; check the ones
  `page_action_keys_never_collide_with_global_keys` does not.
- Advertise a key in exactly two places that agree: `screen_actions()` (every
  bound key, primary first) and the page's action rows (`push_page_actions`).
  Prose never embeds a key.
- Five status glyphs only: `●` ready, `○` off, `◐` unobserved or pending, `✕`
  absent, `⚠` needs attention. Rows state facts, not "yes". Truncate with an
  ellipsis. Node paths, `vid:pid`, NV handles and hashes stay in details or
  Diagnostics. Never show a score, threshold or similarity (section 5).
- Rendering never opens a device or blocks: loads drain in `poll`, and daemon
  work goes through `start_async` or `start_async_task`, routed by `OpTag`.
  Device text passes through `printable` (`src/tui.rs`); camera names arrive
  already cleaned by `irlume_camera::camera_display_name`.
- Internal names differ from labels: `SC_WELCOME` Overview, `SC_REPAIR`
  Diagnostics, `SC_PROFILES` Faces, `SC_KEYRING` Password Wallet, `SC_PAM`
  Login & Apps, `SC_SETTINGS` Preferences, `SC_DONE` Setup Status.

## Recipe: add a TUI action

1. Pick a verb letter that passes the global-key test.
2. Add an `(SC_X, KeyCode::Char('x'))` arm in `on_action`, which `on_key` falls
   through to after the global keys. Only read-only daemon work sends at once,
   with `start_async(label, OpTag::..., Request::..., map_fn)`, routed in
   `poll`. A write or root action sets
   `self.confirm = Some((prompt, label, ConfirmAct::...))` and runs only when
   the dialog is confirmed, so no key press mutates on its own.
3. List the key in `screen_actions()` and the page's `draw_*` action rows.
4. Put pure logic in a `src/tui/*.rs` module that takes the clock as an
   argument (see `tui/attempts.rs`, `tui/dates.rs`).
5. Map `Response::Error("bad request")` to "needs a newer irlumed". A request
   the TUI sends gets a `request_effect` sentence; a More actions entry goes in
   `tui/actions.rs` `ACTIONS` and the docs/TUI.md command table. Test, and
   update docs/TUI.md and the CHANGELOG.

## Tests

- TUI behavior: `let _g = dead_socket();` (holds the env lock), `test_app()`,
  `on_key`, then `wait_op_done`, `wait_live_done`, `wait_enroll_done` or
  `drain_loads` before the guard drops. For a mock daemon, point
  `IRLUME_SOCKET` at a fake that answers one line-JSON request per connection.
- `test_app()` starts with every capability false and `poll` re-derives
  `caps`; pin `reported_caps` for a camera. Pin time with `app.clock_override`
  and `app.wall_override` (which zeroes the zone). Render with `draw_text` or
  `draw_text_at(app, w, h)` and `row_with`.
- Gallery (`synthetic_visual_gallery_all_screens_and_overlays` in
  `tui/visual_tests.rs`): synthetic state only, never `App::new`, `poll`,
  `enter_screen` or a dispatch; update its `SCREENS.len() * 3 + N` count when
  adding frames. `IRLUME_TUI_GALLERY_DIR=<absolute dir>` exports the frames.
- A new page key must pass `every_advertised_key_does_something_on_its_screen`
  (pressed on a plain `test_app()`, it changes something visible),
  `every_screen_survives_every_key`, `help_overlay_lists_every_bound_key_of_the_screen`
  and `footer_lists_each_screens_action_keys`. Helpers: `state_row`, `fake_op()`.
- A new background load is an `App` field: add it to `App::new`, the
  `test_app()` literal and `drain_loads`, or its worker outlives the guard and
  reads the next test's `IRLUME_SOCKET`.
- Other env tests hold `crate::testenv::ENV_LOCK`. Black-box tests
  (`tests/cli.rs`: `Sandbox`, `serve`) run the binary directly under the
  sandbox environment overrides; only `isolated_root_cmd`, for fixed-path root
  probes, needs `/usr/bin/bwrap`, so the rest run on a host without it.

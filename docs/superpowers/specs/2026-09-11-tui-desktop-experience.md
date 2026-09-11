# Irlume desktop TUI experience

## Purpose and scope

Make the existing terminal interface the primary interactive place to set up,
configure, and inspect Irlume. The user requested implementation and delegated
visual design choices. Keep the existing Ratatui application, CLI actions,
authorization checks, existing protocol behavior, and supported terminal environments.
Extend the protocol additively where current daemon observations are missing.

The audit covers Overview/first run, Faces, Fingerprint, Password Wallet,
Recovery, Login & Apps, Diagnostics, Cameras, Test Recognition, Preferences,
legacy Setup Status, action search, dialogs, and Activity. Changes should repair
observed usability and correctness gaps, not add a second application framework.

## Design decisions

1. Use a consistent settings interface: grouped navigation, clear selected and
   focused controls, keyboard and mouse access, visible action labels, and
   layouts that remain usable in supported smaller terminals (at least 80×24). Preserve shortcut workflows
   and all confirmations for security-sensitive actions.
2. Use semantic state badges. Enabled is green, intentionally disabled is
   neutral, unknown is amber, and errors are red. Always include a word and
   glyph so color is never the only signal. Respect `NO_COLOR` and the terminal
   theme; do not infer a dark background merely from truecolor support.
3. Activity is this TUI session's history. Show elapsed timestamps, explicit
   result labels, full readable details, and follow/history controls. Keep
   bounded memory and a stable reading position when entries arrive or expire.
   A compact summary must not let wrapped older messages hide the newest result.
   Expanded history must make every retained line reachable by keyboard/mouse.
4. State the limits of Activity honestly: it is not a complete operating-system
   audit or proof that a camera is physically off. Link users to existing
   diagnostic/history actions for additional daemon observations. Do not add
   raw request, password, token, frame, template, or biometric export logging.
5. A lost background worker must release its loading state. Retained historical
   observations must not remain usable as current state after failure or expiry.
   Explain that refresh failed and allow retry. A foreground
   operation without a result has an unknown outcome, not success or confirmed
   rollback. Refresh enrollment state after an interrupted enrollment worker.
6. Install an Irlume application-menu entry with `Exec=irlume tui`,
   `TryExec=irlume`, and `Terminal=true`, plus a scalable application icon.
   Desktop environments select the terminal; no shell command construction,
   terminal guessing, automatic sudo, or automatic authentication action is
   introduced. Nix uses the installed executable's store path. Keep equivalent
   assets in Fedora, Arch, Debian, PPA, Nix, and source install/uninstall flows.

## Live observations and hotplug

The user expanded the request to automatic, present-state observations across
the TUI. This includes changes made through other Irlume clients while the TUI
is open. A poll is an observation, not a promise of instantaneous knowledge:
show observation age and explicit updating/unavailable states whenever freshness
cannot be established. Never turn a failed read into an empty list or OFF badge.

- Add a bounded, memory-only `LiveStatus` daemon response. It reports daemon
  instance, uptime, lifecycle stage, the current worker operation and waiting
  operation counts, independent automatic background qualification, and a
  separately sourced passive camera inventory. Requests
  for this response must not enter the camera worker, open devices, read the TPM,
  initialize a monitor, or append observer events to history. Poll it about once
  a second, including while dialogs and foreground operations are open. F4
  opens scrollable Current observations with full operation and freshness details.
- Live work uses closed categories and opaque operation identifiers. Do not
  publish account names, request arguments, credentials, profile names, raw
  errors, biometric outcomes or inference-stage data. Cancellation stays
  requested until the operation actually ends. This describes daemon worker
  activity, not every operating-system process or physical camera/emitter state.
- Publish a state revision when potentially mutating daemon work finishes.
  Clients use it as an invalidation hint, including on failure; it does not
  assert that a mutation succeeded. This helps external changes invalidate
  cached profile/settings observations without repeatedly reading the TPM.
- Track each independently fallible data source separately: successful time,
  failure/expiry, and an invalidation generation. A successful sibling read does
  not freshen another result. Discard pre-mutation completions and schedule one
  replacement when an explicit refresh arrives during an existing read.
  Keep worker counts bounded. Label deliberate one-shot diagnostics as past
  observations rather than automatically recapturing to make them current.
- The daemon initializes its passive device monitor independently of status
  queries. Its copied inventory distinguishes uninitialized, current,
  refreshing and unavailable, including valid-empty versus failed-empty states.
  Bounded passive recovery belongs to the monitor worker. A current UVC census
  is not a universal census of all camera backends.
- Show attached passive candidates immediately. RGB/IR role classification
  remains a separate observation because sysfs alone cannot establish those
  roles. While Cameras is visible and idle, classify at most once for a changed
  inventory revision; do not repeatedly request capture qualification. Show
  inspection progress/failure honestly. Remove disconnected choices and bind
  retained classification and selection to instance/generation/endpoint identity.
  Invalidate a pending camera switch when that identity changes, and recheck it
  before executing the captured action. Carry the expected supervisor and
  candidate identity through the administrator prompt in a distinct guarded
  request. The daemon rechecks it before mutation; older daemons refuse that
  request rather than silently dropping an optional guard field.

A periodic refresh cannot establish physical device shutdown or observe a change
that the underlying source cannot report. The interface must name its scope
and uncertainty instead of making those claims.

## Alternatives considered

A color-only pass would leave interaction, clipped Activity messages, and menu
discovery unresolved. A standalone graphical application would duplicate the
current interface and add packaging/runtime obligations. A custom terminal
launcher would duplicate desktop policy and terminal argument conventions.
Improve the existing TUI and delegate terminal selection to the desktop entry.

## Verification and acceptance

- Establish the existing TUI test baseline with fake/dead daemon sockets.
- Reproduce confirmed Activity and worker-loss defects with failing tests.
- Exercise screen rendering, state semantics, focus, mouse hit targets, dialogs,
  resizing, scrolling, and unknown states using Ratatui TestBackend.
- Inspect rendered synthetic screen examples in color and without color;
  never use enrolled data to produce review artifacts.
- Validate the desktop file/icon and supported package/source install paths,
  including source uninstall, without installing or changing this host.
- Run the relevant real formatter, Clippy, build, tests, packaging checks,
  and an independent final diff review. Record environmental limits accurately.
- Exercise live-state guards with synthetic time, partial failure, old-worker
  completion, external mutation, daemon restart, hotplug/reordering, lost
  monitors and interrupted operations. Prove the live getter has no camera/TPM
  side effects. Render current/updating/unavailable states and disconnected
  selections; keep old-daemon behavior explicitly unavailable.

No attended camera test or installed-system change is part of this UI work.

## Primary references

- [Desktop Entry specification](https://specifications.freedesktop.org/desktop-entry-spec/latest/)
- [Ratatui 0.30 Style](https://docs.rs/ratatui/0.30.0/ratatui/style/struct.Style.html)
- [NO_COLOR convention](https://no-color.org/)
- Locked Ratatui/Crossterm sources and the repository's existing tests and package manifests.

## Spacing and readability

Separate headings, settings and actions with visible whitespace. Keep related labels
and values together, wrap long explanations, and retain noninteractive gaps between
neighboring buttons. Check narrow terminals as well as normal and wide layouts.

Below 80 columns or 24 rows, show only a resize notice with current and required
dimensions. Keep page/dialog state for enlargement and disable hidden controls.
Check the actual size again for each input and require a matching completed draw
to prevent an unseen confirmation across shrinking or enlarging. Keep safe exit
and enrollment cancellation available; do not stop observations merely for resizing.

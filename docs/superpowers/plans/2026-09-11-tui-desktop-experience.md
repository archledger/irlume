# TUI desktop experience implementation plan

**Goal:** Ship a discoverable, readable, interactive TUI with transparent session history, live daemon work, per-source freshness and automatic camera hotplug updates.

**Architecture:** Keep the current thin client and daemon/CLI action boundaries.
Extract cohesive visual/activity helpers where they reduce duplicated state and
rendering logic; install a standard desktop entry through existing packaging.

**Tech Stack:** Rust 1.88, locked Ratatui 0.30, Crossterm, shell/Python package checks.

**Spec:** [TUI desktop experience](../specs/2026-09-11-tui-desktop-experience.md)

## Constraints

Preserve authorization, cancellation, existing daemon protocol behavior, saved configuration,
keyboard shortcuts, NO_COLOR, and reduced-motion support. Use synthetic UI
fixtures. Do not start a camera, install packages, or mutate live device state.

## Work and validation order

- [x] Inspect all existing TUI flows, tests, dependencies, CI, and packaging.
- [x] Establish the baseline: 200 TUI tests passed on the normal host. Seven
  sandbox-only failures were fake Unix-socket bind denials; no test was skipped.
- [x] Desktop integration: add a static terminal desktop entry and SVG icon;
  cover every supported package/source install and source removal path with a
  real validation script and relevant existing package checks.
- [x] Visual interaction: consolidate state styling; render Preferences as
  actionable settings with clear focus and keyboard/mouse targets; retain
  readable layouts and all safety confirmations across screens.
- [x] Activity: reproduce long-message truncation and full-ring scrolling;
  add a bounded history implementation, timestamps/status labels, compact
  summaries, and a full-height readable viewer with follow/history controls.
- [x] Worker lifecycle: add disconnected-channel regressions for status,
  diagnostics, profiles, operations, and enrollment; clear stale busy states,
  report unknown outcomes, and preserve normal completion before channel close.
- [x] Integrate independent patches and run focused regression suites followed
  by the complete CLI and appropriate workspace/packaging checks.
- [x] Generate synthetic examples from actual Ratatui buffers and inspect them
  at representative sizes and in color/no-color modes.
- [x] Update TUI/setup/command documentation to match actual delivered controls.
- [x] Independently review final diff, save evidence and exact resumption state,
  record the untested desktop/distribution scope, and prepare publication under
  the user's existing commit/push/PR/merge authorization.

## Expanded live-state implementation

- [x] Camera layer: publish a copied bounded passive inventory with explicit
  validity, continuity identity, revision and age; initialize separately from
  reads and recover from monitor failure without opening camera nodes.
- [x] Daemon layer: add memory-only LiveStatus, bounded worker admission/running/
  cancellation/finish accounting, independent background qualification, and
  external-mutation invalidation revision.
- [x] TUI: poll current work during dialogs; gate current-state claims per source,
  preserve typed failure, and discard pre-invalidation worker completions.
- [x] Cameras: automatically show attach/remove changes, classify only on a
  changed inventory while visible/idle, preserve identity and invalidate stale
  camera-switch confirmations, carrying the guard through sudo to the daemon. Keep capture
  qualification a dated observation.
- [x] Verify synthetic failure/recovery, queued/running races, old daemon,
  hotplug/reused paths, no probe side effects, and actual rendered freshness cues.
- [x] Refresh user documentation and visual examples against the final code;
  rerun full checks and independent cross-layer reviews before publishing.

## Final spacing and minimum window requirements

- [x] Separate history controls with noninteractive gaps and separate session records
  from the history explanation/status. Preserve internal compact renderer coverage.
- [x] Add an 80×24 minimum at the terminal rendering/input boundary; below either
  dimension show only a resize message. Preserve page/dialog state and keep safe
  exit/enrollment cancellation available. Reject input across a size change until
  the matching window has been drawn.
- [x] Cover hidden approval, text input, mouse/wheel, restoration, tiny dimensions
  and safe exit/cancellation with synthetic regressions.
- [x] Verify the final 128-frame gallery at supported sizes and undersized boundaries,
  and complete final local checks.

Local validation completed: 2,435 workspace tests, 280 no-color TUI tests,
formatter, Clippy, documentation and release build passed. Six desktop-integration
tests and packaging parity passed; synthetic galleries contain 128 frames per
color mode. Publication status and exact commit/CI evidence are tracked in the
shared Irlume handoff, outside this implementation plan.

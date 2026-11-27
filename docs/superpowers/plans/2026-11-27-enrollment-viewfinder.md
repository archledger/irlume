# TUI Enrollment Viewfinder Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add a pixel-free, live position and distance guide alongside the existing TUI enrollment cues.

**Architecture:** The already-open daemon framing session computes a coarse viewfinder sample from the same detection that produces each cue. The terminal client draws it without opening hardware, sends no extra sample requests, and treats it as optional display data.

**Tech Stack:** Rust 1.88.0, Serde JSON over the existing Unix socket, Ratatui 0.30.2 and its test backend.

**Spec:** [TUI enrollment viewfinder](../specs/2026-11-27-enrollment-viewfinder-design.md)

## Global Constraints

- Rust 1.88.0; existing Ratatui 0.30.2; no new dependencies.
- Send only horizontal and vertical buckets `0..=10` and a three-level size `0..=2`.
- No images, landmarks, identity, additional pose or IR data; no new persistence, logging, support-report or machine CLI API output.
- Existing non-root, active-seat, account-owner framing session only. Root, unnamed and other-account requests receive no new data. Legacy single samples do not carry the guide.
- Keep existing pacing, capture authority, checks, approval and cancellation; no change to enrollment storage, PAM or login/unlock.
- Keep text-only flow for older daemons, compact layouts and `IRLUME_REDUCE_MOTION`.
- Synthetic samples for tests. No live camera, real TPM, system install or publication without separate approval.

## Review Focus

1. Mixed package versions must negotiate implicitly, with older clients sending the exact old request and older daemons returning usable text cues (task 1).
2. Opt-in from another account or a root process must not disclose even the new coarse geometry; the camera admission gate remains in place (task 1).
3. Detector geometry outside the frame or containing non-finite or inverted coordinates must not leak precision or manufacture a marker (task 1).
4. A live marker update during `3, 2, 1` must not clear the current count or change the number of samples; a stale or lost marker must not remain visible (task 2).
5. Resizing, reduced motion, cancellation and entering the approval dialog must not hide the text cue or leave stale geometry behind (task 2).

---

### Task 1: Add optional geometry to authorized framing replies

**Files:**
- Modify `crates/irlume-common/src/lib.rs` and `crates/irlume-common/src/client/position_session.rs` (wire and client).
- Modify `crates/irlume-auth/src/lib.rs` and its framing session call sites (projection from the existing detection).
- Modify `crates/irlume-daemon/src/main.rs` and update exhaustive uses of `PositionSession` and `PositionReport` as required.
- Add a synthetic JSON request seed under `fuzz/seeds/ipc_request/` for the opt-in form.

**Interfaces:**
- `Request::PositionSession { user: Option<String>, viewfinder: bool }`: default false and omitted when false.
- `PositionReport::viewfinder: Option<FramingPosition>`: default `None` and omitted when absent.
- `irlume_common::FramingPosition { x: u8, y: u8, size: u8 }` and `FramingPosition::in_bounds(self) -> bool`; `Copy` and Serde. `x` increases to camera right, `y` down; mirror only in the UI.
- Preserve `PositionSession::connect(user: &str, cancelled: &AtomicBool) -> io::Result<Option<Self>>` as a no-opt-in wrapper. Add `PositionSession::connect_with_viewfinder(user: &str, cancelled: &AtomicBool) -> io::Result<Option<Self>>`.
- `fn framing_position(bbox: [f32; 4], width: u32, height: u32) -> Option<FramingPosition>` in `irlume-auth`. `Engine::position_session` takes `viewfinder: bool` after `user` and before `observer`.
- `fn framing_viewfinder_allowed(peer: &Peer, target_user: Option<&str>, requested: bool) -> bool` in daemon `main.rs`.

- [ ] **Write failing tests.** `position_viewfinder_is_additive_on_the_wire`: assert an omitted flag parses as false and reserializes byte-for-byte to the old shape; the opted-in shape parses on a Serde fixture with the old request fields; old position replies produce `None`; opt-in replies carry only `x`, `y`, and `size` under `viewfinder`; absent geometry serializes with no new key. Reuse the actual client fake socket to check that the new helper writes the flag without a new handshake. `framing_viewfinder_projects_valid_detection_only`: on a `100 × 100` frame assert `[40., 40., 60., 60.]` gives `(5, 5, 1)`, `[-20., 5., 10., 20.]` gives `x = 0`, and `NaN`, inverted bounds, boxes wholly off-frame and zero dimensions produce `None`. `framing_viewfinder_requires_non_root_account_owner`: assert false for missing intent, missing or unknown account, wrong UID and root; true for an opted-in non-root matching UID. Use the existing NSS test guidance and a synthetic peer, never the camera.
- [ ] **Verify red.** Run `cargo +1.88.0 test --locked -p irlume-common -p irlume-auth -p irlume-daemon framing_viewfinder`; run `cargo +1.88.0 test --locked -p irlume-common position_viewfinder`. Confirm failures are missing behavior or API, not unrelated tooling.
- [ ] **Implement the minimal path.** Quantize center by clamping its normalized coordinates to `[0, 1]`, multiplying by ten and rounding. Size uses the existing apparent face width relative to frame width: `< 0.12` small, `> 0.55` large, otherwise medium, without exposing width in the new payload. Reject invalid geometry before quantization. Only the same already-authorized session samples opt into this computation. Preserve reply type, request classification, active-seat and account checks, limits, release handshake and legacy single-sample behavior.
- [ ] **Verify green.** Rerun both focused commands with nonzero matches. Run `cargo +1.88.0 test --locked -p irlume-common position_session` and `cargo +1.88.0 test --locked -p irlume-daemon a_non_root_camera_request_is_served_only_from_the_active_seat`. Inspect the JSON keys on both paths. Run the `ipc_request` fuzz command and limits in `fuzz/README.md` with an isolated corpus built from the seeds. Commit the independently tested change with the repository's signing and DCO convention.

### Task 2: Render the guide and retain text-only behavior

**Files:**
- Create `crates/irlume-cli/src/tui/framing_viewfinder.rs` (projection to terminal cells and rendering).
- Modify `crates/irlume-cli/src/tui.rs` (framing worker, volatile state, countdown, and enrollment layout).
- Modify `crates/irlume-cli/src/tui/visual_tests.rs`, `docs/reference/TUI.md`, `docs/reference/COMMANDS.md`, and `CHANGELOG.md`.

**Interfaces:**
- Consumes `FramingPosition`, `PositionReport::viewfinder` and `PositionSession::connect_with_viewfinder` from task 1.
- `WMsg::Viewfinder { position: Option<FramingPosition>, sampled_at: Instant }`: display-only update, emitted from framing and countdown reports independently of `Cue`, and only for the opted-in modern session. Use `None` to clear no-face or invalid geometry.
- `fn draw(frame: &mut Frame<'_>, area: Rect, position: FramingPosition)` in `tui/framing_viewfinder.rs`, with fixed `WIDTH: u16 = 23` and `HEIGHT: u16 = 7`. Reserve the right column only if the inner content is at least 68 columns and 12 rows; keep at least 43 columns for cues.
- Render only while framing or counting and for samples younger than two seconds. Measure age from the worker's receive timestamp; on `Stall`, `Authorizing`, capture, completion and cancellation clear state rather than freezing a marker.

- [ ] **Write failing tests.** `enrollment_viewfinder_mirrors_and_scales_without_color`: synthetic `x = 2` renders right of center and `x = 8` renders left; `y = 8` renders below `y = 2`; sizes `0`, `1`, `2` draw successively wider markers; target is independent of marker state. `enrollment_viewfinder_updates_without_touching_countdown`: mock reports during the countdown update geometry while the count remains set; assert request count and finish-before-enrollment order are unchanged. `enrollment_viewfinder_clears_and_preserves_text_fallback`: prove no marker after missing detection, invalid data, 2-second expiry, stall, cancellation or authorization; at `80×24`, with reduced motion, and for a legacy reply, keep the cue and existing cancel action. Add synthetic gallery frames if the existing fixture does not cover these states.
- [ ] **Verify red.** Run `cargo +1.88.0 test --locked -p irlume-cli enrollment_viewfinder` and confirm the new tests fail for the absent behavior.
- [ ] **Implement.** Capture the UI's reduced-motion option before starting the worker (no opt-in in that mode). Mirror only horizontal position in the renderer; draw with terminal-default foreground and shape, not color or animated transitions. Distinguish the `Framing guide` title and fixed brackets from the moving `o` marker and its larger variants. Keep the normal countdown branch and no extra polling; update docs for user behavior, not CLI flags or public schemas.
- [ ] **Verify green.** Rerun the focused command, the existing guided enrollment and cancellation tests, and `synthetic_visual_gallery_all_screens_and_overlays`. Inspect generated synthetic wide and compact terminal renders and exercise the existing cancellation affordances with tests. Check that no additional device-open calls or runtime dependencies exist. Commit with signing and one owner DCO trailer.

### Integration verification

- [ ] Run the root `AGENTS.md` Rust and documentation gates, including both Clippy lanes, guarded workspace tests, release build, private rustdoc, docs sync and offline link checks. Use the project's isolation for environmental tests. Do not run ignored TPM or camera tests by glob or on native devices.
- [ ] Review both mixed-version directions, synthetic wide/narrow and monochrome layouts, stale/absent data, and unchanged camera-release/authorization order. Record exactly what ran. Hardware qualification and any public GitHub action remain separate.

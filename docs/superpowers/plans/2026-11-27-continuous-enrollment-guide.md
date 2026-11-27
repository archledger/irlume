# Continuous Enrollment Guide Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Keep the centered, pixel-free guide useful from enrollment start through its result, with live position during capture when available.

**Architecture:** Add an opt-in display event to the existing enrollment socket, fed by the assessment the authoritative worker already performs. The TUI renders one panel with explicit phases and accepts geometry only in the applicable phase and freshness window.

**Tech Stack:** Rust 1.88.0, existing Serde JSON Unix socket, Ratatui 0.30.2, current sandbox and camera-free QEMU fixture.

**Spec:** [Continuous enrollment guide](../specs/2026-11-27-continuous-enrollment-guide-design.md)

## Global Constraints

- Rust 1.88.0 and existing Ratatui 0.30.2, with no new dependencies.
- Coarse `FramingPosition` buckets (`x/y 0..=10`, `size 0..=2`) only, plus freshness; drop stale observations at 2 seconds.
- Explicit opt-in, non-root, same account, existing seat and OS approval gates. No images, landmarks, identity, liveness measurements, logging or new persistence.
- No extra camera session or detector pass and no changes to scan acceptance, pose, PAD/liveness, camera scheduling, progress accounting, authentication, or cancellation.
- Compact and reduced-motion terminals remain text-only. Keep one blank row between major sections when the frame fits.
- Preserve existing request, progress, completion and merge behavior for both mixed versions. No live camera or TPM, system install or publication in this plan.
- Base this follow-up on the original viewfinder candidate `a15adc8ac5665e342ba1dd720304defea1d0454b` in its existing isolated worktree. Preserve the original signed Archhost package and release hashes.

## Review Focus

1. Old client and daemon, no opt-in, wrong account, root, and denied approval get no geometry or replay (task 1).
2. An unavailable or slow reader, or a partially written optional message, cannot corrupt framing or crowd out required progress, merge or final replies (task 1).
3. RGB-only, held concurrent, sequential and admitted fallback paths use only an already observed RGB position; lack of evidence does not affect acceptance or progress (task 1).
4. No pending geometry survives approval, a lost or stale frame, merge, failure, disconnect or result (task 2).
5. First scan, last scan before save, cancellation, and resize show valid status, keep actual progress and avoid overlap (task 2).

### Task 1: Publish optional capture observations on the authorized connection

**Files:** `crates/irlume-common/src/lib.rs`, `crates/irlume-common/src/client.rs`, `crates/irlume-daemon/src/{main,enrollment_session,worker_wait}.rs`, `crates/irlume-auth/src/lib.rs`, and the existing request/event fixtures and `fuzz/seeds/ipc_request/`.

**Interfaces:**
- Add `viewfinder: bool` to `Request::EnrollmentSession` (`default`, omit false). Add `EnrollmentEvent::Framing { position: Option<FramingPosition>, sampled_mono_ms: u64 }`. Unnegotiated clients never receive the new variant.
- `irlume_common::enrollment_monotonic_ms() -> Option<u64>` wraps Linux `CLOCK_MONOTONIC` with checked conversion. Suppress geometry on clock failure or a timestamp outside `now - 1999..=now`. Old events and session verbs remain unchanged.
- Extend `EnrollmentObserver` with `wants_framing(&self) -> bool` (default false) and `framing(&self, position: Option<FramingPosition>)` (default no-op). Forward both through `EnrollmentProgress`; use only the authorized `enrollment_session::Worker`.
- `Connection::pump` keeps mandatory events authoritative. Use a separate latest-only observation slot and a bounded optional write, never the current eight-entry mandatory event queue.

- [ ] **RED: wire and peer.** `enrollment_framing_is_opt_in_and_additive`: old fixture parses opted-in request, old request serializes identically and sees exactly `Started`, `Progress`, `Merge`; new client works with those alone. `enrollment_framing_obeys_authorization`: wrong account, root, unset flag and refused authorization produce no optional event; same non-root seat owner sees geometry only after accepted operation. Preserve all existing nonroot and polkit negatives. Use synthetic sockets; assert no fallback after an accepted session fails.
- [ ] **RED: producer and backpressure.** `enrollment_framing_reuses_rgb_assessment` covers existing RGB detection, absent/invalid RGB, and consecutive assessments that do not admit a scan. Assert the same captured progress and control outcome with advisory enabled or off, and no extra opens/detections via available synthetic seams. `enrollment_framing_does_not_block_control_events` exercises a full/slow socket, a short write and a merge/final reply, checking complete lines and no new worker error caused by a dropped advisory.
- [ ] **Implement.** Gate when `serve_peer_until` constructs `enrollment_session::channel`, after its existing `pregate` and `operation_authorization::authorize`. In `capture_scan_loop`, project from the existing RGB `IdentityImage` detection/dimensions before `materialize_pair_identity` via the existing `assess_with_fresh_pair_finish` and `assess_full_with_finish` closures, and the RGB-only deferred result before its existing embedding step. Retain fixture dispatch and validate the camera scope exactly as before. Use the same projection helper as the framing phase; no exact coordinates leave the engine. Missing RGB sends a clear observation, not an invented position; feedback never counts as progress. Deadline/cancel makes optional emission a no-op. Replace pending samples in a single disposable slot; rate-limit new writes to at most one per existing 250 ms pump, emit only when operation is not terminal or awaiting merge and the socket is writable. For a partial optional line, retain just its suffix; finish it before any next wire line, under the existing mandatory writer's deadline, and never start an optional write during final drain. Mandatory progress, merge and final handling retain their existing path.
- [ ] **GREEN:** guarded `cargo +1.88.0 test --locked -p irlume-common -p irlume-auth -p irlume-daemon enrollment_framing` (new cases from all three crates), existing session, worker waiter, posture, cancellation, and storage-path tests. Confirm IPC fuzz seed and contract. Commit with one owner DCO and signature.

### Task 2: Keep the panel stable through approval, capture and result

**Files:** `crates/irlume-cli/src/tui.rs`, `crates/irlume-cli/src/tui/{framing_viewfinder,visual_tests,enrollment_cancel_tests}.rs`, `docs/reference/{TUI,COMMANDS}.md`, `docs/security/THREAT_MODEL.md`, `CHANGELOG.md`.

**Interfaces:**
- Represent `Framing`, `Authorizing`, `Capturing`, `Merge`, and `Result` separately from the most recent marker. Send `WMsg::CaptureStarted` on `EnrollmentEvent::Started` and `WMsg::CaptureFraming { position, sampled_mono_ms }` for newly opted-in observations; accept the latter only during `Capturing`. Existing `WMsg::Cue`, `Count`, `Captured` and result messages keep their authority.
- Add a read-only enrollment result view or snapshot independent of the active enrollment worker. It must not keep normal input blocked, suppress existing Activity/diagnostics, or report success based on scan count. Dismiss/replace it on leaving the Faces view or opening a new enrollment using existing controls.

- [ ] **RED: actual worker and renderer.** `continuous_enrollment_uses_one_panel_in_order` runs a mock session through approval, Started, advisory, progress, merge and final reply. Assert box and progress positions across phases at 128×48, single blank separator, no marker during approval, countdown unaffected, no count advance on geometry, and no success before final. `continuous_enrollment_clears_obsolete_geometry` covers `None`, missing semantic stage, timestamp at 2 seconds, future/out-of-bounds event, cancel/disconnect, refusal and a genuine final success reply. Assert refresh and existing keyboard/cancel actions still work and result is sanitized.
- [ ] **RED: older and compact paths.** `continuous_enrollment_fallback_keeps_truthful_progress` exercises an opted-in worker against a legacy daemon with no observations, both existing one-shot fallback and batch-only response forms, 80×24, short-wide and reduced-motion. Assert text and cancel remain visible, no new opt-in under reduced motion, and no unsupported phase is presented as active geometry.
- [ ] **Implement.** Reuse the existing centered shell, guide borders, progress and colors. Keep the frame in place when size allows; enrollment phase copy changes, not layout. Show “Waiting for approval” until Started and “Capturing scans” thereafter absent fresh feedback. No pose changes beyond the existing framing flow. Set the display result only from actual final outcome; use existing error/merge/cancel affordances and preserve camera Finish acknowledgement before authorization. Update user docs and trust model.
- [ ] **GREEN:** guarded `cargo +1.88.0 test --locked -p irlume-cli --bin irlume continuous_enrollment` (at least 3 new tests); rerun current viewfinder, cancellation and synthetic gallery tests; inspect wide/short renders. Verify extended mock in a camera-free VM at exact built head, including framed approval/capture/result and no marker on unqualified phases. Record scope, render paths and output hashes, then commit with one owner DCO and signature.

### Final gate

- [ ] Exact signed head: root AGENTS fmt, both Clippy lanes, private Rustdoc, release, network/device-free guarded workspace, docs sync and offline links. Rerun optional IPC fuzz tests with the repository's pinned tools. Compare against earlier behavior and capture no-device screenshot evidence.
- [ ] Independent whole-change review of the new disclosure and state machine. Preserve installed `a15adc8a`; no native deployment, PR or other publication without owner direction.

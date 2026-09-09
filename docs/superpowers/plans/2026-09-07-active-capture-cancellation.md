# Active Capture Cancellation Implementation Plan

> **For agentic workers:** Use the established test-first execution and independent review workflow. Continue in the existing isolated worktree and preserve prior uncommitted changes.

**Goal:** Stop an abandoned authentication at returned camera-frame boundaries, release streams and restore controls without completing the remaining capture budget.

**Architecture:** Add an opt-in CaptureControl carrying the existing watchdog callback plus a distinct request-cancellation signal. Preserve Progress and all existing entry points as wrappers with cancellation disabled. Carry control in TrackedStream, check around every returned dequeue, and preserve typed cancellation through camera errors and auth fallback decisions. Existing resource owners remain responsible for stream-off and emitter restoration.

**Tech Stack:** Rust 2021, MSRV 1.88, pinned v4l 0.14, existing scoped worker threads and RAII guards.

**Spec:** User-authorized reduction of the 5.110-second release delay recorded in /home/wisbfime/archledger-gp/artifacts/irlume/2026-09-07-cancellation-live-check/report.md.

## Global Constraints

- Preserve camera rate floors, frame provenance, warm-up retry/dequeue budgets, privacy/lease checks, emitter ordering and existing public entry points.
- Scheduler yield is distinct from client cancellation. Cancellation must not demote camera qualification, retry hardware, emit partial evidence or mutate retry history.
- No forced termination of driver calls or inference; returned-call checks are cooperative.
- No raw biometric evidence, automatic desktop scanning, custom KDE work or publication.
- Keep the installed build until source/test/review/build gates pass; install with an exact manifest and verified rollback. Coordinate any physical test before its cue.

## Task 1: Camera frame cancellation and cleanup

Files: create crates/irlume-camera/src/capture_control.rs and capture_cancellation_tests.rs; modify lib.rs and sequential_batch.rs; extend sequential_batch_tests.rs.

Interfaces: CaptureControl::new(progress: Progress, cancelled: Arc<dyn Fn() -> bool + Send + Sync>), CaptureControl::with_progress(progress: Progress), check() -> irlume_common::Result<()>. New additive session/capture `_with_control` entry points accept &CaptureControl. Existing `_with_progress` wrappers disable cancellation.

- [x] Add typed marker and control plumbing with checks initially absent, then failing regressions for already-cancelled dequeue, cancellation during a returned frame, rate-fill interruption and preserved next-request operation.
- [x] Run `cargo test -p irlume-camera --locked capture_cancellation` and record assertion failures, with hardware opt-ins untouched.
- [x] Check control before/after TrackedStream dequeue and before opening/arming/recovering sessions; map only the typed marker to Error::Preempted. Warm-up must not retry it.
- [x] Pass control through sequential batch checkpoints, checking after opener/capture and before starting another phase. Regression must show no IR opener after cancelled RGB and owner-drop on failure.
- [x] Run focused regressions; preserve ordinary warm-up and parallel-fill tests.

## Task 2: Authentication wiring and cancellation classification

Files: crates/irlume-auth/src/lib.rs, grouped_auth.rs, docs/DESKTOP-AUTH.md.

- [x] Add Engine::capture_control() using existing capture_progress() and the request-only cancellation callback; ordinary CLI callers retain disabled cancellation.
- [x] Route held, concurrent, standalone and grouped authentication captures through the additive control entry points.
- [x] Preserve Error::Preempted before concurrent setup degradation, in-place recovery and one-shot retry decisions. Check cancellation before inference/materialization where captures have returned.
- [x] Add regressions proving heartbeat still runs, scheduler yield does not cancel auth frames, request cancellation does, and cancellation does not enter camera fallback/retry.
- [x] Update documentation with returned-frame semantics and remaining in-flight driver/inference limitation. Record an incremental patch instead of committing unrelated existing work.

## Task 3: Qualify and deploy

- [x] Run camera/auth/daemon ordinary tests, all-target Clippy -D warnings, MSRV1.88 check, fmt, rustdoc -D warnings and release build with CARGO_TARGET_DIR=/home/wisbfime/archledger-gp/irlume/target; inspect every result and real test counts.
- [x] Independently review cancellation propagation and cleanup; fix findings with regressions and repeat affected checks.
- [ ] Verify the source manifest, payload hash and dynamic linkage, install the exact daemon/docs/metadata overlay with protected-state checks and rollback.
- [ ] Reuse the prior attended trial method and cold-after-restart conditions, without a stronger performance claim than the measurements support. Observe cancellation time, FD release and separate emitter restoration events; always remove the temporary logger.
- [ ] Verify final hashes/service/caps/SELinux/camera-idle/diagnostic cleanup and refresh shared memory with exact resumption state and remaining frontend work.

# Consented authentication deadlines

**Goal:** Keep the existing consented desktop flow and 15s desktop / 5s privileged defaults, reject expired grants and secrets, and stop collecting at cooperative frame/inference boundaries.

**Architecture:** One monotonic authentication window spans engine setup, attempts and daemon completion. Zero retains legacy one-shot behavior. A scoped engine deadline supplies existing capture and inference checkpoints; a typed expiry is distinct from disconnect and hardware faults. The client also enforces an overall response-read budget so partial replies cannot prolong PAM waiting.

**Tech stack:** Rust workspace, MSRV 1.88, Linux UnixStream, existing synthetic camera and inference fixtures.

**Spec:** User authorized the recommendation in the current task; canonical handoff project-irlume.md and audit artifact 2026-09-07-auth-deadlines.

**Global constraints:** Preserve the 29 existing changes, on-demand PAM wiring, owner opt-in, PAD and matcher thresholds, zeroizing secret owners, retry/fallback policy, stock frontend compatibility. No camera/TPM exercise, install, publish or external messaging during offline validation. Blocking driver/TPM calls cannot be forcibly interrupted; preserve loader ownership and document this limit. Never detach repeated TPM loaders merely to meet a wall-clock claim.

- [x] Reproduce ordinary late grants and capture begun after expiry in auth/src/lib.rs using the production retry loop and injected clock. Cover zero-window one-shot and unchanged denial settlement.
- [x] Add a shared auth window and scoped engine deadline, typed common expiry and camera control deadline. Gate frame collection, inference, camera recovery and retries without hardware degradation or extra retry strikes. Add meaningful camera/error-routing/scope regressions.
- [x] Carry the window through daemon verify/unseal completion; reject expiry/disconnect around blocking work and before publishing credentials. Preserve retry-history behavior and test finalization with delayed synthetic operations.
- [x] Reproduce and fix plain UnixStream response trickle extending a PAM client read budget in common/src/client.rs. Preserve framing, zeroization, cancellation and public default budgets; add real private-socket regressions.
- [x] Run cargo test -p irlume-common -p irlume-camera -p irlume-auth -p irlume-daemon -p irlume-pam --locked; inspect hardware ignores and run no hardware opt-ins. Run affected all-target Clippy, MSRV1.88 check, release daemon/PAM build, rustdoc warnings-denied, fmt and diff checks.
- [x] Obtain independent scoped review, fix verified findings and rerun relevant gates. Record exact delta/hash and installed-state preservation, update DESKTOP-AUTH and canonical memory. Prepare reviewable candidate and rollback before any installation; coordinate a separately cued physical timeout test if needed.

## Validation and remaining attended step

Final offline validation: 1177 default tests + 30 explicitly selected userspace PAM wrapper tests passed; 35 existing opt-ins left disabled. Workspace Clippy/MSRV1.88, release daemon/PAM, scoped rustdoc, formatter and diff checks passed. Independent rereview approved all corrections, including active-probe empty-token cleanup. Evidence lives in the task artifact directory.

- [ ] After a fresh user readiness cue, perform a guarded attended timeout trial with the packaged candidate and verified rollback. No camera test or installation was performed during offline validation.

The retained enrollment-loader drain and already-running driver/TPM calls may finish after the window; a camera-off wall-clock guarantee is outside this cooperative correction. The legacy PAM wait loop is not part of the on-demand contract. A retry reset whose atomic write crosses expiry can remain stored despite refused response admission; no rollback transaction is claimed.

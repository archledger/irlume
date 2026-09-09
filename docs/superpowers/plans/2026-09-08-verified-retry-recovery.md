# Verified Retry Recovery Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox syntax for tracking.

**Goal:** Provide explicit password-verified reset of existing face retry state, with independent persistent protection against reset-password guessing.

**Architecture:** A root-only, non-setuid PAM helper verifies a local account password through a dedicated service. The daemon reserves reset attempts durably outside its camera worker, binds the result to the live request and serializes the reset with face accounting. The CLI adds status/reset commands. This slice does not enable the new cumulative face ceiling.

**Tech Stack:** Rust 2021/MSRV 1.88, existing libc/serde/zeroize dependencies, Linux-PAM, private Unix channels and the existing atomic retry store.

**Spec:** ../specs/2026-09-08-cumulative-retry-recovery-design.md

## Global Constraints

- Use the current linked worktree; preserve its 38 pre-existing local changes. No commits, publication or installation this turn.
- No real account password test, camera capture, enrollment access or installed PAM change. Real PAM tests use private synthetic fixtures only.
- Keep face authentication defaults and version-1 face records unchanged in this slice.
- Reset-password budget: five failures then 30 seconds before each subsequent verification; 50 failures require administrator reset. Reserve before helper execution, so unknown completion is charged.
- Helper interface: `irlume-password-verify USER`, raw password bytes on stdin terminated by EOF, maximum 4096 bytes, no NUL/empty input; exit 0 verified, 1 rejected, 2 unavailable/invalid. No stdout or credential-bearing stderr.
- Helper service: fixed `irlume-retry-reset`; installed executable `/usr/libexec/irlume-password-verify`, root-owned mode 0755, never setuid. Fixed local-password auth/account service; no includes, Irlume, fingerprint, nullok, password changes or sessions.
- The daemon supplies a cleared environment and fixed executable/service; untrusted request data cannot select either. Bound process execution and kill/reap on failure or cancellation.
- Proposed protocol: `RetryStatus { user }`, `RetryReset { user, password: SecretBytes }`; response `RetryStatus { failures: u32, cooldown_seconds: u64, recovery_failures: u32, recovery_cooldown_seconds: u64, recovery_required: bool, password_reset_available: bool }`. A valid status response is capability negotiation; legacy daemon errors mean unsupported.
- Root reset is an explicit admin override; non-root reset always requires independent password verification. Neither generic polkit success nor keyring preflight is proof.

### Task 1: Password verifier and package boundary

**Files:** Create `crates/irlume-password-verify/{Cargo.toml,src/main.rs,tests/pam.rs}`, `packaging/pam/irlume-retry-reset`; modify workspace Cargo manifests/lock and actual package/install/confinement manifests that ship helper binaries.

**Interfaces:** Consumes fixed username argv and bounded password stdin. Produces only exit 0/1/2 as above. Controller will implement daemon invocation; do not edit daemon/common/CLI code.

- [x] Write tests that execute the helper contract: root-only invocation, invalid/missing/extra args, empty/oversized/NUL input, correct and wrong password, auth success plus account refusal, no password echo, and repeated conversation refusal.
- [x] Run the new tests and retain failing evidence before adding implementation.
- [x] Implement minimal Rust/libpam bindings, document every unsafe call, free PAM conversation responses correctly and scrub owned secret buffers. Require `pam_authenticate` and `pam_acct_mgmt` success, always call `pam_end`, accept exactly one password prompt. Reject unexpected prompt styles or repeated password requests. Verify final PAM_USER remains the requested identity.
- [x] Use private PAM wrapper fixtures or a private compiled PAM test module to execute actual libpam paths without installed PAM edits. Tests requiring wrapper prerequisites must be explicitly exercised locally, not merely skipped and claimed.
- [x] Wire helper and service into the actual package formats, Nix/release/install machinery and confinement. Do not grant the main daemon broad shadow access or ship a helper reachable as a public service.
- [x] Run helper tests, MSRV check, Clippy, fmt and relevant package parsing/confinement validation. Report exact commands, outcomes and limitations.

Example contract assertion (implementation test must launch the real helper):

```rust
assert_eq!(run_case("correct-password-account-expired").status.code(), Some(1));
assert!(run_case("wrong-password").stdout.is_empty());
```

### Task 2: Persistent recovery gate and daemon dispatch

**Files:** `crates/irlume-daemon/src/retry_throttle.rs`, new `retry_throttle/recovery.rs` and tests, new `retry_recovery.rs`; integrate in `main.rs`, `arbiter.rs` and shared protocol `crates/irlume-common/src/lib.rs`.

**Interfaces:** `retry_recovery::dispatch(&Request, &Peer, &UnixStream) -> Response` handles both requests before engine readiness. Private retry-store operations take the resolved account and a verifier closure, retain a per-account operation guard, reserve a failed check before invoking the closure, and reset the face record only after the closure reports fresh success. No reset capability is serializable or client-provided.

- [x] Write behavioral tests for cross-account refusal before verifier execution; five/30/50 recovery boundaries; crash/reopen retaining charged attempts; no face-state writes on bad verifier; unsafe record refusal; success clearing existing face cooldown; failed reset commit refusal; active face work exclusion; client disappearance/deadline refusal; root override and status without a camera.
- [x] Run tests red against unimplemented operations.
- [x] Implement strict separate recovery records beside existing face records. Reuse trusted directory/read/write primitives without changing legacy face semantics. Serialize face check-to-record and recovery reset through one account operation guard. A helper wait must not hold the global directory lock or camera worker.
- [x] Launch the fixed helper through cleared environment and bounded input. Validate executable/ancestors and the fixed service before reporting available; root-owned non-writable files only. Hold a live peer/process binding and revalidate after helper return and before durable reset. Keep a conservative recovery charge on ambiguous failure; update face first, then clear recovery budget, so a torn reset cannot replenish guessing without password verification.
- [x] Integrate exhaustive request authorization, operation-class and diagnostic tables. Preserve old wire shapes and prevent direct worker dispatch from bypassing verification. Ensure status/reset are reachable while models are starting.
- [x] Run guarded daemon/common suites and inherited cancellation/deadline tests, Clippy and MSRV.

Example state-machine expectations:

```rust
for _ in 0..5 { assert!(attempt_with_wrong_password().is_err()); }
assert_eq!(verifier_calls_after_immediate_retry(), 5);
advance_clock(30);
assert!(attempt_with_wrong_password().is_err());
assert!(immediate_retry_does_not_invoke_verifier());
```

### Task 3: CLI, docs and integrated qualification

**Files:** new `crates/irlume-cli/src/retry.rs`, `main.rs`, relevant CLI tests, `docs/DISABLE.md`, `docs/SETUP.md`, completion/help sources discovered from current CLI wiring.

**Interfaces:** `retry::run(sub: Option<&str>, args: &[String]) -> ExitCode`; status probes new daemon support before prompting; non-root own-account reset uses existing no-echo password reader and SecretBytes. Root `--user` reset explicitly describes administrator action.

- [x] Write tests for old-daemon refusal without password prompt, status text/exit results, same-account reset request shape, helper unavailable, typed password not echoed and root override.
- [x] Run red, then implement CLI routing and concise fallback guidance. Distinguish template-key recovery from retry reset.
- [x] Run CLI tests plus real userspace PAM helper qualification and package checks. Compare final source hashes against the initial snapshot and inspect the incremental patch.
- [x] Obtain independent review of the complete added trust boundary and fix actionable findings. Final scoped formatting, Clippy, compiler and tests must be fresh after fixes.
- [x] Update the canonical handoff/index and artifact report with actual test evidence, limitations and exact resumption state. Leave the installed system unchanged and the cumulative face ceiling inactive.

## Execution decisions

- The user approved implementation of the recommended recovery-first slice. Routine design details are settled within that scope; no repeated permission question is needed.
- Preserve the dirty worktree and save incremental artifacts. Commit-based review/cleanup instructions from skills do not authorize destroying or publishing this pre-existing work.
- Where independent failure protection and face reset span two files, write the verified face reset first and recovery-counter reset second. A crash leaves a conservative recovery charge; no unverified password gains a reset. Atomic publication of both fields belongs to the later unified v2 face migration.

## Completion evidence

Completed source implementation and independent review; evidence is retained in `artifacts/irlume/2026-09-08-verified-retry-recovery/` under the canonical shared-memory root. The final workspace run reports 2,086 passing tests; prerequisite-dependent and ignored tests are accounted for in the report. The private helper suite separately exercised 21 synthetic PAM cases, and the CLI administrator override was explicitly exercised as root. Workspace MSRV, Clippy, rustdoc and formatting pass. No installation or cumulative face ceiling was enabled. Distribution backend, installed confinement and real account qualification remain separate follow-up work.

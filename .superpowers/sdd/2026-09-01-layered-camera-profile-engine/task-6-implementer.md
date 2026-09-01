# Task 6 Implementer Report

## Executive Summary

| Severity | Remaining | Resolved during review |
|---|---:|---:|
| Critical | 0 | 0 |
| Important | 0 | 3 |
| Minor | 0 | 0 |

**Overall risk:** Medium. This change adds fail-closed authority checks to the authentication path and new diagnostic-only exact V4L2 negotiation. The complete software workspace passes, but exact profile opens were not exercised against physical camera hardware in this task.

**Recommendation:** Approve the Task 6 slice. Keep profile qualification and production profile selection behind Tasks 7 and 8.

## What Was Implemented

- Added camera-owned `CameraAttemptContract`, fixed versioned evidence-window rules, qualification facts, and field-specific `CapturePlanViolation` values.
- Added auth-owned `AttemptCapturePlan`, composing camera authority with calibration, preprocessing, and the closed production model contract set.
- Bound camera authority to exact camera incarnations, generations, connection context, requested and accepted stream contracts, capture schedule, conditioning selection, evidence rules, qualification context key, and policy versions.
- Added exact RGB and IR profile opens through the process camera supervisor and diagnostics leases without changing `RgbCamera::open` or `IrCamera::open` defaults.
- Required exact advertised interval membership, exact `S_FMT` and interval acceptance, and complete format and interval readback before an exact profile open succeeds.
- Added camera-owned diagnostic profile capture that validates the opened pair and canonical manifests before minting an opaque `SceneObservation`.
- Derived observation freshness from the oldest contributing RGB or IR capture-window start and rejected role-window starts beyond `EVIDENCE_PAIR_BOUND_V1`.
- Added the composite plan to authentication capture selection, rebuilt it for a fresh sequential retry after concurrent evidence was discarded, and validated independently reconstructed auth authority plus both canonical manifests before constructing typed model views.
- Preserved existing production transport defaults, runtime degradation, PAD and password behavior, model thresholds, and enrollment state.

## TDD Evidence

### Initial RED

The Task 6 focused plan test was run before the initial implementation:

```text
cargo test -p irlume-auth --lib capture_plan::tests
```

Compilation failed because the immutable attempt-plan types did not exist.

### Review RED

- `external_callers_cannot_forge_camera_attempt_authority` failed while `CameraAttemptContract::new` was public.
- `changed_model_contract_invalidates_the_attempt_plan` initially failed to compile because no shared model-ID validator existed.
- `authentication_does_not_validate_a_plan_against_itself` identified the self-comparison at the pre-inference boundary.
- `immutable_camera_attempt_names_an_ir_tuple_mismatch` failed with `Err(RgbTuple)` instead of `Err(IrTuple)`.

Each focused regression passed after the minimal corresponding production correction.

## Verification

- `cargo test -p irlume-camera --lib`: 645 passed, 0 failed, 26 declared hardware tests ignored.
- `cargo test -p irlume-auth --lib`: 145 passed, 0 failed, 3 declared environment tests ignored.
- `cargo test -p irlume-camera -p irlume-auth --lib profile`: 19 passed, 0 failed.
- `cargo test -p irlume-auth --lib capture_plan::tests`: 5 passed, 0 failed.
- `cargo test --workspace --all-targets --locked`: 1,990 passed, 0 failed, 100 declared environment or hardware tests ignored across 61 result groups.
- `cargo check --workspace --all-targets --locked`: passed.
- `cargo clippy --workspace --all-targets --locked -- -D warnings`: passed.
- `cargo fmt --all -- --check`: passed.
- `git diff --check`: passed.
- `sha256sum -c SHA256SUMS` from `models/`: all seven assets passed through temporary links to the unchanged main-checkout assets.
- Added-line U+2014 check: no matches.

The plan's combined command, `cargo test -p irlume-camera -p irlume-auth --lib capture_plan profile`, is not accepted by Cargo because it supplies two positional filters. The two filters were run separately, and both crate libraries were also run in full.

## Differential Review

### Scope

The review covered all seven Task 6 source files against base `93d0d1cf3f1911ea8dcbe162c89af7b794f48789`, the binding Task 6 brief, the accepted layered ownership design, one-hop callers in authentication and camera supervision, and the complete runnable workspace tests.

| File | Risk | Review focus |
|---|---|---|
| `crates/irlume-auth/src/lib.rs` | High | Pre-inference ordering, retries, discarded evidence, schedule authority |
| `crates/irlume-auth/src/capture_plan.rs` | High | Composite immutability, model and preprocessing drift |
| `crates/irlume-camera/src/attempt_contract.rs` | High | Authority construction, canonical validation, observation minting |
| `crates/irlume-camera/src/lib.rs` | High | Exact V4L2 negotiation, camera sessions, runtime provenance |
| `crates/irlume-camera/src/backend.rs` | Medium | Supervisor-only profile routing |
| `crates/irlume-camera/src/capture_qualification.rs` | High | Exact requested and accepted tuple projection |
| `crates/irlume-camera/src/conditioning.rs` | High | Observation opacity and freshness authority |

The highest-blast-radius boundary is `assess_full_with`, which serves one-shot authentication, held-session authentication, and support probes. Existing full auth and daemon suites cover those software paths. Exact-profile opens have only diagnostic and test callers in this slice.

### Resolved Findings

1. `CameraAttemptContract::new` was public, allowing an external caller to choose arbitrary evidence-window and qualification values before invoking public camera orchestration. The constructor is now crate-private; external callers can obtain production authority only through `from_runtime`, which installs the fixed v1 rules.
2. Authentication passed the expected `AttemptCapturePlan` as both expected and observed values. That made auth-owned calibration, preprocessing, and model comparisons vacuous. Authentication now independently reconstructs observed authority from the retained runtime contract and actual completed schedule before validating canonical evidence.
3. Generic runtime stream-contract failure mapped every role to `RgbTuple`. Camera validation now checks each canonical role against its exact stream contract first, so an IR mismatch returns `IrTuple` and an RGB mismatch returns `RgbTuple`.

### Adversarial Review

- A caller cannot use a forged public camera contract to enlarge the fixed evidence-pair window and mint a fresh observation from stale role evidence.
- Changed camera incarnation, endpoint context, raw requested or accepted contract, schedule, conditioning selection, catalog version, contributor count, delivered rate, continuity, or active-IR provenance fails before model-view construction.
- A failed concurrent pair is discarded before a new sequential plan and fresh pair are captured.
- Exact profile requests cannot silently accept driver-adjusted geometry, fourcc, interval, or post-negotiation stream state.
- Exact profile opens require a diagnostics operation lease and do not alter normal production open defaults.

No validation removal or security-fix regression was found. The implementation adds authority checks and does not weaken the existing runtime pair gate.

## Files Changed

- `crates/irlume-camera/src/attempt_contract.rs`
- `crates/irlume-auth/src/capture_plan.rs`
- `crates/irlume-auth/src/lib.rs`
- `crates/irlume-camera/src/backend.rs`
- `crates/irlume-camera/src/capture_qualification.rs`
- `crates/irlume-camera/src/conditioning.rs`
- `crates/irlume-camera/src/lib.rs`
- `.superpowers/sdd/2026-09-01-layered-camera-profile-engine/task-6-implementer.md`

## Residual Risks

- Physical camera, v4l2loopback, packaged TFLite, TPM, and PAM-wrapper tests remain explicitly ignored where their required environment is absent.
- The new exact profile opens are diagnostic authority only. Task 7 must qualify complete authentication quality, and Task 8 must separately authorize any production profile selection.
- No camera, service, enrollment, qualification store, model artifact, system configuration, remote, or GitHub state changed. Six temporary model symlinks were removed after verification.

## Commit

Task 6 is intended for one signed and DCO-compliant commit with subject `feat: bind immutable camera attempt plans`.

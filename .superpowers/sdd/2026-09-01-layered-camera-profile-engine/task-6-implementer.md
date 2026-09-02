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

## Review Fix Round 1

### Findings Resolved

1. Normal runtime construction incorrectly required requested and driver-accepted tuples to be identical, even though strict diagnostic profile opens alone must reject adjustment. `PairTransportProfile` now retains requested and accepted RGB and IR tuples independently. Existing exact profile construction remains exact by construction, while normal attempt authority preserves legitimate driver adjustment.
2. Authentication rebuilt model, preprocessing, and calibration authority from the same literals used by the expected plan. `ModelContractSet` now carries actual initialized adapter contracts, model wrappers expose their closed input contract IDs, canonical RGB and GREY producers own their preprocessing identities, and the engine contributes its actual IR calibration space. Expected authority is frozen at attempt start and independently reconstructed at the pre-input boundary.
3. `CameraAttemptContract::from_runtime` stamped fixed producer and policy versions plus invalidation generation zero without proving stored qualification. It is now crate-private. Public construction requires a conclusive matching `StoredCaptureQualificationState`, and carries its producer version, policy version, schedule resolution, and record revision as invalidation generation.
4. Selected conditioning was compared as an immutable value but was not bound to successful control application. Selected policy application now requires exact readback, owns restoration, performs explicit reverse-order restoration with readback, and yields a `ConditioningRestoration` proof. Camera orchestration must supply the matching proof before it may mint `SceneObservation`.
5. Source-text and private-slice checks were replaced with behavioral tests through production authority methods for model, preprocessing, calibration, qualification, tuple, and conditioning drift.

### Additional RED And GREEN Evidence

- Adjusted IR tuple RED failed to compile because `PairTransportProfile` had no independent requested and accepted accessors. GREEN preserves 640x400 requested and 4x1 accepted IR tuples while exact diagnostic opens remain unchanged.
- Qualification RED failed to compile because no stored-authority constructor existed. GREEN rejects unavailable and mismatched authority and carries revision 7 into the immutable contract.
- Producer RED failed because `InferenceAuthority` did not exist. GREEN reports field-specific `ModelContract`, `Preprocessing`, and `Calibration` violations from independently observed authority.
- Conditioning RED failed because `apply_selected_policy` did not exist. GREEN proves exact application, readback, restoration, and refusal to overwrite an external change.

### Final Verification

- `cargo test --workspace --all-targets --locked`: 1,994 passed, 0 failed, 100 declared environment or hardware tests ignored across 61 result groups.
- `cargo check --workspace --all-targets --locked`: passed.
- `cargo clippy --workspace --all-targets --locked -- -D warnings`: passed.
- `cargo fmt --all -- --check`: passed.
- `sha256sum -c SHA256SUMS`: all seven unchanged model assets passed through temporary links; all six temporary links were removed afterward.
- `git diff --check`: passed.
- Added-line U+2014 check: no matches.
- Supplementary `cargo check -p irlume-vision --no-default-features` still reaches the pre-existing feature-gating error at `model_input.rs`'s call to ONNX-only `mesh_box_valid`; all ten errors initially introduced by the new adapter authority API were removed with an `onnx` feature gate.

No camera, service, enrollment, qualification store, model artifact, system configuration, remote, GitHub, or production profile-selection state changed.

## Controller Review Fix Round 2

### Remaining Finding Resolved

Direct controller re-review found that Review Fix Round 1 proved selected-policy restoration only in the diagnostic profile path. Production authentication still captured through the legacy default-conditioning entrypoints and could validate canonical evidence without proving that the plan-selected controls were applied and restored. The strict selected path also treated unavailable optional BLC as a fatal control error.

Production attempt authority is now frozen before capture. One-shot, held-session, sequential-fallback, and RGB self-heal captures all apply the exact plan selection. Each evidence window must return an opaque, matching `ConditioningRestoration` after exact readback and exact displaced-value restoration before `AttemptCapturePlan::validate_canonical_pair` can succeed or any detector input can be constructed. Held streams remain open, but conditioning is reapplied and restored around each complete evidence window. Missing or write-refused optional BLC remains an allowed no-op; any uncertain post-write state or failed restoration fails closed.

### RED And GREEN Evidence

- RED: `selected_policy_omits_unavailable_optional_blc_and_still_proves_restoration` failed to compile because selected guards exposed no proof seam. GREEN confirms optional omission and matching restoration authority.
- GREEN: `camera_attempt_requires_matching_conditioning_restoration_before_inference` accepts only a proof for the frozen selection and rejects policy drift.
- GREEN: production capture constructs the immutable plan before opening a stream, requires selected conditioning on held and one-shot paths, refreshes authority for sequential fallback, and requires fresh proof after RGB self-heal.

### Verification

- `cargo test -p irlume-camera --lib`: 651 passed, 0 failed, 26 declared hardware tests ignored.
- `cargo test -p irlume-auth --lib`: 145 passed, 0 failed, 3 declared environment tests ignored.
- `cargo test --workspace --all-targets --locked`: 1,996 passed, 0 failed, 100 declared environment or hardware tests ignored across 61 result groups.
- `cargo check --workspace --all-targets --locked`: passed.
- `cargo clippy --workspace --all-targets --locked -- -D warnings`: passed.
- `cargo fmt --all -- --check`: passed.
- `git diff --check`: passed.
- `sha256sum -c SHA256SUMS`: all seven unchanged model assets passed through temporary links; all six links were removed afterward.

No hardware, service, enrollment, qualification store, model artifact, system configuration, remote, GitHub, or production profile-selection state changed.

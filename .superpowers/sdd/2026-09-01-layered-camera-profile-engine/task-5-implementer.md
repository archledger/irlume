# Task 5 Implementer Report

## What Was Implemented

- Added a fixed, versioned conditioning catalog with stable `lit-auto`, `backlit-auto`, `low-light`, and `dark-ir` identifiers.
- Preserved the current safe behavior in every initial policy: BLC 2, automatic exposure enabled, six RGB warm-up frames, five RGB temporal-median frames, and ambient subtraction disabled.
- Required public catalog construction to validate every standard-control request against one bounded `CapabilityInventory`, including eligibility, represented type, inclusive range, exact step lattice, and sparse menu membership.
- Added deterministic scene classification from bounded brightness distribution, clipping, contrast, ambient-dark, and active-IR facts only.
- Added process-local observations with a fixed 30-second TTL and exact invalidation on camera instance, generation, validated connection context, full transport profile, or catalog version change.
- Kept the selector free of detector, recognition, liveness, PAD, identity, score, and authentication-result inputs. No classification stream or preflight capture was added.
- Replaced the one-control `BlcRestore` with `AppliedConditioningGuard` while retaining read-before-write, exact readback confirmation, immediate mismatch undo, and conditional restoration.
- Applied standard controls in ascending ID order and restored confirmed writes in reverse order.
- Retained the guard before stream creation and after the stream field so failed stream creation, ordinary teardown, error return, cancellation, and panic unwind restore owned changes after STREAMOFF where a stream exists.
- Left the emitter journal, vendor extension controls, capture schedules, transport selection, model contracts, thresholds, authentication policy, and password fallback unchanged.

## RED Evidence

The required focused command was run before implementation:

```text
cargo test -p irlume-camera --lib conditioning::tests
```

Compilation failed on 94 references to absent Task 5 contracts, including `SceneClass`, `ConditioningPolicyId`, `ConditioningPolicy`, `ConditioningCatalog`, `ConditioningSelection`, `AppliedConditioningGuard`, scene statistics, context binding, policy validation, and generic control application.

## GREEN Evidence

- `cargo test -p irlume-camera --lib conditioning::tests`: 14 passed, 0 failed.
- `cargo test -p irlume-camera --lib ir_emitter::tests`: 129 passed, 0 failed.
- `cargo test -p irlume-camera --all-targets`: 648 passed, 0 failed, 26 declared hardware tests ignored.
- `cargo test --workspace --all-targets --locked`: 1,973 passed, 0 failed, 100 declared environment or hardware tests ignored across 61 result groups.
- `cargo check --workspace --all-targets --locked`: passed.
- `cargo clippy --workspace --all-targets --locked -- -D warnings`: passed.
- `cargo fmt --all -- --check`: passed.
- `git diff --check`: passed.
- Added-line U+2014 check: no matches.
- All seven model assets passed `models/SHA256SUMS`; six temporary ONNX links were removed after verification.

## Behavior Equivalence

- RGB session startup still reads BLC before writing, skips an unreadable control, skips a control already at 2, requests exactly 2 otherwise, confirms exact readback, and undoes an unconfirmed request immediately.
- A confirmed BLC write remains owned until stream teardown. Restoration still occurs only while the control reads as the value Irlume requested, preserving a newer external value.
- The safe default retains `AE_WARMUP == 6` and `RGB_BURST == 5`; automatic exposure remains enabled and ambient subtraction remains disabled.
- The current production consumer selects only the safe default. Scene-dependent policy selection is exposed as a typed contract for later attempt planning but is not wired into authentication in this task.
- Every initial catalog policy intentionally has the same current-safe settings, so selecting a different ID cannot yet change capture, preprocessing, model input, or verdict behavior.
- Emitter mode remains exclusively under the existing specialized durable journal and guard. Generic conditioning can name only bounded standard V4L2 controls.

## Files Changed

- `crates/irlume-camera/src/conditioning.rs`
- `crates/irlume-camera/src/lib.rs`
- `.superpowers/sdd/2026-09-01-layered-camera-profile-engine/task-5-implementer.md`

## Differential Review

| Severity | Remaining | Resolved during review |
|---|---:|---:|
| Critical | 0 | 0 |
| Important | 0 | 2 |
| Minor | 0 | 3 |

**Overall risk:** Low to medium. The generalized guard touches production RGB session setup and teardown, but the concrete policy remains byte-for-byte equivalent in requested control ID and value and is covered by focused failure-ordering and full workspace tests.

**Recommendation:** Approve based on the recorded verification and unchanged production selection.

### Scope And Blast Radius

The review covered the complete Task 5 change against base `03f90eab4e2402af185eed77d36f6288af4f428e`, the binding brief, accepted design, standard-control inventory, RGB session field-drop order, lease checks, existing BLC behavior, emitter ownership, and all new policy tests. No consumer outside `irlume-camera` changed.

### Review Corrections

1. The first implementation exposed an unqualified fixed catalog even though individual policies had inventory validation. Public catalog construction now requires a `CapabilityInventory` and validates every policy before returning authority. The one concrete legacy-safe policy constructor is crate-private and used only to preserve current production BLC behavior before Task 6 integrates qualified attempt plans.
2. The first observation context duplicated connection and transport identity as free-form strings. It now owns the existing validated `ConnectionContext` and full `PairTransportProfile`, closing an avoidable hidden-data channel and making every connection or transport field part of exact invalidation.
3. Warnings-denied Clippy found a redundant closure, a redundant guard pattern, and a collapsible conditional during implementation. Each was corrected mechanically without changing policy behavior.

### Ownership And Failure Review

- The guard records only writes that changed a value and then read back exactly as requested. It never adopts a preexisting requested value as its own.
- A later apply failure drops the partially armed guard, restoring every earlier confirmed write in reverse order.
- Timeout and STALL writes receive exactly one attempt. No escalation or harder retry path exists.
- Drop performs a final read and restores only an exact owned value. A moved or unreadable control authorizes no restore.
- `RgbSession` declares the conditioning guard after `stream`; Rust field drop order therefore stops streaming before restoring controls. Failed stream construction drops the already-armed local guard.
- `ControlIo::write_control` retains the exact endpoint lease check before every production write, including restoration.
- A best-effort restoration failure remains diagnostic-only, matching the pre-Task 5 BLC behavior. Durable crash recovery remains specific to emitter writes and was not generalized silently.

## Concerns

- Physical camera, v4l2loopback, TPM, PAM wrapper, and packaged TFLite runtime tests remain declared ignored in this environment. Mocked control ordering and failure tests plus the complete non-hardware workspace suite cover the software boundary; equipped-host gates may still run before production integration.
- Standard V4L2 controls have no compare-and-set operation. As before, another writer can race between the guard's final read and restore write; the implementation preserves newer values observable at the read boundary but cannot exclude a later race.
- No system, hardware, service, enrollment, remote, persisted authority, model artifact, or production camera state changed during implementation.

## Commit

Task 5 is committed separately with signed+DCO subject `feat: qualify camera conditioning policies`.

## Fix Round 1

### Findings Addressed

1. The selector previously represented attempt phase as `Option<&SceneObservation>`. A caller could therefore attach an observation without structurally proving that selection was for a later attempt. Selection now takes the closed `ConditioningAttempt` enum: `First` carries no observation authority, while `Later` carries exactly one preceding `SceneObservation`.
2. `SceneObservation::new` was public, so arbitrary caller-authored statistics could become policy-selection authority. The constructor is removed. Observations are opaque externally and are minted only by a crate-private catalog factory from canonical RGB evidence and optional canonical IR evidence whose camera instance and generation match the exact conditioning context.
3. The fixed catalog previously required BLC 2 on every represented inventory. BLC is now optional catalog content and is included only when the exact eligible integer request for value 2 passes the represented control domain. Manual policies still reject absent, ineligible, wrong-type, out-of-range, and off-lattice requests.

### RED Evidence

- `cargo test -p irlume-camera --lib conditioning::tests` failed to compile because `ConditioningAttempt` and the inventory-domain fixed-catalog test seam did not exist.
- `cargo test -p irlume-camera --doc conditioning` failed because the external `SceneObservation::new` construction marked `compile_fail` still compiled successfully.
- `cargo test -p irlume-camera --lib scene_observation_is_derived_from_canonical_camera_evidence` failed to compile because the canonical-evidence observation factory and catalog seam did not exist.

### GREEN Evidence

- `cargo test -p irlume-camera --lib conditioning::tests`: 17 passed, 0 failed.
- `cargo test -p irlume-camera --doc conditioning`: 1 compile-fail test passed.
- `cargo test -p irlume-camera --lib scene_observation_is_derived_from_canonical_camera_evidence`: 1 passed, 0 failed.
- `cargo test -p irlume-camera --lib ir_emitter::tests`: 129 passed, 0 failed.
- `cargo test -p irlume-camera --all-targets`: 652 passed, 0 failed, 26 declared hardware tests ignored.
- `cargo test --workspace --all-targets --locked`: 1,977 passed, 0 failed, 100 declared environment or hardware tests ignored across 61 result groups.
- `cargo check --workspace --all-targets --locked`: passed.
- `cargo clippy --workspace --all-targets --locked -- -D warnings`: passed.
- `cargo fmt --all -- --check`: passed.
- `git diff --check`: passed.
- Added-line U+2014 check: no matches.
- All seven model assets passed `models/SHA256SUMS`; six temporary ONNX links were removed after verification.

### Behavior And Authority Review

- Current production still calls only `current_safe_default`; later-attempt selection and observation derivation remain a Task 6 seam.
- First-attempt selection cannot carry an observation. Later-attempt selection retains exact context, catalog version, monotonic future-time rejection, and the fixed 30-second TTL.
- The observation factory accepts canonical camera evidence only and rejects an RGB or IR camera incarnation mismatch before deriving bounded brightness, clipping, contrast, and illumination facts.
- Fixed-catalog BLC inclusion reuses the same exact domain validation as manually authored policies. No vendor extension control or emitter ownership changed.
- Every catalog policy still has identical non-BLC safe settings, so the fix changes neither capture schedule, model input, threshold, authentication policy, nor password fallback.
- Final differential review found no remaining Critical, Important, or Minor issue in the fix scope.

### Fix Files

- `crates/irlume-camera/src/conditioning.rs`
- `crates/irlume-camera/src/lib.rs`
- `.superpowers/sdd/2026-09-01-layered-camera-profile-engine/task-5-implementer.md`

### Fix Commit

Fix Round 1 is committed separately with signed+DCO subject `fix: close conditioning authority gaps`.

## Fix Round 2

### Findings Addressed

1. Fix Round 1's crate-private `ConditioningCatalog::observe` factory proved only camera instance and generation, then copied caller-supplied connection and full transport-profile facts into a new observation. Canonical evidence does not prove those facts. Task 5 now has no production constructor or factory capable of minting `SceneObservation`.
2. The removed factory used the later RGB/IR capture end as observation freshness, which allowed fresh evidence from one role to renew older facts from the other. Task 6 now explicitly owns the first production minting path after exact profile opens and complete immutable attempt-plan/evidence validation. Its plan contract uses the oldest contributing capture-window start and rejects RGB/IR windows beyond a fixed, versioned evidence-pair bound.

### RED Evidence

- Added `production_code_has_no_scene_observation_minting_path` before changing production code.
- `cargo test -p irlume-camera --lib conditioning::tests::production_code_has_no_scene_observation_minting_path` failed 0 passed/1 failed because production still contained `fn observe(`. The failing assertion identified the premature factory directly.

### GREEN Evidence

- `cargo test -p irlume-camera --lib conditioning::tests`: 18 passed, 0 failed.
- `cargo test -p irlume-camera --doc conditioning`: 1 external-construction compile-fail test passed.
- `cargo test -p irlume-camera --all-targets`: 652 passed, 0 failed, 26 declared hardware tests ignored.
- `cargo test --workspace --all-targets --locked`: 1,977 passed, 0 failed, 100 declared environment or hardware tests ignored across 61 result groups.
- `cargo check --workspace --all-targets --locked`: passed.
- `cargo clippy --workspace --all-targets --locked -- -D warnings`: passed.
- `cargo fmt --all -- --check`: passed.
- `git diff --check`: passed.
- Added-line U+2014 check: no matches.
- All seven model assets passed `models/SHA256SUMS`; six temporary ONNX links were removed after verification.

### Authority And Design Review

- Removed `ConditioningCatalog::observe`, `evidence_matches_context`, `statistics_from_evidence`, and the partial-context `ObservationContextMismatch` error claim.
- Removed the camera integration test that depended on the unsound production factory.
- `SceneObservation` remains externally opaque. Selector TTL, exact-context, catalog-version, and future-time behavior uses an observation helper located only inside the module's `#[cfg(test)]` test module.
- A source-level regression test checks the non-test portion of `conditioning.rs` for both an observation factory and any `SceneObservation` construction expression. The existing doctest independently proves external construction does not compile.
- `ConditioningAttempt::First` and `ConditioningAttempt::Later` remain unchanged. Current production still selects only the safe default.
- The accepted design and Task 6 plan now require camera-owned minting only after exact profile opens plus complete attempt-plan and canonical-evidence validation prove camera incarnation, connection, requested and accepted RGB/IR tuples, schedule, catalog, and manifests.
- Task 6 freshness is bound to the oldest contributing capture-window start and rejects role windows beyond a fixed, versioned evidence-pair bound. No Task 6 production path was implemented here.
- The approved optional-BLC construction and manual-policy rejection behavior are unchanged.
- Final review found no remaining Critical, Important, or Minor issue in the Fix Round 2 scope.

### Fix Files

- `crates/irlume-camera/src/conditioning.rs`
- `crates/irlume-camera/src/lib.rs`
- `docs/superpowers/specs/2026-09-01-layered-camera-profile-engine-design.md`
- `docs/superpowers/plans/2026-09-01-layered-camera-profile-engine.md`
- `.superpowers/sdd/2026-09-01-layered-camera-profile-engine/task-5-implementer.md`

### Fix Commit

Fix Round 2 is committed separately with signed+DCO subject `fix: remove premature observation authority`.

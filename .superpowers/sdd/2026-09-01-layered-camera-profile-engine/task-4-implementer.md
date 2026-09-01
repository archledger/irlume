# Task 4 Implementer Report

## What Was Implemented

- Added camera-independent validated `CanonicalRgbView` and `CanonicalGreyView` types with nonzero geometry, checked payload arithmetic, exact payload lengths, and immutable pixels.
- Added a closed `ModelInputContractId` and `ModelContractSet` covering YuNet, ArcFace, ViT RGB PAD, FLIR IR PAD, short-range BlazeFace, full-range BlazeFace, and both supported FaceMesh generations.
- Froze shape, layout, channel order, numeric type, value range, normalization, crop policy, and preprocessing version metadata for every contract.
- Added private-payload typed inputs for detector, ArcFace, ViT RGB PAD, FLIR IR PAD, short-range BlazeFace, full-range BlazeFace, and FaceMesh inference.
- Retained an explicit measurement-only ArcFace tensor type for the normalization A/B bench without reopening the production embedder to arbitrary tensors.
- Changed every public production model inference method to accept only its matching typed input. Removed raw `RgbView`, `FrameView`, byte-slice, and duplicated public preprocessing entry points.
- Preserved direct TFLite sessions as measurement-only parity tooling while feeding them tensors produced by the matching typed input.
- Migrated authentication, CLI commands, tests, examples, parity tools, and benchmarks to the typed boundary.
- Added an authentication source ratchet that rejects raw vision view types in non-test authentication source and proves all required typed gateways remain present.
- Preserved legacy 192-side and current 256-side FaceMesh support with distinct contracts selected from the loaded model.
- Amended the accepted design and implementation plan to record that BlazeFace, FaceMesh, full-range measurement tooling, and downstream consumers were initially omitted from Task 4 scope.

`irlume-vision` remains independent of `irlume-camera`.

## RED Evidence

The required focused command was run before implementation:

```text
cargo test -p irlume-vision --lib model_input::tests
```

Compilation failed because `ModelContractSet`, `ModelInputContractId`, validated canonical views, and typed model inputs did not exist.

After raw inference signatures were removed, `cargo check -p irlume-auth -p irlume-cli --all-targets` failed across authentication examples and CLI consumers that still passed `RgbView`, raw aligned chips, or the removed `detect_any` and preprocessing helpers. Those compiler failures established the downstream migration boundary.

Two scope-correction tests were also observed failing before implementation:

- The full-range BlazeFace test failed because `BlazeFaceFullRangeLetterbox192V1` and `FullRangeBlazeFaceInput` did not exist.
- The legacy FaceMesh test failed because `FaceMesh192RgbV1` and contract-selected FaceMesh input construction did not exist.

## GREEN Evidence

- `cargo test -p irlume-vision --lib model_input::tests`: 7 passed, 0 failed.
- `cargo test -p irlume-auth --lib authentication_source_has_no_raw_model_input_view_types`: 1 passed, 0 failed.
- `cargo check -p irlume-auth -p irlume-cli --all-targets`: passed without warnings.
- `cargo check --workspace --all-targets`: passed without warnings.
- `cargo test -p irlume-vision -p irlume-auth --lib`: 218 passed, 0 failed, 4 declared environment tests ignored.
- `cargo test --workspace --all-targets --locked`: 1,955 passed, 0 failed, 100 declared environment or hardware tests ignored across 61 result groups.
- `cargo clippy --workspace --all-targets --locked -- -D warnings`: passed.
- `cargo fmt --all -- --check`: passed.
- `git diff --check`: passed.

The isolated worktree contains only the tracked TFLite mesh asset. The first required library run therefore reached 120 passing authentication tests but failed 20 model-backed tests with the same missing `models/glintr100.onnx` setup error. Six temporary symlinks to the canonical checkout were created, all seven model files passed `models/SHA256SUMS`, the required library and locked workspace suites passed, and every temporary link was removed.

## Files Changed

- `crates/irlume-vision/src/model_input.rs`
- `crates/irlume-vision/src/lib.rs`
- `crates/irlume-vision/src/blaze_full.rs`
- `crates/irlume-auth/src/lib.rs`
- `crates/irlume-auth/examples/blaze_full_parity.rs`
- `crates/irlume-auth/examples/blaze_short_parity.rs`
- `crates/irlume-auth/examples/detect_bench.rs`
- `crates/irlume-auth/examples/embed_parity.rs`
- `crates/irlume-auth/examples/landmark_dump.rs`
- `crates/irlume-auth/examples/landmark_failure_probe.rs`
- `crates/irlume-auth/examples/landmark_replay.rs`
- `crates/irlume-auth/examples/letterbox_bench.rs`
- `crates/irlume-auth/examples/liveness_replay.rs`
- `crates/irlume-auth/examples/mesh_parity.rs`
- `crates/irlume-auth/examples/moire_replay.rs`
- `crates/irlume-auth/examples/mp_latency_bench.rs`
- `crates/irlume-auth/examples/norm_ab_bench.rs`
- `crates/irlume-auth/examples/stage_bench.rs`
- `crates/irlume-cli/src/main.rs`
- `crates/irlume-cli/src/pad.rs`
- `crates/irlume-cli/src/suncal.rs`
- `docs/superpowers/specs/2026-09-01-layered-camera-profile-engine-design.md`
- `docs/superpowers/plans/2026-09-01-layered-camera-profile-engine.md`
- `.superpowers/sdd/2026-09-01-layered-camera-profile-engine/task-4-implementer.md`

## Differential Review

| Severity | Remaining | Resolved during review |
|---|---:|---:|
| Critical | 0 | 0 |
| Important | 0 | 1 |
| Minor | 0 | 2 |

**Overall risk:** Medium. This intentionally removes public raw inference signatures and migrates every workspace consumer while preserving preprocessing arithmetic and inference policy.

**Recommendation:** Approve after the recorded verification and hygiene gates.

### Scope And Blast Radius

The review covered the complete change against base `37d4df8fd885390100377335938b7f538acfb72a`, the expanded Task 4 brief, accepted design, implementation plan, all public model wrappers, authentication paths, CLI paths, tests, examples, benchmarks, and direct TFLite parity tools. No capture schedule, camera qualification, model weights, thresholds, verdict policy, model selection, or production profile authority changed.

### Behavior Equivalence

- YuNet retains the same 640 top-left square letterbox, BGR planar layout, bilinear sampling, and zero fill. GREY8 inputs sample replicated luma directly instead of allocating an equivalent RGB expansion.
- ArcFace retains the same five-point 112 alignment, RGB order, `(px - 127.5) / 128.0` normalization, TTA flip-average, and output normalization.
- ViT RGB PAD retains the m96 clamped crop, 224 bilinear resize, RGB CHW order, and centered unit normalization. Existing arithmetic goldens now exercise the typed input.
- FLIR IR PAD retains the 16/112 padding, square placement, virtual 128 resize, center 112 crop, 127 fill, replicated-grey channels, and `(px - 127.5) / 128.0` normalization.
- Short-range and full-range BlazeFace retain square zero-pad letterboxing, center-of-pixel sampling, RGB NHWC order, and `(px - 127.5) / 127.5` normalization.
- FaceMesh retains fixed-quarter-margin square cropping, center-of-pixel sampling, RGB NHWC order, `[0,1]` normalization, and frame-space output mapping for both legacy 192 and current 256 inputs.
- The real-model determinism, pinned embedding, detector, FaceMesh, BlazeFace, PAD, authentication, CLI, and workspace tests all pass.

### Review Corrections

- The first expanded implementation fixed FaceMesh at 256 and rejected the previously supported legacy 192 ONNX generation. The loader documentation and `MESH_INPUT` fallback exposed the regression. Distinct 192 and 256 contracts plus model-selected input preparation restored the accepted behavior.
- Full-range BlazeFace initially remained a raw `RgbView` measurement API. A distinct 192 contract and typed input closed that final model-wrapper escape hatch.
- The migrated ViT tests initially left the old private preprocessor in place, producing a dead-code warning and duplicate arithmetic. The tests now exercise `VitRgbPadInput` directly and the duplicate helper is removed.

## Concerns

- Physical camera, v4l2loopback, TPM, PAM wrapper, and packaged TFLite runtime tests remain declared ignored in this environment. The unchanged preprocessing arithmetic, real ONNX model tests, parity-tool compilation, and full workspace suite cover the software boundary, but equipped-host gates may still run before production integration.
- No system, hardware, service, enrollment, remote, or production authority state changed.

## Fix Round 1

### Findings Fixed

1. `mesh_parity::native_landmarks` and `mp_latency_bench::native_mesh_run` independently rebuilt FaceMesh crop, sampling, NHWC, and normalization arithmetic before submitting arbitrary tensors directly to TFLite. Both paths now submit only tensors produced by `FaceMeshMeasurementInput`, which delegates to the same private preprocessing implementation as production `FaceMeshInput`.
2. The ONNX FaceMesh loader previously read only dimension 1 and defaulted missing or dynamic geometry to 192. It now validates an f32 tensor of rank 4, accepts only declared batch `1` or unknown `-1`, requires static square 192 or 256 spatial dimensions and static channel 3, then assigns the matching existing closed contract.

The pinned 256 graph declares `tensor(float) ['unk__2008',256,256,3]`; the legacy 192 graph declares `tensor(float) [1,192,192,3]`. The compatibility decision therefore permits only dynamic or static-one declared batch while every typed adapter still produces an actual batch-one tensor matching contract metadata `[1,H,W,3]`. No model artifact, checksum, pin, or contract changed.

### RED Evidence

- `cargo test -p irlume-vision --lib facemesh` failed compilation because `FaceMeshMeasurementInput` and `facemesh_contract_for_onnx_tensor` did not exist.
- After the first exact static-only selector, focused tests passed but the real vision plus auth library run failed 20 authentication setup tests because the pinned 256 model declared `[-1,256,256,3]`. Independent ONNX Runtime inspection confirmed input `input_12`, type `tensor(float)`, shape `['unk__2008',256,256,3]`.
- After the compatibility decision, `cargo test -p irlume-vision --lib facemesh_input_shape_tests` passed the malformed-input test and failed only the new dynamic-batch acceptance assertion, returning `input shape [-1, 256, 256, 3] must be [1,192,192,3] or [1,256,256,3]`.

### GREEN Evidence

- `cargo test -p irlume-vision --lib model_input::tests`: 9 passed, 0 failed.
- `cargo test -p irlume-vision --lib facemesh_input_shape_tests`: 2 passed, 0 failed.
- `cargo check -p irlume-auth --examples`: passed.
- `cargo test -p irlume-vision -p irlume-auth --lib`: 222 passed, 0 failed, 4 declared environment tests ignored.
- `cargo test --workspace --all-targets --locked`: 1,959 passed, 0 failed, 100 declared environment or hardware tests ignored across 61 result groups.
- `cargo check --workspace --all-targets --locked`: passed.
- `cargo clippy --workspace --all-targets --locked -- -D warnings`: passed.
- `cargo fmt --all -- --check`: passed.
- `git diff --check`: passed.
- Added-line U+2014 check: no matches.
- Focused source scan found no sampling loop, raw FaceMesh tensor allocation, or `run_f32(&data)` in either affected example. Their only FaceMesh TFLite submissions are `run_f32(input.tensor())`.
- All seven model assets passed `models/SHA256SUMS`; six temporary ONNX links were removed after verification.

### Files Changed

- `crates/irlume-vision/src/model_input.rs`
- `crates/irlume-vision/src/lib.rs`
- `crates/irlume-auth/examples/mesh_parity.rs`
- `crates/irlume-auth/examples/mp_latency_bench.rs`
- `.superpowers/sdd/2026-09-01-layered-camera-profile-engine/task-4-implementer.md`

### Commit

Fix Round 1 is the separate signed+DCO commit with subject `fix: close typed FaceMesh authority gaps`; this report is committed with that fix.

### Self-Review

- Critical: 0 remaining.
- Important: 0 remaining; both independently verified findings are closed.
- Minor: 0 remaining.
- The measurement adapter adds no contract. Standard measurement tensors are byte-for-byte equal to production adapter tensors for the same view, box, and contract.
- Horizontal skew is explicit, finite, and limited to one quarter of the selected crop. It changes only crop X and uses the shared sampler and normalization implementation.
- The loader rejects missing or non-tensor input, non-f32 type, wrong rank, static batch other than 1, dynamic or unsupported spatial dimensions, nonsquare dimensions, wrong layout dimensions, and dynamic or non-3 channels before contract assignment.

### Concerns

- The packaged TFLite runtime end-to-end test, physical camera, v4l2loopback, TPM, and PAM wrapper tests remain declared ignored in this environment. Both TFLite examples compile and their tensor authority is covered by focused adapter tests and source inspection.
- No model artifact, checksum, inference threshold, crop policy, normalization arithmetic, production verdict, system state, or external authority changed.

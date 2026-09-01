# Task 3 Implementer Report

## What Was Implemented

- Added owned, validated `CanonicalRgbEvidence` and `CanonicalIrEvidence` types with private pixel storage and read-only pixel, dimension, capture-window, statistics, and manifest accessors.
- Added `EvidenceManifest` with a bounded contributor count and format-neutral selection facts for single, selected, reduced, and lit-minus-ambient evidence.
- Enforced nonzero geometry, exact RGB8 and GREY8 payload lengths, matching stream roles, valid contributor selections, coherent aggregate provenance, and a maximum of 64 contributors.
- Moved the current RGB temporal median and IR selected-frame or ambient-subtraction construction behind canonical evidence constructors.
- Preserved the current five-frame RGB median, ten-frame IR burst, clip-aware gate-frame selection, default no-subtraction behavior, and opt-in subtraction thresholds.
- Retained raw selected IR pixels inside canonical evidence when subtraction changes model pixels, so clipping and glint gates continue to inspect the correct source.
- Changed denoised RGB and IR capture-with-statistics entry points to return canonical evidence while keeping single-frame framing entry points on `Frame`.
- Added format-neutral runtime validation and diagnostic projections for canonical evidence without exposing camera-native format provenance.
- Migrated camera tests, examples, authentication, CLI probes, and calibration tools to read canonical evidence through accessors.

The existing `AggregateFrameProvenance` implementation already enforced the required 64-contributor bound, coherent camera binding, format, role, timestamp domain, continuity, and selection indices. No `frame_provenance.rs` change was necessary.

## RED Evidence

The required focused command was run before implementation:

```text
cargo test -p irlume-camera --lib evidence::tests
```

Compilation failed because `CanonicalRgbEvidence`, `CanonicalIrEvidence`, `EvidenceManifest`, `EvidenceSelection`, and `EvidenceError` did not exist. This established the canonical-boundary RED state before production implementation.

After the camera entry points changed return types, `cargo check --workspace --all-targets` failed at downstream tuple destructuring and direct `Frame` field access. Those compiler errors established the downstream migration boundary. The migration then replaced only the obsolete shape with canonical accessors and retained raw clipping reads through `saturation_pixels()`.

## GREEN Evidence

- `cargo test -p irlume-camera --lib evidence::tests`: 6 passed, 0 failed.
- `cargo test -p irlume-camera --lib`: 614 passed, 0 failed, 26 declared hardware tests ignored.
- `cargo test -p irlume-camera --all-targets --locked`: passed, including 614 library tests, 12 contract tests, qualification coverage, and all compiled examples; 26 declared hardware tests ignored.
- `cargo check --workspace --all-targets`: passed.
- `cargo test --workspace --all-targets --locked`: 1,942 passed, 0 failed, 100 declared environment or hardware tests ignored across 61 result groups.
- `cargo clippy --workspace --all-targets --locked -- -D warnings`: passed.
- `cargo fmt --all -- --check`: passed.
- `git diff --check`: passed.
- Added-line U+2014 scan: no matches.

The linked worktree lacks six ignored ONNX assets. The first workspace test therefore failed 20 authentication tests with the same missing `models/glintr100.onnx` setup error. Six temporary symlinks to the parent checkout were then created, all seven entries in `models/SHA256SUMS` verified, the locked workspace suite passed, and all temporary links were removed.

## Files Changed

- `crates/irlume-camera/src/evidence.rs`
- `crates/irlume-camera/src/lib.rs`
- `crates/irlume-camera/examples/capture_bench.rs`
- `crates/irlume-camera/examples/frame_mean_probe.rs`
- `crates/irlume-camera/examples/illumination_probe.rs`
- `crates/irlume-auth/src/lib.rs`
- `crates/irlume-auth/examples/embed_parity.rs`
- `crates/irlume-cli/src/main.rs`
- `crates/irlume-cli/src/pad.rs`
- `.superpowers/sdd/2026-09-01-layered-camera-profile-engine/task-3-implementer.md`

## Differential Review

| Severity | Remaining | Resolved during review |
|---|---:|---:|
| Critical | 0 | 0 |
| Important | 0 | 0 |
| Minor | 0 | 2 |

**Overall risk:** Medium. This deliberately changes public capture return types and moves production authentication inputs behind validated owned evidence.

**Recommendation:** Approve after the recorded verification and hygiene gates.

### Scope And Blast Radius

The review covered the complete change against base `50572617382149f0562571b700aab544fb295ade`, the Task 3 brief, the accepted design, runtime provenance validation, capture reduction paths, authentication consumers, CLI consumers, and examples. The return-type change required downstream migrations so the workspace continued to compile, but detector, alignment, recognition, PAD, liveness, threshold, capture-schedule, profile selection, and preprocessing policy remain unchanged.

### Ownership And Validation

- Canonical pixels are owned `Vec<u8>` values with no mutable or ownership-transferring public accessor.
- Public conversions accept only `Frame` values carrying validated runtime provenance; no raw-pixel constructor is public.
- Geometry multiplication is checked before exact payload comparison.
- Aggregate construction rejects empty, oversized, mixed-binding, mixed-format, discontinuous, or invalidly selected contributors.
- `Debug` output reports dimensions and lengths but not pixels or native provenance.
- Canonical diagnostic methods retain exact runtime validation internally while exposing only existing share-safe trace projections.

### Behavior Equivalence

- Fixed RGB fixtures prove the upper-middle per-byte median remains exact and all contributors remain in the capture window.
- Fixed IR fixtures prove default selected pixels and clipping pixels are identical.
- Fixed lit and ambient fixtures prove subtraction output, lit and ambient selection indices, aggregate contributor ownership, and raw clipping retention.
- Existing camera reduction, contention, runtime-contract, authentication, CLI, and workspace tests pass without threshold or policy changes.

### Review Notes

- Added direct equivalence assertions for frame-based and canonical runtime diagnostic events.
- Corrected stale comments that referred to the removed statistics tuple and `IrCaptureStats::saturation_frame` field.
- Reviewer subagents are unavailable in this harness, so the final review was performed manually over the complete diff and relevant one-hop dependencies using the Rust API, ownership, error, numeric-safety, documentation, and testing checks.

## Concerns

- None blocking Task 3.
- Physical camera and v4l2loopback tests remain declared ignored in this environment. Existing hardware behavior is preserved by pure fixture equivalence and the unchanged capture selection policy, but the controller may run those gates on equipped hosts before production integration.

## Fix Round 1

### Defects Fixed

- Removed the public `TryFrom<Frame>` and `TryFrom<(Frame, IrCaptureStats)>` implementations. External callers can no longer turn a publicly mutable `Frame` into canonical evidence.
- Bound every internal canonical frame to the width and height retained by its validated runtime format provenance, in addition to the existing role and payload checks.
- Added `EvidenceError::InvalidStatistics` and made IR burst construction recompute contributor-dependent facts from retained contributor pixels and illumination provenance.
- Validated burst, camera-classified, and camera-lit counts; ambient observation and mean; lit mean; selected gate index; subtraction partner; and all three saturation fractions.
- Preserved `white_level` as capture-owned evidence because decoded pixels and provenance cannot reconstruct the negotiated sensor ceiling.
- Kept a test-only crate-private IR constructor for existing unit fixtures that intentionally exercise downstream behavior with synthetic statistics. It does not exist in production builds and exposes no external authority.

### RED Evidence

- The first focused run failed to compile because the required `InvalidStatistics` error contract did not exist.
- After adding only that error variant, `cargo test -p irlume-camera --lib evidence::tests` ran 11 tests: 7 passed and the 4 new authority regressions failed because malformed geometry, counts, ambient facts, and selected/subtracted contributor claims were accepted.
- `cargo test -p irlume-camera --doc` failed both new compile-fail tests because both public conversions still compiled.

### GREEN Evidence

- `cargo test -p irlume-camera --lib evidence::tests`: 11 passed, 0 failed.
- `cargo test -p irlume-camera --doc`: 2 compile-fail tests passed, 0 failed.
- `cargo test -p irlume-camera --lib`: 619 passed, 0 failed, 26 declared hardware tests ignored.
- `cargo test -p irlume-camera --all-targets --locked`: passed 619 library tests, 12 contract tests, 1 qualification contract, and 2 example tests; 26 declared hardware tests ignored.
- `cargo check --workspace --all-targets`: passed.
- `cargo test --workspace --all-targets --locked`: 1,947 passed, 0 failed, 100 declared environment or hardware tests ignored across 61 result groups.
- `cargo clippy --workspace --all-targets --locked -- -D warnings`: passed.
- `cargo fmt --all -- --check`: passed.
- `git diff --check`: passed.

The linked worktree still lacks six ignored ONNX assets. Six temporary symlinks to the parent checkout were created after all seven files passed `models/SHA256SUMS`; the full workspace suite passed, and every temporary link was removed.

### Files Changed

- `crates/irlume-camera/src/evidence.rs`
- `crates/irlume-camera/src/lib.rs`
- `.superpowers/sdd/2026-09-01-layered-camera-profile-engine/task-3-implementer.md`

### Self-Review

- Public single-frame `Frame` APIs remain unchanged; only the unintended public canonical conversions were removed.
- Production capture still computes the same means, metadata counts, clipping fractions, gate-frame index, ambient partner, and output pixels before canonical construction. Validation independently recomputes those facts and rejects disagreement without changing thresholds, selection policy, model inputs, or capture scheduling.
- Geometry is checked against provenance before payload acceptance, closing the mutable-field relabeling path for both RGB and IR evidence.
- Compile-fail doctests prove both external minting routes remain unavailable.
- All changed production methods remain crate-private, canonical pixel fields remain owned and private, and the synthetic constructor is compiled only under `cfg(test)`.

### Concerns

- Physical camera and v4l2loopback tests remain declared ignored in this environment. The unchanged production calculations and fixture equivalence cover the authority correction, but equipped-host gates may still be run before production integration.

# Task 2 Implementer Report

## What Was Implemented

- Added a bounded, observation-only V4L2 capability inventory behind one injected source seam.
- Added raw format, frame-size, frame-interval, standard-control, and menu enumeration over one pinned, leased, read-only file descriptor.
- Capped formats at 64, geometries per format at 256, discrete intervals per tuple at 256, controls at 256, and menu indices at 256.
- Preserved discrete, continuous, and stepwise domains while materializing only exact endpoints and exact intersections with versioned geometry and interval requirements.
- Retained unsupported advertised formats as a diagnostic count without creating undecodable candidates.
- Retained standard user, camera, and image-source controls with exact scalar fields and bounded menu values.
- Excluded disabled, read-only, write-only, execute-on-write, button, class, and vendor-private controls from conditioning-policy eligibility.
- Added ASUS, BRIO, and NexiGo fixtures that preserve the observed exact decoded tuples and do not invent lower IR rates.
- Exported the inventory module without changing production capture, qualification, transport selection, capture-schedule selection, model input, or MJPG decoding.

`VIDIOC_TRY_FMT` remains in the separate `TransportProfileQualifier` stage described by the accepted design. The inventory itself issues only observation ioctls and creates no capture authority.

## RED Evidence

The initial focused command was:

```text
cargo test -p irlume-camera --lib capability_inventory::tests
```

It failed with 92 compiler errors because the inventory types, source seam, and functions did not exist. Additional focused RED cycles established missing range-domain accessors and reproduced an overflow panic in extreme control-lattice validation before those paths were implemented safely.

Final review found that a read-only standard control was still policy-eligible. The regression test was added first and failed as intended:

```text
running 1 test
test capability_inventory::tests::controls_retain_only_standard_classes_and_gate_dangerous_flags ... FAILED
assertion failed: inventory.controls()[1..].iter().all(|control| !control.policy_eligible())
test result: FAILED. 0 passed; 1 failed; 0 ignored
```

## GREEN Evidence

- `cargo test -p irlume-camera --lib capability_inventory::tests`: 11 passed, 0 failed.
- `cargo test -p irlume-camera --lib frame_interval::tests`: 20 passed, 0 failed.
- The focused read-only regression test passed after adding `V4L2_CTRL_FLAG_READ_ONLY` to the eligibility exclusion mask.
- `cargo test -p irlume-camera --all-targets --locked`: 621 passed, 0 failed, 26 declared hardware tests ignored.
- `cargo test --workspace --all-targets --locked`: 1,934 passed, 0 failed, 100 declared environment or hardware tests ignored across 61 result groups.
- `cargo clippy -p irlume-camera --all-targets -- -D warnings`: passed.
- `cargo fmt --all -- --check`: passed.
- `git diff --check`: passed before staging.

The linked worktree lacks six ignored ONNX assets. Six temporary symlinks to the parent checkout were created solely for the workspace test, all seven files passed `models/SHA256SUMS`, and the links were removed immediately after the successful run. The first link command incorrectly prefixed targets with `models/` while already running inside that directory; it failed before creating anything, and the corrected basename command succeeded.

## Files Changed

- `crates/irlume-camera/src/capability_inventory.rs`
- `crates/irlume-camera/src/frame_interval.rs`
- `crates/irlume-camera/src/lib.rs`
- `.superpowers/sdd/2026-09-01-layered-camera-profile-engine/task-2-implementer.md`

## Differential Review

| Severity | Remaining | Resolved during review |
|---|---:|---:|
| Critical | 0 | 0 |
| Important | 0 | 1 |
| Minor | 0 | 0 |

**Overall risk:** Medium. This adds a public read-only API and private unsafe ioctl calls over driver-controlled data.

**Recommendation:** Approve after the recorded verification and hygiene gates.

### Scope And Blast Radius

The review covered all three code files against base `ce59a2af9830ecc687d56bf8da1b371527b2e7de`, the Task 2 brief, the accepted design, existing decoder paths, camera lease validation, and Linux V4L2 enumeration contracts. The new module has no production callers. `FrameIntervalDomain::candidate_values` has one caller, inside the new module. The module export has no behavioral caller. Blast radius is therefore low until a later qualifier task consumes the API.

### Safety And Failure Analysis

- Every raw ioctl structure is zero-initialized, receives only documented input fields, and remains valid for the complete call.
- Echoed query fields, reserved fields, domain types, monotonic control IDs, capacity boundaries, and termination errno are validated fail-closed.
- Exact rational and lattice arithmetic uses checked-width integer representations and no floating point.
- Enumeration errors remain distinct from empty observations.
- No write-capable open, setting ioctl, control write, stream start, persisted authority, or production selection path was added.
- No security-related validation was removed from existing code. The only existing-file production change is the private bounded candidate projection used by the new inventory.

### Resolved Finding

`StandardControlCapability::policy_eligible` originally excluded disabled, write-only, and execute-on-write controls but not `V4L2_CTRL_FLAG_READ_ONLY`. A later reversible conditioning policy cannot safely name a control it cannot write and restore. A failing behavior test was added, then the read-only flag was added to the exclusion mask.

### Coverage And Limitations

The pure source seam covers discrete and range domains, exact lattice intersections, duplicate advertisements, unknown formats, invalid and extreme controls, every primary item cap, bounded menu retention, error versus empty distinction, and the three observed camera fixtures. The production raw ioctl adapter is compile-checked and shares all post-enumeration validation with fixtures, but no physical camera was opened by this task. Automated reviewer subagents and the full Rust review orchestrator are unavailable in this harness, so the final review was performed manually over the complete changed surface and its one-hop dependencies.

## Concerns

- None blocking Task 2.
- This inventory creates candidates only. Later tasks must retain the separate read-only `VIDIOC_TRY_FMT`, exact set/readback, hardware qualification, quality, security, and latency gates before any profile gains authority.

## Fix Round 1

### Findings Fixed

- Made control validation explicitly type-aware. Integer, boolean, menu, and integer-menu controls retain scalar-lattice validation and are the only types eligible for later policy use. Valid integer64, string, compound, and other unsupported standard controls remain available diagnostically without being interpreted as represented scalar controls or gaining policy eligibility.
- Made menu observation fail closed when no item was enumerated or when sparse enumeration omitted the advertised default index. Sparse non-default holes remain valid when the default is present.

### RED Evidence

After adding the integer64/unsupported-type and incomplete-menu regressions, this focused command failed before production changes:

```text
cargo test -p irlume-camera --lib capability_inventory::tests
```

```text
running 13 tests
test capability_inventory::tests::unsupported_control_types_remain_diagnostic_and_policy_ineligible ... FAILED
test capability_inventory::tests::incomplete_menus_fail_closed ... FAILED

called `Result::unwrap()` on an `Err` value: InvalidControl { id: 9963776, reason: "step is not positive" }
assertion failed: matches!(inventory_from_source(&mut source, StreamRole::Rgb),
    Err(CapabilityError::InvalidControl { id: actual, .. }) if actual == id)

test result: FAILED. 11 passed; 2 failed; 0 ignored
```

### GREEN Evidence

- `cargo test -p irlume-camera --lib capability_inventory::tests`: 13 passed, 0 failed.
- `cargo test -p irlume-camera --lib frame_interval::tests`: 20 passed, 0 failed.
- `cargo test -p irlume-camera --all-targets --locked`: 621 passed, 0 failed, 26 declared hardware tests ignored.
- `cargo test --workspace --all-targets --locked`: 1,936 passed, 0 failed, 100 declared environment or hardware tests ignored across 61 result groups.
- `cargo clippy -p irlume-camera --all-targets -- -D warnings`: passed.
- `cargo fmt --all -- --check`: passed.
- `git diff --check`: passed.
- All seven entries in `models/SHA256SUMS` were verified before the workspace gate. The six temporary ONNX symlinks were removed immediately afterward. The first checksum invocation used the repository root even though the manifest paths are relative to `models/`; it failed without running tests, then passed from the correct working directory.

### Files And Commit

- `crates/irlume-camera/src/capability_inventory.rs`
- `.superpowers/sdd/2026-09-01-layered-camera-profile-engine/task-2-implementer.md`
- Parent: `a12b72316871af181aa680ce745ee98e1ebba19b`.
- Fix commit: the separate signed+DCO Fix Round 1 commit containing this section.

### Self-Review

- The changes are confined to shared control validation, policy-eligibility derivation, and their pure regressions. The raw ioctl surface and every production capture, qualification, selection, model-input, and MJPG path are unchanged.
- Unsupported standard control types are retained but cannot become policy inputs. Supported represented types still fail closed on invalid scalar metadata and dangerous flags.
- Menu default completeness is checked after bounded index validation. Empty menus and missing defaults fail with `CapabilityError::InvalidControl`; sparse non-default holes remain accepted.

### Concerns

- None blocking Task 2.

# Per-Role Delivered-Rate Shortfall Evidence Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Persist and present exact per-role delivered-rate shortfall evidence without changing capture qualification or authentication policy.

**Architecture:** Add fixed-size share-safe DTOs in `irlume-common`, fold typed `Error::DeliveredRate` payloads into each camera probe arm, and persist the measured summary as an additive optional field in schema-2 `ArmEvidence`. Project authoritative and latest-attempt evidence separately through the existing camera-to-auth diagnostic path, then render exact facts in `camera-tune` and support reports.

**Tech Stack:** Rust, Serde, Cargo unit tests, existing `irlume-common`, `irlume-camera`, `irlume-auth`, `irlume-daemon`, and `irlume-cli` crates.

**Spec:** `docs/superpowers/specs/2026-08-31-rate-shortfall-evidence-design.md`

## Global Constraints

- Keep capture qualification schema version exactly `2`.
- Do not change delivered-rate floors, the `98` percent tolerance, retry counts, requested rounds, outcomes, authority replacement, capture schedules, or authentication behavior.
- Use fixed RGB and IR slots, never an unbounded map or vector.
- Compare delivered-to-floor ratios with exact integer arithmetic, never floating point.
- Preserve missing persisted evidence as legacy unknown and fresh empty evidence as measured empty.
- Label authoritative and latest-attempt evidence separately.
- Keep all output share-safe and free of device paths, serial values, frames, embeddings, and identity.
- Use plain punctuation and introduce no U+2014 em dash.

---

### Task 1: Fixed-Size Common Evidence Contract

**Files:**
- Modify: `crates/irlume-common/src/diagnostics.rs:271-465`
- Test: `crates/irlume-common/src/diagnostics.rs:1040-1200`

**Interfaces:**
- Consumes: existing `CameraRoleLabel` and Serde support.
- Produces: `RateShortfallEvidence`, `RateShortfallsByRole`, and `RateShortfallsByArm`; additive `CaptureStatus.authoritative_rate_shortfalls` and `CaptureStatus.latest_attempt_rate_shortfalls` fields.

- [ ] **Step 1: Write failing DTO and old-wire tests**

Add tests that construct fixed RGB and IR slots, serialize exact numerator and denominator fields, reject no data implicitly by preserving `Option`, and deserialize the pre-#644 `CaptureStatus` JSON with both new fields equal to `None`:

```rust
#[test]
fn old_capture_status_defaults_rate_shortfall_sections_to_absent() {
    let old = r#"{"schedule":"sequential","source":"stored_qualification","qualification_state":"measured_sequential"}"#;
    let status: CaptureStatus = serde_json::from_str(old).unwrap();
    assert_eq!(status.authoritative_rate_shortfalls, None);
    assert_eq!(status.latest_attempt_rate_shortfalls, None);
}
```

- [ ] **Step 2: Run the common test and verify RED**

Run: `cargo test -p irlume-common --lib old_capture_status_defaults_rate_shortfall_sections_to_absent`

Expected: compilation fails because the new fields and DTOs do not exist.

- [ ] **Step 3: Implement the bounded DTOs and additive fields**

Define the DTO shape with public serializable fields so downstream presentation stays mechanical:

```rust
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct RateShortfallEvidence {
    pub role: CameraRoleLabel,
    pub failure_count: u32,
    pub delivered_num: u64,
    pub delivered_den: u64,
    pub floor_num: u32,
    pub floor_den: u32,
    pub tolerance_percent: u32,
    pub window_count: u32,
    pub window_span_us: u64,
}

#[derive(Clone, Debug, Default, Eq, PartialEq, Serialize, Deserialize)]
pub struct RateShortfallsByRole {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub rgb: Option<RateShortfallEvidence>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ir: Option<RateShortfallEvidence>,
}

#[derive(Clone, Debug, Default, Eq, PartialEq, Serialize, Deserialize)]
pub struct RateShortfallsByArm {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sequential: Option<RateShortfallsByRole>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub concurrent: Option<RateShortfallsByRole>,
}
```

Add both `CaptureStatus` fields with `#[serde(default, skip_serializing_if = "Option::is_none")]` and update existing fixtures with `None`.

- [ ] **Step 4: Run common tests and verify GREEN**

Run: `cargo test -p irlume-common --lib diagnostics::tests`

Expected: all diagnostics tests pass, including old-wire compatibility and share-safe key checks.

- [ ] **Step 5: Commit the contract slice**

```bash
git add crates/irlume-common/src/diagnostics.rs
git commit -s -m "feat: define rate shortfall diagnostics"
```

### Task 2: Exact Accumulation And Schema-2 Persistence

**Files:**
- Modify: `crates/irlume-camera/src/lib.rs:6490-6577,7483-7555,8079-8119,12293-12479`
- Modify: `crates/irlume-camera/src/capture_qualification.rs:801-966,1015-1064,1170-1282,1658-1739`
- Test: `crates/irlume-camera/src/lib.rs`
- Test: `crates/irlume-camera/src/capture_qualification.rs`

**Interfaces:**
- Consumes: common DTOs from Task 1 and existing `CameraStreamRateEvidence` payloads.
- Produces: `PairSample.rate_shortfalls: RateShortfallsByRole`, `ArmEvidence::rate_shortfalls() -> Option<&RateShortfallsByRole>`, and `QualificationAttempt::rate_shortfalls() -> RateShortfallsByArm`.

- [ ] **Step 1: Write failing exact-accumulation tests**

Extend the existing `below_floor_error` helper to accept exact delivered and floor fractions. Add tests proving that two RGB errors retain the lower exact delivered-to-floor ratio even when decimal rounding would tie, and that one round with RGB and IR typed errors increments the round failure once while creating one count in each role slot.

```rust
assert_eq!(sample.failed, 1);
assert_eq!(sample.rate_shortfall_failures, 1);
assert_eq!(sample.rate_shortfalls.rgb.as_ref().unwrap().failure_count, 1);
assert_eq!(sample.rate_shortfalls.ir.as_ref().unwrap().failure_count, 1);
```

- [ ] **Step 2: Run focused accumulation tests and verify RED**

Run: `cargo test -p irlume-camera --lib rate_shortfall -- --nocapture`

Expected: compilation fails because `PairSample.rate_shortfalls` does not exist.

- [ ] **Step 3: Implement exact fixed-slot observation**

Add a private observer that parses only `rgb` and `ir`, increments that slot's failure count, and replaces the retained sample only when its exact ratio is lower. Form each ratio as `(delivered_num * floor_den) / (delivered_den * floor_num)` in `u128`, then compare two `u128` fractions with quotient and remainder steps rather than overflow-prone cross multiplication. Keep the existing per-round `rate_shortfall_failures` count and observe both error legs before returning.

- [ ] **Step 4: Run focused accumulation tests and verify GREEN**

Run: `cargo test -p irlume-camera --lib rate_shortfall -- --nocapture`

Expected: worst-sample and simultaneous-role tests pass; existing typed shortfall tests remain green.

- [ ] **Step 5: Write failing persistence semantics tests**

Add tests that remove `rate_shortfalls` from serialized `ArmEvidence` and observe `None`, construct a current healthy arm and observe `Some(RateShortfallsByRole::default())`, round-trip RGB and IR evidence, and assert `SCHEMA_VERSION == 2`.

```rust
assert_eq!(legacy.rate_shortfalls(), None);
assert_eq!(fresh.rate_shortfalls(), Some(&RateShortfallsByRole::default()));
assert_eq!(SCHEMA_VERSION, 2);
```

- [ ] **Step 6: Run persistence tests and verify RED**

Run: `cargo test -p irlume-camera --lib capture_qualification::tests::rate_shortfall`

Expected: compilation fails because `ArmEvidence` has no optional persisted summary or getter.

- [ ] **Step 7: Implement additive persistence and attempt projection**

Add `#[serde(default, skip_serializing_if = "Option::is_none")] rate_shortfalls: Option<RateShortfallsByRole>` to `ArmEvidence`. Add a concrete `RateShortfallsByRole` argument to `ArmEvidence::new`, store it as `Some`, pass `PairSample.rate_shortfalls.clone()` from `qualification_arm`, and update all constructor call sites with measured-empty values. Validate that populated RGB and IR slots carry their matching role and nonzero failure counts and denominators. Add getters and build `RateShortfallsByArm` from the sequential and concurrent arm options without changing outcome logic.

- [ ] **Step 8: Run camera tests and verify GREEN**

Run: `cargo test -p irlume-camera --lib`

Expected: all runnable camera tests pass; hardware-only tests remain ignored.

- [ ] **Step 9: Commit the accumulation and persistence slice**

```bash
git add crates/irlume-camera/src/lib.rs crates/irlume-camera/src/capture_qualification.rs
git commit -s -m "feat: persist per-role rate shortfalls"
```

### Task 3: Preserve Authoritative And Latest Attempt Evidence

**Files:**
- Modify: `crates/irlume-camera/src/lib.rs:7148-7154,7483-7506`
- Modify: `crates/irlume-auth/src/lib.rs:1334-1448,1476-1600,2000-2123`
- Test: `crates/irlume-camera/src/capture_qualification.rs`
- Test: `crates/irlume-auth/src/lib.rs`

**Interfaces:**
- Consumes: `QualificationAttempt::rate_shortfalls()` from Task 2.
- Produces: `StoredCaptureQualificationState.authoritative_rate_shortfalls`, `StoredCaptureQualificationState.latest_attempt_rate_shortfalls`, and matching `CaptureStatus` projection.

- [ ] **Step 1: Write failing authority-preservation tests**

Create a conclusive authoritative attempt with a concurrent RGB shortfall, then save an inconclusive latest attempt with a different IR shortfall. Assert that resolution still uses the original authority and that the two projected summaries remain distinct.

```rust
assert_eq!(state.resolution, QualificationResolution::SequentialRequired(SequentialReason::DeliveredRateShortfall));
assert_eq!(state.authoritative_rate_shortfalls.unwrap().concurrent.unwrap().rgb.unwrap().failure_count, 4);
assert_eq!(state.latest_attempt_rate_shortfalls.unwrap().concurrent.unwrap().ir.unwrap().failure_count, 1);
```

- [ ] **Step 2: Run authority tests and verify RED**

Run: `cargo test -p irlume-camera --lib inconclusive_attempt_preserves_authoritative_rate_shortfalls`

Expected: compilation fails because stored state exposes no evidence fields.

- [ ] **Step 3: Project both record views through camera state**

In `resolve_capture_qualification_state`, derive latest evidence from `record.last_attempt()` and authoritative evidence from `record.authoritative()` before resolving the record. Preserve `None` when no record or no authority exists.

- [ ] **Step 4: Write failing auth support-context tests**

Extend capture-selection fixtures so `emit_capture_context` publishes a `CaptureStatus` with separately labeled authoritative and latest-attempt values. Assert an inconclusive latest attempt does not overwrite the authoritative field.

- [ ] **Step 5: Run auth tests and verify RED**

Run: `cargo test -p irlume-auth --lib rate_shortfall`

Expected: compilation fails because `CaptureModeSelection` and `CaptureStatus` do not carry the new fields.

- [ ] **Step 6: Thread evidence through auth diagnostics only**

Add the two optional summaries to `CaptureModeSelection`, populate them from `StoredCaptureQualificationState`, default them to `None` for unavailable and RGB-only selections, and copy them into `CaptureStatus` in `emit_capture_context`. Do not consult either field in schedule selection, runtime degradation, liveness, or authentication.

- [ ] **Step 7: Run camera and auth tests and verify GREEN**

Run: `cargo test -p irlume-camera -p irlume-auth --lib`

Expected: all runnable tests pass and the authority-preservation regression is green.

- [ ] **Step 8: Commit the diagnostic projection slice**

```bash
git add crates/irlume-camera/src/lib.rs crates/irlume-auth/src/lib.rs
git commit -s -m "feat: expose qualification rate evidence"
```

### Task 4: Camera-Tune Exact Facts

**Files:**
- Modify: `crates/irlume-daemon/src/main.rs:1569-1845,3273-3574`
- Test: `crates/irlume-daemon/src/main.rs`

**Interfaces:**
- Consumes: `ContentionReport` and `PairSample.rate_shortfalls` from Task 2.
- Produces: stable human-readable per-role exact-rate wording for conclusive and inconclusive `camera-tune` results.

- [ ] **Step 1: Write failing conclusive and partial wording tests**

Add one report with four RGB typed shortfalls and one completed concurrent round, and one conclusive all-shortfall report with both roles represented. Assert the text includes role, count, exact delivered and required rates, tolerance, and window facts. The partial assertion must include the observed `1 of 5` shape rather than claiming five clean rounds.

```rust
assert!(message.contains("RGB: 4 shortfalls"));
assert!(message.contains("worst delivered 10/1 fps; required 15/1 fps"));
assert!(message.contains("tolerance 98%; window 30 deltas over 3000000us"));
```

- [ ] **Step 2: Run daemon wording tests and verify RED**

Run: `cargo test -p irlume-daemon --bin irlumed rate_shortfall -- --nocapture`

Expected: assertions fail because current wording prints only aggregate below-floor counts.

- [ ] **Step 3: Implement one bounded formatter and use it in both paths**

Add a pure formatter that emits RGB then IR from fixed slots. Append it to delivered-rate sequential verdicts, the all-error early return when typed rate evidence exists, and the incomplete-round `why` passed to `inconclusive_probe_message`. Keep existing verdict and authority wording intact.

- [ ] **Step 4: Run daemon tests and verify GREEN**

Run: `cargo test -p irlume-daemon --bin irlumed rate_shortfall -- --nocapture`

Expected: conclusive, simultaneous-role, and partial-attempt wording tests pass.

- [ ] **Step 5: Commit the camera-tune slice**

```bash
git add crates/irlume-daemon/src/main.rs
git commit -s -m "feat: report exact camera rate shortfalls"
```

### Task 5: Support Report And Final Verification

**Files:**
- Modify: `crates/irlume-cli/src/support_report.rs:331-382,808-924`
- Modify fixtures: `crates/irlume-daemon/src/diagnostics.rs:620-669`
- Modify fixtures: `crates/irlume-common/src/diagnostics.rs:1075-1085`

**Interfaces:**
- Consumes: the two additive `CaptureStatus` evidence fields from Task 1 and populated values from Task 3.
- Produces: separately labeled authoritative and latest-attempt support-report sections with explicit unknown, measured-empty, and measured-shortfall states.

- [ ] **Step 1: Write failing support rendering tests**

Extend the support fixture so authoritative concurrent RGB has four shortfalls, latest sequential is measured-empty, and latest concurrent IR has one shortfall. Add a legacy fixture with absent arm evidence. Assert exact labels and values:

```rust
assert!(text.contains("authoritative rate shortfalls"));
assert!(text.contains("concurrent RGB: 4 shortfalls, worst delivered 10/1 fps, required 15/1 fps"));
assert!(text.contains("latest-attempt rate shortfalls"));
assert!(text.contains("sequential: measured, no delivered-rate shortfalls"));
assert!(legacy_text.contains("concurrent: legacy unknown"));
```

- [ ] **Step 2: Run support tests and verify RED**

Run: `cargo test -p irlume-cli --bin irlume support_report::tests::human_report_includes_sanitized_topology_contracts_and_capture_authority -- --exact`

Expected: assertions fail because no rate-evidence sections are rendered.

- [ ] **Step 3: Implement bounded support rendering**

Add pure helpers for one role, one arm, and one authority label. Render absent outer evidence as unavailable, absent arm evidence as legacy unknown, empty fixed slots as measured with no shortfalls, and populated slots with exact facts. Keep the report schema unchanged because the source `CaptureStatus` fields are additive and defaulted.

- [ ] **Step 4: Run support and daemon diagnostic tests and verify GREEN**

Run: `cargo test -p irlume-cli --bin irlume support_report::tests`

Run: `cargo test -p irlume-daemon --bin irlumed diagnostics::tests`

Expected: all targeted tests pass and existing privacy assertions still reject paths and identity fields.

- [ ] **Step 5: Run formatting, static checks, and the full workspace gate**

Run: `cargo fmt --all -- --check`

Run: `cargo clippy --workspace --all-targets --all-features -- -D warnings`

Run: `cargo test --workspace --all-targets --all-features`

Run: `git diff --check`

Run: `! git diff --unified=0 f8698b49 -- crates/irlume-common/src/diagnostics.rs crates/irlume-camera/src/lib.rs crates/irlume-camera/src/capture_qualification.rs crates/irlume-auth/src/lib.rs crates/irlume-daemon/src/main.rs crates/irlume-daemon/src/diagnostics.rs | rg '^\+.*\u2014'`

Run: `! rg -n $'\u2014' crates/irlume-cli/src/support_report.rs docs/superpowers/specs/2026-08-31-rate-shortfall-evidence-design.md docs/superpowers/plans/2026-08-31-rate-shortfall-evidence.md`

Expected: formatting, Clippy, tests, diff hygiene, and plain-punctuation checks all pass. Hardware-dependent tests may remain explicitly ignored.

- [ ] **Step 6: Commit the support and verification slice**

```bash
git add crates/irlume-cli/src/support_report.rs crates/irlume-daemon/src/diagnostics.rs crates/irlume-common/src/diagnostics.rs docs/superpowers/specs/2026-08-31-rate-shortfall-evidence-design.md docs/superpowers/plans/2026-08-31-rate-shortfall-evidence.md
git commit -s -m "feat: render qualification rate evidence"
```

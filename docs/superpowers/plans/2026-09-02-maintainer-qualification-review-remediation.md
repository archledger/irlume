# Maintainer Qualification Review Remediation Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task. Subagents are prohibited for this work. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Close all five findings from the Task 8 full-slice review while preserving opaque signed authority, existing public function signatures, schema 1, and production isolation.

**Architecture:** A crate-private immutable `CampaignPolicyLimits` snapshot is retained by `ValidatedProtocol` and carried through its existing private clone path. Protocol validation uses typed populations and a domain-separated seed derivation; lifecycle, reducer, review, and compiler boundaries enforce their own policy-derived limits without accepting caller overrides.

**Tech Stack:** Rust 2024, Serde closed canonical JSON, `irlume-common` validated atoms and SHA-256, Cargo tests and compile-fail doctests.

**Spec:** `docs/superpowers/specs/2026-09-02-maintainer-qualification-review-remediation-design.md`

## Global Constraints

- Work only in `/home/wisbfime/irlume/.worktrees/feat-layered-camera-profile-engine` on `feat/layered-camera-profile-engine` from signed+DCO base `eb7157cd3c12c10ff2f4726822513e6cfadaba4e`.
- Do not touch `/home/wisbfime/irlume/.worktrees/exp-lunar-lake-npu-benchmark` or any TFLite/NPU file, process, result, or handoff owned by the separate session.
- Do not reconcile the 17-ahead/17-behind source history, merge, rebase, push, create a PR, or begin Delivery Phase 4.
- Do not access a real campaign, participant, consent registry, biometric asset, camera, hardware, keyring, package, service, daemon, writer, signer, publication path, or production state.
- Keep `irlume-qualification` unpublished with direct dependencies limited to `irlume-common`, Serde, and serde_json.
- Keep `irlume-camera` free of a normal `irlume-qualification` dependency; its existing dev dependency remains test-only.
- Preserve all current public function signatures and schema-1 serialized fields.
- Add no public test constructor, caller-supplied policy limit, target override, generic map, free-text diagnostic, or dynamic error content.
- Use checked arithmetic for every duration and count sum.
- Follow strict RED, GREEN, REFACTOR. Observe each named test fail for the expected missing invariant before editing production code.
- Use ASCII only and verify no U+2014 appears in changed deliverables.
- Do not commit unless the user explicitly authorizes it. If authorized, use signing key `F35053398E3C80FE20891B82C10B8492BD7F30C6` and exact trailer `Signed-off-by: Wisbendji Fimerlus <archledger236@gmail.com>`.

## File Map

- `crates/irlume-qualification/src/policy.rs`: construct the immutable crate-private policy-limit snapshot.
- `crates/irlume-qualification/src/protocol.rs`: retain limits, validate protocol lifetime, planned public cells, bona fide power populations, and deterministic seeded ordering.
- `crates/irlume-qualification/src/lifecycle.rs`: enforce bundle and private-retention deadlines and preserve accepted retention authority.
- `crates/irlume-qualification/src/reducer.rs`: reject unavailable required stages and recheck realized public cells.
- `crates/irlume-qualification/src/result.rs`: enforce result and review lifetimes during reviewed-authority assembly.
- `crates/irlume-qualification/src/compiler.rs`: enforce policy artifact lifetime and private-retention ceiling.
- `crates/irlume-camera/src/release_qualification.rs`: change only if the exact artifact expiry expectation changes.
- `docs/superpowers/specs/2026-09-02-camera-profile-maintainer-qualification-campaign-design.md`: add a narrow pointer to the approved correction.
- `docs/superpowers/plans/2026-09-02-camera-profile-maintainer-qualification-contracts.md`: append the review-remediation checkpoint and superseding plan pointer.
- `.superpowers/sdd/2026-09-01-layered-camera-profile-engine/task-8-maintainer-campaign-contracts-review.md`: append remediation evidence and final re-review verdict; never delete original findings.

---

### Task 1: Retain Policy Limits And Enforce Collection Lifetimes

**Files:**
- Modify: `crates/irlume-qualification/src/policy.rs`
- Modify: `crates/irlume-qualification/src/protocol.rs`
- Modify: `crates/irlume-qualification/src/lifecycle.rs`
- Test: owning `#[cfg(test)]` modules in those three files

**Interfaces:**
- Consumes: verified `CampaignPolicy`, verified `CampaignProtocol`, and existing collection eligibility snapshot.
- Produces: crate-private `CampaignPolicyLimits`, a privately retained limits field in `ValidatedProtocol`, narrow crate-private limit accessors, protocol lifetime enforcement, and collection retention enforcement.

- [ ] **Step 1: Add failing policy-limit authority tests**

In `policy.rs`, add a test that calls the wished-for crate-private limits snapshot and checks every value against `policy_value()`:

```rust
#[test]
fn policy_exposes_every_validated_limit_as_one_immutable_snapshot() {
    let policy: CampaignPolicy = serde_json::from_value(policy_value()).unwrap();
    policy.validate().unwrap();
    let limits = policy.limits();

    assert_eq!(limits.protocol_seconds(), 2_592_000);
    assert_eq!(limits.bundle_seconds(), 2_592_000);
    assert_eq!(limits.result_seconds(), 2_592_000);
    assert_eq!(limits.review_seconds(), 604_800);
    assert_eq!(limits.artifact_seconds(), 31_536_000);
    assert_eq!(limits.private_asset_retention_seconds(), 31_536_000);
    assert_eq!(limits.minimum_public_cell_size(), 20);
}
```

Name the production change that makes this pass: `CampaignPolicy::limits` returns all seven already-validated values; no caller constructs the snapshot.

- [ ] **Step 2: Run the policy test and verify RED**

Run:

```bash
cargo test -p irlume-qualification policy::tests::policy_exposes_every_validated_limit_as_one_immutable_snapshot -- --exact
```

Expected: compilation fails because `CampaignPolicy::limits` and `CampaignPolicyLimits` do not exist.

- [ ] **Step 3: Implement the minimal immutable limits snapshot**

Add beside `ExpiryRules`:

```rust
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct CampaignPolicyLimits {
    artifact_seconds: u64,
    bundle_seconds: u64,
    minimum_public_cell_size: u32,
    private_asset_retention_seconds: u64,
    protocol_seconds: u64,
    result_seconds: u64,
    review_seconds: u64,
}
```

Implement one `pub(crate) const fn` accessor per field. Add:

```rust
pub(crate) const fn limits(&self) -> CampaignPolicyLimits {
    CampaignPolicyLimits {
        artifact_seconds: self.expiry_rules.artifact_seconds,
        bundle_seconds: self.expiry_rules.bundle_seconds,
        minimum_public_cell_size: self.minimum_public_cell_size,
        private_asset_retention_seconds: self.private_asset_retention_seconds,
        protocol_seconds: self.expiry_rules.protocol_seconds,
        result_seconds: self.expiry_rules.result_seconds,
        review_seconds: self.expiry_rules.review_seconds,
    }
}
```

Remove the superseded standalone `protocol_expiry_seconds` accessor only after its caller migrates. Keep the existing public `private_asset_retention_seconds` accessor unchanged; removing public surface is outside this correction.

- [ ] **Step 4: Run the policy test and verify GREEN**

Run the exact command from Step 2. Expected: PASS.

- [ ] **Step 5: Add failing protocol and collection lifetime tests**

In `protocol.rs`, extract a test-only helper that verifies an explicit policy value and rewrites the protocol's `policy_sha256` before calling `ValidatedProtocol::new`. Use it for:

```rust
#[test]
fn protocol_rejects_expiry_beyond_signed_protocol_lifetime() {
    let mut policy = policy_value();
    policy["expiry_rules"]["protocol_seconds"] = json!(1);
    let protocol = protocol_value();
    assert_eq!(validate_with_policy(&policy, &protocol), Err(CampaignError::ProtocolInvalid));
}
```

Use the unchanged default fixture to prove equality because its existing expiry is exactly `created_at_unix + 2_592_000`; use the one-second policy only for the rejection case. A one-second equality variant cannot retain the fixture's later phase timestamps.

In `lifecycle.rs`, add two real-interface cases based on the existing verified policy/protocol and collection snapshot helpers:

```rust
#[test]
fn collection_retention_obeys_signed_bundle_lifetime() {
    let inputs = collection_inputs_with_limits(1, 31_536_000);
    assert_eq!(validate_collection_eligibility(inputs.protocol(), inputs.snapshot_after(1), inputs.now()), Ok(inputs.expected()));
    assert_eq!(validate_collection_eligibility(inputs.protocol(), inputs.snapshot_after(2), inputs.now()), Err(CampaignError::ConsentIneligible));
}

#[test]
fn collection_retention_obeys_signed_private_lifetime() {
    let inputs = collection_inputs_with_limits(31_536_000, 1);
    assert_eq!(validate_collection_eligibility(inputs.protocol(), inputs.snapshot_after(1), inputs.now()), Ok(inputs.expected()));
    assert_eq!(validate_collection_eligibility(inputs.protocol(), inputs.snapshot_after(2), inputs.now()), Err(CampaignError::ConsentIneligible));
}
```

The helper names above are test-only desired interfaces. Implement them in the owning test module from existing `policy_value`, `protocol_value`, and `verified_snapshot` primitives. They must not enter production code.

Add overflow cases with `collection_not_after_unix = u64::MAX` and a positive policy duration, expecting `ConsentIneligible`.

- [ ] **Step 6: Run the lifetime tests and verify RED**

Run:

```bash
cargo test -p irlume-qualification protocol::tests::protocol_rejects_expiry_beyond_signed_protocol_lifetime -- --exact
cargo test -p irlume-qualification lifecycle::tests::collection_retention_obeys_signed_bundle_lifetime -- --exact
cargo test -p irlume-qualification lifecycle::tests::collection_retention_obeys_signed_private_lifetime -- --exact
```

Expected: each test fails because only the old protocol lifetime accessor and framework one-year retention ceiling are enforced.

- [ ] **Step 7: Retain limits and enforce exact deadlines**

Change `ValidatedProtocol` to:

```rust
pub struct ValidatedProtocol {
    protocol: Verified<CampaignProtocol>,
    policy_sha256: Sha256Digest,
    limits: CampaignPolicyLimits,
}
```

In `ValidatedProtocol::new`, construct `let limits = policy.document().limits();`, reject checked-add failure or protocol expiry beyond `created_at_unix + limits.protocol_seconds()`, and retain `limits` only after every existing validation passes.

Add narrow crate-private accessors on `ValidatedProtocol`:

```rust
pub(crate) const fn limits(&self) -> CampaignPolicyLimits;
```

In `validate_collection_eligibility`, compute both limits with `checked_add`:

```rust
let bundle_limit = protocol
    .protocol()
    .collection_not_after_unix()
    .checked_add(protocol.limits().bundle_seconds())
    .ok_or(CampaignError::ConsentIneligible)?;
let private_limit = protocol
    .protocol()
    .collection_not_after_unix()
    .checked_add(protocol.limits().private_asset_retention_seconds())
    .ok_or(CampaignError::ConsentIneligible)?;
```

Reject retention later than either value or protocol expiry. Do not change evaluation/publication signatures; they already preserve the exact accepted retention timestamp.

- [ ] **Step 8: Verify GREEN and regression scope**

Run:

```bash
cargo test -p irlume-qualification policy::tests
cargo test -p irlume-qualification protocol::tests
cargo test -p irlume-qualification lifecycle::tests
cargo fmt --all -- --check
git diff --check
```

Expected: all pass. Inspect `git diff` and confirm no public function signature or serialized field changed.

- [ ] **Step 9: Create a signed checkpoint only if explicitly authorized**

If authorized:

```bash
git add crates/irlume-qualification/src/policy.rs crates/irlume-qualification/src/protocol.rs crates/irlume-qualification/src/lifecycle.rs docs/superpowers/specs/2026-09-02-maintainer-qualification-review-remediation-design.md docs/superpowers/plans/2026-09-02-maintainer-qualification-review-remediation.md
git commit -SF35053398E3C80FE20891B82C10B8492BD7F30C6 --signoff -m "fix: enforce qualification policy lifetimes"
```

Before accepting the commit, verify exact signature fingerprint and exact DCO trailer. If commit authorization is absent, leave reviewed changes uncommitted and proceed only with user approval.

---

### Task 2: Bind Power And Public Cells To Exact Populations

**Files:**
- Modify: `crates/irlume-qualification/src/protocol.rs`
- Modify: `crates/irlume-qualification/src/reducer.rs`
- Test: owning test modules in those files

**Interfaces:**
- Consumes: `ValidatedProtocol` with retained `minimum_public_cell_size`, signed `CasePlan` values, locked sample sizes, and exact evaluated case instances.
- Produces: order-independent checked planned-count helpers, bona fide-only power authorization, planned public-cell enforcement, and realized public-cell defense in depth.

- [ ] **Step 1: Add the exact attack-substitution RED test**

In `protocol.rs`, add the reviewed reproduction as a permanent test. Starting from `protocol_value()`:

1. Select the first stratum.
2. Set its bona fide baseline and candidate `planned_count` to 40.
3. Leave the display/replay pair at 99.
4. Rename that attack pair's case IDs so it sorts before the bona fide pair.
5. Re-sort cases by case ID.
6. Require `ValidatedProtocol::new` to return `ProtocolInvalid`.

Use the name:

```rust
#[test]
fn attack_counts_cannot_authorize_a_bona_fide_stratum_lock()
```

Name the production change that makes it pass: stratum locks sum only baseline bona fide plans with the exact stratum ID.

- [ ] **Step 2: Run the attack-substitution test and verify RED**

Run:

```bash
cargo test -p irlume-qualification protocol::tests::attack_counts_cannot_authorize_a_bona_fide_stratum_lock -- --exact
```

Expected: assertion fails because `ValidatedProtocol::new` currently returns `Ok`.

- [ ] **Step 3: Add planned public-cell boundary RED tests**

Add a table-driven real-constructor test over the four attack `PresentationClass` values. For each category, reduce its baseline and candidate planned total to `minimum_public_cell_size - 1`, then expect `ProtocolInvalid`. Add exact-floor controls that pass.

The policy's 40-case stratum minimum already rejects a bona fide stratum below the 20-case public floor, so a protocol-level bona fide test would pass before this correction and would not be valid RED evidence. Test bona fide overall and stratum boundaries directly against the wished-for private public-cell validator with an injected minimum of 100 over the existing 99-case fixture.

Use these names:

```rust
#[test]
fn every_planned_public_category_obeys_the_signed_cell_floor()

#[test]
fn planned_bona_fide_cells_use_the_same_public_floor_validator()
```

The helper-boundary test must fail to compile before production implementation because the validator does not exist. Do not count rejection by the pre-existing 40-case stratum rule as RED evidence for the public-floor correction.

- [ ] **Step 4: Run planned-cell tests and verify RED**

Run:

```bash
cargo test -p irlume-qualification protocol::tests::every_planned_public_category_obeys_the_signed_cell_floor -- --exact
cargo test -p irlume-qualification protocol::tests::planned_bona_fide_cells_use_the_same_public_floor_validator -- --exact
```

Expected: below-floor attack categories are accepted by current production validation, and the bona fide helper test fails to compile because the validator does not exist.

- [ ] **Step 5: Implement checked typed population helpers**

Add private helpers in `protocol.rs` that operate on baseline plans only:

```rust
fn planned_count(
    cases: &[CasePlan],
    presentation: PresentationClass,
    stratum_id: Option<&Identifier>,
) -> Result<u64, CampaignError> {
    cases
        .iter()
        .filter(|case| case.is_baseline())
        .filter(|case| case.presentation_class() == presentation)
        .filter(|case| stratum_id.is_none_or(|id| case.stratum_id() == id))
        .try_fold(0u64, |sum, case| {
            sum.checked_add(u64::from(case.planned_count()))
                .ok_or(CampaignError::ProtocolInvalid)
        })
}
```

Use this helper for overall and stratum power capture targets. Delete the current first matching case lookup. Add this private boundary:

```rust
fn validate_planned_public_cells(
    minimum: u32,
    cases: &[CasePlan],
    strata: &[StratumPlan],
) -> Result<(), CampaignError>;
```

Call it from `ValidatedProtocol::new` with `policy.limits().minimum_public_cell_size()`. Require every projected category total and every bona fide stratum total to meet the supplied minimum.

- [ ] **Step 6: Verify protocol GREEN**

Run all three exact tests and then:

```bash
cargo test -p irlume-qualification protocol::tests
```

Expected: all pass.

- [ ] **Step 7: Add realized public-cell RED tests**

In `reducer.rs`, test the reducer-owned helper boundary with synthetic evaluated cases so protocol construction does not mask reducer behavior. Require `CohortIncomplete` for each presentation category and each bona fide stratum below the retained floor, and success at equality.

Define and test this private interface:

```rust
fn validate_realized_public_cells(
    minimum: u32,
    cases: &[EvaluatedPairedCase],
) -> Result<(), CampaignError>;
```

Use test names:

```rust
#[test]
fn every_realized_public_category_obeys_the_signed_cell_floor()

#[test]
fn every_realized_bona_fide_stratum_obeys_the_signed_cell_floor()
```

- [ ] **Step 8: Run realized-cell tests and verify RED**

Run both exact reducer tests. Expected: compilation fails because `validate_realized_public_cells` does not exist.

- [ ] **Step 9: Implement reducer defense in depth**

Implement checked category and bona fide-stratum counts over exact evaluated instances. Call the helper after provenance/completeness matching and before `build_gate_results`, using:

```rust
validate_realized_public_cells(
    context.protocol.limits().minimum_public_cell_size(),
    &cases,
)?;
```

Do not pool categories or strata and do not alter output schemas.

- [ ] **Step 10: Verify GREEN and mutation sensitivity**

Run:

```bash
cargo test -p irlume-qualification protocol::tests
cargo test -p irlume-qualification reducer::tests
```

Temporarily remove the `BonaFide` filter from the protocol count helper. Confirm `attack_counts_cannot_authorize_a_bona_fide_stratum_lock` fails, then restore production code and rerun GREEN. Verify `git diff --check`.

- [ ] **Step 11: Create a signed checkpoint only if explicitly authorized**

If authorized:

```bash
git add crates/irlume-qualification/src/protocol.rs crates/irlume-qualification/src/reducer.rs
git commit -SF35053398E3C80FE20891B82C10B8492BD7F30C6 --signoff -m "fix: bind qualification sample populations"
```

Verify the exact signature and DCO. Otherwise stop at a reviewed uncommitted checkpoint.

---

### Task 3: Derive Pair Order From The Signed Seed

**Files:**
- Modify: `crates/irlume-qualification/src/protocol.rs`
- Test: `crates/irlume-qualification/src/protocol.rs`

**Interfaces:**
- Consumes: `balanced_order_seed`, canonical logical case IDs, and explicit pair order positions.
- Produces: private domain-separated rank derivation and exact expected order validation with no serialized schema change.

- [ ] **Step 1: Add pinned order-vector RED tests**

Create private wished-for helpers:

```rust
fn order_rank(seed: &Sha256Digest, logical_case_id: &Identifier) -> Sha256Digest;

fn expected_baseline_first(
    seed: &Sha256Digest,
    logical_case_ids: impl Iterator<Item = &Identifier>,
) -> Result<BTreeMap<Identifier, bool>, CampaignError>;
```

Add one test with four literal logical IDs and the existing fixture seed, SHA-256 of byte `8`, `2c624232cdd221771294dfbb310aca000a0df6ac8b66b696d90ef06fdefb64a3`. Pin these independently calculated rank strings:

```text
logical-00 283c6dc79c4ace764bacf6b96e6fe01b335e7c06e19e7b0c3313230e9ff19721
logical-01 b1e16e16c3803b5043df4da8d473063a944c315a06cbe0e2b685f2686de6c023
logical-02 4f9388ca5b948e70e38b23e28f6118425aab54c1c5287ad95924583f38dcb823
logical-03 8dda5e7acac64d77259aa78165d014c79e3762453f50984b5a147311154f3126
```

The sorted assignment map is `logical-00 = baseline first`, `logical-02 = candidate first`, `logical-03 = baseline first`, and `logical-01 = candidate first`. Do not calculate expected values by calling the function under test.

Use:

```rust
#[test]
fn balanced_order_seed_has_pinned_domain_separated_assignments()
```

- [ ] **Step 2: Run the vector test and verify RED**

Run the exact test. Expected: compilation fails because the order helpers do not exist.

- [ ] **Step 3: Implement rank derivation and balanced alternation**

Build rank bytes exactly as approved:

```rust
let mut bytes = b"irlume-campaign-order-v1\0".to_vec();
bytes.extend_from_slice(seed.as_str().as_bytes());
bytes.push(0);
bytes.extend_from_slice(logical_case_id.as_str().as_bytes());
Sha256Digest::of(&bytes)
```

Collect `(rank, logical_case_id)` pairs, reject duplicate logical IDs, sort by rank then ID, reject an odd count, and assign baseline-first for even zero-based ranks. Use `BTreeMap` for deterministic lookup.

- [ ] **Step 4: Verify the pinned helper GREEN**

Run the exact test. If the independently pinned rank literals differ, inspect the byte contract; do not rewrite expected values merely to match an implementation mistake.

- [ ] **Step 5: Add protocol-level order RED tests**

Update `protocol_value()` test fixture generation to derive order positions from the approved algorithm. Then add:

```rust
#[test]
fn protocol_order_is_seed_derived_and_input_order_independent()

#[test]
fn protocol_rejects_one_swapped_seeded_assignment()

#[test]
fn changing_seed_requires_matching_new_assignments()
```

The first validates the fixture after reordering source logical IDs before serialization. The second swaps both sides of one explicit pair while retaining aggregate balance. The third changes only the seed and expects `ProtocolInvalid`, then rewrites every order position from the new seed and expects success.

- [ ] **Step 6: Run protocol order tests and verify RED**

Expected: the swapped assignment and changed seed are accepted because current validation checks aggregate balance only.

- [ ] **Step 7: Enforce expected assignments in `validate_cases`**

Pass `&self.balanced_order_seed` into `validate_cases`. Build expected assignments from each pair's logical ID and reject any baseline or candidate position mismatch. Keep the existing explicit pair-shape and aggregate-balance checks as defense in depth.

- [ ] **Step 8: Verify GREEN and regressions**

Run:

```bash
cargo test -p irlume-qualification protocol::tests
cargo test -p irlume-qualification lifecycle::tests
cargo test -p irlume-qualification reducer::tests
cargo fmt --all -- --check
git diff --check
```

Temporarily replace the rank sort with lexical logical-ID sort. Confirm the pinned vector or changed-seed test fails, then restore and rerun GREEN.

- [ ] **Step 9: Create a signed checkpoint only if explicitly authorized**

If authorized:

```bash
git add crates/irlume-qualification/src/protocol.rs
git commit -SF35053398E3C80FE20891B82C10B8492BD7F30C6 --signoff -m "fix: derive campaign order from signed seed"
```

Verify the exact signature and DCO. Otherwise preserve the uncommitted reviewed checkpoint.

---

### Task 4: Fail Closed On Every Unavailable Required Stage

**Files:**
- Modify: `crates/irlume-qualification/src/reducer.rs`
- Test: `crates/irlume-qualification/src/reducer.rs`

**Interfaces:**
- Consumes: exact evaluated cases after authority and provenance matching.
- Produces: one policy-v1 missingness guard rejecting `NotApplicable` in all ten baseline/candidate stage fields for every presentation class.

- [ ] **Step 1: Add the exhaustive missingness RED matrix**

Refactor only test code to expose mutable access to each stage field by a closed table of setters. Iterate all five presentation classes and these ten labels:

```text
baseline detection
baseline recognition
baseline liveness
baseline rgb_pad
baseline ir_pad
candidate detection
candidate recognition
candidate liveness
candidate rgb_pad
candidate ir_pad
```

For each matrix entry, start from a complete passing real-interface reduction fixture, set exactly one field to `StageOutcome::NotApplicable`, and require `Err(CampaignError::CaptureIncomplete)`.

Use:

```rust
#[test]
fn every_required_stage_fails_closed_for_every_presentation()
```

- [ ] **Step 2: Run the matrix and verify RED**

Run:

```bash
cargo test -p irlume-qualification reducer::tests::every_required_stage_fails_closed_for_every_presentation -- --exact
```

Expected: bona fide rows pass the assertion, while non-bona-fide rows fail because the reducer returns a result or another later disposition.

- [ ] **Step 3: Generalize the existing missingness guard**

Replace the bona fide-only condition with:

```rust
if cases.iter().any(|case| {
    required_stages(case)
        .into_iter()
        .any(|outcome| matches!(outcome, StageOutcome::NotApplicable))
}) {
    return Err(CampaignError::CaptureIncomplete);
}
```

Keep this before gate, security, latency, transcript, and public-result construction.

- [ ] **Step 4: Add `Incorrect` denominator controls**

Add two exact controls. Set candidate detection to `Incorrect` for every bona fide instance and require `NoninferiorityFailed`. For each attack presentation, set one candidate stage to `Incorrect` while retaining `authentication_accept = false`; require successful reduction and assert the corresponding private transcript case retains `Incorrect`. This proves `Incorrect` remains in evidence while only `NotApplicable` is rejected.

- [ ] **Step 5: Verify GREEN and mutation sensitivity**

Run:

```bash
cargo test -p irlume-qualification reducer::tests::every_required_stage_fails_closed_for_every_presentation -- --exact
cargo test -p irlume-qualification reducer::tests
```

Temporarily restore the `BonaFide` condition, observe the matrix fail on attack classes, restore production code, and rerun GREEN.

- [ ] **Step 6: Create a signed checkpoint only if explicitly authorized**

If authorized:

```bash
git add crates/irlume-qualification/src/reducer.rs
git commit -SF35053398E3C80FE20891B82C10B8492BD7F30C6 --signoff -m "fix: reject unavailable qualification stages"
```

Verify the exact signature and DCO. Otherwise preserve the reviewed uncommitted checkpoint.

---

### Task 5: Enforce Result, Review, And Artifact Lifetimes

**Files:**
- Modify: `crates/irlume-qualification/src/result.rs`
- Modify: `crates/irlume-qualification/src/compiler.rs`
- Modify only if expected bytes change: `crates/irlume-camera/src/release_qualification.rs`
- Test: owning qualification test modules and camera compatibility test

**Interfaces:**
- Consumes: retained policy limits, signed public `evaluated_at_unix`, signed review `reviewed_at_unix`, accepted bundle retention, protocol expiry, and collection close.
- Produces: reviewed-authority rejection after result/review limits and compiler expiry bounded by artifact/private/framework limits.

- [ ] **Step 1: Add result and review lifetime RED tests**

In `result.rs`, extend the existing verified review fixture helper to accept policy `result_seconds`, policy `review_seconds`, public `evaluated_at_unix`, and attestation `reviewed_at_unix` while recomputing every affected digest and signature fixture.

Add:

```rust
#[test]
fn review_obeys_signed_result_lifetime()

#[test]
fn review_obeys_signed_review_lifetime()

#[test]
fn review_cannot_outlive_accepted_bundle_retention()
```

For each policy-duration test, equality at `evaluated_at_unix + 1` passes under a one-second limit and one second later returns `ReviewRejected`. Keep the other limit longer so each test isolates one field. For bundle retention, set the signed review time equal to the accepted retention timestamp and expect success, then one second later and expect `ReviewRejected`. Add checked-add overflow cases expecting `ReviewRejected`.

- [ ] **Step 2: Run review lifetime tests and verify RED**

Run:

```bash
cargo test -p irlume-qualification result::tests::review_obeys_signed_result_lifetime -- --exact
cargo test -p irlume-qualification result::tests::review_obeys_signed_review_lifetime -- --exact
cargo test -p irlume-qualification result::tests::review_cannot_outlive_accepted_bundle_retention -- --exact
```

Expected: the later review is accepted whenever it remains inside protocol review expiry because result, review, and bundle-retention deadlines are not all enforced at assembly.

- [ ] **Step 3: Enforce review-time limits**

In `assemble_reviewed_aggregate`, calculate:

```rust
let result_not_after = public
    .evaluated_at_unix
    .checked_add(context.protocol.limits().result_seconds())
    .ok_or(CampaignError::ReviewRejected)?;
let review_not_after = public
    .evaluated_at_unix
    .checked_add(context.protocol.limits().review_seconds())
    .ok_or(CampaignError::ReviewRejected)?;
```

Reject `reviewed_at_unix` after either deadline or after the bundle's accepted retention expiry. Add only the narrow crate-private `ValidatedFrozenBundle::retention_expires_unix()` accessor needed by result assembly.

- [ ] **Step 4: Verify review GREEN**

Run:

```bash
cargo test -p irlume-qualification result::tests::review_obeys_signed_result_lifetime -- --exact
cargo test -p irlume-qualification result::tests::review_obeys_signed_review_lifetime -- --exact
cargo test -p irlume-qualification result::tests::review_cannot_outlive_accepted_bundle_retention -- --exact
cargo test -p irlume-qualification result::tests
```

Expected: all pass.

- [ ] **Step 5: Add artifact lifetime RED tests**

Refactor private `bounded_expiry` to accept the values it must reconcile rather than reading globals:

```rust
fn bounded_expiry(
    protocol_expiry: u64,
    collection_not_after: u64,
    private_retention_seconds: u64,
    artifact_seconds: u64,
    qualified_at: u64,
) -> Result<u64, CampaignError>;
```

Before implementing it, add direct tests proving:

- one-second artifact lifetime returns `qualified_at + 1` when earliest;
- one-second private retention returns `collection_not_after + 1` when earliest;
- protocol expiry remains an independent cap;
- the framework one-year collection cap remains an independent cap;
- overflow in private, artifact, or framework addition returns `ArtifactCompileFailed`;
- expiry equal to or before review time returns `ArtifactCompileFailed`.

Use:

```rust
#[test]
fn compiler_expiry_obeys_every_signed_and_framework_limit()
```

- [ ] **Step 6: Run compiler expiry test and verify RED**

Run the exact test. Expected: compilation fails because `bounded_expiry` has the old three-argument interface.

- [ ] **Step 7: Implement minimal compiler expiry reconciliation**

Compute each checked limit and take the minimum:

```rust
let private_limit = collection_not_after
    .checked_add(private_retention_seconds)
    .ok_or(CampaignError::ArtifactCompileFailed)?;
let framework_limit = collection_not_after
    .checked_add(MAX_ARTIFACT_LIFETIME_SECONDS)
    .ok_or(CampaignError::ArtifactCompileFailed)?;
let artifact_limit = qualified_at
    .checked_add(artifact_seconds)
    .ok_or(CampaignError::ArtifactCompileFailed)?;
let expires_at = protocol_expiry
    .min(private_limit)
    .min(framework_limit)
    .min(artifact_limit);
```

Reject zero review time and non-live expiry as before. Pass retained policy values from `reviewed.protocol().limits()` in the private compiler.

- [ ] **Step 8: Verify compiler and camera GREEN**

Run:

```bash
cargo test -p irlume-qualification compiler::tests
cargo test -p irlume-qualification result::tests
cargo test -p irlume-camera --lib release_qualification::tests
```

The default fixture should retain its existing protocol-limited expiry. If the camera expected bytes change, first confirm the approved minimum calculation requires the change, then update only the exact literal expectation.

- [ ] **Step 9: Verify mutation sensitivity**

Temporarily omit `artifact_limit` from the minimum and confirm the one-second artifact test fails. Restore it. Temporarily omit the result deadline check and confirm the one-second result test fails. Restore it and rerun GREEN.

- [ ] **Step 10: Create a signed checkpoint only if explicitly authorized**

If authorized, stage `result.rs`, `compiler.rs`, and camera test only if changed:

```bash
git add crates/irlume-qualification/src/result.rs crates/irlume-qualification/src/compiler.rs
git add crates/irlume-camera/src/release_qualification.rs
git commit -SF35053398E3C80FE20891B82C10B8492BD7F30C6 --signoff -m "fix: enforce reviewed artifact lifetimes"
```

Omit the camera `git add` command when that file is unchanged. Verify the exact signature and DCO. Otherwise preserve the reviewed uncommitted checkpoint.

---

### Task 6: Close Documentation, Verification, And Re-Review

**Files:**
- Modify: `docs/superpowers/specs/2026-09-02-camera-profile-maintainer-qualification-campaign-design.md`
- Modify: `docs/superpowers/plans/2026-09-02-camera-profile-maintainer-qualification-contracts.md`
- Modify: `.superpowers/sdd/2026-09-01-layered-camera-profile-engine/task-8-maintainer-campaign-contracts-review.md`
- Modify: `.superpowers/sdd/2026-09-01-layered-camera-profile-engine/progress.md`
- Modify: `/home/wisbfime/archledger-gp/project-irlume.md`
- Modify: `/home/wisbfime/archledger-gp/index.md`

**Interfaces:**
- Consumes: completed five-finding remediation and all RED/GREEN evidence.
- Produces: authoritative supersession pointers, complete verification evidence, exact resumption state, and an independent remediation verdict.

- [ ] **Step 1: Add narrow supersession pointers**

In the original campaign design, add a short correction note linking the approved remediation design. In the original contracts plan, append a review-remediation section linking this plan and recording the five findings. Do not rewrite or delete completed historical task steps.

- [ ] **Step 2: Run focused qualification verification**

Run sequentially to avoid process-timeout contention:

```bash
cargo test -p irlume-qualification --all-targets
cargo test -p irlume-qualification --doc
cargo test -p irlume-camera --lib release_qualification::tests
cargo test -p irlume-camera --doc profile_qualification
```

Expected: all pass with zero ignored qualification tests.

- [ ] **Step 3: Run complete quality gates**

Run:

```bash
cargo check --workspace --locked
cargo clippy -p irlume-qualification -p irlume-camera --all-targets -- -D warnings
cargo fmt --all -- --check
git diff --check
```

Search changed files for U+2014, placeholders, private-field leakage vocabulary, new normal qualification dependencies, public constructors, and forbidden capabilities. Confirm no TFLite/NPU path changed.

- [ ] **Step 4: Inspect exact diff and authority surface**

Run:

```bash
git status --short --untracked-files=all
git diff --stat
git diff -- crates/irlume-qualification crates/irlume-camera docs/superpowers
cargo tree -p irlume-camera -e normal
cargo tree -p irlume-camera -e dev
```

Confirm only intended files changed, `irlume-qualification` remains absent from the normal camera graph, and no public function signature or schema field changed.

- [ ] **Step 5: Create one final signed+DCO fix commit only if explicitly authorized**

If earlier task commits were not authorized and the user now authorizes one atomic commit, inspect `git status`, `git diff`, and `git log --oneline -10`, then stage only intended source and tracked documentation. Commit with attached signing-key syntax:

```bash
git commit -SF35053398E3C80FE20891B82C10B8492BD7F30C6 --signoff -m "fix: enforce qualification campaign policy"
```

Never stage ignored SDD files or canonical Archledger files into the repository. Verify every included commit with `git verify-commit` and confirm the exact DCO trailer.

- [ ] **Step 6: Perform inline independent remediation review**

Review the exact remediation range against all five original findings. Re-run the four original adversarial reproductions plus the deterministic-order vector. Check one-hop callers, privacy projection, opaque construction, canonical parsing, signer roles, dependency isolation, arithmetic overflow, and deadline equality.

Append a `Remediation Review` section to the existing Task 8 report. Keep original findings append-only and mark each resolved only with exact code and test evidence. If any finding remains or a new one appears, retain REQUEST CHANGES.

- [ ] **Step 7: Refresh SDD and canonical handoffs**

Record exact branch, HEAD, divergence, changed paths, test counts, review verdict, external-state non-changes, rollback, lessons, and next action. Preserve the separate TFLite/NPU session's newer facts without editing or summarizing its technical evidence.

- [ ] **Step 8: Stop before Delivery Phase 4**

Even if the remediation re-review approves the software slice, stop. Delivery Phase 4, real campaign work, signing, publication, hardware, packaging, commissioning, writers, daemon integration, and production remain separate explicit gates.

## Execution Checkpoint

All five remediation tasks are implemented and inline re-reviewed in the
uncommitted working tree at base `eb7157cd3c12c10ff2f4726822513e6cfadaba4e`.
The qualification suite passes 96 tests with zero ignored; seven qualification
doctests, 14 camera compatibility tests, four camera authority doctests, locked
workspace check, warnings-denied two-crate Clippy, rustfmt, and diff hygiene all
pass. Required mutation checks detected each removed invariant and were fully
restored.

Policy version 1 requires `review_seconds <= result_seconds`, so a real signed
fixture cannot isolate a one-second result limit while keeping the review limit
longer. The result branch is therefore isolated at the private pure checked
deadline boundary, while review and accepted-retention tests exercise the full
verified aggregate-assembly path. A separate call-removal mutation proves the
real assembly path consumes the helper.

The append-only remediation verdict is recorded in
`.superpowers/sdd/2026-09-01-layered-camera-profile-engine/task-8-maintainer-campaign-contracts-review.md`.
No commit, reconciliation, remote action, external state change, or Delivery
Phase 4 work is authorized or performed.

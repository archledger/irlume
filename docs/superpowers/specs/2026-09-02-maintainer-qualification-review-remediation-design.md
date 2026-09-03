# Maintainer Qualification Review Remediation Design

**Status:** Implemented and inline re-reviewed; uncommitted

**Date:** 2026-09-02

**Applies to:** The maintainer qualification contracts through signed+DCO commit `eb7157cd3c12c10ff2f4726822513e6cfadaba4e`

**Review source:** `.superpowers/sdd/2026-09-01-layered-camera-profile-engine/task-8-maintainer-campaign-contracts-review.md`

This document supersedes only conflicting enforcement details in the approved maintainer qualification campaign design. All unrelated authority, statistical, privacy, lifecycle, and scope requirements remain unchanged.

## Purpose

This correction closes the two High, two Medium, and one Low findings from the independent full-slice review without widening the public qualification API or connecting the offline qualification crate to production.

The correction preserves the one-way authority chain:

`verified policy -> validated protocol -> validated lifecycle -> reduced result -> reviewed aggregate -> unsigned artifact`

Every limit remains derived from verified signed authority. No caller may supply a replacement cell floor, duration, deadline, sample population, or order assignment.

## Scope

The correction changes only the non-published `irlume-qualification` crate, its synthetic camera compatibility fixture when expected artifact expiry changes, the existing campaign design, the existing implementation plan, and their tests and reports.

It does not add a production camera dependency, evaluator adapter, vault, filesystem writer, release signer, publication path, package, daemon integration, real campaign, participant data, biometric access, hardware action, or production profile-selection behavior.

TFLite and NPU work is explicitly outside this correction and proceeds in a separate session and worktree.

## Decisions

### Retain validated policy limits inside protocol authority

`CampaignPolicy` produces one crate-private, immutable `CampaignPolicyLimits` value only after canonical parsing and detached-signature verification have succeeded. It contains:

```rust
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

The fields remain private. Narrow crate-private methods expose only the values needed by owning validators.

`ValidatedProtocol` retains `CampaignPolicyLimits` beside the verified protocol and policy digest. The value is not serialized, publicly constructible, or accepted from a caller. Cloning `ValidatedProtocol` preserves the exact limits inherited from the verified policy.

This approach is preferred over passing `Verified<CampaignPolicy>` through every public function because it preserves existing public signatures and prevents unrelated downstream modules from gaining the complete policy document. It is preferred over copying deadlines into `CampaignProtocol` because that would duplicate signed policy authority and change schema 1.

### Use phase-relative checked deadlines

Every duration uses checked `u64` addition. Overflow fails closed with the error owned by that transition.

The exact limits are:

```text
protocol_limit = protocol.created_at_unix + protocol_seconds
bundle_limit = protocol.collection_not_after_unix + bundle_seconds
private_retention_limit = protocol.collection_not_after_unix
    + private_asset_retention_seconds
result_limit = public_result.evaluated_at_unix + result_seconds
review_limit = public_result.evaluated_at_unix + review_seconds
artifact_limit = review_attestation.reviewed_at_unix + artifact_seconds
```

Authority must satisfy all applicable limits, not choose one:

- Protocol validation requires `expires_at_unix <= protocol_limit`.
- Collection eligibility requires `retention_expires_unix` to be no later than protocol expiry, `bundle_limit`, and `private_retention_limit`.
- Evaluation and publication eligibility preserve the exact accepted retention deadline and continue to reject use after it.
- Review assembly requires `reviewed_at_unix` to be no later than the protocol review deadline, protocol expiry, bundle retention deadline, `result_limit`, and `review_limit`.
- Artifact compilation sets `expires_at_unix` to the earliest of protocol expiry, `private_retention_limit`, `artifact_limit`, and the existing absolute one-year-after-collection framework ceiling.
- Artifact compilation rejects an expiry at or before the signed review time.

The signed policy may choose shorter limits than the framework ceilings. Framework ceilings remain defense in depth and never replace a stricter policy value.

`result_limit` and `review_limit` are independently checked even though policy version 1 requires `review_seconds <= result_seconds`. Keeping both checks binds behavior to both signed fields and prevents a later policy-validation change from silently making either field inert.

The existing public function signatures remain unchanged:

```rust
pub fn validate_collection_eligibility(
    protocol: &ValidatedProtocol,
    snapshot: Verified<EligibilitySnapshot>,
    now_unix: u64,
) -> Result<ValidatedCollectionEligibility, CampaignError>;

pub fn reduce_campaign(
    context: ReductionContext<'_>,
    cases: Vec<EvaluatedPairedCase>,
) -> Result<ReductionOutput, CampaignError>;

pub fn assemble_reviewed_aggregate(
    context: ReviewContext<'_>,
    public_result: Verified<PublicAggregateResult>,
    review: Option<Verified<ReviewAttestation>>,
) -> Result<ReviewedAggregate, CampaignError>;

pub fn compile_unsigned_release_artifact(
    reviewed: &ReviewedAggregate,
    release_signer: &SignerFingerprint,
) -> Result<UnsignedReleaseArtifact, CampaignError>;
```

### Use the statistical consumer's population for power authorization

The paired non-inferiority reducer uses only bona fide cases. Protocol power authorization must use that same population.

For each locked sample:

- An overall lock compares `required_cases` with the sum of planned baseline bona fide instances across all strata.
- A stratum lock compares `required_cases` with the sum of planned baseline bona fide instances carrying that exact stratum ID.
- Attack, no-face, non-mated, print, and display/replay counts never satisfy a bona fide power lock.
- Selection is by typed presentation and stratum values, never by first lexical match.
- Missing or insufficient bona fide population returns `CampaignError::ProtocolInvalid`.

The calculation sums all matching logical baseline cells. It does not depend on case ID order and remains correct if a later schema permits more than one bona fide logical cell per stratum.

Every count sum uses checked arithmetic. Overflow returns `CampaignError::ProtocolInvalid` before authority is minted.

### Enforce the policy floor against every emitted public cell

The public-cell floor follows the actual public projection rather than individual private case records.

Before `ValidatedProtocol` is created, planned counts must meet the signed floor for:

- each of the five public presentation-category totals;
- each of the four public security-category totals;
- the overall bona fide paired-gate population;
- every predeclared bona fide stratum paired-gate population.

The two security and category projections share the same attack totals, but both are listed to make the wire contract explicit. Counts use one baseline side per logical pair so paired cases are not double-counted.

Before reduction emits a result, realized authorized cases are checked against the same floor for every category and bona fide stratum. Existing exact completeness checks still require every planned instance exactly once. The reducer therefore provides defense in depth against future changes to bundle completeness or projection grouping.

A short planned cell returns `CampaignError::ProtocolInvalid`. A short realized cell returns `CampaignError::CohortIncomplete`. No short cell is suppressed, pooled into another category, merged across strata, or relabeled.

### Reject unavailable required model stages

All five stage outcomes for both baseline and candidate are required for every authorized campaign case in policy version 1:

- detection;
- recognition;
- liveness;
- RGB PAD;
- IR PAD.

`StageOutcome::NotApplicable` remains part of the closed wire vocabulary so malformed or unsupported evaluator output can be parsed safely, but `reduce_campaign` rejects it for any required case before tables, security results, latency results, transcripts, or public bytes are built.

The rejection remains `CampaignError::CaptureIncomplete`, matching the existing bona fide missingness behavior. `Incorrect` remains the only representation for model rejection, failure to acquire, timeout, missing required PAD evidence, or another model-relevant failure. It remains in the denominator.

### Derive balanced order from the signed seed

Order validation uses one fixed version-1 algorithm with no new dependency.

For each logical pair, compute:

```text
rank = SHA-256(
    UTF-8("irlume-campaign-order-v1")
    || 0x00
    || UTF-8(lowercase balanced_order_seed hex)
    || 0x00
    || UTF-8(logical_case_id)
)
```

Sort logical pairs by `(rank, logical_case_id)`. The logical-case-ID tie-break makes the result total even under a theoretical digest collision. Assign baseline first at even zero-based ranks and candidate first at odd ranks. The candidate receives the opposite position.

The existing requirement that baseline-first and candidate-first counts are equal remains. An odd number of logical pairs is therefore invalid. Validation computes expected positions from logical identity and the seed, independent of serialized case order or caller iteration order, and rejects any mismatch with `CampaignError::ProtocolInvalid`.

The signed case matrix remains explicit. The seed does not generate missing cases; it verifies that the predeclared explicit assignments follow the fixed algorithm.

## Opaque Authority Boundaries

No new public constructor or field is introduced.

- `CampaignPolicyLimits` is crate-private and field-private.
- `ValidatedProtocol` remains constructible only through `ValidatedProtocol::new`.
- Lifecycle authorities remain field-private and can only preserve limits already accepted from `ValidatedProtocol`.
- `ReviewedAggregate` continues to retain the exact `ValidatedProtocol` privately.
- The compiler continues to accept only `&ReviewedAggregate` and `&SignerFingerprint`.
- Camera code continues to depend on `irlume-qualification` only for tests.

Compile-fail authority proofs remain unchanged and must continue passing.

## Error Semantics

The correction uses existing fixed safe diagnostics:

- policy syntax or unsupported bounds: `PolicyUnsupported`;
- protocol duration, ordering, planned-cell, or locked-population mismatch: `ProtocolInvalid`;
- retention mismatch or expired eligibility: `ConsentIneligible`;
- short realized public cell: `CohortIncomplete`;
- any required `NotApplicable` outcome: `CaptureIncomplete`;
- stale result or review lifetime: `ReviewRejected`;
- overflow, non-live expiry, or impossible artifact lifetime: `ArtifactCompileFailed`.

No dynamic value, field name, participant fact, path, third-party text, or arithmetic detail enters a public diagnostic.

## Test Strategy

Implementation follows strict RED, GREEN, REFACTOR cycles. Each production correction begins only after its real-interface test fails for the reviewed defect.

### Policy lifetime tests

- One-second protocol lifetime rejects a later protocol expiry.
- One-second bundle lifetime rejects later retention even when protocol and framework limits permit it.
- One-second private-retention lifetime rejects later retention even when bundle lifetime permits it.
- One-second result lifetime rejects a review after the result limit.
- One-second review lifetime rejects a review after the review limit.
- One-second artifact lifetime produces exactly review time plus one second when it is the earliest limit.
- Every checked addition overflow fails with the owning fixed error.
- Equality at each maximum deadline passes; one second later fails.
- Artifact expiry equal to review time fails as non-live.

### Population and public-cell tests

- An attack pair sorting before a bona fide pair cannot satisfy a stratum lock.
- Large attack counts cannot satisfy overall or stratum bona fide locks.
- Multiple bona fide logical cells in one stratum sum deterministically if the current schema permits constructing them; otherwise the test remains at the helper boundary.
- Every category exactly at the public floor passes; one below fails.
- Every bona fide stratum exactly at the public floor passes; one below fails.
- Realized category and stratum counts are independently checked before public projection.
- Removing, duplicating, relabeling, or moving a case cannot improve authority.

### Missingness tests

- A table-driven matrix changes each of the ten baseline/candidate stage fields to `NotApplicable` for each of the five presentation classes.
- Every matrix entry returns `CaptureIncomplete` before result construction.
- The same fields set to `Incorrect` remain counted and reach the appropriate security or non-inferiority decision.

### Deterministic order tests

- Pinned logical IDs and seed produce exact expected ranks and positions.
- Reordering serialized input leaves expected assignments unchanged.
- Changing the seed changes the pinned assignment vector.
- Swapping one explicit position fails.
- Attack-case lexical precedence cannot influence the hash-ranked assignment.
- Odd logical-pair counts and unbalanced assignments fail.

### Regression gates

- All qualification unit tests and compile-fail doctests.
- Camera compiler compatibility and authority doctests.
- Locked workspace check.
- Warnings-denied Clippy for qualification and camera targets.
- Rustfmt and diff hygiene.
- Dependency, capability, privacy, signature, and DCO audits.
- Independent re-review of the fix range before any Delivery Phase 4 work.

## Alternatives Rejected

### Pass verified policy into every transition

This makes policy enforcement explicit but widens stable public signatures and lets downstream callers choose a policy argument that must then be reconciled repeatedly. Retaining validated limits in opaque protocol authority is smaller and harder to misuse.

### Add derived absolute deadlines to protocol schema 1

This would duplicate policy-derived authority, require fixture and consumer schema changes, and create disagreement cases between durations and absolute deadlines. Existing timestamps plus opaque validated limits are sufficient.

### Freeze policy version 1 to the current duration values

This would make unused dynamic fields harmless but contradicts the approved rule that shorter lifecycle windows are signed policy content. It would also hide rather than enforce the reviewed contract.

### Remove `NotApplicable` from the enum

Removing it narrows parseable input but creates unnecessary schema churn. Keeping it parseable and rejecting it at the policy-v1 reducer boundary preserves closed diagnostics and makes unsupported evidence fail explicitly.

### Keep only aggregate balance

Aggregate balance does not prove deterministic assignment and leaves the signed seed decorative. Hash ranking plus alternation provides an auditable, input-order-independent assignment with exact global balance.

## Completion Gate

The review verdict may change from REQUEST CHANGES only after:

1. all five findings have failing regression tests observed before production edits;
2. the minimal corrections pass focused and complete gates;
3. temporary mutations prove the tests detect their intended regressions;
4. any authorized fix commit is signed by the required maintainer key and carries the exact DCO trailer;
5. an independent review finds no remaining Critical, High, Medium, or Low defect in the remediation range.

Delivery Phase 4 and all real campaign, biometric, hardware, signing, publication, packaging, commissioning, writer, daemon, and production work remain separately unauthorized.

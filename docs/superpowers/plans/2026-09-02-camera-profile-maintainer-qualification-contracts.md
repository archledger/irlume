# Camera Profile Maintainer Qualification Contracts Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use
> superpowers:executing-plans to implement this plan task-by-task. The user
> prohibits subagents for this project, so execute inline with a fresh review
> checkpoint after every task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Implement the synthetic-only campaign contracts, fixed statistical
methods, reviewed aggregate authority, privacy-safe projection, and canonical
unsigned schema-1 artifact compiler from Delivery Phases 2 and 3.

**Architecture:** Add a non-published `irlume-qualification` workspace crate
whose deep interface accepts bounded canonical documents and categorical case
outcomes, then returns validated contracts, deterministic aggregate results, or
fixed safe failures. Keep it independent of camera, auth, enrollment, daemon,
and model crates. `irlume-camera` receives only a dev-dependency compatibility
test proving compiler bytes pass its existing private schema-1 parser; production
camera code gains no campaign dependency or writer.

**Tech Stack:** Rust 2021 with MSRV 1.88, Serde/serde_json, existing
`irlume_common::sha256_hex`, fixed IEEE-754 formulas quantized to integer parts
per billion, an explicit-path detached OpenPGP verifier, Cargo unit/property-style
enumeration/doctests, Clippy, rustfmt, Git signed commits, and DCO.

**Spec:** `docs/superpowers/specs/2026-09-02-camera-profile-maintainer-qualification-campaign-design.md`

## Global Constraints

- Work only in `/home/wisbfime/irlume/.worktrees/feat-layered-camera-profile-engine`
  on `feat/layered-camera-profile-engine`; do not reconcile, rebase, merge, push,
  or alter fetched remote `77fe8e7a4098dc50fcaa0d7764cd22848f704136`
  without separate authorization.
- Execute inline. Do not dispatch subagents.
- Use strict TDD. Observe the named RED failure before writing each behavior.
- This plan implements Delivery Phases 2 and 3 only. Synthetic vault,
  filesystem, and model evaluator adapters require a separate Delivery Phase 4
  plan and approval.
- Do not recruit, execute consent, create or mount a vault, access biometrics,
  open a camera, run models, read enrollment, authenticate, create a release key,
  sign or publish a real artifact, package, commission, wire a writer, call
  `ProfileSelectionStore::save`, or change daemon/service/production state.
- Every fixture is synthetic categorical data or generated non-biometric bytes.
  No identity, token-to-identity mapping, path, image, crop, tensor, template,
  embedding, model score, serial number, or third-party error text may enter a
  public result or release artifact.
- Every metadata document is closed, compact canonical JSON, at most 256 KiB,
  unknown-field rejecting, versioned, and content-addressed with lowercase
  SHA-256. Capture shards contain at most 128 paired cases, 32 assets per role
  per case, and 64 MiB per asset.
- One protocol binds one campaign ID, one policy digest, one exact identity-free
  hardware scope, and one exact baseline/candidate profile pair. Candidate
  output never supplies labels, exclusions, strata, or expected outcomes.
- Freeze confidence at one-sided 95 percent, alpha `0.05`, planned power at
  least 80 percent, overall non-inferiority margin `-0.02`, per-stratum margin
  `-0.05`, latency increase at 5 percent of the fixed budget, and 10,000
  participant/PAI-cluster bootstrap resamples.
- Use method IDs `paired_mover_wilson_v1`, `clopper_pearson_upper_v1`,
  `paired_power_normal_v1`, and `cluster_bootstrap_latency_v1`. Any formula,
  precision, rounding, seed, quantile, or boundary change requires a new method
  ID and policy version.
- Security direction tolerates zero candidate accepts. Any candidate accept,
  including a shared baseline/candidate accept, fails and blocks publication.
- Missing model-relevant evidence counts as an incorrect outcome. Only a
  protocol-listed pre-outcome equipment/provenance invalidation may repeat, and
  every attempt remains in the private transcript.
- Operator and reviewer full 40-character uppercase hexadecimal fingerprints
  must differ. Short IDs and trust-database status are not authority.
- The reviewed-envelope digest, not the bare public-result digest, becomes
  schema-1 `campaign_result_sha256`.
- Artifact qualification time is copied from the signed review timestamp.
  Expiry is no later than protocol expiry or one year after collection.
- Keep release signing, publication, packaging, local commissioning, and
  production selection outside this plan.
- Add no third-party dependency. Numerical and OpenPGP process behavior must be
  implemented from repository/standard-library facilities and pinned by tests.
- Every commit is GPG-signed and carries exactly
  `Signed-off-by: Wisbendji Fimerlus <archledger236@gmail.com>`.
- New and changed writing contains no U+2014.

## File Map

- Modify root `Cargo.toml`: add the non-published qualification crate and its
  workspace dependency; add no registry dependency.
- Create `crates/irlume-qualification/Cargo.toml`: depend only on
  `irlume-common`, Serde, and serde_json.
- Create `crates/irlume-qualification/src/lib.rs`: crate documentation, private
  module declarations, and the intentionally small public interface.
- Create `crates/irlume-qualification/src/canonical.rs`: validated identifiers,
  digests, fingerprints, fixed-point rates, bounded canonical JSON, document
  digesting, and fixed safe diagnostics.
- Create `crates/irlume-qualification/src/signature.rs`: role-bound detached
  signature verification, opaque `Verified<T>`, and explicit-path isolated GPG
  adapter with no signing capability.
- Create `crates/irlume-qualification/src/policy.rs`: closed campaign policy and
  exact version-1 method constants.
- Create `crates/irlume-qualification/src/protocol.rs`: exact-pair signed
  protocol, hardware/profile/model contracts, cohort/case plans, ordering seed,
  pilot discordance, and locked sample sizes.
- Create `crates/irlume-qualification/src/lifecycle.rs`: phase-linked consent
  eligibility snapshots, capture shards, bundle index, repeat histories, and
  deletion records.
- Create `crates/irlume-qualification/src/statistics.rs`: MOVER-Wilson lower
  bounds, one-sided Clopper-Pearson upper bounds, paired power/sample size,
  deterministic clustered latency bootstrap, and intersection decisions.
- Create `crates/irlume-qualification/src/result.rs`: categorical transcript
  input, deterministic private transcript, aggregate-only public result, review
  attestation, and reviewed envelope.
- Create `crates/irlume-qualification/src/reducer.rs`: one pure reduction and
  projection interface; no file, model, clock, process, or key access.
- Create `crates/irlume-qualification/src/compiler.rs`: pure schema-1 unsigned
  artifact compiler consuming only a verified reviewed aggregate and exact
  target contract.
- Modify `crates/irlume-camera/Cargo.toml`: add `irlume-qualification` as a
  dev-dependency only.
- Modify `crates/irlume-camera/src/release_qualification.rs`: add only an
  in-module compatibility test; do not alter production visibility or parsing.
- Update ignored SDD progress and create an ignored implementer report after
  each implementation task; never force-add ignored SDD files.

---

### Task 1: Establish Canonical Documents And Signature Authority

**Files:**
- Modify: `Cargo.toml:5-18,56-80`
- Create: `crates/irlume-qualification/Cargo.toml`
- Create: `crates/irlume-qualification/src/lib.rs`
- Create: `crates/irlume-qualification/src/canonical.rs`
- Create: `crates/irlume-qualification/src/signature.rs`
- Test: the two new source modules and crate rustdoc

**Interfaces:**
- Consumes: `irlume_common::sha256_hex`, canonical JSON bytes, detached OpenPGP
  bytes, trusted public-key bytes, explicit verifier path, expected signer role,
  and expected full fingerprint.
- Produces: `Identifier`, `Sha256Digest`, `SignerFingerprint`, `RatePpb`,
  `SignedRateDifferencePpb`, `SignerRole`, `SignatureMetadata`,
  `CanonicalDocument`, opaque `Verified<T>`, `DetachedSignatureVerifier`,
  `GpgDetachedSignatureVerifier`, `CampaignDiagnostic`, and `CampaignError`.

- [ ] **Step 1: Scaffold the crate and write failing canonical-boundary tests**

Add the workspace member and dependency:

```toml
members = [
    "crates/irlume-common",
    "crates/irlume-qualification",
    "crates/irlume-camera",
    "crates/irlume-vision",
    "crates/irlume-liveness",
    "crates/irlume-core",
    "crates/irlume-kwallet-init",
    "crates/irlume-gkr-unlock",
    "crates/irlume-auth",
    "crates/irlume-fingerprint",
    "crates/irlume-daemon",
    "crates/irlume-pam",
    "crates/irlume-cli",
]

[workspace.dependencies]
irlume-qualification = { path = "crates/irlume-qualification" }
```

Create the crate manifest:

```toml
[package]
name = "irlume-qualification"
version.workspace = true
edition.workspace = true
rust-version.workspace = true
license.workspace = true
publish = false

[dependencies]
irlume-common.workspace = true
serde.workspace = true
serde_json.workspace = true

[lints]
workspace = true
```

Write tests that require these exact constructors and limits:

```rust
#[test]
fn authority_atoms_reject_noncanonical_input() {
    assert!(Identifier::new("").is_err());
    assert!(Identifier::new(&"x".repeat(257)).is_err());
    assert!(Identifier::new("line\nbreak").is_err());
    assert!(Sha256Digest::new(&"ab".repeat(32)).is_ok());
    assert!(Sha256Digest::new(&"AB".repeat(32)).is_err());
    assert!(SignerFingerprint::new(
        "F35053398E3C80FE20891B82C10B8492BD7F30C6"
    ).is_ok());
    assert!(SignerFingerprint::new("2BD7F30C6").is_err());
    assert!(RatePpb::new(1_000_000_001).is_err());
    assert!(SignedRateDifferencePpb::new(-1_000_000_001).is_err());
}
```

- [ ] **Step 2: Run the focused test and verify RED**

Run: `cargo test -p irlume-qualification canonical::tests::authority_atoms`

Expected: compilation FAIL because the validated types do not exist.

- [ ] **Step 3: Implement the validated atoms and document contract**

Use private fields and fallible constructors. `Identifier` permits 1 through
256 UTF-8 bytes with no control characters. Digests are exactly 64 lowercase
hexadecimal characters. Fingerprints are exactly 40 uppercase hexadecimal
characters. Rates use integer parts per billion:

```rust
pub const RATE_SCALE_PPB: u64 = 1_000_000_000;
pub const MAX_CAMPAIGN_DOCUMENT_BYTES: usize = 256 * 1024;
pub const MAX_DETACHED_SIGNATURE_BYTES: usize = 64 * 1024;

#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct Identifier(String);

#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct Sha256Digest(String);

#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct SignerFingerprint(String);

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct RatePpb(u64);

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct SignedRateDifferencePpb(i64);
```

Expose `as_str()` or `get()` only. Implement Serde through validated wire
conversion so deserialization cannot bypass constructors.

Define a sealed document trait implemented only by campaign document types:

```rust
pub trait CanonicalDocument: private::Sealed + Sized {
    fn from_canonical_json(bytes: &[u8]) -> Result<Self, CampaignError>;
    fn to_canonical_json(&self) -> Result<Vec<u8>, CampaignError>;
    fn digest(&self) -> Result<Sha256Digest, CampaignError>;
    fn signature_metadata(&self) -> &SignatureMetadata;
}
```

Every parser rejects bytes over 256 KiB before Serde, validates every nested
field, serializes compactly, and requires byte equality. Pretty, reordered,
duplicate-key, trailing-data, unknown-field, NaN/infinite, and unsupported enum
input fails as `CampaignError::CanonicalInvalid` without retaining Serde text.

- [ ] **Step 4: Write failing signature-role and GPG isolation tests**

Define the closed role vocabulary:

```rust
pub enum SignerRole {
    PolicyAuthor,
    ProtocolAuthor,
    Operator,
    Evaluator,
    Reviewer,
}

pub enum SignatureAlgorithm { OpenPgp }

pub struct SignatureMetadata {
    algorithm: SignatureAlgorithm,
    role: SignerRole,
    signer_fingerprint: SignerFingerprint,
}
```

Tests must prove an invalid signature, short fingerprint, wrong role, unexpected
full fingerprint, metadata/verifier mismatch, empty signature, oversized
signature, malformed status, multiple `VALIDSIG` records, timeout, and nonzero
process exit all fail. A synthetic status line succeeds only when its primary
fingerprint exactly equals metadata and expectation.

- [ ] **Step 5: Run signature tests and verify RED**

Run: `cargo test -p irlume-qualification signature::tests`

Expected: compilation FAIL because verification interfaces do not exist.

- [ ] **Step 6: Implement opaque verification and the isolated GPG adapter**

Use this exact seam:

```rust
pub trait DetachedSignatureVerifier {
    fn verify(
        &self,
        canonical_payload: &[u8],
        detached_signature: &[u8],
    ) -> Result<SignerFingerprint, CampaignError>;
}

pub struct Verified<T> {
    document: T,
    digest: Sha256Digest,
    signer: SignerFingerprint,
}

pub fn verify_document<T: CanonicalDocument>(
    canonical_payload: &[u8],
    detached_signature: &[u8],
    expected_role: SignerRole,
    expected_signer: &SignerFingerprint,
    verifier: &impl DetachedSignatureVerifier,
) -> Result<Verified<T>, CampaignError>;
```

`Verified<T>` has no public constructor and exposes read-only `document()`,
`digest()`, and `signer()` accessors. Verification checks byte/signature bounds,
cryptographic result, exact expected fingerprint, exact metadata fingerprint,
and exact role before parsing returns authority.

`GpgDetachedSignatureVerifier::new(executable_path, trusted_key_bytes)` rejects
relative/empty executable paths and empty or over-256-KiB keys. Each call creates
an owner-only temporary GNUPG home beneath a caller-supplied or system temporary
root, writes payload/signature/key with mode `0600`, and invokes the explicit
binary directly without a shell. Its argument vector contains `--batch`,
`--no-tty`, `--homedir`, the allocated GNUPG-home path, and `--status-fd 1`;
imports only the supplied key, then verifies. Parse exactly one `[GNUPG:]
VALIDSIG` record. Validate both its signing-key and final primary-key fingerprint
fields as full 40-character uppercase hexadecimal; use the final primary-key
fingerprint as role authority and reject a missing or second record. Ignore trust
status. Bound stdout/stderr to 64 KiB, enforce a 10-second timeout, kill/reap on
timeout, and remove the entire temporary root through an RAII guard. Expose no
signing method.

- [ ] **Step 7: Add fixed safe diagnostics and run GREEN**

Define exactly these public categories:

```rust
pub enum CampaignDiagnostic {
    PolicyUnsupported,
    ProtocolInvalid,
    ConsentIneligible,
    CohortIncomplete,
    BundleUnsafe,
    CaptureIncomplete,
    ProvenanceMismatch,
    EvaluatorDrift,
    SecurityGateFailed,
    NoninferiorityFailed,
    LatencyFailed,
    ReviewMissing,
    ReviewRejected,
    ArtifactCompileFailed,
}
```

`CampaignError::diagnostic()` maps every internal variant to one category.
`Display` emits only the 14 exact snake-case strings from the spec. Table-test
that no rendering contains `/`, `\\`, `gpg:`, token values, IDs, paths, or raw
Serde/process text.

Run: `cargo test -p irlume-qualification canonical::tests signature::tests`

Expected: PASS.

Run: `cargo clippy -p irlume-qualification --all-targets -- -D warnings`

Expected: PASS.

- [ ] **Step 8: Format, inspect, and commit**

Run: `cargo fmt --all -- --check`

Run: `git diff --check`

Inspect `git status`, `git diff`, and `git log --oneline -10`, then stage only:

```bash
git add Cargo.toml Cargo.lock crates/irlume-qualification/Cargo.toml crates/irlume-qualification/src/lib.rs crates/irlume-qualification/src/canonical.rs crates/irlume-qualification/src/signature.rs
git commit -S -s -m "feat: establish qualification document authority"
```

Expected: one signed+DCO commit; `Cargo.lock` changes only for the new local
workspace package.

---

### Task 2: Define Policy And Exact-Pair Protocol Contracts

**Files:**
- Create: `crates/irlume-qualification/src/policy.rs`
- Create: `crates/irlume-qualification/src/protocol.rs`
- Modify: `crates/irlume-qualification/src/lib.rs`
- Test: both new modules

**Interfaces:**
- Consumes: canonical validated atoms and verified policy/protocol signatures.
- Produces: `CampaignPolicy`, `CampaignProtocol`, `HardwareScope`,
  `ProfileContract`, `StratumPlan`, `CasePlan`, `PilotDiscordance`,
  `LockedSampleSize`, and `ValidatedProtocol::new`.

- [ ] **Step 1: Write failing policy tests**

The canonical policy fixture must declare schema/policy `1`, all required 2D
classes, demographic axes `age`, `gender`, `skin_tone`, operational axes,
paired crossover, fixed methods/margins/confidence/power/bootstrap count,
bounded repeats, expiry rules, one-year retention, minimum public cell size,
role separation, and invalidation rules. Tests mutate each frozen method field,
remove each required attack/gate/axis, set zero public cell size, exceed retention,
duplicate/reorder ordered IDs, and add an unknown field.

- [ ] **Step 2: Run policy tests and verify RED**

Run: `cargo test -p irlume-qualification policy::tests`

Expected: compilation FAIL because `CampaignPolicy` does not exist.

- [ ] **Step 3: Implement the closed policy and exact v1 constants**

Pin these constants in code and require exact equality during validation:

```rust
pub const CAMPAIGN_POLICY_SCHEMA_VERSION: u32 = 1;
pub const CAMPAIGN_POLICY_VERSION: u32 = 1;
pub const ONE_SIDED_ALPHA_PPB: u64 = 50_000_000;
pub const REQUIRED_POWER_PPB: u64 = 800_000_000;
pub const OVERALL_MARGIN_PPB: i64 = -20_000_000;
pub const STRATUM_MARGIN_PPB: i64 = -50_000_000;
pub const LATENCY_BUDGET_FRACTION_PPB: u64 = 50_000_000;
pub const LATENCY_BOOTSTRAP_RESAMPLES: u32 = 10_000;
pub const MAX_PRIVATE_RETENTION_SECONDS: u64 = 31_536_000;
pub const MAX_CAPTURE_SHARD_CASES: usize = 128;
pub const MAX_ASSETS_PER_ROLE_PER_CASE: usize = 32;
pub const MAX_ASSET_BYTES: u64 = 64 * 1024 * 1024;
```

Use closed enums for `ExpectedOutcome`, `PresentationClass`, `PaiSpecies`,
`BinaryGate`, `StratificationAxis`, `MissingnessRule`, and `WithdrawalRule`.
Required binary gates are detection, recognition, liveness, RGB PAD, and IR PAD.
Required security classes are no-face, non-mated live cross-identity, print, and
display/replay. Three-dimensional masks and active IR are explicit exclusions.

The policy's dynamic target-population, operational axes, category values,
minimum stratum counts, minimum public cell size, repeat cap, and expiry windows
remain signed policy content, but validation bounds them, sorts them
lexicographically, rejects duplicates, and never accepts caller overrides.

- [ ] **Step 4: Write failing exact-pair protocol tests**

Use these top-level contracts with private fields and read-only accessors:

```rust
pub struct CampaignProtocol {
    schema_version: u32,
    campaign_id: Identifier,
    policy_id: Identifier,
    policy_sha256: Sha256Digest,
    source_revision: Sha256Digest,
    evaluator_build_sha256: Sha256Digest,
    created_at_unix: u64,
    collection_not_before_unix: u64,
    collection_not_after_unix: u64,
    evaluation_not_after_unix: u64,
    review_not_after_unix: u64,
    expires_at_unix: u64,
    hardware_scope: HardwareScope,
    baseline: ProfileContract,
    candidate: ProfileContract,
    contracts: RuntimeContractDigests,
    operating_points: Vec<OperatingPoint>,
    strata: Vec<StratumPlan>,
    cases: Vec<CasePlan>,
    balanced_order_seed: Sha256Digest,
    pilot_discordance: Vec<PilotDiscordance>,
    locked_sample_sizes: Vec<LockedSampleSize>,
    equipment_invalidations: Vec<EquipmentInvalidation>,
    public_regression_evidence: Vec<PublicRegressionEvidence>,
    signature: SignatureMetadata,
}

pub struct ValidatedProtocol {
    protocol: Verified<CampaignProtocol>,
    policy_sha256: Sha256Digest,
}

impl ValidatedProtocol {
    pub fn new(
        policy: &Verified<CampaignPolicy>,
        protocol: Verified<CampaignProtocol>,
    ) -> Result<Self, CampaignError>;
}
```

Tests reject identical profiles, profile/stream role errors, non-reduced frame
intervals, another hardware class, policy mismatch, changed model/preprocessing/
conditioning/producer/threshold/software digests, candidate-derived expected
outcomes, duplicate/missing case matrix cells, unbalanced order, unknown PAI,
missing stratum, unlocked/underpowered sample size, optional stopping, an expiry
past policy limits, or the same protocol-author and operator fingerprint.
Each optional `PublicRegressionEvidence` binds a license identifier, source URL,
mirror identity, content digest, model-calibration result digest, and operating
point. It may be empty and can never satisfy or replace a private case or gate.

- [ ] **Step 5: Run protocol tests and verify RED**

Run: `cargo test -p irlume-qualification protocol::tests`

Expected: compilation FAIL because protocol contracts do not exist.

- [ ] **Step 6: Implement protocol reconstruction and parity validation**

Persist stream tuples with closed pixel-format/role fields and numerator/
denominator intervals. Reconstruct and validate exact requested/accepted RGB and
IR roles; reject normalization by requiring reduced interval parts to equal the
wire values. Do not import `irlume-camera`.

Require every case to bind a predeclared expected outcome, stratum, scene,
participant-or-PAI class, bounded collection block, logical reference relation,
and baseline/candidate order. Every logical case has exactly two profile sides
with opposite balanced positions. Protocol cases and strata are sorted by ID and
match locked sample sizes exactly. `ValidatedProtocol::new` compares every
policy-controlled field and recomputes planned power through Task 4's interface;
until Task 4 lands, keep the call behind a private function whose Task 2 test
fixture implements only exact structural/sample-size equality, then replace that
function in Task 4 in the same file without changing the public interface.

- [ ] **Step 7: Run GREEN, quality gates, and commit**

Run: `cargo test -p irlume-qualification policy::tests protocol::tests`

Run: `cargo clippy -p irlume-qualification --all-targets -- -D warnings`

Run: `cargo fmt --all -- --check`

Run: `git diff --check`

Expected: PASS.

```bash
git add crates/irlume-qualification/src/lib.rs crates/irlume-qualification/src/policy.rs crates/irlume-qualification/src/protocol.rs
git commit -S -s -m "feat: define qualification policies and protocols"
```

---

### Task 3: Define Eligibility, Bundle, And Deletion Lifecycles

**Files:**
- Create: `crates/irlume-qualification/src/lifecycle.rs`
- Modify: `crates/irlume-qualification/src/lib.rs`
- Test: `lifecycle.rs`

**Interfaces:**
- Consumes: `ValidatedProtocol`, three verified eligibility snapshots, signed
  capture shards, and a signed bundle index.
- Produces: `EligibilitySnapshot`, `CaptureShard`, `BundleIndex`,
  `ValidatedCollectionEligibility`, `ValidatedFrozenBundle`,
  `ValidatedEvaluationEligibility`, `ValidatedPublicationEligibility`, and
  `DeletionRecord`.

- [ ] **Step 1: Write failing three-phase consent-chain tests**

Use exact phases and statuses:

```rust
pub enum EligibilityPhase { Collection, Evaluation, Publication }
pub enum EligibilityStatus { Active, Expired, Withdrawn }

pub struct EligibilitySnapshot {
    schema_version: u32,
    phase: EligibilityPhase,
    protocol_sha256: Sha256Digest,
    purpose: Identifier,
    token_set_sha256: Sha256Digest,
    allowed_presentations: Vec<PresentationClass>,
    collection_opens_unix: u64,
    collection_closes_unix: u64,
    retention_expires_unix: u64,
    aggregate_publication_acknowledged: bool,
    publication_boundary_acknowledged: bool,
    registry_revision: u64,
    predecessor_sha256: Option<Sha256Digest>,
    statuses: Vec<TokenEligibility>,
    signature: SignatureMetadata,
}
```

Tests cover active, expired, missing, and withdrawn tokens; purpose/class/window
mismatch; disconnected predecessor/revision; changed token set; duplicate token;
real-identity-like fields rejected as unknown; collection with predecessor;
evaluation/publication without predecessor; and retention past one year.

- [ ] **Step 2: Run eligibility tests and verify RED**

Run: `cargo test -p irlume-qualification lifecycle::tests::eligibility_`

Expected: compilation FAIL because lifecycle contracts do not exist.

- [ ] **Step 3: Implement opaque phase transitions**

Provide only these constructors:

```rust
pub fn validate_collection_eligibility(
    protocol: &ValidatedProtocol,
    snapshot: Verified<EligibilitySnapshot>,
    now_unix: u64,
) -> Result<ValidatedCollectionEligibility, CampaignError>;

pub fn validate_evaluation_eligibility(
    bundle: &ValidatedFrozenBundle,
    snapshot: Verified<EligibilitySnapshot>,
    now_unix: u64,
) -> Result<ValidatedEvaluationEligibility, CampaignError>;

pub fn validate_publication_eligibility(
    evaluation: &ValidatedEvaluationEligibility,
    snapshot: Verified<EligibilitySnapshot>,
    now_unix: u64,
) -> Result<ValidatedPublicationEligibility, CampaignError>;
```

Each output has private fields and read-only digest/token-set accessors. The
publication object binds all three snapshot digests. No function permits phase
skipping or snapshot replacement.

- [ ] **Step 4: Write failing capture-shard and frozen-index tests**

Define `AssetDescriptor`, `AttemptRecord`, `CaseSideCapture`, `PairedCaseCapture`,
`CaptureShard`, and `BundleIndex`. Paths are relative slash-separated components,
never empty, `.`, `..`, absolute, backslash-containing, NUL-containing, or over
4096 bytes. Metadata validation rejects more than 128 paired cases per shard,
more than 32 assets per role/case, asset sizes over 64 MiB, duplicate paths/
digests/positions, extra/missing/reordered cases, wrong expected outcomes,
profile/provenance mismatch, non-pre-outcome repeats, repeat-cap overflow,
conditioning restoration uncertainty, and index/shard digest mismatch.

- [ ] **Step 5: Run bundle tests and verify RED**

Run: `cargo test -p irlume-qualification lifecycle::tests::bundle_`

Expected: compilation FAIL because bundle contracts do not exist.

- [ ] **Step 6: Implement metadata-only freeze validation**

Use this interface:

```rust
pub fn validate_frozen_bundle(
    protocol: &ValidatedProtocol,
    collection: &ValidatedCollectionEligibility,
    index: Verified<BundleIndex>,
    shards: Vec<Verified<CaptureShard>>,
) -> Result<ValidatedFrozenBundle, CampaignError>;
```

Require exact ordered digest lists and logical parity for every baseline/
candidate case. This task validates descriptors only; it does not open a path,
inspect an asset, mount a root, or claim read-only filesystem state. Those checks
belong to the separately approved vault/evaluator plan.

- [ ] **Step 7: Implement signed deletion records and lifecycle tests**

`DeletionRecord` contains only campaign digest, ordered affected asset digests,
`Withdrawal`, `Expiry`, or `CampaignInvalidated`, completion timestamp, reviewer
fingerprint, `Completed`, `Interrupted`, or `Failed`, and reviewer signature.
Only `Completed` closes retention. Interrupted/failed records return an
unresolved governance incident and block bundle reuse. Test pre-publication
withdrawal invalidation and post-publication deletion without aggregate
retraction.

- [ ] **Step 8: Run GREEN, quality gates, and commit**

Run: `cargo test -p irlume-qualification lifecycle::tests`

Run: `cargo clippy -p irlume-qualification --all-targets -- -D warnings`

Run: `cargo fmt --all -- --check`

Run: `git diff --check`

Expected: PASS.

```bash
git add crates/irlume-qualification/src/lib.rs crates/irlume-qualification/src/lifecycle.rs
git commit -S -s -m "feat: seal qualification campaign lifecycles"
```

---

### Task 4: Pin Paired Statistical And Latency Methods

**Files:**
- Create: `crates/irlume-qualification/src/statistics.rs`
- Modify: `crates/irlume-qualification/src/lib.rs`
- Modify: `crates/irlume-qualification/src/protocol.rs`
- Test: `statistics.rs` and protocol power checks

**Interfaces:**
- Consumes: paired 2 by 2 counts, attack accepts/denominators, pilot discordant
  probabilities, margins, clustered paired latencies, budget, and protocol seed.
- Produces: `PairedTable`, `MoverWilsonResult`, `ClopperPearsonUpper`,
  `PowerPlan`, `LatencyResult`, and `IntersectionDecision`.

- [ ] **Step 1: Write failing paired-bound and exact-security tests**

Define the table orientation once:

```rust
pub struct PairedTable {
    both_fail: u64,
    candidate_only_success: u64,
    baseline_only_success: u64,
    both_succeed: u64,
}

pub fn paired_mover_wilson_lower(
    table: PairedTable,
) -> Result<SignedRateDifferencePpb, CampaignError>;

pub fn clopper_pearson_upper(
    accepts: u64,
    trials: u64,
) -> Result<RatePpb, CampaignError>;
```

Add hand-computed vectors, all-zero/all-one marginals, zero denominator,
one-discordant-pair cases, exact margin equality (fails because lower bound must
exceed the margin), and every table with `n <= 24` to prove swap symmetry and
that adding a baseline-only success cannot improve the lower bound. Pin
Clopper-Pearson one-sided 95 percent values including `0/10 = 0.2588655509`,
`0/20 = 0.1391083407`, `1/20 = 0.2161061642`, and `20/20 = 1.0`, quantized to
nearest integer ppb with half values away from zero.

- [ ] **Step 2: Run statistical tests and verify RED**

Run: `cargo test -p irlume-qualification statistics::tests::paired_`

Expected: compilation FAIL because statistical functions do not exist.

- [ ] **Step 3: Implement the pinned formulas**

For candidate proportion `p_c`, baseline proportion `p_b`, difference
`d = p_c - p_b`, and one-sided normal quantile
`z = 1.6448536269514722`, compute each Wilson one-sided marginal interval with
`center = (p + z^2/(2n))/(1 + z^2/n)` and
`half = z*sqrt(p*(1-p)/n + z^2/(4n^2))/(1 + z^2/n)`. Estimate paired
correlation as
`rho = (p_both_succeed - p_b*p_c) /
sqrt(p_b*(1-p_b)*p_c*(1-p_c))`, clamp it to `[-1, 1]`, and use zero covariance
when either marginal variance is zero. Compute the lower bound:

```text
d - sqrt(max(0,
    (p_c - L_c)^2 + (U_b - p_b)^2
    - 2*rho*(p_c - L_c)*(U_b - p_b)))
```

Implement one-sided Clopper-Pearson as `1` when `x == n`, otherwise
`BetaInv(0.95; x + 1, n - x)`. Use 100 bisection steps, the repository's
Lanczos `ln_gamma` coefficients and Lentz continued fraction, and reject zero
denominators. Keep floating point private; quantize all outputs to integer ppb.

- [ ] **Step 4: Write failing power/sample-size tests**

Use:

```rust
pub struct PowerPlan {
    candidate_only_success_ppb: RatePpb,
    baseline_only_success_ppb: RatePpb,
    margin_ppb: RatePpb,
    alpha_ppb: RatePpb,
    target_power_ppb: RatePpb,
    minimum_pairs: u64,
}

pub fn minimum_paired_sample_size(
    candidate_only_success_ppb: RatePpb,
    baseline_only_success_ppb: RatePpb,
    margin_ppb: RatePpb,
) -> Result<PowerPlan, CampaignError>;
```

Pin the normal approximation:

```text
d = q01 - q10
v = q01 + q10 - d^2
power(n) = Phi((d + margin) * sqrt(n / v) - z_0.95)
```

Search the smallest positive `n` whose power is at least `0.80`; reject
`d + margin <= 0`, zero/invalid variance, probabilities whose sum exceeds one,
or `n > 10_000_000`. Implement `Phi` with the pinned Abramowitz-Stegun 7.1.26
polynomial and constants recorded beside the function. Tests independently
recompute the previous and selected `n` and prove selected passes while previous
fails.

- [ ] **Step 5: Implement power and replace protocol structural stub**

Replace Task 2's private structural-only sample-size function with
`minimum_paired_sample_size`. `ValidatedProtocol::new` requires each signed
overall and stratum locked count to equal or exceed the recomputed minimum and
rejects capture targets that stop before every locked count. Run:

`cargo test -p irlume-qualification protocol::tests statistics::tests::power_`

Expected: PASS.

- [ ] **Step 6: Write failing deterministic cluster-bootstrap tests**

Use exact integer microseconds:

```rust
pub struct ClusterLatency {
    cluster_id: Identifier,
    observations: Vec<PairedLatencyUs>,
}

pub struct PairedLatencyUs {
    baseline_us: u64,
    candidate_us: u64,
}

pub fn cluster_bootstrap_latency(
    clusters: &[ClusterLatency],
    budget_us: u64,
    seed: &Sha256Digest,
) -> Result<LatencyResult, CampaignError>;
```

Sort clusters by ID. Use SplitMix64 with the first eight seed digest bytes read
big-endian and unbiased rejection sampling for cluster indices. Each of 10,000
resamples draws the original cluster count with replacement, includes every
observation from selected clusters, computes baseline and candidate nearest-rank
p95 separately, and stores signed `candidate_p95 - baseline_p95`. Sort the 10,000
deltas and select nearest-rank 95 percent at index `ceil(0.95 * 10000) - 1`.
Overall p50/p95 also use nearest rank. Pass only when candidate p95 is within the
fixed budget and the upper increase is at most 5 percent of budget.

Tests pin byte-identical results across repeated calls, input-order independence,
seed sensitivity, cluster versus frame resampling distinction, empty cluster,
overflow, exact 5 percent equality pass, and one-microsecond-over failure.

- [ ] **Step 7: Run GREEN, quality gates, and commit**

Run: `cargo test -p irlume-qualification statistics::tests protocol::tests`

Run: `cargo clippy -p irlume-qualification --all-targets -- -D warnings`

Run: `cargo fmt --all -- --check`

Run: `git diff --check`

Expected: PASS.

```bash
git add crates/irlume-qualification/src/lib.rs crates/irlume-qualification/src/statistics.rs crates/irlume-qualification/src/protocol.rs
git commit -S -s -m "feat: pin paired qualification statistics"
```

---

### Task 5: Reduce Categorical Cases Into Private And Public Results

**Files:**
- Create: `crates/irlume-qualification/src/result.rs`
- Create: `crates/irlume-qualification/src/reducer.rs`
- Modify: `crates/irlume-qualification/src/lib.rs`
- Test: both new modules

**Interfaces:**
- Consumes: validated protocol/bundle/evaluation eligibility, exact evaluator
  provenance, and ordered `EvaluatedPairedCase` categorical outcomes.
- Produces: `ReductionOutput { private_transcript, public_result }`, with each
  result requiring evaluator-role detached verification before review.

- [ ] **Step 1: Write failing reducer and missingness tests**

Define closed outcomes, not scores:

```rust
pub enum StageOutcome { Success, Incorrect, NotApplicable }

pub struct ProfileCaseOutcome {
    detection: StageOutcome,
    recognition: StageOutcome,
    liveness: StageOutcome,
    rgb_pad: StageOutcome,
    ir_pad: StageOutcome,
    authentication_accept: bool,
    latency_us: u64,
}

pub struct EvaluatedPairedCase {
    case_id: Identifier,
    stratum_ids: Vec<Identifier>,
    presentation: PresentationClass,
    expected: ExpectedOutcome,
    baseline: ProfileCaseOutcome,
    candidate: ProfileCaseOutcome,
    attempt_history_sha256: Sha256Digest,
}

pub fn reduce_campaign(
    context: ReductionContext<'_>,
    cases: Vec<EvaluatedPairedCase>,
) -> Result<ReductionOutput, CampaignError>;
```

Tests prove timeout/failure-to-acquire/missing PAD arrive as `Incorrect`, every
planned case appears exactly once, no outcome-known exclusion exists, reordering
input yields identical bytes, and removing/corrupting/failing evidence never
improves a disposition.

- [ ] **Step 2: Run reducer tests and verify RED**

Run: `cargo test -p irlume-qualification reducer::tests`

Expected: compilation FAIL because reducer/result types do not exist.

- [ ] **Step 3: Implement private transcript and public projection**

`PrivateTranscriptShard` contains at most 128 ordered cases with predecessor
digests, campaign tokens from the bundle, per-case categorical expected/actual
outcomes, bounded model decision values supplied by the future evaluator,
latencies, attempts, and strata/PAI memberships. `PrivateTranscriptIndex` binds
the ordered shard digests, exact reducer inputs, evaluation eligibility digest,
and output digest. Every shard and index is independently canonical and at most
256 KiB. They reject identity, consent-document, enrollment, grant, release-key,
absolute-path, and free-text fields structurally by having no such fields.

`PublicAggregateResult` contains exactly the fields listed in the spec:
predecessor/target contract digests; overall and predeclared-stratum
denominators; mated/non-mated/no-face/per-PAI counts and one-sided upper bounds;
five paired tables with MOVER-Wilson bounds/margins/dispositions overall and per
stratum; latency summaries/upper bound; provenance/completeness/security/
availability/latency dispositions; collection/evaluation bounds; explicit
`three_dimensional_masks` and `active_ir` exclusions; evaluator signature
metadata. It has no generic map, flattened extension, token, path, serial,
per-case, or free-text field.

- [ ] **Step 4: Implement all hard gates and intersection decision**

Fail security if candidate accepts any required security case. If both profiles
accept one security case, return `SecurityGateFailed` and retain only aggregate
counts. For bona fide gates, require every overall lower bound strictly greater
than `-0.02` and every stratum lower bound strictly greater than `-0.05`. Require
every locked denominator and minimum public cell size. Require latency pass.
All dispositions form an intersection: one failed component fails the public
result, and a failed result cannot be passed to review assembly.

- [ ] **Step 5: Add projection, category, and determinism tests**

Test one synthetic pass plus independent failure of every fixed category that
can arise before review/compilation. Serialize public bytes and reject any
occurrence of token fixtures or these field names: `identity`, `path`, `image`,
`crop`, `tensor`, `template`, `embedding`, `score`, `serial`, `consent`,
`per_case`, `error_text`. Run the same reduction twice and after input reorder;
private and public canonical bytes and digests must match exactly.

- [ ] **Step 6: Run GREEN, quality gates, and commit**

Run: `cargo test -p irlume-qualification result::tests reducer::tests`

Run: `cargo clippy -p irlume-qualification --all-targets -- -D warnings`

Run: `cargo fmt --all -- --check`

Run: `git diff --check`

Expected: PASS.

```bash
git add crates/irlume-qualification/src/lib.rs crates/irlume-qualification/src/result.rs crates/irlume-qualification/src/reducer.rs
git commit -S -s -m "feat: reduce qualification campaign outcomes"
```

---

### Task 6: Require Independent Review And Assemble Reviewed Authority

**Files:**
- Modify: `crates/irlume-qualification/src/result.rs`
- Modify: `crates/irlume-qualification/src/lib.rs`
- Test: `result.rs`

**Interfaces:**
- Consumes: verified passing public result, verified matching private transcript
  index, publication eligibility, exact policy/protocol/bundle/evaluator
  provenance, independently reproduced result digest, and an optional verified
  reviewer attestation whose absence is a fixed `ReviewMissing` failure.
- Produces: opaque `ReviewedAggregate` whose canonical envelope digest is the
  only campaign result digest accepted by Task 7.

- [ ] **Step 1: Write failing review-attestation tests**

Define exact checks and decision:

```rust
pub struct ReviewChecks {
    consent: bool,
    cohort: bool,
    cases: bool,
    attacks: bool,
    ordering: bool,
    provenance: bool,
    completeness: bool,
    statistics: bool,
    public_projection: bool,
    expiry: bool,
}

pub enum ReviewDecision { Passed, Rejected }

pub struct ReviewAttestation {
    schema_version: u32,
    policy_sha256: Sha256Digest,
    protocol_sha256: Sha256Digest,
    collection_eligibility_sha256: Sha256Digest,
    evaluation_eligibility_sha256: Sha256Digest,
    publication_eligibility_sha256: Sha256Digest,
    bundle_sha256: Sha256Digest,
    evaluator_build_sha256: Sha256Digest,
    transcript_sha256: Sha256Digest,
    public_result_sha256: Sha256Digest,
    source_revision: Sha256Digest,
    reproduced_public_result_sha256: Sha256Digest,
    checks: ReviewChecks,
    decision: ReviewDecision,
    operator_fingerprint: SignerFingerprint,
    reviewer_fingerprint: SignerFingerprint,
    reviewed_at_unix: u64,
    signature: SignatureMetadata,
}
```

Reject every digest mismatch, same operator/reviewer, non-reviewer signer role,
one false check, rejected decision, reproduced-result mismatch, review outside
protocol bounds, stale publication eligibility, and policy/protocol expiry.

- [ ] **Step 2: Run review tests and verify RED**

Run: `cargo test -p irlume-qualification result::tests::review_`

Expected: compilation FAIL because review contracts do not exist.

- [ ] **Step 3: Implement review validation and pure envelope assembly**

Use:

```rust
pub struct ReviewedAggregateEnvelope {
    schema_version: u32,
    campaign_id: Identifier,
    policy_sha256: Sha256Digest,
    protocol_sha256: Sha256Digest,
    public_result_sha256: Sha256Digest,
    review_attestation_sha256: Sha256Digest,
    evaluator_fingerprint: SignerFingerprint,
    reviewer_fingerprint: SignerFingerprint,
    reviewed_at_unix: u64,
}

pub struct ReviewedAggregate {
    envelope: ReviewedAggregateEnvelope,
    envelope_sha256: Sha256Digest,
    public_result: Verified<PublicAggregateResult>,
    review: Verified<ReviewAttestation>,
}

pub fn assemble_reviewed_aggregate(
    context: ReviewContext<'_>,
    public_result: Verified<PublicAggregateResult>,
    review: Option<Verified<ReviewAttestation>>,
) -> Result<ReviewedAggregate, CampaignError>;
```

The assembler takes no filesystem, vault, biometric, key, package, camera,
commissioning, or selection-store parameter. It copies review timestamp and
fingerprints exactly. It verifies all predecessor digests and signatures before
hashing canonical envelope bytes. `None` maps to `ReviewMissing`; a verified
rejected attestation maps to `ReviewRejected`. No missing or rejected object can
construct `ReviewedAggregate`.

- [ ] **Step 4: Add authority and tamper tests**

Add compile-fail rustdoc proving external code cannot construct `Verified<T>` or
`ReviewedAggregate` from fields. Mutate each envelope authority field and prove
digest change or rejection. Swap a valid public result, review, protocol,
publication snapshot, evaluator, operator, or reviewer and prove failure.

- [ ] **Step 5: Run GREEN, quality gates, and commit**

Run: `cargo test -p irlume-qualification result::tests`

Run: `cargo test -p irlume-qualification --doc`

Run: `cargo clippy -p irlume-qualification --all-targets -- -D warnings`

Run: `cargo fmt --all -- --check`

Run: `git diff --check`

Expected: PASS.

```bash
git add crates/irlume-qualification/src/lib.rs crates/irlume-qualification/src/result.rs
git commit -S -s -m "feat: require independent campaign review"
```

---

### Task 7: Compile Canonical Unsigned Schema-1 Artifact Bytes

**Files:**
- Modify: `crates/irlume-qualification/src/protocol.rs`
- Modify: `crates/irlume-qualification/src/result.rs`
- Create: `crates/irlume-qualification/src/compiler.rs`
- Modify: `crates/irlume-qualification/src/lib.rs`
- Modify: `crates/irlume-camera/Cargo.toml`
- Modify: `crates/irlume-camera/src/release_qualification.rs`
- Test: compiler module and camera private parser compatibility

**Interfaces:**
- Consumes: `ReviewedAggregate` retaining the exact validated signed protocol,
  its matching passing public result/review, and the intended allowlisted
  release signer fingerprint. No caller supplies target contracts.
- Produces: `UnsignedReleaseArtifact { canonical_bytes, artifact_sha256 }` only.
  It does not produce a detached signature or verified release evidence.

- [ ] **Step 1: Write failing upstream-authority correction tests**

In `protocol.rs`, change the synthetic protocol fixture's hardware scope to:

```rust
"hardware_scope": {
    "hardware_class": "usb-rgb-ir-v1",
    "interface_layout_sha256": digest("a"),
    "ir": {
        "backend": "v4l2-uvc",
        "descriptor_sha256": digest("b"),
        "driver": "uvcvideo",
        "interface_number": 2,
        "pid": 0x5678,
        "speed_millimbps": 5_000_000u64,
        "vid": 0x0bda
    },
    "match_policy_version": 1,
    "rgb": {
        "backend": "v4l2-uvc",
        "descriptor_sha256": digest("c"),
        "driver": "uvcvideo",
        "interface_number": 0,
        "pid": 0x5678,
        "speed_millimbps": 5_000_000u64,
        "vid": 0x0bda
    }
}
```

Add `protocol_binds_exact_identity_free_release_endpoint_scope`. Parse the
fixture successfully, then mutate each nested descriptor, VID, PID, interface,
driver, backend, and speed independently and assert the canonical protocol
digest changes. Also assert zero speed, equal RGB/IR descriptor digests, empty
driver/backend, and unknown endpoint fields return `ProtocolInvalid` or
`CanonicalInvalid` as appropriate. Assert serialized protocol bytes contain no
`serial`, `devpath`, `device_path`, or `relative_path` field.

In `result.rs`, update the compile-fail `ReviewedAggregate` literal with its
private `protocol` field. Add `reviewed_aggregate_retains_only_its_exact_validated_protocol`:

```rust
let reviewed = passing_reviewed_aggregate();
assert_eq!(
    reviewed.protocol().protocol_sha256(),
    reviewed.envelope().protocol_sha256()
);
```

Expose `protocol_sha256()` read-only on `ReviewedAggregateEnvelope`; keep
`ReviewedAggregate::protocol()` crate-private so no public API can substitute
protocol authority. Refactor the existing passing review setup into
`pub(crate) fn passing_reviewed_aggregate() -> ReviewedAggregate`, and make the
`#[cfg(test)]` result test module `pub(crate)` so compiler unit tests can reuse
only this fully validated test authority. This helper remains absent from normal
library builds.

- [ ] **Step 2: Run upstream-authority tests and verify RED**

Run: `cargo test -p irlume-qualification protocol::tests::protocol_binds_exact_identity_free_release_endpoint_scope`

Expected: FAIL because `HardwareEndpointScope` and nested endpoint parsing do
not exist.

Run: `cargo test -p irlume-qualification result::tests::reviewed_aggregate_retains_only_its_exact_validated_protocol`

Expected: FAIL because `ReviewedAggregate` does not retain `ValidatedProtocol`.

- [ ] **Step 3: Implement the minimal signed endpoint and retained-protocol authority**

Replace descriptor-only hardware fields with:

```rust
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct HardwareEndpointScope {
    backend: Identifier,
    descriptor_sha256: Sha256Digest,
    driver: Identifier,
    interface_number: u8,
    pid: u16,
    speed_millimbps: u64,
    vid: u16,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct HardwareScope {
    hardware_class: Identifier,
    interface_layout_sha256: Sha256Digest,
    ir: HardwareEndpointScope,
    match_policy_version: u32,
    rgb: HardwareEndpointScope,
}
```

`HardwareEndpointScope::validate` rejects zero speed. `HardwareScope::validate`
retains schema-1 match-policy equality and rejects equal RGB/IR descriptor
digests. Add crate-private read-only accessors for compiler projection: endpoint
backend, descriptor digest, driver, interface, PID, speed, VID; hardware
interface-layout digest, match-policy version, RGB, and IR; profile requested and
accepted tuples, schedule, runtime contracts; and stream format, dimensions,
interval, and role. Do not add camera imports or serial/path fields.

Clone `context.protocol` into `ReviewedAggregate.protocol` only in the successful
assembly branch, then add the crate-private getter. Keep envelope bytes and
envelope digest unchanged by this retained internal authority.

Run: `cargo test -p irlume-qualification protocol::tests`

Run: `cargo test -p irlume-qualification result::tests`

Expected: PASS.

- [ ] **Step 4: Write failing compiler projection tests**

Use this only public compiler interface:

```rust
pub fn compile_unsigned_release_artifact(
    reviewed: &ReviewedAggregate,
    release_signer: &SignerFingerprint,
) -> Result<UnsignedReleaseArtifact, CampaignError>;

pub struct UnsignedReleaseArtifact {
    canonical_bytes: Vec<u8>,
    artifact_sha256: Sha256Digest,
}
```

Provide read-only `canonical_bytes() -> &[u8]` and
`artifact_sha256() -> &Sha256Digest`; provide no constructor or mutable bytes.

Test exact projection of campaign ID, protocol digest, reviewed envelope digest,
hardware scope, baseline/candidate requested and accepted RGB/IR tuples,
schedules, conditioning catalog/selected policy, preprocessing/model contracts,
policy/producer versions, all passing gates, review timestamp, bounded expiry,
and OpenPGP release signer metadata. Assert
`campaign_result_sha256 == reviewed.envelope_sha256()` and
`qualified_at_unix == review.reviewed_at_unix()`.

- [ ] **Step 5: Run compiler tests and verify RED**

Run: `cargo test -p irlume-qualification compiler::tests`

Expected: compilation FAIL because compiler types do not exist.

- [ ] **Step 6: Implement a private schema-1 wire mirror and pure compiler**

Mirror the existing `irlume-camera` wire field order exactly:

```text
schema_version, policy_version, producer_version, campaign_id,
campaign_protocol_sha256, campaign_result_sha256, qualified_at_unix,
expires_at_unix, hardware_scope, baseline, candidate,
conditioning_catalog_sha256, selected_policy_sha256,
preprocessing_contract_sha256, model_contract_sha256, gates, signature
```

All six gate fields serialize as `passed`; failed/rejected reviewed input is
unconstructible. Expiry is the minimum of protocol expiry and collection end
plus 31,536,000 checked seconds. Reject zero/reversed/overflowing time and any
target field mismatch between retained protocol and public result. Before
projection, recompute the canonical protocol hardware, baseline profile, and
candidate profile digests and compare them with `hardware_scope_sha256`,
`baseline_profile_sha256`, and `candidate_profile_sha256`. Also compare policy,
protocol, collection bounds, conditioning catalog, selected policy,
preprocessing, model, producer, software, threshold, and source-revision facts.
Any mismatch, arithmetic overflow, invalid time, serialization, size, or
canonical round-trip failure maps to `ArtifactCompileFailed`. The release signer
is already a validated `SignerFingerprint`; the compiler does not reparse or
weaken that boundary.

Map qualification `PixelFormat` and `CaptureSchedule` exhaustively into private
wire enums. The endpoint wire declaration order is exactly
`descriptor_sha256, vid, pid, interface_number, driver, backend,
speed_millimbps`; profile order is exactly `profile_id, requested_rgb,
accepted_rgb, requested_ir, accepted_ir, schedule`. Serialize compactly, bound
to 256 KiB, parse back through the compiler's closed wire type, require byte
equality, then hash.

- [ ] **Step 7: Add target-mismatch, privacy, and opaque-output tests**

Extract a private `validate_target_bindings(&ValidatedProtocol,
&PublicAggregateResult)` so compiler unit tests can supply canonical synthetic
protocol/public documents without forging `ReviewedAggregate`. Independently
mutate every artifact target source listed in Step 6 and assert
`ArtifactCompileFailed`. Test review time zero, collection-end addition overflow,
and expiry at or before review time. Test the private closed wire parser directly
with bytes over 256 KiB, unknown fields, and noncanonical bytes.

Serialize compiler bytes and assert absence of the exact lifecycle token fixture
`"0".repeat(64)` and these forbidden field fragments:

```rust
[
    "identity", "participant", "token", "consent", "relative_path",
    "device_path", "devpath", "serial", "image", "crop", "tensor",
    "template", "embedding", "score", "third_party", "error_text",
]
```

Add compile-fail rustdoc proving external field construction and authority
promotion do not exist:

```rust
/// ```compile_fail
/// use irlume_qualification::UnsignedReleaseArtifact;
/// let _ = UnsignedReleaseArtifact {
///     canonical_bytes: b"{}".to_vec(),
///     artifact_sha256: todo!(),
/// };
/// ```
///
/// ```compile_fail
/// use irlume_qualification::UnsignedReleaseArtifact;
/// let unsigned: UnsignedReleaseArtifact = todo!();
/// let _verified = unsigned.into_verified_release_qualification();
/// ```
```

- [ ] **Step 8: Add camera parser compatibility as a dev-only seam**

Add to `crates/irlume-camera/Cargo.toml`:

```toml
[dev-dependencies]
irlume-qualification.workspace = true
```

Inside `release_qualification.rs`'s existing `#[cfg(test)] mod tests`, parse
canonical synthetic policy/protocol/lifecycle/result/review JSON through the
qualification crate's public interfaces using a camera-test-local
`FakeVerifier`, compile the resulting passing reviewed aggregate, then call private
`ReleaseQualificationArtifact::from_canonical_json(bytes)`. Assert campaign ID,
protocol digest, reviewed-envelope digest, review timestamp, expiry, profile IDs,
all target digests, and release signer fingerprint. Retain the camera parser's
existing nested profile/hardware mutation coverage; protocol/public target
mismatches belong to Step 7 before bytes exist. Do not change production module
visibility, constructors, or dependencies.

Keep all campaign fixture assembly in the camera test module. Do not add a
qualification test-fixture feature, public fixture constructor, checked-in
artifact bytes, or production dependency. Generate the 1,782 categorical
outcomes from the signed protocol's locked case counts, use only generated
non-biometric values, and mint each opaque authority through
`verify_document`, lifecycle validators, `reduce_campaign`, and
`assemble_reviewed_aggregate` before compilation.

Search Cargo manifests and metadata and confirm `irlume-camera` has no normal
dependency on `irlume-qualification`; only `[dev-dependencies]` may contain it.

- [ ] **Step 9: Run GREEN, quality gates, and commit**

Run: `cargo test -p irlume-qualification compiler::tests`

Run: `cargo test -p irlume-camera --lib release_qualification::tests`

Run: `cargo test -p irlume-qualification --doc`

Run: `cargo clippy -p irlume-qualification -p irlume-camera --all-targets -- -D warnings`

Run: `cargo fmt --all -- --check`

Run: `git diff --check`

Expected: PASS.

```bash
git add Cargo.lock crates/irlume-qualification/src/lib.rs crates/irlume-qualification/src/protocol.rs crates/irlume-qualification/src/result.rs crates/irlume-qualification/src/compiler.rs crates/irlume-camera/Cargo.toml crates/irlume-camera/src/release_qualification.rs
git commit -S -s -m "feat: compile reviewed qualification artifacts"
```

---

### Task 8: Prove The Software Authority Boundary And Stop

**Files:**
- Modify: `crates/irlume-qualification/src/lib.rs`
- Modify: `crates/irlume-qualification/src/lifecycle.rs`
- Modify: `crates/irlume-qualification/src/reducer.rs`
- Modify: `.superpowers/sdd/2026-09-01-layered-camera-profile-engine/progress.md`
- Create: `.superpowers/sdd/2026-09-01-layered-camera-profile-engine/task-8-maintainer-campaign-contracts-implementer.md`
- Test: complete qualification crate, camera compatibility, workspace checks

**Interfaces:**
- Consumes: Tasks 1 through 7.
- Produces: exhaustive synthetic authority proofs, signed implementation commit
  evidence, and an exact stop state before vault/evaluator or real campaign work.

- [ ] **Step 1: Add external authority compile-fail proofs**

Crate docs must prove external code cannot:

```rust
/// ```compile_fail
/// use irlume_qualification::{ReviewedAggregate, Verified};
/// let reviewed = ReviewedAggregate::new_for_test();
/// let verified = Verified::new_for_test(reviewed);
/// ```
///
/// ```compile_fail
/// use irlume_qualification::UnsignedReleaseArtifact;
/// let bytes = UnsignedReleaseArtifact::from_unreviewed_result(b"{}");
/// ```
```

The imports may succeed, but constructors must not exist. Keep document structs'
fields private and do not add test constructors outside `#[cfg(test)]`.

- [ ] **Step 2: Run authority doctests**

Run: `cargo test -p irlume-qualification --doc`

Expected: PASS because prohibited construction fails to compile.

- [ ] **Step 3: Complete exhaustive synthetic category and monotonicity matrices**

Retain the existing table that triggers each of the 14 `CampaignDiagnostic`
variants through `CampaignError::diagnostic`, the exhaustive paired 2 by 2 table
enumeration through denominator 24, every role collision, and every target
digest mismatch. Add the two missing real-interface matrices in their owning
modules: every inactive consent status at collection, evaluation, and
publication in `lifecycle.rs`, and every individual model gate failure in
`reducer.rs`. For each valid passing fixture, remove one case, fail one stage,
corrupt one digest, or advance one expiry and assert the verdict cannot improve.

This owning-module placement is an approved Task 8 scope correction. It avoids
duplicating the full signed protocol and lifecycle fixture in `lib.rs` merely to
reach private validated authority.

- [ ] **Step 4: Run the complete focused software suite**

Run: `cargo test -p irlume-qualification --all-targets`

Expected: every test PASS with no ignored real-data or hardware test in this
crate.

Run: `cargo test -p irlume-camera --lib release_qualification::tests`

Expected: PASS, including schema-1 compiler compatibility.

Run: `cargo test -p irlume-camera --doc profile_qualification`

Expected: PASS, preserving existing product authority isolation.

- [ ] **Step 5: Run workspace quality gates**

Run: `cargo check --workspace --locked`

Run: `cargo clippy -p irlume-qualification -p irlume-camera --all-targets -- -D warnings`

Run: `cargo fmt --all -- --check`

Run: `git diff --check`

Expected: PASS without model execution, camera access, or hardware tests.

- [ ] **Step 6: Audit forbidden capabilities and dependency direction**

Record exact searches proving:

- `irlume-qualification` has no dependency or source import for camera, auth,
  core, daemon, CLI, PAM, model, enrollment, commissioning, selection store,
  network, or production state;
- no normal dependency from `irlume-camera` to `irlume-qualification` exists;
- no call to `ProfileSelectionStore::save` was added;
- no source exposes signing, artifact publication, vault mounting, biometric
  reading, camera capture, authentication, enrollment, commissioning, package,
  daemon, or production writer capability;
- no fixture or serialized public output contains the prohibited names/values;
- tracked changes are limited to the new crate, root workspace declaration,
  camera dev-dependency/compatibility test, and this plan's implementation docs.

- [ ] **Step 7: Commit closure proofs**

Inspect `git status`, `git diff`, and `git log --oneline -10`, then stage only
tracked closure changes:

```bash
git add docs/superpowers/plans/2026-09-02-camera-profile-maintainer-qualification-contracts.md crates/irlume-qualification/src/lib.rs crates/irlume-qualification/src/lifecycle.rs crates/irlume-qualification/src/reducer.rs
git commit -S -s -m "test: prove campaign qualification authority"
```

Expected: one signed+DCO closure commit. Do not force-add ignored SDD files.

- [ ] **Step 8: Verify commits and refresh durable handoffs**

Run `git verify-commit` for all eight plan commits, verify exact fingerprint
`F35053398E3C80FE20891B82C10B8492BD7F30C6`, inspect the exact DCO trailer on
each, and confirm tracked status is clean. The ignored implementer report records
RED/GREEN evidence, test counts, formulas/reference vectors, all commit OIDs,
authority/dependency searches, external state, rollback, mistakes/near misses,
and exact resumption state. Refresh SDD progress, Archledger project handoff,
and its index row.

- [ ] **Step 9: Stop at independent review and the next separate plan gate**

Request independent review of the complete eight-commit software slice. Do not
start synthetic vault/filesystem/model evaluator implementation, design a real
campaign protocol, recruit, execute consent, create a vault, access biometrics,
run hardware, sign or publish an artifact, package, commission, wire a writer,
reconcile the divergent branch, or change production.

After acceptance, the next separately approved plan is Delivery Phase 4:
synthetic vault, descriptor-safe filesystem verification, and deterministic
evaluator adapters. Real campaign protocol design remains Delivery Phase 6 and
requires another explicit user gate.

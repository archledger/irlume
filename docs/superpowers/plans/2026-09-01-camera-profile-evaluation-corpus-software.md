# Camera Profile Evaluation Corpus Software Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking. The user prohibits subagents for this project, so execute inline with review checkpoints.

**Goal:** Replace the provisional combined evaluation manifest with bounded signed protocol, capture, and consent contracts plus a synthetic-only, identity-free owner-pilot reducer that cannot create profile-selection authority.

**Architecture:** Keep future profile-selection records in `profile_qualification.rs`, but move all schema-1 owner-pilot inputs into a new `profile_evaluation` boundary. Camera owns protocol, capture, consent, signature, and safe-asset validation; auth owns model-result comparison and the no-write pilot report. No schema-1 API converts a pilot report into `ProfileAuthGateEvidence` or writes `ProfileSelectionStore`.

**Tech Stack:** Rust 2021 workspace, Serde/serde_json, existing `irlume_common::sha256_hex`, Unix `openat`/`O_NOFOLLOW` through `libc`, GnuPG detached-signature verification through a bounded `std::process::Command` adapter, Cargo unit and all-target tests.

**Spec:** `docs/superpowers/specs/2026-09-01-camera-profile-evaluation-corpus-design.md`

## Global Constraints

- Work only in `/home/wisbfime/irlume/.worktrees/feat-layered-camera-profile-engine` on `feat/layered-camera-profile-engine`.
- Preserve unrelated worktree changes and the separate experiment and NPU worktrees.
- Use inline TDD with observed RED before implementation GREEN for every behavior change.
- Do not use subagents.
- Schema 1 is fixed to owner-pilot evidence and cannot mint, save, or replace profile-selection authority.
- Do not create or mount a vault, inspect or copy biometric assets, capture camera data, run hardware tests, read production enrollment, or change daemon/service/production state.
- All test assets are generated synthetic bytes under unique temporary directories and deleted by RAII cleanup.
- No raw paths, identities, consent contents, images, templates, embeddings, or scores may appear in share-safe result types.
- Protocol, capture, ledger, and signature documents remain bounded at 256 KiB each; cases remain bounded at 128 and assets at 32 per role per case.
- Asset files remain bounded at 2 MiB each and are opened component-by-component with `openat`, `O_NOFOLLOW`, and owner-only mode checks.
- Consent retention is at most 31,536,000 seconds and caller-supplied `now_unix` drives tests; do not read wall time inside validation.
- Detached-signature verification requires exact fingerprint `F35053398E3C80FE20891B82C10B8492BD7F30C6`; never accept a short key ID or trust status alone.
- Default test commands remain model-free. Use the established temporary model-link procedure only for the final all-target gate, verify all seven checksums first, and remove links afterward.
- Added repository text uses ASCII and no U+2014.

## File Structure

- `crates/irlume-camera/src/profile_qualification.rs`: future authority records, deterministic selection, and store only; no owner-pilot callback or combined corpus schema.
- `crates/irlume-camera/src/profile_evaluation.rs`: protocol, capture, consent, expected-outcome, digest, parity, and ledger-chain contracts.
- `crates/irlume-camera/src/profile_evaluation_signature.rs`: bounded canonical document loading and detached GPG verification.
- `crates/irlume-camera/src/profile_evaluation_assets.rs`: descriptor-relative, no-symlink asset opening and digest verification.
- `crates/irlume-camera/src/lib.rs`: exports the three evaluation modules.
- `crates/irlume-auth/src/profile_evaluation.rs`: aggregate-only observations, asymmetric owner-pilot acceptance, and identity-free report.
- `crates/irlume-auth/src/lib.rs`: exports the auth evaluation module and removes the provisional authority-producing reducer.
- `.superpowers/sdd/2026-09-01-layered-camera-profile-engine/task-7-implementer.md`: append-only implementation evidence after the software slice passes.

This plan deliberately excludes a real model replay engine, legacy-data import, vault creation, daemon command, camera collection, hardware qualification, and any writer. Those are separate later plans and user gates.

---

### Task 1: Preserve The Offline Authority Core Without A Pilot Authority Path

**Files:**
- Modify: `crates/irlume-camera/src/profile_qualification.rs:28-340,401-464,1321-1669,1830-1855`
- Modify: `crates/irlume-auth/src/lib.rs:49-128,8287-8318`
- Modify: `crates/irlume-camera/src/lib.rs:53-59`
- Test: `crates/irlume-camera/src/profile_qualification.rs`

**Interfaces:**
- Consumes: existing `ProfileQualificationAttempt`, `ProfileGateEvidence`, `ProfileSelectionRecord`, and `ProfileSelectionStore` from the dirty Task 7 worktree.
- Produces: the same future authority core, but no public `DiagnosticAuthAssessmentCallback`, no public `ProfileAuthGateEvidence` constructor, no `ProfileGateEvidence::assess_auth`, and no auth-side `aggregate_diagnostic_profile_cases`.

- [ ] **Step 1: Add a compile-fail visibility test and remove obsolete manifest tests from the expected test list**

Add this rustdoc to the public `ProfileGateEvidence` documentation so rustdoc
executes it while the example attempts to use the aggregate model-evidence type:

```rust
/// Aggregate model evidence is not constructible outside camera qualification.
///
/// ```compile_fail
/// use irlume_camera::profile_qualification::ProfileAuthGateEvidence;
/// let _ = ProfileAuthGateEvidence::new(
///     irlume_camera::profile_qualification::GateStatus::Passed,
///     irlume_camera::profile_qualification::GateStatus::Passed,
///     irlume_camera::profile_qualification::GateStatus::Passed,
///     irlume_camera::profile_qualification::GateStatus::Passed,
///     irlume_camera::profile_qualification::GateStatus::Passed,
/// );
/// ```
pub struct ProfileGateEvidence {
    negotiation: Option<GateStatus>,
    transport: Option<GateStatus>,
    lit: SceneGateEvidence,
    backlit: SceneGateEvidence,
    low_light: SceneGateEvidence,
    dark_ir: SceneGateEvidence,
    detection: Option<GateStatus>,
    recognition: Option<GateStatus>,
    liveness: Option<GateStatus>,
    rgb_pad: Option<GateStatus>,
    ir_pad: Option<GateStatus>,
    p50_latency_ms: Option<u64>,
    p95_latency_ms: Option<u64>,
    latency_budget_ms: Option<u64>,
}
```

Delete only the provisional `ProfileEvaluationManifest` fixture/tests and the auth reducer tests. Keep all selection, gate-completeness, context-drift, ranking, and store tests.

- [ ] **Step 2: Run the focused tests and verify RED**

Run: `cargo test -p irlume-camera --doc profile_qualification`

Expected: FAIL because `ProfileAuthGateEvidence` and its constructor are still public, so the `compile_fail` example compiles.

- [ ] **Step 3: Remove the owner-pilot authority path**

Make the evidence type and constructor crate-private. Delete the complete
`DiagnosticAuthAssessmentCallback` trait declaration and the complete
`ProfileGateEvidence::assess_auth` method; do not leave renamed wrappers.

Also remove `DiagnosticProfileCaseResult` and `aggregate_diagnostic_profile_cases` from `irlume-auth`. Keep `GateStatus` public because later report projection uses the closed status vocabulary, but do not expose a conversion from pilot results to `ProfileAuthGateEvidence`.

Remove the provisional combined-manifest types, constants, validators, and manifest-only error variants from `profile_qualification.rs`. Keep `QualificationScene` temporarily in this module until Task 2 moves it.

- [ ] **Step 4: Run the preserved authority tests and doctests**

Run: `cargo test -p irlume-camera --lib profile_qualification::tests`

Expected: PASS for gate completeness, deterministic selection, digest/context drift, sequential fallback, record parsing, CAS, ownership/mode, and symlink tests.

Run: `cargo test -p irlume-camera --doc profile_qualification`

Expected: PASS with the external constructor rejected at compile time.

Run: `cargo test -p irlume-auth diagnostic_profile_cases`

Expected: zero matching tests, proving the provisional reducer was removed rather than renamed.

- [ ] **Step 5: Run warnings and formatting gates**

Run: `cargo clippy -p irlume-camera -p irlume-auth --all-targets -- -D warnings`

Expected: PASS.

Run: `cargo fmt --all -- --check`

Expected: PASS.

- [ ] **Step 6: Commit the preserved authority core**

```bash
git add crates/irlume-camera/src/profile_qualification.rs crates/irlume-camera/src/capture_qualification.rs crates/irlume-camera/src/conditioning.rs crates/irlume-camera/src/lib.rs crates/irlume-camera/src/profile.rs crates/irlume-auth/src/lib.rs
git commit -S -s -m "feat: add offline camera profile qualification core"
```

Before committing, inspect `git status`, `git diff`, and `git log --oneline -10`; stage exactly the six listed source files and verify no combined manifest or public pilot callback remains.

---

### Task 2: Add The Signed Owner-Pilot Protocol Contract

**Files:**
- Create: `crates/irlume-camera/src/profile_evaluation.rs`
- Modify: `crates/irlume-camera/src/profile_qualification.rs:332-340,415-428,490-505`
- Modify: `crates/irlume-camera/src/profile.rs:272-292`
- Modify: `crates/irlume-camera/src/lib.rs:53-60`
- Test: `crates/irlume-camera/src/profile_evaluation.rs`

**Interfaces:**
- Consumes: `irlume_common::sha256_hex` and the existing four fixed qualification scenes.
- Produces: `ProfileEvaluationProtocolManifest::from_json(&[u8])`, `to_canonical_json()`, `to_pretty_json()`, `digest()`, `cases()`, `reference_sets()`, and closed protocol enums.

- [ ] **Step 1: Write failing protocol round-trip and semantic tests**

Create `profile_evaluation.rs` with test fixtures that use no biometric files:

```rust
#[test]
fn owner_pilot_protocol_roundtrips_with_explicit_no_face_na() {
    let protocol = ProfileEvaluationProtocolManifest::from_json(PROTOCOL_FIXTURE.as_bytes())
        .expect("valid protocol");
    assert_eq!(protocol.purpose(), ProfileEvaluationPurpose::OwnerPilot);
    assert_eq!(protocol.cases().len(), 48);
    let no_face = protocol.cases().iter()
        .find(|case| case.presentation() == EvaluationPresentation::NoFace)
        .unwrap();
    assert_eq!(no_face.expected().recognition(), ExpectedRecognition::NotApplicable);
    assert_eq!(
        ProfileEvaluationProtocolManifest::from_json(
            protocol.to_canonical_json().unwrap().as_bytes()
        ).unwrap(),
        protocol,
    );
}

#[test]
fn detection_absent_rejects_claimed_downstream_results() {
    let body = fixture_with_no_face_recognition("no_match");
    assert_eq!(
        ProfileEvaluationProtocolManifest::from_json(body.as_bytes()).unwrap_err(),
        ProfileEvaluationError::InvalidOutcomeCombination,
    );
}

#[test]
fn schema_one_rejects_authorizing_purpose_and_spoof_presentations() {
    assert!(matches!(
        ProfileEvaluationProtocolManifest::from_json(
            fixture_with_purpose("authorizing_cohort").as_bytes()
        ),
        Err(ProfileEvaluationError::Json(_)),
    ));
    assert!(matches!(
        ProfileEvaluationProtocolManifest::from_json(
            fixture_with_presentation("printed_photo").as_bytes()
        ),
        Err(ProfileEvaluationError::Json(_)),
    ));
}
```

The fixture contains one reference declaration and exactly six genuine plus six no-face cases for each of `lit`, `backlit`, `low_light`, and `dark_ir`.

- [ ] **Step 2: Run protocol tests and verify RED**

Run: `cargo test -p irlume-camera --lib profile_evaluation::tests::owner_pilot_protocol`

Expected: compilation FAIL because the module and protocol types do not exist.

- [ ] **Step 3: Implement the protocol types and bounds**

Define these exact public types:

```rust
pub const PROFILE_EVALUATION_PROTOCOL_SCHEMA_VERSION: u32 = 1;
pub const PROFILE_EVALUATION_ACCEPTANCE_POLICY_VERSION: u32 = 1;
pub const MAX_PROFILE_EVALUATION_DOCUMENT_BYTES: usize = 256 * 1024;
pub const MAX_PROFILE_EVALUATION_CASES: usize = 128;
pub const MAX_PROFILE_EVALUATION_REFERENCES: usize = 32;

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ProfileEvaluationPurpose { OwnerPilot }

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum QualificationScene { Lit, Backlit, LowLight, DarkIr }

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum EvaluationPresentation { GenuineLive, NoFace }

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ExpectedRecognition { Match, NoMatch, NotApplicable }

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ExpectedLiveness { Live, Spoof, NotApplicable }

#[derive(Clone, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum ProfileEvaluationError {
    Json(String),
    UnsupportedProtocolSchema(u32),
    UnsupportedCaptureSchema(u32),
    UnsupportedConsentSchema(u32),
    UnsupportedAcceptancePolicy(u32),
    DocumentTooLarge,
    InvalidId,
    InvalidDigest,
    InvalidPath,
    DuplicateId,
    ProtocolCaseCount,
    ProtocolReferenceCount,
    PilotMatrixMismatch,
    InvalidOutcomeCombination,
    MissingReference,
    CaptureAssetCount,
    DuplicateAsset,
    InvalidAsset,
    InvalidCaptureProfile,
    CaptureCaseMismatch,
    CaptureReferenceMismatch,
    CaptureAuthorityMismatch,
    IdenticalComparisonProfile,
    ConsentChainInvalid,
    ConsentRetentionExceeded,
    ConsentWithdrawn,
    ConsentExpired,
    ConsentMissing,
    ConsentPurposeMismatch,
    ConsentPresentationMismatch,
}
```

Keep detection and PAD closed enums from the provisional implementation, including PAD `NotApplicable`. Add private `validate()` methods and public read-only accessors. Move `QualificationScene` into shared `profile.rs` beside `ProfileGate`; import it from both evaluation and qualification so the future authority core does not depend on the owner-pilot schema module.

Implement `Display` without embedding document contents, paths, identities, or
Serde error source text in share-safe projections. Later tasks extend this same
enum only with the exact variants named in their steps.

Validation must enforce:

- schema and acceptance policy exactly 1;
- purpose exactly `OwnerPilot` through the enum;
- nonempty unique protocol, reference, case, and participant-token IDs, each at most 256 bytes with no controls;
- one reference set for every genuine participant token;
- no-face has no participant/reference and all downstream stages N/A;
- genuine has detection present, recognition match, liveness live, and both PAD roles genuine;
- exactly six cases for every scene/presentation pair, therefore exactly 48 cases;
- no unknown fields and canonical compact JSON at most 256 KiB.

- [ ] **Step 4: Add boundary and canonicalization tests**

Add focused tests for unsupported versions, unknown fields, empty/excessive/duplicate IDs, orphan references, duplicate matrix slots, five or seven attempts in one slot, invalid outcome combinations, deterministic digest, and pretty-to-canonical equivalence.

Run: `cargo test -p irlume-camera --lib profile_evaluation::tests`

Expected: PASS.

- [ ] **Step 5: Run camera quality gates**

Run: `cargo clippy -p irlume-camera --all-targets -- -D warnings`

Expected: PASS.

Run: `cargo fmt --all -- --check`

Expected: PASS.

- [ ] **Step 6: Commit the protocol contract**

```bash
git add crates/irlume-camera/src/profile_evaluation.rs crates/irlume-camera/src/profile_qualification.rs crates/irlume-camera/src/profile.rs crates/irlume-camera/src/lib.rs
git commit -S -s -m "feat: define owner pilot evaluation protocol"
```

---

### Task 3: Add Capture Manifests And Baseline/Candidate Parity

**Files:**
- Modify: `crates/irlume-camera/src/profile_evaluation.rs`
- Test: `crates/irlume-camera/src/profile_evaluation.rs`

**Interfaces:**
- Consumes: `ProfileEvaluationProtocolManifest`, `PairTransportProfile`, `CaptureSchedule`, `StreamTuple`, and `FrameInterval` accessors.
- Produces: `ProfileEvaluationCaptureManifest`, `EvaluationAsset`, `EvaluationReferenceCapture`, `EvaluationCaseCapture`, `CaptureProfileContract`, and `ValidatedCapturePair::new(...)`.

- [ ] **Step 1: Write failing capture and parity tests**

```rust
#[test]
fn capture_manifest_binds_exact_requested_and_accepted_tuples() {
    let protocol = protocol_fixture();
    let capture = capture_fixture(&protocol, "candidate-15", "aa");
    let profile = capture.profile().to_pair_transport_profile().unwrap();
    assert_eq!(profile.id(), "candidate-15");
    assert_eq!(profile.requested_rgb().interval().parts(), (1, 15));
    assert_eq!(profile.accepted_rgb().interval().parts(), (1, 15));
    assert_eq!(capture.protocol_digest(), protocol.digest().unwrap());
}

#[test]
fn capture_pair_requires_same_protocol_and_ordered_case_set() {
    let protocol = protocol_fixture();
    let baseline = capture_fixture(&protocol, "production-30-15", "aa");
    let mut candidate = capture_fixture(&protocol, "candidate-15-15", "bb");
    candidate.case_captures.swap(0, 1);
    assert_eq!(
        ValidatedCapturePair::new(&protocol, &baseline, &candidate).unwrap_err(),
        ProfileEvaluationError::CaptureCaseMismatch,
    );
}
```

- [ ] **Step 2: Run capture tests and verify RED**

Run: `cargo test -p irlume-camera --lib profile_evaluation::tests::capture_`

Expected: compilation FAIL because capture contracts do not exist.

- [ ] **Step 3: Implement serializable profile and asset contracts**

Do not derive `Deserialize` on `FrameInterval`, `StreamTuple`, or `PairTransportProfile`, because that would bypass constructor invariants. Define persisted wrappers that reconstruct through public constructors:

```rust
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct CaptureStreamContract {
    role: StreamRole,
    format: DecodedPixelFormat,
    width: u32,
    height: u32,
    interval_numerator: u32,
    interval_denominator: u32,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct CaptureProfileContract {
    profile_id: String,
    requested_rgb: CaptureStreamContract,
    accepted_rgb: CaptureStreamContract,
    requested_ir: CaptureStreamContract,
    accepted_ir: CaptureStreamContract,
    schedule: CaptureSchedule,
}
```

Add `Deserialize`/`Serialize` only to `DecodedPixelFormat` with
`#[serde(rename_all = "snake_case")]`. `CaptureProfileContract::to_pair_transport_profile()` must reconstruct every interval and stream through `FrameInterval::new`, `StreamTuple::new`, and the existing crate-private `PairTransportProfile::from_negotiated`; do not make that constructor public.

Define `ProfileEvaluationCaptureManifest` with exact fields from the spec: schema/capture IDs, protocol digest, profile, context/catalog/policy/model/preprocessing digests, producer/policy versions, nonzero start/end Unix seconds, reference captures, case captures, and canonical digest. Each `EvaluationAsset` has relative path, SHA-256, role, `ppm_rgb8` or `pgm_grey8`, width, height, and sequence position.

Provide bounded `from_json`, `to_canonical_json`, `to_pretty_json`, and `digest`
methods matching the protocol contract. Canonical bytes are compact struct-order
JSON and every deserialized value is revalidated.

Validation must reject empty/excessive assets, duplicate paths or sequence positions, role/media mismatch, dimensions that disagree with the accepted tuple, invalid lowercase SHA-256, invalid paths, zero/reversed timestamps, unsupported versions, and non-exact case/reference coverage.

- [ ] **Step 4: Implement A/B parity without authority conversion**

```rust
pub struct ValidatedCapturePair<'a> {
    protocol: &'a ProfileEvaluationProtocolManifest,
    baseline: &'a ProfileEvaluationCaptureManifest,
    candidate: &'a ProfileEvaluationCaptureManifest,
}

impl<'a> ValidatedCapturePair<'a> {
    pub fn new(
        protocol: &'a ProfileEvaluationProtocolManifest,
        baseline: &'a ProfileEvaluationCaptureManifest,
        candidate: &'a ProfileEvaluationCaptureManifest,
    ) -> Result<Self, ProfileEvaluationError>;
}
```

Require matching protocol digest, ordered case IDs, ordered reference IDs, model contract, preprocessing, catalog, producer, policy, and camera-context digest. Require different profile IDs or return `ProfileEvaluationError::IdenticalComparisonProfile`. Do not compare or normalize asset paths between profiles.

Expose read-only `protocol()`, `baseline()`, and `candidate()` accessors on
`ValidatedCapturePair`; do not expose a constructor that bypasses `new`.

- [ ] **Step 5: Run capture and protocol tests**

Run: `cargo test -p irlume-camera --lib profile_evaluation::tests`

Expected: PASS.

Run: `cargo clippy -p irlume-camera --all-targets -- -D warnings`

Expected: PASS.

- [ ] **Step 6: Commit capture contracts**

```bash
git add crates/irlume-camera/src/profile.rs crates/irlume-camera/src/profile_evaluation.rs
git commit -S -s -m "feat: bind profile evaluation captures"
```

---

### Task 4: Add Signed Consent-Ledger Revisions

**Files:**
- Modify: `crates/irlume-camera/src/profile_evaluation.rs`
- Test: `crates/irlume-camera/src/profile_evaluation.rs`

**Interfaces:**
- Consumes: participant tokens and presentations from `ProfileEvaluationProtocolManifest`.
- Produces: `ConsentLedgerRevision`, `ValidatedConsentLedger`, `validate_consent_chain(...)`, and `ValidatedConsentLedger::authorize_protocol(...)`.

- [ ] **Step 1: Write failing retention, chain, and authorization tests**

```rust
#[test]
fn active_owner_consent_authorizes_only_the_signed_pilot_protocol() {
    let protocol = protocol_fixture();
    let chain = vec![ledger_revision_fixture(1, None, false)];
    let ledger = validate_consent_chain(&chain, chain[0].digest().unwrap().as_str(), 1_800_000_000)
        .unwrap();
    assert!(ledger.authorize_protocol(&protocol).is_ok());
}

#[test]
fn withdrawn_or_over_year_consent_fails_before_assets() {
    let protocol = protocol_fixture();
    let withdrawn = vec![ledger_revision_fixture(1, None, true)];
    assert_eq!(
        validate_consent_chain(&withdrawn, withdrawn[0].digest().unwrap().as_str(), 1_800_000_000)
            .unwrap()
            .authorize_protocol(&protocol)
            .unwrap_err(),
        ProfileEvaluationError::ConsentWithdrawn,
    );
    assert_eq!(
        ConsentParticipant::new_for_test(0, 31_536_001).validate().unwrap_err(),
        ProfileEvaluationError::ConsentRetentionExceeded,
    );
}
```

- [ ] **Step 2: Run consent tests and verify RED**

Run: `cargo test -p irlume-camera --lib profile_evaluation::tests::consent_`

Expected: compilation FAIL because consent types do not exist.

- [ ] **Step 3: Implement bounded ledger revisions**

Define:

```rust
pub const PROFILE_CONSENT_LEDGER_SCHEMA_VERSION: u32 = 1;
pub const MAX_CONSENT_RETENTION_SECS: u64 = 31_536_000;
pub const MAX_CONSENT_PARTICIPANTS: usize = 32;

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ConsentLedgerRevision {
    schema_version: u32,
    revision: u64,
    previous_revision_digest: Option<String>,
    participants: Vec<ConsentParticipant>,
}
```

`ConsentParticipant` contains participant token, private display identity, receipt digest, relative receipt path, allowed purpose list, allowed presentation list, collection/expiry Unix seconds, optional withdrawal Unix seconds, and bounded referenced capture-manifest digests. Do not expose a display-identity accessor outside the module.

Provide bounded `from_json`, `to_canonical_json`, and `digest` methods on each
ledger revision; do not provide a pretty or share-safe ledger serializer because
the ledger contains PII.

`validate_consent_chain(revisions, expected_head_digest, now_unix)` must require revisions starting at 1, increasing exactly by one, exact previous-digest links, a matching explicit head digest, unique participant tokens, and valid collection/expiry/withdrawal chronology. It returns a `ValidatedConsentLedger` with only token and permission lookups exposed. `authorize_protocol` rejects referenced expired or withdrawn participants at the captured `now_unix`; unreferenced historical withdrawals do not invalidate the ledger chain. Task 5 verifies every detached signature before this pure chain validator is called.

- [ ] **Step 4: Add negative chain and PII-boundary tests**

Test missing revision, repeated revision, wrong previous digest, wrong explicit head, duplicate token, missing receipt digest, path traversal, purpose mismatch, presentation mismatch, expiry at exactly one year, expiry one second beyond, withdrawal before collection, and protocol token missing from ledger.

Serialize every public projection and assert it does not contain the synthetic private display identity or receipt path.

Run: `cargo test -p irlume-camera --lib profile_evaluation::tests::consent_`

Expected: PASS.

- [ ] **Step 5: Commit consent contracts**

```bash
git add crates/irlume-camera/src/profile_evaluation.rs
git commit -S -s -m "feat: validate profile evaluation consent"
```

---

### Task 5: Verify Bounded Canonical Documents And Detached Signatures

**Files:**
- Create: `crates/irlume-camera/src/profile_evaluation_signature.rs`
- Modify: `crates/irlume-camera/src/profile_evaluation.rs`
- Modify: `crates/irlume-camera/src/lib.rs:53-62`
- Test: `crates/irlume-camera/src/profile_evaluation_signature.rs`

**Interfaces:**
- Consumes: canonical protocol, capture, and ledger bytes plus detached signature bytes and a trusted public-key path.
- Produces: `DetachedSignatureVerifier`, `GpgDetachedSignatureVerifier`, `VerifiedSigner`, and bounded `verify_signed_protocol`, `verify_signed_capture`, and `verify_signed_ledger_revision` loaders.

- [ ] **Step 1: Write failing signer and tamper tests**

```rust
#[test]
fn valid_signature_requires_the_full_allowlisted_fingerprint() {
    let verifier = FakeVerifier::valid(PROFILE_EVALUATION_SIGNER_FINGERPRINT);
    let signed = verify_signed_bytes(b"canonical", b"signature", &verifier).unwrap();
    assert_eq!(signed.signer().fingerprint(), PROFILE_EVALUATION_SIGNER_FINGERPRINT);
}

#[test]
fn short_or_wrong_fingerprint_and_modified_payload_fail() {
    for fingerprint in ["BD7F30C6", "035053398E3C80FE20891B82C10B8492BD7F30C6"] {
        let verifier = FakeVerifier::valid(fingerprint);
        assert_eq!(
            verify_signed_bytes(b"canonical", b"signature", &verifier).unwrap_err(),
            ProfileEvaluationSignatureError::UntrustedSigner,
        );
    }
    assert!(verify_signed_bytes(
        b"modified", b"signature", &FakeVerifier::invalid_signature()
    ).is_err());
}
```

- [ ] **Step 2: Run signature tests and verify RED**

Run: `cargo test -p irlume-camera --lib profile_evaluation_signature::tests`

Expected: compilation FAIL because the module does not exist.

- [ ] **Step 3: Implement a verifier seam and exact status parser**

```rust
pub const PROFILE_EVALUATION_SIGNER_FINGERPRINT: &str =
    "F35053398E3C80FE20891B82C10B8492BD7F30C6";

pub trait DetachedSignatureVerifier {
    fn verify(
        &self,
        canonical_payload: &[u8],
        detached_signature: &[u8],
    ) -> Result<VerifiedSigner, ProfileEvaluationSignatureError>;
}

pub struct GpgDetachedSignatureVerifier {
    executable: PathBuf,
    trusted_public_key: PathBuf,
    timeout: Duration,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ProfileEvaluationSignatureError {
    Io,
    ProcessFailed,
    Timeout,
    StatusTooLarge,
    InvalidSignature,
    UntrustedSigner,
    NonCanonicalDocument,
}
```

The production adapter must:

- create a unique mode-0700 temporary GPG home;
- write only the detached signature and trusted public key into mode-0600 files there;
- pass the canonical payload to `gpg --verify <signature> -` over a piped stdin, never write payload bytes to temporary storage;
- invoke the configured executable directly with argument arrays, never a shell;
- clear inherited environment except fixed `LC_ALL=C`; use `--batch`, `--no-options`, `--no-tty`, `--no-autostart`, `--disable-dirmngr`, the isolated `--homedir`, and a mode-0600 `--status-file` inside that home;
- import only the supplied trusted public key, then verify the detached signature;
- poll `try_wait()` until a five-second deadline, kill and reap on timeout;
- write the at-most-256-KiB stdin payload from a scoped writer thread, close stdin, and join that thread after exit or kill so a child that stops reading cannot deadlock the timeout;
- read at most 64 KiB + 1 from the status file after the child exits and reject overflow;
- accept only successful exit plus one `VALIDSIG` status record whose fingerprint token is the exact full fingerprint; permit the documented trailing `VALIDSIG` fields but no second conflicting record;
- reject `GOODSIG` without `VALIDSIG`, short IDs, duplicate conflicting `VALIDSIG`, and any other fingerprint;
- remove the temporary home through RAII cleanup.

Expose the executable and trusted-key paths as constructor inputs. Read the trusted public key with `O_NOFOLLOW`, require a regular file, and cap it at 64 KiB before copying it into the isolated home. Do not fetch keys or consult a default user keyring.

- [ ] **Step 4: Add a fake executable integration test**

Generate a mode-0700 shell fixture under a unique test directory that records argv, consumes stdin, and writes exact status lines to the path supplied after `--status-file`. Test successful import/verify flow, nonzero exit, timeout while not reading stdin, oversized status, wrong fingerprint, and proof that the command receives paths as separate arguments even when the temporary root contains spaces. Assert the synthetic canonical payload does not appear in any temporary regular file after verification.

Run: `cargo test -p irlume-camera --lib profile_evaluation_signature::tests`

Expected: PASS without accessing a real keyring or network.

- [ ] **Step 5: Bind signatures to parsed canonical documents**

Add loaders that read at most 256 KiB payload plus 64 KiB signature, verify the exact bytes first, parse the relevant document, require `to_canonical_json()` bytes to equal the signed bytes, and return `(document, VerifiedSigner)`. Pretty JSON or semantically equivalent reordered JSON must fail canonical-byte equality.

For ledger chains, require a valid detached signature for every revision before calling `validate_consent_chain`.

- [ ] **Step 6: Run quality gates and commit**

Run: `cargo test -p irlume-camera --lib profile_evaluation_signature::tests`

Expected: PASS.

Run: `cargo test -p irlume-camera --lib profile_evaluation::tests`

Expected: PASS.

Run: `cargo clippy -p irlume-camera --all-targets -- -D warnings`

Expected: PASS.

```bash
git add crates/irlume-camera/src/profile_evaluation_signature.rs crates/irlume-camera/src/profile_evaluation.rs crates/irlume-camera/src/lib.rs
git commit -S -s -m "feat: verify profile evaluation signatures"
```

---

### Task 6: Verify Assets Beneath A Read-Only Synthetic Root

**Files:**
- Create: `crates/irlume-camera/src/profile_evaluation_assets.rs`
- Modify: `crates/irlume-camera/src/lib.rs:53-63`
- Test: `crates/irlume-camera/src/profile_evaluation_assets.rs`

**Interfaces:**
- Consumes: `EvaluationAsset` descriptors from a validated capture manifest.
- Produces: `VerifiedEvaluationAsset::open(root, descriptor)`, `VerifiedCaseAssets::open(root, capture, case_id)`, and `VerifiedReferenceAssets::open(root, capture, reference_id)` holding only one verified bounded asset sequence at a time.

- [ ] **Step 1: Write failing safe-open tests with generated bytes**

```rust
#[test]
fn verified_asset_opens_nested_regular_file_by_descriptor() {
    let root = SyntheticRoot::new();
    let bytes = synthetic_pgm(2, 2, 7);
    root.write_private("cases/lit/ir-000.pgm", &bytes);
    let descriptor = asset_descriptor("cases/lit/ir-000.pgm", &bytes);
    let verified = VerifiedEvaluationAsset::open(root.path(), &descriptor).unwrap();
    assert_eq!(verified.bytes(), bytes);
}

#[cfg(unix)]
#[test]
fn verified_asset_refuses_intermediate_and_final_symlinks() {
    let root = SyntheticRoot::new();
    root.write_private("outside.pgm", &synthetic_pgm(1, 1, 1));
    root.symlink_dir("cases", root.path());
    assert_eq!(
        VerifiedEvaluationAsset::open(
            root.path(),
            &asset_descriptor_for_path("cases/outside.pgm")
        ).unwrap_err(),
        ProfileEvaluationAssetError::UnsafePath,
    );
}
```

- [ ] **Step 2: Run asset tests and verify RED**

Run: `cargo test -p irlume-camera --lib profile_evaluation_assets::tests`

Expected: compilation FAIL because the module does not exist.

- [ ] **Step 3: Implement descriptor-relative `openat` traversal**

Define:

```rust
pub const MAX_PROFILE_EVALUATION_ASSET_BYTES: usize = 2 * 1024 * 1024;

pub struct VerifiedEvaluationAsset {
    role: StreamRole,
    media: EvaluationAssetMedia,
    width: u32,
    height: u32,
    sequence: u16,
    bytes: Vec<u8>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ProfileEvaluationAssetError {
    UnsupportedPlatform,
    UnsafeRoot,
    UnsafePath,
    UnsafeOwnershipOrMode,
    NotRegularFile,
    TooLarge,
    DigestMismatch,
    Io,
}
```

On Unix, open the root with `O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW`. Walk every already-validated relative component with `openat`: intermediate components use `O_DIRECTORY | O_NOFOLLOW`; the final component uses `O_RDONLY | O_NOFOLLOW`. Check every opened directory/file is owned by `geteuid()` and has no group/other permission bits. Require the final descriptor to be a regular file, read at most 2 MiB + 1, and compare exact lowercase SHA-256 before returning bytes.

Do not use `canonicalize`, join-and-open, or reopen a path after verification. On non-Unix targets return `UnsupportedPlatform` rather than weakening traversal semantics.

- [ ] **Step 4: Add all filesystem failure tests**

Test root symlink, intermediate symlink, final symlink, FIFO/non-regular file, group-readable root, group-readable asset, wrong owner when the test can run as root, missing asset, digest mismatch, 2 MiB exact pass, 2 MiB + 1 fail, duplicate descriptor paths, and role/media mismatch.

`VerifiedCaseAssets::open` and `VerifiedReferenceAssets::open` validate the full requested descriptor list before returning one case/reference sequence. They never load the whole corpus, return a partial sequence, serialize, or expose source paths.

- [ ] **Step 5: Run asset and Miri-compatible pure tests**

Run: `cargo test -p irlume-camera --lib profile_evaluation_assets::tests`

Expected: PASS, with root-only ownership test conditionally skipped through an explicit early return when not root.

Run: `cargo clippy -p irlume-camera --all-targets -- -D warnings`

Expected: PASS with every unsafe block carrying a precise safety comment.

- [ ] **Step 6: Commit the asset boundary**

```bash
git add crates/irlume-camera/src/profile_evaluation_assets.rs crates/irlume-camera/src/lib.rs
git commit -S -s -m "feat: verify profile evaluation assets"
```

---

### Task 7: Add The Identity-Free Owner-Pilot Reducer And Report

**Files:**
- Create: `crates/irlume-auth/src/profile_evaluation.rs`
- Modify: `crates/irlume-auth/src/lib.rs:9-13`
- Test: `crates/irlume-auth/src/profile_evaluation.rs`

**Interfaces:**
- Consumes: validated protocol/capture pair plus aggregate `ObservedAuthOutcomes` per ordered case for baseline and candidate; no images, paths, templates, embeddings, scores, enrollment handles, or grant handles.
- Produces: `evaluate_owner_pilot(...) -> Result<OwnerPilotReport, OwnerPilotEvaluationError>` and canonical identity-free JSON.

- [ ] **Step 1: Write failing security, availability, and public-lane tests**

```rust
#[test]
fn no_face_has_zero_tolerance() {
    let fixture = PilotFixture::all_correct();
    let mut candidate = fixture.candidate.clone();
    candidate.set_detection("lit-no-face-06", ObservedDetection::Present);
    let report = evaluate_owner_pilot(
        &fixture.protocol,
        &fixture.captures,
        &fixture.baseline,
        &candidate,
        PublicRegressionEvidence::passed(
            "11".repeat(32),
            "22".repeat(32),
            "33".repeat(32),
        ),
    ).unwrap();
    assert_eq!(report.local_status(), OwnerPilotLocalStatus::Failed);
}

#[test]
fn genuine_requires_five_of_six_and_no_regression_from_baseline() {
    let five_and_five = PilotFixture::with_genuine_counts(5, 5);
    assert_eq!(five_and_five.evaluate().local_status(), OwnerPilotLocalStatus::Passed);
    let six_and_five = PilotFixture::with_genuine_counts(6, 5);
    assert_eq!(six_and_five.evaluate().local_status(), OwnerPilotLocalStatus::Failed);
    let four_and_five = PilotFixture::with_genuine_counts(4, 5);
    assert_eq!(four_and_five.evaluate().local_status(), OwnerPilotLocalStatus::Failed);
}

#[test]
fn missing_public_results_make_composite_incomplete_not_local_failed() {
    let report = PilotFixture::all_correct()
        .evaluate_with_public(PublicRegressionEvidence::Unavailable);
    assert_eq!(report.local_status(), OwnerPilotLocalStatus::Passed);
    assert_eq!(report.composite_status(), OwnerPilotCompositeStatus::Incomplete);
}
```

- [ ] **Step 2: Run auth evaluation tests and verify RED**

Run: `cargo test -p irlume-auth --lib profile_evaluation::tests`

Expected: compilation FAIL because the auth module does not exist.

- [ ] **Step 3: Implement score-free observed outcomes**

Define closed observed enums mirroring expected outcomes and this aggregate-only input:

```rust
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ObservedAuthOutcomes {
    detection: ObservedDetection,
    recognition: Option<ObservedRecognition>,
    liveness: Option<ObservedLiveness>,
    rgb_pad: Option<ObservedPad>,
    ir_pad: Option<ObservedPad>,
}

pub struct OrderedCaseObservations {
    protocol_digest: String,
    capture_digest: String,
    cases: Vec<(String, ObservedAuthOutcomes)>,
}
```

Constructors validate 64-character lowercase digests, bounded unique case IDs, at most 128 cases, and N/A consistency. There is deliberately no score, identity, path, image, template, enrollment, or grant field.

- [ ] **Step 4: Implement asymmetric scene/gate aggregation**

For each scene and applicable stage, count baseline and candidate expected-outcome matches across exactly six genuine cases. Candidate passes that scene/stage only when `candidate_correct >= 5 && candidate_correct >= baseline_correct`.

For each scene, all six candidate no-face cases must match detection absent. Any false detection fails local status. Missing, extra, reordered, or duplicate observations return an error rather than changing a denominator.

Define:

```rust
pub enum OwnerPilotLocalStatus { Passed, Failed }
pub enum OwnerPilotCompositeStatus { DiagnosticPass, Failed, Incomplete }
pub enum PublicRegressionEvidence {
    Unavailable,
    Passed { protocol_digest: String, result_digest: String, model_contract_digest: String },
    Failed { protocol_digest: String, result_digest: String, model_contract_digest: String },
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum OwnerPilotEvaluationError {
    ProtocolDigestMismatch,
    CaptureDigestMismatch,
    CaseSetMismatch,
    InvalidObservation,
    InvalidPublicEvidence,
    Serialization,
}
```

Composite is `Incomplete` when public is unavailable, `Failed` when either public or local fails, and `DiagnosticPass` only when both pass. The name `DiagnosticPass` is binding and must not be shortened to `Passed`.

- [ ] **Step 5: Implement an identity-free report projection**

`OwnerPilotReport` stores only protocol/baseline/candidate/public digests, bounded profile IDs, scene/presentation names, per-gate denominators and counts, local/composite status, and fixed categorical reasons. Add `to_share_safe_json()` using a dedicated serializable projection.

Test that JSON does not contain fixture participant tokens, reference IDs, asset paths, display identities, receipt paths, the substrings `score`, `embedding`, `template`, or any absolute temporary root.

Do not implement `From<OwnerPilotReport> for ProfileAuthGateEvidence` or any function returning `ProfileSelectionRecord`.

- [ ] **Step 6: Run auth and camera tests**

Run: `cargo test -p irlume-auth --lib profile_evaluation::tests`

Expected: PASS.

Run: `cargo test -p irlume-camera --lib profile_evaluation::tests`

Expected: PASS.

Run: `cargo test -p irlume-camera --lib profile_qualification::tests`

Expected: PASS.

Run: `cargo clippy -p irlume-auth -p irlume-camera --all-targets -- -D warnings`

Expected: PASS.

- [ ] **Step 7: Commit the no-write reducer**

```bash
git add crates/irlume-auth/src/profile_evaluation.rs crates/irlume-auth/src/lib.rs
git commit -S -s -m "feat: report owner pilot profile evidence"
```

---

### Task 8: Bind Future Authority Records To Separate Evidence Digests

**Files:**
- Modify: `crates/irlume-camera/src/profile_qualification.rs:558-966,1186-1267,1740-2041`
- Test: `crates/irlume-camera/src/profile_qualification.rs`

**Interfaces:**
- Consumes: future authority core from Task 1 and the separate protocol/capture digest vocabulary from Tasks 2 and 3.
- Produces: future records with `evaluation_protocol_digest` and per-profile `capture_manifest_digest`; still no owner-pilot adapter or writer.

- [ ] **Step 1: Write failing digest-separation tests**

```rust
#[test]
fn selected_and_fallback_bind_one_protocol_and_independent_capture_manifests() {
    let record = selection_record();
    assert_eq!(record.evaluation_protocol_digest(), "44".repeat(32));
    assert_eq!(record.selected().capture_manifest_digest(), "55".repeat(32));
    assert_eq!(
        record.sequential_fallback().unwrap().capture_manifest_digest(),
        "66".repeat(32),
    );
}

#[test]
fn candidates_with_different_protocols_or_reused_capture_digest_fail() {
    let mut attempts = passing_attempts();
    attempts[1].evaluation_protocol_digest = "77".repeat(32);
    assert_eq!(select_fixture(attempts).unwrap_err(), ProfileQualificationError::ContextChanged);

    let mut attempts = passing_attempts();
    attempts[1].capture_manifest_digest = attempts[0].capture_manifest_digest.clone();
    assert_eq!(select_fixture(attempts).unwrap_err(), ProfileQualificationError::InvalidEvidence);
}
```

- [ ] **Step 2: Run qualification tests and verify RED**

Run: `cargo test -p irlume-camera --lib profile_qualification::tests::selected_and_fallback_bind`

Expected: compilation FAIL because records still contain one `evaluation_manifest_digest`.

- [ ] **Step 3: Replace the combined digest field**

Replace every `evaluation_manifest_digest` field with:

```rust
evaluation_protocol_digest: String,
capture_manifest_digest: String,
```

At the selection-record root, retain only `evaluation_protocol_digest`; each `QualifiedProfileRecord` stores its own `capture_manifest_digest`. Validate all digests, require every candidate to share one protocol, and reject one capture digest reused by different profile IDs or schedules. Preserve separate selected/fallback capture digests during serialization and round-trip.

Do not add schema migration or backward compatibility because schema 1 has not shipped or persisted.

- [ ] **Step 4: Prove owner-pilot reports cannot enter selection**

Add this compile-fail doctest to the public `OwnerPilotReport` documentation in
`crates/irlume-auth/src/profile_evaluation.rs`, where `irlume-camera` is an
actual dependency:

```rust
/// ```compile_fail
/// use irlume_auth::profile_evaluation::OwnerPilotReport;
/// use irlume_camera::profile_qualification::ProfileGateEvidence;
/// fn convert(report: OwnerPilotReport) -> ProfileGateEvidence { report.into() }
/// ```
```

Run: `cargo test -p irlume-auth --doc`

Expected: PASS because the conversion does not exist.

- [ ] **Step 5: Run full focused software gates**

Run: `cargo test -p irlume-camera --lib profile_evaluation::tests`

Expected: PASS.

Run: `cargo test -p irlume-camera --lib profile_evaluation_signature::tests`

Expected: PASS.

Run: `cargo test -p irlume-camera --lib profile_evaluation_assets::tests`

Expected: PASS.

Run: `cargo test -p irlume-camera --lib profile_qualification::tests`

Expected: PASS.

Run: `cargo test -p irlume-auth --lib profile_evaluation::tests`

Expected: PASS.

Run: `cargo clippy -p irlume-camera -p irlume-auth --all-targets -- -D warnings`

Expected: PASS.

- [ ] **Step 6: Commit digest separation**

```bash
git add crates/irlume-camera/src/profile_qualification.rs crates/irlume-auth/src/profile_evaluation.rs
git commit -S -s -m "fix: separate profile evaluation authorities"
```

---

### Task 9: Final Review, Three-Crate Verification, And Evidence

**Files:**
- Modify: `.superpowers/sdd/2026-09-01-layered-camera-profile-engine/progress.md`
- Create or append: `.superpowers/sdd/2026-09-01-layered-camera-profile-engine/task-7-implementer.md`
- Modify: `/home/wisbfime/archledger-gp/project-irlume.md`
- Modify: `/home/wisbfime/archledger-gp/index.md`

**Interfaces:**
- Consumes: all prior tasks.
- Produces: verified software-only Task 7 corpus-contract slice and exact resumption state; no new code behavior.

- [ ] **Step 1: Review the complete diff against the approved spec**

Inspect:

```bash
git diff 567e8676..HEAD -- crates/irlume-camera/src crates/irlume-auth/src
git status --short --branch
git log --show-signature --format=fuller 567e8676..HEAD
```

Confirm:

- schema 1 has no authorizing purpose;
- no pilot callback returns `ProfileAuthGateEvidence`;
- no pilot report converts to a selection record;
- no daemon, CLI, example, vault, model, enrollment, hardware, package, service, or production file changed;
- every persistent input is bounded and revalidated;
- every signature requires the exact full fingerprint;
- every filesystem read is descriptor-relative and no-follow;
- no result type carries PII, paths, images, templates, embeddings, or scores.

- [ ] **Step 2: Verify model sources before creating temporary links**

Run the established source-manifest check against all seven model artifacts. Expected: every source file matches `models/SHA256SUMS` exactly.

Verify the worktree `models/` parent exists and contains only its established three entries, then create temporary links for the six missing model files using explicit absolute destination paths. Do not overwrite any existing path.

- [ ] **Step 3: Run the final three-crate all-target gate**

Run: `cargo test -p irlume-camera -p irlume-auth -p irlume-daemon --all-targets`

Expected: PASS for every runnable target; only already-declared environment/hardware tests are ignored.

Run: `cargo clippy -p irlume-camera -p irlume-auth -p irlume-daemon --all-targets -- -D warnings`

Expected: PASS.

Run: `cargo fmt --all -- --check`

Expected: PASS.

Run: `git diff --check`

Expected: PASS.

Run a no-added-U+2014 check over `567e8676..HEAD`. Expected: no matches.

- [ ] **Step 4: Remove temporary links and verify cleanup**

Remove only the six links created in Step 2. Verify `models/` is restored to its exact pre-test entries and rerun `git status --short --branch`.

- [ ] **Step 5: Write implementation evidence and refresh shared state**

Record exact commands, test counts, ignored counts, commit OIDs/signatures/DCO, review findings, external state, rollback, and lessons in the Task 7 implementer report and Archledger. State explicitly:

- no biometric content was inspected or copied;
- no vault or hardware action occurred;
- schema 1 remains diagnostic-only;
- real model replay, legacy import, and collection remain separate plans and gates.

- [ ] **Step 6: Commit only repository evidence if tracked**

The SDD directory is gitignored. If the implementer report must remain branch evidence, force-stage only that report after inspecting it:

```bash
git add -f .superpowers/sdd/2026-09-01-layered-camera-profile-engine/task-7-implementer.md
git commit -S -s -m "docs: record profile corpus contract evidence"
```

Do not stage `progress.md`, Archledger files outside the repository, model links, generated test data, or any corpus asset.

## Deferred Plans And Gates

After this plan is complete, stop. The following require separate plans and explicit user approval:

1. **Offline model replay:** strict PPM/PGM decoding, canonical evidence reconstruction, ephemeral ArcFace references, actual detector/recognition/liveness/PAD model execution, and model-intermediate zeroization using synthetic fixtures first.
2. **Legacy owner import:** metadata-only subset proposal, explicit asset-list approval, encrypted vault creation/mount, copy, checksum, legacy manifest, and source-preservation proof.
3. **Fresh owner capture:** daemon-owned no-write collection command, deterministic A/B ordering, camera/emitter restoration, four scenes, six genuine and six no-face attempts per scene/profile, and no-write report.
4. **Authorizing corpus:** multi-participant consent, cross-identity probes, presentation attacks, statistical policy, rollback-resistant consent head, selection writer, and Task 8 production review.

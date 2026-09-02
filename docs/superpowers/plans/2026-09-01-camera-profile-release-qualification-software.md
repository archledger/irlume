# Camera Profile Release Qualification Software Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:executing-plans
> to implement this plan task-by-task. The user prohibits subagents for this
> project, so execute inline with a fresh review checkpoint after every task.
> Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Replace the unshipped owner-local corpus protocol with bounded signed
release-qualification evidence and independent non-biometric local commissioning
that must both pass before an optimized camera profile can be ranked.

**Architecture:** `irlume-camera` owns three separate authority boundaries: a
closed aggregate-only release artifact, detached-signature verification against
one allowlisted maintainer key, and an exact-device local commissioning record.
The retained profile selection core consumes only opaque verified release and
local evidence, revalidates every nested contract, ranks complete candidates,
and leaves all production writers disconnected.

**Tech Stack:** Rust 2021 with MSRV 1.88, Serde/serde_json, existing
`irlume-common` SHA-256 and secure-file helpers, direct `gpg` process invocation
behind a crate-private verifier seam, Cargo tests, rustdoc compile-fail tests,
Clippy, rustfmt, Git signed commits, DCO.

**Spec:** `docs/superpowers/specs/2026-09-01-camera-profile-release-qualification-design.md`

## Global Constraints

- End users never create or manage a qualification corpus.
- Do not access, inspect, copy, hash, collect, or delete biometric data.
- Do not create or mount a vault, access enrollment, run real models, open a
  camera, execute a hardware gate, publish an artifact, or wire a writer.
- Release artifacts contain aggregate pass/fail dispositions only. They contain
  no identities, paths, frames, crops, tensors, templates, embeddings, scores,
  consent records, serial numbers, or private campaign metadata.
- Local commissioning contains transport, signal, timing, conditioning,
  restoration, camera, and connection facts only. It contains no model result
  or authentication decision.
- Release evidence and local evidence are independent opaque types. Neither API
  can construct or substitute for the other.
- Selection requires exact baseline, candidate, hardware class, requested and
  accepted tuples, schedule, conditioning, preprocessing, model, producer,
  policy, and campaign bindings.
- Unknown fields, enum values, schemas, policies, signers, hardware scopes, and
  digests fail closed. Missing, stale, expired, unsigned, or failed evidence
  authorizes nothing.
- Preserve password fallback, conservative capture qualification, and the
  already-qualified sequential fallback.
- `ProfileSelectionStore::save` remains crate-private and unused outside tests.
  Task 8 and every production writer remain blocked.
- No compatibility adapter is required for the unshipped owner-pilot or current
  unshipped profile-selection schema 1.
- No new Cargo dependency is added. Signature verification invokes an explicit
  executable path directly without a shell, default keyring, network, or key
  discovery.
- Every commit is GPG-signed and carries exactly
  `Signed-off-by: Wisbendji Fimerlus <archledger236@gmail.com>`.
- New and changed writing contains no U+2014.
- Execute inline. Do not dispatch subagents.

## File Map

- Delete `crates/irlume-camera/src/profile_evaluation.rs`: remove the unshipped
  owner-pilot protocol and dirty capture-manifest lane.
- Create `crates/irlume-camera/src/release_qualification.rs`: closed schema-1
  aggregate release artifact, exact baseline/candidate contracts, bounds,
  canonicalization, policy validation, and safe categorical errors.
- Create `crates/irlume-camera/src/release_qualification_signature.rs`: bounded
  secure file loading, isolated detached-GPG verification, exact full-fingerprint
  status parsing, and opaque verified release evidence.
- Create `crates/irlume-camera/src/profile_commissioning.rs`: exact-device
  non-biometric record, freshness, local gates, hardware-class matching, and
  opaque validated local evidence.
- Modify `crates/irlume-camera/src/capture_qualification.rs`: add read-only
  endpoint and connection accessors needed for hardware-class matching.
- Refactor `crates/irlume-camera/src/profile_qualification.rs`: remove the
  forgeable combined attempt/gate surface, consume both opaque evidence types,
  retain deterministic ranking and secure revision-CAS storage, and bind each
  selected profile to both evidence digests.
- Modify `crates/irlume-camera/src/profile.rs`: remove only the dirty Task 3
  Serde additions from `DecodedPixelFormat`; retain `QualificationScene`.
- Modify `crates/irlume-camera/src/lib.rs`: remove owner-pilot export and add
  the new internal modules.
- Update ignored
  `.superpowers/sdd/2026-09-01-layered-camera-profile-engine/progress.md` and
  the Task 7 implementer report after every task.

---

### Task 1: Retire The Unshipped Owner-Pilot Surface

**Files:**
- Delete: `crates/irlume-camera/src/profile_evaluation.rs`
- Modify: `crates/irlume-camera/src/profile.rs:18-21`
- Modify: `crates/irlume-camera/src/profile_qualification.rs:4-5`
- Modify: `crates/irlume-camera/src/lib.rs:56-59`
- Test: rustdoc in `crates/irlume-camera/src/profile_qualification.rs`

**Interfaces:**
- Consumes: committed Task 2 owner-pilot module plus dirty Task 3 capture work.
- Produces: no `profile_evaluation` public module, a restored committed
  `DecodedPixelFormat`, and the existing shared `profile::QualificationScene`.

- [ ] **Step 1: Add a failing external-surface retirement doctest**

Replace the module comment at the top of `profile_qualification.rs` with this
compile-fail proof:

```rust
//! Offline release and local evidence composition for exact camera profiles.
//!
//! The superseded owner-local protocol is not a public product surface.
//!
//! ```compile_fail
//! use irlume_camera::profile_evaluation::ProfileEvaluationProtocolManifest;
//! ```
```

- [ ] **Step 2: Run the doctest and verify RED**

Run: `cargo test -p irlume-camera --doc profile_qualification`

Expected: FAIL because `profile_evaluation` still exists and the compile-fail
snippet unexpectedly compiles.

- [ ] **Step 3: Remove only the superseded and dirty owner-pilot work**

Delete `profile_evaluation.rs` and remove this line from `lib.rs`:

```rust
pub mod profile_evaluation;
```

Restore `DecodedPixelFormat` to its committed pre-Task-3 declaration:

```rust
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash, Ord, PartialOrd)]
pub enum DecodedPixelFormat {
```

Do not remove `serde::{Deserialize, Serialize}` from `profile.rs`; other committed
profile contracts still use those derives. Do not move or rename
`QualificationScene`.

- [ ] **Step 4: Prove the owner-pilot vocabulary is gone and shared scenes remain**

Run: `cargo test -p irlume-camera --doc profile_qualification`

Expected: PASS because the retired import cannot compile.

Run: `cargo test -p irlume-camera --lib profile::tests`

Expected: PASS.

Run: `git diff --check`

Expected: PASS. `git status --short` lists `profile_evaluation.rs` only as a
deletion, and the other source changes are this task's focused edits.

- [ ] **Step 5: Run quality gates and commit the retirement**

Run: `cargo clippy -p irlume-camera --all-targets -- -D warnings`

Expected: PASS.

Run: `cargo fmt --all -- --check`

Expected: PASS.

```bash
git add crates/irlume-camera/src/profile_evaluation.rs crates/irlume-camera/src/profile.rs crates/irlume-camera/src/profile_qualification.rs crates/irlume-camera/src/lib.rs
git commit -S -s -m "refactor: retire owner profile evaluation"
```

Expected: one signed+DCO commit. No compatibility shim or replacement code is
part of this cleanup commit.

---

### Task 2: Define The Closed Aggregate Release Artifact

**Files:**
- Create: `crates/irlume-camera/src/release_qualification.rs`
- Modify: `crates/irlume-camera/src/lib.rs:54-61`
- Test: `crates/irlume-camera/src/release_qualification.rs`

**Interfaces:**
- Consumes: `profile::{CaptureSchedule, DecodedPixelFormat, PairTransportProfile,
  StreamTuple}` and `frame_interval::FrameInterval`.
- Produces: crate-private `ReleaseQualificationArtifact`,
  `ReleaseHardwareScope`, `ReleaseProfileContract`, `ReleaseGateDispositions`,
  `ReleaseSignatureMetadata`, `ReleaseQualificationError`, and test-only
  `fixture_canonical_artifact` for sibling module tests.

- [ ] **Step 1: Write failing schema, canonicalization, and privacy tests**

Create the module with tests first. Use a generated JSON fixture containing no
biometric assets or identities:

```rust
#[test]
fn artifact_round_trips_canonically_and_binds_baseline_and_candidate() {
    let bytes = fixture_json("baseline-30-15", "candidate-15-15");
    let artifact = ReleaseQualificationArtifact::from_canonical_json(&bytes).unwrap();
    assert_eq!(artifact.to_canonical_json().unwrap().as_bytes(), bytes.as_slice());
    assert_eq!(artifact.baseline_profile().id(), "baseline-30-15");
    assert_eq!(artifact.candidate_profile().id(), "candidate-15-15");
    assert_ne!(artifact.baseline_profile(), artifact.candidate_profile());
}

#[test]
fn artifact_rejects_unknown_fields_versions_and_failed_gates() {
    assert_eq!(
        parse_mutated("unknown_authority", serde_json::json!(true)),
        Err(ReleaseQualificationError::Json),
    );
    assert_eq!(
        parse_mutated("schema_version", serde_json::json!(99)),
        Err(ReleaseQualificationError::UnsupportedSchema(99)),
    );
    assert_eq!(
        parse_nested_mutated("gates", "rgb_pad", serde_json::json!("failed")),
        Err(ReleaseQualificationError::ReleaseGateFailed),
    );
}

#[test]
fn serialized_artifact_contains_only_approved_aggregate_fields() {
    let body = String::from_utf8(fixture_json("baseline", "candidate")).unwrap();
    for forbidden in [
        "identity", "participant", "template", "embedding", "score",
        "consent", "relative_path", "serial", "image", "tensor",
    ] {
        assert!(!body.contains(forbidden), "forbidden field {forbidden}");
    }
}
```

Also add focused cases for document size, identifier length, invalid digest,
zero versions, identical profiles, wrong RGB/IR roles, non-reduced or zero
intervals, expiry before qualification, unsupported policy, unsupported
hardware-match policy, unknown enum values, and reordered pretty JSON.

Define sibling-consumed fixture helpers at module root under `#[cfg(test)]` with
these exact signatures:

```rust
#[cfg(test)]
pub(crate) fn fixture_artifact_value(
    baseline_id: &str,
    candidate_id: &str,
) -> serde_json::Value;
#[cfg(test)]
pub(crate) fn fixture_json(baseline_id: &str, candidate_id: &str) -> Vec<u8>;
#[cfg(test)]
pub(crate) fn fixture_canonical_artifact() -> Vec<u8>;
#[cfg(test)]
pub(crate) fn fixture_release_scope() -> ReleaseHardwareScope;
```

Keep mutation helpers inside this module's private test module:

```rust
fn parse_mutated(field: &str, value: serde_json::Value)
    -> Result<ReleaseQualificationArtifact, ReleaseQualificationError>;
fn parse_nested_mutated(parent: &str, field: &str, value: serde_json::Value)
    -> Result<ReleaseQualificationArtifact, ReleaseQualificationError>;
```

The fixture baseline uses RGB YUYV 640x480 at 30 fps and IR GREY8 640x400 at 15
fps. Its candidate uses exact 15/15 fps. It also uses lowercase repeated-byte
SHA-256 values, policy/producer/schema 1, fixed time `1_788_192_000`, expiry
`1_788_278_400`, and all aggregate dispositions passed.
`fixture_canonical_artifact` returns `serde_json::to_vec` over that value without
pretty printing.

- [ ] **Step 2: Run artifact tests and verify RED**

Run: `cargo test -p irlume-camera --lib release_qualification::tests`

Expected: compilation FAIL because the module and contracts do not exist.

- [ ] **Step 3: Implement exact wire contracts and bounds**

Add to `lib.rs`:

```rust
mod release_qualification;
```

Implement these exact constants and closed enums:

```rust
pub(crate) const RELEASE_QUALIFICATION_SCHEMA_VERSION: u32 = 1;
pub(crate) const RELEASE_QUALIFICATION_POLICY_VERSION: u32 = 1;
pub(crate) const RELEASE_QUALIFICATION_PRODUCER_VERSION: u32 = 1;
pub(crate) const HARDWARE_SCOPE_MATCH_POLICY_VERSION: u32 = 1;
pub(crate) const MAX_RELEASE_QUALIFICATION_BYTES: usize = 256 * 1024;

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum AggregateDisposition {
    Passed,
    Failed,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct ReleaseGateDispositions {
    detection: AggregateDisposition,
    recognition: AggregateDisposition,
    liveness: AggregateDisposition,
    rgb_pad: AggregateDisposition,
    ir_pad: AggregateDisposition,
    latency: AggregateDisposition,
}
```

Use explicit wire enums and structs instead of adding Serde to
`DecodedPixelFormat`, `StreamTuple`, or `PairTransportProfile`:

```rust
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum ReleasePixelFormat {
    Yuyv,
    Nv12,
    Grey8,
    Grey16,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct ReleaseStreamTuple {
    format: ReleasePixelFormat,
    width: u32,
    height: u32,
    interval_numerator: u32,
    interval_denominator: u32,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct ReleaseProfileContract {
    profile_id: String,
    requested_rgb: ReleaseStreamTuple,
    accepted_rgb: ReleaseStreamTuple,
    requested_ir: ReleaseStreamTuple,
    accepted_ir: ReleaseStreamTuple,
    schedule: CaptureSchedule,
}
```

`ReleasePixelFormat::to_domain()` maps each closed wire variant explicitly.
`ReleaseProfileContract::to_profile()` reconstructs every tuple through
that mapping, `FrameInterval::new`, `StreamTuple::new`, and
`PairTransportProfile::from_negotiated`. It never trusts deserialized geometry,
roles, or intervals directly. Require the reconstructed interval parts to equal
the wire numerator and denominator so non-reduced encodings fail rather than
silently normalizing.

Define hardware scope without a device serial or devpath:

```rust
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct ReleaseEndpointScope {
    descriptor_sha256: String,
    vid: u16,
    pid: u16,
    interface_number: u8,
    driver: String,
    backend: String,
    speed_millimbps: u64,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct ReleaseHardwareScope {
    match_policy_version: u32,
    interface_layout_sha256: String,
    rgb: ReleaseEndpointScope,
    ir: ReleaseEndpointScope,
}
```

The top-level artifact has only these fields:

```rust
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct ReleaseQualificationArtifact {
    schema_version: u32,
    policy_version: u32,
    producer_version: u32,
    campaign_id: String,
    campaign_protocol_sha256: String,
    campaign_result_sha256: String,
    qualified_at_unix: u64,
    expires_at_unix: Option<u64>,
    hardware_scope: ReleaseHardwareScope,
    baseline: ReleaseProfileContract,
    candidate: ReleaseProfileContract,
    conditioning_catalog_sha256: String,
    selected_policy_sha256: String,
    preprocessing_contract_sha256: String,
    model_contract_sha256: String,
    gates: ReleaseGateDispositions,
    signature: ReleaseSignatureMetadata,
}
```

Define signature metadata as:

```rust
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum ReleaseSignatureAlgorithm {
    OpenPgp,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct ReleaseSignatureMetadata {
    algorithm: ReleaseSignatureAlgorithm,
    signer_fingerprint: String,
}
```

The signer fingerprint is exactly 40 uppercase hexadecimal bytes. Signature
bytes remain detached and never enter this struct.

Provide `baseline_profile_sha256()` and `candidate_profile_sha256()` by hashing
the compact canonical JSON of each validated nested profile contract. Later
selection uses the baseline digest to prevent comparison-result replay against a
different reference profile.

- [ ] **Step 4: Implement strict canonical and temporal validation**

`from_canonical_json(bytes)` must:

1. reject more than 256 KiB before parsing;
2. parse with `deny_unknown_fields` on every struct;
3. revalidate all versions, strings, digests, tuples, roles, and profiles;
4. reject identical baseline and candidate profile contracts;
5. require every aggregate disposition to be `Passed`;
6. require `qualified_at_unix > 0` and
   `expires_at_unix.map_or(true, |expiry| expiry > qualified_at_unix)`;
7. serialize compact JSON and require byte equality with the input.

Provide a separate `validate_at(now_unix)` that returns
`ArtifactNotYetValid` when `now_unix < qualified_at_unix` and `ArtifactExpired`
when `now_unix >= expires_at_unix`. Do not read the system clock inside the
pure artifact module.

The `Display` implementation maps to fixed categories and never includes Serde
text, campaign IDs, paths, or nested values. `ReleaseQualificationError::Json`
is a fieldless category; discard Serde text at this boundary.

- [ ] **Step 5: Run focused GREEN and mutation-style drift tests**

Run: `cargo test -p irlume-camera --lib release_qualification::tests`

Expected: PASS, including one mutation table that changes each authority field
individually and proves the canonical digest changes or validation rejects it.

Run: `cargo clippy -p irlume-camera --all-targets -- -D warnings`

Expected: PASS.

- [ ] **Step 6: Format, inspect, and commit the artifact contract**

Run: `cargo fmt --all -- --check`

Expected: PASS.

Run: `git diff --check`

Expected: PASS.

```bash
git add crates/irlume-camera/src/release_qualification.rs crates/irlume-camera/src/lib.rs
git commit -S -s -m "feat: define release qualification artifacts"
```

---

### Task 3: Verify Detached Signatures And Canonical Files

**Files:**
- Create: `crates/irlume-camera/src/release_qualification_signature.rs`
- Modify: `crates/irlume-camera/src/lib.rs:54-62`
- Test: `crates/irlume-camera/src/release_qualification_signature.rs`

**Interfaces:**
- Consumes: canonical `ReleaseQualificationArtifact` bytes, detached signature
  bytes, trusted public-key bytes, explicit executable path, and caller-supplied
  current Unix time.
- Produces: opaque crate-private `VerifiedReleaseQualification`,
  `verify_release_qualification_bytes`, `verify_release_qualification_files`,
  `GpgDetachedSignatureVerifier`, and fixed-category
  `ReleaseSignatureError`, plus a `#[cfg(test)]` sibling fixture that mints
  evidence only through the real byte verifier.

- [ ] **Step 1: Write failing signer, tamper, and canonical-byte tests**

Create tests around a crate-private fake verifier:

```rust
#[test]
fn valid_signature_mints_opaque_release_evidence() {
    let payload = fixture_canonical_artifact();
    let verified = verify_release_qualification_bytes(
        &payload,
        b"synthetic-signature",
        FIXED_NOW,
        &FakeVerifier::valid(ALLOWLISTED_RELEASE_SIGNER_FINGERPRINT),
    )
    .unwrap();
    assert_eq!(verified.artifact_sha256(), irlume_common::sha256_hex(&payload));
    assert_eq!(verified.signer_fingerprint(), ALLOWLISTED_RELEASE_SIGNER_FINGERPRINT);
}

#[test]
fn wrong_short_or_modified_signature_authorizes_nothing() {
    for verifier in [
        FakeVerifier::valid("BD7F30C6"),
        FakeVerifier::valid("035053398E3C80FE20891B82C10B8492BD7F30C6"),
        FakeVerifier::invalid_signature(),
    ] {
        assert!(verify_release_qualification_bytes(
            &fixture_canonical_artifact(),
            b"synthetic-signature",
            FIXED_NOW,
            &verifier,
        )
        .is_err());
    }
}
```

Add cases for missing signature, oversized payload/signature/key/status, pretty or
reordered signed JSON, artifact metadata fingerprint mismatch, not-yet-valid and
expired artifacts, key symlinks, payload symlinks, non-regular files, process
failure, timeout, and status output containing only `GOODSIG`.

Define `FakeVerifier` at module root under `#[cfg(test)]` as one stored
`Result<VerifiedSigner, ReleaseSignatureError>`. `valid(fingerprint)` returns one
`VerifiedSigner` with that exact string; `invalid_signature()` returns
`ReleaseSignatureError::InvalidSignature`. This lets the sibling fixture below
use the same real byte-verification path. Duplicate and conflicting `VALIDSIG`
cases belong only to the fake executable status-parser tests because the trait
returns at most one signer.

After GREEN, expose only under `#[cfg(test)]`:

```rust
pub(crate) fn verified_release_fixture(
    baseline_id: &str,
    candidate_id: &str,
    candidate_rgb_fps: u32,
    candidate_ir_fps: u32,
    candidate_schedule: CaptureSchedule,
    campaign_byte: u8,
    now_unix: u64,
) -> VerifiedReleaseQualification;
```

It mutates the test artifact value, reserializes canonical bytes, and calls
`verify_release_qualification_bytes` with the allowlisted `FakeVerifier`. It
does not construct `VerifiedReleaseQualification` directly.

- [ ] **Step 2: Run signature tests and verify RED**

Run: `cargo test -p irlume-camera --lib release_qualification_signature::tests`

Expected: compilation FAIL because the verifier module does not exist.

- [ ] **Step 3: Implement an unforgeable verifier seam**

Add to `lib.rs`:

```rust
mod release_qualification_signature;
```

Keep the trait, fake, verified type, and constructors crate-private:

```rust
pub(crate) const ALLOWLISTED_RELEASE_SIGNER_FINGERPRINT: &str =
    "F35053398E3C80FE20891B82C10B8492BD7F30C6";

pub(crate) trait DetachedSignatureVerifier {
    fn verify(
        &self,
        canonical_payload: &[u8],
        detached_signature: &[u8],
    ) -> Result<VerifiedSigner, ReleaseSignatureError>;
}

pub(crate) struct VerifiedSigner {
    fingerprint: String,
}

pub(crate) struct VerifiedReleaseQualification {
    artifact: ReleaseQualificationArtifact,
    artifact_sha256: String,
    signer_fingerprint: String,
}
```

`verify_release_qualification_bytes` verifies the exact input bytes first, then
parses canonical JSON, calls `validate_at(now_unix)`, requires artifact signature
metadata to match the verifier's exact full fingerprint, and only then constructs
`VerifiedReleaseQualification`. No public or test-independent constructor exists.

- [ ] **Step 4: Implement isolated GPG process verification**

`GpgDetachedSignatureVerifier` has explicit executable path, trusted public-key
bytes, and timeout. It must:

- create a unique mode-0700 temporary GPG home;
- place only the public key, detached signature, and status output there as
  mode-0600 regular files;
- pass canonical payload bytes to `gpg --verify <signature> -` over piped stdin;
- invoke the executable directly with argument arrays, never a shell;
- clear inherited environment except `LC_ALL=C`;
- pass `--batch`, `--no-options`, `--no-tty`, `--no-autostart`,
  `--disable-dirmngr`, isolated `--homedir`, and `--status-file`;
- import only the supplied bounded key before verification;
- poll `try_wait()` to a five-second default deadline, then kill and reap;
- write at most 256 KiB through a scoped writer thread, close stdin, and join the
  writer after normal exit or kill;
- read at most 64 KiB plus one byte of status and reject overflow;
- accept successful exit plus exactly one `VALIDSIG` whose first fingerprint
  token equals the full allowlisted fingerprint;
- reject `GOODSIG` alone, short IDs, missing `VALIDSIG`, duplicate records,
  conflicting records, nonzero exit, and other fingerprints;
- remove the temporary home through RAII cleanup.

Never consult a user keyring, fetch a key, start dirmngr, or copy payload bytes
into a temporary regular file.

- [ ] **Step 5: Add bounded no-symlink file loading and fake executable tests**

`verify_release_qualification_files` accepts explicit artifact, signature,
trusted-key, and executable paths. Open all three with `O_NOFOLLOW`, require
regular files, cap payload at 256 KiB, signature at 64 KiB, and key at 64 KiB,
require UID 0 ownership with no group/world write bits, then delegate to the
byte verifier. A `#[cfg(test)] verify_release_qualification_files_for_owner`
accepts the current test UID so unprivileged tests exercise the same metadata
checks. No production function accepts an owner override.

Add deterministic path construction without directory discovery:

```rust
pub(crate) struct ReleaseQualificationPaths {
    artifact: PathBuf,
    signature: PathBuf,
    trusted_key: PathBuf,
}

impl ReleaseQualificationPaths {
    pub(crate) fn under(root: &Path, artifact_name: &str) -> Result<Self, ReleaseSignatureError>;
    pub(crate) fn system(artifact_name: &str) -> Result<Self, ReleaseSignatureError>;
}
```

`artifact_name` is a nonempty ASCII safe label of at most 128 bytes containing
only lowercase letters, digits, `-`, and `_`. `under(root, name)` resolves
`<root>/share/irlume/profile-qualifications/<name>.json`, the adjacent
`<name>.json.asc`, and `<root>/share/irlume/release-qualification-key.asc`.
`system(name)` uses root `/usr`. No code enumerates a directory or accepts a path
component from artifact contents.

Generate a mode-0700 fake executable under a unique test directory. It records
argument boundaries, consumes stdin, and writes exact status lines to the path
following `--status-file`. Test:

- successful import and verify invocations;
- a path containing spaces remains one argument;
- payload bytes do not appear in any temporary regular file;
- timeout when the process does not read stdin;
- oversized status and nonzero exit;
- wrong, short, duplicate, and missing `VALIDSIG` records;
- RAII cleanup after every failure.

After the isolated key import succeeds, truncate the status file before the
verify invocation. Parse only status records from verification, never import
status records.

Build one synthetic package-root fixture through
`ReleaseQualificationPaths::under` and prove exact path construction, safe-label
rejection, bounded loading, no-symlink behavior, owner/mode rejection, and
successful fake verification through the test-only current-owner seam. Add pure
metadata cases proving UID other than 0, group-write, and world-write all fail
the production policy.

No test invokes a real keyring or network.

- [ ] **Step 6: Run quality gates and commit signature verification**

Run: `cargo test -p irlume-camera --lib release_qualification_signature::tests`

Expected: PASS.

Run: `cargo test -p irlume-camera --lib release_qualification::tests`

Expected: PASS.

Run: `cargo clippy -p irlume-camera --all-targets -- -D warnings`

Expected: PASS.

Run: `cargo fmt --all -- --check`

Expected: PASS.

```bash
git add crates/irlume-camera/src/release_qualification_signature.rs crates/irlume-camera/src/lib.rs
git commit -S -s -m "feat: verify release qualification signatures"
```

---

### Task 4: Define Non-Biometric Local Commissioning Evidence

**Files:**
- Create: `crates/irlume-camera/src/profile_commissioning.rs`
- Modify: `crates/irlume-camera/src/capture_qualification.rs:167-341`
- Modify: `crates/irlume-camera/src/release_qualification.rs`
- Modify: `crates/irlume-camera/src/lib.rs:54-63`
- Test: `crates/irlume-camera/src/profile_commissioning.rs`

**Interfaces:**
- Consumes: `QualificationContext`, exact candidate `PairTransportProfile`,
  `ReleaseHardwareScope`, conditioning digests, fixed caller time, and local
  aggregate transport measurements.
- Produces: crate-private `LocalCommissioningRecord`, opaque
  `ValidatedLocalCommissioning`, `LocalCommissioningGates`, and
  `ProfileCommissioningError`, plus a `#[cfg(test)]` sibling fixture that mints
  local evidence only through `validate_for`.

- [ ] **Step 1: Write failing local-only, freshness, and scope tests**

Create synthetic context and measurement fixtures only:

```rust
#[test]
fn complete_fresh_local_record_matches_one_exact_device_and_release_scope() {
    let record = fixture_commissioning();
    let validated = record
        .validate_for(
            &fixture_release_scope(),
            &fixture_candidate_profile(
                "candidate-15-15",
                15,
                15,
                CaptureSchedule::Concurrent,
            ),
            &fixture_current_context(15, 15),
            FIXED_NOW,
        )
        .unwrap();
    assert_eq!(validated.profile_id(), "candidate-15-15");
    assert_eq!(validated.p95_latency_ms(), 6_000);
}

#[test]
fn model_or_biometric_fields_are_not_local_commissioning_vocabulary() {
    let mut value = fixture_commissioning_value(
        "candidate-15-15",
        15,
        15,
        CaptureSchedule::Concurrent,
    );
    value["recognition"] = serde_json::json!("passed");
    assert_eq!(
        LocalCommissioningRecord::from_canonical_json(value.to_string().as_bytes()),
        Err(ProfileCommissioningError::Json),
    );
}

#[test]
fn stale_scope_tuple_or_restoration_failure_authorizes_nothing() {
    assert!(matches!(
        validate_mutation("expires_at_unix", serde_json::json!(FIXED_NOW)),
        Err(ProfileCommissioningError::Stale),
    ));
    assert!(matches!(
        validate_changed_connection(),
        Err(ProfileCommissioningError::HardwareScopeMismatch),
    ));
    assert!(matches!(
        validate_changed_tuple(),
        Err(ProfileCommissioningError::ProfileMismatch),
    ));
    assert!(matches!(
        validate_failed_restoration(),
        Err(ProfileCommissioningError::LocalGateFailed),
    ));
}
```

Also test unknown fields, schema/policy/producer versions, empty and oversized
strings, invalid digests, zero timestamps, expiry ordering, wrong role, changed
serial or devpath, changed descriptor/interface/VID/PID/driver/backend/speed,
changed schedule, conditioning digest drift, p50 greater than p95, zero latency,
failed negotiation/transport/continuity/signal/conditioning/restoration gates,
failed runtime-degradation compatibility, and non-canonical JSON.

Import `fixture_release_scope` from `release_qualification`. Define the
sibling-consumed helpers at module root under `#[cfg(test)]` with these exact
signatures:

```rust
#[cfg(test)]
pub(crate) fn fixture_current_context(rgb_fps: u32, ir_fps: u32)
    -> QualificationContext;
#[cfg(test)]
pub(crate) fn fixture_candidate_profile(
    id: &str,
    rgb_fps: u32,
    ir_fps: u32,
    schedule: CaptureSchedule,
) -> PairTransportProfile;
#[cfg(test)]
pub(crate) fn fixture_commissioning_value(
    id: &str,
    rgb_fps: u32,
    ir_fps: u32,
    schedule: CaptureSchedule,
) -> serde_json::Value;
```

Keep test-local mutation helpers in the private test module:

```rust
fn fixture_commissioning() -> LocalCommissioningRecord;
fn validate_mutation(field: &str, value: serde_json::Value)
    -> Result<ValidatedLocalCommissioning, ProfileCommissioningError>;
fn validate_changed_connection()
    -> Result<ValidatedLocalCommissioning, ProfileCommissioningError>;
fn validate_changed_tuple()
    -> Result<ValidatedLocalCommissioning, ProfileCommissioningError>;
fn validate_failed_restoration()
    -> Result<ValidatedLocalCommissioning, ProfileCommissioningError>;
```

Use descriptor digest `ab` repeated 32 times, VID `0x0bda`, PID `0x5678`,
interfaces 0/2, driver `uvcvideo`, backend `v4l2-uvc`, speed 5,000,000
millimbps, RGB YUYV 640x480, IR GREY8 640x400, fixed current time
`1_788_192_050`, expiry `1_788_278_400`, and passed gates with latency
4,000/6,000/8,000 ms. Changed-scope helpers build a fresh context through the
public validated constructors rather than mutating private fields.

- [ ] **Step 2: Run commissioning tests and verify RED**

Run: `cargo test -p irlume-camera --lib profile_commissioning::tests`

Expected: compilation FAIL because the module and evidence types do not exist.

- [ ] **Step 3: Add read-only hardware matching accessors**

Add only these accessors to existing validated types:

```rust
impl ConnectionContext {
    pub(crate) const fn speed_millimbps(&self) -> u64;
    pub(crate) fn driver(&self) -> &str;
    pub(crate) fn backend(&self) -> &str;
}

impl CameraEndpoint {
    pub(crate) fn descriptor_sha256(&self) -> &str;
    pub(crate) const fn vid(&self) -> u16;
    pub(crate) const fn pid(&self) -> u16;
    pub(crate) const fn interface_number(&self) -> u8;
}
```

Do not add setters, public constructors, generalized field projection, or
diagnostic formatting. The release matcher reads no serial or devpath; the local
exact-scope comparison retains both through `QualificationContext` equality.

- [ ] **Step 4: Implement the closed local record and opaque validated type**

Add to `lib.rs`:

```rust
mod profile_commissioning;
```

Use these exact local gates:

```rust
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct LocalCommissioningGates {
    negotiation_passed: bool,
    transport_passed: bool,
    continuity_passed: bool,
    signal_sanity_passed: bool,
    conditioning_applied: bool,
    restoration_exact: bool,
    runtime_degradation_compatible: bool,
    p50_latency_ms: u64,
    p95_latency_ms: u64,
    latency_budget_ms: u64,
}
```

The record contains only:

```rust
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct LocalCommissioningRecord {
    schema_version: u32,
    policy_version: u32,
    producer_version: u32,
    measured_at_unix: u64,
    expires_at_unix: u64,
    profile_id: String,
    context: QualificationContext,
    schedule: CaptureSchedule,
    conditioning_catalog_sha256: String,
    selected_policy_sha256: String,
    interface_layout_sha256: String,
    gates: LocalCommissioningGates,
}
```

It stores no scene label because commissioning does not evaluate people or model
quality. The future authorized runner must use a non-human target and persist
only this aggregate record, but this plan does not implement that runner.

`ValidatedLocalCommissioning` has private fields and no constructor outside this
module. `validate_for(release_scope, candidate, current_context, now)` must:

1. revalidate canonical record structure;
2. reject `now < measured_at_unix` and `now >= expires_at_unix`;
3. require record context equality with the caller's current exact context,
   including serial, devpath, descriptors, interfaces, and connection facts;
4. reconstruct the exact candidate from `QualificationContext` and schedule;
5. require candidate ID plus requested/accepted tuples and schedule equality;
6. match release RGB/IR descriptor, VID, PID, interface, driver, backend, speed,
   and interface-layout digest without comparing serial or devpath;
7. retain the exact local `QualificationContext`, including serial/devpath, in
   the validated evidence;
8. require every Boolean gate, including runtime-degradation compatibility, and
   `0 < p50 <= p95 <= budget`;
9. compute a SHA-256 digest over canonical local record bytes.

Implement hardware-class comparison as
`ReleaseHardwareScope::matches_context(&QualificationContext,
interface_layout_sha256)` inside `release_qualification.rs`. The commissioning
module calls that method instead of reading sibling-module private fields.

After GREEN, expose only under `#[cfg(test)]`:

```rust
pub(crate) fn validated_commissioning_fixture(
    candidate_id: &str,
    candidate_rgb_fps: u32,
    candidate_ir_fps: u32,
    candidate_schedule: CaptureSchedule,
    now_unix: u64,
) -> ValidatedLocalCommissioning;
```

It serializes the test record canonically and calls the real parser plus
`validate_for`; it never initializes opaque evidence fields directly.

- [ ] **Step 5: Run focused tests and boundary checks**

Run: `cargo test -p irlume-camera --lib profile_commissioning::tests`

Expected: PASS.

Run: `cargo test -p irlume-camera --lib capture_qualification::tests`

Expected: PASS.

Run: `cargo clippy -p irlume-camera --all-targets -- -D warnings`

Expected: PASS.

- [ ] **Step 6: Format and commit local commissioning contracts**

Run: `cargo fmt --all -- --check`

Expected: PASS.

Run: `git diff --check`

Expected: PASS.

```bash
git add crates/irlume-camera/src/profile_commissioning.rs crates/irlume-camera/src/capture_qualification.rs crates/irlume-camera/src/release_qualification.rs crates/irlume-camera/src/lib.rs
git commit -S -s -m "feat: validate local profile commissioning"
```

---

### Task 5: Require Both Evidence Classes For Selection

**Files:**
- Modify: `crates/irlume-camera/src/profile_qualification.rs`
- Modify: `crates/irlume-camera/src/release_qualification.rs`
- Modify: `crates/irlume-camera/src/release_qualification_signature.rs`
- Modify: `crates/irlume-camera/src/profile_commissioning.rs`
- Test: `crates/irlume-camera/src/profile_qualification.rs`

**Interfaces:**
- Consumes: `VerifiedReleaseQualification`, `ValidatedLocalCommissioning`,
  current `QualificationAuthorityContext`, and `RankingBudget`.
- Produces: crate-private `QualifiedCandidateEvidence`, deterministic
  `select_profiles`, schema-1 `ProfileSelectionRecord` bound to both evidence
  digests, public read-only load/accessors, and crate-private test-only save.

- [ ] **Step 1: Replace attempt fixtures with failing dual-evidence tests**

Delete tests that construct `ProfileGateEvidence` and
`ProfileQualificationAttempt`. Add these tests using module-owned fixtures that
mint opaque evidence through the real validators:

```rust
#[test]
fn release_and_local_pass_select_balanced_candidate_and_sequential_fallback() {
    let candidates = vec![
        candidate_fixture("concurrent-30-15", 30, 15, CaptureSchedule::Concurrent),
        candidate_fixture("concurrent-15-15", 15, 15, CaptureSchedule::Concurrent),
        candidate_fixture("sequential-15-15", 15, 15, CaptureSchedule::Sequential),
    ];
    let record = select_profiles(
        candidates,
        authority_fixture(),
        RankingBudget::new(1, 20_000_000, 10_000).unwrap(),
    )
    .unwrap();
    assert_eq!(record.selected().profile_id(), "concurrent-15-15");
    assert_eq!(record.sequential_fallback().unwrap().profile_id(), "sequential-15-15");
    assert_ne!(
        record.selected().release_qualification_sha256(),
        record.selected().local_commissioning_sha256(),
    );
}

#[test]
fn mismatched_evidence_never_enters_ranking() {
    assert!(matches!(
        candidate_with_profile_mismatch(),
        Err(ProfileQualificationError::ProfileMismatch),
    ));
    assert!(matches!(
        candidate_with_scope_mismatch(),
        Err(ProfileQualificationError::HardwareScopeMismatch),
    ));
    assert!(matches!(
        candidate_with_model_drift(),
        Err(ProfileQualificationError::ModelContractChanged),
    ));
}
```

Add cases for baseline mismatch across candidates, campaign drift,
preprocessing digest drift, conditioning catalog and selected-policy drift,
duplicate candidate IDs, changed exact local context, no concurrent candidate,
sequential-only selection, no passing profile, candidate count 0 and 33, and
stale revision-CAS writes. Release expiry, local expiry, unsupported release
versions, failed release gates, and failed local gates remain tests of the
modules that reject them before opaque candidate evidence exists.

Define the selection fixture in this test module as:

```rust
fn candidate_fixture(
    id: &str,
    rgb_fps: u32,
    ir_fps: u32,
    schedule: CaptureSchedule,
) -> QualifiedCandidateEvidence {
    let release = verified_release_fixture(
        "baseline-30-15",
        id,
        rgb_fps,
        ir_fps,
        schedule,
        0x44,
        FIXED_NOW,
    );
    let local = validated_commissioning_fixture(
        id,
        rgb_fps,
        ir_fps,
        schedule,
        FIXED_NOW,
    );
    QualifiedCandidateEvidence::new(release, local, &authority_fixture()).unwrap()
}
```

`authority_fixture()` returns the same four fixed digests emitted by the release
and local fixtures. Mismatch tests call the two sibling fixture functions with
different IDs, RGB/IR rates, schedules, baseline IDs, campaign bytes, or current
times,
then assert the real candidate constructor or selector rejects the pair.

Define these helper return types explicitly:

```rust
fn authority_fixture() -> QualificationAuthorityContext;
fn candidate_with_profile_mismatch()
    -> Result<QualifiedCandidateEvidence, ProfileQualificationError>;
fn candidate_with_scope_mismatch()
    -> Result<QualifiedCandidateEvidence, ProfileQualificationError>;
fn candidate_with_model_drift()
    -> Result<QualifiedCandidateEvidence, ProfileQualificationError>;
```

- [ ] **Step 2: Run selection tests and verify RED**

Run: `cargo test -p irlume-camera --lib profile_qualification::tests`

Expected: compilation FAIL because selection still consumes the removed
combined attempt/gate surface.

- [ ] **Step 3: Replace the combined gate model with exact current contracts**

Remove `ProfileAuthGateEvidence`, `SceneGateEvidence`, `ProfileGateEvidence`,
`ProfileQualificationAttempt`, `GateStatus`, and every builder that can fabricate
model gates locally.

Define current installed contracts as:

```rust
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct QualificationAuthorityContext {
    model_contract_sha256: String,
    preprocessing_contract_sha256: String,
    conditioning_catalog_sha256: String,
    selected_policy_sha256: String,
}
```

Its constructor remains crate-private. Validate all four lowercase SHA-256
digests. Release producer/policy/campaign facts come from signed evidence and
must not be caller-supplied through this context.

Extend `ProfileQualificationError` with the fieldless or bounded variants used
by this task:

```rust
ProfileMismatch,
HardwareScopeMismatch,
BaselineProfileMismatch,
PreprocessingContractChanged,
SelectedPolicyChanged,
DuplicateCandidate,
```

Retain `UnsupportedSchema(u32)`, `UnsupportedPolicy(u32)`,
`ModelContractChanged`, `ConditioningCatalogChanged`, `ContextChanged`,
`CandidateCount`, `NoPassingProfile`, `InvalidEvidence`, `InvalidDigest`,
`RecordTooLarge`, fieldless `Json`, and `Context(QualificationError)` where still
applicable. Discard parse text so it cannot escape through `Display`. `Display`
remains safe and categorical.

Define the only candidate input:

```rust
pub(crate) struct QualifiedCandidateEvidence {
    release: VerifiedReleaseQualification,
    local: ValidatedLocalCommissioning,
}
```

`QualifiedCandidateEvidence::new(release, local, authority)` must compare exact
candidate profile, hardware class, conditioning catalog, selected policy,
preprocessing, model, and local context before constructing the value. It must
also expose the release baseline fingerprint used to require a common baseline
across one ranking operation.

- [ ] **Step 4: Refactor selected records and deterministic ranking**

Replace `evaluation_manifest_digest` everywhere. Each
`QualifiedProfileRecord` stores:

```rust
profile_id: String,
context: QualificationContext,
schedule: CaptureSchedule,
p50_latency_ms: u64,
p95_latency_ms: u64,
release_qualification_sha256: String,
local_commissioning_sha256: String,
```

`ProfileSelectionRecord` stores common schema/policy/producer/current-contract
digests and baseline profile digest, plus selected and optional sequential
fallback records. It has `#[serde(deny_unknown_fields)]`, and every nested record
revalidates both evidence digests and exact scope after deserialization.

Freeze the top-level record shape as:

```rust
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ProfileSelectionRecord {
    schema_version: u32,
    policy_version: u32,
    producer_version: u32,
    measured_at_unix: u64,
    scope: ProfileScope,
    release_policy_version: u32,
    release_producer_version: u32,
    hardware_match_policy_version: u32,
    campaign_id: String,
    campaign_protocol_sha256: String,
    campaign_result_sha256: String,
    baseline_profile_sha256: String,
    model_contract_sha256: String,
    preprocessing_contract_sha256: String,
    conditioning_catalog_sha256: String,
    selected_policy_sha256: String,
    selected: QualifiedProfileRecord,
    sequential_fallback: Option<QualifiedProfileRecord>,
}
```

All candidates in one ranking operation must share the release policy,
producer, hardware-match policy, campaign ID, campaign protocol/result digests,
baseline profile digest, and current installed contract digests. Candidate
artifact and commissioning digests remain per `QualifiedProfileRecord`.

`select_profiles` must:

1. reject 0 or more than 32 candidates;
2. reject duplicate `(profile_id, schedule)` pairs;
3. require one exact physical `ProfileScope`, one baseline digest, and one set of
   current contract digests;
4. accept only already-validated dual evidence;
5. derive profile payload from exact candidate tuples;
6. rank concurrent candidates when any pass, otherwise rank sequential;
7. retain the balanced passing sequential fallback;
8. store each candidate's separate release and local evidence digests;
9. revalidate the complete record before returning it.

Do not add a conversion from raw artifact JSON, raw local JSON, aggregate gates,
or authentication output directly into `QualifiedProfileRecord`.

- [ ] **Step 5: Disconnect writers and preserve secure read behavior**

Keep `ProfileSelectionStore::system` and `load` read-only public APIs for future
review. Change `save` and `at` to `pub(crate)` and prove no non-test call exists.
Retain atomic replacement, directory fsync, mode 0700/0600, ownership checks,
`O_NOFOLLOW`, record bounds, lock files, monotonic revisions, and stale-CAS
rejection unchanged.

The unshipped schema-1 record shape is replaced directly. Do not add migration
or fallback parsing for its old `evaluation_manifest_digest` field.

- [ ] **Step 6: Run focused selection and store gates**

Run: `cargo test -p irlume-camera --lib profile_qualification::tests`

Expected: PASS, including balanced ranking, sequential fallback, strict parse,
mode, symlink, and stale-revision tests.

Run: `cargo test -p irlume-camera --doc profile_qualification`

Expected: PASS.

Run: `cargo clippy -p irlume-camera --all-targets -- -D warnings`

Expected: PASS.

- [ ] **Step 7: Format, inspect, and commit dual-evidence selection**

Run: `cargo fmt --all -- --check`

Expected: PASS.

Run: `git diff --check`

Expected: PASS.

```bash
git add crates/irlume-camera/src/profile_qualification.rs crates/irlume-camera/src/release_qualification.rs crates/irlume-camera/src/release_qualification_signature.rs crates/irlume-camera/src/profile_commissioning.rs
git commit -S -s -m "feat: require dual profile qualification evidence"
```

---

### Task 6: Prove Authority Isolation And Close The Software Slice

**Files:**
- Modify: `crates/irlume-camera/src/profile_qualification.rs`
- Modify: `crates/irlume-camera/src/release_qualification_signature.rs`
- Modify: `crates/irlume-camera/src/profile_commissioning.rs`
- Modify: `.superpowers/sdd/2026-09-01-layered-camera-profile-engine/progress.md`
- Create: `.superpowers/sdd/2026-09-01-layered-camera-profile-engine/task-7-release-qualification-implementer.md`
- Test: rustdoc and all new module tests

**Interfaces:**
- Consumes: the complete synthetic software slice from Tasks 1 through 5.
- Produces: compile-time authority-boundary proofs, safe diagnostic projection,
  full verification evidence, and an exact stop state before campaign, hardware,
  packaging publication, writer, daemon, or production work.

- [ ] **Step 1: Add failing external construction proofs**

Add these compile-fail blocks to the `profile_qualification` module docs:

```rust
//! Release evidence cannot be fabricated outside camera verification.
//!
//! ```compile_fail
//! use irlume_camera::release_qualification_signature::VerifiedReleaseQualification;
//! let _ = VerifiedReleaseQualification::new_for_test();
//! ```
//!
//! Local commissioning evidence cannot be fabricated from release data.
//!
//! ```compile_fail
//! use irlume_camera::profile_commissioning::ValidatedLocalCommissioning;
//! let _ = ValidatedLocalCommissioning::new_for_test();
//! ```
//!
//! Profile-selection publication is not an external API.
//!
//! ```compile_fail
//! let store = irlume_camera::profile_qualification::ProfileSelectionStore::system();
//! let record = irlume_camera::profile_qualification::ProfileSelectionRecord::from_json(b"{}").unwrap();
//! store.save(record, None).unwrap();
//! ```
```

If the modules are private, the imports themselves are the intended compile
failure. Do not make them public to produce a different error.

- [ ] **Step 2: Run doctests and verify the boundary**

Run: `cargo test -p irlume-camera --doc profile_qualification`

Expected: PASS because all prohibited external constructions fail to compile.

- [ ] **Step 3: Add fixed-category diagnostic projection tests**

Define a public non-authorizing diagnostic enum with exactly these variants:

```rust
pub enum ProfileQualificationDiagnostic {
    ArtifactMissing,
    ArtifactTooLarge,
    ArtifactSchemaUnsupported,
    SignatureMissing,
    SignatureInvalid,
    SignerUntrusted,
    ArtifactExpired,
    HardwareScopeMismatch,
    BaselineProfileMismatch,
    ProfileTupleMismatch,
    CameraContextMismatch,
    ModelDigestChanged,
    PreprocessingDigestChanged,
    ConditioningDigestChanged,
    CommissioningMissing,
    CommissioningStale,
    ReleaseGateFailed,
    LocalGateFailed,
}
```

Map internal release, signature, commissioning, and selection failures into this
enum. `Display` uses the exact snake-case names from the design. Add a table test
that feeds internal errors containing path-like or third-party text and proves
the rendered output contains none of: `/`, `\\`, `gpg:`, `campaign`, `serial`,
`score`, or fixture identifiers.

Do not serialize raw internal error text or make the diagnostic enum a
constructor for either evidence class.

- [ ] **Step 4: Run every synthetic Task 7 test group**

Run: `cargo test -p irlume-camera --lib release_qualification::tests`

Expected: PASS.

Run: `cargo test -p irlume-camera --lib release_qualification_signature::tests`

Expected: PASS.

Run: `cargo test -p irlume-camera --lib profile_commissioning::tests`

Expected: PASS.

Run: `cargo test -p irlume-camera --lib profile_qualification::tests`

Expected: PASS.

Run: `cargo test -p irlume-camera --doc profile_qualification`

Expected: PASS.

- [ ] **Step 5: Run the camera crate and workspace quality gates**

Run: `cargo test -p irlume-camera --all-targets`

Expected: every runnable software test PASS; declared hardware tests remain
ignored and are not forced.

Run: `cargo check --workspace --locked`

Expected: PASS without requiring model execution.

Run: `cargo clippy -p irlume-camera --all-targets -- -D warnings`

Expected: PASS.

Run: `cargo fmt --all -- --check`

Expected: PASS.

Run: `git diff --check`

Expected: PASS.

- [ ] **Step 6: Audit forbidden surfaces and writer disconnection**

Search the repository and confirm:

- no source reference to `ProfileEvaluationProtocolManifest`,
  `ProfileEvaluationCaptureManifest`, owner pilot, consent ledger, or evaluation
  vault remains outside superseded historical documentation;
- no production call to `ProfileSelectionStore::save` exists;
- no auth, daemon, CLI, PAM, enrollment, model, or camera-capture file changed in
  this plan;
- no retained or packaged artifact, signature, public key, biometric asset,
  vault file, hardware output, model output, or qualification record was
  created; temporary synthetic test fixtures were removed by their guards;
- the tracked diff is restricted to Task 6 diagnostic and boundary-proof source
  files before commit.

Record exact search commands and results in the implementer report. Historical
superseded design and plan references are expected and must not be deleted.

- [ ] **Step 7: Commit the tracked closure proofs**

```bash
git add crates/irlume-camera/src/profile_qualification.rs crates/irlume-camera/src/release_qualification_signature.rs crates/irlume-camera/src/profile_commissioning.rs
git commit -S -s -m "test: prove profile qualification authority"
```

Expected: one signed+DCO commit containing only tracked diagnostic and boundary
proof changes.

- [ ] **Step 8: Verify all six commits and write the implementation report**

Run `git verify-commit` for every implementation commit and inspect each commit
body for the exact DCO trailer. Confirm `git status --short` is empty except for
ignored SDD updates, which Git does not list.

The ignored implementer report records:

- all six commit OIDs, good signature results, and exact DCO trailers;
- RED and GREEN evidence with test counts and declared ignores;
- final Clippy, rustfmt, workspace check, and diff hygiene;
- exact retained API and removed owner-pilot API;
- proof that release and local evidence remain unconstructible externally;
- proof that no writer or production consumer is connected;
- no biometric, vault, hardware, enrollment, daemon, package, remote, or GitHub
  state changed;
- any mistake or near miss, its cause, correction, and prevention;
- exact next gate.

Do not force-add ignored SDD files. Refresh SDD and Archledger after the commit.

- [ ] **Step 9: Stop at the independent user gate**

Report the exact clean HEAD and ask for review. Do not design or execute the
maintainer campaign, create a real signing key or artifact, package a public key,
run local hardware commissioning, connect a daemon reader or writer, modify Task
8, or change production profile selection.

The next separately approved plan must cover maintainer campaign protocol,
private corpus governance, statistical policy, and aggregate artifact
production. Hardware commissioning and production integration remain later,
independent plans.

# Layered Camera Profile And Evidence Engine Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build a context-qualified camera transport and conditioning engine that converts camera-specific streams into stable typed model inputs without changing production profile selection until complete hardware and authentication-quality gates pass.

**Architecture:** Add pure transport-profile and ranking contracts, a bounded read-only V4L2 capability inventory, typed canonical evidence and model-input adapters, reversible conditioning policies, and an immutable per-attempt plan. Keep qualification offline until the final task, then permit production selection only from a context-bound record whose transport, detector, recognition, liveness, PAD, and latency evidence all pass.

**Tech Stack:** Rust, V4L2 through the existing `v4l` and raw ioctl seams, Serde, ONNX Runtime through `ort`, existing camera leases/provenance/qualification stores, Cargo unit and hardware-gated tests.

**Spec:** `docs/superpowers/specs/2026-09-01-layered-camera-profile-engine-design.md`

## Global Constraints

- Models never receive V4L2 buffers, camera fourcc values, unvalidated payload layouts, or mutable frame references.
- Generate transport candidates only from exact device-advertised tuples and represent intervals as reduced exact fractions.
- Security and quality are hard gates. Rank USB demand and p95 latency only after every applicable detector, recognition, liveness, and PAD gate passes.
- Keep the selected transport profile fixed for an exact qualified camera and connection context.
- Select conditioning policies only between attempts and freeze one immutable plan during each evidence window.
- Use only standard V4L2 controls and already-whitelisted emitter controls. Never scan or write unknown vendor extension units.
- Preserve read-before-write, exact readback confirmation, restore-on-drop, and emitter-journal behavior.
- Preserve ADR-0019 fail-closed PAD availability and password fallback.
- Preserve existing production profile and capture-schedule selection through Tasks 1-7.
- Do not add MJPG decoding in this plan.
- Do not change model weights, thresholds, normalization, crop margins, enrollment semantics, or stored embedding spaces.
- Keep support output share-safe: no paths, serials, frames, crops, tensors, embeddings, identities, or sensitive per-user scores.
- Use plain punctuation and introduce no U+2014 em dash.

---

### Task 1: Pure Transport Profile And Ranking Contracts

**Files:**
- Create: `crates/irlume-camera/src/profile.rs`
- Modify: `crates/irlume-camera/src/lib.rs:33-57`
- Test: `crates/irlume-camera/src/profile.rs`

**Interfaces:**
- Consumes: `frame_interval::FrameInterval`, `contracts::StreamRole`, and existing exact stream terminology.
- Produces: `StreamTuple`, `PairTransportProfile`, `QualifiedProfileMetrics`, `CandidateVerdict`, `pareto_frontier`, and `rank_balanced`.

- [ ] **Step 1: Write failing construction and ranking tests**

Add tests that reject zero geometry, retain exact intervals, calculate bounded nominal payload for YUYV, NV12, and GREY, reject MJPG as undecodable, remove a profile dominated on both payload and p95 latency, and deterministically break equal-score ties by payload then ID:

```rust
#[test]
fn balanced_ranking_never_admits_failed_quality() {
    let passing = candidate("asus-15-15", 13_056_000, 6_400, CandidateVerdict::Passed);
    let faster_but_failed = candidate(
        "failed-pad",
        9_000_000,
        5_000,
        CandidateVerdict::Rejected(ProfileGate::Pad),
    );
    assert_eq!(
        rank_balanced(&[faster_but_failed, passing], budget()).unwrap().id(),
        "asus-15-15"
    );
}

#[test]
fn pareto_frontier_removes_a_profile_worse_on_both_axes() {
    let better = candidate("better", 13_000_000, 6_000, CandidateVerdict::Passed);
    let dominated = candidate("dominated", 18_000_000, 7_000, CandidateVerdict::Passed);
    let candidates = [dominated, better];
    let ids: Vec<_> = pareto_frontier(&candidates).into_iter().map(|p| p.id()).collect();
    assert_eq!(ids, vec!["better"]);
}
```

- [ ] **Step 2: Run the focused tests and verify RED**

Run: `cargo test -p irlume-camera --lib profile::tests`

Expected: compilation fails because `profile` and its contracts do not exist.

- [ ] **Step 3: Implement bounded exact profile types**

Define the core types with private fields and validating constructors:

```rust
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash, Ord, PartialOrd)]
pub enum DecodedPixelFormat {
    Yuyv,
    Nv12,
    Grey8,
    Grey16,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
pub enum CaptureSchedule {
    Sequential,
    Concurrent,
}

#[derive(Clone, Debug, Eq, PartialEq, Hash)]
pub struct StreamTuple {
    role: contracts::StreamRole,
    format: DecodedPixelFormat,
    width: NonZeroU32,
    height: NonZeroU32,
    interval: frame_interval::FrameInterval,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PairTransportProfile {
    id: String,
    rgb: StreamTuple,
    ir: StreamTuple,
    schedule: CaptureSchedule,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ProfileGate {
    Negotiation,
    Transport,
    Signal,
    Detection,
    Recognition,
    Liveness,
    Pad,
    Latency,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CandidateVerdict {
    Passed,
    Rejected(ProfileGate),
}
```

Use checked `u128` arithmetic for bytes per frame times exact frames per second. Return `None` for compressed or unknown payload cost. Reject profile IDs that are empty, oversized, or contain control characters.

Implement `pareto_frontier(&[QualifiedProfileMetrics]) -> Vec<&QualifiedProfileMetrics>` over passing profiles only. Implement `rank_balanced(&[QualifiedProfileMetrics], RankingBudget) -> Option<&QualifiedProfileMetrics>` by normalizing payload and p95 latency against fixed nonzero versioned policy budgets, summing exact fixed-point millionths, then breaking ties by lower payload and lexicographic profile ID. Adding an unrelated candidate must not change another candidate's normalized cost. Do not include model scores in the rank.

- [ ] **Step 4: Run focused tests and verify GREEN**

Run: `cargo test -p irlume-camera --lib profile::tests`

Expected: all profile construction, payload, filtering, Pareto, and deterministic ranking tests pass.

- [ ] **Step 5: Commit the pure contract slice**

```bash
git add crates/irlume-camera/src/profile.rs crates/irlume-camera/src/lib.rs
git commit -s -m "feat: define qualified camera profiles"
```

### Task 2: Bounded Read-Only V4L2 Capability Inventory

**Files:**
- Create: `crates/irlume-camera/src/capability_inventory.rs`
- Modify: `crates/irlume-camera/src/lib.rs:33-57,4098-4183,4629-4684`
- Modify: `crates/irlume-camera/src/frame_interval.rs:213-700`
- Test: `crates/irlume-camera/src/capability_inventory.rs`
- Test: `crates/irlume-camera/src/frame_interval.rs`

**Interfaces:**
- Consumes: `StreamTuple`, `DecodedPixelFormat`, `FrameIntervalDomain`, camera leases, `VIDIOC_ENUM_FMT`, `VIDIOC_ENUM_FRAMESIZES`, `VIDIOC_ENUM_FRAMEINTERVALS`, `VIDIOC_QUERYCTRL`, and `VIDIOC_TRY_FMT`.
- Produces: `CapabilityInventory::read(device, role)`, `FormatCapability`, `GeometryDomain`, and fixed-size `StandardControlCapability` entries.

- [ ] **Step 1: Write failing bounded-enumeration tests**

Create a fake ioctl source covering discrete and stepwise frame sizes, discrete and continuous intervals, an unknown format, duplicate tuples, a control with an invalid range, and a source that exceeds each item cap. Assert unknown observation remains an error rather than an empty inventory.

```rust
#[test]
fn failed_format_enumeration_is_not_an_empty_capability_claim() {
    let mut source = FakeSource::format_error(libc::EIO);
    let error = inventory_from_source(&mut source, StreamRole::Rgb).unwrap_err();
    assert!(matches!(error, CapabilityError::Enumeration { stage: CapabilityStage::Formats, .. }));
}

#[test]
fn only_decodable_exact_tuples_become_candidates() {
    let inventory = inventory_from_source(&mut asus_fixture(), StreamRole::Rgb).unwrap();
    assert!(inventory.tuples().iter().any(|t| t.width() == 640 && t.height() == 480));
    assert!(inventory.tuples().iter().all(|t| matches!(
        t.format(),
        DecodedPixelFormat::Yuyv | DecodedPixelFormat::Nv12
    )));
}
```

- [ ] **Step 2: Run focused inventory tests and verify RED**

Run: `cargo test -p irlume-camera --lib capability_inventory::tests`

Expected: compilation fails because the inventory module and ioctl source do not exist.

- [ ] **Step 3: Implement one injected capability source**

Define a private seam so production and fixture enumeration share the same validation:

```rust
trait CapabilitySource {
    fn formats(&mut self) -> Result<Vec<[u8; 4]>, CapabilityError>;
    fn frame_sizes(&mut self, fourcc: [u8; 4]) -> Result<GeometryDomain, CapabilityError>;
    fn intervals(
        &mut self,
        query: frame_interval::FrameIntervalQuery,
    ) -> Result<frame_interval::FrameIntervalDomain, CapabilityError>;
    fn controls(&mut self) -> Result<Vec<StandardControlCapability>, CapabilityError>;
}
```

Cap formats at 64, geometries per format at 256, interval values per tuple at the existing 256, and controls at 256. Preserve continuous and stepwise domains without unbounded expansion. Map only formats already decoded by `irlume-camera`; retain unsupported advertised formats in a diagnostic count, not as candidates.

Materialize a finite candidate set from range domains using only exact domain
endpoints and exact intersections with versioned geometry/rate requirements.
For a stepwise domain, include an intersection only when it lies on the exact
lattice. Never sample arbitrary floating-point values or expand an unbounded
range.

Enumerate controls with raw bounded `VIDIOC_QUERYCTRL` iteration rather than `v4l::Device::query_controls`, matching the existing driver-panic warning. Retain only standard user, camera, and image-source class controls. Record ID, type, minimum, maximum, step, default, flags, and menu values with explicit caps. Exclude disabled, write-only, execute-on-write, and vendor-private controls from policy eligibility.

- [ ] **Step 4: Add ASUS, BRIO, and NexiGo capability fixtures**

Encode the observed relevant tuples from the design spec as pure fixtures. Assert:

- ASUS yields RGB 640x480 YUYV at exact 1/30 and 1/15 plus IR 640x400 GREY at 1/15.
- BRIO yields RGB 640x480 YUYV at exact 1/30 through 1/5 advertised values plus IR 340x340 GREY at 1/30.
- NexiGo yields RGB 640x480 YUYV and IR 640x360 GREY only at 1/30 for the current decoded geometries.
- No fixture invents a lower IR rate.

- [ ] **Step 5: Run inventory and interval tests and verify GREEN**

Run: `cargo test -p irlume-camera --lib capability_inventory::tests frame_interval::tests`

Expected: all bounded enumeration, exact-domain, device fixture, and error-distinction tests pass.

- [ ] **Step 6: Commit the inventory slice**

```bash
git add crates/irlume-camera/src/capability_inventory.rs crates/irlume-camera/src/frame_interval.rs crates/irlume-camera/src/lib.rs
git commit -s -m "feat: inventory exact camera capabilities"
```

### Task 3: Canonical Camera Evidence Boundary

**Files:**
- Create: `crates/irlume-camera/src/evidence.rs`
- Modify: `crates/irlume-camera/src/lib.rs:129-220,4285-4365,4918-4969,5352-5690`
- Modify: `crates/irlume-camera/src/frame_provenance.rs`
- Test: `crates/irlume-camera/src/evidence.rs`
- Test: `crates/irlume-camera/src/lib.rs`

**Interfaces:**
- Consumes: validated `Frame`, aggregate provenance, `IrCaptureStats`, RGB temporal median, and IR burst-selection facts.
- Produces: `CanonicalRgbEvidence`, `CanonicalIrEvidence`, `EvidenceManifest`, and capture methods returning canonical evidence.

- [ ] **Step 1: Write failing canonical-evidence validation tests**

Test that RGB requires exactly `width * height * 3` bytes and RGB provenance, IR requires exactly `width * height` bytes and IR provenance, aggregate contributor windows remain bounded, and subtracted IR records both lit and ambient contributors.

```rust
#[test]
fn canonical_rgb_rejects_a_short_or_wrong_role_frame() {
    let short = fixture_frame(Spectrum::Rgb, 4, 4, vec![0; 47]);
    assert_eq!(CanonicalRgbEvidence::try_from(short).unwrap_err(), EvidenceError::PayloadLength);

    let ir = fixture_frame(Spectrum::Ir, 4, 4, vec![0; 16]);
    assert_eq!(CanonicalRgbEvidence::try_from(ir).unwrap_err(), EvidenceError::WrongRole);
}
```

- [ ] **Step 2: Run evidence tests and verify RED**

Run: `cargo test -p irlume-camera --lib evidence::tests`

Expected: compilation fails because canonical evidence types do not exist.

- [ ] **Step 3: Implement typed owned evidence**

Define private-pixel, validated wrappers:

```rust
pub struct CanonicalRgbEvidence {
    width: NonZeroU32,
    height: NonZeroU32,
    rgb8: Vec<u8>,
    manifest: EvidenceManifest,
}

pub struct CanonicalIrEvidence {
    width: NonZeroU32,
    height: NonZeroU32,
    grey8: Vec<u8>,
    saturation_source: Option<Vec<u8>>,
    stats: IrCaptureStats,
    manifest: EvidenceManifest,
}
```

Expose dimensions, read-only pixels, capture window, and manifest accessors. Do not expose a constructor that accepts arbitrary pixels without validated runtime provenance. Move temporal-median contributor construction and IR selected/ambient contributor facts into these constructors.

Change `RgbSession::denoised`, `capture_rgb_denoised_with_progress`, and IR capture-with-stats entry points to return canonical evidence. Migrate internal camera tests and examples in the same task. Keep single-frame framing APIs returning `Frame` because they are not model evidence.

- [ ] **Step 4: Add equivalence tests for current reduction behavior**

Use fixed RGB bursts and IR lit/dark fixtures to prove canonical output bytes match the existing five-frame median, lit-frame selection, clipping source, and default no-subtraction behavior exactly.

- [ ] **Step 5: Run camera tests and verify GREEN**

Run: `cargo test -p irlume-camera --lib`

Expected: all runnable camera tests pass; declared hardware tests remain ignored.

- [ ] **Step 6: Commit the canonical camera boundary**

```bash
git add crates/irlume-camera/src/evidence.rs crates/irlume-camera/src/frame_provenance.rs crates/irlume-camera/src/lib.rs crates/irlume-camera/examples
git commit -s -m "refactor: type canonical camera evidence"
```

### Task 4: Typed Model Input Contracts

**Files:**
- Create: `crates/irlume-vision/src/model_input.rs`
- Modify: `crates/irlume-vision/src/lib.rs:1-40,560-660,1010-1060,1316-1611`
- Modify: `crates/irlume-vision/src/align.rs:294-369`
- Modify: `crates/irlume-auth/src/lib.rs:3694-3835,4268-4600`
- Test: `crates/irlume-vision/src/model_input.rs`
- Test: `crates/irlume-auth/src/lib.rs`

**Interfaces:**
- Consumes: validated read-only RGB8/GREY8 pixel views exposed by canonical camera evidence at the auth boundary, detector landmarks, and existing measured preprocessing functions. `irlume-vision` must not depend on `irlume-camera`.
- Produces: `DetectorInput`, `ArcFaceInput`, `VitRgbPadInput`, `FlirIrPadInput`, `ModelInputContractId`, and `ModelContractSet`.

- [ ] **Step 1: Write failing model-contract and preprocessing tests**

Add tests pinning each contract ID, shape, layout, channel order, numeric type, normalization, crop policy, and version. Assert a model adapter rejects a mismatched contract before inference.

```rust
#[test]
fn arcface_contract_is_frozen() {
    assert_eq!(ModelInputContract::arcface_v1().shape(), &[1, 3, 112, 112]);
    assert_eq!(ModelInputContract::arcface_v1().normalization(), Normalization::ArcFace128);
}

#[test]
fn vit_adapter_rejects_a_flir_contract() {
    let input = fixture_vit_input();
    assert_eq!(input.require(ModelInputContractId::FlirIrPadV1).unwrap_err(), ModelInputError::ContractMismatch);
}
```

- [ ] **Step 2: Run vision tests and verify RED**

Run: `cargo test -p irlume-vision --lib model_input::tests`

Expected: compilation fails because typed model inputs and contract IDs do not exist.

- [ ] **Step 3: Implement typed adapters around existing preprocessing**

Define closed contract IDs and private input payloads:

```rust
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
pub enum ModelInputContractId {
    YuNetLetterbox640V1,
    ArcFace112RgbV1,
    VitRgbPadM96V1,
    FlirIrPad112V1,
}

pub struct CanonicalRgbView<'a> {
    pixels: &'a [u8],
    width: NonZeroU32,
    height: NonZeroU32,
}

pub struct DetectorInput<'a> {
    view: CanonicalRgbView<'a>,
    contract: ModelInputContractId,
}

pub struct ArcFaceInput {
    chip_rgb: Vec<u8>,
    tensor_nchw: Vec<f32>,
}
```

Provide validating `CanonicalRgbView::try_from_parts` and
`CanonicalGreyView::try_from_parts` constructors that require nonzero geometry
and exact payload length. Authentication may call them only after validating the
camera evidence manifest against the attempt plan. Keep existing preprocessing
arithmetic unchanged and move its public entry through the typed constructors.
Change detector, embedder, `PadVit`, and `PadIr` inference entry points to accept
only their matching typed input.

- [ ] **Step 4: Migrate authentication to the typed gateway**

Construct detector inputs from canonical RGB and IR evidence, derive landmarks,
then construct ArcFace, ViT RGB PAD, and FLIR IR PAD inputs. Ensure no
authentication call passes `Frame`, `RgbView`, or an arbitrary byte slice
directly to an inference method.

Add a source-level ratchet test that scans non-test `irlume-auth` source and
rejects calls to the removed raw inference signatures.

- [ ] **Step 5: Run vision and auth tests and verify GREEN**

Run: `cargo test -p irlume-vision -p irlume-auth --lib`

Expected: preprocessing goldens and all runnable authentication tests pass with
unchanged model outputs and verdict fixtures.

- [ ] **Step 6: Commit the typed model boundary**

```bash
git add crates/irlume-vision/src/model_input.rs crates/irlume-vision/src/lib.rs crates/irlume-vision/src/align.rs crates/irlume-auth/src/lib.rs
git commit -s -m "refactor: type model input contracts"
```

### Task 5: Reversible Conditioning Policies

**Files:**
- Create: `crates/irlume-camera/src/conditioning.rs`
- Modify: `crates/irlume-camera/src/lib.rs:473-588,3889-3955,5194-5322`
- Test: `crates/irlume-camera/src/conditioning.rs`
- Test: `crates/irlume-camera/src/lib.rs`

**Interfaces:**
- Consumes: `StandardControlCapability`, camera lease identity, existing BLC restore behavior, and existing emitter guard.
- Produces: `SceneClass`, `ConditioningPolicyId`, `ConditioningPolicy`, `ConditioningCatalog`, `ConditioningSelection`, and `AppliedConditioningGuard`.

- [ ] **Step 1: Write failing policy-selection and restoration tests**

Test deterministic scene classification at exact boundaries, rejection of a
control absent from inventory, rejection of a requested value off the advertised
step lattice, exact readback confirmation, reverse-order restoration, no retry
after timeout or STALL, preservation of another writer's newer value, safe
default selection on the first attempt, and expiration or invalidation of prior
scene observations.

```rust
#[test]
fn policy_cannot_name_an_unadvertised_control() {
    let policy = policy_with(ControlSetting::integer(V4L2_CID_GAIN, 8));
    assert_eq!(policy.validate_against(&inventory_without_gain()).unwrap_err(), PolicyError::UnsupportedControl(V4L2_CID_GAIN));
}

#[test]
fn restore_does_not_overwrite_a_newer_external_value() {
    let mut controls = FakeControls::with_value(V4L2_CID_BACKLIGHT_COMPENSATION, 0);
    let guard = apply_policy(&mut controls, &blc_policy(2)).unwrap();
    controls.external_write(V4L2_CID_BACKLIGHT_COMPENSATION, 1);
    drop(guard);
    assert_eq!(controls.value(V4L2_CID_BACKLIGHT_COMPENSATION), 1);
}
```

- [ ] **Step 2: Run conditioning tests and verify RED**

Run: `cargo test -p irlume-camera --lib conditioning::tests`

Expected: compilation fails because conditioning policy contracts do not exist.

- [ ] **Step 3: Implement a small fixed policy catalog**

Define `lit-auto`, `backlit-auto`, `low-light`, and `dark-ir` identifiers with
bounded standard-control settings and preprocessing flags. The initial catalog
must reproduce current behavior: BLC value 2 when supported, auto exposure left
enabled, existing RGB warm-up/median, and ambient subtraction disabled.

Scene selection uses the safe default on the first attempt. Later selections may
consume only fresh process-local brightness histogram, clipping, contrast, and
illumination facts from a preceding evidence window. Expire observations after
the fixed catalog TTL and invalidate them on camera incarnation, connection,
transport profile, or catalog-version change. The selector's signature cannot
accept model scores, detections, authentication verdicts, or identity data. Do
not open a separate preflight stream for classification.

- [ ] **Step 4: Generalize the existing control restore guard**

Replace `BlcRestore` with `AppliedConditioningGuard` while preserving the exact
read-before-write, set, readback-confirm, and conditional-restore behavior. Apply
controls in deterministic ID order and restore in reverse order. Arm the guard
before stream creation. Keep emitter mode under its existing specialized journal
and guard rather than treating vendor XU writes as generic controls.

- [ ] **Step 5: Prove current behavior is unchanged**

Run: `cargo test -p irlume-camera --lib conditioning::tests blc ir_emitter`

Expected: policy tests pass and every existing BLC/emitter restoration test
remains green.

- [ ] **Step 6: Commit the conditioning slice**

```bash
git add crates/irlume-camera/src/conditioning.rs crates/irlume-camera/src/lib.rs
git commit -s -m "feat: qualify camera conditioning policies"
```

### Task 6: Immutable Attempt Capture Plan And Exact Profile Opens

**Files:**
- Create: `crates/irlume-auth/src/capture_plan.rs`
- Modify: `crates/irlume-auth/src/lib.rs:3466-3495,3579-3683,3847-4270`
- Modify: `crates/irlume-camera/src/backend.rs:1-320`
- Modify: `crates/irlume-camera/src/lib.rs:3769-4023,5051-5322,7125-7217`
- Test: `crates/irlume-auth/src/capture_plan.rs`
- Test: `crates/irlume-camera/src/lib.rs`

**Interfaces:**
- Consumes: `PairTransportProfile`, `ConditioningSelection`, `ModelContractSet`, camera incarnations, capture qualification context, and exact interval negotiation.
- Produces: `AttemptCapturePlan`, `RgbCamera::open_profile`, `IrCamera::open_profile`, and `CapturePlanViolation`.

- [ ] **Step 1: Write failing immutable-plan tests**

Test that one plan binds exact camera generations, both requested/accepted
tuples, schedule, conditioning ID, preprocessing versions, calibration ID,
model contracts, and qualification key. Assert any changed field produces a
specific violation before inference.

```rust
#[test]
fn changed_model_contract_invalidates_the_attempt_plan() {
    let plan = fixture_plan();
    let observed = fixture_observation().with_model_contract(ModelInputContractId::FlirIrPad112V1);
    assert_eq!(plan.validate(&observed).unwrap_err(), CapturePlanViolation::ModelContract);
}
```

- [ ] **Step 2: Run plan tests and verify RED**

Run: `cargo test -p irlume-auth --lib capture_plan::tests`

Expected: compilation fails because the attempt plan does not exist.

- [ ] **Step 3: Implement exact profile opens through existing leases**

Add profile-aware opens that receive one validated `StreamTuple`, call
`S_FMT`, request the exact interval through the existing qualification seam,
and verify every accepted format and interval field. Remove the private
experiment-only `QualificationIntervalProfile` after migrating its callers to
the new profile type.

Do not change `RgbCamera::open` or `IrCamera::open` production defaults in this
task. Profile-aware opens are reachable only from diagnostics and tests.

- [ ] **Step 4: Build and validate the immutable plan**

Construct `AttemptCapturePlan` after both cameras are opened and exact
qualification context is available, but before either session streams. Bind the
conditioning guard and model contracts before capture. Expose no mutators.

Validate canonical evidence manifests against the plan before detector input is
constructed. A mismatch returns `CapturePlanViolation` and discards both roles.

- [ ] **Step 5: Run camera and auth tests and verify GREEN**

Run: `cargo test -p irlume-camera -p irlume-auth --lib capture_plan profile`

Expected: exact-open, immutability, mismatch, and existing runtime pair-contract
tests pass.

- [ ] **Step 6: Commit the attempt-plan slice**

```bash
git add crates/irlume-auth/src/capture_plan.rs crates/irlume-auth/src/lib.rs crates/irlume-camera/src/backend.rs crates/irlume-camera/src/lib.rs
git commit -s -m "feat: bind immutable camera attempt plans"
```

### Task 7: Offline Full-Quality Profile Qualification

**Files:**
- Create: `crates/irlume-camera/src/profile_qualification.rs`
- Create: `crates/irlume-camera/examples/profile_qualification_probe.rs`
- Modify: `crates/irlume-camera/src/capture_qualification.rs`
- Modify: `crates/irlume-camera/src/lib.rs:7067-7959`
- Modify: `crates/irlume-auth/src/lib.rs:3466-4600`
- Modify: `crates/irlume-daemon/src/main.rs`
- Test: `crates/irlume-camera/src/profile_qualification.rs`
- Test: `crates/irlume-daemon/src/main.rs`

**Interfaces:**
- Consumes: capability inventory, pure candidate ranking, exact profile opens, conditioning catalog, immutable attempt plans, and a diagnostic-only auth assessment callback.
- Produces: `ProfileQualificationAttempt`, `ProfileGateEvidence`, `ProfileSelectionRecord`, `ProfileSelectionStore`, and no-authority probe output.

- [ ] **Step 1: Write failing gate-completeness and authority tests**

Test that transport-only evidence, missing PAD, missing recognition consistency,
missing p95 latency, a mismatched model digest, or an inconclusive context change
cannot produce a selected profile. Test that a complete passing record chooses
the deterministic balanced winner and separately retains a passing sequential
fallback.

```rust
#[test]
fn transport_only_attempt_cannot_select_a_profile() {
    let attempt = fixture_attempt().with_transport_pass();
    assert_eq!(attempt.selection().unwrap_err(), ProfileQualificationError::MissingGate(ProfileGate::Detection));
}
```

- [ ] **Step 2: Run qualification tests and verify RED**

Run: `cargo test -p irlume-camera --lib profile_qualification::tests`

Expected: compilation fails because full-quality profile records do not exist.

- [ ] **Step 3: Implement a separate bounded profile-selection record**

Keep existing schema-2 capture qualification readable and authoritative for the
legacy fixed profile. Add a separate profile-selection schema keyed by fd-derived
camera pair and connection context before format selection. Store:

```rust
pub struct ProfileSelectionRecord {
    schema_version: u32,
    policy_version: u32,
    producer_version: u32,
    measured_at_unix: u64,
    scope: ProfileScope,
    model_contract_digest: String,
    conditioning_catalog_digest: String,
    selected: QualifiedProfileRecord,
    sequential_fallback: Option<QualifiedProfileRecord>,
}
```

Bound strings, vectors, candidate count, and serialized record size. Validate
all fields after deserialization. Use atomic write, directory fsync, ownership,
mode, symlink, and compare-and-swap protections matching the existing
qualification store. Loading a malformed or unsupported record authorizes
nothing.

- [ ] **Step 4: Compose every qualification gate**

For each candidate, collect exact negotiation/readback, sequential/concurrent
transport facts, scene signal facts, detector presence and geometry,
profile-independent recognition regression, liveness result, every applicable
PAD evidence state, and p50/p95 wall time. Run model gates over a representative,
consented evaluation corpus with fixed manifests and expected outcomes. A local
comparison against an existing enrolled profile may add aggregate evidence but
cannot by itself authorize a machine-wide profile and must not change enrollment.

Expose a diagnostic-only auth callback that returns bounded aggregate gate
evidence and cannot grant, enroll, update templates, or write qualification
state. Require complete lit, backlit, low-light, and dark-IR contexts only when
the policy catalog declares them applicable.

- [ ] **Step 5: Replace the disposable interval probe with the full probe**

Add `profile_qualification_probe` with explicit RGB/IR devices, rounds,
candidate IDs, and a `--no-write` default. Delete
`examples/interval_profile_probe.rs` only after the new probe covers independent
RGB/IR intervals and exact failure propagation. Writing a selection record must
require the daemon-owned qualification command and explicit operator consent,
not the example.

- [ ] **Step 6: Run software tests and verify GREEN**

Run: `cargo test -p irlume-camera -p irlume-auth -p irlume-daemon --all-targets`

Expected: all runnable software tests pass; hardware qualification tests remain
declared ignored.

- [ ] **Step 7: Run the ASUS hardware gate without changing production selection**

Run the probe for ASUS 30/15 and exact 15/15 in bright, backlit, low-light, and
dark-IR conditions. Require complete detector, recognition, liveness, ViT RGB
PAD, FLIR IR PAD, transport, provenance, and p50/p95 latency evidence. Keep
BRIO/NexiGo sequential results as negative controls. Restore and hash-verify
daemon, camera controls, emitter state, qualification stores, and installed
binaries after every run.

Expected: the task produces evidence only. A passing ASUS result is eligible
for Task 8 review but does not change production behavior by itself.

- [ ] **Step 8: Commit the offline qualifier slice**

```bash
git add crates/irlume-camera/src/profile_qualification.rs crates/irlume-camera/src/capture_qualification.rs crates/irlume-camera/src/lib.rs crates/irlume-camera/examples/profile_qualification_probe.rs crates/irlume-camera/examples/interval_profile_probe.rs crates/irlume-auth/src/lib.rs crates/irlume-daemon/src/main.rs
git commit -s -m "feat: qualify complete camera profiles"
```

### Task 8: Device-Scoped Production Selection And Diagnostics

**Files:**
- Modify: `crates/irlume-auth/src/capture_plan.rs`
- Modify: `crates/irlume-auth/src/lib.rs:3579-3683,3847-4270`
- Modify: `crates/irlume-camera/src/profile_qualification.rs`
- Modify: `crates/irlume-common/src/diagnostics.rs`
- Modify: `crates/irlume-daemon/src/diagnostics.rs`
- Modify: `crates/irlume-cli/src/support_report.rs`
- Modify: `docs/ARCHITECTURE.md`
- Modify: `docs/HARDWARE.md`
- Test: all modified modules

**Interfaces:**
- Consumes: a fully validated `ProfileSelectionRecord`, exact profile opens, immutable attempt plan, existing capture qualification, and runtime degradation.
- Produces: production `CapturePlanSelection`, sanitized profile/policy diagnostics, and legacy-default fallback when no valid profile-selection authority exists.

- [ ] **Step 1: Write failing selection precedence and invalidation tests**

Test these exact cases:

- No profile-selection record preserves the existing fixed-profile behavior.
- A valid exact-context record selects its transport profile and schedule.
- Changed camera incarnation, USB connection, model digest, preprocessing
  version, conditioning catalog, or accepted driver tuple invalidates selection.
- An invalid record falls back to the existing safe sequential/default path and
  never tries another tuple.
- Runtime degradation discards the current concurrent evidence and selects only
  the stored sequential fallback on the next attempt.

```rust
#[test]
fn absent_profile_authority_preserves_legacy_selection() {
    let selection = select_capture_plan(&scope(), None, &legacy_capture_authority()).unwrap();
    assert_eq!(selection.source(), CapturePlanSource::LegacyFixedProfile);
}
```

- [ ] **Step 2: Run focused production-selection tests and verify RED**

Run: `cargo test -p irlume-auth --lib capture_plan_selection`

Expected: assertions fail because production does not consult profile-selection authority.

- [ ] **Step 3: Integrate profile selection before stream creation**

Collect pair scope through non-streaming fd identity, load and validate one
profile record, open the exact selected tuple, validate the resulting context,
select a pre-qualified conditioning policy, and build the immutable attempt
plan before `STREAMON`.

If no valid record exists, run the existing fixed RGB 640x480 and requested IR
640x400 behavior unchanged. If a record exists but its exact open or context
validation fails, discard it for the operation and use the existing safe
sequential/default path. Do not search for another profile during authentication.

- [ ] **Step 4: Add bounded diagnostics**

Extend diagnostics with sanitized fixed-size values:

```rust
pub struct CameraPlanStatus {
    pub source: CameraPlanSourceLabel,
    pub profile_id: Option<DiagnosticLabel>,
    pub conditioning_policy: Option<DiagnosticLabel>,
    pub qualification_state: ProfileQualificationStateLabel,
    pub fallback_reason: Option<ProfileFallbackReasonLabel>,
}
```

Emit aggregate stage timings for inventory load, plan validation, control
application, RGB reduction, IR reduction, detector input, alignment,
recognition input, and PAD inputs. Keep role-delivered-rate and control-restore
failures bounded. Add privacy tests rejecting paths, serials, image fields,
tensor fields, embedding fields, and score fields.

- [ ] **Step 5: Update architecture and hardware documentation**

Document transport profile, conditioning policy, canonical evidence, model
input contract, attempt capture plan, qualification invalidation, and the exact
device-scoped result from Task 7. State explicitly that BRIO and NexiGo remain
sequential and that MJPG is unsupported.

- [ ] **Step 6: Run final software verification**

Run: `cargo fmt --all -- --check`

Run: `cargo clippy --workspace --all-targets --all-features -- -D warnings`

Run: `cargo test --workspace --all-targets --all-features`

Run: `cargo doc --workspace --all-features --no-deps`

Run: `git diff --check`

Run: `! rg -n $'\u2014' crates docs/superpowers/specs/2026-09-01-layered-camera-profile-engine-design.md docs/superpowers/plans/2026-09-01-layered-camera-profile-engine.md docs/adr/0020-layered-camera-profile-and-evidence-engine.md`

Expected: formatting, Clippy, tests, rustdoc, diff hygiene, and plain-punctuation checks pass. Hardware-dependent tests may remain explicitly ignored.

- [ ] **Step 7: Run final hardware verification before enablement**

On the exact authorized ASUS context, compare the selected profile against the
legacy profile over complete lit/backlit/low-light/dark-IR attempts. Verify
detector, recognition, liveness, both applicable PAD models, delivered rates,
continuity, control restoration, password fallback, and p50/p95 latency. Verify
BRIO and NexiGo still select sequential capture. Restore and hash-verify all
system state after the run.

Expected: production enablement proceeds only if the exact reviewed Task 7
record and this repeated gate both pass. Otherwise keep legacy production
selection unchanged.

- [ ] **Step 8: Commit the production integration slice**

```bash
git add crates/irlume-auth/src/capture_plan.rs crates/irlume-auth/src/lib.rs crates/irlume-camera/src/profile_qualification.rs crates/irlume-common/src/diagnostics.rs crates/irlume-daemon/src/diagnostics.rs crates/irlume-cli/src/support_report.rs docs/ARCHITECTURE.md docs/HARDWARE.md docs/adr/0020-layered-camera-profile-and-evidence-engine.md docs/superpowers/specs/2026-09-01-layered-camera-profile-engine-design.md docs/superpowers/plans/2026-09-01-layered-camera-profile-engine.md
git commit -s -m "feat: select qualified camera profiles"
```

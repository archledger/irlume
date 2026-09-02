# Automatic Inference Device Selection Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add observable global `auto | cpu | npu` inference-device selection that preserves ONNX Runtime CPU behavior, proves direct OpenVINO NPU or GPU assignment, and never silently changes device.

**Architecture:** A deep inference-runtime module hides ONNX Runtime and direct OpenVINO adapters behind one backend-neutral session interface. The daemon rebuilds the complete configured ONNX model set for each allowed candidate, accepts only one complete engine with assignment proof, and publishes the engine and a bounded resolution report atomically.

**Tech Stack:** Rust, `ort` 2.0.0-rc.13, `openvino` 0.11.0 with runtime linking, serde, systemd, AppArmor, Fedora/Debian/Nix packaging, Python benchmark contracts.

**Spec:** `docs/superpowers/specs/2026-09-01-automatic-inference-device-selection-design.md`

## Global Constraints

- Public requested values are exactly `auto`, `cpu`, and `npu`; GPU is automatic-only.
- `auto` candidate order is exactly NPU, GPU, CPU.
- One physical device serves the complete configured ONNX model set for one engine lifetime.
- Explicit `npu` never attempts GPU or CPU and always preserves password fallback on failure.
- CPU remains on the existing ONNX Runtime configuration and pinned decision baseline.
- Accelerator candidates use direct OpenVINO, never ONNX Runtime's OpenVINO execution provider or OpenVINO `AUTO`.
- Every OpenVINO compiled model must report exactly the requested `EXECUTION_DEVICES` value.
- TFLite FaceMesh remains separate from ONNX device selection and reporting.
- No preprocessing, threshold, calibration, enrollment, recognition, liveness, or PAD decision changes are authorized.
- Base packages must omit the default-off `experimental-openvino` feature, work without OpenVINO, and gain no accelerator runtime dependencies.
- Merely installing OpenVINO libraries must never activate an accelerator in a released base-package binary.
- NPU and GPU production activation remain blocked by the qualification gates in the approved design.
- Do not install packages, change services, alter hardware, or modify production configuration during software implementation without separate user approval.
- Do not commit, push, create a PR, or merge unless the user explicitly requests it.
- Use exact `Signed-off-by: Wisbendji Fimerlus <archledger236@gmail.com>` if a later user instruction authorizes commits.
- Add no U+2014 characters.

## File Structure

- Create `crates/irlume-vision/src/inference/mod.rs`: backend-neutral compiler interface, candidate runtime, session enum, sanitized evidence.
- Create `crates/irlume-vision/src/inference/ort.rs`: existing ONNX Runtime CPU construction and tensor adaptation.
- Create `crates/irlume-vision/src/inference/openvino.rs`: runtime-loaded OpenVINO discovery, explicit compilation, assignment proof, tensor adaptation, cache handling.
- Keep model preprocessing and output interpretation in `crates/irlume-vision/src/lib.rs`; only replace direct ORT session ownership.
- Keep global candidate resolution in `crates/irlume-daemon/src/main.rs`, where the complete engine and all configured model paths are already assembled.
- Keep requested-policy parsing, candidate/resolved enums, and wire-safe report types in `irlume-common` so vision, daemon, and CLI share one dependency-safe contract.
- Keep accelerator matrix and hardware checks separate from normal package activation.

---

### Task 1: Closed Execution-Device Policy

**Files:**
- Modify: `crates/irlume-common/src/config.rs:21-30,70-126,238-275,1000-1305`
- Modify: `crates/irlume-common/src/lib.rs`

**Interfaces:**
- Consumes: existing `observe_kv`, `read_kv`, `write_kv`, and `IRLUME_CONFIG_DIR` behavior.
- Produces: policy types, candidate/resolved device enums, backend enum, bounded wire report types, visible observations, and strict precedence parsing used by every later task.

- [ ] **Step 1: Write strict parser and precedence tests**

Add tests covering this table:

```rust
#[test]
fn execution_device_policy_precedence_is_strict() {
    use ExecutionDevicePolicy::{Auto, Cpu, Npu};
    use ExecutionDevicePolicySource::{Default, Environment, Settings};

    assert_eq!(resolve_execution_device_policy(None, None).unwrap(),
        EffectiveExecutionDevicePolicy { policy: Auto, source: Default });
    assert_eq!(resolve_execution_device_policy(None, Some("cpu")).unwrap(),
        EffectiveExecutionDevicePolicy { policy: Cpu, source: Settings });
    assert_eq!(resolve_execution_device_policy(Some(OsStr::new("npu")), Some("cpu")).unwrap(),
        EffectiveExecutionDevicePolicy { policy: Npu, source: Environment });
    assert!(resolve_execution_device_policy(Some(OsStr::new("gpu")), Some("cpu")).is_err());
    assert!(resolve_execution_device_policy(None, Some("AUTO")).is_err());
}
```

Also test non-Unicode environment values, empty values, unreadable settings, comment preservation, and unrelated-key preservation.

- [ ] **Step 2: Run RED**

Run: `cargo test -p irlume-common config:: --locked`

Expected: FAIL because the policy types and resolver do not exist.

- [ ] **Step 3: Add the closed contract**

Implement:

```rust
pub const EXECUTION_DEVICE_KEY: &str = "execution_device";
pub const EXECUTION_DEVICE_ENV: &str = "IRLUME_EXECUTION_DEVICE";

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ExecutionDevicePolicy { Auto, Cpu, Npu }

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum ExecutionDevicePolicySource { Environment, Settings, Default }

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct EffectiveExecutionDevicePolicy {
    pub policy: ExecutionDevicePolicy,
    pub source: ExecutionDevicePolicySource,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum CandidateDevice { Cpu, Gpu, Npu }

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ResolvedExecutionDevice { Cpu, Gpu, Npu }

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum InferenceBackend { OnnxRuntime, OpenVino }

pub const MAX_REJECTED_INFERENCE_CANDIDATES: usize = 2;
pub const MAX_INFERENCE_REASON_BYTES: usize = 256;
pub const MAX_AVAILABLE_INFERENCE_DEVICES: usize = 8;
pub const MAX_INFERENCE_DEVICE_BYTES: usize = 96;
pub const MAX_INFERENCE_VERSION_BYTES: usize = 128;

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum InferenceCacheState { Disabled, Cold, Warm, Rebuilt, Unavailable }

pub struct RejectedInferenceCandidate {
    pub device: ResolvedExecutionDevice,
    pub reason: String,
}

pub struct InferenceCacheStatus {
    pub root: String,
    pub state: InferenceCacheState,
    pub runtime_version: Option<String>,
}

pub struct InferenceResolutionReport {
    pub requested_policy: ExecutionDevicePolicy,
    pub policy_source: ExecutionDevicePolicySource,
    pub resolved_device: ResolvedExecutionDevice,
    pub backend: InferenceBackend,
    pub ort_version: Option<String>,
    pub openvino_version: Option<String>,
    pub available_openvino_devices: Vec<String>,
    pub rejected_candidates: Vec<RejectedInferenceCandidate>,
    pub cache: Option<InferenceCacheStatus>,
    pub tflite_facemesh_loaded: Option<bool>,
}

pub fn resolve_execution_device_policy(
    environment: Option<&OsStr>,
    setting: Option<&str>,
) -> Result<EffectiveExecutionDevicePolicy, ExecutionDevicePolicyError>;

pub fn execution_device_policy(
) -> Result<EffectiveExecutionDevicePolicy, ExecutionDevicePolicyError>;
```

Invalid higher-precedence input must return an error instead of consulting the lower-precedence source. The bounded report constructor truncates lists and strings at the constants above. Cache roots are generated internally below `/var/cache/irlume` and never copied from arbitrary third-party error text.

- [ ] **Step 4: Run GREEN and quality checks**

Run:

```bash
cargo test -p irlume-common config:: --locked
cargo clippy -p irlume-common --all-targets --locked -- -D warnings
cargo fmt --all -- --check
```

Expected: PASS.

- [ ] **Step 5: Review checkpoint**

Confirm the diff changes only common policy and wire contracts, accepts no
settable `gpu` spelling, enforces every diagnostic bound, and never turns
malformed input into `auto` or `cpu`.

---

### Task 2: Backend-Neutral Inference Contracts

**Files:**
- Create: `crates/irlume-vision/src/inference/mod.rs`
- Modify: `crates/irlume-vision/src/lib.rs:19-27`

**Interfaces:**
- Consumes: `irlume_common::Result` and f32 model tensors.
- Produces: tensor contracts, the bounded `ModelCompiler` seam, `CandidateRuntime`, and `InferenceSession` used by both adapters and every model wrapper. Device and backend enums come from Task 1.

- [ ] **Step 1: Write fake-adapter contract tests**

Tests must reject wrong input name, wrong rank, wrong fixed dimension, batch other than one, element-count mismatch, missing output, duplicate output, unexpected output shape, and non-f32 metadata. Prove returned outputs remain owned after a fake request is dropped.

Use contracts shaped like:

```rust
const AURAFACE: SessionContract = SessionContract {
    model: "auraface",
    input: TensorContract::f32("data", &[BatchOneOrDynamic, Fixed(3), Fixed(112), Fixed(112)]),
    outputs: &[TensorContract::f32("1333", &[BatchOneOrDynamic, Fixed(512)])],
};
```

- [ ] **Step 2: Run RED**

Run: `cargo test -p irlume-vision inference::tests --locked`

Expected: FAIL because the inference module does not exist.

- [ ] **Step 3: Implement the minimal deep interface**

Implement these public crate interfaces while keeping native adapter types private:

```rust
pub enum DimensionContract { Fixed(usize), BatchOneOrDynamic }

pub struct TensorContract {
    pub name: &'static str,
    pub dimensions: &'static [DimensionContract],
}

pub struct SessionContract {
    pub model: &'static str,
    pub input: TensorContract,
    pub outputs: &'static [TensorContract],
}

pub struct TensorInput<'a> {
    pub name: &'a str,
    pub shape: &'a [usize],
    pub values: &'a [f32],
}

pub struct OwnedTensor {
    pub name: String,
    pub shape: Vec<usize>,
    pub values: Vec<f32>,
}

impl InferenceSession {
    pub fn run_f32(&mut self, input: TensorInput<'_>) -> Result<Vec<OwnedTensor>>;
}

pub trait ModelCompiler {
    fn compile(
        &mut self,
        model: &[u8],
        contract: &'static SessionContract,
    ) -> Result<InferenceSession>;
}
```

`CandidateRuntime` implements `ModelCompiler`. The trait is intentionally
public because `irlume-auth` needs a recording test adapter; it exposes no
native backend type and remains smaller than either dependency interface.

- [ ] **Step 4: Run GREEN**

Run:

```bash
cargo test -p irlume-vision inference::tests --locked
cargo clippy -p irlume-vision --all-targets --locked -- -D warnings
```

Expected: PASS with only the fake adapter compiled.

- [ ] **Step 5: Review checkpoint**

Verify no `ort` or `openvino` type appears in the module's externally usable interface.

---

### Task 3: Preserve ONNX Runtime CPU Behind The Seam

**Files:**
- Create: `crates/irlume-vision/src/inference/ort.rs`
- Modify: `crates/irlume-vision/src/lib.rs:243-713,724-912,1038-1256,1327-1537`

**Interfaces:**
- Consumes: Task 2 contracts and the existing runtime probing at `lib.rs:261-515`.
- Produces: `CandidateRuntime::ort_cpu`, ORT-backed `InferenceSession`, and migrated wrappers with unchanged model decisions.

- [ ] **Step 1: Add ORT adapter regression tests**

Add tests that require the current ORT configuration: API level 24, dynamic library probing, two intra-op threads, graph optimization level 3, no accelerator provider of any kind, named f32 ports, and owned outputs.

Keep the pinned AuraFace embedding regression at `lib.rs:2499-2538` unchanged.

- [ ] **Step 2: Run RED**

Run:

```bash
cargo test -p irlume-vision inference::ort --locked
cargo test -p irlume-vision the_recognizer_embedding_of_a_fixed_input_has_not_moved --locked
```

Expected: the new adapter test fails before implementation; the existing CPU baseline passes.

- [ ] **Step 3: Move ORT construction behind `OrtSession`**

Implement:

```rust
impl CandidateRuntime {
    pub fn ort_cpu() -> Result<Self>;
    pub fn compile(
        &mut self,
        model: &[u8],
        contract: &'static SessionContract,
    ) -> Result<InferenceSession>;
}
```

Remove every accelerator registration from the policy-owned ORT CPU builder.
Legacy CUDA, TensorRT, and CoreML compile-time paths may remain in a separately
named legacy builder for existing compile checks, but `CandidateRuntime::ort_cpu`
must always construct a provider-free ORT CPU session.

- [ ] **Step 4: Migrate every ONNX wrapper**

Replace direct `ort::Session` storage with `InferenceSession` in `Embedder`,
`Adapter`, ONNX `FaceMesh`, `Detector`, `BlazeRescue`, `PadVit`, and `PadIr`.
Give each wrapper a runtime-aware constructor:

```rust
pub fn load_from_memory_with_runtime(
    runtime: &mut dyn ModelCompiler,
    model: &[u8],
) -> Result<Self>;

pub fn load_from_file_with_runtime(
    runtime: &mut dyn ModelCompiler,
    path: &str,
) -> Result<Self>;
```

Existing convenience constructors may create a fresh ORT CPU runtime for
standalone tests and tools. Production daemon construction must later use only
the runtime-aware forms.

- [ ] **Step 5: Run wrapper tests after each migration group**

Run:

```bash
cargo test -p irlume-vision --lib --locked
cargo test -p irlume-vision facemesh_input_shape_tests --locked
cargo test -p irlume-vision mesh_backend_tests --locked
```

Expected: all existing expectations pass unchanged.

- [ ] **Step 6: Review checkpoint**

Reject any threshold, expected embedding, output interpretation, preprocessing,
or TFLite change. Verify model output binding uses names and shapes rather than
new positional assumptions.

---

### Task 4: Direct OpenVINO Adapter And Assignment Proof

**Files:**
- Modify: `Cargo.toml:81-84`
- Modify: `Cargo.lock`
- Modify: `crates/irlume-vision/Cargo.toml:7-36`
- Create: `crates/irlume-vision/src/inference/openvino.rs`
- Modify: `.cargo/config.toml:3-10`
- Modify: `.github/workflows/ci.yml:149-180`

**Interfaces:**
- Consumes: Task 2 session contract and Task 3 candidate runtime enum.
- Produces: runtime-loaded explicit NPU/GPU compilation with authoritative assignment and cache evidence.

- [ ] **Step 1: Write runtime-absent and assignment tests**

Add injected loader tests proving:

```rust
assert!(CandidateRuntime::openvino(Npu, cache).is_err());
assert_eq!(sanitize_devices(["NPU", "GPU.0"]), vec!["NPU", "GPU.0"]);
assert!(validate_execution_devices(Npu, "CPU").is_err());
assert!(validate_execution_devices(Npu, "NPU").is_ok());
assert!(validate_execution_devices(Gpu, "GPU").is_ok());
```

Also test unknown runtime metadata is converted to an error rather than
unwinding, dynamic batch is reshaped only to one, and non-batch dynamic
dimensions are rejected.

- [ ] **Step 2: Run RED**

Run: `cargo test -p irlume-vision --features experimental-openvino inference::openvino --locked`

Expected: FAIL because the feature and adapter do not exist.

- [ ] **Step 3: Add the pinned runtime-linked dependency**

Add:

```toml
openvino = { version = "=0.11.0", default-features = false, features = ["runtime-linking"] }
```

Replace the old `openvino = ["ort/openvino"]` feature with:

```toml
experimental-openvino = ["dep:openvino"]
```

This feature is default off and omitted from every released base-package build
command. Its name and help text must state that qualification is incomplete.

- [ ] **Step 4: Implement explicit OpenVINO compilation**

Construction order must be:

1. `Core::new()` through runtime loading.
2. Query and sanitize available devices.
3. Reject an unavailable requested device.
4. Read ONNX bytes from memory.
5. Validate original ports against the session contract.
6. Reshape only permitted dynamic batch dimensions to one.
7. Set the versioned cache directory.
8. Compile explicitly with `DeviceType::NPU` or `DeviceType::GPU`.
9. Query `PropertyKey::Other("EXECUTION_DEVICES".into())`.
10. Require exact requested assignment.
11. Create the inference request and validate compiled ports again.

Wrap documented binding panic surfaces at the adapter seam and convert them to
bounded errors.

- [ ] **Step 5: Run GREEN and linkage checks**

Run:

```bash
cargo test -p irlume-vision --features experimental-openvino inference::openvino --locked
cargo check -p irlume-vision --all-features --locked
cargo build -p irlume-daemon --release --features experimental-openvino --locked
! readelf -d target/release/irlumed | rg -i 'openvino|ze_loader'
cargo tree -p irlume-vision -e features --features experimental-openvino
```

Expected: PASS; the daemon has no load-time OpenVINO or Level Zero dependency.

- [ ] **Step 6: Add ignored exact-model hardware test**

Add one ignored serial test that discovers all ONNX entries from
`models/SHA256SUMS`, compiles them for explicit NPU, verifies exact
`EXECUTION_DEVICES=NPU`, and performs deterministic f32 inference. It must fail
on a missing or skipped ONNX model.

- [ ] **Step 7: Review checkpoint**

Verify no `AUTO`, `HETERO`, ORT OpenVINO EP, individual model fallback, or
assignment inference from provider presence remains.

---

### Task 5: Inject One Candidate Runtime Through The Complete Engine

**Files:**
- Modify: `crates/irlume-auth/src/lib.rs:47-126,3036-3096,3204-3404`

**Interfaces:**
- Consumes: the bounded `ModelCompiler` interface and every runtime-aware model constructor.
- Produces: complete engine construction where all configured ONNX models share one candidate and TFLite remains separate.

- [ ] **Step 1: Write injected-runtime engine tests**

Use a recording fake runtime to prove:

- YuNet, AuraFace, optional Adapter, ONNX FaceMesh, BlazeFace, ViT, and FLIR all
  receive the same candidate runtime.
- TFLite FaceMesh never reaches the ONNX runtime.
- An absent optional model remains absent.
- In `auto`, a present configured ONNX model's accelerator-specific compile or
  assignment failure rejects NPU or GPU before model-level degradation.
- CPU is the final baseline. A CPU parse or load failure follows the model's
  existing required, optional, or fail-closed PAD behavior.
- In explicit `npu`, core detector or recognizer failure makes face
  authentication unavailable; optional rescue failure remains unavailable;
  required PAD failure keeps its applicable path password-only. None may retry
  another backend.
- Dropping a partial build drops every previously compiled session.

- [ ] **Step 2: Run RED**

Run: `cargo test -p irlume-auth inference_runtime --locked`

Expected: FAIL because engine constructors do not accept a runtime.

- [ ] **Step 3: Add runtime-aware engine construction**

Implement:

```rust
pub fn load_with_runtime(
    runtime: &mut dyn ModelCompiler,
    det_path: &str,
    model_path: &str,
) -> Result<Self>;

pub fn load_with_recognizer_weights_and_runtime(
    runtime: &mut dyn ModelCompiler,
    det_path: &str,
    model: &HashedModel,
) -> Result<Self>;
```

Each ONNX-bearing `with_*` path receives the same `&mut dyn ModelCompiler`.
Represent model outcomes as `NotConfigured`, `Loaded`, or `LoadFailed` before
building the final engine. Absence alone is optional. In `auto`, a present
model's NPU/GPU backend failure rejects that accelerator candidate. Preserve
existing CPU and explicit-NPU model-level availability semantics, but never
retry one failed model through another backend inside the candidate.

- [ ] **Step 4: Run GREEN and existing decision tests**

Run:

```bash
cargo test -p irlume-auth inference_runtime --locked
cargo test -p irlume-auth --lib --locked
cargo test -p irlume-vision --lib --locked
```

Expected: PASS with unchanged decision expectations.

- [ ] **Step 5: Review checkpoint**

Verify a complete engine owns sessions from one candidate only and no global
environment read occurs inside a model wrapper.

---

### Task 6: Global Resolver And Atomic Engine Publication

**Files:**
- Modify: `crates/irlume-daemon/src/main.rs:365-413,622-696,881-945,5849-5935`

**Interfaces:**
- Consumes: effective policy and runtime-aware complete engine construction.
- Produces: exact candidate order, immutable `BuiltEngine`, panic-rebuild preservation, and bounded rejection evidence.

- [ ] **Step 1: Write pure resolver tests**

Test this exact behavior:

```rust
assert_eq!(candidate_order(Auto, Experimental), Ok(&[Npu, Gpu, Cpu]));
assert_eq!(candidate_order(Cpu, Disabled), Ok(&[Cpu]));
assert_eq!(candidate_order(Auto, Disabled), Ok(&[Cpu]));
assert_eq!(candidate_order(Npu, Experimental), Ok(&[Npu]));
assert!(candidate_order(Npu, Disabled).is_err());
```

Injected builders must also prove failed candidates drop before the next call,
only complete engines can return, explicit NPU never invokes another candidate,
failed rebuild retains the old engine and old report together, and no inference
call invokes resolution.

- [ ] **Step 2: Run RED**

Run:

```bash
cargo test -p irlume-daemon --bin irlumed resolve_engine --locked
cargo test -p irlume-daemon --bin irlumed panic_rebuild --locked
```

Expected: FAIL because the resolver does not exist.

- [ ] **Step 3: Extend engine build configuration**

Implement:

```rust
struct EngineBuildConfig {
    // existing fields remain
    execution_device: EffectiveExecutionDevicePolicy,
    accelerator_support: AcceleratorSupport,
    openvino_cache_root: PathBuf,
}

struct BuiltEngine {
    engine: irlume_auth::Engine,
    rgb_pad_status: PadModelStatus,
    ir_pad_status: PadModelStatus,
    inference: InferenceResolutionReport,
}

fn build_engine_for_candidate(
    config: &EngineBuildConfig,
    recognizer: Option<&HashedModel>,
    candidate: CandidateDevice,
) -> Result<BuiltEngine>;

fn resolve_engine_with<F>(
    policy: EffectiveExecutionDevicePolicy,
    mut build: F,
) -> Result<BuiltEngine>
where F: FnMut(CandidateDevice) -> Result<BuiltEngine>;
```

Do not preflight and compile twice. Each candidate invokes complete engine
construction once, and a successful result carries all compiled sessions.
`AcceleratorSupport::Experimental` can be constructed only in a binary built
with the default-off `experimental-openvino` feature. A base-package binary
uses `Disabled`; its `auto` policy resolves CPU and explicit `npu` reports that
the experimental accelerator implementation is unavailable.

- [ ] **Step 4: Preserve policy across panic rebuild**

Capture `EffectiveExecutionDevicePolicy` in `EngineBuildConfig` at startup.
Panic recovery reuses that value and does not reread the environment or
settings. Publish the new `BuiltEngine` atomically only after complete success.

- [ ] **Step 5: Run GREEN**

Run:

```bash
cargo test -p irlume-daemon --bin irlumed resolve_engine --locked
cargo test -p irlume-daemon --bin irlumed panic_rebuild --locked
cargo test -p irlume-daemon --bin irlumed pad_model --locked
```

Expected: PASS.

- [ ] **Step 6: Review checkpoint**

Verify candidate order is application-owned, explicit NPU failure reaches only
password fallback, and no mid-attempt or per-model switching path exists.

---

### Task 7: Additive Bounded Health And Support Diagnostics

**Files:**
- Modify: `crates/irlume-common/src/diagnostics.rs:465-638`
- Modify: `crates/irlume-common/src/lib.rs:960-990,1892-1936`
- Modify: `crates/irlume-daemon/src/diagnostics.rs`
- Modify: `crates/irlume-daemon/src/main.rs:3090-3151,3459-3482`
- Modify: `crates/irlume-auth/src/lib.rs:2298`
- Modify: `crates/irlume-cli/src/support_report.rs:943`

**Interfaces:**
- Consumes: successful resolver evidence and sanitized candidate failures.
- Produces: one optional wire-safe `InferenceResolutionReport` in health and support snapshots.

- [ ] **Step 1: Write old/new compatibility and bound tests**

Test old health JSON into the new type, new health round-trip, existing-field
byte shape when inference is absent, old support snapshot decoding, candidate
count and reason truncation, available-device bounds, and absence of biometric
or tensor fields.

- [ ] **Step 2: Run RED**

Run:

```bash
cargo test -p irlume-common health --locked
cargo test -p irlume-common diagnostics:: --locked
```

Expected: FAIL because the report type and optional fields do not exist.

- [ ] **Step 3: Add optional report fields and bounded projections**

Use the Task 1 report types. Add this bounded projection and update every
`SupportSnapshot::bounded` caller:

```rust
pub fn bounded_inference_report(
    report: InferenceResolutionReport,
) -> InferenceResolutionReport;
```

Add to `Response::Health` and `SupportSnapshot`:

```rust
#[serde(default, skip_serializing_if = "Option::is_none")]
pub inference: Option<InferenceResolutionReport>,
```

Third-party error text must be sanitized and bounded before entering this type.

- [ ] **Step 4: Publish engine and report together**

Extend daemon `EngineBits` and the daemon diagnostic store with the same
optional report. Ensure startup and rebuild update engine, PAD status, health,
and support-snapshot evidence atomically. Existing bounded snapshot producers
that have no daemon resolution pass `None` explicitly.

- [ ] **Step 5: Run GREEN**

Run:

```bash
cargo test -p irlume-common health --locked
cargo test -p irlume-common diagnostics:: --locked
cargo test -p irlume-daemon --bin irlumed health --locked
```

Expected: PASS.

- [ ] **Step 6: Review checkpoint**

Verify diagnostics distinguish requested `auto` from resolved hardware and do
not include frames, crops, tensors, embeddings, identities, scores, credentials,
or unrestricted raw runtime errors.

---

### Task 8: CLI, Doctor, TUI, Machine Contract, And Documentation

**Files:**
- Modify: `crates/irlume-cli/src/main.rs:143-265,3883-4003`
- Modify: `crates/irlume-cli/src/commands.rs:665-839,1525-1570,2076-2169`
- Modify: `crates/irlume-cli/src/doctor_report.rs:42-96`
- Modify: `crates/irlume-cli/src/support_report.rs:70-457`
- Modify: `crates/irlume-cli/src/tui.rs:429-445,874-897,1452-1621`
- Modify: `crates/irlume-cli/src/machine.rs:335-462`
- Modify: `crates/irlume-cli/tests/cli.rs:171-215`
- Modify: `crates/irlume-cli/tests/cli_dispatch.rs:314-456`
- Modify: `crates/irlume-cli/tests/machine_api.rs:342-419`
- Modify: `schemas/machine-api-v1.schema.json:302-451`
- Create: `schemas/fixtures/v1/status-daemon-running-inference.json`
- Create: `schemas/fixtures/v1/doctor-inference.json`
- Modify: `docs/COMMANDS.md`
- Modify: `docs/MACHINE-API.md`
- Modify: `docs/SETUP.md:470-500`

**Interfaces:**
- Consumes: strict policy observations and optional inference health.
- Produces: root-controlled persistence, honest human output, and additive contract-1 machine output.

- [ ] **Step 1: Write CLI dispatch and no-write tests**

Test exactly:

```text
irlume inference-device auto
irlume inference-device cpu
irlume inference-device npu
irlume inference-device status
```

Invalid syntax exits 2 without writing. Non-root writes exit 1 without writing.
Successful writes preserve unrelated settings and state that restart is
required. `status` distinguishes persisted, environment, effective policy,
source, daemon-resolved device, backend, and candidate failures.

- [ ] **Step 2: Run RED**

Run:

```bash
cargo test -p irlume-cli --test cli_dispatch inference_device --locked
cargo test -p irlume-cli --test cli help_lists_every_public_command --locked
```

Expected: FAIL because the command does not exist.

- [ ] **Step 3: Implement command routing and persistence**

Add:

```rust
pub fn inference_device(sub: Option<&str>, args: &[String]) -> ExitCode;
```

Route `(Some("inference-device"), sub)` to it. Validate before calling
`write_kv("settings.conf", EXECUTION_DEVICE_KEY, policy.as_str())`.

- [ ] **Step 4: Extend doctor, support report, and TUI tests**

Add stable doctor IDs:

```text
execution-device-policy
inference-resolution
openvino-runtime
inference-cache
```

An old daemon renders inference as unknown, never CPU. Local runtime probes may
report loadability but never claim the daemon's resolved physical device.

- [ ] **Step 5: Extend machine schema additively**

Add optional `status.data.inference` with bounded enums and arrays. Do not add
it to `required`, close existing objects, or bump contract 1. Preserve every
existing fixture unchanged as old-daemon compatibility evidence and add the two
separately named inference-aware fixtures above.

- [ ] **Step 6: Run GREEN and conformance**

Run:

```bash
cargo test -p irlume-cli --test cli_dispatch inference_device --locked
cargo test -p irlume-cli --test cli help_lists_every_public_command --locked
cargo test -p irlume-cli --test machine_api --locked
cargo test -p irlume-cli support_report --locked
cargo test -p irlume-cli tui::tests::run_checks --locked
python3 scripts/machine-api-conformance.py
```

Expected: PASS.

- [ ] **Step 7: Review checkpoint**

Verify every surface says policy and resolved device separately, GPU is not a
settable value, TFLite is separate, and older daemon/client combinations remain
usable.

---

### Task 9: Versioned Cache, Confinement, Packaging, And Hosted CI

**Files:**
- Create: `packaging/openvino/matrix.toml`
- Create: `scripts/check-openvino-matrix.py`
- Create: `scripts/test-check-openvino-matrix.py`
- Modify: `packaging/systemd/irlumed.service:56-109`
- Modify: `crates/irlume-vision/src/inference/openvino.rs`
- Modify: `crates/irlume-vision/src/inference/mod.rs`
- Modify: `packaging/apparmor/usr.bin.irlumed`
- Modify: `packaging/apparmor/usr.local.bin.irlumed`
- Modify: `packaging/fedora/irlume.spec`
- Modify: `packaging/arch/PKGBUILD`
- Modify: `packaging/selinux/irlume.te`
- Modify: `packaging/debian/build-deb.sh`
- Modify: `packaging/ppa/debian/rules`
- Modify: `scripts/build-ppa-source.sh`
- Modify: `nix/package.nix`
- Modify: `nix/module.nix`
- Modify: `flake.nix`
- Modify: `scripts/check-packaging-parity.sh`
- Modify: `.github/workflows/ci.yml`
- Modify: `.github/workflows/install-matrix.yml`

**Interfaces:**
- Consumes: runtime-linked OpenVINO adapter and cache root.
- Produces: default-off experimental accelerator readiness without changing base-package dependencies or released automatic behavior.

- [ ] **Step 1: Write matrix validation tests**

Record only the measured experimental NPU matrix:

```toml
status = "experimental"
openvino = "2026.2.0-21903-52ddc073857-releases/2026/2"
level_zero_tag = "v1.28.2"
level_zero_commit = "6369d8d642e9c7625e67f38664267f171b8e42dc"
npu_userspace = "1.35.0.20260722-29947505341"
gpu_status = "disabled-unqualified"
```

The checker fails on missing provenance, malformed hashes, enabled GPU without
a matrix, or status other than experimental before release evidence exists.

- [ ] **Step 2: Provision the versioned cache**

Add `CacheDirectory=irlume` and a restrictive mode to systemd, mirror it in
Nix, and use `/var/cache/irlume/openvino/<sanitized-runtime-version>/`.
OpenVINO owns entry keys. Test clean, warm, corrupt, unwritable, and runtime
version change behavior. Cache recovery gets one bounded rebuild attempt and
never changes explicit NPU device.

- [ ] **Step 3: Add narrow AppArmor rules**

Add equivalent rules to both profiles for exact OpenVINO library families,
the versioned cache tree, `/dev/accel/accel[0-9]*`, and
`/dev/dri/renderD[0-9]*`. Do not grant broad `/usr/**`, `/dev/**`, home, or
network access.

- [ ] **Step 4: Keep base packages runtime-free**

Build normal Fedora, Arch, Debian/PPA, and Nix packages without the
`experimental-openvino` feature and without OpenVINO, Level Zero, Intel NPU,
compiler, or GPU dependencies. CI separately compiles and tests the feature,
but no base-package build enables it. Do not create or upload accelerator
payload packages in this task.

- [ ] **Step 5: Add hosted runtime-absence checks**

CI must compile the default-off feature without OpenVINO installed, prove base
packages cannot construct accelerator candidates, prove experimental `auto`
records OpenVINO rejections and resolves CPU, prove explicit experimental `npu`
fails without reaching ORT,
inspect ELF dynamic dependencies, inspect package dependencies and files, parse
both AppArmor profiles, and verify systemd cache directives.

Fedora SELinux currently runs the daemon as `unconfined_service_t`; do not add
speculative broad allow rules. Add a policy comment and parity assertion for
the cache label, then require the enforcing hardware gate to report zero
relevant AVC denials. If a future dedicated daemon domain is introduced, derive
device and library grants from captured AVC evidence.

- [ ] **Step 6: Run packaging verification**

Run available local gates:

```bash
python3 scripts/test-check-openvino-matrix.py
python3 scripts/check-openvino-matrix.py
systemd-analyze verify packaging/systemd/irlumed.service
./scripts/check-packaging-parity.sh
bash packaging/debian/build-deb-container.sh
nix flake check --no-build --show-trace
nix build .#default --no-link --show-trace
```

Inspect resulting package dependency lists and Nix closure for accidental
OpenVINO or Level Zero dependencies. Do not upload artifacts.

- [ ] **Step 7: Review checkpoint**

Verify ordinary installations still function with ORT CPU only, Arch is
covered, and neither installed libraries nor package-manager suggestions can
activate accelerator discovery.

---

### Task 10: Hardware Gate, Full Verification, And Release Boundary

**Files:**
- Create: `.github/workflows/openvino-hardware.yml`
- Create: `scripts/hardware/run-openvino-hardware.sh`
- Create: `scripts/hardware/validate-openvino-hardware.py`
- Create: `scripts/hardware/test-run-openvino-hardware.py`
- Create: `scripts/hardware/test-validate-openvino-hardware.py`
- Create: `benchmarks/test_bench_npu_contracts.py`
- Modify: `benchmarks/bench_npu_models.py`
- Modify: `benchmarks/bench_npu_pipeline.py`
- Modify: `models/SHA256SUMS` only if model inventory itself changes; otherwise treat it as read-only authority.
- Modify: `docs/research/2026-09-01-lunar-lake-npu-benchmark.md`

**Interfaces:**
- Consumes: exact model inventory, Rust adapter ignored test, temporary verified runtime, and bounded report schema.
- Produces: trusted manual/scheduled Lunar Lake evidence while leaving production activation blocked.

- [ ] **Step 1: Write pure benchmark and validator tests**

The benchmark contract must derive all ONNX models from `models/SHA256SUMS`,
exclude only TFLite from OpenVINO assignment, fail on missing or skipped models,
require exact assignment for every graph, require inference for every graph,
and require positive NPU busy-time movement.

- [ ] **Step 2: Add a trusted hardware workflow**

Use only `workflow_dispatch` and schedule, both checking out `refs/heads/main`
from the repository itself. Never use `pull_request` or `push`. Set
`permissions: { contents: read }`, runner labels `[self-hosted, lunar-lake,
npu]`, `timeout-minutes: 45`, and a single non-canceling concurrency group.
Pin actions by commit SHA. Upload only bounded JSON and sanitized logs, never
frames, tensors, embeddings, identities, or credentials.

- [ ] **Step 3: Run hosted-contract tests**

Run:

```bash
python3 benchmarks/test_bench_npu_contracts.py
python3 scripts/hardware/test-run-openvino-hardware.py
python3 scripts/hardware/test-validate-openvino-hardware.py
bash -n scripts/hardware/run-openvino-hardware.sh
python3 -m py_compile benchmarks/bench_npu_models.py benchmarks/bench_npu_pipeline.py scripts/hardware/validate-openvino-hardware.py
```

Expected: PASS without hardware.

- [ ] **Step 4: Run full software gates**

Run:

```bash
cargo fmt --all -- --check
cargo check --workspace --all-targets --locked
cargo clippy --workspace --all-targets --all-features --locked -- -D warnings
./scripts/run-tests-guarded.sh --min 1900 -- cargo test --workspace --locked
RUSTDOCFLAGS="-D warnings" cargo doc --workspace --no-deps --locked
sha256sum --check --strict SHA256SUMS
git diff --check
```

Run the checksum command from `models/` because manifest paths are relative to
that directory.

- [ ] **Step 5: Run explicitly authorized temporary NPU gates**

With the existing `/tmp/opencode/npu-spike` runtime only, run:

```bash
env LD_LIBRARY_PATH="$OPENVINO_LIBS:$LEVEL_ZERO_LIBS:$NPU_LIBS" \
  ZE_ENABLE_ALT_DRIVERS="$NPU_LIBS/libze_intel_npu.so.1.35.0" \
  IRLUME_EXECUTION_DEVICE=npu \
  cargo test -p irlume-vision --locked --features experimental-openvino \
  -- --ignored openvino_npu_runs_every_shipped_onnx_model --test-threads=1

env LD_LIBRARY_PATH="$OPENVINO_LIBS:$LEVEL_ZERO_LIBS:$NPU_LIBS" \
  ZE_ENABLE_ALT_DRIVERS="$NPU_LIBS/libze_intel_npu.so.1.35.0" \
  "$NPU_VENV/bin/python" benchmarks/bench_npu_models.py

env LD_LIBRARY_PATH="$OPENVINO_LIBS:$LEVEL_ZERO_LIBS:$NPU_LIBS" \
  ZE_ENABLE_ALT_DRIVERS="$NPU_LIBS/libze_intel_npu.so.1.35.0" \
  "$NPU_VENV/bin/python" benchmarks/bench_npu_pipeline.py
```

The hardware runner resolves the named roots from the verified matrix instead
of trusting caller-provided paths. Also run the assignment-mismatch negative
test, concurrent residency test, clean/warm/corrupt cache tests, and
suspend/resume only if the user separately authorizes the system operation.

- [ ] **Step 6: Keep release activation blocked**

Do not add accelerator dependencies or enable released NPU automatic discovery
until qualified-corpus final detector, PAD, liveness, and recognition decisions,
cross-backend enrollment/authentication, Rust end-to-end timing, cache upgrade,
standard permissions, zero confinement denials, suspend/resume, and same-domain
energy gates pass. GPU additionally needs its own matrix, all-model assignment,
performance, and qualified-corpus parity.

- [ ] **Step 7: Final review and handoff**

Run a security-focused differential review, verify no threshold or production
activation change, record exact test results and external state, and refresh
`project-irlume.md`, `project-ux5406s-device.md` when hardware evidence changes,
and `index.md`.

## Execution Notes

- Tasks 1 through 9 produce software support that remains safe when OpenVINO is
  absent.
- Task 10 separates pure hosted checks from operations requiring the measured
  Lunar Lake host and explicit user authorization.
- Any evidence showing the direct Rust adapter cannot preserve existing model
  contracts must stop implementation and amend the approved design rather than
  weakening assignment proof or changing model decisions.
- Any distribution lacking a supportable OpenVINO matrix remains CPU-only.
- Mark the benchmark report's earlier model-by-model ORT OpenVINO implementation
  suggestion as superseded by ADR-0021 without altering measured results.

# Automatic Inference Device Selection Design

## Problem

Irlume's shipped ONNX models currently run through one shared ONNX Runtime
session builder. CPU is the production default. Compile-time features can
register accelerator execution providers, including OpenVINO, but runtime
configuration cannot request a device and health output cannot prove which
physical device executed a graph. The current OpenVINO registration also
permits silent CPU fallback.

An isolated benchmark on the ASUS UX5406SA proved that OpenVINO 2026.2 can
compile and execute all six shipped ONNX graphs on the Lunar Lake NPU. Each
compiled graph reported `EXECUTION_DEVICES=NPU`, kernel NPU busy time moved,
and the primary five-model sequence averaged 16.431 ms. This establishes an
implementation opportunity, not production authorization. Qualified-corpus
final-decision parity, package compatibility, GPU behavior, cache lifecycle,
suspend and resume, permissions, and same-domain energy measurements remain
open.

The implementation therefore needs a device policy that is automatic by
default, strict when NPU is explicitly requested, observable, and unable to
change devices during an authentication attempt.

## Goals

- Expose exactly `auto`, `cpu`, and `npu` as user-requested policies.
- Make `auto` try NPU, then Intel GPU, then CPU.
- Resolve one device for the complete configured ONNX model set.
- Prove every OpenVINO model's physical assignment before accepting a device.
- Preserve the existing ONNX Runtime CPU path and its decision behavior.
- Keep TFLite FaceMesh assignment separate from ONNX device reporting.
- Prevent explicit NPU requests from silently falling back to another device.
- Preserve PAM password fallback and fail-closed PAD availability.
- Report requested policy, effective source, resolved hardware, backend,
  candidate failures, runtime versions, and cache state without biometric
  content.
- Keep accelerator deployment experimental until its qualification gates pass.

## Non-Goals

- Exposing an explicit `gpu` policy.
- Choosing a different device for each model.
- Changing devices during one authentication attempt.
- Retuning model preprocessing, thresholds, calibration, or decisions.
- Treating OpenVINO `AUTO` as proof of a strict NPU, GPU, CPU fallback order.
- Shipping an unqualified accelerator path as production-ready.
- Replacing the existing TFLite FaceMesh backend.
- Installing or changing host drivers, firmware, services, or production
  configuration as part of implementation development.

## Terminology

**Execution-device policy**:
The user-requested `auto`, `cpu`, or `npu` behavior. A policy is not a physical
device.

**Resolved execution device**:
The single CPU, GPU, or NPU accepted for the complete configured ONNX model set
during one engine build.

**Candidate attempt**:
One bounded attempt to build the complete configured ONNX model set for a
specific physical device.

**Configured ONNX model set**:
Every shipped ONNX model expected to load for the current daemon configuration.
The TFLite FaceMesh model is not part of this set.

**Resolution report**:
A bounded, non-biometric record of the requested policy, its source, the
accepted backend and device, and rejected candidate reasons.

## Evidence And Constraints

The current implementation and deployment impose these constraints:

- `irlume-vision` centralizes ONNX Runtime construction, but each model wrapper
  currently stores and invokes an ONNX Runtime session directly.
- The packaged runtime contains only the ONNX Runtime core library. It does not
  include `libonnxruntime_providers_openvino.so` or a matched OpenVINO stack.
- ONNX Runtime does not expose a reliable post-session interface that reports
  which execution provider or physical device actually executed a graph.
- Direct OpenVINO exposes available devices and a compiled model's
  `EXECUTION_DEVICES` property.
- The `openvino` Rust crate can dynamically load OpenVINO, read ONNX from
  memory, compile for CPU, GPU, or NPU, create inference requests, and query
  arbitrary compiled-model properties. It is an Intel-maintained binding over
  the OpenVINO C interface, but OpenVINO does not list Rust among its officially
  supported language interfaces.
- The benchmark used OpenVINO 2026.2 and Intel NPU userspace 1.35. Fedora 44
  currently offers a different OpenVINO 2025.1 and Intel NPU 1.32 combination,
  so benchmark results do not transfer without rerunning the complete gate.
- GPU performance and parity have not been measured.

## Decision

Use application-controlled global resolution with two internal inference
adapters.

- The existing ONNX Runtime adapter remains the CPU implementation.
- A direct OpenVINO adapter implements explicit NPU and GPU execution.
- OpenVINO's meta-device `AUTO` is not used for policy resolution.
- One engine build uses one physical device for all configured ONNX models.
- OpenVINO candidates are accepted only when every compiled model reports the
  exact requested physical device through `EXECUTION_DEVICES`.

### ExecutionDevicePolicy

Define a closed policy with three values:

| Value | Behavior |
|---|---|
| `auto` | Try the complete model set on NPU, then GPU, then CPU |
| `cpu` | Build the complete model set through the existing ONNX Runtime CPU path |
| `npu` | Build explicitly for OpenVINO NPU and reject any other assignment |

The default is `auto`. An invalid value is a configuration error and never
silently becomes `auto` or `cpu`.

The persisted key is `execution_device` in `/etc/irlume/settings.conf`.
`IRLUME_EXECUTION_DEVICE` has higher precedence. The effective configuration
records whether it came from the environment, settings, or the default.

The CLI exposes:

```text
irlume inference-device <auto|cpu|npu|status>
```

Writing a persisted value requires root and states that a daemon restart is
required. `status` distinguishes the persisted value, environment override,
effective policy, and the daemon's resolved physical device.

### Inference Runtime Module

Add a deep inference-runtime module in `irlume-vision`. Its external interface
contains only:

- requested policy and effective source;
- candidate-specific runtime construction;
- backend-neutral ONNX model compilation and inference;
- resolved physical-device proof; and
- a bounded resolution report.

ONNX Runtime and OpenVINO are internal adapters behind one backend-neutral
session type. Their native session, tensor, and output types do not escape into
the model wrappers. Existing model preprocessing and output interpretation
remain outside the adapters and unchanged.

The adapter interface must preserve the model wrappers' actual needs rather
than mirror either dependency's complete interface. All current shipped ONNX
graphs use f32 tensors, but the interface must validate names, ranks, shapes,
and element types at the adapter seam instead of assuming they match.

### Global Resolution

The daemon parses policy once and stores it in engine-build configuration. An
engine-build resolver invokes the existing complete engine construction for
each allowed candidate:

```text
auto: NPU build -> GPU build -> CPU build
cpu:  CPU build
npu:  NPU build
```

Each candidate gets a fresh candidate-specific inference runtime. Every ONNX
model constructor receives that runtime. In `auto`, any present configured
model that cannot load, compile, validate its assignment, or create its required
inference session rejects an NPU or GPU candidate before Irlume considers
model-level degradation. A failed candidate and all of its partially compiled
sessions are dropped before the next candidate begins. CPU is the final
qualified baseline and retains existing core, optional, and fail-closed PAD
availability semantics.

Successful resolution returns the complete engine and its immutable resolution
report together. This avoids a separate preflight that would compile every
model twice. Panic recovery retains the requested policy and reruns the same
global resolution procedure.

The resolved device stays fixed for the engine lifetime. There is no mid-call,
mid-attempt, or per-model switching.

### Failure Semantics

Explicit `npu` is strict:

- OpenVINO must be loadable.
- NPU must appear in available devices.
- Every successfully loaded ONNX model must compile for NPU.
- Every compiled model must report `EXECUTION_DEVICES=NPU`.
- No GPU or CPU inference fallback is permitted.

Explicit NPU does not retry another candidate. Core detector or recognizer
failure makes face authentication unavailable and leaves PAM password fallback.
Required PAD model failure preserves ADR-0019's existing password-only behavior
for its applicable path. Optional rescue or measurement models preserve their
existing availability semantics. Every model that remains loaded uses NPU;
none gains permission to fall back to another inference device.

In `auto`, a rejected NPU or GPU candidate records a bounded reason and permits
the next candidate. CPU is the final candidate. Core CPU failure remains an
engine or daemon model-load error because no inference backend remains;
supporting model failures retain their established availability behavior.

Inference errors after successful resolution do not trigger a device change
during an authentication attempt. Explicit NPU remains unavailable and falls
back to the password. Automatic mode may rerun global resolution only through
the daemon's controlled whole-engine rebuild path.

### Diagnostics And Wire Contract

Daemon health, doctor output, the TUI, and support reports add:

- requested execution-device policy;
- effective policy source;
- resolved execution device;
- inference backend;
- ORT and OpenVINO versions when available;
- available OpenVINO devices;
- bounded rejected-candidate reasons;
- cache location and state; and
- separate TFLite model status.

Machine-readable fields are additive and optional so older clients can decode
new daemon health responses and newer clients can decode old responses. A
policy is never rendered as hardware. `auto` may resolve to `npu`, `gpu`, or
`cpu`; diagnostics print both facts.

Startup logs record policy and resolution once. Candidate reasons are bounded
by count and length, contain no model input or output values, and avoid raw
third-party error dumps. No frame, crop, tensor, embedding, identity, score, or
credential enters the resolution report.

### Cache And Lifecycle

Use a versioned OpenVINO cache below `/var/cache/irlume`, provisioned by
`CacheDirectory=irlume` in the systemd unit. The OpenVINO runtime owns cache
entry keys and compilation artifacts. Irlume records the cache root and runtime
version but does not invent a second model-cache format.

A corrupt or incompatible cache entry may be removed and rebuilt through a
bounded recovery path. Cache failure does not authorize a different physical
device in explicit `npu` mode. Automatic mode may reject that candidate and
continue only before an engine is published.

Suspend and resume do not alter the published resolution. A post-resume device
failure follows the same inference-error behavior and may cause a controlled
whole-engine rebuild outside the authentication attempt.

## Packaging

Build the OpenVINO adapter with runtime linking. The base package continues to
work with the existing bundled ONNX Runtime CPU library. The direct adapter is
behind a default-off `experimental-openvino` compile feature until release
qualification passes. Base-package binaries omit that feature, so installing
OpenVINO libraries cannot activate an unqualified accelerator. In those
binaries `auto` resolves to CPU and explicit `npu` reports that accelerator
support is unavailable. Experimental builds enable the feature deliberately.
Qualified accelerator dependencies and enabled binaries are packaged
separately where each distribution can provide a qualified version matrix.

The accelerator package must keep these versions aligned and tested together:

- OpenVINO runtime, ONNX frontend, and selected device plugins;
- Level Zero loader;
- Intel NPU driver and compiler for NPU execution; and
- Intel GPU userspace required by the OpenVINO GPU plugin.

AppArmor grants are narrow and cover only required OpenVINO libraries, the
versioned cache path, `/dev/accel/accel*`, and `/dev/dri/renderD*`. Packaging
must not rely on world-readable or world-writable accelerator nodes. Existing
camera, media-controller, TPM, and daemon confinement behavior remains intact.

The normal package resolves `auto` to CPU because accelerator construction is
compiled out, not merely because runtime discovery happens to fail.
Accelerator implementation support is not production authorization.

## Alternatives Considered

### ONNX Runtime OpenVINO Execution Provider

This would require fewer model-wrapper changes, but distribution would need a
matched custom ONNX Runtime core, OpenVINO provider library, and OpenVINO
runtime. The current package contains only the CPU-oriented core. More
importantly, ONNX Runtime cannot expose authoritative post-session physical
assignment. Registration or provider presence is not proof that every graph
executed on the requested device. This does not meet the observability
contract.

### OpenVINO AUTO Meta-Device

`AUTO` can select among CPU, GPU, and NPU, but its suitability logic is not the
same contract as an application-controlled strict fallback ladder. It may also
resolve different models differently. That violates global single-device
resolution and makes qualification harder.

### Per-Model Resolution

Selecting the best device independently for each model could improve throughput
on mixed-support hardware. It was rejected because it creates mixed execution,
larger diagnostics and cache state, more parity combinations, and less
predictable failure behavior. The measured Lunar Lake NPU already compiled all
shipped graphs, so that complexity is not justified by current evidence.

### Direct OpenVINO For CPU Too

Using OpenVINO for all three physical devices would reduce the number of
adapters. It would also replace the qualified ONNX Runtime CPU baseline and
change CPU numerical and packaging behavior without evidence that such a
migration is needed. CPU therefore remains on ONNX Runtime.

## Verification And Release Gates

Implementation follows test-driven development.

Pure and injected tests cover:

- parsing, defaults, precedence, and invalid configuration;
- exact candidate order;
- global all-model acceptance;
- strict NPU assignment and failure;
- visible automatic candidate rejection and CPU fallback;
- cleanup of partially built candidates;
- panic-rebuild policy preservation;
- additive health serialization and old-client compatibility;
- CLI and TUI rendering; and
- bounded, non-sensitive failure reasons.

Adapter contract tests cover input and output names, ranks, shapes, element
types, and inference result ownership. Existing decision-layer tests must pass
without threshold or expectation changes.

Hardware-gated tests must compile every shipped ONNX graph, query its
`EXECUTION_DEVICES`, run inference, and reject assignment mismatch. NPU release
also requires qualified-corpus final detector, PAD, liveness, and recognition
decision parity, cache and upgrade behavior, permissions, suspend and resume,
and same-domain privileged energy measurement.

GPU cannot participate in released automatic selection until exact-model
performance and qualified-corpus parity are measured on supported Intel GPU
hardware. Until then, GPU support remains implemented but experimental.

Verification includes focused tests, locked workspace tests, warnings-denied
Clippy, rustfmt, packaging and confinement checks, model checksums, and the
preserved NPU benchmark harness.

## Rollback

- Set `execution_device=cpu` or `IRLUME_EXECUTION_DEVICE=cpu` and restart the
  daemon to force the existing CPU backend.
- Remove the optional accelerator package to make OpenVINO unavailable; `auto`
  then resolves to CPU.
- No model, threshold, enrollment, camera qualification, or PAM configuration
  migration is required.
- OpenVINO cache files are derived artifacts and may be deleted while the
  daemon is stopped.

## Approval

Approved by the user on 2026-09-01. The user authorized evidence-driven detail
changes during implementation, provided the documented policy, strict failure,
global resolution, observability, and production-qualification constraints are
preserved or any material change returns for review.

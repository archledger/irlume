# ADR-0033: GPU inference under per-model certification

## Status

Proposed 2026-10-10.

Amends ADR-0022 section 15 ("No GPU"): that section reserved GPU devices
for a revisit "only with evidence that CPU-only users face unacceptable
latency". The #1053 Phase 2 measurements are that evidence (the Context
records them). Everything else in ADR-0022 is unchanged and binding:
this ADR adds the GPU as an eligible device under the same regime. It
depends on the ADR-0022 amendment of 2026-10-09 (provider selection,
closed native loading) and on the recognizer device selection of #1053
(`recognizer_device`, merged as #1054).

By itself this ADR admits no loading profile, certifies no model, and
changes no placement: `CERTIFIED` stays empty and the recognizer stays on
CPU until the gates below are satisfied on real hardware.

## Context

The device selection of #1053 reports `gpu` as a selected target but no
build admits GPU placement. Phase 2 of #1053 measured the recognizer
(glintr100, 260,694,151 bytes, input NCHW 3x112x112 f32 through the
production `preprocess_arcface`) on identical synthetic inputs across the
fleet ([the measurement record](../research/2026-10-10-gpu-benchmarks.md)):

| Host and lane | Median per inference |
|---|---|
| minihost, ADL-N CPU, production ONNX Runtime session | 258.5 ms |
| minihost, ADL-N integrated GPU, OpenVINO GPU | 102.0 ms |
| minihost, ADL-N CPU, OpenVINO CPU | 178.6 ms |
| archhost, 16-thread CPU, production ONNX Runtime session | 108.7 ms |
| archhost, RTX 3060 (dGPU), ONNX Runtime CUDA EP | 7.6 to 7.8 ms |

Three findings shape the decision:

1. An Intel integrated GPU through the same OpenVINO C API provider
   irlume already validates for the NPU is 2.5x faster than the weakest
   fleet CPU for this model, at compile and memory costs the ADR-0022
   regime already budgets (3.37 s first compile, 0.71 s cache-warm,
   +0.3 to +0.5 GiB resident).
2. A discrete GPU through an ONNX Runtime execution provider is faster
   still (14x its own CPU) but is a different trust architecture: a
   CUDA probe on archhost measured the `ort` crate's default of silently
   running on CPU when the provider library cannot load, a cuDNN
   absence that surfaces only at the first convolution after session
   creation succeeds, and one teardown-time heap corruption.
3. Output drift is real and device-specific: the OpenVINO GPU lane
   reproduced cosine 0.999524 to 0.999687 against the CPU reference on
   every run, stable but not the CPU function. This is exactly the class
   of difference the ADR-0022 certification gates exist to judge, and it
   is why "the GPU is fast" can never by itself place a model.

## Decision

### 1. The GPU joins the ADR-0022 regime; no rule is relaxed

Every ADR-0022 rule applies to the GPU with the device substituted:
authentication probes only (section 2), the per-model certification table
(section 3), platform identity (section 4, extended below), system
OpenVINO loaded at run time through the validated provider (section 5 and
its 2026-10-09 amendment), a fixed batch and compile configuration
(section 6), the certification requirements (section 7), compile at
startup (section 8), fallback to the CPU session on any failure
(section 9), one restart for a crash or hang (section 10), a daemon-owned
cache (section 11), the kill switches and `recognizer_device` semantics
of #1053 (section 12), and reporting (section 13).

### 2. The provider is the validated OpenVINO C API path

GPU placement uses the same root-owned, soname-validated
`libopenvino_c.so.2621`/`.2620` provider loading the NPU uses, compiled
for one explicit GPU device. Exactly one GPU is selected; `MULTI`,
`HETERO` and `AUTO` devices stay out of scope for placement, because
they spread one model across devices or choose them per run, which no
identity or certification can name. Multi-GPU systems must disambiguate
(`GPU.0`, `GPU.1`): an identity that cannot name one device refuses
placement. The default `PERFORMANCE_HINT` for latency-oriented compile
configurations matches the NPU precedent (batch 1, LATENCY).

### 3. GPU platform identity extends the ADR-0022 identity

The identity adds the GPU plugin version, the GPU device name and PCI
vendor and device of the selected render node, the OpenCL ICD or Level
Zero loader the GPU plugin resolves, the GPU driver version, the compile
configuration, and the SHA-256 of every runtime library the daemon maps
once the GPU is enumerated, under the same one-open-file inode discipline
as ADR-0022 section 4. A driver or compute-runtime update is a different
identity; a kernel release is not a field, for the same reason as
ADR-0022.

### 4. Loading admission stays closed until the GPU conformance profile exists

The GPU loads more of the system than the NPU path names today: the
compute runtime, its ICD or Level Zero stack, and parts of the graphics
driver. Opening GPU placement requires the same installation and launch
conformance evidence ADR-0022's 2026-10-09 amendment demands for the
NPU, extended to that inventory. No setting bypasses it; until then a
`gpu` selection keeps the recognizer on CPU with the selection's reason
reported, exactly as #1054 ships today.

### 5. Certification gates are unchanged and binding

A GPU certification must reproduce, on the target GPU identity and the
CPU reference: the startup parity canary, the decision fingerprint over
every decision arm, zero impostor accepts that the CPU reference denies,
zero presentation-attack flips, and the drift bounds per arm, with the
compile configuration pinned as an identity field. The measured 0.9995
cosine band is an input to those gates, not a pass of them. Enrollment,
self-tests and every non-probe path stay on CPU.

### 6. `auto` ranks certification, never device class

The #1053 contract holds: `auto` places the recognizer on an accelerator
only when that accelerator's model certification passed on its identity.
Ranking among several certified devices is set by measured evidence on
the decision hardware (the UX5406S rerun of the measurement record is
pending), not by device class or vendor.

### 7. Execution-provider GPUs stay out of scope

The CUDA and TensorRT execution provider features remain compile-time
off and admit no placement. The archhost probe measured why they need
their own ADR before any use: provider registration defaults to failing
silently (CPU execution with no error; the strict opt-in must be
mandatory and verified), a missing cuDNN surfaces only at inference time
after a successful session creation, one run corrupted the heap at
session teardown, and the dependency closure (driver, CUDA runtime,
cuBLAS, cuDNN; about 2.6 GiB on the probe host) is a trust surface this
project has not audited. The measurements are recorded so a future ADR
starts from evidence.

## Consequences

- ADR-0022 section 15 no longer reserves the GPU; its revisit condition
  is discharged by this record.
- The implementation order is fixed by Phasing below; nothing in this
  ADR requires a behavior change in the same PR.
- `doctor` and `status --json` will eventually report GPU runtime
  discovery and qualification as they do for the NPU; the selection row
  of #1054 already reports the configured target.
- A certified GPU placement changes the recognizer's operating point
  only within the certified decision fingerprint; re-certification
  follows every identity change, as ADR-0022 already requires.
- Discrete-GPU users keep CPU or OpenVINO-GPU placement; the CUDA
  evidence stays on file for a later decision.

## Phasing

1. Device selection contract: merged (#1054).
2. Benchmarks and probe evidence: done, this record's Context and the
   measurement record.
3. Implementation: the GPU device target through the validated provider
   machinery (enumeration, identity, compile, retirement), hardware-gated
   tests runnable on an Intel GPU host (minihost today), no loading
   admission change.
4. Certification runs on the decision hardware (UX5406S; minihost as the
   proxy), producing ADR-0022 section 7 evidence per identity.
5. Loading-admission profile for the GPU inventory, reviewed separately
   (the AppArmor work of #1046 belongs to the same track).
6. Placement of `auto` on a certified GPU, if the ranking evidence
   supports it.

## Acceptance tests

- Hardware-gated (ignored) GPU tests mirroring the `npu_hw_*` lanes:
  discovery and identity on a real GPU, compile under the fixed
  configuration, the parity canary against the CPU reference, and
  retirement to CPU on drift or mapped-library mismatch.
- No-GPU CI lanes keep the CPU answers: an absent GPU is a reason, not a
  build or start failure, in both `npu` and default builds.
- Identity tests: `GPU.0`/`GPU.1` disambiguation refuses an ambiguous
  identity; a rebuilt compute-runtime library is a different identity
  under the inode discipline.
- A `gpu` selection without an admitted loading profile reports the
  admission refusal as its CPU reason (already true of #1054 for the
  unadmitted build; the admission-aware reason lands with phase 3).
- Source-shape or unit test: no execution provider is registered without
  the strict failure mode if the inert features are ever built (phase 3
  seam; the archhost evidence is the reason).
- The certification table stays empty unless every gate of section 5
  passes on the named identity.

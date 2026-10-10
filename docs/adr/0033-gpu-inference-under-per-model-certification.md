# ADR-0033: GPU inference under per-model certification

## Status

Proposed 2026-10-10.

Amends ADR-0022 section 15 ("No GPU") on the maintainer's decision to
reopen GPU support during #1053. Section 15 asked for "evidence that
CPU-only users face unacceptable latency"; the #1053 Phase 2 measurements
show the accelerator is much faster, not that CPU users today face a
failed budget: authentication is capture-bound and no user-facing
latency target is violated. This ADR therefore does not claim the
section 15 condition is met by measurement alone; it records the
maintainer exercising the revisit with the measurements as motivation,
and keeps CPU the default (`auto` stays on CPU until a certification
passes). Everything else in ADR-0022 is unchanged and binding:
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

No end-to-end latency budget is recorded here: the numbers below are
per-inference recognizer costs on synthetic inputs, the motivation for
the revisit rather than proof of a user-facing failure.

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
for one explicit GPU device. `MULTI`, `HETERO` and `AUTO` devices stay
out of scope for placement, because they spread one model across devices
or choose them per run, which no identity or certification can name. A
system that exposes more than one GPU refuses GPU placement until a
reviewed rule selects one: `recognizer_device=gpu` is a class-level
setting with no device index, and inventing an implicit ordering
(first, fastest, any) would place a model on a device the certification
never named. Exactly one visible GPU, or no placement; a device-index
setting is future work with its own evidence. The default `PERFORMANCE_HINT` for latency-oriented compile
configurations matches the NPU precedent (batch 1, LATENCY).

### 3. GPU platform identity extends the ADR-0022 identity

The identity adds the GPU plugin version, the GPU device name and PCI
vendor and device of the selected render node, the OpenCL ICD or Level
Zero loader the GPU plugin resolves, the GPU driver version, the build of
the GPU firmware the kernel loaded where the driver exposes it (on Intel
integrated graphics the GuC and HuC firmware versions of the render
node), the compile configuration, and the SHA-256 of every runtime
library the daemon maps once the GPU is enumerated, under the same
one-open-file inode discipline as ADR-0022 section 4. Like that section,
a firmware build that cannot be read makes the identity unreadable and
placement refuses, and the firmware is a field because a driver version
does not imply it. A driver or compute-runtime update is a different
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
CPU reference, the ADR-0022 section 7 gates in their original direction:
the startup parity canary, the decision fingerprint over every decision
arm, and no input the CPU reference denies that the GPU grants, over both
the impostor corpus and the presentation-attack corpus. The direction is
the ADR-0022 rule: no new grants. A GPU that denies more attacks or more
impostors than the CPU reference is not disqualified by that alone. The
drift bounds per arm, with the compile configuration pinned as an
identity field, are unchanged. The measured 0.9995 cosine band is an
input to those gates, not a pass of them. Enrollment, self-tests and
every non-probe path stay on CPU.

### 6. `auto` ranks certification, never device class

The #1053 contract holds: `auto` places the recognizer on an accelerator
only when that accelerator's model certification passed on its identity.
Ranking among several certified devices is set by measured evidence on
the decision hardware (the UX5406S rerun of the measurement record is
pending), not by device class or vendor.

### 7. Execution-provider GPUs stay inert

The CUDA, OpenVINO-EP, TensorRT and CoreML execution-provider features
of `irlume-vision` are not a placement path, and as of this ADR they are
inert in every build: a custom build compiled with one of those features
no longer registers its provider in an ONNX session at all (these
sessions serve the recognizer, the detector and the PAD cues, so
registration placed authentication-adjacent computation outside
`CERTIFIED`, with the silent-CPU default on failure, both measured in
the archhost probe). Registration exists only behind the exact escape
`IRLUME_TEST_ALLOW_UNCERTIFIED_EP=1`, announced by an unconditional
warning (not the opt-in debug log, in the spirit of the virtual-camera
escape's visibility), and is strict there: a provider that cannot load
is an error, and CPU fallback for operations the registered providers
cannot cover is disabled, so a graph the providers cannot fully execute
refuses instead of running partly on the CPU unannounced. A future ADR that wants an
execution-provider lane must still solve what the probe measured: the
silent-fallback default, a missing cuDNN surfacing only at inference
time after a successful session creation, one teardown-time heap
corruption, and the dependency closure (driver, CUDA runtime, cuBLAS,
cuDNN; about 2.6 GiB on the probe host) that this project has not
audited.

### 8. A GPU kill switch beside the selection

`recognizer_device` names an intent; it is not an emergency switch, the
same way the NPU needed its own. The GPU gets `gpu` in
`settings.conf` and `IRLUME_GPU` on the daemon with ADR-0022 section 12
semantics substituted: either source disabling wins; an empty, unknown
or non-UTF-8 value, an unreadable settings file, or a duplicated key
disables GPU use; a recognized on value leaves admission and
certification to decide and enables nothing by itself. The switch
disables GPU placement independently of the NPU switch: the NPU-named
keys stay NPU-only, and coupling them would leave the GPU running
precisely when an operator believed every accelerator was off.

## Consequences

- ADR-0022 section 15 no longer reserves the GPU; the maintainer's
  revisit of it is recorded here, with CPU the default until a
  certification passes.
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
   machinery (enumeration, identity with firmware, compile, retirement,
   the `gpu` kill switch, the single-GPU rule), hardware-gated tests
   runnable on an Intel GPU host (minihost today), no loading admission
   change. The execution-provider inertness of section 7 landed with
   this ADR, ahead of the rest.
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
- Identity tests: a system exposing more than one GPU refuses placement
  (section 2); a rebuilt compute-runtime library, or a GPU firmware
  build that cannot be read, is a different or unusable identity under
  the inode discipline (section 3).
- A `gpu` selection without an admitted loading profile reports the
  admission refusal as its CPU reason (already true of #1054 for the
  unadmitted build; the admission-aware reason lands with phase 3).
- The execution providers stay escape-gated and strict in every feature
  combination: the source-shape test landed with this ADR
  (`execution_providers_stay_escape_gated_and_strict`).
- The `gpu`/`IRLUME_GPU` switch follows the section 12 semantics: either
  source disabling wins, malformed values disable, and an on value
  admits nothing (phase 3 tests beside the `npu` switch tests).
- The certification table stays empty unless every gate of section 5
  passes on the named identity.

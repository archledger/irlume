# ADR-0033: GPU inference under per-model certification

## Status

Withdrawn 2026-10-30 by [ADR-0038](0038-remove-gpu-inference.md), except section 7
as narrowed there. The text below is kept as the record.

Proposed 2026-10-10. Amended 2026-10-11 (driver identity), 2026-10-21
(precision `f32`, ranking evidence, measured hosts) and 2026-10-22 (the
runtime-suspend arm where the driver holds the device; the certification
key binds the numerics set).

Amended 2026-10-22 by the [measurement-only build boundary](#amendment-2026-10-22-measurement-only-evidence-builds),
which specifies future tooling and admits no production loading profile.

Amended 2026-10-29 by the [`auto` ranking contract](#amendment-2026-10-29-the-auto-ranking-contract),
which specifies phase 6 and adds no order, certification entry or loading
permission.

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

By itself this ADR admits no loading profile and certifies no model:
`CERTIFIED` stays empty and certified placement stays on CPU until the
gates below are satisfied on real hardware. One shipped-behavior change
rides along (section 7 and the CHANGELOG): custom builds that compiled an
execution-provider feature previously placed every ONNX session on that
provider; those sessions now run on the CPU unless the exact test escape
is set.

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
configurations matches the NPU precedent (batch 1, LATENCY). Unlike the
NPU premise of ADR-0022 section 6, OpenVINO GPUs accept several
inference precisions, and the precision changes the drift a certification
judges, so the fixed compile configuration names
`INFERENCE_PRECISION_HINT` explicitly: the certified configuration is
`f16` (the GPU default on current drivers), the value is an identity
field, and a certification run records the precision it used, so an
implementation claiming conformance compiles with the same one.
(Amended 2026-10-21, below: the certified precision is `f32`; the f16
default measured outside the drift budget on both measured identities.)

### 3. GPU platform identity extends the ADR-0022 identity

The identity adds the GPU plugin version, the GPU device name and PCI
vendor and device of the selected render node, the OpenCL ICD or Level
Zero loader the GPU plugin resolves, the GPU driver version (amended
2026-10-11, below), the build of the GPU firmware the kernel loaded
where the driver exposes it (on Intel integrated graphics the GuC and
HuC firmware versions of the render node), the compile configuration,
and the SHA-256 of every runtime library the daemon maps once the GPU is
enumerated, under the same one-open-file inode discipline as ADR-0022
section 4. Like that section,
a firmware build that cannot be read makes the identity unreadable and
placement refuses, and the firmware is a field because a driver version
does not imply it. A driver or compute-runtime update is a different
identity; a kernel release is not a field, for the same reason as
ADR-0022. (Amended 2026-10-22, below: every mapped library stays hashed
and in the exact identity, while the certification key binds the
numerics set, and a changed support set runs an extended canary.)

### 4. Loading admission stays closed until the GPU conformance profile exists

The GPU loads more of the system than the NPU path names today: the
compute runtime, its ICD or Level Zero stack, and parts of the graphics
driver. Opening GPU placement requires the same installation and launch
conformance evidence ADR-0022's 2026-10-09 amendment demands for the
NPU, extended to that inventory. No setting bypasses it; until then a
`gpu` selection keeps the recognizer on CPU with the selection's reason
reported, exactly as #1054 ships today.

The measurement-only exception specified below needs its own reviewed
launch admission; it cannot open this production gate.

#### Candidate-input checker, 2026-10-23

The first offline foundation validates a supplied candidate child
environment under `gpu-candidate-inputs-v1`. That minimal description
requires exactly `NEO_CACHE_PERSISTENT=0`, permits optional `LANG=C` and
`LC_ALL=C`, and rejects every other variable, including an empty override.
Duplicate names, invalid raw names or values, unsupported versions and
oversized inputs refuse with fixed categories that contain no input value.

This checker does not read or change the process environment, inspect
files, establish cache behavior, load a provider or verify confinement.
Its private-field checked result contains only the policy ID and declared
cache-off intent. It is neither a launch profile nor an admission token;
no production caller uses it to open loading. The installation/native
closure, launcher provenance, affinity and enforcing-host evidence above
remain required. Both certification tables remain empty.

#### Supplied-byte ELF metadata

The default-off `native-metadata` feature extracts metadata from supplied
ELF64 little-endian x86-64 executable/shared-object bytes. It uses program
headers, including for sectionless files; section tables cannot override
the dynamic segment. Interpreter and effective string values borrow the
input buffer. Unknown tags, duplicate string references and entries after
the first `DT_NULL` remain visible; trailing entries never become effective.

The parser rejects malformed ranges, unsupported layouts, conflicting
string-table definitions and any competing LOAD mapping that intersects
the string table. Limits are 256 MiB of input, 128 program headers, 4,096
dynamic entries, 256 string references, 4,096 bytes per string and 1 MiB of
referenced string bytes. Unit tests exercise minimal and NPU-combined
builds; a separate fuzz target checks deterministic results and output bounds.

Successful extraction establishes neither file provenance nor loading
support. The parser does no filesystem access, dependency resolution,
hashing, native loading or device discovery. Its output cannot authorize
a launch or produce a certification. Complete dependency resolution and
trusted launch admission remain required by section 4.

#### Declared fixture graph

The `native-metadata` feature also checks `declared-fixture-graph-v1` graphs.
It matches arbitrary node IDs to supplied buffers, verifies canonical
SHA-256 text against those bytes, and parses those same buffers. The
description supplies generic roots, not presumed ORT, driver or plugin roles.

This fixture policy uses one logical `lib/` namespace and an optional
`bin/` executable with an explicit, exact `PT_INTERP` binding. Aliases and
SONAMEs have one owner; NEEDED ordering and repeated edges are preserved.
Active metadata follows an explicit tag/flag policy. RPATH refuses;
RUNPATH accepts only `$ORIGIN` for libraries or `$ORIGIN/../lib` for the
bound executable, selecting the declared directory rather than host paths.
Ineffective entries after `DT_NULL` remain subject to parser structure and
resource bounds but do not become active loading policy.

Limits are 256 nodes/roots, 256 aliases, 4,096 edges including interpreter
edges, 256 MiB per supplied buffer and 1 GiB total supplied bytes. Parser
limits remain separate. Checked graphs borrow their own description and
input buffers. The evidence/NPU adapter maps observer indices to IDs and
uses retained observer bytes without reopening files. That mapping is an
explicit remapping of labels, not proof that physical paths equal logical
paths.

Graph success establishes declared edge coverage only. It does not validate
relocations or ABI behavior, discover omitted dynamic roots, emulate glibc,
authenticate a generation or authorize a launch. It changes no certification,
runtime identity or cache key. Production profile roles, acquisition,
immutable-generation lifetime and trusted bootstrap remain separate work.

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
every non-probe path stay on CPU. (Amended 2026-10-22, below: where the
driver holds the device while a model is retained, a hold witness meets
the runtime-suspend parts of ADR-0022 measurements 6 and 7.)
(ADR-0022 amendment 2026-10-22, [certification corpora and decisions at full
extent](0022-npu-inference-under-per-model-certification.md#amendment-2026-10-22-certification-corpora-and-decisions-at-full-extent):
what these gates run over, which enrollment shapes an entry covers (those
that both an impostor arm and an attack arm reach), how differences are
recorded and who reads them, and the separate runs for ADR-0022 measurements
6 and 7.)

### 6. `auto` ranks certification, never device class

The #1053 contract holds: `auto` places the recognizer on an accelerator
only when that accelerator's model certification passed on its identity.
Ranking among several certified devices is set by measured evidence on
the decision hardware (the UX5406S rerun of the measurement record is
pending), not by device class or vendor. (Amended 2026-10-29, below: CPU
is a ranked target, orders live in a separate reviewed table, `auto`
probes a device only when that table could select it, and a refusal falls
through to the next class, then CPU.)

#### Pure recommendation foundation, 2026-10-23

A shared pure API now evaluates caller-asserted candidate facts and an
exact workload-bound order. It compares opaque keys byte for byte without
defining a certification-key format or verifying their authenticity.
Switches filter recommendations, explicit selection never substitutes the
other accelerator, and missing or contradictory evidence recommends CPU.
Either accelerator, or CPU itself, may lead a supplied valid order.

The result is a hypothetical recommendation, not eligibility, permission or
actual placement. There is no production caller, native collector or new
wire field in this foundation. Collector-order guarantees, genuine
eligibility production, end-to-end ranking evidence and resolved-device
reporting remain required before changing `auto` behavior.

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
refuses instead of running partly on the CPU unannounced. No arm is
silent: a compiled provider without the escape warns that it stays
unregistered and the sessions run on the CPU, and a build with no
provider feature that receives the escape warns that it is ineffective,
so no experiment mistakes a CPU session for a provider result and no CPU
session is mislabeled as uncertified. Three ordering and selection rules
complete the contract: every session that is not on the escaped
providers registers the environment's exact default CPU execution
provider (the Microsoft CPU device; explicit registration is the only
suppression of the automatic device-selection policy the builder arms,
and that policy would rank any other CPU-type EP ahead of the reference
CPU EP, which the certification's parity reference names), so a runtime
with built-in accelerators or additional CPU-type providers cannot
auto-place or substitute these models; under the escape TensorRT
registers ahead of CUDA so it claims its subgraphs first; and CoreML
never registers, because every MLComputeUnits combination admits the CPU
and no strict arm could promise it accelerator-only execution, so a
build that compiled it is told it stays inactive. A future ADR that wants an
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


## Amendment 2026-10-11: the driver version is the hashed driver stack

Section 3 named "the GPU driver version" as an identity field. Measuring
the shipped 2026.2.1 builds ([the identity
record](../research/2026-10-11-gpu-identity.md)) found that reading the
plugin's `GPU_DRIVER_VERSION` through the OpenVINO C API kills the
calling process on both measured builds (the root-owned archive and the
Fedora RPM), deterministically, before any error can be returned. No
safe read of that property exists at this runtime version, so the
identity does not read it: the driver version is carried by the
mapped-library manifest's content hashes instead, which section 3
already makes a different identity on any driver or compute-runtime
rebuild. A future runtime that answers the property safely may add it
back as an explicit field; until then the manifest is the binding form.

## Amendment 2026-10-21: the fixed precision is f32

Section 2 named `f16` because it is the GPU plugin's configuration
default (`ov::hint::inference_precision` defaults to `f16` in the 2026.2.1
GPU plugin's option table, which accepts `f16`, `f32` and `dynamic`).
Measuring that default under the ADR-0022 section 7 gates found its drift
outside the budget on both identities measured so far, and `f32` inside it
by three orders of magnitude:

- UX5406S (Arc 140V, `xe`), identity `f8591769`, 2026-10-12, `f16`: the
  recorded genuine IR arm's lower threshold shift moved 5 of 1,474 verdicts
  (0.339 points) and the recorded genuine RGB arm added one rejection in
  339 (0.295 points), both above the 0.2-point budget of section 7.5
  ([the identity record](../research/2026-10-11-gpu-identity.md), phase 4
  correction).
- ThinkPad X13 Yoga Gen 4 (Iris Xe `8086:a7a1`, `i915`), identity `6aa45541`,
  2026-10-13, `f16`: genuine LFW maximum absolute drift 0.00108 moved the
  false-reject rate by one pair in 400 in both shift directions (0.25
  points) while all 3,397 CPU/GPU verdicts agreed and no new grant
  occurred; section 7.4 passed and section 7.5 failed.
- The same ThinkPad, 2026-10-19, `f32` (identities `f592e9bc` and
  `d689e37d`, which differ only in the memory size reported after a
  reboot; both are `27288f0e` since #1172): maximum absolute drift
  6.6e-7 on genuine LFW and 3.1e-7 to 4.0e-7 on the eight other arms, zero
  verdict differences in 3,397 comparisons, no new grant, every
  shifted-threshold recount unchanged; three retained-process runs of 1,000
  bit-exact calls with one proven system suspend, 41 of 41 cache-matrix
  processes and 5 of 5 power-management stages. The section 7.6
  runtime-suspend subset was not observed in that campaign (the harness
  reported it inconclusive under a display session that kept the render
  node open); on 2026-10-21, with the display blanked, the same identity
  proved a runtime suspend and a system suspend in one retained process
  with 1,000 of 1,000 calls bit-exact (the precision record).
- UX5406S, identity `ec747155`, 2026-10-21, `f32`: all 13 measured arms
  pass both gates (recorded genuine IR 1,474, IR attacks 138, recorded
  genuine RGB 339, RGB attacks 209, 400 genuine and 400 impostor LFW
  pairs, seven FairFace groups of 371), maximum absolute drift 7.5e-7,
  zero verdict differences in 5,557 comparisons, no new grant; the two
  arms that failed at `f16` on this host pass with no movement.

The evidence is summarized in
[the precision record](../research/2026-10-21-gpu-f32-precision.md) with
the archive paths and digests.

Decision: the fixed compile configuration is
`batch=1;PERFORMANCE_HINT=LATENCY;INFERENCE_PRECISION_HINT=f32`. The
precision remains an identity field, so every `f16` identity and the
evidence collected on it leave certification consideration; the `f16`
reliability and cache evidence does not transfer. The ADR pins no
execution mode: the 2026.2.1 GPU plugin derives a precision from
`EXECUTION_MODE_HINT` only when the caller set no `inference_precision`
(`apply_execution_hints` in the plugin's `execution_config.cpp`), so the
explicit hint governs. Costs recorded for section 11: the `f32` compiled
blob is about twice the `f16` blob (263,474,861 against 133,509,421 bytes
on the ThinkPad); the corpora lane's wall time matched `f16` within two
minutes there. Section 2's phrase "the GPU default on current drivers"
described the plugin's configuration default, not a driver property.

Two clarifications ride with this amendment. Section 6's pending ranking
evidence exists: the UX5406S three-way measurement of 2026-10-10 (raw
recognizer inference at the plugin's default compile properties, before
the precision question) gave medians of 3.59 ms on the OpenVINO NPU lane,
5.51 to 5.81 ms on the OpenVINO GPU lane and 98.7 to 105.7 ms on the
production ONNX Runtime CPU lane ([the benchmark
record](../research/2026-10-10-gpu-benchmarks.md)); it ranks raw
inference only, and `auto` ranking among certified devices will rest on
end-to-end evidence under the certified configuration. On measured hosts:
the Phasing names the UX5406S as the decision hardware with minihost as
the proxy; the ThinkPad X13 Yoga Gen 4 produced the reliability, cache and precision
evidence above and is a second measured identity, not the decision
hardware. The 2026.2.1 runtime measured on the UX5406S and in the
2026-10-11 amendment is the intel-npu-stack 0.2.0 candidate package set;
Fedora 44 itself ships OpenVINO 2025.1.0.

## Amendment 2026-10-22: the runtime-suspend arm where the driver holds the device

ADR-0022 section 7 asks for output bits that repeat "after the NPU has
runtime-suspended" (measurement 6) and for crash-free calls "some after
runtime suspends" (measurement 7); section 1 carries both to the GPU. On
the `xe` driver neither event can happen while a compiled model is
retained. The Intel compute runtime creates its VM in long-running mode
when it enumerates the device (`getFlagsForVmCreate` sets
`DRM_XE_VM_CREATE_FLAG_LR_MODE` unconditionally in intel-compute-runtime
26.35.39758.11 and 26.35.39758.17), and the kernel takes a runtime-PM
reference for every such VM that it drops only when the VM is destroyed,
at process exit (`drivers/gpu/drm/xe/xe_vm.c` at v7.2, unchanged on
mainline after v7.3, where the source comment calls the reference
necessary for long-running workloads). Measured on the UX5406S, identity
`ec747155`, 2026-10-21, with the panel dark: the GPU runtime-suspended in
the lifetime diagnostic's CPU-only stage (206 of 301 samples) and in none
of the four stages that held a compute context, the stage with the
platform dropped and the libraries still mapped included (0 of 301
each). The retained control's 120 s runtime window read `active`
throughout with the suspended-time counter unchanged, and the GPU
suspended again about a second after the retained process exited (35 of
45 samples). The retained control therefore reports the runtime arm as a
missing event (`RELIABILITY_COVERAGE_READY=false`) by driver design, not
by a fault ([the precision record](../research/2026-10-21-gpu-f32-precision.md)).

Decision, on the maintainer's choice of 2026-10-22:

1. The GPU session stays in irlumed on every host, as the NPU session
   does; no helper process exits on idle to let the GPU sleep. A GPU
   placement on a host whose driver holds the device therefore keeps the
   GPU out of runtime suspend for the daemon's lifetime. System suspend
   is unaffected: the UX5406S proved one with the model retained and
   1,000 of 1,000 calls bit-exact. The idle power the hold costs while
   the display is off and the system awake was not measured; platform
   S0ix residency did not grow in any stage of the dark-panel diagnostic,
   the CPU-only stage included, so the hold cost no S0ix residency there.
2. On such an identity the runtime parts of measurements 6 and 7 are met
   by a hold witness instead of a runtime event. The evidence for the
   identity being certified shows, with the display off: the lifetime
   diagnostic with the GPU runtime-suspending in the CPU-only stage and
   in none of the stages that hold a compute context; the retained
   control with the GPU `active` and `power/control` at `auto` for its
   whole runtime window, a proven system suspend, every call bit-exact
   and every boundary unchanged; and the GPU runtime-suspending again
   once the retained process has exited. Each run archives the kernel
   release. An identity whose runtime event is observable proves it as
   before (the ThinkPad X13 Yoga Gen 4 on `i915` proved a runtime and a
   system suspend in one retained process on 2026-10-21); the hold
   witness applies only where the diagnostic shows the hold.
3. A kernel release is not an identity field (section 3), so a later
   kernel could release the hold under a certified identity. The
   certification entry therefore records which runtime witness it rests
   on. For an entry resting on the hold, the daemon reads the bound
   device's `power/runtime_suspended_time` after the engine build and
   with each GPU answer. Growth means a runtime suspend happened with
   the model retained, which that certification never measured: the
   recognizer retires the GPU to CPU, that answer is computed on CPU, and
   doctor names re-certification as the remedy. A system suspend does not
   grow that counter (on the UX5406S it stayed at 173,292 ms across the
   proven suspend) and keeps the section 8 recheck.

This states how the runtime arm is witnessed where the driver rules the
event out; no gate is relaxed. The transition the arm guards against
cannot occur while the model is retained on such an identity, the
transition that can occur is proven, and if the first ever occurs the GPU
leaves service. Phase 3 (#1161) carries the counter guard and the
witness field of the entry, phase 5 (#1162) the read access to the bound
device's power attributes.

## Amendment 2026-10-22: the certification key binds the numerics set

Section 3 binds the SHA-256 of every library the process maps once the
GPU is enumerated, and an entry matches only that exact set. On the
UX5406S the measured identity binds 37 libraries from about 25 Fedora
packages, most of them with no part in the recognizer's arithmetic
(glibc, libstdc++, zlib, zstd, xz, libxml2, ncurses, libedit, libffi,
tbb, pugixml). Fedora 44 shipped stable updates to those packages on 9
dates between 2026-07-22 and 2026-10-22, and the production daemon's own
dependencies (systemd, OpenSSL) add 4 more, so an exact-set entry would
match a routinely updated host for about a week at a time, and every
re-certification is a campaign of over an hour on the decision hardware
plus attended suspend steps and a release ([the certification-key
record](../research/2026-10-22-gpu-certification-key.md)).

On the fixed configuration the recognizer is a static graph (batch 1,
fixed shapes) that the GPU plugin compiles at engine build: host code
shapes the compiled program (graph transformations and constant folding
in OpenVINO, OpenCL C kernel compilation through the compute runtime,
opencl-clang, clang, LLVM, the SPIR-V translator and IGC), and at
inference the host only dispatches it. The section 8 canary checks that
compiled program's exact output bits on every engine build, so a host
library that changes the program changes those bits and the GPU stays on
CPU. Fedora's IGC and opencl-clang link the system LLVM, clang and
SPIR-V translator libraries (`libLLVM.so.22.1`, `libclang-cpp.so.22.1`,
`libLLVMSPIRVLib.so.22.1`), so those take part in kernel code generation
and a system LLVM update alone can change it.

Decision:

1. The mapped libraries split into two reviewed lists. The numerics set
   is the OpenVINO libraries, the Intel compute runtime's drivers and
   memory library (the OpenCL and Level Zero drivers, gmmlib) and the
   kernel compiler toolchain (IGC, opencl-clang, clang, LLVM, the SPIR-V
   translator). The support set is every other library the measured
   inventories map: the C and C++ runtimes, threading, compression, XML,
   terminal and FFI libraries, lld, SPIRV-Tools, the OpenCL and Level Zero
   loaders, irlume's CPU-side runtimes and the daemon's own dependencies.
   A mapped library on neither list refuses placement, and doctor names
   it, until a review classifies it: the inventory and inode discipline
   of section 3 is unchanged, and every mapping still has to be a hashed,
   inode-checked file.
2. The certification key binds the device, firmware and configuration
   fields of section 3 and the content of the numerics set by library
   name, independent of the installation prefix as in the ADR-0022
   provider-portability amendment. The exact identity of section 3, with
   every library, still names caches, markers and diagnostics.
3. The entry also records the support set's content digest and the GPU
   output digest of an extended reference set (more fixed inputs than
   the section 8 three, each run twice). When the live support digest
   differs from the entry's, the engine build reproduces the extended
   digest before the recognizer answers from the GPU, which also repeats
   each input; any other bits keep it on CPU and doctor says why.

What this changes: a support-library update keeps the certification as
long as the compiled program reproduces the certified bits on the
section 8 inputs and the extended set, instead of requiring that exact
library bytes passed the campaign. What it leaves uncovered: behaviour
that depends on input values those reference inputs never reach, and a
nondeterminism a support library would introduce at inference after the
build-time checks passed; the repeated extended inputs narrow the second
and neither is a known mechanism for the classified libraries. Updates
to the numerics set still need a new certification. With gmmlib in the
numerics set, the same 92 days give 6 re-binding dates instead of 13.
This amendment covers the GPU; the NPU keeps the ADR-0022 binding. Phase
3 (#1161) carries the lists, the key, the support digest, the extended
set and the refusal; the production daemon's inventory under the real
unit completes the support list before any entry.

## Consequences

- ADR-0022 section 15 no longer reserves the GPU; the maintainer's
  revisit of it is recorded here, with CPU the default until a
  certification passes.
- The implementation order is fixed by Phasing below; the only behavior
  change this ADR ships is the execution-provider inertness of section 7
  (and its CHANGELOG entry).
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
- For an entry resting on the hold witness (amendment 2026-10-22),
  growth of the bound device's `power/runtime_suspended_time` after the
  engine build retires the GPU to CPU and that answer is computed on
  CPU, while a system suspend with the counter unchanged keeps only the
  section 8 recheck (phase 3, fake power attributes).
- Certification key (amendment 2026-10-22): a changed support library
  keeps the key and a changed numerics library changes it; a mapped
  library on neither list refuses placement with its name; a live support
  digest that differs from the entry's runs the extended reference set,
  whose mismatch keeps the GPU on CPU (phase 3, fixture inventories).

## Amendment 2026-10-22: measurement-only evidence builds

The [ADR-0022 measurement-only build contract](0022-npu-inference-under-per-model-certification.md#amendment-2026-10-22-measurement-only-evidence-builds)
applies to the GPU certification campaign. This is a specification for
future tooling; no evidence entry, loading permission or certification is
created by this amendment.

The initial evidence path may bypass the ordinary admission and table
lookup only after the distinct measurement-launch admission succeeds.
It keeps the single-GPU rule, fixed `f32` configuration, complete identity
and numerics/support inventory checks, CPU reference parity and guarded
production compile. A driver-hold candidate also keeps its bound runtime
counter guard. Missing or changed evidence retires or refuses the run;
the candidate is never a production table entry.

The CPU reference cannot use an escaped ORT provider. The measurement
build's feature and environment rejection rules apply even if such a
provider is available on the machine. Its isolated cache must prove a
second-process import, not merely a successful recompile. The private data
and record restrictions remain those of ADR-0022's full-extent amendment.

Acceptance requires real compiler tests for the shipped-artifact guards,
negative reference-provider and launch-profile cases, cache-hit/miss and
alias cases through the guarded wrapper, and probe-counter/suspend cases.
Toy compiler tests or the earlier unit-test-only hardware runs do not
meet these implementation and measurement requirements. Ordinary GPU
loading, installation and enforcing-profile validation remain section 4
and #1162; this evidence profile is not their conformance proof.

## Amendment 2026-10-29: the `auto` ranking contract

Section 6 leaves `auto` ranking to measured evidence, and the 2026-10-23
foundation added the pure `recognizer_ranking::recommend`, which no
production code calls. This amendment fixes how phase 6 (#1163) calls it.
Three facts constrain that:

- `recommend` supplies no default order: under `auto`, an eligible
  candidate yields CPU without an order bound to the same workload
  (`MissingEvidence`, `EvidenceMismatch`), and an explicit `npu` or `gpu`
  consumes no order.
- A GPU's certification key exists only after the process has loaded
  OpenVINO, enumerated the GPU and compiled the warm-up model
  (`GpuPlatform::open` assembles the identity after those steps), and on
  `xe` the enumeration alone keeps the GPU out of runtime suspend until
  the process exits (amendment 2026-10-22; a bare `clGetPlatformIDs` and
  `clGetDeviceIDs` probe reproduces it, [the precision
  record](../research/2026-10-21-gpu-f32-precision.md)). Probing the GPU
  to learn whether `auto` may use it pays that hold even when the answer
  is CPU.
- The certification entry says whether a GPU may answer, not whether
  `auto` should prefer it, and the costs that would decide that are
  unmeasured under `f32`: single-request latency (the precision record)
  and the idle power of the hold (amendment 2026-10-22, decision 1).

Decision:

1. CPU is a ranked target. Certification makes an accelerator eligible;
   only a reviewed order puts it ahead of CPU (Phasing item 6). Orders
   live in `RANKED`, a compiled table beside the certification tables
   that stays empty until reviewed evidence fills it. An order has the
   shape `recommend` takes: a workload key and a strict order over CPU
   and at most one target per accelerator class, CPU exactly once. The
   workload key binds the model's SHA-256, the consumer (the CPU
   reference's ONNX Runtime version, the wired thresholds and the decision
   fingerprint) and the ranking protocol version of decision 4. A GPU
   target names its certification's numerics key, which binds the
   compile configuration; an NPU target names the identity key of its
   ADR-0022 entry. Each order also records the PCI vendor and device IDs
   of every accelerator it ranks, and names its evidence record.
   `RANKED` may hold several orders for one workload key, because each
   certified identity and each re-certification under a new key is
   measured on its own; the accelerator keys they name tell them apart.
   No accelerator target (class and key) appears in two orders for one
   workload, so a live key picks at most one order; a test over the
   compiled table checks this, and an order measured for a target that
   an older order names replaces that order. The certification entry
   keeps its fields: re-ranking needs no re-certification, and a GPU
   re-certified under a new numerics key has no order until one is
   measured.
2. `auto` probes only what an order could select. Before any runtime
   work, the daemon opens an accelerator class's context under `auto`
   only when that class's switch allows it and at least one order for
   this workload passes for the class: the order puts a key of that
   class ahead of CPU, an entry of that class for this model and
   consumer carries that key, and the host exposes a device with the PCI
   IDs the order records for it. The check reads every order for the
   workload, because the live key that picks one (decision 3) exists
   only after the probe. The IDs come from sysfs, whose `vendor` and
   `device` attributes return the kernel's cached values and take no
   runtime-PM reference (`drivers/pci/pci-sysfs.c` at v7.2 and on
   mainline of 2026-10-28). A class that fails the check runs no
   discovery and reports why on CPU (decision 5).
3. A refusal falls through to the next class, then CPU. At engine build
   (ADR-0022 sections 8 and 10 unchanged), the classes that pass
   decision 2 are probed one at a time, each at most once, in the
   sequence their passing orders give them. Where those orders disagree,
   or none ranks both classes, the NPU goes first, because only the GPU
   probe has a known hold (on `xe`); on such a host the NPU can win where
   the GPU's own order put the GPU first. A probe that refuses
   (admission, no entry for the live key, compile, parity, the runtime
   guard) leaves its slot on CPU, and the walk moves on. For a slot that
   places, the daemon calls `recommend` with that slot alone,
   `ReportedEligible` under its live key, and the one order that names
   the key, or no order when none does. The answer decides:
   - an accelerator answer keeps the slot and ends the walk;
   - `MissingEvidence` (no order names the live key) or
     `OrderedEvidence` with CPU (the order puts CPU ahead of the live
     key) drops the slot, and the walk moves on;
   - every other CPU answer (`InvalidOrder`, `EvidenceMismatch`,
     `InvalidKey`, `WorkloadMismatch`, `AmbiguousCandidates`,
     `NoEligibleAccelerator`) rejects the order or the inputs, which only
     an inconsistent table or walk produces, so the walk ends on CPU with
     no further probe.

   A refused or dropped slot is not passed to later calls: under `auto`
   `recommend` skips an absent class as it skips a refused one, so that
   slot can neither win nor invalidate the next class's order. The walk
   ends on CPU when no class is left. Retirement after placement stays
   ADR-0022 section 9: CPU for the engine's lifetime, never the other
   accelerator.
4. Ranking protocol `irlume-ranking-v1` measures every target of an order
   on one host, on the certified identity, through the production
   compile:
   - decision latency from the first frame the engine receives to the
     decision, p50 and p95 over the same recorded authentications, with
     the desktop idle and with the compositor rendering continuously on
     the integrated GPU;
   - CPU time per authentication;
   - idle power with the display off and runtime power management on
     (`power/control` at `auto`), in alternating windows with and without
     the context retained, from package energy and, on battery, the
     discharge rate, with the power profile recorded;
   - resident memory added, cold compile from an emptied cache and warm
     import.

   An accelerator goes ahead of CPU only when its p95 latency is lower
   than CPU's in each latency condition, its CPU time per authentication
   is lower, and, for each power source measured, the mean idle power of
   the windows with the context retained exceeds the mean of the windows
   without it by no more than the margin. A run whose windows without
   the context differ from each other by more than the margin decides
   nothing and is repeated, so a noisier baseline cannot widen the
   allowance. The power figures are preliminary: windows of 10 minutes,
   3 of each kind, and a margin of 50 mW, until the preliminary ranking
   measurement on the UX5406S (#1163) confirms or replaces them before
   the first order lands. Two qualifying accelerators are ordered by p95
   latency under compositor load. Memory, compile and import figures are
   recorded and do not rank; the Context weighs them for the regime. CPU
   authentication violates no user-facing latency target (Status), so
   `auto` does not trade idle power for latency; explicit `gpu` remains
   for an owner who accepts that cost. Once the first order lands, a
   changed metric, rule or figure is a new version, and orders measured
   under an older one stop matching.
5. Health, `status --json` and doctor gain optional fields under contract
   1: the target the selection resolved to (`cpu`, `npu` or `gpu`) and a
   closed reason from `recognizer_ranking::Reason`. On CPU under `auto`
   the reason is the last one the walk met (decision 2 checks the NPU,
   then the GPU, before any probe), so a refusal is reported as
   `Refused` with its cause, not as `NoEligibleAccelerator`. Phase 6
   extends both closed sets additively, one new wire string per value:
   `Refusal` gains a failed compile (including a compile or inference
   that did not return earlier in this boot), a failed parity check (the
   startup check or the extended reference set) and a runtime-suspend
   guard that could not be armed, and `Reason` gains no device with an
   order's PCI IDs. The other causes map to existing values: a switch
   that is off is `SwitchDisabled`; no order putting the class's key
   ahead of CPU before the probe, and no order naming the live key after
   it, are `MissingEvidence`, as when `recommend` gets no order; no entry
   for the model and consumer, or for the live key, is `NotCertified`;
   closed admission is `LoadingNotAdmitted`; more than one GPU is
   `AmbiguousDevice`, an absent runtime or no GPU found after the PCI
   check is `RuntimeUnavailable`, an unreadable identity or an
   unclassified library is `IdentityUnavailable`, and an ineligible
   model is `NotCertified`. The fields report the
   policy result of the published engine; `device` and `accelerator` keep
   reporting execution, so a retirement to CPU leaves the resolved target
   unchanged. No key, workload or measured value is carried, root and
   non-root callers see the same values, absence means unreported and an
   unknown value decodes as `unknown`, as for selection provenance.
6. Explicit `gpu` and `npu` are unchanged: they consume no order, the
   check of decision 2 does not apply to them, and they report what their
   probe found. Each switch filters only its own class (section 8), so
   under `auto` an NPU switch that is off does not keep the GPU from
   consideration, unlike today's NPU-only `auto`, which the NPU switch
   stops.

What this changes: no behavior today. `RANKED` does not exist yet,
loading admission stays closed, both `CERTIFIED` tables stay empty and
`auto` keeps the recognizer on CPU. Once an admitted, certified GPU
exists, `auto` still stays on CPU until a reviewed order for its numerics
key lands, so explicit `gpu` is the first way to use it; running the
protocol in the certification campaign's window lets an entry and its
order land together. A probe that ends on CPU (a live key no entry or
order names, an order that puts CPU first, or a slot refusal) still keeps
an `xe` GPU out of runtime suspend until the daemon exits; decision 2
confines that to hosts with a ranked device's PCI IDs. What it leaves
open: the power figures of decision 4 until the UX5406S measurement sets
them; an accelerator answer ends the walk even when the order that names
the live key ranks only that class, so the walk's sequence, not a
measurement, then decides between the classes; and an order names CPU
only by position, not by processor model,
so one host's measurement ranks the GPU against that host's CPU wherever
the order's accelerator keys match.

Acceptance (phase 6, synthetic tables and an injected opener): under
`auto` the opener is never called unless the class's switch, a matching
entry, an order putting the class ahead of CPU and that order's PCI IDs
all allow it, checked over every order for the workload; both orders of
two eligible classes are followed, and disagreeing orders probe the NPU
first; a live key selects the one order that names it, and a live key no
order names, or an order putting CPU first, drops the slot and moves on;
a refused first candidate falls through to the next and then to CPU,
each probed once; a rejected order ends the walk with no further probe;
a table that names one accelerator target in two orders of a workload
fails its test; the GPU switch off wins and the NPU switch off does not
block the GPU; explicit `gpu` probes with no order; a refusal under
`auto` is reported with its cause; a retirement keeps the resolved
target and reports CPU execution; an unknown reason string decodes as
`unknown`; an older daemon's missing fields decode as unreported.

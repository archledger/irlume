# ADR-0022: Optional NPU inference under per-model certification

## Status

Proposed 2026-10-08. First drafted 2026-09-15 and held unpublished;
revised after the 1.38.0 platform retest and the root cause of the NPU
compile crash ([intel-npu-stack#20]).

Depends on ADR-0013 (PAD cues are deny-only) and ADR-0019 (fail-closed PAD
availability); amends neither. Replaces the experimental design for one
globally resolved inference device explored in #647, which merged only into
an experimental branch and never reached `main`.

## Context

Irlume runs six ONNX models through ONNX Runtime on CPU: the YuNet detector
(score floor 0.6), the BlazeFace rescue detector (0.5), the glintr100
recognizer (match thresholds 0.55 RGB and IR, 0.635 IR dark, 0.40 adapted IR,
all in `irlume-core`), the ViT RGB PAD cue (deny line 0.55), the FLIR IR PAD
cue (deny line 0.9) and the ONNX FaceMesh fallback. The production FaceMesh
runs on LiteRT. Every decision (score validation, thresholds, voting, PAD
evidence policy, TPM, PAM) is computed on CPU from model outputs.

Authentication is capture-bound. On the UX5406S (Lunar Lake) the production
CPU stage means are YuNet 7.1 to 7.8 ms, FaceMesh 5.6 ms, glintr100 121.3 ms,
ViT 202.5 ms and FLIR 2.5 ms, 0.34 s in all, while a dual-sensor grant takes
seconds (8.75 s on the BRIO in ADR-0028). The NPU is therefore not mainly a
latency change. What it changes is CPU load and package power: the recognizer
plus the ViT are 95% of that model time, and in the direct OpenVINO runs of
measurement 1 below a model kept 235% to 288% of a core busy on CPU and 5% to
35% on the NPU.

**Platform.** The [intel-npu-stack] profile `fedora-44-lunar-lake-x86_64`
(stack 0.1.1) is qualified: NPU driver and firmware 1.38.0, OpenVINO and the
NPU compiler 2026.2.0, Level Zero loader 1.32.0. The NPU is PCI 8086:643e,
"Intel(R) AI Boost", architecture 4000, at `/dev/accel/accel0`. Fedora ships
the OpenVINO C API only under a versioned soname (`libopenvino_c.so.2620` for
2026.2.0).

**Measurements so far.**

1. 2026-09-01, isolated OpenVINO 2026.2.0 with driver 1.35.0, dynamic batch
   fixed to 1, synthetic inputs (#647): all six ONNX graphs compiled for
   `NPU` and reported `EXECUTION_DEVICES=NPU`. Warm NPU means were glintr100
   6.1 ms and ViT 9.3 ms; all six stayed compiled in one process, and the
   five-model sequence took 16.4 ms. Cold compilation of all six took 5.6 s
   (ViT alone 2.4 s); with a warm cache, 176 ms. Synthetic parity: recognizer
   cosine 0.999999, ViT P(spoof) delta 0.00028, FLIR P(fake) delta 0.00052,
   YuNet score delta 0.0064, BlazeFace 0.000055, mesh 0.28 px. Synthetic
   inputs show numerical compatibility, not decision parity.
2. 2026-09-15, Phase 0, a C API probe with driver 1.35.0 and eight real
   grayscale frames per model: YuNet and FLIR completed 3 of 3 runs, BlazeFace
   2 of 6, and the three dynamic-batch models (glintr100, ViT, ONNX mesh)
   crashed in NPU compilation every time. FLIR's maximum delta on real frames
   was 0.0117.
3. 2026-09-19 and 2026-09-26, driver 1.38.0 ([intel-npu-stack#20]): the crash
   is a null dereference in the NPU compiler's `Reshape` importer when a graph
   reaches it with an unbounded dynamic batch ([npu_compiler#352], open
   upstream; unchanged on its `develop` branch). The Phase 0 probe declared
   the C partial-shape structures with the wrong layout, so its reshape calls
   were invalid and those graphs reached the compiler with a dynamic batch;
   its reading of "unranked inputs" was an artifact of that, and its
   intermittent BlazeFace failures are unconfirmed outside that probe. With
   the batch fixed to 1 (through the C++ and the typed C API) or an `N...`
   input layout, glintr100, ViT, the ONNX mesh and the TFLite mesh compile on
   the packaged 1.38.0 stack and run with the layout. An unbounded dynamic
   batch still crashes 2026.2.0.

**Drift and margins.** The measured attack margins are narrow: ViT attack
presentations measured 0.594 to 0.656 against the 0.55 deny line (0.044
above it), and the FLIR attack floor is 0.941 against 0.9 (0.041). Phase
0's 0.0117 FLIR delta on real frames is more than a quarter of that margin.
Synthetic parity cannot settle this; only measurement at the wired
thresholds on the evaluation corpora can.

**Runtime facts.** The NPU plugin compiles static shapes. Compiled blobs are
not portable across driver or compiler versions. The bundled onnxruntime
1.28.1 has no OpenVINO execution provider: reaching the NPU through it would
mean shipping `libonnxruntime_providers_openvino.so` with a second, unqualified
OpenVINO inside. The existing `ort` execution-provider features of
`irlume-vision` (`cuda`, `openvino`, `tensorrt`, `coreml`) are compile-time
developer options that no package enables; they are not part of this design.

## Decision

### 1. CPU is the reference and the default

Every model is certified on CPU by definition. The ONNX Runtime CPU sessions,
their construction and the bundled onnxruntime stay as they are. A model runs
on the NPU only through section 3; everything else is CPU.

### 2. The NPU computes model outputs, nothing else

Score validation, thresholds, voting, PAD evidence policy, the attempt record,
TPM and PAM stay on CPU and unchanged. The NPU returns the same output tensors
the CPU session would, and the same code consumes them.

### 3. A per-model certification table in the source

Device selection is per model and decided by a table compiled into
`irlume-vision`, keyed by the model's SHA-256 and a platform identity
(section 4). A model whose digest and the running identity match an entry
runs on the NPU; any other combination runs on CPU. There is no `AUTO`,
`HETERO` or `MULTI` device, no GPU, and no selection by device availability or
speed. An entry is added only by a reviewed change that cites its
certification evidence (section 7).

### 4. Platform identity

The identity is the tuple the daemon can read without privileges beyond its
own: the loaded `libopenvino_c` soname, the OpenVINO runtime build string, the
NPU plugin version, the plugin's `NPU_DRIVER_VERSION` and
`NPU_COMPILER_VERSION`, its `DEVICE_ARCHITECTURE`, and the PCI vendor and
device of the accelerator node. NPU firmware is not readable from the
sandboxed daemon; the stack ships firmware and driver as one release, and the
certification evidence records the firmware version. A difference in any
field is a different identity.

### 5. System OpenVINO, loaded at run time

The daemon loads the certified OpenVINO C API through the system loader by its
versioned soname (`libopenvino_c.so.2620` for 2026.2.0), so another OpenVINO
release reads as absent. It never searches environment-supplied or `/opt`
paths and never bundles OpenVINO. Absence, a missing symbol, a load error or an
identity outside the table is a recoverable "no NPU" answer, like the TFLite
library probe, never an error that stops the daemon. The code sits behind an
`irlume-vision` Cargo feature, `npu`, off by default; a build without it is
the current daemon.

### 6. The batch is fixed to 1 before compilation

Irlume runs every model at batch 1. Before compiling a model for the NPU, the
loader fixes a dynamic batch dimension to 1; a model with any other dynamic
dimension is ineligible and runs on CPU. A graph with a dynamic batch is never
handed to the NPU compiler ([npu_compiler#352]). The checksummed file bytes
are what OpenVINO reads; the reshape happens in memory.

### 7. What certification requires

A table entry for (model digest, identity) requires all of:

1. **Same artifact.** The bytes verified against `models/SHA256SUMS`, read
   from memory, `f32` at the API boundary. No converted, repacked or quantized
   copy. The NPU's internal precision is the plugin default and is part of
   what parity measures.
2. **The production reference.** Parity is against the ONNX Runtime CPU
   session irlume uses, not OpenVINO's CPU plugin.
3. **Real evaluation data.** The genuine and attack corpora that set the
   wired thresholds (the sun-campaign set and the PAD qualification sets).
4. **Zero verdict flips.** Every wired threshold that consumes the output
   gives the same verdict for every evaluation sample, on CPU and on the NPU.
5. **Drift inside the margin.** At each such threshold, the maximum absolute
   output delta is at most 5% of the smaller class margin: the distance from
   the threshold to the 1st percentile of the CPU scores of the class that
   must stay above it, or to the 99th percentile of the class that must stay
   below it. With today's measured windows that allows about 0.0022 for the
   ViT and 0.0020 for the FLIR.
   Detection and landmark models are judged end to end: identical detection
   counts per frame, and rules 4 and 5 applied to the recognizer and PAD
   decisions downstream of them.
6. **Crash-free.** 20 cold compiles in separate processes with the cache
   bypassed, 20 warm loads from the cache, and 1,000 inferences, without a
   crash or an error.
7. **Recorded.** The evidence (identity, model digest, run counts, deltas,
   margins, verdict tables, no biometric data) is archived and cited by the
   change that adds the entry.

### 8. Compilation happens at startup, not in an attempt

NPU sessions are compiled when the engine is built, after its CPU sessions and
before the daemon reports ready, at startup and at every engine rebuild. No
compilation happens inside an authentication attempt.

### 9. Failure falls back to the CPU session

The CPU session of a model on the NPU stays loaded. A load or compile failure
leaves that model on CPU for the engine's lifetime. An inference error makes
the same call return the CPU session's result and retires the NPU session for
the engine's lifetime. Neither path changes a threshold, a vote or the
evidence policy, so an NPU fault cannot widen authentication; if the CPU
session fails too, ADR-0019 and the core-model startup rules apply unchanged.

### 10. A compiler crash costs one restart

Before compiling a model, the daemon writes a marker named by the model
digest, the identity and the boot ID into the cache directory, and removes it
when the compile returns. A marker from the current boot found at startup
means a compile did not return: that model stays on CPU for that identity,
and doctor says so. A marker from an earlier boot allows one new attempt, so a
power loss does not pin a model to CPU. With `Restart=on-failure`, a crashing
compiler costs one restart, never a loop.

### 11. A daemon-owned cache

The OpenVINO cache lives in `/var/cache/irlume/npu/<identity digest>/`,
root-owned, mode 0700. Compiled blobs are code the NPU executes, so no user
can write them. A new identity gets a new directory; others are removed. The
CLI never uses the NPU and never creates this directory.

### 12. A kill switch

`IRLUME_NPU=0` or `npu=0` in `settings.conf` disables all NPU use, with the
same parsing as `pad_vit`. A value that cannot be read disables it, the
direction of the reference path.

### 13. Reporting

`irlume doctor`, its `--json` form and the daemon's status report each model's
device and, on CPU, the reason: not built, disabled, not certified for this
identity, runtime absent, identity unreadable, compile failed, a compile did
not return, or retired after an inference error. A platform row gives the
identity. New wire and JSON fields are additive.

### 14. The production mesh stays on LiteRT

There is no LiteRT NPU delegate on Linux. OpenVINO's TFLite frontend compiles
the production mesh on the NPU with a fixed batch, so a later change may
certify it under the same table and rules; until then it runs on LiteRT CPU.

### 15. No GPU

GPU devices stay out of scope. Revisit only with evidence that CPU-only users
face unacceptable latency.

## Consequences

- A build without `npu`, or with it and an empty table, makes the decisions it
  makes today on every host. `doctor` can report the platform before any model
  is certified.
- An OpenVINO, driver or compiler update moves a host back to CPU until its new
  identity is certified. This is deliberate: certification is per identity,
  and the cost is a certification run per stack release.
- The CPU sessions stay resident, as they are today; NPU sessions add their own
  memory.
- Packaging follows certification: the Fedora package turns on `npu`, adds
  `CacheDirectory=`, an AppArmor rule for `/dev/accel/accel[0-9]*` and the
  OpenVINO libraries, and a weak dependency on the stack only when the table
  has an entry for an identity that package can meet. Other lanes are
  unchanged.
- The recognizer and the ViT are where the CPU time is, so they are the useful
  first candidates. The FLIR's Phase 0 delta (0.0117) is nearly six times
  its allowance, so it is likely to stay on CPU.

## Rejected alternatives

- **One device for all models, automatic `npu`, `gpu`, `cpu` order, strict
  explicit `npu`** (#647). Drift differs per model and per threshold, GPU is
  unqualified, and a strict mode trades face availability for a power
  preference.
- **ONNX Runtime's OpenVINO execution provider.** A second OpenVINO inside a
  provider library irlume would have to ship, outside any qualification.
- **Bundling OpenVINO.** The qualified platform stack would stop being the
  only NPU authority on the host.
- **Compiling in a helper process.** It isolates a crash completely; the
  marker of section 10 bounds a crash to one restart without a second
  executable. Revisit if compile crashes become routine.
- **Compiling on first use.** A cold compile takes up to 2.4 s per model inside
  an attempt.

## Phasing

1. This ADR.
2. Loader, identity, empty table, kill switch, fixed-batch compile, cache and
   marker, doctor and status rows, behind the default-off `npu` feature.
   Hardware tests are `#[ignore]`.
3. Certification runs on the qualified Fedora 44 Lunar Lake identity; one
   table entry per model that passes section 7.
4. Packaging per Consequences.

## Acceptance tests

- Table: an empty table resolves every model to CPU on every identity; an
  entry matches only its exact digest and identity; changing any one identity
  field resolves to CPU.
- Kill switch: `IRLUME_NPU=0`, `npu=0` and a malformed value disable the NPU;
  unset leaves the table to decide.
- Absence: with no `libopenvino_c.so.2620`, a missing symbol or a load error,
  every model is on CPU with the matching reason, and nothing panics.
- Batch: a model with a dynamic batch is compiled only with the batch fixed to
  1; a model with another dynamic dimension is ineligible.
- Fallback: an injected compile error leaves the model on CPU; an injected
  inference error returns the CPU result for that call and keeps later calls
  on CPU.
- Marker: a current-boot marker keeps the model on CPU without compiling; an
  earlier-boot marker allows one attempt; a successful compile removes it; a
  new identity ignores markers of the old one.
- Cache: the directory is 0700 root and per identity, other identities'
  directories are removed, and the CLI never creates it.
- Decisions: with a model on the NPU, grants and denials come from the same
  thresholds, votes and PAD availability rules as on CPU.
- Wire: new status fields decode with a frozen copy of the pre-change client
  types, and a pre-change daemon's status decodes in the new client.
- Hardware (`#[ignore]`, Lunar Lake): the identity reads back; every
  eligible model compiles with the batch fixed to 1 and reports
  `EXECUTION_DEVICES=NPU`; outputs match ONNX Runtime CPU on fixed synthetic
  inputs within the bounds of section 7.

[intel-npu-stack]: https://github.com/archledger/intel-npu-stack
[intel-npu-stack#20]: https://github.com/archledger/intel-npu-stack/issues/20
[npu_compiler#352]: https://github.com/openvinotoolkit/npu_compiler/issues/352

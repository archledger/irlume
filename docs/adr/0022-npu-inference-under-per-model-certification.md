# ADR-0022: Optional NPU inference under per-model certification

## Status

Proposed 2026-10-08. First drafted 2026-09-15 and held unpublished;
revised after the 1.38.0 platform retest and the root cause of the NPU
compile crash ([intel-npu-stack#20]), then audited the same day against
measurements of the implementation on the qualified stack (measurement 4).

Depends on ADR-0013 (PAD cues are deny-only) and ADR-0019 (fail-closed PAD
availability); amends neither. Replaces the experimental design for one
globally resolved inference device explored in #647, which merged only into
an experimental branch and never reached `main`.

## Context

Irlume runs six ONNX models through ONNX Runtime on CPU: the YuNet detector
(score floor 0.6), the BlazeFace rescue detector (0.5), the glintr100
recognizer (match thresholds 0.55 RGB and IR, 0.635 IR dark, 0.40 adapted IR,
and the fusion arm's 0.50 weighted and 0.10 per-modality floors, all in
`irlume-core`), the ViT RGB PAD cue (deny line 0.55), the FLIR IR PAD cue
(deny line 0.9) and the ONNX FaceMesh fallback. The production FaceMesh runs
on LiteRT. Every decision (score validation, thresholds, voting, PAD evidence
policy, TPM, PAM) is computed on CPU from model outputs.

Authentication is capture-bound. On the UX5406S (Lunar Lake) the production
CPU stage means are YuNet 7.1 to 7.8 ms, FaceMesh 5.6 ms, glintr100 121.3 ms,
ViT 202.5 ms and FLIR 2.5 ms, 0.34 s in all, while a dual-sensor grant takes
seconds (8.75 s on the BRIO in ADR-0028). The NPU is therefore not mainly a
latency change. What it changes is CPU load and package power: the recognizer
plus the ViT are 95% of that model time, and per call the recognizer takes
227 ms of CPU time on its CPU session and 0.15 ms on the NPU, the ViT 351 ms
and 1.5 ms (measurement 4). Section 3 explains why only the recognizer, 36%
of that time, may move.

**Platform.** The [intel-npu-stack] profile `fedora-44-lunar-lake-x86_64`
(stack 0.1.1) is qualified: NPU driver and firmware 1.38.0, OpenVINO and the
NPU compiler 2026.2.0 (`NPU_COMPILER_VERSION` 8.2), Level Zero loader 1.32.0.
The NPU is PCI 8086:643e, "Intel(R) AI Boost", architecture 4000, at
`/dev/accel/accel0`; on the UX5406S the kernel (7.2.8) loaded the firmware
build of 2026-08-20 (`6fc835a1`). The NPU runtime-suspends 100 ms after each
use. At every compile the driver reports that the compiler and the loaded
firmware speak different but compatible interface versions (ELF ABI 1.4.0
against 1.2.2, mapped inference 11.15.0 against 11.4.10). Fedora ships the
OpenVINO C API only under a versioned soname (`libopenvino_c.so.2620` for
2026.2.0).

**Measurements.**

1. 2026-09-01, isolated OpenVINO 2026.2.0 with driver 1.35.0, dynamic batch
   fixed to 1, synthetic inputs (#647): all six ONNX graphs compiled for
   `NPU` and reported `EXECUTION_DEVICES=NPU`. Warm NPU means were glintr100
   6.1 ms and ViT 9.3 ms; all six stayed compiled in one process, and the
   five-model sequence took 16.4 ms. Cold compilation of all six took 5.6 s
   (ViT alone 2.4 s); from the driver's own cache, 176 ms. Synthetic parity:
   recognizer cosine 0.999999, ViT P(spoof) delta 0.00028, FLIR P(fake)
   delta 0.00052, YuNet score delta 0.0064, BlazeFace 0.000055, mesh 0.28 px.
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
   the packaged 1.38.0 stack when read from a file. An unbounded dynamic
   batch still crashes 2026.2.0.
4. 2026-10-08, the implementation of this ADR (`irlume-vision`, release
   build) on the UX5406S and the qualified stack, models through irlume's own
   structs against their ONNX Runtime CPU sessions:
   - The recognizer, the ViT and the FLIR compiled with the batch fixed to 1
     and reported `EXECUTION_DEVICES=NPU` in every run. Cold compile: 2.3 to
     5.2 s, 3.4 to 8.0 s and 0.15 to 0.35 s; from the OpenVINO cache: 0.38 to
     0.53 s, 0.59 to 0.90 s and 0.02 s. Their CPU sessions build in 0.43
     to 0.44 s and 0.23 to 0.28 s (recognizer, ViT). The three blobs take
     298 MiB on disk (recognizer 127 MiB).
   - Per call, CPU session against NPU: recognizer 118 ms against 6.8 ms,
     ViT 182 ms against 14.7 ms, FLIR 2.2 ms against 0.44 ms.
   - Synthetic parity: recognizer cosine 0.9999982, ViT delta 0.000032, FLIR
     delta 0.000007. Interleaving three inputs on one infer request and
     repeating them returned identical bits; so did an inference after the
     NPU had runtime-suspended.
   - Real recorded frames: 2,397 local frames (1,851 with a face; genuine IR
     sessions, paper, screen, phone, video-replay and banner IR attacks, RGB
     genuine and banner frames), each through both backends at the wired
     thresholds. Recognizer: embedding cosine at least 0.999996, match
     scores against a reference within 0.00038, no flip on 1,347 genuine
     IR frames (impostor pairs were not part of this set). FLIR: deltas up
     to 0.0139 on genuine frames (mean 0.0014) and 0.0060 on attacks, no
     flip. ViT: deltas up to 0.0018 on genuine frames and 0.0027 on
     attacks, and one attack frame 0.0009 above the deny line on CPU fell
     below it on the NPU.
   - The NPU plugin accepts only f16 and i8 as `INFERENCE_PRECISION_HINT`
     ("Supported values: f16, i8"); there is no f32 inference on the NPU.
   - `NPU_COMPILER_TYPE` defaults to `PREFER_PLUGIN`, which resolved to the
     plugin compiler (output bit-identical to a forced `PLUGIN`); `DRIVER`
     is not available with the 1.38.0 driver
     (`ZE_RESULT_ERROR_UNSUPPORTED_FEATURE`).
   - As root, inside the daemon's sandbox properties (`systemd-run`), the
     firmware build reads back from debugfs and debugfs is read-only.
   - OpenVINO 2026.2.0 refuses the TFLite mesh read from a memory buffer
     ("Unable to read the model"), the only way irlume reads a model it has
     verified.
   - A marker write and remove costs 13 µs on the laptop's disk.

**Drift and margins.** The measured attack margins are narrow: ViT attack
presentations measured 0.594 to 0.656 against the 0.55 deny line (0.044
above it), and the FLIR attack floor is 0.941 against 0.9 (0.041). On real
frames the NPU's f16 arithmetic moves the FLIR by up to 0.0139 and the ViT by
up to 0.0027, a third and a sixteenth of those margins, and one ViT attack
frame went from deny to pass at frame level (production votes the median of
five). Synthetic inputs showed neither
(0.000007 and 0.000032 on the same compiled models). The recognizer moved by
0.00038 at most. The recognizer's classes overlap at its threshold instead:
on LFW at 0.55 the false-accept rate is 0.00002 and the false-reject rate
0.2974, and between 0.50 and 0.55 the false-reject rate moves about 0.24
points per 0.001 of threshold.

**Runtime facts.** The NPU plugin compiles static shapes; OpenVINO documents
dynamic shapes on the NPU as a preview limited to bounded dimensions.
Compiled blobs are not portable across OpenVINO, driver or compiler
versions. With `CACHE_DIR` set the NPU plugin bypasses the driver's own blob
cache, and OpenVINO deletes and recompiles a cached blob it fails to import
(`core_impl.cpp`, 2026.2.0). The driver pins the memory it maps to the NPU,
so it cannot be swapped. `NPU_TURBO` raises power and is documented as not
meant for sustained use. The bundled onnxruntime 1.28.1 has no OpenVINO
execution provider: reaching the NPU through it would mean shipping
`libonnxruntime_providers_openvino.so` with a second, unqualified OpenVINO
inside. The existing `ort` execution-provider features of `irlume-vision`
(`cuda`, `openvino`, `tensorrt`, `coreml`) are compile-time developer options
that no package enables; they are not part of this design.

## Decision

### 1. CPU is the reference and the default

Every model is certified on CPU by definition. The ONNX Runtime CPU sessions,
their construction and the bundled onnxruntime stay as they are. A model runs
on the NPU only through section 3; everything else is CPU.

### 2. The NPU computes authentication outputs, nothing else

Score validation, thresholds, voting, PAD evidence policy, the attempt record,
TPM and PAM stay on CPU and unchanged. The NPU returns the same output tensors
the CPU session would, and the same code consumes them. Enrollment embeds on
CPU: every stored template comes from the CPU reference, so no template
depends on the NPU, a fallback or a stack update, and the only mixed
comparison is an NPU probe against a CPU template, which section 7
certifies.

### 3. A per-model certification table in the source

Device selection is per model and decided by a table compiled into
`irlume-vision`. An entry binds three things: the model's SHA-256, a platform
identity (section 4), and the CPU reference it was certified against: the
ONNX Runtime version, the wired thresholds that consume the output, a
fingerprint of the CPU session's decoded outputs for fixed synthetic inputs
through irlume's own preprocessing, and a fingerprint of the recognition
decision downstream of them (for fixed synthetic score pairs and brightness
weights, the cosine match, Platt scaling, brightness weighting, fusion,
template selection and every grant verdict the production code returns). A
model runs on the NPU only when its digest, the running identity and the
loaded ONNX Runtime version all match an entry; any other combination runs on
CPU. Tests recompute the thresholds and both fingerprints from the current
code, so a change to preprocessing, decoding, the decision code, a threshold
or the ONNX Runtime output fails them until the entry is certified again or
removed in the same change. There is no `AUTO`,
`HETERO` or `MULTI` device, no GPU, and no selection by device availability or
speed. An entry is added only by a reviewed change that cites its
certification evidence (section 7).

Only the recognizer is eligible. The PAD cues are deny-only evidence with
attack margins of 0.041 to 0.044; on the qualified stack their NPU drift
is a third (FLIR) and a sixteenth (ViT) of those margins, one ViT attack
frame went from deny to pass, and the NPU offers no f32 to reduce it, so
they stay on CPU. The detectors and the
ONNX mesh fallback shape other models' inputs, so their entries would have to
bind every downstream model as well; together they are about 13 ms of the
339 ms, and they stay on CPU too. TFLite models are not eligible (section
14). Moving another model needs an amendment with new evidence.

### 4. Platform identity

The identity is the loaded `libopenvino_c` path, the OpenVINO runtime build
string, the NPU plugin version, the plugin's `NPU_DRIVER_VERSION` and
`NPU_COMPILER_VERSION`, its `DEVICE_ARCHITECTURE`, the PCI vendor and device of
the accelerator node, the build of the firmware the kernel loaded, and the
compile configuration of section 6. The driver accepts other kernel and
firmware combinations, and the qualified stack already pairs a compiler and
a firmware of different interface versions, so the firmware is not implied by
the driver version. The kernel reports the loaded build in the device's
`fw_version` debugfs entry; it is readable by root, the daemon's
`ProtectKernelTunables=` mounts debugfs read-only rather than hiding it, and
kernel lockdown still permits read-only debugfs entries. A firmware build that
cannot be read makes the identity unreadable, and every model runs on CPU. A
difference in any field is a different identity. The kernel release is not a
field: Fedora ships a kernel every few days, and keying on it would keep the
NPU off most of the time. A kernel driver fault that returned plausible but
wrong output is what the parity check of section 8 catches, and a kernel
update always brings a reboot and so a new engine build; section 10 bounds a
crash. Doctor reports the running kernel release.

### 5. System OpenVINO, loaded at run time

The daemon loads the certified OpenVINO C API from an absolute path: its
versioned soname (`libopenvino_c.so.2620` for 2026.2.0) in a fixed list of
distribution library directories (`/usr/lib64`, `/usr/lib/x86_64-linux-gnu`,
`/usr/lib`), as the TFLite runtime is found. A bare name is never handed to
the loader, so neither `LD_LIBRARY_PATH` nor the loader cache can substitute
another library, and another OpenVINO release reads as absent. It never
bundles OpenVINO. Absence, a missing symbol, a load error or an identity
outside the table is a recoverable "no NPU" answer, like the TFLite library
probe, never an error that stops the daemon. A soname is added to the list
only after the binding's C declarations are compared with that release's
headers (for 2026.2.0 they match the 2026.1.2 headers the binding was
generated from, apart from one comment). The code sits behind an
`irlume-vision` Cargo feature, `npu`, off by default; a build without it is
the current daemon.

### 6. A fixed batch and a fixed compile configuration

Irlume runs every model at batch 1. Before compiling a model for the NPU, the
loader fixes a dynamic batch dimension to 1; a model with any other dynamic
dimension is ineligible and runs on CPU. A graph with a dynamic batch is never
handed to the NPU compiler ([npu_compiler#352]). The checksummed file bytes
are what OpenVINO reads; the reshape happens in memory. The rest of the
compile configuration is fixed in the code too: the plugin's own compiler,
forced (`NPU_COMPILER_TYPE=PLUGIN`) and read back, because the default may
fall back to the driver's compiler, a different NPU program; the latency
performance hint; the plugin's default inference precision (f16, the only
floating-point precision it accepts); and no `NPU_TURBO`. It changes
outputs, so it is a field of the identity, and changing it leaves no entry
matching. A host where the plugin compiler cannot be selected runs the
model on CPU.

### 7. What certification requires

A table entry requires all of:

1. **Same artifact.** The bytes verified against `models/SHA256SUMS`, read
   from memory, `f32` at the API boundary. No converted, repacked or quantized
   copy. The NPU's internal precision is part of what parity measures.
2. **The production reference and path.** Parity is against the ONNX Runtime
   CPU session irlume uses, not OpenVINO's CPU plugin, and is measured
   through irlume's own loader, preprocessing and decoders, not a separate
   harness: Phase 0's harness mis-declared one C structure and reported
   crashes and unranked inputs that were not there.
3. **Real evaluation data.** The genuine and impostor pairs of the corpora
   that set the recognizer's thresholds (LFW and FairFace for RGB; CBSR NIR
   and Tufts for IR), each comparison an NPU probe against a CPU template.
   Because the fusion arm combines an RGB and an IR score with both
   brightness weights, paired cases also run through the production fusion
   and profile-selection code: recorded RGB+IR pairs where they exist, and
   otherwise every combination of the corpora's RGB and IR comparisons over
   the recorded brightness range.
4. **Error rates no worse.** At every threshold and fusion floor the
   decision applies, the NPU probes' false-accept rate is not above the CPU
   probes' (one pair in 100,000 allowed for ties), and their false-reject
   rate is not above the CPU's by more than 0.2 percentage points. Every
   verdict that differs is listed, and each lies within the measured maximum
   drift of its threshold.
5. **Drift small against the threshold.** The maximum absolute score drift
   d, read as a shift of the threshold on the CPU scores, moves the
   false-accept rate by at most 10% of its value (one pair in 100,000 when
   it is zero) and the false-reject rate by at most 0.2 points. This stays
   meaningful where the classes overlap at the threshold, as they do for the
   recognizer; the recognizer's measured 0.00038 would move LFW's
   false-reject rate at 0.55 by about 0.09 points.
6. **Repeatable.** An input gives the same output bits every time on one
   compiled model: repeated, interleaved with other inputs, and after the NPU
   has runtime-suspended.
7. **Crash-free.** 20 cold compiles in separate processes with the cache
   bypassed, 20 warm loads from the cache, and 1,000 inferences, some after
   runtime suspends, without a crash or an error.
8. **Recorded.** The evidence (identity, model digest, run counts, deltas,
   margins, verdict tables, no biometric data) is archived and cited by the
   change that adds the entry.

### 8. Compilation happens at startup, not in an attempt

NPU sessions are compiled when the engine is built, after its CPU sessions and
before the daemon reports ready, at startup and at every engine rebuild. No
compilation happens inside an authentication attempt. Before the recognizer
answers from the NPU, every engine build runs three fixed reference inputs
through both of its sessions; an embedding cosine below 0.9999 (measured
0.9999982) keeps it on CPU, and doctor says so. From the cache the recognizer
adds 0.4 to 0.5 s before ready; after an identity change the first start
compiles it cold, 2.3 to 5.2 s. Until ready, clients get the existing "still
starting" answer and use the password.

### 9. Failure falls back to the CPU session

The CPU session of a model on the NPU stays loaded. A load or compile failure
leaves that model on CPU for the engine's lifetime. An inference error makes
the same call return the CPU session's result and retires the NPU session for
the engine's lifetime. An inference that crashes the daemon or hangs until the
watchdog kills it is covered by section 10. No path changes a threshold, a
vote or the evidence policy, so an NPU fault cannot widen authentication; if
the CPU session fails too, ADR-0019 and the core-model startup rules apply
unchanged.

### 10. A crash or a hang costs one restart

Before compiling a model, and before every NPU inference, the daemon writes a
marker named by the identity and model digests, holding the boot ID, into the
cache's marker directory, and removes it when the call returns (13 µs per
inference, measured). Markers are kept across identity changes within a boot,
so a rollback to an identity that crashed still finds its marker; startup
removes those of earlier boots. A marker from the current boot found at startup
means a compile or an inference did not return (a crash, or a hang a watchdog
restart ended): that model stays on CPU for that identity for the rest of the
boot, and doctor says so. A marker from an earlier boot allows one new attempt,
so a power loss does not pin a model to CPU. A compile counts as worker
activity for the watchdog, startup included, so one that does not return within
`WatchdogSec=` (90 s, against a longest measured cold compile of 5.2 s) stops
the pings and ends in a restart rather than a hang. With `Restart=on-failure`,
a crashing or wedged compile or inference costs one restart, never a loop.

### 11. A daemon-owned cache

The OpenVINO cache lives in `/var/cache/irlume/npu/<identity digest>/` and the
markers in `/var/cache/irlume/npu/markers/`, root-owned, mode 0700. Compiled
blobs are code the NPU executes, so no user can write them. With `CACHE_DIR`
set it is the only blob cache (the driver's own is bypassed), and a blob
OpenVINO cannot import is deleted and compiled again. A new identity gets a new
blob directory; the others' are removed. The recognizer's blob takes 127 MiB.
The CLI never uses the NPU and never creates this directory.

### 12. A kill switch

`IRLUME_NPU` and the `npu` key of `settings.conf` switch NPU use off. Each is
read the same way: absent leaves the table to decide; after trimming, ASCII
`1`, `true`, `yes` or `on` in any case leaves the table to decide; `0`,
`false`, `no` or `off` disables; any other value, an empty value, a value
that is not UTF-8, or a `settings.conf` that exists but cannot be read
disables. Either source disabling wins. This is deliberately stricter than the
`pad_vit` switch, which treats only a recognized off value as off: here a
setting that cannot be understood selects the reference path.

### 13. Reporting

`irlume doctor`, its `--json` form and the daemon's status report each model's
device and, on CPU, the reason: not built, disabled, not certified for this
identity and reference, runtime absent, identity unreadable, ineligible,
compile failed, failed the parity check, a compile or inference did not return
earlier in this boot, or retired after an inference error. A platform row gives
the identity. New wire and JSON fields are additive.

### 14. TFLite models stay on LiteRT

The production mesh runs on LiteRT, which has no NPU delegate on Linux.
OpenVINO's TFLite frontend compiles it from a file, but OpenVINO 2026.2.0
refuses it from a memory buffer (measurement 4), and reading it from a path
would reopen the file after irlume verified it. Its reference is also
LiteRT's CPU output, not ONNX Runtime's. A TFLite model therefore has no
entry under this ADR; one needs an amendment that defines a LiteRT reference
(runtime version and fingerprint) and a read path for verified bytes.

### 15. No GPU

GPU devices stay out of scope. Revisit only with evidence that CPU-only users
face unacceptable latency.

## Consequences

- A build without `npu`, or with it and an empty table, makes the decisions it
  makes today on every host. `doctor` can report the platform before any model
  is certified.
- An OpenVINO, driver, compiler or firmware update, or a change to the
  compile configuration, moves a host back to CPU until its new identity is
  certified. This is deliberate: certification is per identity, and the cost
  is a certification run per stack release.
- Memory: the recognizer's NPU session adds 500 to 537 MiB of process memory
  beside its CPU session (467 to 705 MiB), which stays resident as today and
  can be swapped (on the UX5406S under memory pressure, 0.9 GB of
  the CPU-only daemon was in swap); the driver also pins what it maps to the
  NPU, which cannot be swapped.
- Disk: 127 MiB of compiled blob under `/var/cache/irlume/npu`.
- The driver's interface-version warnings appear in the daemon's journal at
  every compile.
- Packaging follows certification: the Fedora package turns on `npu`, adds
  `CacheDirectory=`, an AppArmor rule for `/dev/accel/accel[0-9]*` and the
  OpenVINO libraries, and a weak dependency on the stack only when the table
  has an entry for an identity that package can meet. Other lanes are
  unchanged.
- The gain is the recognizer's: per call 118 to 183 ms on CPU against 6.7
  to 6.8 ms on the NPU, and 227 to 328 ms of CPU time against 0.15 to 0.24
  ms. The ViT, the larger CPU cost, stays on CPU under this ADR.

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
- **Compiling on first use.** A cold compile of the recognizer takes up to
  5.2 s, and a cache import up to 0.5 s, inside an attempt.
- **Compiling after the daemon reports ready**, switching the recognizer
  between attempts. It removes 0.4 to 0.5 s from startup at the cost of a
  device switch during the daemon's life and compiler work beside a running
  attempt.
- **Dropping the recognizer's CPU session while it runs on the NPU.** It saves
  memory that can be swapped anyway, and a fallback would have to re-read,
  re-hash and rebuild 260 MB inside an attempt.
- **A fresh infer request for every inference**, as Frigate does for ArcFace
  models. Repeatability is measured and required instead (section 7).
- **The kernel release or the `intel_vpu` module build in the identity.** It
  would move hosts to CPU every few days; the parity check at every engine
  build catches a driver that returns wrong output (sections 4, 8).
- **`NPU_TURBO`.** More power for an attempt that is capture-bound.
- **Zero flips and a percentile margin.** The recognizer's classes overlap at
  its threshold (29.7% of LFW genuine pairs fall below 0.55), so a margin to
  a class percentile can be negative and some flips are certain on a large
  corpus; the rate rules of section 7 bound what matters.
- **The PAD cues on the NPU.** Measured on real frames, the FLIR drifts by a
  third of its attack margin and one ViT attack frame went from deny to pass;
  the NPU computes in f16 only, so no setting reduces it. A later stack or a
  mixed-precision compile could be re-measured under a new amendment.

## Phasing

1. This ADR.
2. Loader, identity, empty table, kill switch, fixed-batch compile, cache and
   marker, doctor and status rows, behind the default-off `npu` feature, for
   the recognizer. Hardware tests are `#[ignore]` and also measure the PAD
   cues on the NPU, which production never places there.
3. Certification of the recognizer on the qualified Fedora 44 Lunar Lake
   identity; a table entry if it passes section 7.
4. Packaging per Consequences.

## Acceptance tests

- Table: an empty table resolves every model to CPU on every identity; an
  entry matches only its exact digest, identity and ONNX Runtime version;
  changing any one identity field, the compile configuration included,
  resolves to CPU.
- Reference: changing a recorded threshold, the preprocessing, the decoding
  or the recognition decision code (Platt scaling, brightness weighting,
  fusion, matching, template selection) fails the fingerprint and threshold
  tests.
- Compiler: the plugin compiler is set and read back; a host where it cannot
  be selected runs the model on CPU.
- Parity: an NPU whose output differs from CPU on the reference inputs leaves
  the model on CPU before it answers a request.
- Eligibility: only the recognizer can have an entry; the PAD cues, the
  detectors, the ONNX mesh fallback and TFLite models never do.
- Enrollment: with the recognizer on the NPU, enrollment scans come from the
  CPU session.
- Identity: an unreadable firmware build resolves every model to CPU.
- Kill switch: `IRLUME_NPU=0`, `npu=0`, an empty, malformed or non-UTF-8
  value and an unreadable `settings.conf` disable the NPU; absent and
  recognized on values leave the table to decide.
- Absence: with no `libopenvino_c.so.2620` in the listed directories, a
  missing symbol or a load error, every model is on CPU with the matching
  reason, and nothing panics; a library reachable only through
  `LD_LIBRARY_PATH` is not loaded.
- Batch: a model with a dynamic batch is compiled only with the batch fixed to
  1; a model with another dynamic dimension is ineligible.
- Fallback: an injected compile error leaves the model on CPU; an injected
  inference error returns the CPU result for that call and keeps later calls
  on CPU.
- Marker: a current-boot marker keeps the model on CPU without compiling; an
  earlier-boot marker allows one attempt; a returned compile or inference
  removes it; a marker left by an inference (a killed process) keeps the
  model on CPU after the restart; a new identity ignores markers of the old
  one, and a return to the old identity in the same boot still sees them.
- Watchdog: a compile that does not return stops the watchdog pings, at
  startup and at a rebuild.
- Cache: the directory is 0700 root and per identity, other identities'
  directories are removed, and the CLI never creates it.
- Decisions: with a model on the NPU, grants and denials come from the same
  thresholds, votes and PAD availability rules as on CPU.
- Wire: new status fields decode with a frozen copy of the pre-change client
  types, and a pre-change daemon's status decodes in the new client.
- Hardware (`#[ignore]`, Lunar Lake): the identity reads back; every
  eligible model compiles with the batch fixed to 1 and reports
  `EXECUTION_DEVICES=NPU`; outputs track ONNX Runtime CPU on fixed synthetic
  inputs and on recorded frames, with the PAD cues' drift reported;
  interleaved and post-suspend inferences repeat bit for bit.

[intel-npu-stack]: https://github.com/archledger/intel-npu-stack
[intel-npu-stack#20]: https://github.com/archledger/intel-npu-stack/issues/20
[npu_compiler#352]: https://github.com/openvinotoolkit/npu_compiler/issues/352

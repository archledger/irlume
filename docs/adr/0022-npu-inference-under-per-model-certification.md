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

Amended 2026-10-09 by the [provider-selection and closed-loading
record](#amendment-2026-10-09-provider-selection-and-closed-native-loading)
below. Native loading is closed and the certification table is empty. The
earlier design and measurement history below does not admit a loading profile
or certify a model for authentication.

Amended 2026-10-22 by the [full-extent
record](#amendment-2026-10-22-certification-corpora-and-decisions-at-full-extent)
below: section 7 item 3's corpora run at full extent and in both directions
from named copies (both LFW copies, FairFace 0.25, CBSR, Tufts and the
supplementary Oulu-CASIA), with single-identity, household, fusion,
enrolled-user and attack arms, every production threshold value and the
sessions of a fixed private manifest; an enrollment shape that an impostor
arm and an attack arm do not both reach keeps its probes on CPU. Item 8's
record keeps comparisons of recorded data, and of corpora whose terms
restrict sharing, on the measuring machine except as aggregates over each
arm's whole extent under a hiding digest, validated there as root before
they leave, and items 6 and 7 run separately through the production compile.
It admits no profile and adds no entry.

Amended 2026-10-22 by the [experimental IR-only CPU-reference
rule](#amendment-2026-10-22-experimental-ir-only-probes-stay-on-cpu).

Amended 2026-10-22 by the [measurement-only build contract](#amendment-2026-10-22-measurement-only-evidence-builds).
It specifies future evidence tooling, not an available loading exception.

Amended 2026-10-23 by the [bounded decision fingerprint](#amendment-2026-10-23-bounded-decision-fingerprint).

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
   structs against their ONNX Runtime CPU sessions; the aggregates, the
   identity and reference digests and the commands are in the
   [measurement record][measurement 4]:
   - The recognizer, the ViT and the FLIR compiled with the batch fixed to 1
     and reported `EXECUTION_DEVICES=NPU` in every run. Cold compile: 2.2 to
     5.2 s, 3.4 to 8.0 s and 0.15 to 0.35 s; from the OpenVINO cache: 0.38 to
     0.53 s, 0.59 to 0.90 s and 0.02 s. Their CPU sessions build in 0.43
     to 0.44 s and 0.23 to 0.28 s (recognizer, ViT). The three blobs take
     298 MiB on disk (recognizer 127 MiB).
   - Per call, CPU session against NPU: recognizer 118 ms against 6.8 ms,
     ViT 182 ms against 14.7 ms, FLIR 2.2 ms against 0.44 ms.
   - Synthetic parity: recognizer cosine 0.9999982, ViT delta 0.000032, FLIR
     delta 0.000007. Interleaving three inputs on one infer request and
     repeating them returned identical bits; so did an inference after the
     NPU had runtime-suspended, and so did separate processes. The
     recognizer's NPU embeddings of the reference inputs lie 0.0017 to
     0.0026 (L2) from the CPU's. The CPU session's output bits for the
     same inputs are identical across processes, P-cores, E-cores and
     thread placement.
   - Real recorded frames: 2,397 local frames (1,851 with a face; genuine IR
     sessions, paper, screen, phone, video-replay and banner IR attacks, RGB
     genuine and banner frames), each through both backends at the wired
     thresholds. Recognizer: embedding cosine at least 0.999996, match
     scores against a reference within 0.00038, no flip on 1,347 genuine
     IR and 282 genuine RGB frames, and none on 222 IR and RGB attack
     frames scored against the owner they present (zero-effort impostor
     pairs were not part of this set). FLIR: deltas up
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
   - A marker write and remove costs 13 µs on the laptop's disk; the marker
     as shipped costs about 50 µs (Amendment 2026-10-08).

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
CPU: every stored template comes from the CPU reference, so no template depends
on the NPU, a fallback or a stack update, and the only mixed comparison is an
NPU probe against a CPU template, which section 7 certifies. That holds only
for templates the entry's own CPU reference produced, so each new scan also
records its producer (the recognizer digest, the ONNX Runtime version and the
CPU reference digest of section 3), an additive field beside `embed_space`,
which today records the recognizer digest alone. An attempt uses an NPU probe
only when every scan of the user's enrollment that it can match carries the
entry's producer; otherwise, including for every enrollment made before this
field, the probe is computed on CPU, as today, until the user enrolls again.
When an IR adapter is configured (`IRLUME_IR_ADAPTER`; none ships since
ADR-0004), the recognizer stays on CPU: an adapter is user-supplied, transforms
the raw IR embedding before its own threshold, and is part of no certification.

The experimental IR-only route also stays on the CPU reference, regardless
of the recognizer's placement; see the [2026-10-22 amendment](#amendment-2026-10-22-experimental-ir-only-probes-stay-on-cpu).

### 3. A per-model certification table in the source

Device selection is per model and decided by a table compiled into
`irlume-vision`. An entry binds three things: the model's SHA-256, a platform
identity (section 4), and the CPU reference it was certified against: the ONNX
Runtime version, the wired thresholds that consume the output, a fingerprint of
the CPU session's decoded outputs for fixed synthetic inputs through irlume's
own preprocessing, the SHA-256 of the CPU session's raw output bits for the
same inputs, and a fingerprint of the recognition decision downstream of them
(for fixed synthetic score pairs and brightness weights, the cosine match, the
per-enrollment IR calibration (its fit, its map applied to probe and templates,
and the calibrated-centroid arm), Platt scaling, brightness weighting, fusion,
template selection and every grant verdict the production code returns). A
model runs on the NPU only when its digest, the running identity and the loaded
ONNX Runtime version all match an entry, and when at every engine build the
live CPU session reproduces the entry's CPU output digest exactly. The CPU
session repeats those bits across processes, core types and thread placement
(measurement 4), so a runtime of the same version that computes differently on
this host or CPU, by any amount, does not inherit the certification; any other
combination runs on CPU. Tests recompute the thresholds and both fingerprints
from the current code, so a change to preprocessing, decoding, the decision
code, a threshold or the ONNX Runtime output fails them until the entry is
certified again or removed in the same change. There is no `AUTO`, `HETERO` or
`MULTI` device, and no selection by device availability or speed. An
entry is added only by a reviewed change that cites its certification evidence
(section 7).

An entry does not admit the experimental IR-only route to the accelerator;
that route has no separate certified decision coverage.

Amended 2026-10-10 by ADR-0033: the "no GPU" clause of this prohibition
is superseded there; the GPU is eligible under this table's regime, one
explicit device, while `AUTO`, `HETERO` and `MULTI` remain refused.

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
the accelerator node, the build of the firmware the kernel loaded, the compile
configuration of section 6, and the SHA-256 of every runtime library the daemon
maps once the NPU is enumerated (OpenVINO and its plugins, the Level Zero
loader, the NPU user-mode driver) plus the NPU compiler loader that applying
the configuration loads and the NPU compiler and IR and ONNX frontends that
compiling loads, which are resolved by path beside the mapped plugin and core
and hashed before any compile, so the identity, its cache directory and its
markers are known before the first compile and whether or not a cache import
maps them. Each library is hashed through one open file whose inode is kept.
When the platform opens and after every compile, every OpenVINO or Level Zero
library the process has mapped must be one of them with the same inode;
otherwise the model stays on CPU and what that compile wrote to the cache is
discarded, so a package update between hashing and loading cannot run bytes the
identity does not name. The device is not compared, because on btrfs `stat` and
the memory map report different devices for the same file (measured), and an
update renames a new file into place, so it always has a new inode. A rebuilt
library that keeps its version string, or a distribution update of the Level
Zero loader, is therefore a different identity; hashing the libraries makes
discovery take about 0.5 s. The driver accepts other kernel and firmware
combinations, and the qualified stack already pairs a compiler and a firmware
of different interface versions, so the firmware is not implied by the driver
version. The kernel reports the loaded build in the device's `fw_version`
debugfs entry; it is readable by root, the daemon's `ProtectKernelTunables=`
mounts debugfs read-only rather than hiding it, and kernel lockdown still
permits read-only debugfs entries. A firmware build that cannot be read makes
the identity unreadable, and every model runs on CPU. A difference in any field
is a different identity. The kernel release is not a field: Fedora ships a
kernel every few days, and keying on it would keep the NPU off most of the
time. A kernel driver fault that returned plausible but wrong output is what
the parity check of section 8 catches, and a kernel update always brings a
reboot and so a new engine build; section 10 bounds a crash. Doctor reports the
running kernel release.

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
3. **Real evaluation data.** The genuine and impostor pairs of the corpora that
   set the recognizer's thresholds (LFW for RGB; CBSR NIR and Tufts for IR) and
   FairFace's impostor pairs as a demographic leg (FairFace has no identity
   labels, so no genuine pairs), each comparison an NPU probe against a CPU
   template; and the recorded presentation attacks of enrolled users that the
   PAD cues are evaluated on, each scored against the presented user's
   template. Because the fusion arm combines an RGB and an IR score with both
   brightness weights, paired cases also run through the production fusion and
   profile-selection code: recorded RGB+IR pairs where they exist, and
   otherwise every combination of the corpora's RGB and IR comparisons over the
   recorded brightness range. Production takes the best score over up to 90
   scans (3 profiles of 30) against a threshold scaled by the template count,
   so the corpora also run as production-shaped enrollments across the
   supported template counts, with each enrollment's IR calibration fitted as
   enrollment fits it, so the calibrated probe, the calibrated templates and
   the calibrated-centroid arm are all exercised, and rules 4 and 5 compare the
   final grant decisions, not only pairs.
   (Amended 2026-10-22, below: the copy and extent of each corpus; the
   recorded sessions of a fixed private manifest, the run manifest derived
   from it before each run, and named re-recordings of six recordings it
   lacks; the decision, household, fusion and enrolled-user arms with their
   zero-effort impostor populations; the attack arms on one-profile and
   household enrollments; the brightness grid; every production threshold
   value; the exclusions; and the enrollment shapes that keep their probes
   on CPU.)
4. **No new grant for an impostor or an attack; error rates no worse.** No
   impostor comparison that the CPU denies may be granted on the NPU, at any
   threshold, fusion floor or production-shaped decision, whatever the
   aggregate rates do. No presentation attack whose recognizer verdict the CPU
   denies may be granted by the recognizer on the NPU, whatever the PAD cues
   decide, so a later change to the PAD cues cannot turn a masked difference
   into a grant. Beyond that, the NPU probes' false-accept rate is not above
   the CPU probes', and their false-reject rate is not above the CPU's by more
   than 0.2 percentage points; genuine pairs may change verdict within that
   budget. Every verdict that differs is listed, and each lies within the
   measured maximum drift of its threshold.
5. **Drift small against the threshold.** The maximum absolute score drift
   d, read as a shift of the threshold on the CPU scores, moves the
   false-accept rate by at most 10% of its value (one pair in 100,000 when
   it is zero) and the false-reject rate by at most 0.2 points. This stays
   meaningful where the classes overlap at the threshold, as they do for the
   recognizer; the recognizer's measured 0.00038 would move LFW's
   false-reject rate at 0.55 by about 0.09 points.
6. **Repeatable.** An input gives the same output bits every time on one
   compiled model: repeated, interleaved with other inputs, after the NPU has
   runtime-suspended, and after a system suspend and resume of the certified
   machine.
   (Amended 2026-10-22, below: a run separate from items 3 to 5, through the
   production compile, that records every system suspend and counts every
   resume recheck, each of which must pass.)
7. **Crash-free.** 20 cold compiles in separate processes with the cache
   bypassed, 20 warm loads from the cache, and 1,000 inferences, some after
   runtime suspends and some after system suspends, without a crash or an
   error.
   (Amended 2026-10-22, below: compiles and warm loads go through the
   production compile into a cache the run owns, emptied for each cold
   compile with the driver stack's compiler cache off; every other run
   records its driver-cache setting.)
8. **Recorded.** The evidence (identity, model digest, run counts, deltas,
   margins, verdict tables, no biometric data) is archived and cited by the
   change that adds the entry.
   (Amended 2026-10-22, below: the difference record. A private arm, one
   that consumes recorded data or a CBSR, Tufts or Oulu-CASIA score, spans
   its whole extent under an id from a fixed list and is archived only as
   its counts, drift, outcome, flip totals in each direction, a within-drift
   flag and the digest of its local list, which opens with a random value
   drawn for the run. That list, with every difference at any drift and the
   verdict tables, and the run's console output stay on the measuring
   machine for the maintainer alone; the record leaves it only after its
   validator, run there as root, has passed it; and such an arm with a
   difference above a drift of 1e-5 is refused.)

### 8. Compilation happens at startup, not in an attempt

NPU sessions are compiled when the engine is built, after its CPU sessions and
before the daemon reports ready, at startup and at every engine rebuild. No
compilation happens inside an authentication attempt. Each entry records the
SHA-256 of the NPU's output bits for three fixed reference inputs. The NPU
repeats those bits exactly, across inferences and across processes (measurement
4), so every engine build requires the recorded digest, together with the live
CPU digest of section 3, before the recognizer answers from the NPU; any other
bits keep it on CPU, and doctor says so. A system suspend can outlive the
engine, so after one the recognizer reproduces the NPU digest again before its
next NPU answer (about 21 ms; the CPU session is not affected by a suspend, and
its check is not repeated); a mismatch retires it to CPU and that answer is
computed on CPU. A suspend is detected as growth of `CLOCK_BOOTTIME` over
`CLOCK_MONOTONIC`, which counts system suspend only, not the NPU's runtime
power-down while idle. A kernel, driver or firmware change that alters the
NPU's numerics therefore needs a new certification, and one that does not alter
them does not. Discovery with the library digests takes about 0.5 s; from the
cache the recognizer then adds 0.4 to 0.5 s before ready, and after an identity
change the first start compiles it cold, 2.2 to 5.2 s. Until ready, clients get
the existing "still starting" answer and use the password.

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
cache's marker directory, and removes it when the call returns (about 50 µs per
inference on the shipped path, measured; Amendment 2026-10-08). The marker is
committed before OpenVINO is entered: written to a temporary file, renamed into
place and read back; if that fails, the call is not made and the model stays on
CPU. A marker that exists but cannot be read, or holds no boot ID, counts as
one from the current boot. Markers are kept across identity changes within a
boot, so a rollback to an identity that crashed still finds its marker; startup
removes those of earlier boots. A marker from the current boot found at startup
means a compile or an inference did not return (a crash, or a hang a watchdog
restart ended): that model stays on CPU for that identity for the rest of the
boot, and doctor says so. A marker from an earlier boot allows one new attempt,
so a power loss does not pin a model to CPU. Discovery (loading the plugin,
enumerating the device, reading the identity) has its own boot-scoped marker,
so a crash or hang there is not repeated either. Discovery and every compile
count as worker activity for the watchdog, startup included, so one that does
not return within `WatchdogSec=` (90 s, against a longest measured cold compile
of 5.2 s) stops the pings and ends in a restart rather than a hang. With
`Restart=on-failure`, a crashing or wedged compile or inference costs one
restart, never a loop.

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

Amended 2026-10-10 by ADR-0033: the maintainer reopened the GPU question on
the #1053 measurements (which show the accelerator faster, not a failed
user-facing latency budget), and ADR-0033 admits the GPU under this ADR's
regime, keeps CPU the default until a certification passes, and leaves the
execution-provider (CUDA, TensorRT) lane inert.

## Consequences

- A build without `npu`, or with it and an empty table, makes the decisions it
  makes today on every host. `doctor` can report the platform before any model
  is certified.
- Existing enrollments keep authenticating on CPU until the user enrolls
  again, because their scans do not record the certified producer; an ONNX
  Runtime update does the same for scans made before it.
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
  `CacheDirectory=`, a weak dependency on the stack only when the table has
  an entry for an identity that package can meet, and AppArmor rules for
  `/dev/accel/accel[0-9]*` (read and write), the OpenVINO and Level Zero
  libraries (map and read), `/sys/kernel/debug/accel/*/fw_version` (read)
  and `/var/cache/irlume/npu/**` (read and write); without the last two the
  identity is unreadable and nothing can be cached. Other lanes are
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
  or the recognition decision code (IR calibration, Platt scaling, brightness
  weighting, fusion, matching, template selection) fails the fingerprint and
  threshold tests.
- Producer: an attempt against an enrollment with any scan that lacks the
  entry's producer, or carries another one, computes its probe on CPU.
- Compiler: the plugin compiler is set and read back; a host where it cannot
  be selected runs the model on CPU.
- Parity: an NPU that does not reproduce its entry's reference digest, or a
  CPU session that does not reproduce its entry's CPU digest bit for bit,
  leaves the model on CPU before it answers a request.
- Resume: after a system suspend the NPU digest is checked again before the
  next NPU answer; a mismatch leaves the model on CPU and that answer comes
  from the CPU session; without a suspend it is not rechecked.
- Adapter: with an IR adapter configured, the recognizer stays on CPU.
- Libraries: changing the bytes of any runtime library in the identity, the
  Level Zero loader included, changes the identity.
- Loaded as hashed: a runtime library replaced after it was hashed, deleted
  while mapped, or mapped without being hashed keeps the model on CPU.
- Discovery: a discovery marker from the current boot keeps every model on
  CPU without loading the plugin again.
- Packaging: under the enforcing AppArmor profile, the identity reads back
  (firmware included) and the cache and markers are written.
- Eligibility: only the recognizer can have an entry; the PAD cues, the
  detectors, the ONNX mesh fallback and TFLite models never do.
- Enrollment: with the recognizer on the NPU, enrollment scans come from the
  CPU session.
- Experimental IR-only: its inference explicitly uses the CPU view even
  with a placed recognizer, and the route never sets probe admission. The
  source guard checks all production modules and catches multiline direct
  embedding calls outside the two admitted probe helpers.
- Evidence builds: global and dependency-only measurement cfg injection
  refuse every affected shipped artifact; normal builds still compile.
  Alternate ORT providers, an unadmitted measurement launch, a reused or
  aliased production cache, and a purported cache import that recompiled
  all refuse before supporting certification evidence (amendment below).
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
  one, and a return to the old identity in the same boot still sees them; a
  marker that cannot be written keeps the model on CPU without calling
  OpenVINO, and one that cannot be read or holds no boot ID counts as
  current.
- Watchdog: a compile that does not return stops the watchdog pings, at
  startup and at a rebuild.
- Cache: the directory is 0700 root and per identity, other identities'
  directories are removed, and the CLI never creates it.
- Decisions: with a model on the NPU, grants and denials come from the same
  thresholds, votes and PAD availability rules as on CPU; certification
  compares final grant decisions on production-shaped enrollments of 1 to 90
  scans.
- Threshold set (amendment 2026-10-22): the generated set equals every
  threshold the identity arms can return without an IR adapter, for every
  template and profile count, and a changed scaling constant, cap or fusion
  floor changes the set and the decision fingerprint.
- Decision arms (amendment 2026-10-22): the planners reproduce the
  enumerated counts of the extent record from file names for LFW, CBSR and
  Tufts, the household enrollments of the attack arms included (149,515 of
  shape (k, k) and, without the household member, 15,840 of shape (k, 0),
  per maintainer camera and order), take the first n alignable images in the
  arm's order, leave out each probe the CPU reference cannot align, derive
  the shuffle from the file-list digest, and give the same RGB verdict in
  the filled and the balanced layout.
- Shapes (amendment 2026-10-22): probes stay on CPU for every enrollment
  outside the admit list, whose shapes both an impostor arm and an attack
  arm reach (one profile with n_ir <= n_rgb <= 30, or two or three profiles
  of equal (k, k) or (k, 0) with k <= 30; each profile with three or more IR
  scans holding a calibration fitted from exactly its current pairs, every
  other profile none). A test covers each refusal: four profiles, 31
  matchable scans, profiles of unequal shape, IR on part of the scans of
  several profiles, a profile of three or more IR scans without calibration,
  and a calibration not fitted from the current pairs.
- Fusion arm (amendment 2026-10-22): the grid holds both knees of each ramp
  and the recorded endpoints between them; recorded pairs fuse as recorded;
  at every grid point the closed-form counting agrees with the production
  `fuse` on a dense grid of cosines and weights and on every candidate; the
  range-wide counts equal those at the two extreme grid points; the shift
  moves both input cosines before the verdict is recomposed; in the
  sequential posture neither fusion nor the RGB-primary arm grants.
- Difference record (amendment 2026-10-22): the validator refuses a line
  outside the grammar, a path or a name, and treats an arm as public only
  when every source digest the arm names is an LFW or FairFace copy on its
  list. On any other arm it refuses an id that is not on the compiled list
  of private arm ids, a second line for one id, and, at any drift, a
  difference line, a per-threshold count or budget line, a nearest-score
  line and any field beyond the arm's id and class, counts, drift, outcome,
  summed flip totals, within-drift flag and list digest; it refuses a
  missing list digest, a pass with the flag unset, a pass of an impostor,
  attack or negative arm with a new grant, and an arm that measured nothing
  (other than the no-face control), or has a flip while its drift is above
  1e-5, but is not marked refused. The writer of a private arm is built only
  from the arm's whole plan, never from one shape or one measured budget.
  The local check refuses a list that does not open with its random value.
  For a public arm the validator refuses a margin above the drift and
  difference lines that do not equal the flip counts. A run with a private
  arm prints only the harness result line, the local check's line and the
  validator's line, and its record leaves the root-only directory only after
  the validator, run there as root, has passed it.
- Wire: new status fields decode with a frozen copy of the pre-change client
  types, and a pre-change daemon's status decodes in the new client.
- Hardware (`#[ignore]`, Lunar Lake): the identity reads back; every
  eligible model compiles with the batch fixed to 1 and reports
  `EXECUTION_DEVICES=NPU`; outputs track ONNX Runtime CPU on fixed synthetic
  inputs and on recorded frames, with the PAD cues' drift reported;
  interleaved and post-suspend inferences repeat bit for bit.

## Amendment 2026-10-08: marker cost on the shipped path

Measurement 4's 13 µs timed a plain write and remove. The marker as section
10 ships it (a temporary file, its permissions, a rename and a read-back,
then the removal) costs 47.6 µs per inference on the qualified laptop's
`/var/cache` and 52 µs on its home filesystem, both btrfs (median of five
runs of 1,000; #1042). That is under 1% of a 7 ms recognizer inference, so
section 10's marker around every inference stands.

## Amendment 2026-10-09: provider selection and closed native loading

This amends sections 3, 4, 5 and 13. Provider selection, portable identity
matching and reporting remain groundwork: no installation/launch profile is
admitted, native entry is refused, and `CERTIFIED` remains empty. CPU
authentication remains authoritative. Settings cannot bypass either gate.

### Provider selection

Upstream distributions, distro builds, root-managed source installations and
intel-npu-stack follow the same rules. The reference stack is optional. The
resolver checks `libopenvino_c.so.2621` before `libopenvino_c.so.2620`, using the
fixed system directories from section 5 followed by `/usr/local/lib64`,
`/usr/local/lib/x86_64-linux-gnu` and `/usr/local/lib` for each soname.
An absolute `npu_library` machine setting selects a file in another prefix;
`IRLUME_NPU_LIBRARY` on the daemon takes precedence. Canonical targets also
accept the full filenames `libopenvino_c.so.2026.2.0` and
`libopenvino_c.so.2026.2.1`. Filename acceptance grants no model certification.

Invalid authoritative values, malformed assignments to the exact key, duplicate
keys, unreadable settings and untrusted paths refuse selection rather than
choose another provider. Automatic lookup advances only on absence; other
lookup errors refuse. Files and installation ancestors must be root-owned
without group/other writes, with root-owned symlinks and trusted targets.
The selected alias remains the legacy identity input; the validated canonical
endpoint is the prospective native loading path. C API selection uses neither
a bare loader name nor user library-search environment variables.

### Closed native loading

Loading admission refuses before `dlopen`, binding loading or device
enumeration for automatic and explicit selection alike. A future profile
must establish effective native dependency/plugin/driver loading routes,
compiler/frontend configuration, trusted code locations and the process
launch environment. It must keep one provider for the process lifetime and
require a daemon restart when that provider changes. Root ownership of a
C API file and later content hashing do not establish this contract.

Opening the gate requires a separately reviewed implementation and conformance
evidence for the installation and launch arrangement. Enforcing AppArmor
validation and any required rules remain future work. This amendment admits
no profile, enables no package feature and adds no certification entry.

The [measurement-only build contract](#amendment-2026-10-22-measurement-only-evidence-builds)
below does not open this production admission.

### Separate exact and portable identities

The full section 4 identity retains the selected C API alias and original
path-based manifest membership. Its digest continues to name diagnostics,
caches, identity-specific markers and exact-key entries. Expanded inventory
coverage does not rewrite legacy digests or widen exact entries.

Portable qualification requires a separate v2 execution manifest containing all
observed absolute file-backed executable mappings plus the known compiler
loader, compiler, IR frontend and ONNX frontend hashed before compile. This
conservatively binds unrelated shared native libraries too. The process
executable identified by `/proc/self/exe` remains in mapped-file/inode checks
but is excluded only from the portable key, avoiding self-reference when an
entry is compiled into that executable. Failure to identify it in the inventory
refuses construction. All observed shared native code stays keyed; anonymous
executable mappings and non-executable data files are outside this inventory.
Executable files mapped later without an entry and deleted/replaced mapped
files refuse placement. Distinct paths with duplicate basenames refuse portable
qualification even when their content matches.

The versioned execution key omits directory prefixes but retains basenames,
content hashes and the hardware/firmware/runtime/compiler/configuration fields.
An entry using that key can match equivalent layouts only when those fields
match. Model and CPU producer/consumer bindings, thresholds, decision
fingerprints and live reference parity checks remain required. Section 7's
certification requirements are unchanged. The inventory is a content identity
check, not loading admission or proof of native dependency closure.

### Discovery reporting and peer privacy

Discovery observations are separate from context/cache readiness and model
placement. A failure before discovery runs reports no observation; native
loading-admission refusal also reports none. A discovery error otherwise records
unavailability. Completed discovery retains availability and its platform digest
across later marker-cleanup, cache-preparation or placement errors.

Optional status fields distinguish runtime availability and current qualified
placement, preserving absence for older peers. Engine placement is not a
per-account guarantee: matchable scans with absent or different CPU-producer
tags require CPU probes, including legacy scans. Non-root Health replies use
fixed fallback categories; only root peers receive native error details, which
also remain in bounded privileged journal diagnostics. The user-facing contract
is [NPU provider selection](../NPU.md).

### Acceptance criteria

Software checks cover malformed/duplicate settings, environment precedence,
nonabsence lookup errors, selected-alias continuity, legacy-manifest preservation,
sibling/external executable inventory, prefix normalization, duplicate ambiguity,
content/inode changes, executable-key exclusion, pre-native refusal,
discovery/cache transitions and root/non-root Health projection. These checks
do not admit a native profile, establish real installation relocation, validate
enforcing AppArmor or certify a model.

## Amendment 2026-10-22: certification corpora and decisions at full extent

Section 7 item 3 names the corpora and the decision shapes a certification
runs. It does not say how much of each corpus runs, at which threshold
values items 4 and 5 apply, or how item 4's list of differing verdicts
reaches the record of item 8. A bounded subset can leave an arm with nothing
near its threshold. On the UX5406S on 2026-10-22, the 3,000 impostor pairs
of the LFW 10-fold protocol held no CPU accept at 0.55, and their nearest
CPU score sat 0.2087 below it, so that arm could not have shown a new grant
at any drift under 0.2. That run (identity `1f570994`, f32) also embedded
its accelerator probes through test-side copies of the preprocessing and
judged 0.55 only, so it is an input to certification, not a pass of it ([the
extent record](../research/2026-10-22-certification-extent.md)).

This amendment fixes the extent before any certification run. Items 4 and 5
keep their rules; this amendment fixes what they run over and which
enrollment shapes an entry covers. It amends item 8's record for recorded
data of people and for corpora whose terms restrict sharing, and it sets the
conditions of the separate runs for items 6 and 7. It admits no loading
profile, enables no package feature and adds no certification entry.

### What set the thresholds

`RGB_MATCH_THRESHOLD` moved to 0.55 on 2026-06-28 (commit `11cf4a9e`) on two
measurements. One is LFW grouped by identity over every pair: 5,749
identities, 242,257 genuine and 87,307,271 impostor unordered pairs, and a
false-accept rate of 3e-5 at 0.50 and 2e-5 at 0.55. It ran on archhost over
the original, non-aligned LFW images as packaged on Hugging Face
(`marcelohaps/lfw` at `12a61458`), cloned there 25 minutes before commit
`1bf31564` recorded the first run, and the committed
[`lfw-aura.txt`](../recognition-results/data/lfw-aura.txt) is byte for byte
that host's 2026-08-04 re-run over the same clone. The other is FairFace
over every pair within each demographic group
([FAIRNESS.md](../FAIRNESS.md)), on the validation split of its 0.25
configuration (`HuggingFaceM4/FairFace` at `54d573cd`): each committed group
result is byte for byte that host's 2026-08-04 output over a tree whose
files equal that copy's, and every group reproduced the June rate to the
printed digit.

The SFHQ figure that the comment of `11cf4a9e` also cites, 9.8e-5 at 0.50,
named no subset; the committed re-run gives 4.71e-4 at 0.50 and 1.43e-4 at
0.55 ([`sfhq-aura.txt`](../recognition-results/data/sfhq-aura.txt)), and
item 3 does not name SFHQ. The 2.3e-3 at 0.50 of [VERIFY.md](../VERIFY.md)
section 5 pairs every image of the deep-funneled Kaggle copy
(`jessicali9530/lfw-dataset`) with every other, genuine pairs included, and
the 2.0e-3 at 0.55 that commit `565d193c` put beside it in the `irlume-core`
comment matches the all-pairs rate that the identity-grouped run's counts
imply. They are an upper bound, not an impostor rate.

Both LFW copies are therefore gating families. The original images are the
threshold's own extent; the deep-funneled copy gates because the published
upper bound cites it. FairFace runs its 0.25 validation copy, the
threshold's own, and no other configuration gates.

The false-reject side of 0.55 rests on live genuine sessions of the
maintainer: the live floor that commit `11cf4a9e` cites, and the
`calcapture` sessions of 2026-08-05 on archhost's Logitech Brio and the
Zenbook's built-in camera, whose anchor runs landed on that floor ([the
2026-08-05 record](../recognition-results/2026-08-05-buffalo-l.md), lines
34-36; [`MANIFEST.json`](../recognition-results/data/MANIFEST.json)
`frr_leg`). The sessions' aggregates live in
[`floor-aggregates.json`](../recognition-results/data/floor-aggregates.json).
Their raw records hold CPU embeddings, not frames, as do the self-captured
pairs of ADR-0004's validation bed, so neither can be replayed through an
accelerator. The genuine side of certification is carried by the recorded
frames below and their named re-recordings, not by these files, and the
household member's older captures in that bed are not used.

`IR_DARK_MATCH_THRESHOLD` 0.635 rests on the CBSR split of
`benchmarks/securedark_sweep.py` (the first 11 sorted frames enroll, the
other 9 probe), the Tufts calibrated arm and the live dark session of
2026-08-23 (ADR-0016). The pairwise CBSR run that the `IR_MATCH_THRESHOLD`
comment cites (7.72M impostor pairs) has no output in the repository; the
committed pairwise CBSR results use 6,000 pairs per arm.

### Copies

Each corpus runs from one named copy, recorded by its source, revision,
derivation and a digest of its sorted per-file SHA-256 list:

| Family | Copy | Images | Archived |
|---|---|---|---|
| LFW, original | Hugging Face `marcelohaps/lfw` at `12a61458` | 13,233 | per comparison |
| LFW, deep-funneled | Kaggle `jessicali9530/lfw-dataset` | 13,233 | per comparison |
| FairFace | Hugging Face `HuggingFaceM4/FairFace` 0.25 validation at `54d573cd`, JPEG quality 95 | 10,954 | per comparison |
| CBSR NIR | Kaggle `gpreda/cbsr-nir-face-dataset` | 3,940 | aggregates |
| Tufts TD_RGB_A and TD_NIR_A | Kaggle `wahabarabo/tufts-faces` | 3,234 pairs | aggregates |
| Oulu-CASIA NIR-VIS | Kaggle `aryanbaibaswata/oulu-casia` | 64,912 | aggregates |

The Kaggle mirrors of CBSR, Tufts and Oulu-CASIA are the certification
copies by the maintainer's decision of 2026-10-22, as the LFW threshold copy
is itself a re-post. Their owners' terms are quoted in the record and put to
the maintainer, not accepted on the maintainer's behalf: CASIA's release
agreement forbids distributing or publishing its database "either entirely
or partly", the Tufts terms forbid giving research associates and colleagues
access and distributing it to anyone who has not agreed to them, and no
published terms were found for Oulu-CASIA. Their images, and every
comparison and decision that consumes one of their scores, stay on the
measuring machine, and their arms are archived only as aggregates (The
record, below).

### Corpora

Every comparison is an accelerator probe against a CPU template, as item 3
says. The CPU score of a pair is symmetric, but a comparison of an
accelerator probe with a CPU template is not, so every pair runs in both
directions. A sample or a cap is a development run, not certification
evidence. The record gives every count by file name.

- **LFW.** Every ordered within-identity pair and every ordered
  cross-identity pair of each copy: 484,514 and 174,614,542. An identity is
  the file name without its trailing `_NNNN` index, the `irbench --lfw`
  rule. The 6,000 pairs of the 10-fold protocol are a reported sub-arm.
- **FairFace.** Every ordered pair within each group, 17,556,198 in all.
  Each group is its own arm and no pair crosses groups. The consecutive
  pairs of each sorted group are a reported sub-arm.
- **CBSR NIR.** Every ordered pair: 74,860 genuine and 15,444,800 impostor
  comparisons.
- **Tufts.** Every ordered pair within each modality: 96,162 genuine and
  10,359,360 impostor comparisons each, over 110 subjects. An identity is
  the subject directory, and an RGB image pairs with the NIR image of the
  same set, subject and file suffix, which gives 3,234 pairs.
- **Oulu-CASIA NIR-VIS.** A supplementary arm: it set no threshold and item
  3 does not name it. It runs because it is the only public corpus with NIR
  and visible images of the same subjects under three recorded lightings
  (dark, weak and strong). Every ordered pair within each modality and
  lighting runs, and items 4 and 5 apply to it as to every arm.

### Recorded sessions

A private manifest on the measuring machine fixes the recorded data. Its
SHA-256 is
`3236ea19bda75b5afcb66afb4d72ea4c67c7f0ab2299c7daa0547a98938c84a9`, and it
lists 73 sessions:

| Category | Camera | Sessions |
|---|---|---|
| Genuine, the maintainer | Zenbook built-in, IR bursts and RGB | 39 |
| Genuine, the maintainer | NexiGo | 10 |
| Genuine, the maintainer | Zenbook RGB webcam | 3 |
| Genuine, one other consenting household member | Zenbook RGB webcam | 1 |
| Presentation attacks, all showing the maintainer's face | Zenbook | 8 |
| Presentation attacks, all showing the maintainer's face | NexiGo | 11 |
| No-face control | Zenbook | 1 |

An arm runs every frame of every session the manifest lists in its category.
The manifest records which sessions and categories make up the extent.
Before any run, local code derives from it a run manifest, which stays
beside it on the measuring machine. The run manifest keeps every row of the
manifest and adds each session's camera, its modality read from the decoded
channel count (not a directory name) and the SHA-256 of its file list. The
record of each run names the run manifest by its SHA-256. A file under the
manifest's root that no row covers, or a changed file-list digest, refuses
the run. A session of anyone who has not consented is neither listed in the
manifest nor kept under its root.

The manifest holds the attack recordings of the 2026-07-17 PAD candidate
evaluation ([its record](../pad-results/2026-07-17-third-party-pad-candidates.md)):
the live banner runs, four on the NexiGo and three on the Zenbook as that
session's log records, its phone attacks and its offline banner corpus. It
also holds the seven NexiGo attack bursts that the 2026-08-21 FLIR
revalidation cites, in whose 252 frames no face is detectable in IR.

It does not hold six recordings that earlier decisions rest on: the IR
liveness self-test of 2026-06-30 behind ADR-0013's breach figure, the
re-measurement of 2026-07-27 at the FLIR threshold of 0.9, the #516 fleet
banner runs, the 2026-08-12 flrgb live session and the 2026-08-22 ViT live
corpus behind the ViT cue's evaluation (ADR-0013), and the live dark session
of 2026-08-23 behind 0.635 (ADR-0016). Their frames were not found on any
host or archive searched on 2026-10-22, and the #516 runs kept one score per
call. Each is re-recorded under its original protocol in the maintainer's
approved attended session, and a later manifest names each re-recording as
the replacement of its session; no entry is added before then.

### Decision arms

Items 4 and 5 also compare final grant decisions, computed by the production
identity arms (the lit arms of `identity_arms.rs`, the dark arms of
`ir_assessment.rs`) over enrollments built by the production scan path, with
the producer stamped and the IR calibration refit as enrollment refits it.
Each probe is embedded by the production probe helpers under the probe rule
of section 2, in a measuring process that a later amendment defines; no
setting reaches it. The gates are held passing, so the recognizer decides
alone.

An enrollment of n templates takes the first n images of an identity that
the CPU reference can align, in the arm's order, as the sweep behind 0.635
takes its first 11 embedded frames. An identity enters a size only with an
alignable image left to probe, and a probe the CPU reference cannot align is
left out of every decision it would have made. Each decision arm records the
enrollments and decisions it enumerated, excluded and measured. Every
decision arm on a corpus, except the two replayed splits, runs in two
orders: sorted relative paths, and a shuffle that sorts each identity's
images by the SHA-256 of the copy's file-list digest in lowercase
hexadecimal, a tab and the image's relative path. The shuffle follows from
the copy; nothing is chosen at run time.

- **Single identities.** For LFW every n from 1 to the smaller of 90 and the
  identity's alignable images less one; for CBSR and Tufts up to 30. The
  identity's other images are genuine probes, and every image of every other
  identity is an impostor probe. Above 30 templates an LFW identity's scans
  fill several profiles, which no enrollment does, since a face never owns
  two profiles; the arm reaches the RGB thresholds for 31 to 90 templates
  that households reach, and the filled and the balanced layout both run.
- **Households.** Two or three identities, each its own profile holding its
  first k images, the same k for every member, for every k up to 30 at which
  each member keeps a probe. Every member's other images are genuine probes,
  since any enrolled face unlocks the account, and every image of every
  identity outside the household is an impostor probe. LFW households are
  drawn from the identities with at least 31 alignable images, CBSR and
  Tufts households from every identity.
- **Replayed splits.** CBSR has no RGB, so no calibration is fitted, and the
  production dark decision there is best-of-n at the scaled
  `IR_DARK_MATCH_THRESHOLD` with no centroid. The split behind 0.635 runs as
  it was measured, within one session as the sweep states, and the release's
  own gallery and probe split runs as distributed. The sweep's raw-centroid
  OR (false-accept rate 1.24e-4 at 0.635) is not a production decision and
  is reported for continuity only.
- **Tufts, calibrated.** Tufts enrollments hold paired scans. From k = 3,
  the smallest fit, the production fit at the shipped ridge lambda runs over
  each profile's k pairs; the calibrated probe is scored against the
  calibrated templates and the calibrated centroid at the scaled thresholds,
  and impostor probes are calibrated with the victim's map, as production
  calibrates any probe.

Every CBSR and Tufts arm also runs at the dim-light fallback bar. For a
decision arm, the d of item 5 is the arm's largest absolute drift over every
score its decisions consume: raw RGB, raw IR, calibrated IR and
calibrated-centroid cosines. The shift moves every CPU input score of the
arm by d, in each direction, before the CPU decision is recomputed. For a
best-of-n arm this equals moving its scaled threshold.

### Fusion

The fusion arm runs the production fusion verdict, floors included, in four
classes: genuine with genuine, which is the genuine class; impostor with
impostor; and the two mixed classes, which are negative arms. Recorded RGB
and IR pairs are fused as recorded: the Tufts pairs and the maintainer's
paired frames. Beside them the arm fuses every combination of a corpus RGB
comparison (each LFW copy and FairFace) with a corpus IR comparison (CBSR
and Tufts NIR), each pairing of sources its own arm, and every combination
of an Oulu-CASIA visible and NIR comparison of the same lighting. At the
decision level the best scores of single-identity decisions of the same n
combine, and decision arms on paired data, the Tufts arms and the enrolled
users' arms, run the full lit decision, fusion included, at every grid
point. Both postures run; in the sequential posture neither fusion nor the
RGB-primary arm may grant on either device.

The brightness weights come from a grid. Per modality it holds the two knees
of the weight ramp in `irlume-core` (60 and 130 for RGB, 35 and 110 for IR)
and the lowest and highest production face-box luma over the recorded
frames, rounded outward to whole units, where they lie between the knees.
Every pair of an RGB and an IR value is a grid point, weighted by the
production ramps, so the grid spans every weight pair production can give
and the recorded range inside it. Brightness is an input of the attempt, as
the image is, and the grid samples it as the corpora sample faces: items 4
and 5 apply at every grid point. The fused score moves monotonically with
the ratio of the two weights, so a combination accepted at some ratio in the
range is accepted at one of the two extreme grid points, and a genuine
combination rejected at some ratio is rejected at one of them; the arm also
counts its rates over the whole range from those two points.

The arm's d is its largest drift over the RGB and IR scores it combines, and
the shift of item 5 moves both input cosines by d before the fused verdict
is recomposed. The comparison-level combinations (9.6e15 for the corpus
pairings, 4.1e16 for Oulu-CASIA) are counted exactly by searches over sorted
scores, and only those within the drift of a boundary go one by one through
the production `fuse` (the record).

### Enrolled users' arms

Recorded data runs through the full lit and dark decisions: the RGB arm,
fusion, the dim-light fallback, the calibrated centroid and the dark arms. A
face never owns two profiles, since enrollment folds a matching face into
its profile, so each person's enrollments hold one profile. Per camera, an
enrollment of shape (n_rgb, n_ir) takes that person's first n_rgb frames the
CPU reference can align, in the manifest's order, keeps the paired IR frame
of the first n_ir of them, and fits the calibration as enrollment fits it.
The maintainer's enrollments take every shape with n_ir <= n_rgb <= 30 that
the camera's recorded modalities allow, the household member's every n_rgb
up to 30 without IR. Every other genuine frame of that person and camera is
a genuine probe. Each arm names its zero-effort impostor population, scored
against the same enrollment at every shape:

- RGB arm: every alignable image of both LFW copies and FairFace; the
  household member's frames against every maintainer enrollment (same camera
  for the Zenbook enrollments); and the maintainer's RGB frames against
  every enrollment of the household member.
- Fallback, calibrated, centroid and dark arms: every alignable CBSR and
  Tufts NIR image, calibrated with the enrolled person's map wherever the
  shape has one.
- Fusion: the person's own recorded pairs as the genuine class, and every
  combination of the RGB and NIR impostor decisions above, with the two
  mixed classes, at every grid point in both postures.
- Attacks: each attack session against every enrollment of the maintainer
  from the camera that recorded it, at every shape, and against the
  household enrollments built from them (below).
- No-face control: a negative arm against every enrollment the attack arms
  build from its camera. It is the one arm that may measure nothing, since
  the CPU-only pass may exclude all of its frames; any frame it keeps is
  held to the negative-arm rule.

Production scales the RGB, fallback and dark thresholds by the enrollment's
scan count over every profile, and the centroid bars by its profile count,
so an attack on an account of two or three profiles of k scans is decided at
the values for 2k or 3k templates and at the two- and three-profile centroid
bars. A household enrollment puts the attack frames there: it joins a
maintainer enrollment of shape (k, k) or (k, 0) to one or two companion
profiles of the same shape, each fitted as enrollment fits it. The
companions of (k, k) are the Tufts subjects that the Tufts households of
that k draw from; those of (k, 0) are the identities of the LFW households
and the household member. Every companion and every pair of companions
joins, the corpus companions' images in both orders. Each attack frame is
also compared with every template of the maintainer's enrollments from its
camera, an RGB frame at every RGB value and an IR frame at every fallback
and dark value, and with the calibrated centroid of each of those
enrollments at every centroid bar for 1 to 3 profiles.

### Shapes an entry covers

An enrollment shape is admitted only where both an impostor arm and an
attack arm of this amendment reach it:

- one profile of any (n_rgb, n_ir) with n_ir <= n_rgb <= 30, reached by the
  enrolled users' arms and the corpora's single-identity arms, and by the
  attack arms on the maintainer's enrollments;
- two or three profiles of equal shape (k, k) or (k, 0) with k <= 30,
  reached by the Tufts and LFW households, and by the attack arms on
  household enrollments;
- in either case, every profile with three or more IR scans holding a
  calibration fitted from exactly its current pairs, and every other profile
  none.

Every other enrollment keeps its probes on the CPU. That covers more than 3
profiles, more than 30 matchable scans in a profile, profiles that differ in
their numbers of RGB or IR scans (such as a profile with IR beside one
without), several profiles whose scans carry IR only in part, a profile with
three or more IR scans and no calibration, and a stored calibration not
fitted from the profile's current pairs.

### Thresholds

Items 4 and 5 apply at every threshold value production can use for the
comparison or decision. The values are generated from the code rather than
listed: the RGB, dim-light fallback and dark bases, each scaled for every
template count, which also gives the calibrated-centroid bars for 1 to 3
profiles; and the fusion floors `FUSION_PROB_THRESHOLD` and
`FUSION_MIN_PER_MODALITY_PROB`. A configured IR adapter keeps the probes on
CPU, so the adapted base is not in the set. Under today's constants each
base gives 90 values for 1 to 90 templates, 270 distinct in all, and 102 up
to the cap, which binds from 102 templates. RGB comparisons run at the 102
RGB values and IR comparisons at the 204 fallback and dark values, although
no admitted shape reaches the values above 90 templates; each decision runs
at the value its own shape uses. A test requires the generated set to equal
every threshold the identity arms can return without an adapter.

At this extent f32 rounding alone may break the no-new-grant rule. Such a
failure is the answer, not a reason to relax the rule. The fusion floors are
the likeliest place: the RGB floor is a cosine of about 0.245, which between
0.1% and 1% of LFW's impostor comparisons exceed, and every RGB comparison
near it meets every IR comparison.

### Exclusions, labels and limits

A comparison is left out only when the CPU reference's detection cascade
finds no usable aligned face in one of its images. That CPU-only pass runs
before any accelerator probe and fixes the list, and each arm records what
it enumerated, excluded and measured. In the runs of items 3 to 5 some
errors fail the run instead of shrinking it: a decode error, a detector
runtime error, an accelerator answer replaced by a CPU one (a fallback, a
retirement, the runtime guard or a resume discard), and any resume recheck.

Labels are fixed before scoring. A FairFace pair the CPU accepts stays a CPU
false accept, and the manifest's categories are the labels of the recorded
sessions.

Items 4 and 5 stay per arm, per corpus copy and per demographic group, with
the inclusive integer limits of the measurement code, and no arm joins
another's denominator. Below 500 genuine comparisons, no net extra rejection
and no shift movement is allowed. A negative arm with no CPU false accept
allows no shift movement below 100,000 comparisons.

### The record

Item 4's list and item 8's deltas, margins and verdict tables form one
difference record in a fixed line grammar. The identity is archived without
paths, as library basenames with their digests. The archived record stays on
the project share, and the change that adds an entry cites it by digest; git
carries per-arm aggregates only.

An arm is public only when every source of the scores it consumes, probe and
template alike, is an LFW or FairFace copy named above by its file-list
digest, and the validator holds that digest. For a public arm the archived
record holds, per threshold value and grid point, the enumerated, excluded
and measured counts and every budget field; per differing verdict, the arm,
the threshold value or grid point, the file-list ordinals of the comparison,
both accept flags, both margins and the arm's drift; and per copy its
source, revision, derivation and file-list digest. A margin is the smallest
equal shift of the verdict's input cosines that flips that device's verdict;
for a verdict on one cosine it is the distance to the threshold. Every grant
in these arms only grows with each of its cosines, so where verdicts differ
each margin is at most the drift, and the validator refuses a larger one.

Every other arm is private, whatever its writer called it: an arm that
consumes recorded data of the maintainer or the household member, as probe
or as template, or any CBSR, Tufts or Oulu-CASIA score. Recorded data of
people is biometric data under item 8, and those three corpora's terms
restrict sharing.

A private arm spans every shape, threshold value and grid point of one
pairwise or decision arm, for one person and camera, or one corpus copy or
pairing of copies, and one class; each impostor population, modality,
lighting and demographic group is an arm of its own. Its id comes from a
fixed list compiled into the validator, and no id names a shape, a template
or profile count, a threshold value or a grid point. The validator refuses a
private arm whose id is not on that list or appears twice in one record, and
the code that writes a private arm cannot build it from one shape or from
one threshold value's measurement.

A private arm leaves the measuring machine only as its enumerated, excluded
and measured counts, its drift, its outcome, its differing verdicts in each
direction summed over its whole extent, one flag saying whether every margin
lay within the drift, and the SHA-256 of its local difference list. That
list opens with a 256-bit random value drawn for that run and kept only in
that list, so its digest discloses nothing of its content. Nothing per
shape, threshold value or comparison of a private arm is archived, at any
drift: the validator refuses a difference line, a per-threshold count or
budget line and a nearest-score line on any private arm, and a pass of an
impostor, attack or negative private arm with any new grant.

The local difference list holds every differing verdict of a private arm at
any drift, with its ordinals, both accept flags and both margins, and the
arm's verdict tables per shape, threshold value and grid point. Item 4's
list and item 8's verdict tables for these arms are met there, and the
maintainer reviews them in place. The list stays on the measuring machine in
a root-owned file of mode 0600 in a 0700 directory and never enters git, the
share or a cloud drive. Everything else the measuring process writes during
a run with a private arm, its standard output and error included, stays with
the list under the same rule, except the archived record, which leaves that
directory only after the validator, run there as root, has passed it. Local
code checks the list against the archived record, refuses a list without its
random opening value, and prints only the result. No agent, model service,
CI job or remote reviewer reads the list or that output, and no part of
either is pasted into an issue, pull request, chat, ledger or shared file.

A private arm that measured nothing, other than the no-face control, or that
has any differing verdict while its drift is above 1e-5, is recorded as
refused and supports no entry. The validator refuses the whole record if it
contains any line outside the grammar, any path, or any token naming a
person, the host or a session.

### Items 6 and 7

The runs of items 3 to 5 contain no suspend and no resume recheck. The runs
of items 6 and 7 are separate. They expect system suspends and record each
one; they count every resume recheck and resume discard, and every recheck
must pass; and every compile and warm load goes through the production
compile, with its marker and per-inference inventory check, into a cache the
run owns. The production compile has no way to bypass its cache, so each of
item 7's cold compiles starts from an emptied run cache instead, with any
compiler cache of the driver stack turned off. Every other run, warm loads
included, records the driver-cache setting it ran under, and an entry holds
only under that setting. The 2026-10-21 runs for items 6 and 7, and the hold
witness of ADR-0033's runtime-suspend amendment of 2026-10-22, ran in
`irlume-vision`'s unit-test binary through test-only compile paths, which
have neither the marker nor the inventory check. They are inputs, and they
are repeated before any entry, whatever the certification key shows.

## Amendment 2026-10-22: experimental IR-only probes stay on CPU

The experimental IR-only pipeline in `ir_assessment.rs` embeds through
`IrInference::embed`. It used the placed recognizer directly, without the
ordinary probe helpers' CPU-reference fallback, and set a probe-admission
flag that its direct call did not consult. The existing source guard read
only `lib.rs` and did not detect the multiline call in that module.

This route now explicitly calls the recognizer's CPU view and does not set
probe admission. The ordinary dual-sensor probe helpers retain their
existing admission and certification checks. This restriction applies to
both NPU and GPU placement; a matching recognizer entry alone does not
certify the experimental route's composed decisions. Admitting that route
later requires its own decision-fingerprint coverage and the corresponding
CPU-template/accelerator-probe evidence under section 7.

The source guard now visits production Rust modules below `irlume-auth/src`,
excluding dedicated test files and support modules, and normalizes
whitespace so a multiline call cannot evade it. Inline test modules are
also checked as a conservative superset. Only the two existing probe
helpers may call the placed recognizer's embedding methods. A separate
regression requires the experimental inference to use the CPU view and
forbids its unused admission assignment.

Both certification tables remain empty and loading admission remains closed.
No threshold, camera selection, IR-only opt-in, liveness check, grant rule
or password fallback changes. This pins the CPU behavior that the empty tables already
give this route; it does not qualify an accelerator.

## Amendment 2026-10-22: measurement-only evidence builds

The full-extent runs need the production preprocessing, probe, compile and
guard paths. The existing `#[cfg(test)]` hardware helpers do not supply
that proof. This amendment specifies a separate, non-shippable evidence
build, initially for the GPU recognizer. It implements nothing by itself:
the guards, measurement-launch admission and evidence interfaces must be
reviewed and tested before any such run. Ordinary loading admission stays
closed, both certification tables stay empty, and no threshold changes.

### Build boundary

The build is selected by the rustc configuration `irlume_hw_evidence`,
never a Cargo feature or a runtime setting. Registering an expected cfg
name with `--check-cfg` does not enable it. The build must be refused at
all seven shipped Rust roots: `irlume-cli`, `irlume-daemon`,
`irlume-gkr-unlock`, `irlume-kwallet-init`, `irlume-password-verify`,
`irlume-pam` and `irlume-pam-view`.

Each root has a direct cfg compile error. `irlume-vision` also exports its
build's cfg state as a constant; every shipped consumer of that crate
rejects a true value at compile time even when the consumer's own cfg is
absent. CLI and daemon additionally refuse at their first runtime action.
Tests enumerate the shipped artifacts and dependency closure, exercise
both global and dependency-only injection, and require normal builds to
compile. Package and release definitions must never select this cfg.

These are mistake-prevention guards for the reviewed source and toolchain,
not protection against a builder who edits the guards or compiler. A
measurement build is never installed as an authentication component.

#### Build-boundary implementation, 2026-10-23

The build-boundary guards are implemented separately from reference isolation
and launch admission. Each internal Rust library reports its own evidence
cfg OR its direct internal dependencies' markers; an ordinary library
rejects an evidence dependency. Each shipped root has a direct cfg refusal,
and each shipped library consumer also rejects the aggregate dependency
marker. This includes markers originating in auth, core or liveness rather
than only in vision. The CLI and daemon call the terminating refusal routine
as their first startup action. A marked start exits with status 1; its fixed
stderr diagnostic is best-effort and cannot make the routine wait indefinitely.

The compiler regression matrix checks normal and marked library builds,
all seven root-only refusals, reverse mixed builds, individual consumer
guards and an unmasked auth/liveness edge. Cargo metadata pins both target
membership and normal dependency edges; a restricted source check verifies
every marker's terms and active startup wiring. Compiler receipts record
which units were marked and the intended refusal diagnostics. These guards
do not provide a launch capability or make an evidence runtime available.

### Reference isolation

An evidence build rejects the ORT execution-provider features `cuda`,
`openvino`, `coreml` and `tensorrt` at compile time. The separate `npu`
feature, which supplies the direct OpenVINO runtime, is allowed. Any
presence of `IRLUME_TEST_ALLOW_UNCERTIFIED_EP` refuses the run before a
model session is built. Every ORT session used for detection, reference
inference or enrollment uses the exact-default CPU provider, without
inherited environment providers. The LiteRT path and delegates must match
the CPU baseline; measurement introduces no accelerator delegate.
The existing `on_cpu()` view alone does not establish that condition: it
bypasses the placed accelerator slot but uses the existing ORT session.

Negative tests combine the evidence cfg with each forbidden feature and
with the escape variable. A reference run must not silently become an
accelerator run, even if its outputs happen to agree.

### Measurement-launch admission

Bypassing the ordinary deployment admission requires a distinct,
default-closed measurement-launch admission. A reviewed host-specific
profile and runner must exist before any real provider is loaded. The cfg,
a trusted C API file and post-load hashes are not substitutes for it.

A trusted launcher, itself started under a trusted loader configuration,
checks the profile before executing a fresh measurement process. The
profile fixes the binary/build identity, explicit environment allowlist,
complete native dependency/plugin closure (including ORT, LiteRT,
OpenVINO and drivers), configuration and trusted native search locations.
It covers loader configuration such as RPATH,
RUNPATH, the loader cache and preload files; inherited loader overrides
are refused. Any OpenCL or driver settings used by the run come from the
reviewed profile, not the caller's environment. Unknown or writable native
dependencies and incomplete profiles refuse before initialization or
warm-up, including when the run needs privilege.

Each process keeps one provider for its entire lifetime; changing it
requires a new process.

The context accepts a validated launch capability, not a self-asserted
environment marker. Post-load and per-inference inventory checks remain
mandatory. A compromised launcher, hostile root or modified toolchain is
outside this assurance; direct execution with an arbitrary inherited
environment is unsupported and must refuse. The runner has no PAM or
daemon-authentication interface and does not access installed enrollment,
keyring or TPM state; its launch profile restricts those resources.

The evidence record names its measurement profile. Success under that
profile does not establish the installed daemon's launch or confinement
contract and cannot open the production admission. That remains the
separate work of ADR-0033 section 4 and #1162.

### Cache and production path

The runner creates a fresh, empty, owner-only 0700 cache on an approved
local filesystem and retains ownership across its child processes. The
evidence API requires that owned cache capability, not an arbitrary path.
It refuses pre-existing contents, symlink components and production cache
paths or aliases before any cache preparation or cleanup. Cleanup may
remove only the runner's own tree.

The candidate uses every production certification field and the production
parity, marker, compile, inventory, runtime-guard and retirement paths.
It is not inserted in `CERTIFIED` and never matches a production lookup.
Opening this evidence path does not add an NPU counterpart or authorize
another model or decision route.

A second process must prove cache import through the same guarded compile
wrapper. It reads back the requested cache, `LOADED_FROM_CACHE` and fixed
compile properties; a second successful compile, short duration or blob
file alone is not proof of import. Empty, corrupt, ignored or unobservable
caches cannot pass the import arm. The implementation must expose strict
cache observation through the production guarded wrapper rather than use
the existing unguarded test entry.

### Evidence conditions

Start/end records come from the same retained compiled model and require
unchanged identity, configuration and mapped inventory. CPU reference,
template and initialization/parity calls are named phases, separate from
the measured accelerator probes. Counter deltas bracket each probe with
no concurrent model calls; this does not change its internal thread pool.
Any measured probe answered by CPU, retirement, resume discard or resume
recheck makes an item 3-5 run unusable. Those runs also refuse a suspend.
The separate item 6-7 runs retain their existing suspend, recheck and cache
requirements; the no-suspend rule is not applied to them.

The full-extent, per-arm and private-record rules of the earlier amendment
remain binding. Raw output and difference lists for private arms stay
owner-only; only the permitted aggregate record may leave after its local
validator passes. No model or device is certified merely because this
build compiled or a measurement process exited successfully.

## Amendment 2026-10-23: bounded decision fingerprint

The decision fingerprint uses the versioned domain
`irlume-decision-fingerprint/2`. It binds threshold coverage and composed
decisions in addition to the original arm grid. It remains a reference for
fixed synthetic inputs, not a substitute for the full-extent qualification
in this ADR. Both certification tables stay empty and native loading stays
closed. Authentication thresholds, grant policy and password fallback do
not change.

### Threshold coverage

The generator calls the existing production threshold helper. It finds
the first exact capped bump using `scaled_threshold(0.0, count)`, without
changing the scaling expression. A dense search stops at count 4,096.
Unsupported scale values, an unreachable cap or a cap beyond the supported
count budget fail construction; there is no truncated success.

Two domains retain role, adapter state, count and exact value bits:

- Enrollment-sized inputs cover template counts 0 through 90 and centroid
  profile counts 0 through 3. Adapter centroids are omitted because the
  production matcher does not construct them.
- Complete inputs cover every count through saturation for all five roles,
  including defensive adapter-centroid inputs. Saturation is currently 102.

The domains contain 463 and 927 records respectively. Each separately
projects sorted, bit-deduplicated RGB and IR cosine values, excluding
adapter records and count zero. Their current sizes are RGB90/IR180 and
RGB102/IR204. Fusion's probability threshold and per-modality floor remain
separate from the cosine projections. Checked size arithmetic precedes
allocation and every append checks the 65,536-record budget.

### Composed decisions

The 527 fixed witnesses call the production matchers, lit and dark
selectors, and fusion function. They cover inclusive comparison boundaries,
competing successful arms, distinct winner names, fusion and calibrated
profile ties, both
sequential deferrals, absent or incompatible IR, malformed calibration,
and mixed tagged/untagged calibration provenance. Production-width vectors
exercise repeated cosine accumulation across multiple eight-element chunks.

Construction checks actual returned score bits and required outcomes before
accepting each record. Per-family counts and ordered IDs detect omitted
cases; each append checks a 1,024-record budget. Input vectors, template
tags, calibration factors and relevant enrollment shapes are encoded with
the outputs so different same-verdict refusal cases cannot substitute for
one another. No model, file, camera or user enrollment is read by this
builder. The independent 4,610-case engine characterization remains intact.

### Stream and failure contract

The outer SHA-256 transcript starts with a `domain` frame and then five
named SHA-256 section digests, in order:

1. `legacy-arm-grid-sha256`, computed from the original stream unchanged;
2. `threshold-constants-sha256`, binding bases, scaling and fusion constants,
   enrollment limits and generation budgets;
3. `enrollment-thresholds-sha256`, with its records and projections;
4. `complete-thresholds-sha256`, with its records and projections;
5. `composed-witnesses-sha256`, with ordered family/ordinal IDs and framed
   input/output records.

Every outer frame carries its name length, name bytes, payload length and
payload bytes. New lengths, ordinals and counts are unsigned 64-bit
little-endian integers, booleans and enum tags are single bytes, and f32
values use their exact bits in little-endian order. Strings carry a length
before their bytes. The legacy section retains its original 32-bit lengths
and native-size count fields; its separate preservation test remains.

Explicit byte order does not make the mathematical results portable.
Rust 1.88 documents [unspecified precision for
`f32::log2`](https://doc.rust-lang.org/1.88.0/std/primitive.f32.html#method.log2),
among other functions in the decision path. Exact reference checks must
run on the claimed build environments; no cross-platform equality follows
from the format alone.

Construction returns a checked digest only after every section succeeds.
Both runtime context openers consume that checked result and return
CPU/NotCertified on failure without invoking the provider opener. The
source-compatible public `decision_fingerprint() -> String` returns an
empty string on failure and is not used for native admission. No result is
cached. A changed digest invalidates certification bound to an older one.

[intel-npu-stack]: https://github.com/archledger/intel-npu-stack
[intel-npu-stack#20]: https://github.com/archledger/intel-npu-stack/issues/20
[npu_compiler#352]: https://github.com/openvinotoolkit/npu_compiler/issues/352
[measurement 4]: ../research/2026-10-08-npu-measurements.md

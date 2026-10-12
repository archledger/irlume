# GPU platform identity probe (ADR-0033 section 3)

- **What:** #1053 identity measurements behind the complete GPU
  identity slice. A C probe read the GPU plugin's device properties
  through the real installed C API, matched the plugin's PCI report
  against the DRM render node sysfs tree, and recorded which native
  libraries the GPU enumeration mapped. The purpose was to establish,
  on the shipped 2026.2.1 builds, exactly what an ADR-0033 section 3
  identity can observe, which loader stack the plugin resolves, and
  what the driver-version property does. Platform facts only; no
  biometric data.
- **Where and when:** 2026-10-11. minihost (Alder Lake-N integrated
  GPU, 24-EU class, `/dev/dri/renderD128`; OpenVINO 2026.2.1
  root-owned archive under `/opt/openvino-2026.2.1-lib`) and the
  UX5406S laptop (Lunar Lake Arc 140V integrated GPU, `renderD128`;
  Fedora RPM `/usr/lib64/libopenvino_c.so.2621`).
- **How:** a C probe through the real C API (`ov_core_get_property`
  on the enumerated `GPU.0`), plus reads of
  `/sys/class/drm/renderD*/device` (address, `vendor`, `device`) and
  `/proc/self/maps`. On minihost the runtime was reached only through
  the test process `LD_LIBRARY_PATH`; no installed loader or system
  library changed on either host.
- **Primary sources:** OpenVINO tag 2026.2.1
  `src/plugins/intel_gpu/src/plugin/plugin.cpp` `get_property`
  (`DEVICE_PCI_INFO` formatted `{domain: %u bus: %u device: 0x%x
  function: %u}`, with `GPU_DEVICE_ID` and
  `GPU_EXECUTION_UNITS_COUNT` around lines 586 to 673);
  `src/common/zero_loader/src/zero.api.cpp` (Level Zero builds dlopen
  `libze_loader.so.1`) while the OpenCL backend links
  `libOpenCL.so.1`; the kernel's `pci-sysfs.c` `vendor` and `device`
  attributes; the DRM render node's `device` symlink into its PCI
  device directory.

## minihost findings

Runtime build `2026.2.1-21919-ede283a88e3-releases/2026/2`, reached
through the test process `LD_LIBRARY_PATH` only.

| Observation | Value |
|---|---|
| `DEVICE_PCI_INFO` | `{domain: 0 bus: 0 device: 0x2 function: 0}` = `0000:00:02.0` |
| sysfs render node | `renderD128` at `0000:00:02.0`, vendor `0x8086`, device `0x46d1` |
| `GPU_DEVICE_ID` | `0x46d1`, equal to the sysfs device attribute |
| `DEVICE_ARCHITECTURE` | `GPU: vendor=0x8086 arch=v12.4.0` |
| `GPU_EXECUTION_UNITS_COUNT` | 24 |
| `GPU_DEVICE_TOTAL_MEM_SIZE` | 7125323776 |
| `DEVICE_TYPE` | integrated |
| Capabilities | FP32 BIN FP16 INT8 GPU_USM_MEMORY EXPORT_IMPORT |
| GPU plugin build (`Core::versions("GPU")`) | `2026.2.1-21919-ede283a88e3-releases/2026/2` |
| Loader family | OpenCL ICD: `libOpenCL.so.1.0.0`, `libigdrcl.so`, `libigc.so.2.41.0`, `libigdgmm.so.12.10.0`; Mesa `libRusticlOpenCL.so.1.0.0` also mapped |

The plugin's PCI report and the render node agree on address, vendor
and device: `0000:00:02.0` is `renderD128`'s sysfs address, and
`GPU_DEVICE_ID` equals the node's `device` attribute.

## UX5406S findings

Fedora RPM 2026.2.1, GPU plugin build `2026.2.1-000--`.

| Observation | Value |
|---|---|
| `DEVICE_PCI_INFO` | same `0000:00:02.0` BDF as minihost |
| sysfs render node | `renderD128` at `0000:00:02.0` |
| `GPU_DEVICE_ID` | `0x64a0` |
| `DEVICE_ARCHITECTURE` | `GPU: vendor=0x8086 arch=v20.4.4` |
| `GPU_EXECUTION_UNITS_COUNT` | 64 |
| `GPU_DEVICE_TOTAL_MEM_SIZE` | 30629367808 |
| Capabilities | the minihost set plus `GPU_HW_MATMUL` |
| GPU plugin build (`Core::versions("GPU")`) | `2026.2.1-000--` |
| Loader family | OpenCL ICD: `libOpenCL.so.1.0.0`, `/usr/lib64/intel-opencl/libigdrcl.so`, `libigc.so.2.41.9`, `libigdgmm.so.12.10.0`; no Rusticl mapped |

## The GPU_DRIVER_VERSION defect

- Reading `GPU_DRIVER_VERSION` through `ov_core_get_property` kills
  the process with SIGSEGV. Deterministic on both measured builds:
  the root-owned archive on minihost and the Fedora RPM on the
  UX5406S. Exact repro: create the core, enumerate `GPU.0`, call the
  property read for `GPU_DRIVER_VERSION`; the call never returns and
  the process dies.
- A bare device index as the device name crashes the same way:
  passing `"0"` where `"GPU.0"` is expected segfaults on both builds.
  The implementation therefore always names the device `GPU.N`.
- Design consequence: the identity never reads `GPU_DRIVER_VERSION`.
  Driver identity comes from the hashed mapped-library manifest
  below, which already makes a driver or compute-runtime rebuild a
  different identity under the one-open-file inode discipline.

## Loader stacks

- Both measured builds resolved the OpenCL ICD family: the plugin
  links `libOpenCL.so.1`, and no Level Zero loader (`libze_loader`)
  was mapped on either host, matching the upstream sources (the
  `zero.api.cpp` dlopen path belongs to Level Zero builds).
- On minihost, ICD enumeration also mapped Mesa's
  `libRusticlOpenCL.so.1.0.0` beside the Intel driver libraries: a
  foreign ICD ran enumeration code inside the process. This is why
  the manifest inventories every file-backed executable mapping
  rather than a guessed name closure.
- Manifest scope, as implemented: every file-backed executable
  mapping from `/proc/self/maps` (minus the process executable, as the
  NPU execution inventory excludes it), plus the IR and ONNX frontends
  beside the core (which compiling loads), each hashed through one
  open file whose inode is kept, re-verified against the maps after
  compile.

## Property surface

`SUPPORTED_PROPERTIES` lists every key above. All of them, including
the numeric-looking ones (`DEVICE_PCI_INFO`, `GPU_DEVICE_ID`,
`GPU_EXECUTION_UNITS_COUNT`, `GPU_DEVICE_TOTAL_MEM_SIZE`), return as
strings through `ov_core_get_property`; the consumer parses. The
fixed compile configuration the identity carries is
`batch=1;PERFORMANCE_HINT=LATENCY;INFERENCE_PRECISION_HINT=f16`, and
a test-only platform compiles on `GPU.0` under it, requires
`EXECUTION_DEVICES` to name that GPU, and re-verifies the mapped
libraries after the compile (the retirement trigger).

## Standing

This is measurement evidence only. Loading admission stays closed
(production discovery refuses before `dlopen`), `CERTIFIED` stays
empty, and CPU authentication stays authoritative. The record feeds
the identity implementation and its `gpu_hw_*` hardware tests; it
places nothing.

## Phase 4 measurement correction, 2026-10-12

These are measurement-only lanes in PR #1058, following the merged
identity slice (#1057). Earlier phase-4 tables are superseded: their
collectors omitted PNM frames or nested attack labels, their rescue
used the ONNX mesh alternative, and their populations cannot stand
as evidence for the corrected default-native-mesh path.

Test source: `crates/irlume-vision/src/onnx/gpu_tests.rs` SHA-256
`bc177053c5d7dc444eef9f67a2484f4d552bcadd9d5e9e56de19648111c3a7a8`,
Rust 1.88.0 release build with `npu`. Hardware: UX5406S Arc 140V,
Fedora 44, installed OpenVINO 2026.2.1, ONNX Runtime 1.28.1 and
native TFLite CPU mesh. Configuration remains
`batch=1;PERFORMANCE_HINT=LATENCY;INFERENCE_PRECISION_HINT=f16`.
Kernel `7.2.9-201.fc44.x86_64`, compute-runtime RPM
`26.35.39758.11-3.fc44`, OpenVINO RPM `2026.2.1-1.intelnpu.fc44`.

Receipt identifier: `r6-20261012`. The synthetic CPU-reference digest
reported by the compile lane is
`cbee96a116304c8a6e1d7890258254f1f4db41896b3fa58ceb9a2b224fad4a7a`.
This is a runtime fingerprint from fixed synthetic inputs, not a
biometric template. The local private receipt retains the exact
invocation; the share-safe record below contains only aggregate results.
Executed binary SHA-256:
`d06c873d6ee6a96991b238ac5f779daeb26c7e7779d40fb9a9d11a2d4764f693`.
The combined run finished 5 tests passed, 0 failed in 3557.99 seconds.
This includes the suspend lane's inconclusive no-suspend path, not a
qualified post-resume result.

The release test binary was built with
`cargo +1.88.0 test --release --locked -p irlume-vision --features npu --lib -- gpu_groundwork_tests --test-threads=1`.
It was then run as root with zero core limits and CPU affinity `0-3`:

```sh
env ORT_DYLIB_PATH=/usr/share/irlume/onnxruntime/lib/libonnxruntime.so \
    IRLUME_TFLITE_LIB=/usr/share/irlume/tflite/libtensorflowlite_c.so \
    IRLUME_NPU_TEST_MODELS=/usr/share/irlume/models \
    IRLUME_NPU_EVAL_DIR="$SUNCAL_ROOT" \
    IRLUME_GPU_CORPORA_LFW="$LFW_ROOT" \
    IRLUME_GPU_CORPORA_FAIRFACE="$FAIRFACE_ROOT" \
    IRLUME_GPU_TEST_SUSPEND_WAIT_SECS=10 \
    "$VISION_TEST_BINARY" --ignored \
    gpu_hw_identity_binds_plugin_render_node_and_libraries \
    gpu_hw_compile_parity_and_retirement_under_the_fixed_configuration \
    gpu_hw_real_frames_track_cpu gpu_hw_recognition_corpora_drift \
    gpu_hw_suspend_resume_recheck --test-threads=1 --nocapture
```

The root variables stand for the existing suncal session tree, LFW
`train` plus its canonical eight-field `pairs.csv`, and FairFace's
seven demographic group directories. Pair caps use the unchanged
defaults: 400 genuine and 400 impostor LFW comparisons and a 2600
FairFace cap shared within groups. These are bounded evidence subsets,
not whole-dataset evaluations.

Every lane loads the same CPU recognizer, YuNet, BlazeFace and default
`face_landmarks_detector.tflite` before GPU inventory capture. Each
receipt names its actual identity. The recorded-frame receipt reports
digest `f85917697c1fc39ddc9f0e15bb2ca9a84d66aaa69bdc7fef56ce41e52af272ed`
with 37 mapped libraries, including the CPU runtimes. All five combined
lane receipts agree exactly. Three additional fresh processes, run in
suspend-baseline/discovery/compile order, each passed its single selected
test and reported the same digest, configuration, library count and
native-mesh baseline. The standalone compile also reproduced all four
synthetic GPU input digests and the CPU-reference fingerprint. The
standalone suspend wait was zero; it qualifies no post-resume behavior.

Every artifact is checked against the embedded committed
`models/SHA256SUMS`; a model root chooses a location, not accepted
hashes. The recognizer hash is
`a7933ea5330113b01c9b60351d8f4c33003f145d8470ac5f0e52ee2effe25c60`.
RGB probes use production TTA; IR probes remain plain. CPU and GPU
embeddings use production normalization. Templates remain CPU
embeddings. Detection and alignment use CPU models; PAD, fusion,
calibration and template-count authentication decisions are not
measured by these pairwise lanes.

### Recorded genuine frames and presentation attacks

The corrected recursive suncal walk includes PGM/PPM and nested
attack takes: 2627 decoded frames, 2160 usable aligned faces, 67
top-level session directories. Classification uses directory
components, not image names. The first usable genuine frame of each
modality supplies its CPU template before any attack is scored.

| Arm at 0.55 | n | max abs drift | flips |
|---|---|---|---|
| genuine IR | 1474 | 0.000730 | 0 |
| IR presentation attacks | 138 | 0.000285 | 0 |
| genuine RGB (TTA) | 339 | 0.000274 | 1 rejection |
| RGB presentation attacks (TTA) | 209 | 0.000196 | 0 |

The lane passed its mapped-inventory, non-vacuity and zero-new-attack-
grant assertions. Its reported lowest CPU/GPU embedding cosine was
0.999994; the recorded-frame lane does not assert a cosine bound.
One genuine RGB comparison accepted by CPU was rejected by GPU; this
is not identical decision parity and must not be read as certification.
The CPU cascade attempted 568 rescues, recovered 101 faces, and
reported zero geometric mesh refusals and zero alignment refusals.
Unexpected inference failures and input read/decode/traversal errors
refuse the measurement rather than disappearing as no-face samples.

### Recognition corpora

The corrected canonical LFW and within-group FairFace lane passed.
Headers, pair rows, labels and referenced files validated, and all
seven demographic groups contributed measured comparisons.

| Arm at 0.55, RGB TTA | n | max abs drift | flips |
|---|---|---|---|
| genuine LFW | 400 | 0.000236 | 0 |
| impostor LFW | 400 | 0.000229 | 0 |
| impostor FairFace | 2597 | 0.000313 | 0 |

Zero new impostor grants over 2997 impostor comparisons. FairFace's
2600 cap is divided by seven groups using integer quotas: 371 per
group, hence 2597 measured pairs, not 2600. Skipped candidate pairs
are replaced within each group until its measured quota is reached.

| FairFace group | discovered images | measured pairs | skipped candidate pairs |
|---|---|---|---|
| Black | 1556 | 371 | 18 |
| East Asian | 1550 | 371 | 12 |
| Indian | 1516 | 371 | 18 |
| Latino Hispanic | 1623 | 371 | 12 |
| Middle Eastern | 1209 | 371 | 10 |
| Southeast Asian | 1415 | 371 | 16 |
| White | 2085 | 371 | 36 |

Every group's receipt reported zero flips. The cache reported 61
distinct images without a usable aligned face; skipped-pair counts
are not distinct-image counts. The CPU cascade attempted 202 rescues,
recovered 141 faces, and reported zero geometric mesh refusals and
zero alignment refusals. No input or inference error was skipped.

### Suspend and certification limits

The `r6-20261012` run qualified no actual attended suspend. Earlier
positive claims based on the production recheck trigger are withdrawn:
that trigger intentionally permits extra rechecks after scheduling
delays and is not proof of suspend. Production remains unchanged.
The measurement lane instead requires a later lower bound of
CLOCK_BOOTTIME-minus-MONOTONIC to exceed its baseline upper bound by
more than 1 ms. Delayed clock reads cannot manufacture that proof;
small suspends can remain inconclusive. A wait without proof does not
exercise or qualify post-resume checks. The lane never suspends the host.
The final combined run waited 10 seconds and explicitly reported
inconclusive evidence with no post-resume checks exercised.

IR recognition corpora, fusion/calibration/template-count decisions,
repeatability and crash campaigns remain separate
ADR-0022 section 7 obligations. `CERTIFIED` stays empty, production
loading admission stays closed, and CPU authentication stays authoritative.

## Qualification continuation, 2026-10-12

These additional observations use the same test source, binary, model
pins, Arc 140V stack and identity as `r6-20261012` above. They do not
establish full certification or change production loading admission.

### Attended system suspend

Receipt `attended-suspend-20261012` selects only
`onnx::gpu_tests::gpu_groundwork_tests::gpu_hw_suspend_resume_recheck`,
with a 1200-second wait, a 1500-second process cap, zero core limits
and CPU affinity `0-3`. The operator manually suspends the machine
after the baseline is ready, then wakes and unlocks it; the test does
not initiate a power transition.

The same process proves bounded clock growth and verifies all three
fixed synthetic output fingerprints and the mapped-library inventory
after resume. Result: 1 passed, 0 failed, 164.08 seconds. Its identity
remains `f85917697c1fc39ddc9f0e15bb2ca9a84d66aaa69bdc7fef56ce41e52af272ed`,
37 mapped libraries and the default native TFLite mesh. The kernel
journal independently records `s2idle` entry at 19:51:28 UTC and resume
and suspend exit at 19:52:13 UTC. This closes one actual system-suspend
baseline, not the runtime-suspend or 1000-inference requirements.

### Independent process observations

Twenty fresh processes each pass the exact existing compile/parity/
retirement test. All four fixed synthetic GPU output fingerprints and
the CPU-reference fingerprint repeat across processes, with the same
identity and configuration. Each process uses a fresh temporary
application model-cache directory. Runtime cache bypass and cache-hit
provenance were not queried, so these are repeatability observations,
not the required 20 cache-bypassed cold compiles or 20 warm loads.

### Observed rejection-budget gap

The recorded genuine RGB arm above has one additional rejection among
339 comparisons: `100 / 339 = 0.294985` percentage points. That exceeds
ADR-0022 section 7's inclusive 0.2-point genuine rejection-increase
budget for this measured arm. Pooling genuine IR or LFW comparisons
into its denominator would conceal, not resolve, this gap.

The earlier receipt does not record the baseline CPU/GPU rejection
counts or CPU threshold-shift rates. Its first-reference-template,
face-usable subset is not a production-shaped authentication or a
population FRR estimate. Those missing counts, drift-shift rates, IR
corpora and production fusion/calibration/template-count decisions
remain qualification work. No certification table entry is justified.

### Per-arm measurement-budget reports

The test-only collectors now emit `MEASURED_BUDGET` for each recorded
modality/population, each LFW population and each FairFace demographic
group. Reports include CPU/GPU accept and reject counts, both verdict-
flip directions and error-rate deltas as exact count fractions. Each
arm's measured maximum absolute score drift also shifts its CPU threshold
in both directions, with the resulting counts and budget outcomes.

The genuine net rejection-increase limit is inclusive `1/500`; any new
impostor or attack grant fails regardless of aggregate improvement.
Threshold-shift movement is absolute: genuine error rates may move by
at most `1/500`, negative error rates by at most 10% of their baseline
or `1/100000` when zero. Integer comparisons decide those boundaries;
rounded rates or displayed shifted thresholds never decide acceptance.
Nonfinite inputs refuse the report; empty inputs are inconclusive.

These are per-arm, fixed `score >= 0.55` budgets, not a global drift
bound over all corpora or production-shaped authentication decisions.
Reports explicitly mark `certification=NOT_EVALUATED`. A collector can
complete successfully while reporting a measured-budget `FAIL`; its
existing non-vacuity, mapped-inventory and zero-new-negative-grant
assertions remain enforced. Neither a passing collector nor a passing
partial budget supplies missing certification coverage. Comparisons
remain in memory, and output is aggregate-only; anonymous differing-
verdict margins are private in-memory audit metadata, not persisted
frames, embeddings, scores or identifying paths.

### Measured-budget receipt, 2026-10-12

Receipt `budget-report-20261012` runs the two existing data collectors on
source commit `ec62ed176e3b0418c44a41c421000bd70120e0b7`. GPU test-source
SHA-256 is `dda91f20d5c917c2f506f1799dd69ab9a1bbc2836e0e7df638bde82d05a4a791`;
the private helper is
`04c0acd97fb9180dfff7eb28c985d19a387ece7893df5ccecc91e03d324910d5`.
Binary SHA-256 is
`cacd6ad509644d1c1758577b109ae9e9160958d28414c034cdbe66e81717b40f`.
Both collectors pass their existing assertions, 2 passed and 0 failed
in 1882.85 seconds, and report the same `f8591769...` identity, 37 mapped
libraries, model pins and default native mesh as the earlier receipt.

The 13 separate partial budget reports contain two failures. In the table,
shift counts are changes in the population's CPU error count at its lower
and upper thresholds, not GPU verdict flips. Error counts are rejections
for genuine comparisons and recognizer accepts for negative comparisons.

| Arm | n | CPU / GPU errors | GPU error delta | Lower / upper CPU shift delta | Partial budget |
|---|---|---|---|---|---|
| recorded genuine IR | 1474 | 482 / 482 | 0 | -5 / +2 | FAIL, lower shift |
| recorded IR attacks | 138 | 0 / 0 | 0 | 0 / 0 | PASS |
| recorded genuine RGB | 339 | 312 / 313 | +1 | 0 / +1 | FAIL, verdict and upper shift |
| recorded RGB attacks | 209 | 13 / 13 | 0 | 0 / 0 | PASS |
| genuine LFW | 400 | 108 / 108 | 0 | 0 / 0 | PASS |
| impostor LFW | 400 | 0 / 0 | 0 | 0 / 0 | PASS |
| FairFace Black | 371 | 0 / 0 | 0 | 0 / 0 | PASS |
| FairFace East Asian | 371 | 0 / 0 | 0 | 0 / 0 | PASS |
| FairFace Indian | 371 | 0 / 0 | 0 | 0 / 0 | PASS |
| FairFace Latino Hispanic | 371 | 1 / 1 | 0 | 0 / 0 | PASS |
| FairFace Middle Eastern | 371 | 0 / 0 | 0 | 0 / 0 | PASS |
| FairFace Southeast Asian | 371 | 0 / 0 | 0 | 0 / 0 | PASS |
| FairFace White | 371 | 0 / 0 | 0 | 0 / 0 | PASS |

Recorded genuine IR has no actual verdict flip, but its lower threshold
shift changes 5/1474 errors, `0.339213` percentage points. Section 7.5's
absolute movement budget therefore fails even though that direction
improves the measured rejection rate. The upper shift moves 2/1474,
within budget. Recorded genuine RGB repeats its 1/339 additional
rejection and upper-shift failure, `0.294985` points. Neither failure
can be waived by pooling a passing arm or by the collectors' successful
exits. There are no new recognizer grants on attacks or impostors;
unchanged baseline recognizer accepts are not claims of full-system
authentication grants, and PAD decisions are not measured here.

These face-usable, pairwise subsets and first-reference recorded templates
do not estimate deployed authentication FRR/FAR. Their explicit CPU/GPU
baseline counts replace the earlier count gap, but do not fill the IR
corpora, calibration, fusion, template-count or global-drift requirements.
No certification or loading admission follows. On the same code, all 23
isolated local gates pass, including 4758 guarded workspace tests and
240 vision NPU-feature tests; synthetic reporting regressions total 18.

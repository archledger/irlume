# GPU model-cache provenance, 2026-10-12

This #1053 receipt supplies the two separate-process cache subsets of
ADR-0022 section 7, as applied to GPU by ADR-0033. It does not establish
the full crash-free or repeatability gates. CPU authentication remains
authoritative, `CERTIFIED` remains empty and GPU loading admission closed.

## Artifact and configuration

The cache controls run on source commit
`d9d091fc3e4e99a080b9275779c28ed01b562640`. Source SHA-256 values:

| Source | SHA-256 |
|---|---|
| `crates/irlume-vision/src/npu/gpu.rs` | `838f0bbe9b043102339df00d51b4ca8e54b4ad37bb6187f8b2ab572faaa89918` |
| `crates/irlume-vision/src/npu/gpu_cache_tests.rs` | `dd082217c87742a1fc944710cbc50e953c6fdcc19345737211cd1e80db7ec5b2` |
| `crates/irlume-vision/src/onnx/gpu_tests.rs` | `8d92b5e99ce75e19db17e51e7677be494aa0e280a6a1dd1ba62283e5338ebc44` |

The release test binary's SHA-256 is
`ce53025a91a7c796709aa9db9954c002a2088a3acf45d7111244fbd3bb8007da`.
The pinned recognizer is `glintr100.onnx`, SHA-256
`a7933ea5330113b01c9b60351d8f4c33003f145d8470ac5f0e52ee2effe25c60`.
The Arc 140V configuration is explicit `GPU.0`, batch 1,
`PERFORMANCE_HINT=LATENCY`, `INFERENCE_PRECISION_HINT=f16`, with OpenVINO
2026.2.1 and Rust openvino/openvino-sys 0.11.0. The warmed-platform identity
is `f85917697c1fc39ddc9f0e15bb2ca9a84d66aaa69bdc7fef56ce41e52af272ed`,
with 37 mapped libraries and the default native TFLite mesh.

Production CPU sessions and the default mesh load before inventory capture.
Every process verifies model pins, compiled configuration and assignment,
and rechecks mapped inventory after GPU work and CPU fingerprinting.
The identity's different-model warm-up is separate from recognizer work.
The legacy compile API and production admission behavior are unchanged;
the observation API and controls are test-only.

## Three prerequisite controls

Receipt `cache-pilot-20261012` uses three separate processes, in this order:

| Operation | Core / compiled `CACHE_DIR` | `LOADED_FROM_CACHE` | Result |
|---|---|---|---|
| Enabled-cache miss | both match one fresh empty private directory | `NO` | PASS |
| Automatic import | both match that retained directory | `YES` | PASS |
| Disabled model cache | both empty | `NO` | PASS |

The directory remains caller-owned and exclusive. The first miss refuses
a nonempty or unreadable directory without clearing files. The hit uses
the same model, configuration and retained directory in a new process;
existing cache files or a shorter run cannot substitute for exact `YES`.
Unknown flags, getter errors, mismatched paths/configuration/assignment
and inventory changes refuse the observation.

On this GPU build, `LOADED_FROM_CACHE` works when queried directly but is
not listed in `SUPPORTED_PROPERTIES`. The control queries it directly and
accepts only exact `YES` or `NO`, not an inferred cache state.

## Twenty bypassed compiles and twenty imported loads

After all three controls pass, receipt `cache-campaign-20261012` runs:

| Separate-process campaign | Processes | Successful | Failed | Required provenance |
|---|---|---|---|---|
| Disabled model-cache compile | 20 | 20 | 0 | empty Core and compiled directories, exact `NO` |
| Automatic retained-cache import | 20 | 20 | 0 | matched Core and compiled directories, exact `YES` |

The priming miss and pilot hit are not part of these twenty imported loads.
Each process selects exactly
`onnx::gpu_tests::gpu_groundwork_tests::gpu_hw_model_cache_provenance_control`
and completes normal teardown with 1 passed, 0 failed. The runner stops on
any failure, does not retry or replace processes, disables core dumps and
uses CPU affinity `0-3` with a 300-second per-process cap. All forty logs
are checked against the pilot's identity, model pins, configuration and
reference fingerprints, not only their successful test summaries.

Each process runs four fixed synthetic recognizer inputs, twice immediately
and once again after intervening inputs: 12 GPU reference inferences.
Their output bits match within each process and their four digests match
across all forty processes and the pilot. Dimension, norm and CPU cosine
canaries also pass. The CPU reference fingerprint is unchanged.

| Synthetic input | GPU output-bit SHA-256 |
|---|---|
| 0 | `e36d2af9fd72888075dacde07c246bfaba5c684bb74bfa2805615f053ce43ce5` |
| 1 | `ed919455e6adc7582dff748d212740ed2ff56fb8d51909cf3e69182f822e2080` |
| 2 | `1488b03d06d5eccb1a9b39ee88c5cb810c533878162cba679514078e9e224a0c` |
| 3 | `10352e5ba4b32173f4c47f0743208b19809cad4d04b9f401528437f19a6f36b2` |

CPU reference SHA-256:
`cbee96a116304c8a6e1d7890258254f1f4db41896b3fa58ceb9a2b224fad4a7a`.
The forty processes supply 480 reference inferences and **zero counted
endurance inferences**. Compile/import property queries and platform
warm-up do not count as recognizer endurance work. These controls exercise
no images, enrolled templates or real corpus data. Shared receipts retain
only aggregate fields and public-model/synthetic digests, not cache paths
or raw setup/failure diagnostics.

## Reproduction and evidence limits

The ignored control requires `IRLUME_GPU_CACHE_CONTROL_MODE` to be exactly
`bypass`, `miss` or `hit`. Miss and hit also require an existing absolute
UTF-8 directory in `IRLUME_GPU_CACHE_CONTROL_DIR`; bypass refuses a supplied
directory. Supply the pinned models and CPU/TFLite runtime as documented
in [the identity research note](2026-10-11-gpu-identity.md), build the NPU
feature test binary and invoke the exact control with
`--ignored --exact --test-threads=1 --nocapture`. Retain the miss directory
unchanged for subsequent hit processes. Do not run hardware controls as
ordinary unit tests or overlap another accelerator measurement.

Empty directories plus `NO` establish automatic OpenVINO recognizer
model-cache bypass on this wrapper path, not flushed driver, compiler or
OS caches or a globally cold GPU. Exact `YES` establishes automatic model
cache import, not performance improvement. No timing comparison is claimed.

The earlier twenty fresh-directory observations lacked these readbacks and
remain historical partial evidence. Neither campaign supplies the retained-
model 1,000-inference protocol, runtime-suspend proof or its system-suspend
subsets. A new attended suspend still requires operator readiness; this
control never triggers a power transition. The measured recorded RGB and
genuine-IR drift-shift failures, IR corpora and full production calibration,
fusion, profile selection and template-count coverage remain unresolved.
Every control reports `certification=NOT_EVALUATED`.

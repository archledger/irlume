# Lunar Lake NPU benchmark spike

Date: 2026-09-01

## Decision

Proceed with a narrowly scoped implementation experiment for an explicit Intel
NPU backend. Do not enable it in production yet.

The NPU ran every shipped ONNX graph without fallback. The two dominant CPU
stages, AuraFace and ViT PAD, improved by roughly 20x in warmed synchronous
inference. All six graphs could remain compiled concurrently, and a sequential
run of the primary five model calls averaged 16.43 ms. The comparable sum of
the existing production CPU stage benchmark was 338.93 ms.

That 20.6x comparison is an upper bound for the model portion of an
authentication, not a claim about wall-clock authentication. The NPU probe
called already-preprocessed tensors directly, while the Rust benchmark includes
YuNet preprocessing and production wrappers. Capture, consent watch, alignment,
liveness logic, and PAM interaction were not measured. Production remains
blocked on real-corpus parity at the deployed thresholds, explicit provider
assignment, runtime packaging, cache lifecycle, and energy measurement.

## Isolation and provenance

- Source: branch `exp/lunar-lake-npu-benchmark`, commit
  `fc4bbdda8c067016980152e93e85b6f028079988`.
- No host packages, services, firmware, camera state, or production Irlume
  configuration changed.
- Temporary root: `/tmp/opencode/npu-spike`.
- OpenVINO: `2026.2.0-21903-52ddc073857-releases/2026/2`, installed only in a
  Python 3.12 virtual environment.
- Level Zero loader: tag `v1.28.2`, commit
  `6369d8d642e9c7625e67f38664267f171b8e42dc`; GitHub reports the commit
  signature valid. It was built and installed only under the temporary root.
- Intel NPU userspace: official
  `linux-npu-driver-v1.35.0.20260722-29947505341-ubuntu2404.tar.gz`, SHA-256
  `398343e53fdac6023ad0856ef88bb6011b1e12447a112be55e85e27ef7f96c66`.
  Every release package signature passed `gpgv` against fingerprint
  `EA267657A608300C296B8F8AD52C9665A4077678`.
- Extracted `libze_intel_npu.so.1.35.0` SHA-256:
  `a171e8a122c43e65490b7caca39f971c2944fab2b089021d600c79a29886eef0`.
- Extracted NPU compiler SHA-256:
  `2714baf53242760711623e97a59fa7b6778cb749c7483b93089ba5d2070674ee`.
- OpenVINO's NPU compiler loader SHA-256:
  `ac79cb50c30033b917385342fab4b625e04736a1ad3e35ee8cd35606900c829b`.
- Driver discovery was constrained with `ZE_ENABLE_ALT_DRIVERS` to the exact
  extracted driver path; `LD_LIBRARY_PATH` contained only the temporary loader,
  driver/compiler, and OpenVINO directories ahead of system libraries.
- The seven installed model files passed the repository's `models/SHA256SUMS`.

## Device assignment proof

OpenVINO reported `CPU` and `NPU`, with the NPU identified as:

- full name: `Intel(R) AI Boost`
- architecture: `4000`
- PCI address: `0000:00:0b.0`
- kernel device: `/dev/accel/accel0`

Level Zero debug tracing reported successful loading of the exact temporary
`libze_intel_npu.so.1.35.0`. A synthetic add graph was compiled by explicitly
requesting `NPU`; the compiled model reported `EXECUTION_DEVICES=NPU`, and its
maximum error from the expected result was `1.6284e-4`. Every shipped graph was
also compiled with `core.compile_model(model, "NPU", config)`, then required to
report exactly `EXECUTION_DEVICES=NPU` or abort. The kernel's `npu_busy_time_us`
counter increased during every NPU benchmark and remained unchanged during CPU
runs.

The current user can open `/dev/accel/accel0`; the node was
`crw-rw-rw- root:render` during the test. Packaging must not assume this unusually
permissive mode and must validate normal `render`-group or udev access.

## Method

- Durable harnesses are `benchmarks/bench_npu_models.py` and
  `benchmarks/bench_npu_pipeline.py`. Both emit complete JSON to standard output.
- Deterministic synthetic `float32` tensors matched each production input
  shape, layout, and value range from `model_input.rs`.
- Dynamic batch dimensions were fixed to one.
- OpenVINO `PERFORMANCE_HINT=LATENCY` was used on both devices.
- NPU precision hint defaulted to `float16`; CPU outputs remained `float32`.
- Each warmed standalone result used 10 warmups. Small and medium models used
  100 timed synchronous calls; AuraFace and ViT used 30.
- The coexistence test kept all six compiled models alive, warmed the primary
  five for five rounds, then measured 30 sequential rounds.
- Host load is process CPU time divided by wall time. Values above 100% mean
  more than one CPU core was consumed.
- The benchmark began only after package temperature fell from 96 C to 50 C.
  AC was connected and the battery was charging.

The standalone command shape was:

```sh
env LD_LIBRARY_PATH="$L0_LOADER:$NPU_DRIVER_COMPILER:$OPENVINO_LIBS" \
  ZE_ENABLE_ALT_DRIVERS="$NPU_DRIVER_COMPILER/libze_intel_npu.so.1.35.0" \
  "$VENV/bin/python" benchmarks/bench_npu_models.py \
  --benchmark --warmup 10 --iterations 100 \
  /usr/share/irlume/models/face_detection_yunet_2023mar.onnx
```

AuraFace and ViT used `--iterations 30`. The coexistence and cold-compile
commands were:

```sh
env LD_LIBRARY_PATH="$L0_LOADER:$NPU_DRIVER_COMPILER:$OPENVINO_LIBS" \
  ZE_ENABLE_ALT_DRIVERS="$NPU_DRIVER_COMPILER/libze_intel_npu.so.1.35.0" \
  "$VENV/bin/python" benchmarks/bench_npu_pipeline.py \
  --models-dir /usr/share/irlume/models

env LD_LIBRARY_PATH="$L0_LOADER:$NPU_DRIVER_COMPILER:$OPENVINO_LIBS" \
  ZE_ENABLE_ALT_DRIVERS="$NPU_DRIVER_COMPILER/libze_intel_npu.so.1.35.0" \
  "$VENV/bin/python" benchmarks/bench_npu_pipeline.py \
  --models-dir /usr/share/irlume/models --bypass-umd-cache
```

Here `$L0_LOADER` is the temporary Level Zero `lib64` directory,
`$NPU_DRIVER_COMPILER` is the extracted Intel package library directory, and
`$OPENVINO_LIBS` is the wheel's `openvino/libs` directory. The numeric tables
below are the JSON fields emitted by these harnesses; no post-hoc outlier
filtering was applied.

## Production CPU baseline

Command:

```sh
env CARGO_TARGET_DIR=/tmp/opencode/npu-spike/cargo-target \
  ORT_DYLIB_PATH=/usr/share/irlume/onnxruntime/lib/libonnxruntime.so.1.28.1 \
  cargo run --locked --release -p irlume-auth --example stage_bench -- \
  /usr/share/irlume/models
```

| Production stage | Mean |
|---|---:|
| YuNet, grey 640x480 | 7.10 ms |
| YuNet, RGB 640x480 | 7.80 ms |
| FaceMesh | 5.57 ms |
| AuraFace | 121.29 ms |
| ViT PAD | 202.52 ms |
| FLIR PAD | 2.45 ms |

## Standalone warmed inference

These rows compare the same direct OpenVINO call path on CPU and NPU. Speedup
is CPU mean divided by NPU mean.

| Model | CPU mean | NPU mean | NPU p50 | NPU p95 | Speedup | CPU load: CPU / NPU |
|---|---:|---:|---:|---:|---:|---:|
| BlazeFace short | 1.035 ms | 0.641 ms | 0.523 ms | 1.454 ms | 1.62x | 269.4% / 24.9% |
| FLIR PAD | 2.456 ms | 0.418 ms | 0.357 ms | 0.650 ms | 5.88x | 287.9% / 24.5% |
| FaceMesh 256 | 2.243 ms | 1.990 ms | 1.557 ms | 4.421 ms | 1.13x | 278.4% / 18.7% |
| YuNet 640 | 8.012 ms | 2.085 ms | 1.798 ms | 3.761 ms | 3.84x | 261.9% / 34.3% |
| AuraFace | 144.488 ms | 6.133 ms | 5.887 ms | 9.979 ms | 23.56x | 235.0% / 5.7% |
| ViT PAD | 185.438 ms | 9.301 ms | 9.060 ms | 10.814 ms | 19.94x | 276.2% / 5.2% |

The production-runtime comparison is similar for the dominant graphs:
AuraFace `121.29 / 6.133 = 19.78x` and ViT
`202.52 / 9.301 = 21.77x`. FaceMesh's direct OpenVINO result is only a 1.13x
gain; its larger comparison to the production ORT number must not be attributed
solely to hardware because the CPU runtimes differ.

## Concurrent model residency

All six graphs compiled and remained live in one process. The primary sequence
was YuNet, FaceMesh, AuraFace, ViT, and FLIR.

| Measurement | Result |
|---|---:|
| Primary sequence mean | 16.431 ms |
| Primary sequence p50 | 15.966 ms |
| Primary sequence p95 | 19.191 ms |
| Host CPU load | 11.2% of one core |
| NPU busy delta, 30 rounds | 433,592 us |
| Reported NPU total memory | 33,086,615,552 bytes |

The summed production CPU stage means for the same five models are 338.93 ms,
or 20.6x the NPU sequence mean. Again, this is a model-stage comparison, not a
full authentication measurement.

## Cold and warm compilation

With `NPU_BYPASS_UMD_CACHING=true`, compile times were:

| Model | Compile time |
|---|---:|
| YuNet | 558.8 ms |
| FaceMesh | 590.3 ms |
| AuraFace | 1,654.6 ms |
| ViT | 2,412.9 ms |
| FLIR | 132.8 ms |
| BlazeFace | 258.8 ms |
| **Total of displayed rounded rows** | **5,608.2 ms** |

With the UMD cache available, compiling all six in a later process totaled
175.6 ms. Production therefore needs a versioned persistent cache or controlled
startup warmup. A first authentication must not unexpectedly absorb several
seconds of compilation.

## Synthetic parity

The synthetic probe demonstrates numerical compatibility, not threshold
qualification:

| Model | Semantic check |
|---|---|
| AuraFace | CPU/NPU normalized embedding cosine `0.99999899`; max normalized component delta `0.00019585` |
| ViT | P(spoof) delta `0.0002844`; both below deployed `0.55` threshold |
| FLIR | P(fake) delta `0.0005198`; both below deployed `0.90` threshold |
| YuNet | Same zero candidate count at deployed `0.60`; maximum score delta across strides `0.00643` |
| BlazeFace | Same zero candidate count at deployed `0.50`; maximum score delta `0.0000552` |
| FaceMesh | Maximum coordinate delta `0.2814` input pixel, or `0.00110` normalized |

These results are encouraging but cannot prove authentication parity near a
decision boundary. Before release, replay the existing qualified face, PAD,
detection, and landmark corpora through CPU and NPU and compare final decisions,
not merely tensors. Stored AuraFace templates and thresholds were established
with the CPU path, so cross-backend enrollment/authentication combinations must
be tested explicitly.

## Power evidence limitation

The machine exposes RAPL package, core, uncore, and DRAM energy domains, but
their `energy_uj` files are mode `0400 root:root`; the unprivileged benchmark
could not read them. Battery `power_now` was a charging-rate observation and
was not treated as system power. The measured host CPU-time reduction and NPU
busy counter prove offload, but they do not prove joules saved. Repeated,
idle-controlled CPU and NPU runs at a fixed charge state must read the same RAPL
package and subdomain counters before and after each workload. Those counters
can compare measured package/domain energy; they do not isolate NPU-only or
whole-system energy.

## Implementation gate

> **Superseded implementation direction:** The measurements below remain
> evidence, but ADR-0021 supersedes this section's earlier model-by-model ONNX
> Runtime OpenVINO proposal. The approved implementation uses one globally
> resolved device, direct OpenVINO assignment proof for every configured ONNX
> graph, strict explicit NPU failure to password fallback, and a default-off
> experimental accelerator feature.

An implementation experiment should:

1. Select `NPU` explicitly. The current optional ORT OpenVINO builder uses the
   provider default and permits silent CPU fallback; the `ort` API supports
   `with_device_type("NPU")`, but the shipped ORT runtime must also be built
   with the OpenVINO execution provider.
2. Fail closed to a visible CPU path when NPU initialization fails, and expose
   the actual execution device in diagnostics. Never label fallback as NPU.
3. Offload AuraFace and ViT first. Add YuNet and FLIR if the end-to-end Rust
   benchmark preserves their gains. FaceMesh and BlazeFace are secondary CPU
   relief opportunities, not the economic reason for the backend.
4. Version cache entries by model hash, OpenVINO version, compiler version,
   driver version, and hardware architecture; prewarm outside the auth budget.
5. Run real-corpus decision parity, suspend/resume, concurrent-session,
   permissions, package-upgrade, and cache-corruption tests.
6. Repeat production CPU versus NPU timing through the Rust wrappers and record
   idle-controlled, same-domain privileged RAPL comparisons before proposing
   default enablement.

## Verification and incidents

### Task 10 trusted gate and local exploratory rerun

Task 10 adds a manual and scheduled trusted Lunar Lake workflow, an exact-head
runner, fail-closed model inventory checks, the direct Rust adapter gate, and a
bounded JSON evidence validator. The workflow checks out `refs/heads/main`, uses
only the pinned experimental matrix under `packaging/openvino/`, and uploads
only the validator's allowlisted JSON fields. It does not upload raw benchmark
reports, tensors, embeddings, frames, identities, or credentials.

The hosted and software-only gates passed before hardware access: 8 benchmark
contract tests, 10 runner/workflow contract tests, 5 validator tests, shell
syntax and ShellCheck, Python byte compilation, workflow parsing, all model
checksums, workspace check, all-feature warnings-denied Clippy, rustfmt,
warnings-denied rustdoc, diff hygiene, and 2,011 guarded workspace tests.

A local hardware rerun then used the existing `/tmp/opencode/npu-spike` stack.
It is exploratory evidence, not trusted workflow evidence, because the Task 10
changes are uncommitted and the runner correctly refuses a dirty tree. The
bounded output is tied to base HEAD
`fc4bbdda8c067016980152e93e85b6f028079988`, is 2,216 bytes, and records:

| Model | NPU first inference | NPU busy delta |
|---|---:|---:|
| YuNet | 20.110 ms | 43,284 us |
| FaceMesh | 14.234 ms | 40,350 us |
| AuraFace | 20.630 ms | 146,407 us |
| BlazeFace short | 13.001 ms | 8,800 us |
| ViT PAD | 31.804 ms | 260,975 us |
| FLIR PAD | 15.709 ms | 4,634 us |

The direct Rust adapter compiled and inferred every manifest ONNX model on
exact NPU. The assignment-mismatch and cache lifecycle contracts passed. The
all-model residency run kept all six graphs compiled and inferred, and the
primary YuNet, FaceMesh, AuraFace, ViT, and FLIR sequence completed 30 rounds
with mean 16.908 ms, p50 16.608 ms, p95 19.533 ms, 13.57% of one CPU core, and
429,492 us of NPU busy time.

### Clean commit-bound trusted runner

After the complete software gate and inline differential review passed, the
55-path M1-012 implementation was committed as signed+DCO
`503f8200dd9f8725b1bc41851887ad8093a809e4`. The repository was clean, and the
trusted runner accepted that exact OID. It rebuilt the direct Rust adapter in
private scratch, verified all seven model hashes, reran exact assignment and
both cache contracts, executed both manifest-derived benchmarks, and published
only the validated bounded artifact.

The retained result is `/tmp/opencode/m1-012-trusted-503f820.json`, 2,214 bytes,
mode 0600. It binds the exact commit and pinned experimental matrix, records all
six ONNX graphs on exact `NPU` with positive per-model busy deltas, records all
six resident and inferred in one process, and records 408,704 us total NPU busy
movement over the 30-round primary pipeline. The Rust adapter,
assignment-mismatch rejection, and clean/warm/corrupt cache gates are all true.

This is trusted local commit-bound hardware evidence, not a run of the
scheduled `main` workflow. The branch was created on the earlier typed camera
and model-contract stack rather than directly on `origin/main`; the workflow
continues to check out `refs/heads/main` and therefore remains pending until the
reviewed change is integrated there.

Two fail-closed attempts found integration defects before evidence publication:

- The Python wheel exposes only versioned `libopenvino_c.so.2620`, while
  `openvino-finder` 0.11 checks `LD_LIBRARY_PATH` for unversioned
  `libopenvino_c.so`. The runner now verifies exactly one versioned C API
  library and creates a private ephemeral unversioned symlink in its scratch
  directory. The pinned runtime itself remains unchanged.
- AuraFace's original graph carries a dynamic batch on input and output. The
  OpenVINO adapter accepted the dynamic input for its batch-one reshape but
  rejected the corresponding pre-reshape output batch. It now permits only
  that induced output-batch dynamism, then still requires the compiled graph to
  satisfy the complete concrete tensor contract before inference.
- OpenVINO 2026.2 reports CPU assignment as `['CPU']` but NPU assignment as
  `NPU`. Both benchmarks now normalize only an exact scalar or exact one-element
  device list and continue to reject composite or fallback assignments.

### Isolated existing-enrollment live gate

After separate authorization, one bounded live authentication gate exercised
the branch daemon against a cloned, read-only source copy of the existing
encrypted enrollment and configuration. The daemon ran as root in a private
mount namespace, used a separate socket and cache under a mode-0700 temporary
root, and bound that private cache over `/var/cache`. The installed service
remained active and enabled throughout. No production policy, enrollment,
template key, setting, model, package, or service file was changed.

The daemon resolved the requested `npu` policy to exact OpenVINO `NPU` with a
cold cache while leaving TFLite FaceMesh outside OpenVINO assignment. One
`auth test --events=jsonl` request then granted with liveness. Kernel NPU busy
time increased by 40,347 us during the request. Pre/post SHA-256 values for the
production enrollment, template key, and settings were identical. Cleanup
terminated the isolated daemon and deleted the cloned state, private cache,
socket, raw log, and intermediate event/status files. The retained bounded
evidence is `/tmp/opencode/m1-012-live-auth/evidence.json`, 314 bytes, mode
0600; it contains only device/cache facts, the bounded grant/liveness outcome,
the busy delta, and the unchanged-production-hash assertion.

A first startup-only attempt did not reach camera capture because the harness
incorrectly passed unsupported `--json` to the human `inference-device status`
command. Its failed cleanup also tried to read a root-owned PID file as the
calling user. The orphaned isolated daemon was terminated, all failed-run state
was removed, and production state was reverified before retry. The harness was
corrected to poll the machine `status --json` contract and read the PID through
`sudo`; syntax and ShellCheck passed before the single live retry.

This proves one existing-enrollment live grant through the exact-NPU branch
path. It does not establish qualified-corpus final-decision parity,
cross-backend enrollment/authentication parity, suspend/resume behavior,
standard installed permissions/confinement, cache upgrade/corruption behavior,
performance qualification, or same-domain energy savings. It does not
authorize production accelerator discovery or change any threshold.

### PR exact-tip regression and hardware revalidation

PR #647 exposed a first-run camera regression in the hosted v4l2loopback lane:
the new immutable attempt plan required stored capture qualification before the
legacy fixed sequential profile could capture. The repair represents that path
as typed `LegacyUnqualified` authority, restricts it to the baseline 640x480
RGB plus 640x400 IR requests and sequential schedule, and preserves every
generation, tuple, delivered-rate, continuity, and evidence-window check.
Unconfirmed emitter metadata is deferred only on that compatibility path to
the existing face, liveness, and PAD gates; it neither becomes `ActiveIr`
evidence nor creates stored capture qualification. Exact-path virtual topology
remains a root-controlled test-only exception. Stored-qualified attempts retain
the strict active-emitter requirement.

Hosted CI run `33609156562` passed at signed+DCO commit
`789fcb2c79dd69915114b10cec30eaabb22fd667`, including MSRV and stable Rust,
warnings-denied Clippy and rustdoc, Nix, fuzzing, packaging, PAM, and the full
v4l2loopback camera/authentication lane. The exact-head trusted runner then
verified all seven model hashes, executed all six ONNX graphs on exact `NPU`
with positive per-model busy movement, kept and inferred all six in one
process, and measured 388,586 us of NPU busy movement over the 30-round primary
pipeline. The Rust adapter, assignment-mismatch rejection, and clean/warm/
corrupt cache gates all passed. The retained bounded artifact is
`/tmp/opencode/m1-012-trusted-789fcb2.json`, 2,217 bytes, mode 0600.

One isolated exact-head authentication used a cold private cache and cloned
state, resolved the complete ONNX engine to exact OpenVINO `NPU`, and left
TFLite FaceMesh outside that assignment. It granted with liveness and increased
NPU busy time by 40,554 us. Production enrollment, template-key, and settings
hashes were unchanged, `irlumed.service` remained active and enabled, and only
`/usr/bin/irlumed` remained as the production daemon. Cleanup removed cloned
state, cache, socket, raw log, and intermediate files. The retained bounded
artifact is `/tmp/opencode/m1-012-live-auth-789fcb2/evidence.json`, 314 bytes,
mode 0600.

- Clean baseline before the spike: 1,973 tests passed, 0 failed, 100 ignored.
- Exact installed model hashes: all seven passed.
- Production release stage benchmark: completed successfully.
- The preserved Python probe scripts passed `py_compile` and all requested
  CPU/NPU inference calls.
- One release build attempt failed with `Disk quota exceeded` because the
  temporary Cargo target still held 3.7 GiB of baseline test artifacts. No
  benchmark ran in that failed attempt. `cargo clean --target-dir` removed only
  the isolated target; the release-only rebuild then succeeded.
- An initial pre-benchmark thermal check read 96 C. No warmed results were
  recorded until the package cooled to 50 C.

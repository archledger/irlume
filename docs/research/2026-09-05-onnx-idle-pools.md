# Block idle ONNX workers between inferences

The shared ONNX session builder retains two intra-op threads and disables
intra-op spinning. Multiple model sessions stay resident, so idle workers should
block while another model runs. No graph optimization, model, threshold, PAD
sample count, identity operation or deadline changes.

The preceding three-model experiment found a 13.46% reduction in grouped model
time with spinning disabled, no benefit for isolated ViT, and a 65.77% increase
when reducing each session to one thread. Retain two threads; changing the pool
size is a different optimization and was rejected for this workload.

## Candidate measurements

Measured on archhost, AMD Ryzen 7 5700G, CPUs 0 and 1, nice 0, with the existing
performance governor unchanged. Baseline is the vision library from source base
`3531ae7ecc54062de2c56a49eca66c013b33e197`. Candidate adds only the spinning option
and explanatory comments. Both use the same optimized Rust harness and pinned
model files. `ort` is 2.0.0-rc.13 with dynamic runtime loading.

| ONNX Runtime | FaceMesh backend | Baseline, ms | Candidate, ms | Reduction |
|---|---|---:|---:|---:|
| 1.28.0 | Production TFLite | 1422.301 | 1206.373 | 15.18% |
| 1.28.0 | Legacy ONNX | 1435.794 | 1209.003 | 15.80% |
| 1.24.1 | Production TFLite | 1313.542 | 1158.715 | 11.79% |
| 1.24.1 | Legacy ONNX | 1304.953 | 1150.308 | 11.85% |

Each row uses baseline/candidate/candidate/baseline process order. Each process
runs two warmup and eight measured rounds. A round invokes YuNet, BlazeFace and
FaceMesh, five IR/RGB PAD pairs, RGB embedding with TTA and one IR embedding.
All six models remain loaded. Both repeats show improvement, larger than the
observed differences between repeats. Timing excludes loading and output
comparison. Rescue models run every round in this harness; the real daemon
invokes them conditionally. These are model-call totals, not login latency.

## Numerical and software validation

All 2,208 candidate comparisons were bit-identical to baseline within the same
runtime/backend combination, with matching status and zero maximum absolute
difference. This includes 1,200 synthetic calls and 1,008 calls on 36 images
reused across four runtime/backend combinations. The image sample contains
12 LFW RGB images, 12 Oulu-CASIA NIR images and 12 CelebA-Spoof snapshot images
with nine spoof and three live labels. This is numerical parity on a small
varied sample, not a statistically representative accuracy evaluation.

Images were resized to 320x240. Detection supplied alignment when available;
fixed-box crops exercised wrappers when detection returned no face. RGB-source
grayscale conversions used for IR wrapper checks are not paired IR captures.
No authentication decisions or spoof-detection rates were evaluated. Pixels,
identities, output tensors and per-image hashes were not saved. Only aggregate
parity, success/refusal counts and synthetic timings were retained.

All 72 existing vision tests passed on each runtime, including the explicitly
run pinned TFLite mesh test. Workspace release check, all-target/all-feature
vision Clippy, warnings-denied rustdoc, and formatting passed. Six aggregate
validation checks reject missing processes, output/status differences and
missing PAD timings. Builds used Rust/Cargo 1.96.0; this task did not run fresh
MSRV, packaging, remote CI or accelerated-provider tests.

The runtime [configuration definitions for 1.28.0](https://raw.githubusercontent.com/microsoft/onnxruntime/v1.28.0/include/onnxruntime/core/session/onnxruntime_session_options_config_keys.h)
document the spinning option and its build-dependent default. The 1.24.1
runtime was extracted from a SHA-verified official PyPI wheel into temporary
storage. That runtime and all remote scratch were removed after validation.
Installed services, models and power settings remained unchanged.

This supports the CPU candidate on the tested configurations. It does not
establish end-to-end login improvement, energy savings, every supported runtime
or platform, or biometric accuracy. Existing security checks remain required.

# ADR-0021: Resolve one observable inference device globally

**Status:** Accepted
**Date:** 2026-09-01
**Related:** [ADR-0019](0019-fail-closed-pad-availability.md)
**Design:** [Automatic Inference Device Selection](../superpowers/specs/2026-09-01-automatic-inference-device-selection-design.md)
**Evidence:** [Lunar Lake NPU Benchmark](../research/2026-09-01-lunar-lake-npu-benchmark.md)

## Context

Irlume's production ONNX models use a shared ONNX Runtime CPU path. An optional
OpenVINO execution-provider feature exists, but it neither selects a runtime
device explicitly nor reports the physical device that executed a graph. The
packaged ONNX Runtime also lacks the matched OpenVINO provider library and
runtime.

An isolated benchmark proved that OpenVINO can execute all six shipped ONNX
graphs on this system's Lunar Lake NPU with explicit `NPU` compilation and
compiled-model `EXECUTION_DEVICES=NPU` evidence. Synthetic parity and latency
were encouraging, but production decision parity, packaging, GPU behavior,
cache lifecycle, suspend and resume, and energy remain unqualified.

The device policy must therefore separate a requested policy from proven
hardware assignment, preserve the current CPU baseline, and prevent silent
fallback when NPU is explicitly requested.

## Decision

Use application-controlled global inference-device resolution.

- Expose `auto`, `cpu`, and `npu` policies. Do not expose explicit `gpu`.
- Default `auto` tries the complete configured ONNX model set on NPU, then GPU,
  then CPU.
- Resolve one physical device for the complete configured ONNX model set, not
  one device per model.
- Keep CPU on the existing ONNX Runtime adapter.
- Use direct OpenVINO adapters for explicit NPU and GPU candidates.
- Keep direct OpenVINO behind a default-off `experimental-openvino` feature;
  released base-package binaries cannot construct accelerator candidates, so
  installing runtime libraries alone cannot activate unqualified hardware.
- Accept an OpenVINO candidate only when every compiled model reports the exact
  requested physical device through `EXECUTION_DEVICES`.
- Make explicit `npu` strict. Any NPU load, compile, assignment, or inference
  failure preserves password fallback and never authorizes GPU or CPU
  inference.
- Keep a resolved device fixed for the engine lifetime. Automatic re-resolution
  may occur only during a controlled whole-engine rebuild outside an
  authentication attempt.
- Persist `execution_device` in `settings.conf`, permit
  `IRLUME_EXECUTION_DEVICE` as the higher-precedence override, and report the
  requested policy, source, resolved device, backend, and bounded candidate
  failures.
- Keep TFLite FaceMesh status separate from ONNX execution-device reporting.
- Treat accelerator packaging and activation as experimental until the
  documented qualification gates pass.

## Alternatives Considered

### ONNX Runtime OpenVINO Execution Provider

Rejected because it requires a matched custom runtime distribution and does not
provide authoritative post-session physical-device reporting through ONNX
Runtime.

### OpenVINO AUTO

Rejected because OpenVINO's suitability selection is not the same as Irlume's
strict NPU, GPU, CPU ladder and may produce per-model assignments.

### Per-Model Device Selection

Rejected because mixed execution multiplies parity, diagnostics, cache, and
failure combinations without a demonstrated need. The measured NPU compiled
the complete shipped set.

### Replace CPU With OpenVINO

Rejected because it would change the qualified CPU baseline and packaging
without evidence that the migration is necessary.

## Consequences

- Model wrappers gain one backend-neutral inference seam instead of depending
  directly on ONNX Runtime types.
- Automatic startup can incur failed candidate compilation before reaching a
  working device. The cache and bounded candidate report make that cost and
  reason visible.
- The base package remains CPU-only and omits the experimental adapter feature.
  Qualified accelerator packages carry an enabled binary plus the matched
  OpenVINO, plugin, compiler, driver, and loader matrix.
- GPU implementation cannot enter released automatic selection before its own
  exact-model and qualified-corpus gates pass.
- NPU implementation cannot enter production before final-decision parity,
  cache, permissions, upgrade, suspend and resume, and energy gates pass.
- ADR-0019 fail-closed PAD availability and PAM password fallback remain
  unchanged.

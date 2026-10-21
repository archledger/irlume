# GPU benchmarks and CUDA probe for ADR-0033

- **What:** #1053 Phase 2 measurements. The recognizer (glintr100,
  `a7933ea5...5c60` per `models/SHA256SUMS`) ran on identical synthetic
  inputs, preprocessed by the production `align::preprocess_arcface`
  (NCHW 3x112x112 f32), across ONNX Runtime CPU, OpenVINO CPU and
  OpenVINO GPU lanes, plus an ONNX Runtime CUDA execution-provider probe.
  No biometric data: seeded xorshift chips. Aggregates only.
- **Where and when:** 2026-10-10. minihost (Alder Lake-N CPU and its
  integrated GPU, `/dev/dri/renderD128`, intel-compute-runtime 26.35,
  OpenCL platform; no Level Zero loader on that host) and archhost
  (16-thread CPU; RTX 3060 after the owner-approved driver change,
  NVIDIA 595.104.02). OpenVINO 2026.2.1
  (`openvino_toolkit_ubuntu22_2026.2.1.21919.ede283a88e3_x86_64.tgz`,
  `libopenvino_c.so.2621`) loaded through `openvino-sys` 0.11.0
  runtime-linking from an explicit path. ONNX Runtime: 1.29.0 system
  library on minihost; the official `onnxruntime-linux-x64-gpu_cuda12`
  1.29.0 bundle on archhost, CUDA 12.9 userland and cuDNN 9.22 from
  nixpkgs.
- **How:** a scratch example against `irlume-vision` at `cdc0fd7a`
  (production session configuration: two intra-op threads, spinning off,
  Level3; 20 warmup calls; 300 to 500 timed calls round-robin over 16
  fixed inputs; medians reported, p10/p90 within about 2% unless noted).
  The harness is measurement-only, never committed; a copy is archived
  in the shared ledger with the run logs.
- **Results (median per inference):** minihost CPU 258.5 ms (production
  session), OpenVINO CPU 178.6 ms, OpenVINO GPU 102.0 ms; archhost CPU
  108.7 ms; archhost RTX 3060 through the CUDA execution provider 7.78
  ms and 7.61 ms in two runs. OpenVINO GPU first compile 3.37 s
  (0.71 s with the kernel cache warm); lane RSS +0.3 to +0.5 GiB; CUDA
  load RSS +523 MiB.
- **Determinism observations, not certification:** OpenVINO CPU
  reproduced the ONNX Runtime CPU outputs at cosine 1.000000 on all 16
  inputs; OpenVINO GPU reproduced cosine 0.999524 to 0.999687, the same
  bounds in every run. Both lanes are the input the ADR-0033 section 5
  gates judge.
- **CUDA probe findings (archhost):**
  - `ort` 2.0.0-rc.13 registers execution providers with
    `fail_silently` by default: with the CUDA provider unloadable, the
    session loads, no error or warning appears, and inference runs on
    CPU at CPU speed (109.0 ms vs 108.7 ms no-provider baseline). The
    strict opt-in (`error_on_failure`) surfaced the true error.
  - With the driver and CUDA libraries correct, registration under
    `error_on_failure` succeeds and the GPU runs at the speed above.
  - A missing cuDNN surfaces only at the first convolution, after
    session creation succeeds: registration is not execution.
  - One run aborted at process exit with a corrupted heap
    ("corrupted double-linked list") in the CUDA teardown path, after
    results were printed. Session teardown is a real daemon path
    (model retirement and rebuilds), so this class must be validated
    before any production use.
- **Decision relevance:** motivation for the ADR-0022 section 15
  reopen, not proof of a failed user-facing latency budget
  (authentication is capture-bound and no end-to-end budget is recorded
  here): the integrated GPU is 2.5x the weakest fleet CPU on this model
  through the already-validated provider path, and the dGPU shows an
  order of magnitude more through a path this project has not audited.
  ADR-0033 scopes the first and leaves the second inert.
- **UX5406S rerun (2026-10-10, recorded here 2026-10-21):** the same
  harness extended with an OpenVINO NPU lane ran on the decision hardware
  (Lunar Lake, Arc 140V integrated GPU, Intel AI Boost NPU on the 1.38.0
  driver, Fedora 44 kernel 7.2.8, OpenVINO 2026.2.1 from the
  intel-npu-stack 0.2.0 candidate packages, intel-compute-runtime
  26.35.39758.11), two process runs of 300 and 500 timed calls over the
  16 fixed synthetic inputs. Medians: ONNX Runtime CPU (production
  configuration) 98.7 and 105.7 ms; OpenVINO CPU 82.5 and 90.5 ms;
  OpenVINO GPU 5.81 and 5.51 ms (first compile 0.43 to 0.85 s, lane RSS
  +217 to +375 MiB); OpenVINO NPU 3.59 and 3.59 ms (first compile 1.56 to
  1.60 s, +553 to +560 MiB). Parity observations: OpenVINO CPU cosine
  1.000000 against the ONNX Runtime outputs; both accelerators 0.999996 to
  0.999998. The lanes compiled with the plugin's default properties (no
  latency hint, no explicit precision), so this is a raw-inference ranking
  only; the certified `f32` configuration (ADR-0033 amendment
  2026-10-21) is measured separately. Archive:
  `artifacts/irlume/2026-10-10-1053-gpu-benchmark/zenbook-three-way/`
  (`REPORT.md`, `zenbench-run2.log` for the 300-call run,
  `zenbench-run3.log` for the 500-call run, `gpu_benchmark.rs`). The
  minihost numbers above remain a proxy from the weakest CPU and a
  24-EU-class integrated GPU.

# NPU measurements for ADR-0022

- **What:** measurement 4 of ADR-0022. The implementation of that ADR
  (`irlume-vision` built with its `npu` feature) ran the shipped models on
  an Intel NPU and on their ONNX Runtime CPU sessions, through irlume's own
  model structs, preprocessing and decoders.
- **Where:** UX5406S (Lunar Lake, NPU PCI 8086:643e "Intel(R) AI Boost",
  architecture 4000), Fedora 44, kernel 7.2.8, intel-npu-stack profile
  `fedora-44-lunar-lake-x86_64` (stack 0.1.1, qualified): NPU driver and
  firmware 1.38.0 (loaded firmware build of 2026-08-20, `6fc835a1`), OpenVINO
  and NPU compiler 2026.2.0 (`NPU_COMPILER_VERSION` 524290, 8.2), Level Zero
  loader 1.32.0, ONNX Runtime 1.28.1. Release builds, four CPUs (`taskset -c
  0-3`), core dumps off.
- **When:** 2026-10-08.
- **Models** (`models/SHA256SUMS`): glintr100 `a7933ea5...5c60`, liveness_vit
  `c7f8a6f3...161c`, flir `df80cea7...0c72`, face_landmarks_detector.tflite
  `c7d54204...43d5`.
- **Identity** (ADR-0022 §4, read as root with the compile configuration
  `batch=1;NPU_COMPILER_TYPE=PLUGIN;PERFORMANCE_HINT=LATENCY;INFERENCE_PRECISION_HINT=default(f16);NPU_TURBO=unset`
  and the runtime library digests, the NPU compiler loader and the IR frontend
  included): `4bccf18e7f6e6b5a9d8774b9eeee175a5d3ef398b72914b1e7c488a0ad3b55ed`.
  NPU reference digest of the recognizer on the three reference inputs:
  `9fa7f653f9330e60e4305d5ddac80675fe2ac7deec0e35b3d732b384ef2bede8`, the
  same in every process.
- **How:** the ignored tests in `crates/irlume-vision/src/onnx/npu_tests.rs`
  at commit `0c72b1d9e1a202da2ecf3324b62d4977fc058c37` (branch
  `feat/npu-vision-runtime`, which implements this ADR and adds the `npu`
  feature), for example
  `ulimit -c 0; cargo test -p irlume-vision --features npu --release --lib -- --ignored npu_hw_ --test-threads 1 --nocapture`
  (`IRLUME_NPU_TEST_MODELS` names the model directory, `IRLUME_NPU_EVAL_DIR`
  the recorded frames). The recorded frames are read into memory only; no
  frame, embedding or per-frame score is stored or printed, only the
  aggregates below.

## Compilation, cache and memory

| | Recognizer | ViT | FLIR |
|---|---:|---:|---:|
| Cold compile | 2.2 to 5.2 s | 3.4 to 8.0 s | 0.15 to 0.35 s |
| From the OpenVINO cache | 0.38 to 0.53 s | 0.59 to 0.90 s | 0.02 s |
| CPU session build | 0.41 to 0.44 s | 0.23 to 0.28 s | |
| Compiled blob on disk | 127 MiB | 170 MiB | 1 MiB |
| Process memory, CPU session | +467 to +707 MiB | +246 MiB | |
| Process memory, NPU session (cache) | +537 MiB | +787 MiB | |

Opening the platform takes 0.02 to 0.12 s, and 0.56 s with the runtime
library digests of the identity. Every compile reported
`EXECUTION_DEVICES=NPU`. A marker write and remove costs 13 µs.

## Speed

Mean of 10 calls; the ranges span runs with and without other load on the
host.

| Per call | CPU session wall | CPU session CPU time | NPU wall | NPU CPU time |
|---|---:|---:|---:|---:|
| Recognizer | 118 to 183 ms | 227 to 328 ms | 6.7 to 6.8 ms | 0.15 to 0.24 ms |
| ViT | 182 to 426 ms | 351 to 447 ms | 14.5 to 15.0 ms | 1.4 to 1.5 ms |
| FLIR | 2.2 to 4.5 ms | | 0.44 to 0.59 ms | |

## Parity

Synthetic reference inputs: recognizer embedding cosine 0.9999982 (L2
distance 0.0017 to 0.0026 on the three reference chips), ViT P(spoof) delta
0.000032, FLIR P(fake) delta 0.000007. Three inputs interleaved on one infer
request and repeated, and an inference after the NPU runtime-suspended, gave
the same bits; separate processes gave the same bits.

Recorded frames: 2,397 local frames in 67 sessions, 1,851 with a face
(genuine IR sessions; paper, screen, phone, video-replay and banner IR
attacks; RGB genuine and banner frames), each through both backends.

| Output | Threshold | Frames | Max abs delta | Mean abs delta | Verdicts that differ |
|---|---:|---:|---:|---:|---:|
| Recognizer, genuine IR, score against a reference | 0.55 | 1,347 | 0.00038 | 0.000072 | 0 |
| FLIR P(fake), genuine IR | 0.9 | 1,347 | 0.0139 | 0.0014 | 0 |
| FLIR P(fake), IR attacks | 0.9 | 123 | 0.0060 | 0.00011 | 0 |
| ViT P(spoof), genuine RGB | 0.55 | 282 | 0.0018 | 0.00082 | 0 |
| ViT P(spoof), RGB attacks | 0.55 | 99 | 0.0027 | 0.0012 | 1 |

The lowest recognizer embedding cosine was 0.999996. The one ViT verdict that
differed was an attack frame whose CPU score was 0.0009 above the deny line
and whose NPU score fell below it, at frame level (production votes the
median of five frames). Impostor pairs were not part of this set.

## Configuration facts

- `INFERENCE_PRECISION_HINT` accepts only `f16` and `i8` on the NPU
  ("Supported values: f16, i8"); setting `f32` is refused.
- `NPU_COMPILER_TYPE` defaults to `PREFER_PLUGIN`, which resolved to the
  plugin compiler (output identical to a forced `PLUGIN`); `DRIVER` is not
  available with the 1.38.0 driver (`ZE_RESULT_ERROR_UNSUPPORTED_FEATURE`).
- OpenVINO 2026.2.0 refuses the TFLite mesh read from a memory buffer
  ("Unable to read the model").
- As root, inside a `systemd-run` unit with irlumed's sandbox properties,
  `/sys/kernel/debug/accel/0000:00:0b.0/fw_version` reads back the loaded
  firmware build and debugfs is read-only.
- Once the NPU is enumerated, the process maps the OpenVINO core and C API,
  the auto, hetero, CPU, GPU and NPU plugins, the Level Zero loader and
  tracing layer, and the NPU user-mode driver; setting `NPU_COMPILER_TYPE`
  adds the NPU compiler loader, and compiling adds the NPU compiler and the IR
  and ONNX frontends.
- On the host's btrfs root, `stat` reports a library's subvolume device (0:37)
  and `/proc/self/maps` the filesystem's (00:23) for the same inode, so the
  check that the mapped libraries are the hashed ones compares inodes.

# Inference runtime upstream survey (ort / ONNX Runtime / edgefirst-tflite / LiteRT)

Date: 2026-08-20
Agent: opencode
Method: direct fetches of primary sources only (GitHub releases + API, raw source at release tags, crates.io API, docs.rs, GitHub Advisory Database). All pages fetched 2026-08-20. Claims are tagged **[V]** (verified from a fetched primary source, URL given) or **[I]** (inference/judgment, not verifiable from today's fetches).

Context: irlume pins `ort =2.0.0-rc.13` (load-dynamic + api-24) dlopening ONNX Runtime 1.24.4 CPU linux-x86_64, and `edgefirst-tflite =0.9.0` dlopening `libtensorflowlite_c` for the classic MediaPipe face-mesh model.

## Q1. ONNX Runtime releases

**Latest stable as of 2026-08-20: v1.29.0, published 2026-08-12.** [V] https://github.com/microsoft/onnxruntime/releases/tag/v1.29.0 and https://api.github.com/repos/microsoft/onnxruntime/releases (published_at `2026-08-12T06:15:37Z`). Note v1.28.1 was published 2026-08-18, *after* 1.29.0; it is a patch on the 1.28 line (device-free WebGPU compile, Win32k lockdown fix, FastGelu/external-initializer validation hardening), and 1.29.0 remains marked Latest. [V]

Releases after 1.24.4 (all dates UTC from the GitHub API): [V]

| Version | Published |
|---|---|
| 1.24.4 (baseline) | 2026-03-17 |
| 1.25.0 | 2026-04-20 |
| 1.25.1 | 2026-04-27 |
| 1.26.0 | 2026-05-08 |
| 1.27.0 | 2026-06-19 |
| 1.27.1 | 2026-07-11 |
| 1.28.0 | 2026-07-25 |
| 1.29.0 (latest) | 2026-08-12 |
| 1.28.1 (1.28-line patch) | 2026-08-18 |

A packaging change is underway: CUDA and WebGPU are moving to separately released "plugin EP" packages (CUDA Plugin EP 0.1.0 published 2026-08-17, WebGPU Plugin EP 0.1.0/0.2.1). The CUDA plugin notes state compatibility "back to ONNX Runtime 1.24.4 through version-gated callbacks", i.e. 1.24.4 is treated as a live compatibility floor. [V] https://github.com/microsoft/onnxruntime/releases

**What api-24 means:** `api-24` = ORT C API version 24. The C API version number equals the runtime minor: the header at tag v1.24.4 contains `#define ORT_API_VERSION 24` [V] https://raw.githubusercontent.com/microsoft/onnxruntime/v1.24.4/include/onnxruntime/core/session/onnxruntime_c_api.h, and ort's multiversioning docs map `api-17`..`api-28` one-to-one to ONNX Runtime v1.17..v1.28 (page updated 2026-07-28) [V] https://ort.pyke.io/setup/multiversion. It is not an "ORT 2.4-era" numbering; there is no ORT 2.x runtime. `api-N` sets the *minimum* runtime version ort will target; with `download-binaries` ort still ships ORT 1.28 binaries and "will happily use an older version" under manual linking/dlopen. [V] same page.

**C ABI after 1.24:** no breaking changes. The C API is append-only via `OrtApiBase::GetApi(version)` [V] (mechanism visible in the v1.24.4 header fetched above); ort's docs support the full 1.17–1.28 span from one rc.13 codebase [V]. The "Announcements & Breaking Changes" in 1.28.0 are build/packaging-level (ONNX 1.22.0, protobuf 6.33.5, cuDNN/cuFFT optional for CUDA, CUDA 12 deprecated, onnxruntime-web WebGL/JSEP deprecation) and in 1.29.0 are additive (POSIX telemetry, `ORT_DISABLE_TELEMETRY=1` to disable; no public ABI change) [V] https://github.com/microsoft/onnxruntime/releases/tag/v1.28.0 and /tag/v1.29.0. A newer runtime answering `GetApi(24)` (or up to `GetApi(28)`) is the supported compatibility mechanism.

## Q2. Security

- **onnxruntime repo: zero published GitHub security advisories** as of 2026-08-20. [V] https://github.com/microsoft/onnxruntime/security/advisories ("There aren't any published security advisories")
- **GitHub Advisory Database, query "onnxruntime": 2 hits, neither an onnxruntime-package advisory.** [V] https://github.com/advisories?query=onnxruntime
  - GHSA-3wqj-33cg-xc48 (Moderate, 2026-04-10): path traversal in *rembg* (pip) via custom model loading. Downstream app issue, not ORT. [V] same listing.
  - CVE-2026-14647 / GHSA-226m-2jqq-4xgv (Low 2.1, unreviewed, published 2026-07-04): out-of-bounds read in `convPoolShapeInference_opset19` (`onnx/defs/nn/old.cc`), reported against "component onnxruntime", affects ONNX up to 1.21.x; patch `a7bf3a0` in onnx/onnx. [V] https://github.com/advisories/GHSA-226m-2jqq-4xgv. ORT 1.24.4 bundles onnx 1.20.1 for model parsing [V] https://raw.githubusercontent.com/microsoft/onnxruntime/v1.24.4/cmake/deps.txt, so the code path exists in irlume's runtime; it is reachable only when loading an attacker-crafted model. irlume loads repo-pinned trusted models, so the attack requires local file replacement (disk compromise) — threat model neutralizes it. Low severity (limited info read). **[I]** on the neutralization argument's application to irlume's exact model-loading paths.
- **Hardening fixed in 1.28.0 / 1.29.0, present-as-risk in <=1.27:** 1.28.0's "Security Fixes" section is a large batch of memory-safety fixes: FlatBuffer model-loader hardening, type-confusion OOB write in raw-pointer `bind_input`, OOB in `TensorAt` sub-byte types, arbitrary-memory-read/kernel OOB fixes, `Col2Im` heap over-read, `CropAndResize`/`BeamSearch`/`TreeEnsemble` validation, integer-overflow guards (`SamplingState` heap overflow, `MlasConvPrepare`, `ConstantOfShape`), WebGPU OOB reads, plus supply-chain bumps. [V] https://github.com/microsoft/onnxruntime/releases/tag/v1.28.0. 1.29.0 adds more (TRT engine-refit path traversal, CPU MoE `k`, `TensorScatter`, extensive rank/shape validation across contrib kernels). [V] /tag/v1.29.0. No CVEs are attached to these; they matter chiefly when parsing untrusted models.
- **protobuf:** 1.24.4 bundles protobuf **v21.12** [V] (deps.txt above). 1.28.0 upgraded to **protobuf 6.33.5** "to mitigate CVE-2026-0994 and fix additional CVEs" [V] 1.28.0 notes. CVE-2026-0994 / GHSA-7gcm-g887-7qv7 (High 8.2, published 2026-01-23) is a **Python** `json_format.ParseDict` recursion DoS affecting pip protobuf >= 6.30.0rc1 <= 6.33.4 and < 5.29.6, patched in 6.33.5 / 5.29.6 [V] https://github.com/advisories/GHSA-7gcm-g887-7qv7. ORT's C++ binary-protobuf path is not the vulnerable Python JSON path, and 21.12 is outside the listed affected ranges; not applicable to irlume's dlopened C library. Versions bundled in 1.25–1.27: not fetched, unknown.
- **LiteRT: zero published advisories.** [V] https://github.com/google-ai-edge/LiteRT/security/advisories. LiteRT 2.2.0 does list kernel hardening (integer-overflow checks in conv/reshape/pad kernels, Conv3DTranspose validation, TopK NaN comparator fix, new fuzzing). [V] https://github.com/google-ai-edge/LiteRT/releases/tag/v2.2.0

## Q3. ort crate (pykeio/ort)

- **2.0.0 has NOT gone stable. Latest release: v2.0.0-rc.13, released 2026-07-28.** No rc.14, no 2.0.0 as of 2026-08-20. [V] https://github.com/pykeio/ort/releases (rc.13 marked Latest) and https://docs.rs/ort/2.0.0-rc.13 (built 2026-07-28). rc.11 notes (2026-01-07) said "the next big release of ort should be, finally, 2.0.0". [V] /releases/tag/v2.0.0-rc.11
- **rc.13 is already an ORT-1.28 release**: "rc.13 skips ahead 4 ONNX Runtime versions to v1.28". Multiversioning spans 1.17–1.28 (`api-17`..`api-28` Cargo features; `api-24` in irlume = minimum ORT 1.24). [V] rc.13 release notes + https://ort.pyke.io/setup/multiversion. Discrepancy noted: the docs page text says api-28 is default, but the published rc.13 manifest's default chain resolves to api-27 (`api-28` exists as an opt-in) [V] https://docs.rs/crate/ort/2.0.0-rc.13/features — pin `api-*` explicitly either way.
- **load-dynamic fixes:** rc.13 includes "Don't deadlock when `load-dynamic` fails" (17ed727) [V] rc.13 notes; rc.11 made `ort::init_from` load the dylib immediately so load errors are detectable (8b3a1ed) [V] rc.11 notes.
- **Breaking changes a move off rc.12 would entail** (irlume is already on rc.13; listed for completeness): rc.13 — EP structs compile-time gated behind feature flags (CPU always available; `lax-feature-matching` escape hatch), custom-operator API rework, CUDA-13-only pyke binaries (irrelevant for CPU/load-dynamic) [V] rc.13 notes. rc.12 — multiversioning introduced, `ndarray` 0.17, `ort::tensor` → `ort::value`, `IoBinding`/`Adapter` moved into `ort::session`, `with_denormal_as_zero` → `with_flush_to_zero`, `ORT_LIB_LOCATION` → `ORT_LIB_PATH` [V] rc.12 notes. rc.10/rc.11 — `default-features = false` implies no_std, EP boolean options now take `bool`, module flattening undone (rc.9). [V] respective release pages.
- **XNNPACK EP: yes, rc.13 has it.** `ort::ep::XNNPACK` is exported [V] https://docs.rs/ort/2.0.0-rc.13/ort/ep/index.html, behind the `xnnpack` feature [V] https://docs.rs/crate/ort/2.0.0-rc.13/features. Caveat: the EP must be compiled into the dlopened ORT binary; whether Microsoft's stock `onnxruntime-linux-x64` release tarballs include the XNNPACK EP could not be verified today (the onnxruntime.ai XNNPACK page and the repo docs listing both 404'd). ORT 1.24.4's build pins a XNNPACK source snapshot (2025.06.22) in deps.txt, i.e. available at build time, per-build-flag. **[I]** Historically stock x64 Linux packages have not enabled XNNPACK; treat "works with the official CPU tarball" as unproven until `is_available()` says otherwise on the fleet.
- **Threaded CPU config:** rc.11 notes: pyke binaries are built `--client_package_build` (low-resource edge defaults, spinning disabled), x86_64 targets x86-64-v3 (Haswell/Zen+), Clang-built [V] rc.11 notes. irlume dlopens Microsoft's package, so those defaults do not apply; ort exposes spinning/threading via SessionBuilder (`with_intra_op_spinning` referenced in rc.11 notes) [V]. Runtime-side: ORT 1.29.0 adds `ORT_INTRA_OP_NUM_THREADS` / `ORT_INTER_OP_NUM_THREADS` env defaults [V] 1.29.0 notes.

## Q4. edgefirst-tflite

- **Current version: 0.9.0, published 2026-08-02 — irlume is already on the newest.** [V] https://crates.io/api/v1/crates/edgefirst-tflite (`newest_version`/`max_version` 0.9.0). Repo: **EdgeFirstAI/tflite-rs** (not "edgefirst-rs"). [V] https://github.com/EdgeFirstAI/tflite-rs
- **0.9.0 changelog highlights** [V] https://raw.githubusercontent.com/EdgeFirstAI/tflite-rs/main/CHANGELOG.md: soft-optional LiteRT Next bindings — vendors **LiteRT v2.1.6 C headers**, `LiteRtFunctions::try_load` probes symbols without failing classic TFLite load; `litert` module with `Environment`/`Model`/`Options`/`CompiledModel` RAII wrappers; several LiteRT lifetime/use-after-free fixes; zero-copy input via `set_custom_allocation_for_input` (unsafe, 64-byte alignment enforced). Classic `Interpreter`/`Delegate` paths unchanged.
- **LiteRT version targeted:** 2.1.6 headers vendored in 0.9.0 [V] changelog. Current LiteRT runtime release is 2.2.0 (2026-08-13) [V] https://github.com/google-ai-edge/LiteRT/releases — headers one minor behind, and the LiteRT path is optional/unused by irlume today.
- **XNNPACK:** supported since 0.4.0 via `Delegate::xnnpack(&lib, num_threads)`, built-in delegate, requires the loaded `libtensorflowlite_c` to be built with `-DTFLITE_ENABLE_XNNPACK=ON` [V] changelog + repo README (same URL as above).
- **Does a newer version need a newer lib?** No newer crate version exists. The crate does not link TFLite at build time at all; `Library::new()` dlopens and probes at runtime (discovery order: `TFLITE_LIBRARY_PATH` env, vendored, versioned `libtensorflow-lite.so.2.x.y`, unversioned `libtensorflowlite_c.so`), so the same binary spans TFLite versions without recompilation. [V] README.

## Q5. LiteRT / TensorFlow / face mesh model

- **LiteRT release train** (all [V] https://github.com/google-ai-edge/LiteRT/releases): 2.2.0 (2026-08-13, latest; Rust crate `google-ai-edge-litert` published, XNNPACK fp16 support for conv/fc ops, experimental "YNNPack" CPU accelerator), 2.1.6 (2026-07-02), 2.1.5 (2026-05-18), 2.1.4 (2026-04-13), 2.1.3 (2026-03-17), 2.1.2 (2026-01-28), 2.1.1 (2026-01-27), 2.1.0 (2025-12-19: "LiteRT beta, feature parity with TensorFlow Lite... officially recommending that developers begin their transition"; classic Interpreter API shipped in Maven v2.1.0+ packages), 2.1.0rc1 (2025-11-21), 1.4.1 (2025-11-19).
- **TensorFlow / classic libtensorflowlite_c:** latest TF release is 2.21.0 (2026-03-06, with rc0 2026-02-09, rc1 2026-03-02). [V] https://github.com/tensorflow/tensorflow/releases. TF 2.20.0 (2025-08-13) notes: "tf.lite will be deprecated, in favor of the new repo google-ai-edge/LiteRT. The duplicated source will also be removed from the TF repo." [V] same page. TF 2.19.0 (2025-03-12): stopped publishing `libtensorflow` packages (unpack from PyPI instead). [V] same page. TF 2.21.0 still carries tf.lite improvements (int2/uint4 ops etc.), so the classic C-API source builds from TF tags for now [V]; the strategic home of the runtime is LiteRT. Whether LiteRT itself publishes a classic `libtensorflowlite_c` binary in its release assets was not verifiable from today's fetches (asset lists not enumerated). **Not fetched.**
- **Security:** no published LiteRT advisories [V] (Q2). TF 2.18.1's security entry (curl bumps) concerns the Python package build, not the C library [V] TF releases page.
- **face_landmarks_detector.tflite vs face_landmarker.task:** the MediaPipe docs page could not be fetched today (transport errors on both `developers.google.com/mediapipe/solutions/vision/face_landmarker` and `ai.google.dev/edge/mediapipe/solutions/vision/face_landmarker`). **Unverifiable today.** **[I]** Background knowledge (not source-checked in this session): MediaPipe Tasks' `face_landmarker.task` (detector + landmarks-with-attention in one .task bundle) has been Google's recommended path since 2023, superseding the classic FaceMesh solution pages; no claim is made here about 2026 model updates. Nothing fetched today indicates the classic .tflite stopped working, and irlume's own benchmark evidence should govern any model swap, not docs status.

## Q6. Perf guidance for tiny CPU models

Verified ORT C API facts (from the v1.24.4 header actually dlopened by irlume) [V] header URL in Q1:
- `OrtSessionOptions::DisableMemPattern` exists (memory-pattern elimination; patterns mainly pay off for concurrent `Run`s on one session).
- `OrtSessionOptions::SetIntraOpNumThreads` exists.
- `ExecutionMode { ORT_SEQUENTIAL, ORT_PARALLEL }` and `GraphOptimizationLevel { ORT_DISABLE_ALL..ORT_ENABLE_ALL }` enums exist.
- CPU arena enable/disable (`EnableCPUMemArena`/`DisableCPUMemArena`) and `SetExecutionMode` are long-standing session options but were outside the truncated portion of the fetched header; not re-verified this session. **[I]**

XNNPACK-vs-CPU-EP for 112x112/192x192 single images on modern x86: the ORT XNNPACK EP documentation page was not reachable today (404), so no upstream performance claim can be cited. **[I]** Judgment: at these sizes, single-inference latency is dominated by launch overhead and prepacked-weight cache behavior; ORT's default CPU EP (MLAS, AVX2 on x86-64-v3) is typically competitive; XNNPACK's wins are historically on ARM/mobile fp32 conv stacks, and the ORT XNNPACK EP prefers NHWC layouts (converting NCHW models can eat the gain). Benchmark before committing; treat XNNPACK as an experiment, not an assumed win. TFLite side: `Delegate::xnnpack` is available (Q4) and equally worth an A/B on the 192x192 mesh model, gated on irlume's lib being built with `TFLITE_ENABLE_XNNPACK=ON` (verify the fleet's lib build flags first).

## RECOMMENDATIONS

**(a) Bump ORT runtime past 1.24.4? Yes, moderately, to 1.28.1 — no emergency.**
No CVE forces it (Q2). The case is defense-in-depth: 1.28.0/1.29.0 land a large memory-safety hardening batch in model loading/parsing and kernels, and even with pinned trusted models, kernel-level validation bugs are second-order defense (malformed intermediate values, future model swaps). Because ort rc.13's multiversioning supports 1.17–1.28, irlume can move the dlopened `libonnxruntime.so` to the official `onnxruntime-linux-x64-1.28.1.tgz` (asset verified in the 1.28.1 release) while keeping `api-24` (runtime answers `GetApi(24)`), or bump the feature to `api-28` to unlock the full surface. 1.29.0 also works at api-28 but is beyond ort's declared support matrix, and it introduces POSIX telemetry — if ever moving to 1.29+, set `ORT_DISABLE_TELEMETRY=1` (verified env var) as a privacy default for an auth daemon. Requires the full four-host fleet revalidation per repo rules. If preferred, deferring until ort 2.0.0 stable and doing crate+runtime in one move is also defensible.

**(b) Move ort off rc.13? No.** rc.13 (2026-07-28) is the latest release; 2.0.0 stable is intended-but-not-shipped, and rc.13 is the first ort whose binaries target ORT 1.28 — staying put also keeps irlume's options open for the runtime bump in (a). When 2.0.0 lands, expect the rc-series breaking changes to be finalized (module paths, env-var renames, EP gating); nothing to pre-do now beyond what rc.13 already required. Keep `api-24` (or bump to `api-28` together with the runtime move) — and keep pinning it explicitly, since the docs-site claim (api-28 default) and the published manifest (api-27 default chain) disagree.

**(c) edgefirst-tflite bump? Nothing to bump.** 0.9.0 (2026-08-02) is the newest version on crates.io; irlume already pins it. The LiteRT Next path it adds is optional and unused. Only adjacent action: when LiteRT support is ever wanted, note 0.9.0 vendors LiteRT 2.1.6 headers vs runtime 2.2.0.

**(d) Security-driven urgency? Low.**
- onnxruntime: no repo advisories, no package CVEs; CVE-2026-14647 (Low, ONNX shape-inference OOB read) is neutralized by irlume's pinned-models threat model; ORT 1.24.4's bundled protobuf 21.12 is outside CVE-2026-0994's affected ranges and that CVE is a Python-only path anyway.
- LiteRT/TFLite: no advisories; 2.2.0 kernel hardening is a nice-to-have, not urgent.
- The honest framing for a changelog: "bump ORT to 1.28.1 for upstream memory-safety hardening" (hygiene), not "security fix".

**(e) Perf options worth testing (cheap A/Bs, in order):**
1. `with_intra_threads(1)` (and inter=1) for the single-image sessions; threads beyond 1 often hurt at 112x112/192x192. Verified API (`SetIntraOpNumThreads`).
2. `DisableMemPattern` for sequential single-shot sessions (verified API). Map through ort's SessionBuilder or config entries.
3. Keep/verify `ORT_SEQUENTIAL` execution and `ORT_ENABLE_ALL` graph optimization (verified enums).
4. Consider disabling the CPU arena for steadier RSS on an always-on daemon (API long-standing, not re-verified today).
5. XNNPACK EP via `ort` `xnnpack` feature — only after confirming the EP actually registers (`is_available()`) against the stock Microsoft tarball on the fleet; expectations modest on x86 (inference).
6. TFLite side: `Delegate::xnnpack(&lib, 2)` on the mesh model, gated on the shipped `libtensorflowlite_c` being built with XNNPACK enabled (verify build flags first).

## Not fetched / unverifiable today

- onnxruntime.ai XNNPACK EP doc page and the ORT repo docs tree listing (both 404).
- MediaPipe face_landmarker docs (transport errors, two URL families).
- protobuf versions bundled in ORT 1.25–1.27.
- LiteRT release asset contents (whether a classic `libtensorflowlite_c` binary is published there).

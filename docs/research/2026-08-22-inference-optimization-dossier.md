# Inference-pipeline optimization dossier (biometric core)

Date: 2026-08-22
Provenance: delegated research agent, official ONNX Runtime docs, ort crate
docs, OpenCV Zoo first-party benchmarks, InsightFace repos, arXiv papers.
Fleet ISA context matters for INT8: 5700G (Zen3) has AVX2 but NO VNNI;
N100 and i5-1335U have AVX-VNNI; ASUS Zen — verify per host.

## Ranked experiments (payoff / risk order)

- **E1 — consent-watch detect-track hybrid.** YuNet every Nth frame (start
  12) + grey8 LK-flow/NCC tracking between; only detector frames may advance
  gate state; disagreement forces immediate re-detect. Watch cost today
  ~120 frames x 7-15 ms = 0.8-1.8 s per stream; hybrid ~0.2-0.3 s. Saving
  ~0.6-1.5 s/stream, 8-20% of the 7.04 s sequential e2e — the biggest
  pipeline win available, independent of the skew decision.
- **E2 — ViT PAD cascade behind FLIR + 3-frame median.** Offline first: from
  logged FLIR/ViT score pairs, find the band where ViT never flips a
  verdict; cascade + audit cadence only if the band is non-empty. Removes
  ~0.3-0.7 s of ViT compute per presentation on confident ones. 3-vs-5
  median replay is a free 40% cut if verdicts never differ. ADR-worthy
  coverage trade-off (ADR-0013 intent).
- **E3 — session warm-up at daemon start.** 2-3 dummy inferences per session
  at construction (pre-faults the 343 MB ViT, grows arenas, spins pools);
  first-vs-steady latency logged. Removes first-post-boot spikes; zero
  accuracy surface. Mechanism documented (onnxruntime#19177, #11581);
  magnitude must be measured on fleet.
- **E4 — INT8 YuNet on VNNI hosts only.** OpenCV Zoo's own int8 YuNet:
  AP delta ≤0.4 points but SLOWER than fp32 on x86 via OpenCV DNN — warning
  that int8 CPU wins are runtime-dependent; ORT/MLAS with VNNI may differ.
  Ship per host only where measured to improve (N100/1335U candidates;
  expect regression on 5700G). Validation: IoU≥0.5 box match on ≥99.9% of a
  ≥10k-frame golden corpus + 100% decision agreement; `qdq_loss_debug`
  triage on failure. S8S8-QDQ, per-channel, reduce_range on non-VNNI.
- **E5 — spinning/power config.** `intra_op.allow_spinning=0` (battery) or
  `spin_duration_us=1000`+`spin_backoff_max=8` (ORT's own tested combo);
  `dynamic_block_base=4` for latency variance. Outputs already known
  bit-identical across thread configs.
- **E6 — INT8 ViT PAD** (after E2 decides remaining ViT load). ViTs are the
  documented hard PTQ case (FQ-ViT: severe degradation without dedicated
  fixes); dynamic MatMul-only first, LayerNorm/softmax blocklisted. Primary
  motivation may be N100 MEMORY (343→~90 MB) rather than latency.
- **E7 — onnxsim + offline serialized models** only if E3's probe shows
  session-init on the auth path.

## Evidence-backed dead ends (do not spend time)

- **FP16 on CPU: no.** ORT CPU EP has no fp16 compute — conversion inserts
  casts (overhead, not speed).
- **Detector swap: no.** SCRFD-500M loses ~6.5 hard-set AP (the dim/IR/glasses
  cases we care about) and measures 28.3 ms single-thread on a Ryzen 9 vs
  our YuNet's 7-15 ms fleet e2e; SCRFD-2.5G costs ~5x the compute.
- **glintr100 quantization: no.** One embedding per capture is not hot, and
  quantizing the matcher perturbs the cosine thresholds everything is
  calibrated against.
- **IO binding: skip.** CPU-EP gains are sub-0.1 ms (0.4 MB tensors); the
  copy that mattered (output decode) is already borrowed.
- **Execution mode / graph level / mem-pattern / arena:** already at the
  right settings; explicit Sequential mode worth one line for
  crash-safety against crate default changes.

## Cross-cutting notes

- Quantization validation replaces bit-identity (impossible): golden hashed
  corpus ≥10k frames/host-class (consent-watch grey + lit IR + replay
  attacks), tolerance gates (IoU, verdict agreement, score distributions),
  fp32 shadow referee behind a flag.
- moire FftPlanner hoist (OnceLock) was already merged in the quick-fix PR.
- RGB 3-frame median denoise: restrict to the detected face ROI if profiling
  shows it hot.
- ORT profiling events (session trace) wired into the probe harness before
  ordering E4-E6, so decisions rest on measured per-op time per host.

## Sources

- https://onnxruntime.ai/docs/performance/tune-performance/threading.html
- https://onnxruntime.ai/docs/performance/model-optimizations/quantization.html
- https://onnxruntime.ai/docs/performance/model-optimizations/graph-optimizations.html
- https://onnxruntime.ai/docs/performance/tune-performance/iobinding.html
- https://onnxruntime.ai/docs/performance/model-optimizations/float16.html
- https://onnxruntime.ai/docs/performance/tune-performance/memory.html
- https://onnxruntime.ai/docs/performance/tune-performance/troubleshooting.html
- https://ort.pyke.io/troubleshooting/performance
- https://github.com/opencv/opencv_zoo/tree/main/models/face_detection_yunet (fp32 vs int8 AP)
- https://github.com/opencv/opencv_zoo/blob/main/benchmark/README.md (CPU latencies; int8 x86 regression)
- https://github.com/deepinsight/insightface/tree/master/detection/scrfd (WIDER tables, 28.3 ms single-thread)
- FQ-ViT: https://arxiv.org/abs/2111.13824 ; DynamicViT: https://arxiv.org/abs/2106.02034
- https://learnopencv.com/object-tracking-using-opencv-cpp-python/ (detect-track practice + failure modes)
- onnxruntime#19177, #11581 (first-inference latency)

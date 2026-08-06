# MediaPipe models on the native runtime: full benchmark and per-stage verdict

Date: 2026-08-06. Machine: ASUS Zenbook S 14, Intel Core Ultra 7 258V, 8 CPUs,
Fedora 44, bundled TFLite runtime v2.19.0 (`/usr/share/irlume/tflite/`).
Corpus: the committed 2026-08-05 stage-3 set, 512 frames (223 with an accepted
YuNet face), both cameras (Zenbook internal, NexiGo N930W).

This closes the question the 0.9.0 cycle opened: irlume can now run Google's
published `.tflite` artifacts unconverted (#295), so every MediaPipe model
relevant to face authentication gets measured on that runtime and compared
with what irlume ships. Earlier measurements this doc builds on:
`2026-08-05-fullrange-threshold.md` (full-range operating point),
`2026-08-05-blaze-full-parity-*.csv` (full-range decode parity),
`2026-08-06-mesh-parity.md` (mesh conversion fidelity).

## Models covered

| Model | sha256 (first 16) | Source | Status in irlume |
|---|---|---|---|
| BlazeFace short-range `.tflite` | `b4578f35940bf5a1` | Face Detector card, Apache-2.0 | shipped as ONNX conversion (rescue slot) |
| BlazeFace full-range `.tflite` | `3698b18f063835bc` | Face Detector card, Apache-2.0 | decoder landed, stage closed (#276) |
| Face landmarks detector `.tflite` (478 pt) | `c7d54204ce044847` | face_landmarker.task `64184e229b263107` | shipped as 468-pt ONNX conversion |
| Face blendshapes `.tflite` | `4f36dded049db18d` | same .task | never run before today |

Holistic stays excluded: 6 of its 7 inner files carry no model card, one is a
different 192px mesh (decision recorded on #276, 2026-08-05). The face
stylizer and the generic image embedder do no work an authentication pipeline
needs, so they were not benchmarked.

## Short-range BlazeFace: the shipped conversion is faithful

Harness: `crates/irlume-auth/examples/blaze_short_parity.rs`. Both models run
in one process on the identical input tensor (`blaze_letterbox_input`, the
production preprocessing) through the identical decode
(`decode_short_range_best`, the production decode), so the only difference
left is ONNX-converted weights on ort against original weights on TFLite.
This pair had never been compared on the native runtime; the 2026-08-05 bench
compared against the official Python runtime, which mixes in a preprocessing
gap.

Result over all 512 frames (`2026-08-06-blaze-short-parity.csv`): zero
one-sided detections, mean IoU 0.999999, minimum 0.999996, maximum score
delta 1.967e-6, and 139 of 512 frames score bit-identically across runtimes.
The instrument proves it can fail: a 2px shift injected into only the native
input drops mean IoU to 0.757 and leaves zero bit-identical scores
(`BLAZE_PARITY_SKEW_PX=2`). The harness is an enforcing gate: pinned 512/512
denominator, minimum IoU bound 0.9999, score-delta bound 5e-6.

## Face mesh: parity settled on 2026-08-06, latency measured today

`2026-08-06-mesh-parity.md` already established the shipped 468-pt ONNX mesh
matches the .task's 478-pt model at mean NME 6.9e-7 (worst 1.5e-6) over the
same crop. What was missing was cost. Measured on one frontal frame, 100
iterations after 10 warmup (`2026-08-06-mp-latency-zenbook.csv`):

| Stage call | Runtime | Threads | Mean ms | p50 | p95 |
|---|---|---|---|---|---|
| YuNet detect | ort | default | 14.32 | 8.93 | 29.73 |
| Short-range Blaze | ort | default | 3.13 | 2.35 | 6.37 |
| Short-range Blaze | tflite | 1 | 2.24 | 2.13 | 2.42 |
| Short-range Blaze | tflite | 2 | 1.46 | 1.38 | 1.82 |
| Short-range Blaze | tflite | 4 | 1.23 | 1.20 | 1.47 |
| Full-range Blaze | tflite | 2 | 4.11 | 4.07 | 4.43 |
| Mesh 468 (shipped) | ort | default | 7.62 | 7.37 | 9.01 |
| Mesh 478 (native) | tflite | 1 | 7.99 | 7.94 | 8.28 |
| Mesh 478 (native) | tflite | 2 | 5.85 | 5.74 | 6.98 |
| Mesh 478 (native) | tflite | 4 | 4.29 | 4.17 | 5.67 |
| Blendshapes | tflite | 1 | 1.76 | 1.71 | 1.83 |

Google's own reference for short-range Blaze is 2.94ms on a Pixel 6 CPU (Face
Detector solution page); the native runtime here lands in the same band. The
tflite rows also sit visibly tighter between p50 and p95 than the ort rows on
this machine.

## Blendshapes: first contact, and it tracks the production EAR cue

Harness: `crates/irlume-auth/examples/blendshapes_probe.rs`. Contract read
from `face_blendshapes_graph.cc` in the MediaPipe source: input [1, 146, 2],
146 selected landmarks as pixel coordinates, output 52 ARKit-order
coefficients. The 146-index subset ends with the 10 iris points (468-477),
which only the 478-pt landmarker-generation mesh emits. The shipped 468-pt
ONNX mesh cannot feed this model.

Over the 223 accepted corpus frames (`2026-08-06-blendshapes-probe.csv`),
per-frame `max(eyeBlinkLeft, eyeBlinkRight)` against irlume's production
`min(EAR)` gives Pearson r = -0.938: eye narrowing raises the blink
coefficient exactly as it lowers EAR. All 52 outputs stayed finite on every
frame. On this all-eyes-open corpus the blink coefficient never exceeded
0.37 in any segment mean; RGB segments sit at 0.04 to 0.21, IR runs higher
(0.13 to 0.37), and glasses-on IR is the worst case (0.32 to 0.37), the same
conditions that degrade EAR.

What this corpus cannot answer: open/closed separation. It holds no
closed-eye frames, so the margin between a genuine blink and the 0.37
worst-case open-eye reading is unmeasured. A blink capture session is the
missing measurement, not more analysis.

## Verdict, per pipeline stage

**Primary detection: YuNet stays.** No MediaPipe detector was benchmarked as
a YuNet replacement and none is a candidate: the 2026-08-05 stage-3 bench has
YuNet at 100% on RGB everywhere, and the rescue slot exists for exactly the
frames it drops.

**Rescue detection: full-range is the measured winner, and the stage stays
closed anyway.** Full-range detects 100% of the far-IR frames short-range
misses 9 of 9 on (2026-08-05 bench) at an affordable 4.1ms against 1.5ms.
That ranking changes nothing today: the rescue slot is grant-capable, so
flipping `Stage::Detection` open waits on an end-to-end false-grant corpus
(prints, screens, other faces carried to the auth outcome), not on any
detection accuracy number. Recorded on #276; re-deciding this on accuracy is
the exact mistake the #299 review caught.

**Landmarks: switch to the native 478-pt .tflite.** The evidence is now
complete on all three axes the decision needed. Fidelity: the two models
agree to mean NME 6.9e-7, and both parity harnesses run as enforcing
regression gates. Latency: native at 2 threads is 23% faster than the
shipped ONNX (5.85ms vs 7.62ms mean), with a tighter tail; 2 threads matches
the precedent `FullRangeBlaze` set. Supply chain: the switch deletes a
conversion step nobody can reproduce from the shipped artifact alone and
replaces it with Google's published file, byte-pinned, on the runtime irlume
already bundles and verifies. It also unlocks the iris block the blendshapes
model requires. Packaging cost: `face_landmarks_detector.tflite` (2.5MB)
joins the model set on every lane, and the mesh loader grows a TFLite path
behind the same pin discipline. Recommendation: do it as its own PR with the
mesh_parity gate as the acceptance test.

**Short-range Blaze runtime: no move needed.** The conversion is proven
faithful to 2e-6, so the ONNX copy is not a correctness risk. If the
landmarks switch lands and the rescue slot later moves to full-range, the
ONNX blaze and its conversion step retire naturally; switching it alone buys
1.7ms in a slot that only runs when YuNet already failed.

**Blendshapes: promising, blocked twice.** 1.8ms, finite everywhere, r=-0.94
against the production cue. As a consent-gesture or liveness signal it would
need (1) the native-mesh switch, since it eats iris points the shipped mesh
lacks, and (2) a blink corpus to measure open/closed separation before any
threshold exists. Not a candidate for wiring until both exist.

## Not measured

- Latency on one machine only (the Zenbook); the mini PC and archhost differ.
- Open/closed blendshape separation (no closed-eye frames in the corpus).
- Multi-thread determinism of the native runtime: the parity gates all ran
  single-threaded, and a 2-thread production mesh should re-run the
  mesh_parity gate at its production thread count before shipping.
- Full-range Blaze accuracy beyond the 2026-08-05 corpus; nothing new today.

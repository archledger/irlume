# Mesh parity: shipped face_landmark.onnx vs Google's face_landmarks_detector.tflite

2026-08-06. Answers the question left open when the native TFLite runtime
landed (#295): is the landmark model irlume ships, an ONNX conversion, faithful
to the artifact Google actually publishes?

## Method

`crates/irlume-auth/examples/mesh_parity.rs`. Both models run in one process
over the same frames: the shipped YuNet supplies one detector box per frame,
both meshes get the identical square crop (margin 0.25, matching
`FaceMesh::landmarks`), identical bilinear sampling, identical [0,1] NHWC
normalization, and the shared `map_checked_mesh_output` on the way back. The
ONNX side runs on ONNX Runtime, the native side on the bundled TFLite runtime
(XNNPACK) through `TfliteSession::from_pinned_bytes`, pin
`c7d54204ce0448474c7f3fa9af494787c0965cbdd6f20fc72867e43046bd43d5` (the mesh
inside the published `face_landmarker.task`, May 2023 revision; the bundle's
`face_detector.tflite` is byte-identical to the standalone short-range
BlazeFace, sha256 `b4578f35940bf5a1...`).

Comparison covers the first 468 landmarks (shared topology; the
landmarker-generation model appends 10 iris points) in x,y, which is what
every irlume consumer reads. NME normalizes by the native mesh's outer-eye
distance (indices 33 and 263).

Instrument check before believing the result: `MESH_PARITY_SKEW_PX=2` shifts
only the native crop and must move the metric, and the harness asserts it
does (a skew run that stays below mean NME 1e-3, or leaves any point
bit-identical, fails). Measured over the full corpus: mean NME 5.191e-3,
worst 2.018e-2, zero bit-identical points
(`2026-08-06-mesh-parity-skew.txt`).

The run is a GATE, not a report: it asserts the corpus denominator
(512 emitted, 223 compared) and bounds worst NME at 2.0e-6, so a parity or
coverage regression fails the run instead of shrinking the CSV. All three
model files are sha256-pinned to the shipped artifacts and the published
mesh; a run against anything else refuses by name.

## Corpus

The stage-3 corpus (`~/irlume-research/2026-08-05-stage3/{zenbook,nexigo}`,
the same frames behind the full-range threshold work): 512 frames across
frontal/close/far/sweep/glasses-on/dim plus empty-room segments, RGB and IR.
223 frames carried a detectable face on both paths; the remainder are the
empty and too-dark segments, present in the CSV with empty metric fields so
the denominator stays visible.

## Result

| kind | compared | mean NME  | worst NME |
|------|----------|-----------|-----------|
| rgb  | 90       | 6.879e-7  | 1.234e-6  |
| ir   | 133      | 6.877e-7  | 1.502e-6  |

7,930 of 104,364 compared points are bit-identical across the two runtimes
(count in `2026-08-06-mesh-parity-summary.txt`, which also records the model
and runtime hashes). Recorded outer-eye distances range 48.5 to 211.2 px,
and the largest rounded per-point distance in `max_px` is 0.0006 px.

## Reading

For the pinned shipped ONNX mesh and the pinned published TFLite mesh, these
223 stage-3 frames show numerical agreement in x and y. The experiment does
not compare z, does not prove graph or weight identity, and establishes
nothing outside this corpus and runtime configuration. The residuals are
consistent with backend arithmetic differences (ORT vs TFLite/XNNPACK), and
the harness does not identify their cause; what it bounds is their size,
four orders of magnitude below anything the EAR rings, frontality gate, or
glint cues could register.

Two consequences:

- The landmarks stage keeps its ONNX artifact with no fidelity cost measured
  on this corpus; there is no accuracy argument here for switching it to the
  native runtime.
- If the conversion step is ever dropped for supply-chain simplicity, this
  harness is the regression gate for the switch, and it now fails on its own
  when parity or coverage regresses.

Raw rows: `2026-08-06-mesh-parity.csv` beside this file.

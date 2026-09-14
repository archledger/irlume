# TFLite binding 0.10.1 admission and ownership audit

## Scope and exact dependencies

PR #705 updates `edgefirst-tflite` from 0.9.0 to exactly 0.10.1. The lockfile
resolves `edgefirst-tflite-sys` 0.10.2 and FlatBuffers 25.12.19. Registry package
SHA-256 values:

| Package | SHA-256 |
|---|---|
| edgefirst-tflite 0.10.1 | `d1ad179564e9705f067a9835b39ad9af13e6d04e102b9abd240a22d0a954d1d8` |
| edgefirst-tflite-sys 0.10.2 | `a73bebc09b5eb609ccc976bfb944f882bee016fb6e7cc54e54d470e01026a277` |
| flatbuffers 25.12.19 | `35f6839d7b3b98adde531effaf34f0c2badc6f4735d26fe74709d8e513a96ef3` |

The wrapper package identifies upstream commit
`0479343c183658674edc0778206c6e8e88e76e0b`. Comparing the published sources with
0.9.0 found unchanged sys runtime/build code, library discovery, explicit-path
loading, interpreter and delegate implementations. The significant wrapper
changes are tensor-width validation and model-buffer inlining, with generated
FlatBuffers object bindings. Disabling default features still removes optional
ZIP/metadata functionality; it no longer removes FlatBuffers.

## Preserved production contract

Irlume continues to load only SHA-verified artifacts. Model admission is ordered:

1. Compare the owned artifact's SHA-256 against the caller's required pin.
2. Inspect the verified bytes' `Model.buffers[*].offset` fields.
3. Reject any nonzero buffer offset, or a malformed layout in this inspection.
4. Resolve the explicitly selected TFLite runtime.
5. Move the accepted allocation into `Model::from_bytes`, then construct the
   interpreter and its delegate.

In upstream 0.10.1, `Model::from_bytes` rewrites a model if any buffer has a nonzero
offset. Its `Model::data()` still returns the original source allocation even
after such a rewrite, so that accessor alone cannot prove what reached the C API.
Irlume rejects the representation that activates rewriting. The approved inline
model therefore follows upstream's original-buffer branch, preserving the exact
SHA-verified allocation at `TfLiteModelCreate`.

The guard in `tflite/model_buffer.rs` is a bounded, allocation-free, safe-Rust
inspection of two schema fields: `Model.buffers` at vtable slot 12 and
`Buffer.offset` at slot 6. It checks table/vector bounds, signed vtable
displacements, field widths and arithmetic overflow. Absent offsets have the
schema default zero. It does not validate graph semantics or authorize a model;
the pin check precedes it, and the upstream parser/runtime retain full model
validation. Future schema or binding changes require reviewing these assumptions.

Offset-buffer models are unsupported even if their input digest matches an
explicit pin. Supporting them later requires a deliberate contract change, not
an implicit consequence of updating this dependency.

Irlume also retains:

- Explicit absolute library paths, with no fallback from a broken override to
  arbitrary dynamic-linker discovery.
- A single Float32 input, checked shape/length, and Float32 outputs. Upstream's
  new element-width check does not replace these checks; equal byte widths do
  not imply equal tensor types.
- Interpreter-before-model field order in `TfliteSession`. The model buffer and
  library remain alive while the interpreter can reference them.

## Regression and real-runtime verification

Automated admission tests cover inline/absent offsets, nonzero offsets in any
buffer, empty vectors, negative vtable displacements, truncation, malformed
offsets and overflow. Constructor tests verify pin-before-layout-before-runtime
ordering. The offset admission regression was observed failing before the guard
was wired into the constructor.

The Linux-only `buffer_runtime_tests` use a test-owned forwarding shared library.
It links to the explicit real TFLite library and intercepts only model creation
and model/interpreter deletion. All parsing and inference still execute in the
real runtime. The test observes the actual pointer and length received by
`TfLiteModelCreate`, verifies they are the original checked allocation, runs
synthetic Float32 input, checks finite outputs and bad-length refusal, and
verifies interpreter deletion completes before model deletion.

The tests cover the production mesh and the separately pinned full-range
BlazeFace artifact. They keep original model files unchanged and write no image,
embedding, credential or inference-output files. The temporary C shim is removed
after the test; one test-only library handle remains mapped until process exit
to mirror production's process-lifetime library reference.

Run the enforced runtime checks with:

```sh
IRLUME_TFLITE_LIB=/usr/share/irlume/tflite/libtensorflowlite_c.so \
IRLUME_TFLITE_MESH_TEST_MODEL=/path/to/face_landmarks_detector.tflite \
IRLUME_TFLITE_TEST_MODEL=/path/to/blaze_face_full_range.tflite \
scripts/run-tests-guarded.sh \
  --require pinned_landmarker_mesh_serves_landmarks_via_facemesh \
  --require pinned_mesh_session_retains_the_owned_allocation \
  --require pinned_mesh_reaches_c_api_without_rewriting \
  --require pinned_full_range_reaches_c_api_without_rewriting \
  -- cargo test -p irlume-vision --locked -- --ignored pinned_ --test-threads=1
```

The existing source-allocation test remains useful, but the C-API observation is
the proof against silent buffer replacement. These are model-admission/runtime
tests, not camera, PAD accuracy or successful-login qualification.

# Runtime benchmark examples

These examples report what they measure and fail on invalid samples. They do
not impose a latency gate on shared CI runners. Build with `--release` for a
performance comparison; a development build is useful only for harness smoke
checks. Save the exact revision, command, Cargo features, compiler version,
runtime files and machine conditions beside any result.

## Synthetic model calls

```sh
cargo run --release --locked -p irlume-auth --example stage_bench -- models 100 10
```

Arguments are model directory, measured samples per stage, and warmup calls per
stage. Samples must be positive; warmup may be zero. Defaults are `models`,
`100`, and `10`. `--help` performs no inference. The fixed synthetic pattern,
frame/chip dimensions and bounding box are printed.

The example uses the production Detector, FaceMesh, Embedder and PAD wrappers,
including their preprocessing. The default mesh is
`face_landmarks_detector.tflite`, routed through the production native TFLite
backend. Single embedding and RGB test-time augmentation are reported
separately. Environment overrides match the daemon's model names:
`IRLUME_DET_MODEL`, `IRLUME_MODEL`, `IRLUME_MESH_MODEL`,
`IRLUME_VIT_PAD_MODEL`, and `IRLUME_PAD_IR_MODEL`.

Each session's file loading and construction has a separate elapsed time. These
are serial construction observations; later sessions share already initialized
runtimes. They are neither a cold-disk guarantee nor cold-login latency. Model
file paths, sizes and SHA-256 snapshots are collected **after construction** to
avoid pre-warming construction through hashing. Keep files immutable throughout
a trial: the path snapshots are measurement provenance, not proof of the bytes
held by a session after concurrent path replacement. This harness does not
reproduce daemon manifest-policy startup or the whole engine construction path.

The ONNX resolver version/selection and actual mapped ONNX/TFLite library paths
and SHA-256 snapshots are reported after loading. TFLite is identified by its
loaded file, without inferring a version from a filename. Linux `/proc/self/maps`
is required when inference is requested. The active ONNX execution provider is
not observed by this harness: record build features and relevant runtime logs,
since an optional provider can fall back to CPU.

All warmup and measured calls must succeed. A first error stops the example
with a nonzero exit status, its stage, warmup/measured phase, and the count of
valid measured samples preceding failure. Partial timings are not published as
a successful stage distribution. A successful detector call returning no faces
is a valid inference sample; it does not establish authentication success or
representative model accuracy.

Successful stages print valid/requested sample counts, warmup count, arithmetic
mean, p50 and p95 in milliseconds. Percentiles use the nearest-rank convention
(`ceil(p * n)`, with ranks starting at one) over sorted durations. Outputs are
consumed through `std::hint::black_box`; reporting and result destruction are
outside the timed call. Black-box barriers are best-effort compiler optimization
barriers, as described in the [Rust standard library documentation](https://doc.rust-lang.org/std/hint/fn.black_box.html).

The stages are independent synthetic calls. **Do not sum them into login
latency.** Real authentication follows conditional detection, PAD, retry,
grouping and identity paths which synthetic content does not reproduce.

## Grayscale detector comparison

```sh
cargo run --release --locked -p irlume-auth --example letterbox_bench -- \
  640 400 models/face_detection_yunet_2023mar.onnx 200 5
```

The historical example name is retained. There is no copied letterbox loop:
full detector calls execute production preprocessing and inference. The RGB
comparison includes `grey_to_rgb` expansion inside every timed call; the native
comparison passes the same grayscale frame through `Grey8View`. Both paths get
the same number of checked warmup and measured calls. Expansion alone is also
reported. Omitting the detector path measures expansion alone and explicitly
reports that neither letterbox nor inference was measured. Dimensions and
sample counts reject malformed or zero values.

These measurements use one fixed input and run paths in a fixed order. They
exclude capture and are not a controlled before/after study. Alternate process
order and repeat on the same build/runtime/device before interpreting a small
difference. Tensor equivalence belongs in vision preprocessing tests; the
benchmark no longer claims that a copied loop proves production equivalence.

## One live engine authentication trial

`auth_timing --help` is safe to inspect without accessing cameras. Running a
trial intentionally opens the configured camera devices and may access
TPM/enrollment state. Use only in an authorized, attended measurement session.
For example, a local login credential-purpose engine trial can select
`--service login --purpose credential-release`; the historic default remains
`--service sudo --purpose auto`. `auto` uses the production service
classification (`AppConsent` for recognized app-consent services, `Verify`
otherwise). Available explicit purposes are `verify`, `credential-release`,
and `app-consent`; `--service none` supplies no service.

The example attempts production auxiliary wrappers for model files beside the
detector, with the daemon's environment overrides for adapter, mesh, BlazeFace,
RGB PAD and IR PAD. Implicit absent files and final loaded capabilities are
printed; an explicitly configured missing file is an error. Auxiliary load
failures stop the trial instead of silently altering the benchmark stack.
The mesh filename defaults to the native TFLite production model. This remains
an engine example, not the daemon's full startup/degraded-policy implementation.

Engine construction with auxiliary models is measured separately. Exactly one
`authenticate_for_with_diagnostics` call is measured, with its typed outcome,
granted/live flags and reason. Refused outcomes are labeled as such, not mixed
into successful-unlock samples. Errors stop with nonzero status and zero valid
samples. A singleton p50/p95 is the one observation, not distribution evidence.

Service and purpose alone do not establish grouped execution. The example
prints grouping as unobserved by its public stage sink. With `IRLUME_LOG=debug`,
the engine's `[assessment-stage] grouped-capture` marker is evidence of that
path; sequential scheduling alone is insufficient. Grouping also requires the
runtime camera contract, stored qualification, available PAD sessions and
budget. Do not describe a sudo trial as grouped local unlock.

Engine timing excludes process startup, daemon ingress/queueing, PAM handling,
actual credential unseal/release and wallet work. Passing credential-release
purpose selects engine policy; it does not measure the daemon's entire
credential-release request. Stage diagnostics can overlap or nest, and
`Liveness` covers different work in paired versus RGB-only paths. Never add the
stage lines together or compare those labels as equivalent work across modes.

## Deterministic checks

```sh
cargo test --locked -p irlume-auth \
  --example stage_bench --example letterbox_bench --example auth_timing
cargo clippy --locked -p irlume-auth \
  --example stage_bench --example letterbox_bench --example auth_timing -- -D warnings
```

The shared sampler tests reject zero samples before any work, stop on warmup
and measured failures, verify valid counts/output observation, and check known
nearest-rank percentiles including empty and singleton inputs. Auth option
tests exercise service-based default purpose, explicit credential purpose and
malformed input without loading models or authenticating.

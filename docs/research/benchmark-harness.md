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

## Daemon request boundaries

```sh
cargo run --release --locked -p irlume-daemon --example daemon_timing -- \
  <user> [--service NAME|none] [--trials N] [--cancel-after MS] [--no-trace]
```

This example talks to the RUNNING daemon over its socket; it performs no
inference itself. Each trial is one real `Authenticate` request measured
request-to-reply on the harness's own clock. With a diagnostic trace
subscription (root; schema 3) it also prints the daemon-side stage boundaries
the daemon emitted for those requests. Attended, authorized use only: cameras
may open and the emitter can fire. `--cancel-after MS` closes the harness's
own socket mid-request, which exercises the production client-disconnect
cancellation path; such trials are labeled `cancelled`, never pooled.

The boundary vocabulary and what each interval covers:

* `IngressParse`: the connection thread from the start of its read through
  request parse, posture gate and authorization, up to the creation of the
  operation scope. Measured from before the read (the scope does not exist
  yet) and reported inside the operation.
* `QueueWait`: from the connection thread's submission instant to the worker
  taking the job.
* `EnrollmentLoad`: engine-side, emitted exactly where a store load (or the
  deferred TPM unseal join) completes. On encrypted stores the deferred load
  deliberately overlaps the camera preflight, so this interval is a
  spawn-to-join resolution interval, not isolated loader CPU time. A user
  with no store at all denies before any load and emits nothing here.
* `EngineAuthenticate`: the daemon's wall time around the whole engine
  authentication call, including its nested engine stages (`CameraOpen`,
  `RateEstablishment`, captures, `Detection`, `Liveness`,
  `IdentityInference`, `Matching`, `StreamOwnerRelease`, `EmitterRestore`).
* `CredentialUnseal`: an unseal request's whole daemon-side handling
  (policy gates, face authentication when reached, release), on every exit
  including policy refusals; nests `EngineAuthenticate` when the engine is
  reached.

Stage intervals may overlap or nest by design; the report lists them and
never sums them. Trials are separated by categorical outcome (granted,
refused, cancelled) and medians use the nearest-rank convention over observed
values only; refused trials are never pooled with grants.

### Explicitly unmeasured boundaries

The harness prints these gaps in every report because they are real parts of
perceived login latency that no current Irlume diagnostic observes:

* worker reply to socket write (the reply channel and the connection
  thread's write are outside the operation scope);
* the PAM stack around the daemon calls;
* desktop/greeter unlock completion.

No trustworthy desktop-unlock completion signal is established: a brief
review (September 2026) of KScreenLocker documentation and community logs
found failure-side journal lines (for example `pam_unix` authentication
failures from `kscreenlocker_greet`) but no documented, stable positive
completion event for a PAM-driven unlock. Candidate mechanisms such as
logind session `Unlock` signals were not verified to fire on normal
PAM-authenticated unlocks, so the boundary stays explicitly unmeasured
rather than approximated. Establishing such a signal would be its own
verified investigation before any report claims desktop-unlock latency.

Cold/warm operation and route labeling: a cold trial requires a freshly
started daemon and is a session-level protocol decision, not a harness flag.
The active capture schedule comes from the trace's stream-contract and
capture-schedule events, never from the service name alone; do not describe
a trial by an assumed schedule. Loaded-system behavior is observed by
running concurrent camera-class requests during a trial, and belongs in the
session notes rather than the tool.

## Deterministic checks

```sh
cargo test --locked -p irlume-auth \
  --example stage_bench --example letterbox_bench --example auth_timing
cargo clippy --locked -p irlume-auth \
  --example stage_bench --example letterbox_bench --example auth_timing -- -D warnings
cargo test --locked -p irlume-daemon --example daemon_timing
cargo clippy --locked -p irlume-daemon --example daemon_timing -- -D warnings
```

The shared sampler tests reject zero samples before any work, stop on warmup
and measured failures, verify valid counts/output observation, and check known
nearest-rank percentiles including empty and singleton inputs. Auth option
tests exercise service-based default purpose, explicit credential purpose and
malformed input without loading models or authenticating. The daemon_timing
tests cover option validation, report labeling (cancelled/refused trials,
unmeasured gaps always present, stages never summed) and nearest-rank medians
without contacting a daemon.

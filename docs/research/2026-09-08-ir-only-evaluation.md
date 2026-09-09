# Experimental IR-only evaluation

This developer diagnostic evaluates one IR presentation without authenticating,
calling PAM, releasing a credential, saving enrollment, or changing persistent camera
configuration. `candidate_match` is experimental identity/PAD evidence only. It is
not qualified for login and must not be consumed as authorization.

The diagnostic exists only with the non-default `irlume-auth/ir-only-evaluation`
Cargo feature and never grants. Irlume also provides an explicit experimental
IR-only product policy with a separate production authorization path. The
diagnostic's `candidate_match` is not consumed by that product route. Existing dual
RGB+IR and sequential/concurrent scheduling remain unchanged.

## Build and invoke

```sh
cargo build --release -p irlume-auth --features ir-only-evaluation --example ir_only_evaluation
target/release/examples/ir_only_evaluation --help
```

Run the executable as real and effective root. Supply the existing detector,
recognizer and FLIR files explicitly; the example does not download models.
Pass the installed ONNX Runtime location through `ORT_DYLIB_PATH` when needed.
It reads the pair through `configured_pair_no_probe`: an explicit process-local
`IRLUME_RGB_DEVICE`/`IRLUME_IR_DEVICE` pair or the persisted camera configuration.
No pair means unavailable, with no fallback to discovery. The IR endpoint must
exist and differ from RGB. Existing IR enrollment binding, physical-device pin,
lease, emitter authorization and runtime frame provenance remain enforced.

```sh
sudo env ORT_DYLIB_PATH=/path/to/libonnxruntime.so \
  IRLUME_RGB_DEVICE=/dev/video0 IRLUME_IR_DEVICE=/dev/video2 \
  target/release/examples/ir_only_evaluation --preflight USER \
  /path/to/detector.onnx /path/to/recognizer.onnx /path/to/flir.onnx \
  --budget-ms 5000
```

Replace placeholders and verify the pair against current device metadata first.
`--preflight` loads models and the requested user's current protected enrollment,
checks readiness and never opens a camera. It may unseal the existing template
encryption key for an encrypted enrollment; it never unseals a login credential.
It uses the read-only protected storage loader, including its per-user state lock,
with no opportunistic envelope reseal or persistent TPM key provisioning.
An optional `--adapter /absolute/path.onnx` must match the enrolled IR space.
Missing explicitly supplied model files fail instead of silently omitting them.

Only after an attended start cue, use `--evaluate` instead of `--preflight`.
For harness cancellation add `--cancel-on-stdin` and keep stdin open; any byte,
EOF or read error requests cancellation. The executable refuses debug tracing
and the virtual-camera test override, suppresses dependency stderr before model
loading, disables process dumpability and core files before biometric/model reads,
and emits only its fixed JSON record. Do not enable image/debug capture
around this operation. The external harness must retain only permitted metadata.

## Operation and output

The library entry points are:

```rust,ignore
Engine::ir_only_evaluation_preflight(&self, enrollment: &Enrollment) -> Category
Engine::evaluate_ir_only(
    &mut self,
    enrollment: &Enrollment,
    control: &CaptureControl,
    budget: Duration,
) -> Report
```

The operation constructs the configured IR target, which validates the supported
sysfs topology before capture: one IR image node with at most its exact same-name
index-1 metadata companion on the isolated interface. It acquires a Diagnostics
lease for those exact endpoints and calls target-bound one-shot capture with pinned
emitter authorization. When the companion exists, capture opens that exact metadata
node for illumination classification; an explicitly absent companion does not
trigger discovery.

The contributor protocol intentionally narrows this further: its current harness
requires exactly one IR image node and one metadata companion, with RGB on another
interface, and rejects every other video open, including failed opens. Treat that
as the campaign's vetted topology, not evidence for arbitrary devices. The device
and lease are dropped before detection/inference begins. There is no retry,
explicit RGB capture, RGB scene substitution, `assess_full` call or authentication call.
The IR image is replicated into three channels solely for the existing detector,
FLIR, alignment and embedder input contracts; this is not an RGB camera frame.
This slice uses the primary detector only, without optional mesh/rescue models.

It checks the existing `evaluate_ir_only` gate, mandatory finite FLIR probability
in `[0,1]` below the existing IR PAD threshold, and the applicable enrollment
falloff floor. Identity uses the existing recognizer/IR-space/dimension filters,
optional adapter or per-profile calibration, best-template count adjustment and
calibrated-centroid profile-count arm at the existing dark IR thresholds. These
thresholds are reused for an experiment; their suitability for a new IR-only
login policy has not been established. Brightness falloff is not measured depth.
No cross-spectrum or RGB scene evidence is available in this experiment.

Current machine-readable results use schema 4. This abbreviated example omits no
fields; `capture_stages_ms` contains all fifteen nullable timing labels documented
by the contributor harness:

```json
{"schema":4,"operation":"ir_only_evaluation","authentication_granted":false,"category":"candidate_match","identity_acceptance":"both","elapsed_ms":1234,"capture_ms":900,"detection_ms":100,"pad_ms":100,"identity_ms":100,"capture_stages_ms":{"open":1,"session_setup":800,"buffers":10,"metadata":5,"emitter":2,"warmup":300,"rate_fill":250,"frames":100,"session_release":80,"image_stop":70,"metadata_streamoff":1,"metadata_buffers":1,"metadata_format":0,"metadata_close":0,"emitter_restore":1}}
```

`identity_acceptance` is `best_template`, `centroid`, or `both` only for a final
`candidate_match`; it is null for every refusal, error, cancellation or expiry.
It reports which existing finite-score predicates passed and never reports scores
or identities. Schemas 1, 2 and 3 remain valid historical records and are not
rewritten. Instrumentation permits empirical arm coverage to be measured, but
does not itself provide trials or qualification evidence.

Timing values are unsigned integer milliseconds. Unrun stages are `null`.
`elapsed_ms` covers the library evaluation, including readiness/capture/inference;
it excludes executable model loading and protected enrollment loading. Capture
time includes lease acquisition, setup and release. Identity time includes
alignment, embedding, optional adapter and matching. Millisecond rounding can
produce zero for a completed fast stage. Times are observations, not hard bounds.

Categories: `ready`, `candidate_match`, `identity_mismatch`, `no_face`,
`liveness_refused`, `pad_unavailable`, `pad_invalid`, `pad_refused`,
`incompatible_enrollment`, `invalid_frame`, `inference_failed`,
`camera_unavailable`, `cancelled`, `deadline_expired`, `invalid_request`,
`enrollment_unavailable`, `models_unavailable`, and `root_required`.

Capture errors additionally report these fixed labels: `camera_busy`,
`camera_rate_refused`, `camera_io_failed`, `camera_hardware_failed`,
`camera_authorization_refused`, `camera_policy_refused`, `camera_capture_failed`,
`camera_lease_timeout`, and `camera_lease_refused`. These preserve existing typed
errors; messages and rate-evidence payloads are discarded. `camera_unavailable`
remains the preflight category for an unavailable/mismatched endpoint. A lease
acquisition timeout is distinct from the five-second (or caller-specified)
evaluation deadline; caller cancellation or expiry still takes precedence.
Generic hardware errors cannot identify provenance, emitter, permission or
other causes once the lower layer has collapsed them into a string. No text
matching or automatic retry attempts to infer a more precise cause.

Schema 4 adds only the bounded identity acceptance field and preserves the schema-3
capture timing map. Consumers must enforce the exact category/acceptance relation.
Older recorded reports are not reclassified. Camera-free tests exercise error-type
classification, payload suppression, inference stopping and cancellation priority.

No result contains names, scores, raw errors, images, embeddings or templates.
Exit status 0 means the diagnostic ran, including a refusal; it never denotes
successful authentication. Invalid syntax and non-root execution exit 2.

## Bounds and qualification limits

The required budget is 100 through 30,000 milliseconds. Caller cancellation and
any earlier caller deadline are preserved; the local deadline also bounds
capture. Checks run before capture, after returned driver calls, between
inference stages and immediately before publishing the category. Late
cancellation or expiry overrides a candidate. Kernel/model calls cannot be
forcibly interrupted by this cooperative contract; a returned report can exceed
the budget. A supervising harness needs a separate startup/hard watchdog, whose
forced cleanup must be recorded separately from normal cooperative release.

Camera-free tests cover missing/invalid/spoof PAD, failed liveness, optional
falloff floor, incompatible templates, identity mismatch and centroid evidence,
malformed frame dimensions, cancellation/expiry at the injected capture boundary,
argument bounds, crash-dump disabling in an isolated child, and a metadata-only
output schema. The real orchestration driver is exercised through typed stages
that interrupt after capture, detection, PAD, alignment, embedding, adaptation
and final identity evaluation. These do not establish device
release timing or the absence of RGB opens in a physical run. The attended
harness must trace opens/closes and independently verify camera cleanup.

First evaluate an ordinary-light genuine user, an empty frame, cooperative
cancellation, and available presentation artifacts such as the user's vinyl
photo banner. Record each result and its coverage separately. Dim-light trials
remain excluded. An unavailable model/lease or an expired attempt is not an
identity/PAD accuracy sample. One subject and one artifact do not establish
false-accept rates, broad presentation-attack resistance, or sensor-injection
resistance. Optional login support requires held-out full-rule genuine/impostor
and attack evaluation across both identity acceptance arms and the relevant
supported camera/model configurations.

## Contributor qualification

Use the [IR-only qualification protocol](../IR_ONLY_QUALIFICATION.md) and its
[campaign record](ir-only-campaign-template.md) before making deployment claims.
The current diagnostic is available for evaluation; empirical acceptance-arm
coverage remains open. A [portable contributor harness](../../scripts/ir-evaluation/README.md)
now supplies explicit host checks and an attended attempt ledger; qualification
on additional hosts remains open. Neither
component replay nor successful developer trials qualify or enable the separate
experimental product policy on an installed login.

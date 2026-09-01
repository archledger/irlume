# Layered Camera Profile And Evidence Engine Design

## Problem

Irlume currently requests one fixed RGB geometry and one fixed IR geometry,
chooses the first supported decoded format, and uses the driver's reported
default frame interval. Capture then converts V4L2 payloads into owned RGB8 or
GREY8 frames, reduces bounded bursts, and passes frame views into detector,
recognition, liveness, and PAD code.

This is already safer than feeding raw camera buffers directly into models, but
three decisions remain coupled:

- Which exact device-advertised format, resolution, and frame interval should
  be requested before streaming.
- Which reversible camera controls and evidence-reduction policy are suitable
  for the current scene.
- Which exact crop, alignment, resize, channel, range, and normalization
  contract each model consumes.

The ASUS internal pair demonstrates why the first decision matters. Its RGB
stream can run at 15 fps instead of 30 fps, reducing the paired nominal
uncompressed payload by about 41 percent. Transport measurements show that
15/15 can preserve concurrent delivery in a dark run where 30/15 did not, but
no detector, recognition, liveness, PAD, or end-to-end latency evidence yet
authorizes that profile. BRIO and NexiGo measurements also show that a lower
nominal payload is not sufficient: BRIO RGB15/IR30 still failed every
concurrent round, and NexiGo exposes no lower-demand decoded tuple.

The system therefore needs a bounded qualification-time profile engine and an
explicit canonical model-input boundary. It does not need a generic USB
bandwidth allocator or a continuously adaptive learned controller.

## Goals

- Select exact transport profiles only from device-advertised UVC tuples.
- Preserve quality and security as hard gates, never weighted preferences.
- Balance USB demand and p95 authentication latency among profiles that pass
  every gate.
- Keep the selected transport tuple fixed for a qualified hardware context.
- Permit bounded runtime conditioning through pre-qualified camera-control and
  preprocessing policies selected between authentication attempts.
- Freeze the complete capture and conditioning plan during each evidence
  window.
- Ensure models receive typed canonical inputs, never V4L2 buffers or
  camera-specific pixel layouts.
- Bind every result to camera, transport, conditioning, preprocessing, and
  model provenance without logging biometric content.
- Preserve password fallback and existing fail-closed PAD policy.

## Non-Goals

- Direct userspace allocation of USB bandwidth or UVC alternate settings.
- Arbitrary format, resolution, or frame-rate search during authentication.
- Profile changes while one authentication attempt is collecting evidence.
- Confidence-driven control feedback from detector, recognizer, liveness, or
  PAD outputs.
- Automatic MJPG support. Compressed capture requires a separate decoder and
  security qualification project.
- Model retraining, threshold changes, or relaxed PAD availability.
- Persisting frames, crops, tensors, embeddings, identities, or sensitive
  per-user model scores in diagnostics.

## Terminology

**Transport profile**:
An exact RGB and IR format, geometry, frame interval, and capture schedule
bound to one camera pair and connection context.

**Conditioning policy**:
A bounded set of reversible standard camera controls and deterministic
evidence-reduction parameters qualified for a scene class.

**Canonical evidence**:
Owned, validated RGB8 or GREY8 scene evidence with complete frame provenance,
after capture decoding and bounded temporal or illumination reduction but
before model-specific tensor conversion.

**Model input contract**:
The exact shape, layout, channel order, numeric type, range, normalization,
crop, alignment, and preprocessing version required by one model.

**Attempt capture plan**:
An immutable binding of camera identities, transport profile, conditioning
policy, evidence-window rules, preprocessing versions, and model contracts for
one authentication attempt.

The existing project meanings of capture schedule, capture qualification,
runtime degradation, support report, and diagnostic trace remain unchanged.

## Capability Inventory

"Default" has three distinct meanings and must never be presented as one fact:

| Layer | Meaning |
|---|---|
| OEM capability | Discrete tuples advertised by camera firmware |
| Driver state | The mutable tuple currently left in a V4L2 node |
| Irlume profile | The tuple Irlume deliberately requests and verifies |

Irlume currently requests RGB 640x480, preferring YUYV then NV12, and requests
IR near 640x400, preferring native greyscale. A driver may adjust the IR
geometry to an advertised tuple. The observed hardware inventory is:

| Camera | RGB advertised presets relevant to Irlume | IR advertised preset | Current Irlume result |
|---|---|---|---|
| ASUS internal | YUYV 640x480, 640x360, 352x288, 320x240, 176x144, and 160x120 at 30/15; 1280x720@10; 1920x1080@5. MJPG 176x144 through 1920x1080 at 30/15. | GREY 640x400@15 only | YUYV 640x480@30 plus GREY 640x400@15 |
| Logitech BRIO | YUYV and NV12 over many geometries and rates. YUYV 640x480 supports 30/24/20/15/10/7.5/5. MJPG extends to 4K and higher rates. | GREY 340x340@30 only | YUYV 640x480@30 plus adjusted GREY 340x340@30 |
| NexiGo N930W | YUYV 640x480@30, 854x480/960x540@20, 1280x720@10, 1920x1080@5. MJPG 640x480 through 1920x1080@30. | GREY 640x360@30 only | YUYV 640x480@30 plus adjusted GREY 640x360@30 |

Approximate uncompressed payload before USB framing and protocol overhead:

| Profile | Nominal payload |
|---|---:|
| ASUS RGB30/IR15 | 22.27 MB/s |
| ASUS RGB15/IR15 | 13.06 MB/s |
| BRIO RGB30/IR30 | 21.90 MB/s |
| BRIO RGB15/IR30 | 12.68 MB/s |
| NexiGo RGB30/IR30 | 25.34 MB/s |

The ASUS RGB endpoint exposes brightness, contrast, saturation, hue,
white-balance mode and temperature, gamma, gain, power-line frequency,
sharpness, backlight compensation, ROI, exposure mode and time, dynamic frame
rate, and read-only privacy controls. Its IR endpoint exposes ROI and read-only
privacy controls. BRIO and NexiGo control inventories must be collected through
the same bounded capability inventory before any conditioning policy can name
their controls. No control is inferred from a model name or vendor family.

Format, geometry, frame interval, and compression selected before streaming
can change USB demand. Cropping, resizing, color conversion, denoising,
alignment, and normalization after dequeue can reduce model compute and
stabilize inputs, but cannot recover USB bandwidth already consumed.

## Decision

Use a layered qualified policy engine with five bounded modules.

### CapabilityInventory

`CapabilityInventory` snapshots exact V4L2 format, geometry, interval, and
standard-control domains together with fd-derived camera identity and USB
connection context.

- Enumeration is bounded by explicit item and serialized-size limits.
- Exact fractions are retained. No frame-rate decision uses floating point.
- Only standard V4L2 controls and already-whitelisted emitter controls are
  eligible. Unknown vendor extension units are never probed or written.
- A missing or failed enumeration is unknown, not an empty capability claim.
- The inventory is observation only and creates no capture authority.

### TransportProfileQualifier

`TransportProfileQualifier` generates only tuples that the inventory advertises
and the capture path can decode. It rejects candidates before hardware testing
when geometry, payload layout, stride bounds, rate floors, or model-input
requirements cannot be met.

Qualification runs these stages in order:

1. Static feasibility and decoder support.
2. Read-only `VIDIOC_TRY_FMT` preview.
3. Exact `VIDIOC_S_FMT` and `VIDIOC_S_PARM` with complete readback.
4. Sequential and concurrent delivered-rate, continuity, payload, identity,
   and illumination validation.
5. Bright, backlit, low-light, and dark-IR signal validation where applicable.
6. Detector, recognition, liveness, ViT RGB PAD, and FLIR IR PAD regression
   gates for every applicable grant path.
7. End-to-end p50/p95 latency and bounded CPU/memory measurement.
8. Context-bound persistence with explicit producer and policy versions.

Quality and security are hard gates. A profile failing one gate is not ranked.
Among passing profiles, the qualifier removes Pareto-dominated candidates and
ranks the remainder by nominal USB demand and measured p95 authentication
latency normalized against fixed versioned policy budgets. Adding or removing
an unrelated candidate cannot change those normalization denominators.
Preprocessing cost is a secondary constraint. Ties prefer lower USB demand and
then a stable profile identifier.

The persisted result contains one selected transport profile and, where
measured, one qualified sequential fallback. An unqualified best-effort profile
is never persisted.

### ConditioningPolicyCatalog

`ConditioningPolicyCatalog` contains a small, versioned set of policies such as
`lit-auto`, `backlit-auto`, `low-light`, and `dark-ir`. A policy may name:

- Standard camera controls with exact requested and required readback values.
- Whether automatic exposure or white balance remains enabled within a
  qualified envelope.
- Warm-up and bounded evidence-window sizes.
- RGB temporal reduction policy.
- IR lit-frame selection and ambient-subtraction eligibility.
- Calibration and preprocessing version identifiers.

A policy can use only controls present in the current capability inventory and
qualified for the exact camera context. Control application follows the
existing read-before-write, confirm, and restore pattern. A write mismatch is
not retried harder. Restoration guards are armed before streaming and survive
error, cancellation, and panic paths.

Scene classification occurs before an authentication attempt. The first attempt
uses the catalog's safe default. A later attempt may use only fresh,
process-local, context-bound non-model statistics from a preceding evidence
window, such as brightness distribution, clipping, contrast, and IR
illumination facts. Observations expire on a bounded timer and immediately on
camera incarnation, connection, transport, or policy-version change. The
classifier never consumes detector, recognition, liveness, PAD confidence, or
an authentication result. The selected conditioning policy is frozen for the
attempt. Irlume does not open a hidden preflight stream solely to classify the
scene.

### CanonicalPreprocessor

The capture boundary owns V4L2 buffers and device-specific payload layouts.
No borrowed V4L2 buffer crosses it.

```text
V4L2 buffers
  -> payload, stride, sequence, timestamp, and role validation
  -> owned decoded RGB8 or GREY8 frames
  -> bounded temporal and illumination evidence reduction
  -> canonical scene evidence
  -> detector tensor
  -> landmarks and alignment
  -> model-specific face tensors
  -> recognition, liveness, and PAD
```

RGB canonical evidence preserves the current auto-exposure warm-up and
five-frame per-pixel temporal median. IR canonical evidence preserves the
ten-frame bounded burst, camera-reported illumination when available,
clip-aware gate-frame selection, ambient evidence, and explicit provenance for
any subtraction. Ambient subtraction remains disabled unless a separately
qualified conditioning policy enables it.

Each model adapter owns its exact tensor contract. Existing measured contracts
remain unchanged, including ArcFace 112x112 alignment and normalization, ViT
RGB PAD m96 crop and 224x224 normalization, and FLIR IR PAD padding, resize,
center crop, and normalization. YuNet 640 letterboxing, short-range BlazeFace
128 letterboxing, full-range BlazeFace 192 letterboxing, and the legacy 192 and
current 256 FaceMesh crop contracts are frozen by the same boundary. A model
whose shape, preprocessing version, color convention, or calibration does not
match the attempt plan is unavailable, preserving ADR-0019 fail-closed
behavior.

### ModelGateway

`ModelGateway` accepts only typed canonical evidence or typed tensors produced
by a matching model adapter. It cannot accept `irlume_camera::Frame`, arbitrary
byte slices, or camera fourcc values directly.

Task 4 scope correction: the initial design and plan named only YuNet, ArcFace,
ViT RGB PAD, and FLIR IR PAD even though authentication also invokes
short-range BlazeFace and FaceMesh during rescue alignment, and measurement
tools invoke full-range BlazeFace. Leaving those APIs raw would have preserved
an alternate camera-buffer-to-inference path and made the typed boundary
incomplete. Task 4 therefore covers every inference wrapper and every auth,
CLI, test, example, and benchmark consumer. Direct TFLite sessions remain
measurement-only runtime parity tools, but their inputs are obtained from the
matching typed contract rather than a duplicated public preprocessor.

Detector output carries the landmarks and transform provenance used to derive
recognition and PAD inputs. RGB and IR geometry mapping is profile and
calibration specific. Nominal dimensions alone never establish cross-spectrum
alignment.

## Attempt Capture Plan

Before streaming, one immutable `AttemptCapturePlan` binds:

- Exact RGB and IR camera incarnation and generation.
- Exact requested and accepted transport profiles.
- Capture schedule and qualified sequential fallback eligibility.
- Conditioning policy and required control restoration values.
- RGB and IR evidence-window and illumination rules.
- Canonical preprocessing and calibration versions.
- Detector, recognizer, liveness, and PAD model identities and input contracts.
- Qualification producer, policy version, context key, and invalidation facts.

The plan cannot change after the evidence window begins. Contract drift aborts
the face attempt. Runtime degradation may mark concurrent capture unhealthy and
select the already-qualified sequential schedule for a later attempt, matching
the existing project definition. It does not create a new transport profile.

## Evidence Manifest

Each canonical tensor bundle carries a bounded non-biometric manifest:

- Transport profile and conditioning policy identifiers.
- Camera incarnation, generation, role, and capture-window facts.
- Frame sequence and timestamp ranges, delivered rates, and continuity facts.
- Control identifiers and exact readbacks, without device paths or serials in
  share-safe output.
- Illumination phases and contributor-selection rationale.
- Crop, alignment, resize, color, normalization, calibration, and
  preprocessing versions.
- Model identifiers and input-contract versions.

The in-process manifest may carry context-bound identity needed for validation.
Support reports and diagnostic traces receive only existing sanitized
projections. Neither representation stores frames, crops, tensors, embeddings,
identities, or sensitive per-user scores.

## Failure And Fallback

- Capability or qualification failure creates no authority.
- Exact negotiation or readback mismatch rejects the candidate immediately.
- Unsupported or mismatched controls reject the conditioning policy.
- Payload, rate, continuity, role, illumination, preprocessing, calibration, or
  model-contract drift aborts the face attempt.
- Required PAD unavailability remains a password-only condition under ADR-0019.
- A qualified sequential schedule may be selected for the next attempt after
  runtime degradation. Captured evidence from the failed concurrent attempt is
  discarded.
- Failed control restoration makes face authentication unavailable until clean
  restoration, restart, or requalification proves a safe state.
- Password fallback remains independent and available.

## Observability

Extend aggregate diagnostics with bounded profile and policy identifiers,
qualification stage outcomes, negotiation/readback results, delivered-rate and
continuity evidence, control restoration outcomes, preprocessing stage timing,
model-contract validation, and fallback reasons.

Do not log raw paths in share-safe output, camera serials, frames, crops,
tensors, embeddings, identities, or sensitive model scores. Existing support
report and diagnostic trace privacy contracts continue to govern projection.

## Verification

- Unit tests for bounded enumeration, exact fractions, filtering, Pareto
  reduction, balanced ranking, deterministic tie-breaking, scene policy
  selection, and context invalidation.
- Mocked ioctl tests for driver adjustment, exact negotiation, readback
  mismatch, unsupported controls, and restoration ordering.
- Golden tests for RGB decode and temporal median, IR decode and burst
  selection, YuNet, ArcFace, ViT RGB PAD, FLIR IR PAD, BlazeFace, and FaceMesh
  preprocessing.
- Contract tests proving inference entry points cannot consume camera buffers or
  untyped frames.
- Hardware qualification in bright, backlit, low-light, and dark-IR scenes.
- Detector, recognition, liveness, and PAD regression gates for every accepted
  transport-profile and conditioning-policy pair.
- Profile-independent model regression over a representative, consented
  evaluation corpus. One enrolled person's recognition score may add local
  evidence but cannot authorize a machine-wide transport profile.
- Fault injection for disconnects, short buffers, stalled streams, timestamp
  resets, control failures, emitter failures, cancellation, and restoration.
- End-to-end p50/p95 latency, CPU, memory, and delivered-rate measurements.

## Rollout

1. Extract typed transport, conditioning, evidence, and model-input contracts
   around existing behavior without changing production selection.
2. Put current RGB median and IR burst logic behind canonical evidence
   constructors and prove existing model inputs remain equivalent.
3. Build a no-authority capability inventory and offline candidate qualifier.
4. Add a small conditioning-policy catalog using only verified standard
   controls and existing safe emitter mechanisms.
5. Run complete ASUS 30/15 versus 15/15 authentication-quality qualification.
6. Enable a winner only for the exact qualified ASUS context. Retain qualified
   sequential capture for BRIO and NexiGo.
7. Consider MJPG only in a separate decoder and security design.

Production behavior remains unchanged through the first four rollout stages.
No transport result alone authorizes a production profile change.

## Alternatives Rejected

### Single Unified Optimizer

Jointly searching transport, controls, preprocessing, and models creates a
combinatorial qualification surface. A result becomes difficult to reproduce,
invalidate, explain, and audit. Transport and model contracts also change for
different reasons and should not share one mutable optimization state.

### Learned Adaptive Tuner

Using model confidence to adjust capture creates an attacker-influenced
feedback loop. It is difficult to reproduce and can silently change the input
distribution that thresholds and PAD operating points were qualified against.

### Vendor-Specific Fixed Overrides

A table keyed only by camera model ignores firmware, endpoint incarnation,
connection topology, driver behavior, and model/preprocessing versions. The
BRIO and NexiGo measurements show that nominal vendor capabilities do not prove
a usable concurrent transport profile.

## Consequences

- Camera variability is contained before inference, while models see stable,
  typed contracts.
- Runtime conditioning can improve scene quality without changing transport or
  model contracts during an attempt.
- Qualification becomes more expensive because every accepted profile and
  policy must pass full authentication-quality gates.
- Context and version invalidation become central correctness requirements.
- Existing camera, vision, and auth modules need narrower interfaces, but no
  new daemon or privileged helper is required.
- The ASUS 15/15 candidate remains experimental until complete qualification.

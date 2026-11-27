# ADR 0007: Bind RGB+IR concurrency to the measured stream and USB context

Date: 2026-08-17

Status: Accepted; implemented (context-bound qualification-v2 and runtime degradation shipped)

## Context

irlume supports two valid capture schedules:

- **concurrent** holds the RGB and IR streams at the same time;
- **sequential** captures one stream at a time.

Concurrent capture is faster when the complete path can sustain it. It is not
a property of a camera model alone. It is a property of an exact RGB media
type, an exact IR media type, their frame intervals, the device firmware and
driver, and the USB connection on which the two streams run.

This matches the architecture Windows exposes for face authentication. Windows
camera profiles declare the media types and combinations that may be used
concurrently; the Windows Hello validation suite then tests the declared IR
stream and, when the profile permits it, RGB+IR concurrency. It does not infer
concurrency from a product name.

Linux has the same underlying constraint. `VIDIOC_S_FMT` and `VIDIOC_S_PARM`
return the format and interval the driver actually accepted, which may differ
from the request. uvcvideo derives an endpoint payload from the chosen format
and interval and selects an alternate interface setting whose periodic USB
bandwidth can carry it. Host-controller admission can then depend on the
device's negotiated link and the other periodic traffic below that controller.

The current implementation gets several important things right:

- an unmeasured pair defaults to sequential;
- the probe holds both sessions in the same schedule the consumer uses;
- a conclusive failure to open or arm both streams selects sequential;
- a clean concurrent verdict requires adequate scene signal;
- authentication never runs the multi-round probe;
- the runtime rate and frame-provenance gates reject bad delivered evidence.

The persisted verdict is too broad, however. It is keyed by
`VID:PID[:serial]` for each node and stores only `concurrent` or `sequential`
plus a small origin sidecar. It does not bind the verdict to:

- the descriptor and interface that produced each stream;
- the exact requested and driver-accepted formats and frame intervals;
- the physical USB port, controller, or negotiated link speed;
- the capture backend, driver, or qualification-policy version.

Serial strings cannot close this gap. Some cameras have no serial, and some
vendors repeat one serial across a batch. Two identical serial-less cameras
also collide under the current key. A result can therefore survive a camera
swap, format change, or move from a SuperSpeed port to a High-Speed path.

There is a second unsafe edge: explicit `camera-tune` currently persists a
recommendation even when its rounds are incomplete or the scene is too dim to
prove healthy RGB retention. Inconclusive evidence must not authorize
concurrent capture.

Finally, bus load is dynamic. A context-bound qualification can establish that
a tuple worked on a connection; it cannot promise that another device will
never consume the controller's remaining budget later. Runtime evidence must
therefore protect every authentication operation.

## Decision

Keep the two capture schedules and replace the unversioned camera-model verdict
with a **context-bound capture qualification**. “Unqualified” is qualification
state, not a third capture schedule. It always resolves to sequential.

The system has two layers:

1. A durable qualification records what a controlled A/B measurement proved
   for an exact camera pair, production stream tuple, and USB connection.
2. A process-local health circuit breaker protects current authentications from
   dynamic failures that occur after qualification.

Neither layer may infer hardware capability from a face-match result alone.

### Durable identity and connection context

Each member of a pair is described from the opened device file descriptor, not
from a caller-supplied path:

- SHA-256 of the USB descriptor blob;
- VID and PID;
- USB serial when present, treated only as corroborating evidence;
- VideoControl interface number and stream role;
- canonical USB device path below `/sys/devices`.

The descriptor digest, optional serial, interface, role, and device path are
matched together. No one field authorizes reuse. The path distinguishes two
identical units connected at once; the descriptor prevents a different model
on a reused port from matching. Moving a camera to another port intentionally
invalidates the qualification.

The connection context also records:

- the stable sysfs path of the USB host controller;
- the device's negotiated USB speed in Mbit/s;
- the kernel driver name;
- the capture backend identifier.

USB bus and device numbers are diagnostic only. They are allocated dynamically
and are not persistent identity.

Hub occupancy and competing traffic are reported when observable but are not
part of the durable key. They change too frequently. Per-operation health is
the authority for those conditions.

### Exact production stream profile

A qualification covers one pair of production stream contracts. Each contract
records:

- role: RGB or IR;
- requested width, height, pixel format, and frame interval;
- driver-accepted width, height, pixel format, stride, image size, and exact
  frame interval;
- the minimum delivered-rate floor used by the qualification.

The accepted values come from the live driver echo. A concurrent capture must
revalidate them after opening both sessions. A mismatch aborts that concurrent
attempt before its frames can reach recognition and retries sequentially.

The initial implementation qualifies only irlume's existing production tuple.
It does not search lower resolutions, lower frame rates, or compressed formats.
Issue #341 correctly gates such a future experiment on evidence of an
addressable bandwidth failure and acceptable recognition quality. A bare errno
does not license automatic degradation.

### Versioned record

Store one bounded JSON record per pair under
`irlume_common::state_dir()/capture-qualifications`. The record has a required
schema version and contains:

- schema and qualification-policy versions;
- descriptive engine version and measurement time;
- both fd-derived camera identities;
- connection context;
- both exact stream contracts;
- requested and completed round counts;
- sequential and concurrent delivered-rate, continuity, error, brightness,
  retention, and latency summaries;
- one authoritative outcome and its reason.

Authoritative outcomes are:

- `concurrent_qualified`;
- `sequential_required` because the pair could not open or arm concurrently,
  could not maintain required delivery, or lost material RGB/IR signal.

An incomplete, internally inconsistent, dark-scene clean result, identity
change, or missing provenance is `inconclusive`. It is useful diagnostic data
but is not an authoritative outcome and is never resolved as concurrent.

The record keeps the last attempt and, when still applicable, the last
authoritative qualification in one atomic object. An inconclusive retune does
not manufacture a new verdict or erase a still-matching earlier one. A context
or profile mismatch makes that earlier qualification inapplicable regardless.

Unknown schemas, oversized files, malformed data, missing required fields, and
unreadable stores all fail to sequential and produce a doctor diagnostic.

The store is root-owned and not writable by the authenticating user. Writers
use a stable per-pair lock inode, write a same-directory temporary file, sync
according to the machine-state durability contract, atomically rename, and
sync the directory. Readers see either the previous complete record or the new
complete record. Measurement writers use a revision compare-and-set so an
automatic enrollment probe cannot overwrite a newer explicit tune.

### Qualification rules

Qualification runs only during an explicit privileged `camera-tune` or the
existing first-enrollment setup opportunity. It may fire the IR illuminator,
so authentication and an unprompted background task must not run it.

Both callers apply the same evidence rules. Explicit tune differs only in that
it may replace an applicable older qualification when its new result is
conclusive. It does not get permission to store weak evidence.

A healthy concurrent qualification requires all requested rounds to complete
and show:

- the exact production contracts on both arms;
- acceptable delivered rate for both streams while held concurrently;
- trusted monotonic timestamps without an unexplained discontinuity or epoch
  recovery;
- no decode, queue, open, arm, or capture error;
- IR illumination provenance required by the production path;
- at least the existing 80% RGB and IR signal-retention floor;
- a scene bright enough to make a clean RGB comparison meaningful.

A conclusive all-error concurrent arm may select sequential only when the
sequential control completes and proves the camera still responds. Partial or
mixed failures remain inconclusive unless a separately specified rule has
enough evidence to name the failure safely.

Latency savings are reported but do not override correctness. Concurrent is an
optimization, not an authentication requirement.

### Runtime resolution and fallback

The capture schedule is resolved once per camera-operation lease and does not
change halfway through that operation:

1. The existing operator environment override may request a schedule for
   diagnostics. It cannot disable format, rate, provenance, or fallback gates.
2. A tripped process-local circuit breaker may demote concurrent to sequential.
3. A fully matching, conclusive qualification may select its outcome.
4. Everything else selects sequential.

The candidate qualification is first selected from read-only sysfs context,
then revalidated against both opened file descriptors and the driver-accepted
contracts. This closes the path-to-fd replug race. A mismatch fails toward
sequential.

Every concurrent authentication remains bounded by runtime evidence. Before a
frame is eligible for recognition, both streams must satisfy their existing
format, delivered-rate, timestamp-continuity, generation, and illumination
contracts. A low-level concurrent failure causes a bounded retry of the same
authentication using sequential capture. If sequential evidence is valid, the
user's authentication continues rather than failing merely because the
optimization stopped working.

Open/arm failure, contract mismatch, delivery-rate shortfall, or broken
provenance trips the circuit breaker immediately for the current pair and
camera generation. Repeated A/B-confirmed signal loss may also trip it, but
face absence by itself may not. The breaker is process-local: it prevents a
transient controller load from permanently rewriting hardware capability.
It resets on a new camera generation, explicit successful tune, or daemon
restart and is visible in diagnostics while active.

Authentication never performs the full multi-round qualification and never
persists a downgrade. Enrollment may gather conclusive signal evidence, but it
also writes only through the qualification rules above; the current
face-triggered persistent self-switch is removed.

### Legacy records

Legacy `capture_mode.*` entries do not carry enough context to authorize
concurrent capture. They remain readable for migration diagnostics but are not
treated as a v2 concurrent qualification.

A legacy sequential entry is safe in direction but still unqualified. The
resolver's default is already sequential, so ignoring it does not make capture
more permissive. The next enrollment probe or explicit tune writes a v2 record.
No migration silently promotes a legacy entry.

### Operator reporting

`camera-tune`, `doctor`, and debug logs distinguish:

- qualified concurrent;
- measured sequential requirement and its evidence;
- unqualified because no measurement exists;
- stale because identity, tuple, backend, controller, port, speed, driver, or
  policy changed;
- inconclusive because rounds or scene evidence were insufficient;
- temporarily demoted by runtime health, including the concrete low-level
  reason.

Messages include the requested and accepted stream tuples and USB context.
They do not call an unknown cause “bandwidth.”

## Verification strategy

Implementation is test-first. Pure policy and serialization tests precede
hardware work.

Software regression covers at least:

- unknown, malformed, future-schema, incomplete, and mismatched records select
  sequential;
- only an exact identity, context, profile, backend, and policy match can
  select concurrent;
- duplicate or absent serials cannot collide across ports;
- driver-adjusted format or interval invalidates the candidate;
- explicit tune cannot store incomplete or dim-scene clean evidence;
- a conclusive sequential result is retained;
- legacy concurrent never authorizes concurrent;
- authentication still cannot invoke the multi-round probe;
- schedule selection is immutable within a lease;
- runtime low-level failure retries sequential and trips only process-local
  health;
- no-face and uncertain recognition results cannot persist a mode change;
- atomic replacement and compare-and-set preserve complete records under
  racing writers;
- full workspace tests, formatting, clippy, and capture stress pass.

Hardware validation runs the identical commit on this host, archhost,
thinkpad, and minihost. For each available RGB+IR pair it records descriptor
identity, exact requested/accepted tuples, driver, topology, controller, and
link speed; runs qualification; then stresses the selected production schedule
and its sequential fallback. RGB-only hardware must report that no pair can be
qualified without regressing RGB capture.

Where physical access permits, validation also covers same-port replug,
different-port or different-link attachment, competing USB load, and
suspend/resume. A stale concurrent record must never survive a context change.
A runtime load failure must complete the bounded sequential retry and must not
write a permanent downgrade. Hardware results are evidence for the tested
tuple and connection only, not a model-wide allowlist.

## Consequences

The common case remains automatic: first enrollment qualifies capable hardware
and later authentications use concurrent capture. Unknown or changed setups are
slower until requalified, but continue to work through sequential capture.

A user can move a camera to a constrained hub without silently reusing a
SuperSpeed concurrent result. Dynamic contention can still arise on an
unchanged topology, but it is contained within the current authentication by
runtime validation and sequential retry.

The record and diagnostics are more complex than a boolean. That complexity is
the information required to make the decision honest. It also creates a clean
future seam for multiple production profiles, but no adaptive bandwidth search
is added without the evidence gate in issue #341.

## Primary sources

- Microsoft, [Windows Hello camera driver bring-up guide](https://learn.microsoft.com/en-us/windows-hardware/drivers/stream/windows-hello-camera-driver-bring-up-guide)
- Microsoft, [UVC camera implementation guide](https://learn.microsoft.com/en-us/windows-hardware/drivers/stream/uvc-camera-implementation-guide)
- Microsoft, [Camera Profile V2 developer specification](https://learn.microsoft.com/en-us/windows-hardware/drivers/stream/camera-profile-v2-specification)
- Microsoft, [Camera Profile V2 sensor-group generation](https://learn.microsoft.com/en-us/windows-hardware/drivers/stream/camera-profile-v2-sensor-group-generation)
- Microsoft, [Camera profiles](https://learn.microsoft.com/en-us/windows-hardware/drivers/stream/camera-profiles)
- Microsoft, [UVC extensions 1.5](https://learn.microsoft.com/en-us/windows-hardware/drivers/stream/uvc-extensions-1-5)
- Linux kernel, [`VIDIOC_G_FMT`, `VIDIOC_S_FMT`](https://docs.kernel.org/userspace-api/media/v4l/vidioc-g-fmt.html)
- Linux kernel, [`VIDIOC_G_PARM`, `VIDIOC_S_PARM`](https://docs.kernel.org/userspace-api/media/v4l/vidioc-g-parm.html)
- Linux kernel, [USB host-side API](https://docs.kernel.org/driver-api/usb/usb.html)
- Linux kernel, [uvcvideo stream negotiation and bandwidth selection](https://github.com/torvalds/linux/blob/master/drivers/media/usb/uvc/uvc_video.c)
- USB-IF, [USB Video Class 1.5 document set](https://www.usb.org/document-library/video-class-v15-document-set)


# ADR-0023: Per-camera-model profile layer (`cameras.d/`)

## Status

Proposed. Revised 2026-09-15 after an external design review; implementation
remains gated on Phase B per-field evidence. Implementation PRs cite this
ADR. Numbered after ADR-0022 (NPU inference, drafted on an unpushed branch);
independent of that ADR's acceptance.

## Context

Every camera-timing behavior that is not a stored schedule verdict is a
compiled fleet constant: the role startup flush (RGB 0 / IR 10), the
30-delta delivered-rate window and its floors (ADR-0014), the amortization
bounds (ADR-0021), and the interval negotiated after format. Cameras differ
measurably (BRIO IR ~30 fps while fleet-floor hosts sit at ~15 fps; the
NexiGo N930W clamps a requested 640x400 IR format to 640x360 and shows
in-window delivery gaps). Sequential-latency attribution showed per-stream
machinery dominates authentication time, and contributors with unsupported
cameras have no way to ship tuning.

The persisted capture-schedule authority is qualification-v2 (ADR-0007,
Accepted and implemented): context-bound records under
`state_dir()/capture-qualifications`, keyed by the exact endpoint identity,
connection context, and requested/accepted stream contracts, with schema,
policy, and measurement-engine versions and a runtime-degradation layer.
Legacy `cameras.conf` `capture_mode.*` keys remain for migration diagnostics
only and authorize nothing. Irlume also has a stable per-camera identity
(`device_identity()`: sysfs vid:pid[:serial]).

Precedents: `alsa-ucm-conf` (repository as the per-device database,
contributed by PR, shipped as a data package), `libinput` quirks (shipped
data files with defined override precedence and diagnostic tooling).
`libcamera`'s code-per-sensor support is the rejected heavyweight contrast.

## Decision

### 1. `cameras.d/` at the repository root, shipped through the packages

One TOML file per camera model, named canonically `<vid>-<pid>.toml`; the
filename must equal the identity inside the file and duplicate identities
are rejected at load (with canonical names, ordering is irrelevant and there
is deliberately no match-ordering rule). Files install read-only to
`/usr/share/irlume/cameras.d/` in every package format and are the
contributor surface. Loading is startup-only in v1 (no hot reload); the
loader enforces file-size and numeric bounds, rejects path traversal, and
requires trusted installation ownership. An unsupported `schema_version` is
ignored as future data; a malformed file claiming a supported version is
skipped with a journal Warning and a doctor row (two different conditions,
reported differently).

### 2. Bounded v1 field set; everything else explicitly out of scope

v1 carries: `schema_version`; `identity` (vid, pid, model string, declared
tested scope); a REQUIRED `evidence` block for any latency-affecting field;
per-role `startup_flush` (bounded: never below the compiled fleet minimum;
only shippable with a demonstrated benefit or correctness need); and
`preferred_interval` (an exact rational preference; the driver's accepted
value and runtime delivered-rate evidence remain authoritative, because
V4L2 treats the interval as a request). Per-role delivered-rate
distributions live in `evidence`: a measurement is an observation, never an
instruction; evidence never satisfies admission requirements, seeds runtime
rate evidence, replaces observed timestamps, or authorizes amortization.

Out of scope for v1 (deferred until individually justified and fully
specified): torch/emitter control (the MS camera-control XU is present on
both fleet cameras, but no torch behavior has been validated; a future
contract must use only the documented Microsoft control, advertised
selectors, device-derived values, no raw writes, no emitter activation at
load, and existing restoration and consent behavior); configurable floors;
configurable amortization bounds.

### 3. Layer boundaries: profiles never manufacture authority

| Layer | What it may establish |
|---|---|
| Shipped model profile | A reviewed capture-setting preference for a declared device scope |
| Local capture qualification (ADR-0007) | Which schedules the measured pair and connection can safely use |
| Live runtime evidence | Whether this particular capture satisfies production requirements |

A shipped profile must never create, extend, or substitute a local
qualification, and a measurement made on one contributor's host is not
proof that every matching camera may use a schedule. ADR-0007's rule that
diagnostic overrides cannot disable format, rate, provenance, or fallback
gates carries forward unchanged.

### 4. Resolution is per domain, not one ladder

First resolve capture settings (authorized machine configuration, then
applicable shipped preferences, then compiled defaults; a privileged
authentication daemon takes no preferences from an authenticating user's
environment or request). Then resolve schedule eligibility through a
qualification matching those effective settings. Then enforce runtime
evidence regardless of where settings came from. Validation runs when
reading each source AND after composing the effective configuration
(individually valid fields may compose invalidly).

### 5. Evidence invalidation and policy snapshots

Changes to evidence-affecting effective capture settings invalidate
incompatible local qualifications and amortized rate evidence; compatibility
is determined from the effective capture contract and policy version, not
the profile filename. (Today's amortization key is node+role with a
completion timestamp and no policy fingerprint; adding capture-policy
dependence is part of this ADR's implementation.) One camera-operation
lease uses one immutable effective-policy snapshot: RGB and IR cannot run
different policy versions within one capture. Persistent qualifications
keep their compatibility checks across package updates and daemon restarts.

### 6. Fallback semantics

Profiles are optional capture preferences. Their absence, rejection, or
incompatibility does not bypass any required runtime gate, and they can
never be the sole mechanism enforcing an authentication-safety requirement
(ADR-0019's availability/refusal separation holds: a dropped profile may
cost performance, never safety). Unknown cameras keep today's behavior
exactly.

### 7. Tighten-only, and honest claims about benefit

Within a field, a profile may only tighten relative to compiled defaults
(e.g. a longer flush), and tighten-only is not treated as a complete safety
proof for physical capture settings: runtime negotiation and delivered
evidence checks remain necessary and authoritative. Because v1 forbids
flushes below the fleet minimum and defers floors and amortization knobs,
this ADR does NOT claim shortened startup flushes as an available
optimization. Any shipped field must name its measured mechanism (better
interval selection, fewer failed starts or retries, or another Phase
B-demonstrated effect); "one worthwhile field is a successful result".

### 8. Contributor workflow

`irlume camera-tune --emit-profile` (future) writes a candidate profile
from a real measurement: deterministic serialization (serializing the same
completed measurement record is byte-for-byte identical; re-measurement
creates a new record), recording tool revision, measurement-policy version,
effective baseline and candidate settings, and a digest of the share-safe
evidence artifact (reusing the existing sanitization path; no serials,
usernames, private paths, or imagery). Emission and verification never
install settings and never touch another daemon instance. PRs add the file
plus a checklist; CI validates schema, bounds, identity/filename agreement,
and duplicate rejection without hardware; `doctor` reports effective values,
their sources, qualification applicability, and why any profile was ignored.

### 9. camera-tune as the measurement authority

- Same-math guarantee: production predicates only, no parallel
  reimplementation.
- Decomposition with defined stage semantics: whether timings are exclusive
  durations or nested spans is stated before any summation; transport
  stabilization and image-signal stabilization are measured and named
  separately, each with its signal criterion and timeout.
- Distributions: per-role delivered-rate evidence reports the lower tail
  (e.g. p05), maximum inter-frame gaps, continuity errors, and failed
  rounds, with the percentile basis (round-level rates vs frame intervals)
  defined. Wall-clock fill duration, actual delta count and timestamp span,
  and the production `meets_floor` result are reported as distinct facts; a
  stage timer must never silently become a delivered-fps measurement (the
  N930W session's 2,174 ms fill timer and the 15 fps / 97% tolerance floor
  are exactly the numbers that must stay distinct).
- Cold and warm, both reported: concurrent-versus-sequential comparisons
  report the first (cold) attempt and amortized later attempts with the
  actual cache-admission path recorded; "concurrent wins cold, sequential
  wins warm" is a legitimate result. Capability qualification stays
  separate from latency preference: healthy-but-slower is not unsafe.
- Equivalent outcomes: only comparable workloads count; successful
  completions are reported separately from refusals, timeouts, and retries
  (no-face identify timings are diagnostics, not authentication
  benchmarks). Phase B uses paired or interleaved arms with the effective
  settings recorded on both. An unstable baseline is preserved as evidence,
  never discarded for being unstable; weak candidates are refused.
- Exclusivity: the camera-operation reservation covers the whole
  experiment, both streams and shared controls; broker-enforced ownership
  is distinguished from best-effort holder observation, and the tool
  refuses authoritative emission when it cannot establish the required
  exclusivity.
- Calibration: emitted numbers validated against the production daemon's
  instrumentation on the same host and session before any profile ships.

## Consequences

- Positive: per-camera wins backed by named mechanisms; a contributor
  surface needing no code; data-only profile fixes riding package updates;
  doctor debuggability.
- Costs: schema/loader work with per-domain validation and policy
  fingerprints; the camera-tune enhancement above; review burden mitigated
  by checklist and CI.
- Acceptance-test groups (CI can prove profiles cannot enter the runtime
  through an unintended path; it cannot prove latency wins):
  unknown/absent/malformed/incompatible profiles preserve baseline
  behavior; no configuration source bypasses hard limits and invalid
  combinations are rejected; evidence-affecting changes cannot reuse
  incompatible qualifications or warm-rate evidence; driver clamping,
  replug, control interference, and pending claims cannot produce
  authoritative weak evidence; measurement comparisons never skip
  applicable PAD, identity, continuity, or deadline requirements.
- Alternatives considered: compile-time tables (update coupling);
  systemd-hwdb (udev machinery for a small table); code-level per-camera
  modules (contributor cost); runtime crowd telemetry (rejected: privacy).
  The highest-value near-term work is the calibrated camera-tune
  measurement path, not a loader full of speculative knobs.

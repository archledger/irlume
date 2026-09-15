# ADR-0023: Per-camera-model profile layer (`cameras.d/`)

## Status

Proposed. Design accepted by the maintainer 2026-09-15; implementation is
gated on Phase B per-field evidence (below). Implementation PRs cite this
ADR. Numbered after ADR-0022 (NPU inference, drafted on an unpushed branch);
independent of that ADR's acceptance.

## Context

Every camera-timing behavior that is not the stored `capture_mode` verdict
is a compiled fleet constant: the role startup flush (RGB 0 / IR 10), the
30-delta delivered-rate window and its floors (ADR-0014), the amortization
bounds (ADR-0021), and the interval negotiated after format
(`negotiate_interval_after_format`). Cameras differ measurably: BRIO IR
delivers ~30 fps while fleet-floor hosts sit at ~15 fps, and exposure settle
behavior differs per model. The sequential-latency attribution showed the
per-stream machinery (open, negotiate, flush, rate window paid serially per
stream) dominates authentication time; per-camera tuning of that
machinery is impossible today without code changes.

Irlume already has a stable per-camera identity (`device_identity()`:
sysfs vid:pid[:serial]) and exactly one per-camera persisted tuning
(`cameras.conf` `capture_mode.<rgb>+<ir>` plus its origin sidcar, measured
verdicts outranking inference). Contributors with unsupported cameras have
no way to ship tuning.

Precedents studied: `alsa-ucm-conf` (the Git repository is the per-device
database; contributors add devices by PR; shipped as a data package),
`libinput` quirks (shipped plaintext data files matched on device
attributes with defined local-override precedence), `systemd-hwdb`
(modalias-matched, udev-integrated; overkill here), and `libcamera`
(code-level per-sensor support; rejected as far too costly for
contributors). `howdy`'s single flat config is the gap this layer fills.

## Decision

1. A `cameras.d/` directory at the repository root carries one profile per
   camera model, named `<vid>-<pid>.toml` (for example `046d-085e.toml`,
   `3443-c803.toml`). The directory is both the contributor surface and the
   shipped artifact, installed read-only to `/usr/share/irlume/cameras.d/`
   in every package format (pacman, deb, rpm).
2. The schema is versioned (`schema_version`) and bounded to fields irlume
   can act on: `identity`, a REQUIRED `evidence` block for any
   latency-affecting field, and a tune-only `capture` set (per-role
   `startup_flush`, `preferred_interval`, per-role `measured_fps`) plus an
   MS-XU-gated `torch` mode. An `unknown keys` parse rejects the file; a
   daemon older than the file's `schema_version` ignores it.
3. The loader validates tighten-only semantics: a profile may raise floors,
   lengthen flushes, or shrink amortization bounds, and may never weaken an
   ADR-0014/0019/0021 invariant. Violations reject at load. A rejected or
   malformed profile is skipped with a journal Warning and a doctor row, and
   behavior falls back to compiled defaults (fail-closed, never fail-open).
   Matching is by vid:pid through the existing identity function, first
   match in sorted filename order, no globs.
4. Precedence, highest first: user configuration; stored measured verdicts
   (`capture_mode` and sidcar); shipped model profile; compiled defaults.
   An unknown camera keeps today's behavior exactly. Profiles carry no
   auth-trust fields and never influence role classification or who is
   authorized; they tune capture only.
5. Contributors add support by running `irlume camera-tune --emit-profile`
   (new flag, below), committing the generated file to `cameras.d/`, and
   opening a PR against a checklist. CI validates schema, tighten-only
   bounds, and parseability of the whole shipped set without hardware.
   `doctor` reports the active profile per camera.
6. Per-field Phase B gating: a latency-affecting field ships only after
   attended, measured evidence on fleet hardware shows a real benefit (or a
   correctness need) for that field. Fields do not ship on hypothesis. A
   field with no measured win is dropped from schema v1.

### camera-tune as the measurement authority

Because `camera-tune` becomes the sole generator of profile evidence, its
accuracy contract is part of this decision:

- Same-math guarantee: emitted values derive from the production predicates
  (the exact `meets_floor` arithmetic, flush accounting, and interval
  negotiation the daemon uses), never a parallel reimplementation.
- Decomposition: per-stage timing (open, negotiate, first frame, exposure
  settle, flush, floor window) per stream role, not one wall-clock number.
- Distribution reporting: delivered fps reported as a distribution (min,
  p50, p95 over N configurable rounds) with minimum-round and
  variance-threshold refusals, extending camera-tune's existing
  refuse-weak-evidence behavior (for example the lit-room refusal).
  Measured motivation: the NexiGo N930W's IR window fills in 2172-2176 ms
  (effective ~13.8 fps delivered against a nominal 30 fps, worst observed
  in-window gap ~625 ms) while presenting as a healthy 30 fps camera
  otherwise; a single point estimate would have hidden it.
- Both baselines: a concurrent-versus-sequential verdict must be computed
  against the amortized-sequential path (ADR-0021 evidence reuse in force),
  not only the unamortized sequential fill. Measured motivation: the
  N930W's tune advertises a 5.7-6.3 s concurrent saving over unamortized
  sequential, but amortized-sequential identify wall time beat the
  concurrent path in practice on the same host; a verdict that ignores
  amortization can pick the slower mode (2026-09-15 archhost session,
  evidence in the issue 719 investigation).
- Isolation: emission is refused while other holders or pending claims
  exist on the device, while identity is unstable, or when access is not
  exclusive to the probe.
- Honest provenance: the evidence block records tool version, date, method,
  rounds, and environment-check results; emitted files are deterministic
  byte-for-byte so reviews see exactly what the tool measured.
- Verification: `--verify-profile` re-measures a shipped profile on hand
  hardware and reports drift, for maintainers and for contributors updating
  profiles.
- Calibration: Phase B validates camera-tune's emitted numbers against the
  production daemon's own timing instrumentation on the same host and
  session before any profile ships.

## Consequences

- Positive: per-camera latency wins backed by evidence; a contributor
  surface that needs no code; data-only profile fixes that ride package
  updates without binary rebuilds; support debuggability through doctor.
- Costs: schema and loader work with tighten-only validation; the
  camera-tune enhancement above; one install line per package spec; review
  burden for profile PRs mitigated by the checklist and CI validation.
- Risks: bad shipped data (mitigated by required evidence, tighten-only
  bounds, user override precedence, doctor visibility, unchanged
  unknown-camera behavior); schema drift (schema_version gate plus CI parse
  of the shipped set on every bump); packaging drift (single source folder,
  one install line each).
- Alternatives considered: compile-time tables (update coupling, no data-only
  fixes); systemd-hwdb integration (udev machinery for a small table);
  code-level per-camera modules as libcamera does (contributor cost);
  runtime crowd-sourced telemetry (rejected: privacy, and irlume carries no
  telemetry).

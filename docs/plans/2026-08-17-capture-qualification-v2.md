# Capture qualification v2 implementation plan

Goal: make concurrent RGB+IR capture an exact, measured optimization while
preserving sequential capture as the reliable fallback for unknown, changed,
or dynamically constrained hardware.

Architecture: ADR 0007. Work is split so every production change follows an
observed failing test and every slice leaves the workspace buildable.

## 1. Introduce the strict qualification domain model

Files:

- Add `crates/irlume-camera/src/capture_qualification.rs`.
- Modify `crates/irlume-camera/src/lib.rs` to declare and re-export the module's
  public reporting and resolver types.

Tests first:

- schema v2 round-trips a complete concurrent and sequential qualification;
- zero intervals, invalid fourcc, empty descriptors, mixed roles, incomplete
  authoritative evidence, and inconsistent outcomes are rejected;
- unknown schema, malformed JSON, and records over the size limit are rejected;
- exact matching accepts every required field and one-field mutations fail;
- a last inconclusive attempt cannot become an authoritative concurrent result.

Implementation:

- Define bounded serde records for camera identity, connection context, exact
  stream contracts, arm summaries, attempt outcome, authoritative
  qualification, and record revision.
- Use required fields for every authorization-relevant value. Unknown future
  schema versions fail closed.
- Keep constructors validating invariants; do not let callers assemble an
  authoritative record with public fields.

Verification:

- `cargo test -p irlume-camera capture_qualification --locked`

## 2. Bind identity and connection facts to opened fds

Files:

- Modify `crates/irlume-camera/src/uvc_descriptor.rs`.
- Modify `crates/irlume-camera/src/lib.rs`.
- Extend tests beside the existing fd identity and negotiated-format tests.

Tests first:

- sysfs parsing records descriptor digest, VID/PID, interface, serial, canonical
  device path, host-controller path, speed, and driver;
- missing or malformed speed/driver/controller evidence fails qualification
  collection instead of filling a permissive default;
- busnum/devnum never enter the persistent identity;
- two serial-less devices on different ports produce different filing keys;
- exact RGB and IR contracts contain the requested and driver-accepted format
  and reduced frame intervals.

Implementation:

- Add a read-only fd-derived qualification identity/context collector reusing
  `identity_from_fd` and descriptor hashing.
- Add private camera methods that snapshot the exact negotiated stream contract
  from the immutable `RgbCamera`/`IrCamera` fields.
- Add a stable pair filing key using length-prefixed, hashed identity parts.

Verification:

- focused camera tests and `cargo test -p irlume-camera --lib --locked`.

## 3. Add one atomic qualification store

Files:

- Modify `crates/irlume-camera/src/capture_qualification.rs`.
- Reuse `irlume_common::write_atomic_reporting` and directory durability
  helpers; do not add a parallel atomic-write implementation.

Tests first:

- absent store is unqualified;
- a complete write reloads byte-for-byte equivalent state at mode 0600;
- replacement never leaves a temporary file;
- a malformed or oversized live record is reported and selects sequential;
- compare-and-set refuses a stale expected revision;
- an automatic write cannot overwrite a newer explicit measurement;
- an inconclusive attempt updates diagnostics without replacing a still-valid
  authoritative qualification;
- duplicate pair writers serialize on one stable lock inode.

Implementation:

- Store under `state_dir()/capture-qualifications/<pair-key>.json` with a
  permanent sibling `.lock`.
- Bound input before deserialization.
- Lock, reread, compare revision, serialize, and atomically publish one JSON
  object. Treat visible-not-durable distinctly in the returned result.
- Provide read/resolve APIs that preserve the reason for sequential fallback.

Verification:

- focused store tests, diff check, and camera crate tests.

## 4. Make the contention probe produce qualification evidence

Files:

- Modify `crates/irlume-camera/src/lib.rs` contention-probe structures and held
  sessions.
- Modify `crates/irlume-daemon/src/main.rs` probe policy.

Tests first:

- a complete held concurrent arm carries identical exact contracts across all
  rounds and delivered-rate evidence meeting both floors;
- contract drift, rate shortfall, discontinuity/recovery, decode error, or
  incomplete rounds is inconclusive and cannot qualify concurrent;
- a fully failed concurrent arm plus healthy trailing sequential control can
  authoritatively require sequential;
- explicit `camera-tune` no longer stores incomplete or dim-scene clean data;
- enrollment compare-and-set cannot replace a tune that lands while probing.

Implementation:

- Extend probe samples with exact contract and health summaries captured from
  the actual held production sessions.
- Apply one conclusive-evidence policy to both tune and enrollment.
- Persist a v2 attempt and, only when conclusive, its authoritative outcome.
- Keep latency descriptive and retain the existing signal threshold.

Verification:

- focused camera and daemon tests; run the no-hardware probe policy suite.

## 5. Replace boolean legacy resolution with an operation decision

Files:

- Modify `crates/irlume-auth/src/lib.rs`.
- Modify `crates/irlume-camera/src/capture_qualification.rs`.
- Modify daemon and CLI reporting call sites as required.

Tests first:

- no v2 record, legacy concurrent, stale context, stale tuple, future policy,
  and unreadable store all resolve sequential;
- exact concurrent qualification resolves concurrent;
- exact sequential qualification resolves sequential with its measured reason;
- environment override can request an initial schedule but cannot turn off
  stream-contract gates;
- one operation snapshots one decision even if the record changes concurrently.

Implementation:

- Introduce `CaptureScheduleDecision` with schedule, source, qualification key,
  and diagnostic reason.
- Resolve against the current read-only context at operation start and
  revalidate against opened fds and accepted contracts before accepting a
  concurrent frame.
- Stop consulting legacy entries as concurrent authority. Keep them visible to
  diagnostics until a v2 measurement replaces them.

Verification:

- auth decision tests, auth integration tests, and CLI/daemon unit tests.

## 6. Add bounded runtime fallback and a process-local circuit breaker

Files:

- Modify `crates/irlume-auth/src/lib.rs` capture orchestration.
- Add a small private runtime-health module only if it makes state ownership
  clearer than keeping it beside the operation resolver.

Tests first:

- concurrent open/arm failure retries the same operation sequentially once;
- accepted-contract mismatch, rate shortfall, and invalid provenance reject the
  concurrent frames, retry sequentially, and trip current-generation health;
- a successful sequential retry continues authentication;
- no-face, uncertain, and ordinary recognition failure do not trip low-level
  health and never persist mode;
- three A/B-confirmed signal-loss observations may trip process-local health,
  while clean evidence resets and inconclusive evidence does not advance it;
- breaker state is scoped by exact pair plus camera generation and resets on a
  new generation;
- environment-forced concurrent remains subject to bounded safety fallback;
- the multi-round probe remains unreachable from authentication.

Implementation:

- Snapshot the schedule per operation.
- Convert supported concurrent capture failures into typed health reasons.
- Retry sequentially within the existing bounded capture budget.
- Keep demotion in memory only and expose a diagnostic snapshot.
- Remove the current enrollment path that writes a persistent sequential mode
  from face-triggered self-healing.

Verification:

- auth focused tests, `no_probe_on_the_auth_path`, and capture stress tests.

## 7. Update operator surfaces and legacy migration reporting

Files:

- Modify `crates/irlume-cli/src/main.rs`, command help, daemon responses, and
  relevant docs.

Tests first:

- doctor distinguishes qualified, measured sequential, unqualified, stale,
  inconclusive, and runtime-demoted states;
- output includes exact stream tuples and USB speed/topology without claiming
  an unknown failure is bandwidth;
- `camera-tune` clearly says when an inconclusive attempt was not stored as
  authority;
- RGB-only machines report no pair without warning about broken authentication.

Implementation:

- Replace legacy mode-only reporting with v2 qualification status.
- Retain compatible parsing of legacy files for diagnostics only.
- Document requalification after a port, link, format, driver, or backend
  change.

Verification:

- CLI and daemon unit suites, command snapshots, and docs diff check.

## 8. Software regression and review

Commands:

- `cargo fmt --all -- --check`
- `cargo clippy --workspace --all-targets --all-features --locked -- -D warnings`
- `cargo test --workspace --locked`
- focused no-probe and capture stress commands documented by the repository.
- `git diff --check`

Review:

- compare the completed diff to ADR 0007;
- audit every permissive default, persistent identity field, and hardware write;
- confirm no test-only model fixture or hardware artifact is committed.

## 9. Four-host hardware matrix

Run the identical reviewed commit on this host, archhost, thinkpad, and
minihost. Record command, commit, kernel, driver, descriptor digest, interfaces,
requested/accepted tuples, controller/topology, link speed, and all outcomes.

For RGB+IR pairs:

- qualify in a conclusive scene;
- stress the selected production schedule;
- force and stress sequential fallback;
- verify same-port replug behavior;
- where physically possible, move between USB paths/link speeds and prove a
  stale concurrent qualification is refused;
- introduce competing USB load where a safe existing test mechanism exists;
- verify a runtime concurrent failure completes the bounded sequential retry
  and writes no permanent downgrade;
- exercise suspend/resume when safe.

For RGB-only hosts:

- verify inventory and RGB capture remain healthy;
- verify qualification reports no RGB+IR pair and makes no emitter write.

Do not issue speculative emitter payloads. Use only descriptor-authorized,
known-safe emitter profiles already accepted by irlume.

## 10. Integration and PR disposition

- Commit each coherent green slice.
- Push the branch only after the complete software review and hardware evidence
  are recorded.
- Update or open the implementation PR with the evidence matrix and remaining
  limitations.
- Re-evaluate PRs #484, #485, and #489 against the actual merged base and this
  design; close only work that is conclusively superseded, with an explanatory
  comment and a link to its replacement.


# Privileged Diagnostic Trace Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add a root-authorized, bounded `irlume trace` JSONL recorder and an offline `irlume trace explain` timeline without persistent debug settings or any impact on authentication/camera execution.

**Architecture:** Build on the share-safe event schema and `SecureArtifact` delivered by the support-report plan. `irlumed` owns one bounded non-blocking subscriber and daemon-generated operation IDs; lower layers emit typed share-safe or trace-only events through a sink that can always drop. The CLI streams daemon-authored JSONL into one partial artifact and publishes it only after a clean terminal record; `trace explain` parses the bounded file offline.

**Tech Stack:** Rust 1.88, serde/serde_json JSONL, bounded `sync_channel` with `try_send`, Unix sockets with `SO_PEERCRED`, monotonic and UTC clocks, SHA-256 context tokens, Linux secure artifact publication.

**Spec:** `docs/adr/0008-privacy-bounded-diagnostics.md`

## Global Constraints

- This plan starts only after `docs/superpowers/plans/2026-08-17-support-report.md` is implemented and merged.
- Recording requires a root peer proven by `SO_PEERCRED`; one subscriber maximum.
- Default duration is 60 seconds; maximums are five minutes, 50,000 events, and 16 MiB.
- Event emission must never block authentication, capture, qualification, emitter restoration, or fallback.
- The daemon, not the client, generates operation IDs.
- Frames, crops, landmarks, embeddings, credentials, template/recovery material, usernames, profile names, and raw emitter payloads remain forbidden even in root traces.
- Exact match/liveness measurements are trace-only and never project into the share-safe ring/report.
- A clean terminal event is required before the `.partial` file may become the final `.jsonl` file.
- `irlume logs debug on|off` remains compatible in this change.

---

### Task 1: Define trace-only events and a bounded parser

**Files:**
- Modify: `crates/irlume-common/src/diagnostics.rs`
- Test: `crates/irlume-common/src/diagnostics.rs`

**Interfaces:**
- Consumes: `OperationId`, `OperationClass`, and `ShareSafeEventKind` from the support-report foundation.
- Produces: `TraceRecord`, `TraceEventKind`, `TraceMeasurement`, `TraceParseError`.
- Produces: `parse_trace<R: BufRead>(reader: R, limits: TraceLimits) -> Result<ParsedTrace, TraceParseError>`.

- [ ] **Step 1: Write failing schema, privacy, and parser tests**

```rust
#[test]
fn trace_schema_allows_measurements_but_forbids_biometric_payloads() {
    let value = serde_json::to_value(TraceRecord::fixture_liveness()).unwrap();
    assert!(value.pointer("/event/measurements/0/value").is_some());
    for forbidden in ["username", "profile", "frame", "crop", "landmarks", "embedding", "credential", "emitter_payload"] {
        assert!(find_key(&value, forbidden).is_none(), "forbidden trace key {forbidden}");
    }
}

#[test]
fn parser_rejects_gaps_duplicate_terminal_and_oversize() {
    assert!(matches!(parse_fixture("gap.jsonl"), Err(TraceParseError::Sequence { .. })));
    assert!(matches!(parse_fixture("two-terminal.jsonl"), Err(TraceParseError::Terminal { .. })));
    assert!(matches!(parse_fixture("oversize.jsonl"), Err(TraceParseError::Limit { .. })));
}
```

- [ ] **Step 2: Run and verify RED**

Run: `cargo test -p irlume-common --locked trace`

Expected: FAIL because trace types/parser do not exist.

- [ ] **Step 3: Implement versioned records and parser**

Use one complete JSON object per line:

```rust
pub struct TraceRecord {
    pub trace_schema: u32,
    pub sequence: u64,
    pub monotonic_us: u64,
    pub utc_unix_ms: u64,
    pub operation_id: OperationId,
    pub operation: OperationClass,
    pub event: TraceEventKind,
    pub terminal: bool,
}
```

`TraceEventKind` has typed variants for a fixed `TraceStarted` privacy/oracle
warning and applied limits, shared transitions, stream contracts,
delivered-rate/continuity/drop evidence, ActiveIr provenance, emitter outcome,
stage timing, detector count, liveness measurements, match measurements,
`EventsDropped { count }`, and final categorical outcome. Store metric names in
an enum, not free-form strings. Parser limits bytes, lines, per-line length,
schema version, monotonically contiguous sequence, exactly one final terminal,
finite numeric values, and known enum variants.

- [ ] **Step 4: Run parser and common-crate tests**

Run: `cargo test -p irlume-common --locked trace`

Expected: PASS for valid, truncated, malformed, gap, dropped-event, and limit fixtures.

- [ ] **Step 5: Commit the trace schema**

```bash
git add crates/irlume-common/src/diagnostics.rs
git commit -m "feat(common): define bounded diagnostic trace records"
```

### Task 2: Add a one-subscriber non-blocking daemon trace hub

**Files:**
- Modify: `crates/irlume-daemon/src/diagnostics.rs`
- Modify: `crates/irlume-daemon/src/main.rs`
- Test: `crates/irlume-daemon/src/diagnostics.rs`
- Test: `crates/irlume-daemon/src/main.rs`

**Interfaces:**
- Produces: `TraceHub::subscribe(peer_uid: u32, limits: TraceLimits) -> Result<TraceSubscription, TraceBusy>`.
- Produces: `TraceHub::emit(operation: &OperationScope, event: TraceEventKind)` using only `try_send`.
- Produces: `Request::TraceSubscribe { duration_ms: u64 }` special streaming connection.
- Consumes: trace schema from Task 1 and existing peer credentials.

- [ ] **Step 1: Write failing concurrency and non-blocking tests**

```rust
#[test]
fn a_slow_subscriber_never_blocks_emitters_and_gets_a_drop_record() {
    let hub = TraceHub::with_capacity(2);
    let subscription = hub.subscribe(0, TraceLimits::fixture()).unwrap();
    let start = Instant::now();
    for _ in 0..10_000 { hub.emit(&scope(), TraceEventKind::fixture_stage()); }
    assert!(start.elapsed() < Duration::from_millis(50));
    assert!(subscription.collect().iter().any(|r| matches!(r.event, TraceEventKind::EventsDropped { .. })));
}

#[test]
fn only_root_and_only_one_subscriber_are_allowed() {
    let hub = TraceHub::default();
    assert!(matches!(hub.subscribe(1000, limits()), Err(TraceSubscribeError::NotAuthorized)));
    let _first = hub.subscribe(0, limits()).unwrap();
    assert!(matches!(hub.subscribe(0, limits()), Err(TraceSubscribeError::Busy)));
}
```

- [ ] **Step 2: Run and verify RED**

Run: `cargo test -p irlume-daemon --locked trace`

Expected: FAIL because the hub/streaming request do not exist.

- [ ] **Step 3: Implement bounded subscription state**

Keep one `Weak` subscriber registration behind a short-lived mutex. Use `sync_channel` plus `try_send`; accumulate drop count atomically when full and synthesize `EventsDropped` before the next successfully queued event. Sequence assignment belongs to the hub and occurs only for records actually emitted, including the drop marker. Deadline, event count, client disconnect, and daemon shutdown each generate one categorical terminal when the socket is still writable.

Special-case `TraceSubscribe` in `serve` after `peer_cred` and request parsing but before arbiter submission. Root-gate it there, send a typed header/accepted record, then drain the subscription with a bounded write timeout. Never put a streaming socket on the camera worker.

- [ ] **Step 4: Run daemon socket and load tests**

Run: `cargo test -p irlume-daemon --locked`

Expected: PASS; a disconnected trace client frees the singleton and cannot cancel unrelated camera work.

- [ ] **Step 5: Commit the trace hub**

```bash
git add crates/irlume-daemon/src/diagnostics.rs crates/irlume-daemon/src/main.rs
git commit -m "feat(daemon): stream one bounded nonblocking trace"
```

### Task 3: Propagate daemon-generated operation context across work

**Files:**
- Modify: `crates/irlume-daemon/src/main.rs`
- Modify: `crates/irlume-daemon/src/arbiter.rs`
- Modify: `crates/irlume-common/src/diagnostics.rs`
- Test: `crates/irlume-daemon/src/main.rs`

**Interfaces:**
- Consumes: `OperationScope` introduced by the support-report plan.
- Produces: explicit scope propagation into worker dispatch, nested camera worker threads, and final response classification.
- Never consumes a client-supplied operation ID.

- [ ] **Step 1: Write failing end-to-end correlation tests**

Connect a trace subscriber, issue fixture requests from separate sockets, and assert each accepted request gets a different opaque ID while every phase for one request uses one ID. Send a JSON request containing unknown `operation_id` and assert serde ignores it and the daemon emits a different value.

- [ ] **Step 2: Run and verify RED**

Run: `cargo test -p irlume-daemon --locked trace_correlation`

Expected: FAIL because scopes are not carried through the queue/worker.

- [ ] **Step 3: Carry the scope explicitly**

Add `scope: OperationScope` to `Queued`. Create it only after request posture/classification. Pass `&scope` to `dispatch`; clone it into any scoped thread that emits. Finish at the one response boundary with a categorical outcome mapped from `Response`, never with response prose. Preserve the same scope across concurrent-to-sequential fallback and enrollment loops.

- [ ] **Step 4: Run daemon and auth lifecycle tests**

Run: `cargo test -p irlume-daemon -p irlume-auth --locked`

Expected: PASS with no user/profile string in trace records.

- [ ] **Step 5: Commit correlation propagation**

```bash
git add crates/irlume-daemon/src/main.rs crates/irlume-daemon/src/arbiter.rs crates/irlume-common/src/diagnostics.rs
git commit -m "feat(diagnostics): correlate daemon operation phases"
```

### Task 4: Instrument capture, emitter, liveness, and matching with typed trace-only facts

**Files:**
- Modify: `crates/irlume-camera/src/lib.rs`
- Modify: `crates/irlume-camera/src/ir_emitter.rs`
- Modify: `crates/irlume-auth/src/lib.rs`
- Modify: `crates/irlume-liveness/src/lib.rs`
- Test: corresponding crate-local unit tests.

**Interfaces:**
- Consumes: non-blocking `DiagnosticSink::emit_trace(TraceEventKind)`.
- Produces: exact stream/provenance, stage timing, gate, and match events specified by ADR 0008.
- Retains `dlog!` for human journal compatibility; never parses or forwards its prose.

- [ ] **Step 1: Write one mutation-resistant test per event family**

Use recording sinks to cover: negotiated request/echo tuple; delivered rate and floor; cumulative drops/continuity epoch; ActiveIr status; typed runtime violation; emitter applied/refused/restored without bytes; detector count; liveness metric plus threshold; match metric plus threshold; final category. Assert trace-only fields never appear in `ShareSafeEvent` serialization.

- [ ] **Step 2: Run and verify RED**

Run: `cargo test -p irlume-camera -p irlume-auth -p irlume-liveness --locked diagnostic_trace`

Expected: FAIL because the production seams emit no trace-only events.

- [ ] **Step 3: Emit at authoritative decision points**

Emit only after the underlying typed result exists: after driver negotiation, provenance validation, rate evaluation, emitter verification/restore, liveness verdict, and match comparison. Measurements use finite validated value objects. Never format enrollment/user/profile values into an event. A failed `try_send` is ignored after the hub accounts for loss.

- [ ] **Step 4: Prove trace backpressure cannot change outcomes**

Run each auth/capture fixture with a no-op sink, recording sink, and permanently-full sink; assert identical returned `Outcome`, fallback, emitter restore, and qualification persistence behavior.

- [ ] **Step 5: Run affected crate suites and commit**

Run: `cargo test -p irlume-camera -p irlume-auth -p irlume-liveness --locked`

```bash
git add crates/irlume-camera/src/lib.rs crates/irlume-camera/src/ir_emitter.rs crates/irlume-auth/src/lib.rs crates/irlume-liveness/src/lib.rs
git commit -m "feat(diagnostics): emit typed live pipeline trace events"
```

### Task 5: Record a trace securely from the CLI

**Files:**
- Create: `crates/irlume-cli/src/trace.rs`
- Modify: `crates/irlume-cli/src/main.rs`
- Modify: `crates/irlume-cli/src/commands.rs`
- Test: `crates/irlume-cli/src/trace.rs`
- Test: `crates/irlume-cli/tests/cli.rs`

**Interfaces:**
- Produces: `trace::run(args: &[String]) -> ExitCode`.
- Consumes: daemon `TraceSubscribe`, `SecureArtifact`, trace parser types.
- Defaults: 60 seconds; cap: 300 seconds, 50,000 records, 16 MiB.

- [ ] **Step 1: Write failing CLI/root/publication tests**

Cover non-root refusal before file creation, duration parsing/cap, existing final path refusal, one active trace busy response, successful terminal publication, disconnect/truncation partial retention, and privacy warning.

```rust
#[test]
fn trace_without_terminal_keeps_partial_and_never_publishes_final() {
    let final_path = temp.path().join("capture.jsonl");
    fixture_daemon().close_after_records(3);
    cmd().args(["trace", "--output", final_path.to_str().unwrap()])
        .assert().failure();
    assert!(!final_path.exists());
    assert_eq!(partials(temp.path()).len(), 1);
}
```

- [ ] **Step 2: Run and verify RED**

Run: `cargo test -p irlume-cli --locked trace`

Expected: FAIL because `trace` is not routed.

- [ ] **Step 3: Implement streaming recording**

Default to `./irlume-trace-YYYYMMDD-HHMMSS.jsonl`. Print the oracle/privacy warning before connecting. Create the partial only after local root check and argument validation; the daemon remains the authority. Read one bounded line at a time, validate schema/sequence incrementally, write through `SecureArtifact`, and commit only after one valid terminal line. On SIGINT, close the socket and leave the partial with a recovery message.

- [ ] **Step 4: Run CLI trace tests**

Run: `cargo test -p irlume-cli --locked trace`

Expected: PASS; final files are 0600 and never replace existing paths.

- [ ] **Step 5: Commit recording**

```bash
git add crates/irlume-cli/src/trace.rs crates/irlume-cli/src/main.rs crates/irlume-cli/src/commands.rs crates/irlume-cli/tests/cli.rs
git commit -m "feat(cli): record bounded privileged diagnostic traces"
```

### Task 6: Explain traces offline without trusting prose

**Files:**
- Modify: `crates/irlume-cli/src/trace.rs`
- Test: `crates/irlume-cli/src/trace.rs`
- Test fixtures: `crates/irlume-cli/tests/fixtures/traces/*.jsonl`

**Interfaces:**
- Produces: `irlume trace explain PATH [--output PATH]`.
- Consumes: bounded `parse_trace` from Task 1.
- Produces: deterministic human timeline grouped by daemon operation ID.

- [ ] **Step 1: Add valid, dropped, truncated, and hostile fixtures**

Include a hostile JSON string containing terminal escapes/markup in an unknown field; the parser must reject the unknown variant or render only enum-owned labels, never echo the string.

- [ ] **Step 2: Write failing explanation tests**

Assert ordering, operation grouping, duration, fallback explanation, explicit dropped-event count, terminal status, truncated refusal, and optional secure no-replace output publication.

- [ ] **Step 3: Run and verify RED**

Run: `cargo test -p irlume-cli --locked trace_explain`

Expected: FAIL because explain is absent.

- [ ] **Step 4: Implement enum-driven timeline rendering**

Render fixed labels from typed variants. Never print raw JSON or parser errors containing the input line. When no `--output` is supplied, write prose to stdout; with `--output`, publish a 0600 `.txt` through `SecureArtifact` and print only the resulting path.

- [ ] **Step 5: Run explain tests and commit**

Run: `cargo test -p irlume-cli --locked trace_explain`

```bash
git add crates/irlume-cli/src/trace.rs crates/irlume-cli/tests/fixtures/traces
git commit -m "feat(cli): explain diagnostic traces offline"
```

### Task 7: Document, stress, and physically validate non-interference

**Files:**
- Modify: `docs/COMMANDS.md`
- Modify: `docs/DEBUGGING.md`
- Modify: `docs/SECURITY_AT_REST.md`
- Modify: `docs/adr/0008-privacy-bounded-diagnostics.md`
- Create: `docs/validation/2026-08-17-diagnostic-trace.md`
- Modify: `scripts/timing-report.py`

**Interfaces:**
- Consumes: completed Tasks 1–6.
- Produces: operator guidance, compatibility note for `logs debug`, and four-device evidence.

- [ ] **Step 1: Update operator and security documentation**

Document root authorization, oracle warning, defaults/caps, partial recovery, offline explain, forbidden data, one-subscriber behavior, and the temporary continued availability of `logs debug on|off`. Change `scripts/timing-report.py` guidance to prefer `irlume trace`/`trace explain` while retaining parsing compatibility for old journal captures.

- [ ] **Step 2: Run the complete software gate**

Run:

```bash
cargo fmt --all -- --check
git diff --check
cargo test --workspace --locked
cargo clippy --workspace --all-targets --locked -- -D warnings
```

Expected: all commands exit 0.

- [ ] **Step 3: Run backpressure and disconnect stress**

Record with an intentionally slow test subscriber while issuing repeated auth/camera fixture operations; confirm bounded `events_dropped`, no worker latency regression beyond the measurement noise budget, clean subscriber replacement after disconnect, and no persistent environment/drop-in/service restart.

- [ ] **Step 4: Validate on the four-device matrix**

On this host, Archhost, ThinkPad, and Minihost at the identical commit, record a 60-second trace while exercising the selected capture schedule. On one dual-stream host force the already-supported concurrent schedule to observe bounded fallback. Confirm traces remain below caps, explain cleanly, contain no forbidden data, and authentication/enrollment results match an untraced control run.

- [ ] **Step 5: Record evidence and finish the ADR**

Write exact commit, device/context, traced/control timing, event/drop counts, fallback behavior, artifact modes/hashes, and disconnect result to `docs/validation/2026-08-17-diagnostic-trace.md`. Change ADR 0008 from `Accepted` to `Implemented` only when both this plan and the support-report plan are complete.

- [ ] **Step 6: Commit docs and evidence**

```bash
git add docs scripts/timing-report.py
git commit -m "docs: record privacy-bounded trace validation"
```

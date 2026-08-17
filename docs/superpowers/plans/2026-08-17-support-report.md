# Share-Safe Support Report Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add a privacy-bounded `irlume support-report` command that creates an inspectable, durable `.txt` report by default, offers a versioned JSON form, and performs camera activity only when the user explicitly requests `--probe`.

**Architecture:** `irlume-common` owns the share-safe wire schema and a reusable create-new artifact publisher. `irlumed` owns a bounded in-memory event ring and the optional camera probe. The CLI combines daemon facts with existing local doctor checks, renders either text or one machine document, and the TUI invokes only the read-only text form.

**Tech Stack:** Rust 1.88, serde/serde_json, SHA-256, Linux `renameat2(RENAME_NOREPLACE)`, Unix `SO_PEERCRED`, the existing irlume daemon socket and Ratatui TUI.

**Spec:** `docs/adr/0008-privacy-bounded-diagnostics.md`

## Global Constraints

- The default report must not open a camera, activate an emitter, change configuration, restart a service, or enable tracing.
- No frames, crops, landmarks, embeddings, credentials, template/recovery material, usernames, profile names, raw camera serials, raw device paths, or raw emitter payloads may enter the report schema.
- Report bodies are capped at 1 MiB; recent history is capped at 256 events and 30 minutes.
- Final artifacts are mode 0600 and must never replace an existing path.
- `--probe` is root-only, uses the daemon-owned camera operation and currently selected schedule, and may use only an already-authorized emitter configuration.
- Machine stdout is exactly one contract-1 JSON document; diagnostics go to stderr.
- Do not add a new dependency when libc, serde, serde_json, and sha2 already provide the required primitives.

---

### Task 1: Create-new secure artifact publisher

**Files:**
- Create: `crates/irlume-common/src/artifact.rs`
- Modify: `crates/irlume-common/src/lib.rs`
- Test: `crates/irlume-common/src/artifact.rs`

**Interfaces:**
- Produces: `SecureArtifact::create(final_path: &Path, limit: u64) -> io::Result<SecureArtifact>`
- Produces: `SecureArtifact::write_chunk(&mut self, bytes: &[u8]) -> io::Result<()>`
- Produces: `SecureArtifact::commit(self) -> io::Result<PublishedArtifact>`
- Produces: `PublishedArtifact { final_path: PathBuf, bytes: u64, durability_warning: Option<String> }`
- Consumes: existing `irlume_common::fsync_dir` and libc.

- [ ] **Step 1: Write failing artifact-lifetime tests**

Add tests covering all namespace and permission invariants:

```rust
#[test]
fn commit_publishes_one_0600_file_without_replacing() {
    let dir = sandbox("artifact-publish");
    let target = dir.join("report.txt");
    let mut first = SecureArtifact::create(&target, 32).unwrap();
    first.write_chunk(b"first").unwrap();
    first.commit().unwrap();
    assert_eq!(std::fs::read(&target).unwrap(), b"first");
    assert_eq!(std::fs::metadata(&target).unwrap().permissions().mode() & 0o777, 0o600);

    let mut second = SecureArtifact::create(&target, 32).unwrap();
    second.write_chunk(b"second").unwrap();
    assert_eq!(second.commit().unwrap_err().kind(), io::ErrorKind::AlreadyExists);
    assert_eq!(std::fs::read(&target).unwrap(), b"first");
}

#[test]
fn an_uncommitted_writer_leaves_only_a_named_partial() {
    let dir = sandbox("artifact-partial");
    let target = dir.join("trace.jsonl");
    let partial = {
        let mut artifact = SecureArtifact::create(&target, 32).unwrap();
        artifact.write_chunk(b"recoverable").unwrap();
        artifact.partial_path().to_owned()
    };
    assert!(!target.exists());
    assert_eq!(std::fs::read(partial).unwrap(), b"recoverable");
}

#[test]
fn byte_limit_is_enforced_before_the_extra_chunk_is_written() {
    let dir = sandbox("artifact-limit");
    let target = dir.join("report.txt");
    let mut artifact = SecureArtifact::create(&target, 5).unwrap();
    artifact.write_chunk(b"12345").unwrap();
    assert_eq!(artifact.write_chunk(b"6").unwrap_err().kind(), io::ErrorKind::FileTooLarge);
    assert_eq!(std::fs::read(artifact.partial_path()).unwrap(), b"12345");
}
```

- [ ] **Step 2: Run the tests and verify RED**

Run: `cargo test -p irlume-common --locked artifact`

Expected: FAIL because `artifact` and `SecureArtifact` do not exist.

- [ ] **Step 3: Implement secure partial creation and no-replace commit**

Create the partial beside the final path with `create_new(true)`, mode `0600`, `O_NOFOLLOW | O_CLOEXEC`, PID plus monotonic counter naming, and no stale-file adoption. Commit with:

```rust
let rc = unsafe {
    libc::syscall(
        libc::SYS_renameat2,
        libc::AT_FDCWD,
        partial_c.as_ptr(),
        libc::AT_FDCWD,
        final_c.as_ptr(),
        libc::RENAME_NOREPLACE,
    )
};
```

Sync the file before rename and the parent directory after rename. Map `EEXIST` to `AlreadyExists`. Keep the partial on any pre-commit failure and remove it after a failed rename only when the failure proves the final name was not published. Detect known network filesystem magic values with `fstatfs` and populate `durability_warning` without refusing the user-selected path.

- [ ] **Step 4: Run focused and common-crate tests**

Run: `cargo test -p irlume-common --locked artifact`

Expected: PASS, including unchanged-target, mode, partial, and size-bound tests.

- [ ] **Step 5: Commit the publisher**

```bash
git add crates/irlume-common/src/artifact.rs crates/irlume-common/src/lib.rs
git commit -m "feat(common): publish support artifacts without replacement"
```

### Task 2: Define the structurally share-safe diagnostic schema

**Files:**
- Create: `crates/irlume-common/src/diagnostics.rs`
- Modify: `crates/irlume-common/src/lib.rs`
- Test: `crates/irlume-common/src/diagnostics.rs`

**Interfaces:**
- Produces: `OperationId`, `ShareSafeEvent`, `ShareSafeEventKind`, `SupportSnapshot`, `SupportProbeResult`, `SupportUnavailable`, `SanitizedCameraContext`.
- Produces: `Request::SupportSnapshot { since_ms: u64 }` and `Request::SupportProbe { since_ms: u64 }`.
- Produces: `Response::SupportSnapshot(Box<SupportSnapshot>)` and `Response::SupportProbe(Box<SupportProbeResult>)`.
- Consumes: existing typed capture-mode resolution and camera qualification
  facts; it must never copy the raw `serde_json::Value` response into the
  support schema.

- [ ] **Step 1: Write schema and privacy mutation tests**

Use only bounded enums/value objects, never arbitrary log prose:

```rust
#[test]
fn share_safe_serialization_has_no_identity_or_biometric_fields() {
    let event = ShareSafeEvent::fixture_capture_fallback();
    let json = serde_json::to_value(event).unwrap();
    for forbidden in [
        "user", "username", "profile", "serial", "device_path", "frame",
        "embedding", "landmark", "score", "threshold", "credential", "payload",
    ] {
        assert!(json.get(forbidden).is_none(), "forbidden field: {forbidden}");
    }
}

#[test]
fn support_snapshot_round_trips_with_unknown_optional_sections() {
    let snapshot = SupportSnapshot::fixture();
    let bytes = serde_json::to_vec(&snapshot).unwrap();
    assert_eq!(serde_json::from_slice::<SupportSnapshot>(&bytes).unwrap(), snapshot);
}
```

Add a source-level contract test that enumerates public struct field names and rejects the forbidden list, so adding `raw_serial: Option<String>` fails even when a fixture leaves it `None`.

- [ ] **Step 2: Run and verify RED**

Run: `cargo test -p irlume-common --locked diagnostics`

Expected: FAIL because the types and request/response variants do not exist.

- [ ] **Step 3: Implement bounded DTOs and wire variants**

Use this shape as the stable seam:

```rust
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct ShareSafeEvent {
    pub sequence: u64,
    pub age_ms: u64,
    pub operation_id: OperationId,
    pub operation: OperationClass,
    pub kind: ShareSafeEventKind,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(tag = "event", rename_all = "snake_case")]
pub enum ShareSafeEventKind {
    LifecycleChanged { role: CameraRoleLabel, generation: u64 },
    CaptureScheduleSelected { schedule: CaptureSchedule, source: CaptureScheduleSource },
    CaptureFallback { reason: RuntimeViolationLabel },
    OperationFinished { outcome: CategoricalOutcome },
}
```

`SanitizedCameraContext` contains only VID:PID, role/interface number, driver,
negotiated link speed, controller and USB topology components, lifecycle
generation, `serial_present: bool`, truncated descriptor/qualification tokens,
and exact requested/accepted format-size-interval tuples. It contains no
`/dev` path and no raw serial. Use truncated digest tokens with a fixed
16-hex-character validator. Cap every vector and string during construction
and again during deserialization. Add `#[serde(default)]` only where old/new
daemon interoperability needs it.

- [ ] **Step 4: Run protocol and privacy tests**

Run: `cargo test -p irlume-common --locked diagnostics`

Expected: PASS with no arbitrary diagnostic prose or forbidden field in the DTO graph.

- [ ] **Step 5: Commit the schema**

```bash
git add crates/irlume-common/src/diagnostics.rs crates/irlume-common/src/lib.rs
git commit -m "feat(common): define share-safe diagnostic events"
```

### Task 3: Add the daemon-owned recent-event ring and operation correlation

**Files:**
- Create: `crates/irlume-daemon/src/diagnostics.rs`
- Modify: `crates/irlume-daemon/src/main.rs`
- Modify: `crates/irlume-daemon/src/arbiter.rs`
- Test: `crates/irlume-daemon/src/diagnostics.rs`
- Test: `crates/irlume-daemon/src/main.rs`

**Interfaces:**
- Consumes: `ShareSafeEvent` and request/response variants from Task 2.
- Produces: `DiagnosticState::begin(operation: OperationClass) -> OperationScope`.
- Produces: `OperationScope::emit(kind: ShareSafeEventKind)` and `OperationScope::finish(outcome: CategoricalOutcome)`.
- Produces: `DiagnosticState::snapshot(since: Duration) -> SupportSnapshot`.

- [ ] **Step 1: Write failing ring-bound and correlation tests**

```rust
#[test]
fn history_keeps_at_most_256_events_and_30_minutes() {
    let clock = FakeClock::at(1_000_000);
    let state = DiagnosticState::with_clock(clock.clone());
    for n in 0..300 { state.fixture_event(n); }
    assert_eq!(state.snapshot(Duration::from_secs(1800)).events.len(), 256);
    clock.advance(Duration::from_secs(1801));
    assert!(state.snapshot(Duration::from_secs(1800)).events.is_empty());
}

#[test]
fn daemon_generates_one_opaque_id_for_all_events_in_a_request() {
    let state = DiagnosticState::default();
    let op = state.begin(OperationClass::Authentication);
    op.emit(ShareSafeEventKind::fixture_selected());
    op.finish(CategoricalOutcome::Denied);
    let events = state.snapshot(Duration::from_secs(60)).events;
    assert_eq!(events[0].operation_id, events[1].operation_id);
    assert_ne!(events[0].operation_id, "caller-value");
}
```

- [ ] **Step 2: Run and verify RED**

Run: `cargo test -p irlume-daemon --locked diagnostics`

Expected: FAIL because the daemon state/scope do not exist.

- [ ] **Step 3: Implement the process-local state**

Store `VecDeque<TimedShareSafeEvent>` behind a poison-tolerant `Mutex`, a monotonic sequence counter, daemon-start monotonic origin, and an ID generator backed by `/dev/urandom` with a monotonic fallback that remains opaque. Prune on insert and snapshot. Add an `operation_id` field to `Queued`; create it only after `read_request`, `SO_PEERCRED` posture validation, and arbiter classification succeed.

Expose `SupportSnapshot` as `Class::Status` and `AnyPeer`; dispatch it from memory on the connection thread. Clamp `since_ms` to 30 minutes before reading the ring.

- [ ] **Step 4: Test authorization, status classification, and old-client compatibility**

Run: `cargo test -p irlume-daemon --locked`

Expected: PASS; snapshot requests never reach the camera worker and never depend on engine readiness.

- [ ] **Step 5: Commit daemon event ownership**

```bash
git add crates/irlume-daemon/src/diagnostics.rs crates/irlume-daemon/src/main.rs crates/irlume-daemon/src/arbiter.rs
git commit -m "feat(daemon): retain bounded share-safe diagnostic events"
```

### Task 4: Emit useful share-safe lifecycle and capture facts

**Files:**
- Modify: `crates/irlume-camera/src/backend.rs`
- Modify: `crates/irlume-camera/src/lib.rs`
- Modify: `crates/irlume-auth/src/lib.rs`
- Modify: `crates/irlume-daemon/src/main.rs`
- Test: `crates/irlume-auth/src/lib.rs`
- Test: `crates/irlume-daemon/src/main.rs`

**Interfaces:**
- Consumes: `OperationScope` from Task 3 through a small `DiagnosticSink` trait defined in `irlume-common::diagnostics`.
- Produces: schedule selection, qualification mismatch, runtime fallback, lifecycle generation, and categorical completion events.
- Must not consume or parse `dlog!` text.

- [ ] **Step 1: Write event-transition tests at existing decision seams**

Add a recording sink and assert typed transitions, not source strings:

```rust
#[test]
fn concurrent_contract_violation_records_fallback_without_measurements() {
    let sink = RecordingSink::default();
    concurrent_pair_requires_fallback_with_sink(
        Err(RuntimePairViolation::DeliveredRate),
        &sink,
    );
    assert_eq!(sink.share_safe(), vec![
        ShareSafeEventKind::CaptureFallback {
            reason: RuntimeViolationLabel::DeliveredRateShortfall,
        },
    ]);
    assert!(!serde_json::to_string(&sink.share_safe()).unwrap().contains("score"));
}
```

Cover generation changes, stored-authority mismatch, selected sequential/concurrent schedule, forced-concurrent safety demotion, and final granted/denied/error categories.

- [ ] **Step 2: Run and verify RED**

Run:

```bash
cargo test -p irlume-auth --locked capture_mode
cargo test -p irlume-daemon --locked diagnostics
```

Expected: FAIL because production decisions do not emit typed events.

- [ ] **Step 3: Thread a non-blocking sink through existing ownership seams**

Add a no-op default so library callers and tests do not need a daemon. The daemon installs the request's `OperationScope` while calling engine work; scoped camera worker threads receive a cloned sink explicitly. Emit after a decision is known and before returning it. Never hold the diagnostic ring mutex while holding a camera lease or emitter guard.

- [ ] **Step 4: Run auth, camera, and daemon regressions**

Run: `cargo test -p irlume-camera -p irlume-auth -p irlume-daemon --locked`

Expected: PASS with unchanged authentication/capture outcomes when the sink is absent or rejects an event.

- [ ] **Step 5: Commit typed production events**

```bash
git add crates/irlume-camera/src/backend.rs crates/irlume-camera/src/lib.rs crates/irlume-auth/src/lib.rs crates/irlume-daemon/src/main.rs
git commit -m "feat(diagnostics): emit share-safe camera transitions"
```

### Task 5: Implement the explicit bounded support probe

**Files:**
- Modify: `crates/irlume-auth/src/lib.rs`
- Modify: `crates/irlume-daemon/src/main.rs`
- Modify: `crates/irlume-daemon/src/arbiter.rs`
- Test: `crates/irlume-auth/src/lib.rs`
- Test: `crates/irlume-daemon/src/main.rs`

**Interfaces:**
- Produces: `Engine::support_probe(&mut self, scope: &dyn DiagnosticSink) -> Result<SupportProbeResult>`.
- Consumes: current capture qualification resolution, ordinary camera lease, known emitter configuration, and existing pair-wide safety fallback.
- Produces no enrollment, authentication, qualification write, or runtime-health reset.

- [ ] **Step 1: Write failing authority and side-effect tests**

Add tests that prove non-root is rejected before camera work, probe classification is `Class::Camera`, the selected schedule is used, a concurrent failure discards both sides and retries sequentially, and every persistence seam remains untouched:

```rust
#[test]
fn support_probe_cannot_publish_qualification_or_reset_health() {
    let stores = FixtureStores::default();
    let result = fixture_engine(&stores).support_probe(&RecordingSink::default()).unwrap();
    assert!(matches!(result.outcome, ProbeOutcome::Captured | ProbeOutcome::FallbackCaptured));
    assert_eq!(stores.qualification_writes(), 0);
    assert_eq!(stores.runtime_health_resets(), 0);
    assert_eq!(stores.enrollment_writes(), 0);
}
```

- [ ] **Step 2: Run and verify RED**

Run:

```bash
cargo test -p irlume-auth --locked support_probe
cargo test -p irlume-daemon --locked support_probe
```

Expected: FAIL because the probe path does not exist.

- [ ] **Step 3: Implement the minimal production-shaped capture**

Reuse the same `CaptureModeSelection`, `RuntimePairContract::validate_pair`, transactional pair arm, pair-wide fallback, and lease lifetime as authentication. Return only categorical capture/schedule/provenance results. Call `apply_known_ir_emitter`; never call discovery/setup. Add `SupportProbe` to the daemon's root-only posture and camera arbiter class.

- [ ] **Step 4: Run focused and workspace tests**

Run: `cargo test -p irlume-auth -p irlume-daemon --locked support_probe`

Expected: PASS, including explicit no-write assertions.

- [ ] **Step 5: Commit the probe**

```bash
git add crates/irlume-auth/src/lib.rs crates/irlume-daemon/src/main.rs crates/irlume-daemon/src/arbiter.rs
git commit -m "feat(diagnostics): add explicit bounded support probe"
```

### Task 6: Render text reports and publish the JSON machine form

**Files:**
- Create: `crates/irlume-cli/src/support_report.rs`
- Modify: `crates/irlume-cli/src/main.rs`
- Modify: `crates/irlume-cli/src/commands.rs`
- Modify: `crates/irlume-cli/src/machine.rs`
- Test: `crates/irlume-cli/src/support_report.rs`
- Test: `crates/irlume-cli/tests/cli.rs`
- Test: `crates/irlume-cli/tests/machine_api.rs`

**Interfaces:**
- Produces: `support_report::run(args: &[String]) -> ExitCode`.
- Produces: `support_report::collect(since: Duration, probe: bool) -> SupportReport`.
- Produces: `support_report::render_text(&SupportReport) -> Result<Vec<u8>, ReportTooLarge>`.
- Consumes: `doctor_run(Mode::Collect)`, daemon support response, `SecureArtifact`, SHA-256.

- [ ] **Step 1: Write CLI contract tests before dispatch exists**

Cover default filename, explicit output refusal, daemon-unavailable sections, privacy preamble, deterministic sections, body hash, probe warning/root gate, argument bounds, and JSON stdout:

```rust
#[test]
fn support_report_is_inspectable_private_and_integrity_marked() {
    let out = temp.path().join("report.txt");
    cmd().args(["support-report", "--output", out.to_str().unwrap()])
        .assert().success();
    let text = std::fs::read_to_string(&out).unwrap();
    assert!(text.starts_with("IRLUME SUPPORT REPORT\nPrivacy:"));
    assert!(text.contains("Unavailable sections"));
    assert!(text.contains("SHA-256 (body):"));
    assert_eq!(mode(&out), 0o600);
}

#[test]
fn arbitrary_doctor_detail_is_never_copied_into_the_report() {
    let report = collect_with_doctor_check(Check {
        id: "fixture",
        state: State::Warn,
        detail: Some("alice /dev/video9 Face Profile 1".into()),
    });
    let text = String::from_utf8(render_text(&report).unwrap()).unwrap();
    assert!(!text.contains("alice"));
    assert!(!text.contains("/dev/video9"));
    assert!(!text.contains("Face Profile 1"));
}

#[test]
fn support_report_json_is_one_document_and_creates_no_file() {
    let output = cmd().args(["support-report", "--json", "--contract", "1"])
        .output().unwrap();
    let doc: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(doc["command"], "support-report");
    assert_eq!(output.stdout.iter().filter(|&&b| b == b'\n').count(), 1);
}
```

- [ ] **Step 2: Run and verify RED**

Run: `cargo test -p irlume-cli --locked support_report`

Expected: FAIL because the command/module/capability do not exist.

- [ ] **Step 3: Implement collection and deterministic rendering**

Parse duration suffixes `s`, `m`, `h`, clamp to 30 minutes, and default to 10 minutes. Build the complete body in memory with a counting writer. Render fixed sections in this order: privacy preamble; report schema/version, UTC creation time, and effective privilege; platform/install/service checks; sanitized camera context; capture schedule/qualification; recent typed events; unavailable sections; privacy checklist. Hash those bytes, append only `SHA-256 (body): <hex>\n`, then publish.

The collector may reuse `doctor_run(Mode::Collect)` for stable check IDs and
states, but it must discard every arbitrary `Check.detail`. Add only an
explicit allowlist of check IDs plus separately collected typed OS, kernel,
installation-channel, and service-health values. `SupportReport` itself must
contain enums/value objects rather than copied prose, so the text and JSON
renderers share the same privacy boundary.

When no output is supplied, choose `irlume-support-YYYYMMDD-HHMMSS.txt` in the current directory. Do not retry with a different final name after `EEXIST`; report the collision. Warn on stderr before `--probe` and when `PublishedArtifact.durability_warning` is present.

- [ ] **Step 4: Implement the machine document and advertise only when complete**

Add `support-report-json` to `CAPABILITIES`, route `support-report --json` to `machine::support_report`, and publish a sanitized JSON value derived from the same `SupportReport` object. Reject `--probe --json` in contract 1 with a typed usage error and create no output file.

- [ ] **Step 5: Run CLI and machine API suites**

Run:

```bash
cargo test -p irlume-cli --locked support_report
cargo test -p irlume-cli --locked --test machine_api
```

Expected: PASS; stdout contains no prose in machine mode, and text output has a verified hash.

- [ ] **Step 6: Commit the CLI report**

```bash
git add crates/irlume-cli/src/support_report.rs crates/irlume-cli/src/main.rs crates/irlume-cli/src/commands.rs crates/irlume-cli/src/machine.rs crates/irlume-cli/tests/cli.rs crates/irlume-cli/tests/machine_api.rs
git commit -m "feat(cli): create privacy-bounded support reports"
```

### Task 7: Add the safe TUI report action

**Files:**
- Modify: `crates/irlume-cli/src/tui.rs`
- Test: `crates/irlume-cli/src/tui.rs`

**Interfaces:**
- Consumes: human `irlume support-report` command from Task 6.
- Produces: `Suspend::SupportReport` and Diagnostics action key `s`.
- Does not expose probe or trace recording in the TUI.

- [ ] **Step 1: Write failing render, key-route, and completion tests**

```rust
#[test]
fn diagnostics_offers_only_the_read_only_support_report() {
    let mut app = test_app_on(SC_REPAIR);
    let text = draw_text(&app);
    assert!(text.contains("Create Support Report"));
    assert!(text.contains("read-only; captures no camera data"));
    app.on_action(KeyCode::Char('s'));
    assert!(matches!(app.suspend, Some(Suspend::SupportReport)));
}
```

Also assert the success Activity line includes the exact path and “inspect before sharing,” and that no TUI route contains `--probe` or starts `trace`.

- [ ] **Step 2: Run and verify RED**

Run: `cargo test -p irlume-cli --locked tui::tests::diagnostics_offers_only_the_read_only_support_report`

Expected: FAIL because the action is absent.

- [ ] **Step 3: Implement the suspended action**

Follow the existing `Suspend::Doctor` pattern, invoke the current executable with `support-report`, preserve the user's working directory, and parse the command's final success line only as a path display—not as diagnostic truth. Update the diagnostics footer and help overlay.

- [ ] **Step 4: Run all TUI tests**

Run: `cargo test -p irlume-cli --locked tui::tests`

Expected: PASS at every terminal size and key-walk mutation test.

- [ ] **Step 5: Commit the TUI action**

```bash
git add crates/irlume-cli/src/tui.rs
git commit -m "feat(tui): create share-safe support reports"
```

### Task 8: Document, verify, and physically validate the report

**Files:**
- Modify: `docs/COMMANDS.md`
- Modify: `docs/MACHINE-API.md`
- Modify: `docs/DEBUGGING.md`
- Modify: `docs/SETUP.md`
- Modify: `docs/adr/0008-privacy-bounded-diagnostics.md`
- Create: `docs/validation/2026-08-17-support-report.md`
- Test: `crates/irlume-cli/tests/machine_api.rs`

**Interfaces:**
- Consumes: completed Tasks 1–7.
- Produces: user/operator contract and four-device validation record.

- [ ] **Step 1: Update docs and stable-ID coverage**

Document the default `.txt`, privacy boundary, 0600/no-overwrite behavior, `--since`, explicit root `--probe`, daemon-unavailable behavior, JSON capability, and the fact that raw journals are not copied. Extend the machine-doc coverage test so every advertised capability has a command section.

- [ ] **Step 2: Run the full software gate**

Run:

```bash
cargo fmt --all -- --check
git diff --check
cargo test --workspace --locked
cargo clippy --workspace --all-targets --locked -- -D warnings
```

Expected: all commands exit 0.

- [ ] **Step 3: Validate read-only reports on all four devices**

On this host, Archhost, ThinkPad, and Minihost, run the identical commit:

```bash
./target/debug/irlume support-report --output ./support-readonly.txt
sha256sum ./support-readonly.txt
stat -c '%a %s %n' ./support-readonly.txt
```

Confirm mode `600`, size under 1 MiB, footer hash matches the body, no camera/emitter journal activity occurs, unplugged/daemon-down sections say unavailable, and a second invocation refuses to replace the file.

- [ ] **Step 4: Validate explicit probe behavior on applicable hardware**

Run `sudo ./target/debug/irlume support-report --probe --output ./support-probe.txt` on the ASUS, BRIO, and NexiGo pairs; run it on the RGB-only ThinkPad and record the categorical RGB-only result. Confirm the selected schedule matches `camera-mode`, concurrent failure uses bounded sequential fallback, no qualification file changes, and no enrollment/authentication is performed.

- [ ] **Step 5: Record evidence and accept the ADR implementation status**

Write exact commit, host/camera IDs, schedule/probe outcomes, artifact hashes/modes, no-overwrite checks, and caveats to `docs/validation/2026-08-17-support-report.md`. Keep ADR 0008 at `Accepted` and add the support-report validation link; the ADR becomes `Implemented` only after the dependent live-trace plan is also complete.

- [ ] **Step 6: Commit documentation and evidence**

```bash
git add docs crates/irlume-cli/tests/machine_api.rs
git commit -m "docs: record support report contract and validation"
```

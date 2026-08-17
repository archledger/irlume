# ADR 0008: Separate share-safe reports from privileged live traces

Date: 2026-08-17

Status: Accepted

## Context

Irlume currently exposes useful but disconnected diagnostic surfaces:

- `doctor`, `status`, `camera-mode`, and `CameraDiagnostics` return structured
  snapshots;
- `irlume logs` filters the system journal;
- `irlume logs debug on` installs a persistent systemd drop-in, restarts the
  daemon, and exposes exact gate and match values until somebody turns it off;
- physical validation scripts collect richer evidence, but they are developer
  tools rather than a support contract.

This makes an ordinary bug report unnecessarily manual. It also makes the
deepest diagnostic setting easy to leave enabled. Copying the raw journal into
a support artifact is not acceptable: existing prose can contain account and
profile names, exact denied-attempt scores are a feedback oracle, and future
log messages could accidentally broaden what gets shared.

A single artifact cannot safely serve both audiences. A report suitable for a
public issue must omit information a root developer may legitimately need
during a controlled reproduction.

## Decision

Provide two deliberately different diagnostic products:

1. A **support report** is a share-safe snapshot. Its default representation is
   a human-readable `.txt` file. It is read-only and does not open a camera,
   activate an emitter, change configuration, restart a service, or enable
   tracing.
2. A **diagnostic trace** is a privileged, live `.jsonl` event stream. It is
   explicitly started, time- and size-bounded, and ends on deadline, client
   disconnect, or daemon restart. It changes no persistent daemon setting.

The two products share typed diagnostic events and sanitization policy, not
raw journal text. The support report receives the share-safe projection; a
trace may contain root-only measurements that the projection deliberately
removes.

### Support report contract

The human command is:

```text
irlume support-report [--output PATH] [--since DURATION] [--probe]
```

Without `--output`, the CLI creates
`./irlume-support-YYYYMMDD-HHMMSS.txt`. It refuses to replace an existing path.
The final file is mode 0600. Its first section states that it contains no
frames, embeddings, credentials, recovery material, usernames, profile names,
raw camera serials, or raw emitter payloads.

The report contains:

- report schema, Irlume version, UTC creation time, and privilege level;
- OS, kernel, installation channel, and installed-service health;
- camera VID:PID, role/interface, driver, negotiated link speed, controller and
  USB topology, descriptor identity, requested/accepted stream contracts, and
  lifecycle generation, with raw serial values omitted;
- resolved capture schedule, source, qualification state/reason/context, and
  process-local degradation reason;
- bounded, typed recent events such as lifecycle changes, capture contract or
  rate failures, fallbacks, and final categorical outcomes;
- an explicit list of unavailable sections and why they were unavailable;
- a final privacy checklist and SHA-256 of the report body preceding the
  integrity footer.

Hardware topology is included because it is required to diagnose port- and
controller-dependent failures. Account identity is not. Device paths are
reported as stable role labels and topology components rather than `/dev`
names. A camera serial is represented only as present/absent. Descriptor and
qualification digests may be truncated tokens sufficient to correlate sections
within one report.

`--since` is bounded to the typed in-memory event history; it does not widen
the command into an arbitrary journal reader. When the daemon is unavailable,
the report remains useful and labels daemon-owned sections unavailable rather
than inventing empty values.

Report data is bounded to 1 MiB and rendered completely before publication.
The CLI writes one unique mode-0600 `.partial` file beside the destination,
syncs it, and publishes it with Linux `renameat2(RENAME_NOREPLACE)` so an
existing destination cannot be replaced between a check and the commit. It
then syncs the parent directory before reporting durable success. An
interruption may leave the clearly named partial file but never a truncated
file bearing the final `.txt` name. User-selected remote/network filesystems
are accepted only with an explicit warning that durable-success semantics are
not qualified there.

`--probe` is a separate, explicit hardware action. It requires root, acquires
the normal daemon-owned camera operation, and executes one bounded capture with
the schedule the daemon would currently select, including its normal safety
fallback. It may activate only a previously known, identity-matched emitter
control. It does not search controls, test an otherwise unauthorized
concurrent schedule, publish qualification, reset runtime health, enroll, or
authenticate. The report says before capture that the camera may illuminate.

The stable machine form is:

```text
irlume support-report --json [--since DURATION]
```

It follows the versioned machine API: one JSON document on stdout, diagnostics
on stderr, no implicit output file, and capability `support-report-json` only
after the schema and implementation are complete. The probing form is not
part of contract version 1 initially; callers can use the human command until
its cancellation and consent semantics are stable.

### Diagnostic trace contract

The live command is:

```text
sudo irlume trace [--duration DURATION] [--output PATH]
irlume trace explain PATH [--output PATH]
```

Recording defaults to 60 seconds and is capped at five minutes, 50,000 events,
and 16 MiB. The daemon permits one active trace subscriber. A second request
fails with a typed busy response rather than silently joining or replacing the
first. `SO_PEERCRED` root authorization is enforced by the daemon; a client
flag or output-file owner is never treated as authority.

The daemon generates the opaque operation ID after accepting and classifying a
request. It never trusts or reflects a caller-supplied correlation ID into the
privileged event stream.

The CLI creates a unique, mode-0600 `.partial` file beside the requested final
path with create-new and no-follow semantics. Events are streamed into that
single file. On a clean terminal event it flushes and syncs the file, renames
it to the requested `.jsonl` path on the same filesystem with
`renameat2(RENAME_NOREPLACE)`, and syncs the parent directory before reporting
durable success. It never overwrites a final path.
An interruption leaves the `.partial` file, clearly marked by its name and
usable for recovery; startup never treats it as a complete trace. No lock file
or multi-file transaction is needed because one recorder owns one immutable
artifact and publication has one namespace commit point. Network filesystems
are unsupported for durable-success claims unless separately qualified.

Each JSON line carries:

- trace schema version, monotonically increasing sequence, trace-relative
  monotonic time, and UTC time;
- an opaque operation ID propagated across CLI/TUI/PAM request handling,
  daemon arbitration, capture, qualification, fallback, and final outcome;
- operation class and phase, not account or profile identity;
- capture schedule/source, pseudonymous context token, exact stream contract,
  delivered-rate/continuity/drop evidence, ActiveIr provenance, and typed
  runtime violations;
- typed emitter outcomes without control payload bytes;
- stage timings, detector counts, liveness gate measurements and thresholds,
  match measurements and thresholds, and categorical final outcome;
- explicit `events_dropped` records when the bounded non-blocking subscriber
  cannot keep up.

The daemon's authentication and camera paths must never block on a trace
consumer. Event emission is a non-blocking side channel with a bounded queue.
Losing trace events can reduce diagnostic completeness but cannot affect an
authentication result, camera lease, emitter restoration, or fallback.

Exact match and liveness measurements are permitted only in the root-owned
trace because they can provide iterative feedback to an attacker. The trace
header warns about that oracle. Frames, crops, landmarks, embeddings,
credentials, template contents, recovery data, usernames, profile names, and
raw emitter payloads are forbidden even in a root trace.

`trace explain` parses a bounded, versioned trace without contacting the
daemon. It verifies sequence and terminal status, reports dropped or truncated
events, groups events by operation ID, and renders a human timeline. It never
accepts malformed lines as trusted prose.

### Event ownership and projection

Diagnostic facts are defined as bounded enums and numeric value objects in the
lowest crate that owns the fact. The daemon owns correlation, authorization,
the recent share-safe ring, and live subscription. The CLI owns text/JSON
rendering and artifact publication. Human journal messages remain useful for
operators but are not parsed back into diagnostic truth.

Every event field has one privacy class:

- **share-safe**: may appear in reports and traces;
- **trace-only**: may appear only in a root-authorized trace;
- **forbidden**: may not enter the diagnostic event model.

Projection is structural: a share-safe DTO contains no trace-only or forbidden
field. Sanitization is therefore enforced by types and serialization tests,
not by regex replacement after arbitrary strings have been collected.

The daemon retains at most 256 share-safe events or 30 minutes, whichever is
smaller. The ring is process-local and intentionally disappears on restart. A
support report states that boundary. Persistent diagnostic history remains the
system journal under the machine's existing access controls.

### Existing debug mode

`irlume logs debug on|off` remains temporarily for compatibility, but help and
documentation direct new investigations to `irlume trace`. Once the structured
trace has equivalent stage coverage and has been hardware-tested, the drop-in
debug toggle is deprecated in a separate compatibility decision. This ADR does
not silently change or remove it.

### TUI surface

The Diagnostics section offers **Create Support Report** and explains that the
default action is read-only and captures no camera data. After success it shows
the exact path, privacy summary, and a reminder to inspect the text before
sharing. Active probing and root-only tracing remain explicit CLI workflows in
the first version; the TUI links to their commands rather than trying to hide a
privilege transition or camera activation inside a dashboard action.

## Considered options

### One text file containing raw journal output

Rejected. It is easy to read but has no enforceable privacy schema, depends on
unstable prose, can include identities, and cannot correlate structured camera
evidence reliably.

### A compressed support bundle by default

Rejected as the primary artifact. Users should be able to open and inspect the
normal report before sharing it. A future explicit `--archive` may add multiple
sanitized artifacts, but it must include the text report as its manifest and
must not weaken the same allowlist.

### Reuse `logs debug on` for live trace

Rejected. It restarts the daemon, persists until manually disabled, writes
exact measurements into the broader journal, and cannot provide reliable
operation correlation or a typed completeness marker.

### Make support reporting probe the camera automatically

Rejected. A diagnostic report must not unexpectedly illuminate a camera,
contend with authentication, or touch a hardware control. Hardware activity is
an explicit `--probe` operation with its own authorization and warning.

## Consequences

- Troubleshooting gains a public, inspectable artifact and a deeper developer
  artifact without pretending their privacy requirements are identical.
- Diagnostic events become a real internal schema. New hardware and auth paths
  must add typed events instead of relying only on prose.
- The daemon needs operation-ID propagation, a share-safe ring, and a bounded
  subscriber that cannot block production work.
- The CLI needs secure single-file publication, JSONL parsing, and deterministic
  text rendering.
- The TUI gains a safe report action but does not silently escalate privilege
  or activate hardware.
- Support reports can diagnose many failures without root; exact live tracing
  and active probing remain privileged.
- This work does not change authentication policy, capture qualification,
  enrollment data, or emitter allowlists.

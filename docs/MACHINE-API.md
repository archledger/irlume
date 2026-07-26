# Machine API

`irlume` exposes a deliberately small, versioned JSON interface for desktop
integrations. Human-facing output remains the default.

## Compatibility

Every document contains:

```json
{
  "contract_version": 1,
  "engine_version": "0.6.1",
  "command": "version",
  "ok": true,
  "data": {}
}
```

Non-streaming machine-mode standard output contains exactly one JSON document.
Diagnostics go to standard error. A successful command exits with zero. Usage
errors exit with 2, while unavailable or failed operations exit nonzero and
return:

```json
{
  "contract_version": 1,
  "engine_version": "0.6.1",
  "command": "profiles.list",
  "ok": false,
  "error": {
    "code": "daemon-unavailable",
    "retryable": true
  }
}
```

Fields may be added within a contract version. Removing a field or changing its
meaning requires a new contract version. Consumers must first call
`irlume version --json` and use only advertised capabilities.

The machine API is not the daemon socket protocol. The socket remains private,
and its serialized Rust enums are not a public compatibility promise.

## Commands

### `irlume version --json`

Does not contact the daemon. It returns the engine version, contract version,
advertised capabilities, and public limits.

### `irlume profiles list --json [--user USER]`

Capability: `profiles-json`.

Returns stable opaque profile and scan IDs, display names, and the two per-user
liveness policy flags. An older daemon that cannot supply valid aligned IDs is
rejected with `unsupported-daemon`; mutable display names are never substituted.

### Profile mutations

Capability: `profile-mutations-json`.

```text
irlume profiles rename --profile-id ID --name NAME --json
irlume profiles rename --profile-id ID --scan-id ID --name NAME --json
irlume profiles delete --profile-id ID --json
irlume profiles delete --profile-id ID --scan-id ID --json
```

Mutation targets are stable opaque IDs. The daemon resolves them inside its
privileged storage boundary and returns the exact affected IDs, typed operation,
explicit before/after display identity, remaining scan count, and
`mutated_other_profiles: false`. IDs and names are bounded and validated before
the request is sent. Deleting the final scan is refused; callers must delete the
profile instead.

### Enrollment and authentication events

Capabilities: `events-jsonl`, `position-report`, and, when explicitly requested,
`preview-ir-jpeg`.

```text
irlume enroll --events=jsonl [--user USER]
irlume auth test --events=jsonl [--user USER]
irlume profiles add-scan --profile-id ID --events=jsonl [--user USER]
```

Each command writes one JSON object per line and flushes after every event.
Every line repeats the contract and engine versions, command, random operation
and session IDs, and a monotonically increasing sequence number:

```json
{
  "contract_version": 1,
  "engine_version": "0.6.1",
  "command": "enroll",
  "operation_id": "operation-…",
  "session_id": "session-…",
  "sequence": 0,
  "event": "started",
  "terminal": false
}
```

The sequence is `started`, one or more `preview` positioning reports, `stage`,
then exactly one terminal `completed`, `failed`, or `cancelled`. Enrollment
completion returns `profile_id`, whether it was created, and the added and total
scan counts. Add-scan completion returns the exact profile ID, counts, and
`mutated_other_profiles: false`. Authentication test completion reports match
and liveness decisions while guaranteeing `credential_released: false` and
`profile_modified: false`.

Position reports contain only bounded booleans, quality 0–100, countdown, and
plain guidance. A frame is emitted only when all three fixed preview flags are
present:

```text
--preview=ir-jpeg --preview-max-fps=8 --preview-max-size=640x480
```

The preview is an in-memory JPEG (IR preferred, RGB fallback), no larger than
640×480 and 96 KiB before base64, accompanied by exactly 478 normalized
landmarks and one normalized face box. Preview events are no faster than 8 fps
and each complete JSON line is below 256 KiB. Omitting the flags still provides
position reports, but never emits a frame, landmarks, spectrum, or face box.

`SIGINT` and `SIGTERM` request cancellation. The client closes an in-flight
daemon connection promptly and emits one terminal `cancelled` event with exit
code 130. If a mutation had already completed, either the client removes the
exact returned opaque IDs or the daemon atomically rolls it back when delivery
of the response fails. New profiles are deleted as a unit; merges and
improve-recognition remove only the scans created by that operation.

Stream failures expose only stable codes and retryability. Defined codes include
`camera-busy`, `not-authorized`, `user-cancelled`, `timeout`,
`positioning-timeout`, `precondition-failed`, `hardware-unavailable`,
`daemon-unavailable`, `protocol-error`, `invalid-preview`, and
`operation-failed`. Consumers must not parse standard error or daemon logs.

## Security and privacy

Ordinary JSON output never includes camera frames, embeddings, templates,
passwords, credential material, TPM secrets, device paths, or usernames. Preview
frames are the sole opt-in exception and exist only in the requested stream;
they are never written to disk. Neither preview nor auth-test output contains
identity embeddings, templates, secrets, or released credentials. Errors
contain stable codes instead of daemon prose.

The following are not part of contract version 1 yet and must not be inferred
from human output or the private socket protocol:

- camera configuration mutation;
- login plan, apply, verify, or rollback transactions.

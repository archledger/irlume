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

Machine-mode standard output contains exactly one JSON document. Diagnostics
go to standard error. A successful command exits with zero. Usage errors exit
with 2, while unavailable or failed operations exit nonzero and return:

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

## Security and privacy

Ordinary JSON output never includes camera frames, embeddings, templates,
passwords, credential material, TPM secrets, device paths, or usernames.
Errors contain stable codes instead of daemon prose.

The following are not part of contract version 1 yet and must not be inferred
from human output or the private socket protocol:

- enrollment or authentication-test event streams;
- preview images and cancellation semantics;
- streaming improve-recognition capture;
- camera configuration mutation;
- login plan, apply, verify, or rollback transactions.

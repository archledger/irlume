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

Capability: `profiles-list-json`.

Returns display names, scan display names, and the two per-user liveness policy
flags. The current enrollment store identifies these records by mutable names,
so this first read-only contract intentionally does not invent opaque IDs or
advertise profile mutations. Mutation-safe IDs must originate in the engine
store before a later capability can expose them.

## Security and privacy

Ordinary JSON output never includes camera frames, embeddings, templates,
passwords, credential material, TPM secrets, device paths, or usernames.
Errors contain stable codes instead of daemon prose.

The following are not part of contract version 1 yet and must not be inferred
from human output or the private socket protocol:

- enrollment or authentication-test event streams;
- preview images and cancellation semantics;
- profile or scan mutation;
- camera configuration mutation;
- login plan, apply, verify, or rollback transactions.

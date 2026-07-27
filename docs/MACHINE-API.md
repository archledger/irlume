# Machine API

`irlume` exposes a deliberately small, versioned JSON interface for desktop
integrations. Human-facing output remains the default.

## Compatibility

Every document contains:

```json
{
  "contract_version": 1,
  "engine_version": "0.7.0",
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
  "engine_version": "0.7.0",
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

### A capability is not a compatibility promise

`capabilities` says a command exists and is reachable. It does not say the
engine's version is one a consumer has been tested against, and it is not a
substitute for `contract_version`. Gate on the contract version you implement;
treat a capability as an availability check on top of that.

Read this the way irlume writes it: a name in that list is permanent public API.
Once a name ships, consumers in the field may enable behaviour on seeing it, and
irlume cannot know which versions those are. So a name is never reused for
different semantics, and never appears before the command behind it is finished.

### Authorization

Every operation is authorized by the daemon from the connecting process's
credentials, not from anything the caller says about itself. An operation is
permitted for `root`, or for the user that owns the records being touched.
`--user` names which account to act on; it does not grant anything. An ordinary
user naming another account is refused.

Consumers should not attempt to pre-check permission. Call the command and read
the error.

### Timeouts and cancellation

Commands that only read state return promptly. Commands that use the camera take
as long as a capture takes, and irlume applies its own internal bounds. A
consumer should set its own timeout, and should treat terminating the process as
the cancellation mechanism for this contract version. There is no cancel
command in contract version 1.

### Deprecation

Within a contract version, no command or documented field is removed and no
documented meaning changes. If a command must change incompatibly, the new shape
arrives under a new `contract_version` and the previous one keeps working for at
least one minor release series, so a consumer has a window in which both are
available. Capability names are not removed once published; a capability that
becomes unavailable on a given machine simply stops being listed by that
machine.

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

Display names are chosen by the user, so treat them as user text rather than
identifiers: they may contain anything the user typed.

### Error codes

| Code | Meaning | `retryable` |
|---|---|---|
| `usage-error` | The command line was not one this contract accepts. Exits 2. | no |
| `daemon-unavailable` | The daemon could not be reached. | yes |
| `operation-failed` | The daemon refused or could not complete the request. | no |
| `protocol-error` | The daemon replied with something this command did not expect. | no |

`operation-failed` is deliberately coarse in contract version 1, and a consumer
should know what it hides: a request refused because the caller may not act on
that account, a request naming an account that does not exist, and a genuine
engine failure all report it identically, because the daemon reports those to the
CLI as prose rather than as typed outcomes. A consumer therefore cannot yet tell
"you are not permitted" from "something broke", and should present a neutral
failure rather than guessing. A distinct authorization code is planned for when
the daemon reports typed outcomes for this path; it will be additive.

The one thing that identical treatment does buy today is that an unprivileged
caller cannot use this command to discover which accounts exist or which are
enrolled.

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

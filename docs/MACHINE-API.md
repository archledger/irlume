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
go to standard error.

**Streaming capabilities are the exception, and only ever by invitation.** A
capability whose name ends in `-events` emits newline-delimited JSON: one event
per line, many lines. A consumer reaches one only by invoking a command it found
in `capabilities`, so a consumer that does not implement streaming never sees
more than one document. The rule above is what every non-streaming command
follows, and it is what a contract 1 consumer built before streaming existed
will continue to observe. A successful command exits with zero. Usage errors exit
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

### Declaring which contract you implement

Pass `--contract N` on any machine command. The engine agrees only to a version
it implements, and refuses anything else **before** contacting the daemon and
before any command with side effects begins:

```
$ irlume profiles list --contract 9 --json
{"contract_version":1,...,"error":{"code":"unsupported-contract","retryable":false}}
```

Exit code 2. A malformed flag (no value, a non-number, repeated) is a
`usage-error`.

`irlume version --json` advertises the range this build speaks:

```json
"contract_versions": { "min": 1, "max": 1 }
```

Pick a version inside that range and pass it. Every response echoes the contract
actually in force in `contract_version`, so a consumer can assert the engine
agreed to the version it implements rather than inferring it.

**Omitting the flag always means contract 1.** It does not mean "whatever is
newest", and it never will. A program written against contract 1 that omits the
flag keeps receiving contract 1 on an engine that has since learned contract 2,
because the alternative is changing the meaning of a response under a program
that never asked for it. Passing the flag is still better: it makes the refusal
explicit and immediate when a consumer meets an engine too old for it.

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

### `irlume status --json [--user USER]`

Capability: `status-json`.

The readiness summary, as values rather than prose. Deliberately narrower than
the human `status`: it reports camera **capability** and never camera identity,
and it does not name the account, because the caller already knows which one it
asked about.

```json
{
  "daemon": "running",
  "auth_method": "auto",
  "face_disabled": false,
  "enrollment": { "known": true, "profiles": 1, "scans": 10 },
  "templates": "encrypted",
  "keyring": { "known": true, "armed": true, "policy": "…" },
  "recovery": { "known": true, "passphrase_set": true },
  "camera": { "rgb": true, "ir": true },
  "fingerprint": false
}
```

`daemon` is one of `running`, `access-denied` or `unreachable`. An unreachable
daemon is reported, not raised as an error, because the fields that do not need
it are still worth having.

Anything derived from the daemon carries `known`. **Unknown is not zero**: when
`known` is false the counts are absent entirely rather than reported as `0`, so a
consumer cannot mistake "we could not find out" for "this account has nothing
enrolled".

`templates` is `encrypted`, `plaintext`, or `unknown`.

### `irlume doctor --json`

Capability: `doctor-json`.

Every readiness check as an identified result:

```json
{ "checks": [
  { "id": "tpm", "state": "pass" },
  { "id": "platform", "state": "info", "detail": "Fedora-family" },
  { "id": "keyring-secrets", "state": "unknown" }
] }
```

`state` is one of `pass`, `warn`, `fail`, `unknown` or `info`. `unknown` is not a
synonym for `fail`: it means the check could not be carried out, usually because
the daemon was unreachable or the command ran without a session bus, and a
consumer should say so rather than report a problem the machine may not have.
`info` is a fact worth reporting that is neither good nor bad, such as the
platform family.

`detail` is English elaboration for a support report. It is not stable and not
for matching. A consumer that branches on that text has reintroduced the problem
this command removes.

**The array is complete.** Every check reports on every run, including checks
that do not apply to this machine, so a consumer may read an id it knows about
and cannot find as "this engine version does not run that check" rather than as
"it passed". A check never disappears because it had nothing to say.

`id` values are public API. The list may grow; an id is never renamed and never
reused for a different meaning. The registry as of this contract:

| Check id | Reports on |
|---|---|
| `platform` | the distribution family irlume detected |
| `install-origin` | where this build came from: a distro package, the Copr, or a source install |
| `tpm` | a usable TPM 2.0 resource-manager device |
| `secure-boot` | Secure Boot enabled, disabled, or in setup mode |
| `boot-mode` | the boot chain, which decides which PCR policy tier applies |
| `signed-pcr-policy` | the systemd signed-PCR (Tier 1) policy for sealing |
| `pcrlock` | the systemd-pcrlock (Tier 2) policy and its NV index |
| `camera-nodes` | whether an RGB and an IR node were classified. Capability only; no device paths |
| `models` | the ONNX weights irlume needs, present and checksummed |
| `ort-dylib-path` | which ONNX runtime library will be loaded |
| `third-party-pad-model` | optional third-party presentation-attack weights, if installed |
| `fingerprint-reader` | whether a fingerprint reader was found |
| `templates` | face templates encrypted at rest for the account asked about |
| `recovery-passphrase` | whether a recovery passphrase is set |
| `credential-release-challenge` | the consent gesture required before the keyring password is released |
| `polkit-app-prompts` | whether polkit application prompts accept a face match |
| `polkit-helper-sandbox` | whether the polkit helper's sandbox permits what irlume needs |
| `ir-calibration` | whether this account's IR enrollment carries the per-user liveness floor |
| `login-wiring` | whether face auth is wired into the login stack |
| `display-manager` | whether the active display manager is one irlume can target |
| `pam-regeneration-guard` | whether a distro PAM regeneration would strip the wiring unnoticed |
| `install-hygiene` | leftover backups, and hand-installed builds overlaying packaged ones |
| `keyring-secrets` | the login keyring's lock state and provider |

## Schema, fixtures, and conformance

Contract 1 has a JSON Schema (2020-12) at `schemas/machine-api-v1.schema.json`,
installed on packaged systems at
`/usr/share/irlume/schemas/machine-api-v1.schema.json`.

**The schema does not close its objects, and a consumer's validator must not
either.** Fields may be added within a contract version, so rejecting unknown
properties turns a permitted engine update into a broken consumer.

`schemas/fixtures/v1/` holds documents captured from a real engine, including the
daemon-unreachable and refusal cases, for building against without an
installation. `scripts/machine-api-conformance.py` checks a build the way a
consumer would: envelope rules, every advertised capability answering, and the
refusals behaving. [INTEGRATION.md](INTEGRATION.md) is the guide for writing a
consumer.

### `irlume login status --json`

Capability: `login-status-json`.

Which PAM surfaces carry face auth, by service name:

```json
{
  "login_manager": {
    "known": true,
    "name": "plasmalogin",
    "recognized": true,
    "services": ["plasmalogin"]
  },
  "surfaces": [
    { "id": "plasmalogin", "role": "login-screen", "present": true, "wired": true, "mode": "on-demand" },
    { "id": "sddm", "role": "login-screen", "present": false, "wired": false },
    { "id": "kde", "role": "lock-screen", "present": true, "wired": true, "mode": "on-demand" },
    { "id": "sudo", "role": "sudo", "present": true, "wired": true, "mode": "verify" }
  ],
  "selinux_module": "loaded"
}
```

`id` is the PAM service name, and it is public API on the same terms as a doctor
check id: the list may grow, an id is never renamed and never reused. Paths under
`/etc/pam.d` are not published, for the reason `status --json` publishes camera
capability and not camera nodes.

`role` is one of `login-screen`, `login-screen-fingerprint`, `lock-screen`,
`sudo` or `polkit`.

`present` is whether the service exists on this machine at all, counting a vendor
copy an override would be materialized from. `wired` is whether it currently
carries the irlume line.

**The surface array is complete.** A service absent from the machine is still
reported, with `present: false`, so a consumer that knows an id and cannot find
it may read that as "this engine version does not wire that service" rather than
as "it is not wired here".

`mode` says how face fires on a wired surface: `face-first` (the camera verifies
as soon as the greeter prompts), `on-demand` (the user submits an empty password
to trigger face), `keyring` (the fingerprint keyring-unlock line, which is not a
face factor), or `verify` (the plain sudo and polkit stanza). It is absent, never
null, when the surface is not wired.

`login_manager.known` is false when no `display-manager.service` is set: a
headless host, or a greeter that registers none. That is not the same as "no
login manager is installed", and a consumer should not render it that way.
`recognized` is whether irlume can wire face login for this login manager. It is
false both for one irlume has no mapping for and for one whose mapped PAM service
irlume has no wiring recipe for; either way `login enable` cannot target it, which
is what a consumer needs to know. `services` are the PAM
services that login manager consults, which is how a consumer decides which
surface entry describes its own login screen without matching on names. A service
listed there with no matching entry in `surfaces` is one this engine has no
wiring recipe for.

`selinux_module` is `loaded`, `not-loaded` or `unknown`. Reading the policy store
needs root, so an ordinary caller gets `unknown`, which is not a synonym for
`not-loaded`.

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
| `unsupported-contract` | The engine does not implement the requested contract. Refused before any side effect. Exits 2. | no |
| `daemon-unavailable` | The daemon could not be reached. | yes |
| `not-authorized` | The caller may not act on the named account. | no |
| `operation-failed` | The engine could not carry out a well-formed request. | no |
| `protocol-error` | The daemon replied with something this command did not expect. | no |

`not-authorized` and `operation-failed` are distinct so a consumer can tell "you
may not do that" from "something broke", and act accordingly: the first is worth
a message about permissions, the second is worth a retry or a support report.

`not-authorized` deliberately says nothing about whether the named account
exists. An ordinary caller is refused before the enrollment store is consulted,
so a real account and an invented one produce the identical answer, and this
command cannot be used to discover which accounts exist or which are enrolled.

`retryable` means an identical request could plausibly succeed later without the
caller changing anything. Only `daemon-unavailable` sets it today. It is not a
promise that a retry will succeed, and it carries no suggested delay.

### `irlume auth test --events=jsonl`

Capability: `auth-test-events`.

Does the claimed account's live face match its own enrolment? This is
verification against one account, never identification, and it releases nothing:
the answer is a verdict. It cannot alter a profile, a threshold, or a credential,
because it issues no request that could.

Output is newline-delimited JSON, one event per line:

```
{"contract_version":1,"engine_version":"0.7.1","command":"auth.test","operation_id":"8db4...","session_id":"a14a...","sequence":0,"event":"started","terminal":false,"data":{"operation":"auth-test"}}
{"contract_version":1,...,"sequence":1,"event":"capturing","terminal":false,"data":{}}
{"contract_version":1,...,"sequence":2,"event":"result","terminal":true,"data":{"granted":false,"live":true,"reason":"no-match"}}
```

Every line carries the whole envelope rather than relying on a header sent once,
so a line remains meaningful on its own in a log or after a dropped read.

Three properties a consumer may rely on:

- `sequence` starts at zero and increments by one with no gaps, so a lost line
  is detected by arithmetic rather than by timeout;
- exactly one event has `terminal` true, and it is the last, so a reader knows
  when to stop without waiting;
- `operation_id` is identical on every line of one invocation.

`reason` is one of `granted`, `not-live`, or `no-match`, derived from `granted`
and `live`. It is never derived from daemon wording, so a reworded message is not
a breaking change.

**The match score is not reported.** A caller that can read a continuous score
can hill-climb against it, adjusting a presentation until it crosses the
threshold, which would turn a diagnostic into an oracle. `granted` and `live`
are the facts a settings panel needs.

The account is not echoed back, for the same reason ordinary machine output
carries no usernames: the caller already knows which account it asked about, and
a desktop may log the stream.

An exit status of zero means the test ran. It does not mean the face matched;
read `granted` for that. A refusal before the stream begins is reported as a
single document with the usual error codes and exit 2, not as a stream. A
failure once the stream has started is a terminal `error` event and exit 1.

Naming an account the caller may not act on is one such failure, and it reports
`operation-failed` rather than `not-authorized`. That flattening is deliberate:
distinguishing the two would answer "does this account exist and is it enrolled"
for any local process, and the engine already refuses to let one account's face
be tested against another's enrolment for the same reason.

One session per user runs at a time. A second concurrent invocation is refused
with `session-busy`, which is retryable. A lock that cannot be taken at all,
because the runtime directory is unwritable, is `operation-failed` and is not
retryable: the two mean opposite things to a caller, and reporting both as busy
would tell a consumer to keep trying against a permission error. The lock is held by the running process
and released by the kernel when it exits, so a panel that is killed mid-capture
does not strand the user.

`--preview` is refused. Preview frames are a separate capability that this
build does not advertise; accepting the flag and ignoring it would suggest that
frames were withheld by policy rather than never implemented.

Stream lines validate against `$defs/event` in the schema, not against the
document root. `schemas/fixtures/v1/auth-test-events.ndjson` is a capture from a
real engine.

### `irlume login plan --action {enable|disable} --json`

Capability: `login-plan-json`.

The plan phase of a login transaction: what `login enable` or `login disable`
would change, without changing anything.

```json
{
  "plan_id": "c574f96dba23c06bbb2e2f395a74f074",
  "action": "disable",
  "changes": [
    { "surface": "gdm-password", "role": "login-screen", "change": "not-installed", "writes": false },
    { "surface": "plasmalogin", "role": "login-screen", "change": "restore-backup", "writes": true },
    { "surface": "kde", "role": "lock-screen", "change": "restore-backup", "writes": true },
    { "surface": "sudo", "role": "sudo", "change": "restore-backup", "writes": true },
    { "surface": "polkit-1", "role": "polkit", "change": "remove-override", "writes": true }
  ],
  "writes": 4,
  "requires_root": true
}
```

Absent surfaces are trimmed from this example for length; a real document lists
every one. The top-level `writes` always equals the number of entries whose own
`writes` is true.

This runs the identical decision the apply path runs, with writing switched off,
so a plan cannot describe an outcome the apply would not produce. Reading the PAM
stack needs no privilege; `requires_root` says whether applying would.

Every surface irlume can wire appears, including absent ones, so a consumer
reading an id it knows and cannot find learns "this engine does not wire that
service" rather than "not wired here". Surfaces are named by PAM service, never
by path, in keeping with the no-paths rule.

`change` is one of `wire`, `materialize-override`, `restore-backup`,
`remove-override`, `strip-in-place`, `already-correct`, `not-installed`,
`no-anchor`, `not-wired`. `writes` on a change says whether applying it would
touch disk, and the top-level `writes` counts them, so "nothing to do" is a fact
the engine states rather than one a consumer infers from outcome names it may
not recognise.

`plan_id` is a digest of the action and the exact per-surface outcomes it was
computed against. Two plans over an unchanged machine share an id; any change to
what would happen produces a different one. It exists so that a later apply can
refuse a plan that no longer matches the machine rather than silently doing
something the consumer never displayed. It is an identifier, not a security
boundary: apply will re-derive the plan from the machine rather than trusting
anything the id encodes.

Sudo and polkit are opt-in on the human command and are not included in a plan,
so a panel never shows a user surfaces they did not ask for. Disabling still
covers every surface, because turning login off leaves nothing behind.

**Applying a plan is not implemented yet.** `login apply`, `login verify` and
`login rollback` are not part of contract 1 and must not be inferred from this
command or from human output.

### `irlume login apply` / `verify` / `rollback`

Capability: `login-transactions`. The mutating half of a login transaction;
`login plan` above is the read-only half.

```
irlume login apply    --action {enable|disable} --plan-id ID --json   # root
irlume login verify   --transaction-id ID --json
irlume login rollback --transaction-id ID [--apply] --json            # root to apply
```

**apply** re-derives the plan from the machine and recomputes its id. A
`plan_id` that no longer matches is refused as `plan-stale`: the consumer
displayed one set of changes and the machine now calls for another, so applying
would change something nobody was shown. The supplied id is never trusted as
input, only compared. On success it returns a `transaction_id`.

A partial apply is reported as a failure and still records its transaction, so
the surfaces that did change can be rolled back. The id is written to standard
error in that case, because an error document carries no `data`.

**verify** answers whether the machine is still as that transaction left it,
per surface: `as-applied`, `changed-since-apply`, or `unreadable`. It also
states `rollback_available`, so a consumer does not have to infer it from
per-surface states it may not recognise. Read-only.

**rollback** restores what the transaction changed, and **refuses unless every
surface is still exactly as apply left it**. Restoring a file something else has
edited since would revert a change the transaction never made, so drift stops
the whole rollback rather than skipping the drifted surface: a half-rolled-back
login stack is its own hazard. Every surface is checked before any is written.
Without `--apply` it reports what it would restore and touches nothing.

Transaction records live under the state directory, `0600` in a `0700`
directory. They contain the pre-change content of each file, which is not secret
(PAM stacks are world-readable) but does describe exactly how a machine
authenticates.

A transaction id is a 32-character hex string. Anything else is a `usage-error`,
rejected rather than sanitised, because the id becomes a filename.

Error codes: `plan-stale`, `changed-since-apply`, `not-found`,
`not-authorized` (apply and `rollback --apply` need root, checked before
anything is written rather than left to a write failing partway),
`operation-failed`.

## Security and privacy

Ordinary JSON output never includes camera frames, embeddings, templates,
passwords, credential material, TPM secrets, device paths, or usernames.
Errors contain stable codes instead of daemon prose.

The following are not part of contract version 1 yet and must not be inferred
from human output or the private socket protocol:

- enrollment event streams;
- preview images and cancellation semantics;
- profile or scan mutation;
- camera configuration mutation;
- enrollment preview images and their cancellation semantics.

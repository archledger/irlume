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
`recognized` is whether irlume maps this login manager to PAM services at all; an
unrecognized one cannot be targeted by `login enable`. `services` are the PAM
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

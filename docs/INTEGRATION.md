# Integrating with irlume

For people writing a settings panel, an installer, a status widget, or anything
else that drives irlume from another program. It covers how to call the engine,
what it promises, what it deliberately does not offer, and how to develop and
test without a face and a camera in the loop.

The contract itself, field by field, is [MACHINE-API.md](MACHINE-API.md). This
document is how to work with it.

## Call the machine API, never the human output

Every command has a human form and, where a machine needs it, a `--json` form.
The human form is written for a person reading a terminal: wording, column
widths and glyphs change when they read better. A consumer that greps it works
until the day it silently does not, and the failure looks like "irlume broke"
rather than "we parsed prose".

```sh
irlume status --json --contract 1
```

- Standard output carries exactly one JSON document, on one line.
- Diagnostics go to standard error. In machine mode it is normally empty.
- Exit 0 on success, 2 for a usage error or an unsupported contract, nonzero for
  a failed operation. The document says which; the exit code is for shells.

## The handshake

Call `irlume version --json` once at startup:

```json
{ "contract_version": 1, "engine_version": "0.8.1", "command": "version", "ok": true,
  "data": { "capabilities": ["version-json", "profiles-list-json", "status-json",
                             "doctor-json", "login-status-json", "auth-test-events",
                             "login-plan-json", "login-transactions", "models-list-json"],
            "contract_versions": { "min": 1, "max": 1 },
            "limits": { "max_profiles": 3 } } }
```

1. Pick a contract version inside `contract_versions` that your code implements,
   and pass it as `--contract N` on every later call. The engine refuses a
   version it does not implement before contacting the daemon and before any
   command with side effects begins.
2. Enable behaviour on the `capabilities` you recognize. Ignore names you do not
   know: the list grows, and an unknown name is a newer engine rather than a
   problem.
3. Ignore `engine_version` when deciding what to do. It is for support reports.

### Do not gate on the engine version

The tempting shortcut is a version test: match `0.6.x`, refuse anything else,
and be sure you are talking to something you tested. It fails on the first
release that changes nothing you use. The engine ships 0.7.0, your regex stops
matching, and your panel tells the user their working installation is
unsupported, entirely because someone else incremented a number.

Gate on `contract_versions` and `capabilities`. Both are promises about
behaviour. The version string is not.

## What contract 1 offers

Nine capabilities. Seven of them only read: they never enroll, wire PAM, write
to the system, or capture an image, and the camera facts in `status --json`
come from enumerating device nodes, not from opening a stream. The other two
are the exceptions a consumer should know before invoking them: `auth test
--events=jsonl` opens the camera for a live capture, and `login apply` (with
`login rollback --apply`) rewrites the PAM stack.

| Command | Capability | Answers |
|---|---|---|
| `irlume version --json` | `version-json` | capabilities, contract range, limits |
| `irlume status --json [--user U]` | `status-json` | daemon reachability, enrollment counts, keyring arming, recovery, camera capability |
| `irlume doctor --json` | `doctor-json` | every readiness check as an id and a state |
| `irlume profiles list --json [--user U]` | `profiles-list-json` | profile and scan display names, per-user liveness flags |
| `irlume login status --json` | `login-status-json` | which PAM surfaces carry face auth |
| `irlume models list --json` | `models-list-json` | every pipeline stage's model candidate, and the third-party state of the open stages |
| `irlume auth test --events=jsonl` | `auth-test-events` | does the caller's live face match its own enrolment, as a stream of events; captures from the camera, releases nothing |
| `irlume login plan --action A --json` | `login-plan-json` | what `login enable` or `disable` would change, without changing anything |
| `irlume login apply` / `verify` / `rollback` | `login-transactions` | carry out, check, and undo a planned PAM change; `apply` and `rollback --apply` write to the system and need root, `verify` only reads |

Three rules run through all of them:

**Unknown is not zero, and unknown is not failure.** Anything derived from the
daemon carries `known`, and when it is false the counts are absent rather than
`0`. A consumer that renders "could not find out" as "nothing enrolled" tells
users to enroll a face they already have. `doctor` states work the same way:
`unknown` means the check could not run, not that it found a problem.

**Lists are complete.** Every doctor check reports on every run, and every PAM
surface irlume can wire appears in `login status` even when the service does not
exist on that machine. So an id you know about and cannot find means this engine
version does not have it, not that it is fine.

**`detail` and display names are not identifiers.** `detail` is English for a
support report, and it changes. Profile display names are whatever the user
typed. Key off `id`, `state`, and the booleans.

## What contract 1 does not offer, and what to do instead

- **One mutation, and only that one.** `login apply` and `login rollback
  --apply` (capability `login-transactions`) rewrite the PAM stack, and only
  after re-deriving a plan the consumer displayed. No machine command enrolls,
  deletes a profile, or changes any other configuration; those actions run
  through the human CLI, where the user sees what is being changed. Launch it,
  or tell the user the command.
- **No push.** `auth test --events=jsonl` streams events, but only to the
  invocation that asked for them; nothing in contract 1 pushes state changes
  to an idle consumer. Poll `status --json` when your window is visible.
- **No cancellation.** Terminating the process is the cancellation mechanism for
  this contract version.
- **No D-Bus service and no client library.** The CLI plus JSON keeps a frontend
  defect out of both the root daemon and the PAM-loaded process, and it works
  the same from C++, Rust, Python or a shell script. Spawning a subprocess and
  validating one JSON document is a small amount of code in any of them.

If you need one of these, open an issue describing the interaction, not the
mechanism. What a frontend actually needs decides whether the answer is a new
capability, a new contract, or a different transport.

## Authorization

The daemon authorizes every operation from the connecting process's credentials,
not from anything the caller claims. An operation is permitted for `root` or for
the user that owns the records. `--user` names which account to act on; it grants
nothing.

Do not pre-check whether the user may do something. Call the command and read the
error: `not-authorized` says nothing about whether the named account exists, so
this path cannot be used to enumerate accounts either.

Do not run irlume as root to "make it work". A settings panel calling as the
logged-in user is the intended shape.

## Validating what you receive

irlume publishes a JSON Schema (2020-12) for contract 1:

- in the source tree: `schemas/machine-api-v1.schema.json`
- on an installed system: `/usr/share/irlume/schemas/machine-api-v1.schema.json`

Validate against the copy the installed engine shipped. **Do not reject unknown
properties.** Fields may be added within a contract version, so a strict
validator turns a permitted engine update into a broken panel.

`scripts/machine-api-conformance.py` checks a build the way a consumer would:
envelope rules, every advertised capability actually answering, and the refusals
behaving. Point it at whichever irlume versions you claim to support, in your own
CI:

```sh
python3 scripts/machine-api-conformance.py --irlume /usr/bin/irlume
```

It needs Python 3 and `jsonschema` (Fedora and Debian `python3-jsonschema`, Arch
`python-jsonschema`). Without the validator it still runs the structural checks
and tells you which checks it skipped. Pass `--strict` in a pipeline: it refuses
to run at all without a validator, so a missing dependency fails the job instead
of turning into a green run that checked less than you think.

## Developing without a camera, a TPM, or a face

`schemas/fixtures/v1/` holds documents captured from a real engine, including the
daemon-unreachable and refusal cases. Build your rendering and error paths
against those: they are what irlume writes, which hand-written fixtures reliably
are not.

For a live engine without touching the real installation, run your own daemon on
your own socket. Every privileged path is redirectable, and the full table is in
[DEVELOPMENT.md](DEVELOPMENT.md#sandbox-environment-overrides):

```sh
export IRLUME_SOCKET=$XDG_RUNTIME_DIR/irlume-dev.sock
export IRLUME_STATE_DIR=$PWD/dev/state
export IRLUME_KEYRING_DIR=$PWD/dev/keyring
export IRLUME_RECOVERY_DIR=$PWD/dev/recovery
export IRLUME_TEMPLATE_KEY_DIR=$PWD/dev/template-keys
```

Cameras can be v4l2loopback devices fed by ffmpeg, and the TPM can be swtpm via
`IRLUME_TCTI`; DEVELOPMENT.md carries both recipes, and irlume's own CI runs that
way.

**Point these at your own daemon instance only.** The camera-substitution knobs
are safe because the production daemon's environment is set by its systemd unit,
which an unprivileged user cannot change, and every use is logged loudly. Setting
them for a process that authenticates real logins removes that property. A
sandbox daemon on a socket of your own is the supported shape; a test knob aimed
at `/run/irlume.sock` is not.

## Reporting a problem

Include the output of `irlume doctor --json` and `irlume version --json`. Neither
contains camera frames, embeddings, templates, passwords, TPM secrets, device
paths, or usernames, so both are safe to attach to a public issue.

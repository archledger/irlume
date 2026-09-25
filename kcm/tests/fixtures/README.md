# KCM page-test fixtures

Machine-API documents for `kcm_pagetest`, one directory per set. Each
directory holds `version.json`, `status.json`, `doctor.json`,
`census.json` and `login.json`, named after the bridge's request names; a
`<name>.fail.txt` instead makes the stand-in module report that request as
failed, with the file's first line as the reason.

These are synthetic documents owned by the module. `real` follows an
unprivileged run of the four commands on a Fedora 44 laptop with an RGB and
IR camera pair; the other sets change it:

| Set | What it covers |
|---|---|
| `real` | a healthy machine, as an ordinary account sees it |
| `unreachable`, `starting`, `access-denied` | each daemon state other than running |
| `key-missing` | encrypted templates without their sealed key, an RGB-only camera |
| `refused` | typed refusals: `daemon-unavailable` (retryable), `not-authorized` (see below) |
| `failure` | requests that produce no document |
| `empty` | no checks, no cameras, no login manager, no surface present |
| `short` | documents without the lists the pages read |
| `edge` | a failing check, an undetermined check without detail, a check state the module does not know, a camera row without a node, a closed privacy shutter, an unrecognized login manager, a service without a surface entry, no SELinux field, values from a newer engine |
| `long` | long identifiers, details and notes |

The `refused` set is deliberately not something a real engine sends:
`status` reports an unreachable daemon as data and `camera census` runs
without the daemon, so neither refuses with `daemon-unavailable`. The set
exists to exercise the refusal path and its Retry action on every page.

The contract's own fixtures in `schemas/fixtures/` are captured from a real
engine and are not edited by hand; these are not a substitute for them.

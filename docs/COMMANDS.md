# Command reference

Every irlume command on one page. `irlume help` prints the short version of
this list in the terminal; this page adds the flags and the sudo requirements.

Conventions that apply everywhere:

- Commands act on the current user by default. `--user U` overrides that
  (managing another account needs root).
- Commands that change system state (PAM wiring, SELinux, camera config,
  the daemon) need `sudo`; the tables below mark them. Everything else runs
  as your own user.
- Commands that turn the camera on (`enroll`, `profiles add-scan`,
  `identify`, `auth test`, `camera diagnostics`, and the TUI's framing guide
  and recognition test) run as your own user only from the session that is
  active on a seat: the desktop or text console you are logged in at, as
  for the camera device itself. From an SSH login, or a session that is not
  the active one on its seat, irlumed refuses them; run them from the active
  session, or with `sudo`. When irlumed cannot read logind's seat state, only
  root can turn the camera on. Status, listing and settings commands are not
  affected.
- `irlume tui` wraps most of these in a guided interface. If you forget a
  command, the TUI is the fallback: enrollment, profiles, wiring, keyring,
  recovery, and fingerprint are all reachable from it.
- Several commands take `--json` for machine-readable output (marked per row
  below). Integrations also declare the contract version they implement with
  `--contract N` anywhere in the invocation; omitted always means 1, and an
  unimplemented one is refused before anything runs. The stable shapes are
  specified in [MACHINE-API.md](MACHINE-API.md).

## Setup and status

| Command | What it does |
|---|---|
| `irlume tui` | guided setup + live dashboard; enroll and configure here. `--page P` starts on a named screen (`overview`, `diagnostics`, `cameras`, `faces`, `wallet`, `recovery`, `fingerprint`, `login`, `settings`); `--new` skips the single-instance guard |
| `irlume setup` | scripted onboarding: enroll, keyring, recovery, PAM wiring, each step prompted y/N |
| `irlume status` | health dashboard: daemon, enrollment, keyring, cameras; `status --json` uses the read-only public [machine API](MACHINE-API.md) |
| `irlume detect` | script-friendly probe; exit `0` = ready, `10` = partial, `20` = absent |
| `irlume doctor` | platform checks in one pass: TPM, Secure Boot, camera, models, polkit app prompts, login-keyring lock state + provider (ksecretd/kwalletd/gnome-keyring/oo7-daemon), the authselect/pam-auth-update regeneration guard, the pam_faillock tally for the target account (root-only; warns above the threshold with the reset remedy), a GNOME keyring token armed on a release whose next upgrade does not carry it over (Fedora 43 or 44, before Fedora 45), what protects the account's sealed keyring secret and template key at rest (whether irlume's state directory is on dm-crypt encryption, and whether a sealed secret's policy covers the boot loader, PCR 4), camera-group health, and install hygiene (leftover backup files next to the managed binaries, hand-installed builds overlaying the packaged ones); `doctor --json` uses the read-only public [machine API](MACHINE-API.md) |
| `irlume deps` | verify runtime dependencies (onnxruntime, models, TPM) |
| `irlume version` | print the installed version (`--version` / `-V` also work); `version --json` uses the public [machine API](MACHINE-API.md) |
| `irlume auth sensor <status\|preflight [user]\|dual\|ir-only --yes>` | inspect or select the machine-wide face sensor policy. `ir-only --yes` is a root-only experimental opt-in; `dual` restores the default. `preflight` is camera-free and reports prerequisites only, never capture success, login readiness, or qualification |
| `irlume auth consent <status\|required\|hands-free --yes>` | privileged-prompt consent policy (ADR-0018): `required` (default) asks for the literal `yes` before a face attempt on sudo/polkit-class services; `hands-free --yes` is the root-only owner opt-out that waives it |

## Enrollment and profiles

| Command | What it does |
|---|---|
| `irlume enroll [--name N] [--scans K] [--reset] [--add-camera] [--camera-choice JSON]` | capture a face profile; `--reset` replaces profiles and camera binding after successful capture, keeping the template key and recovery setup. `--add-camera` (ADR-0024) enrolls a SECOND camera as its own group with a separate store: the daemon measures the new pair and the existing enrollment is untouched. `--camera-choice` uses an explicitly guarded ordinary pair for this operation, preserving the standing pair and `cameras.conf` |
| `irlume profiles` (or `profiles list`) | list profiles and their scans; `profiles list --json` uses the read-only public [machine API](MACHINE-API.md) |
| `irlume profiles add-scan --profile P [--scans N]` | add scans to profile P: improves recognition in new conditions, and adds templates for a second recognizer without re-enrolling as a new person (scans belong to the recognizer the daemon has loaded). If authentication reports no scans for the current recognition model, add scans to an existing profile; retained scans from other models are preserved |
| `irlume profiles remove-camera --group ID` | remove one enrolled camera group (its store and scans); the primary enrollment and other groups are untouched. Find the group ID in `profiles list`, which shows every enrolled camera |
| `irlume profiles rename --profile P [--scan S] --name N` | rename a profile, or one scan inside it |
| `irlume profiles delete --profile P [--scan S]` | delete a profile, or one scan inside it |
| `irlume profiles forget-model <model>` | remove one recognizer's scans (and the calibrations fitted from them) from every profile of a user. `<model>` is `shipped` or an `embed:<sha256>` tag as `profiles list` prints it (used to clean scans left by the removed third-party lane, ADR-0015). A profile left with no scans is deleted with them |
| `irlume profiles eyes-open off` | one-release migration command: clear a stored legacy eyes-open blocker. It cannot be turned on |
| `irlume identify` | 1:N "who is this?"; as root it checks all users, otherwise scoped to you |

## Keyring, TPM, and recovery

| Command | What it does |
|---|---|
| `irlume keyring <arm\|status\|forget>` | TPM-sealed secret so a login also unlocks the wallet/keyring. What is sealed depends on the backend: the login password, the KDE wallet key, or a random token this re-keys a GNOME keyring to. `status` names which. On Fedora 43 or 44, `arm` and `status` tell a token arm to run `forget` before upgrading to Fedora 45, where `arm` then seals the login password, which oo7 accepts. `forget` re-keys a token back and takes `--force` to skip that. `arm` refuses a token, before sealing, when the active login screen's PAM stack has no irlume session line (run `login enable --apply` first) or the account logs in automatically. On NixOS only the login password is sealed, and `arm` refuses an account that has or would get either other kind ([NIXOS.md](NIXOS.md)) |
| `irlume reseal` | re-bind the sealed secret to the current PCRs after a firmware or kernel update; prompts for the password, safe to re-run. It re-binds the kind that is armed (a login password or a KDE wallet key). A GNOME keyring token re-binds itself on the next password login, so this reports that and does nothing. On NixOS it re-binds only a login password and refuses a KDE wallet key or a GNOME keyring token, as `keyring arm` does ([NIXOS.md](NIXOS.md)) |
| `irlume recovery <status\|setup\|restore\|forget>` | recovery passphrase + profile encryption |
| `irlume retry <status\|reset> [--user U]` | face-attempt retry throttle: `status` shows the failure budget and cooldown state (and the separate reset-password budget); `reset` clears the tally for your own account (root can pass `--user` for any account). Does not touch the pam_faillock OS counter; `irlume doctor` reports that one |
| `irlume diag` | Separate keyring-credential and face-template-key seal/PCR-drift diagnostics; run with `sudo` for full detail |

## System integration

| Command | Sudo | What it does |
|---|---|---|
| `irlume login <status\|enable\|disable\|reconcile> [--with-sudo] [--with-polkit] [--apply] [--force] [--adjust-jumps]` | yes | PAM wiring for the greeter and lock screen; `--with-sudo` adds face-`sudo`, `--with-polkit` adds app prompts (Bitwarden unlock, pkexec; see docs/APP-INTEGRATION.md); `reconcile` re-applies the wiring after a distro PAM regeneration and keeps irlume's `/etc/pam.d` copies of vendor PAM files in step with them (also run by the `irlume-reconcile.path` unit and timer); without `--apply` it previews; `enable --force` rebuilds those copies from the vendor file even when they have lines irlume did not write, keeping each previous file as `<file>.pre-irlume` (the preview lists them, and a different `.pre-irlume` already there stops it); `enable` keeps face and fingerprint off LightDM, leaving only the keyring hand-off, while its XDMCP or VNC server is on, since those serve login screens to remote users; `disable`, and an `enable` that would unwire a login screen delivering it, refuse while an account's GNOME keyring is keyed to an irlume token, since the session line they remove delivers that token, and `--force` goes ahead anyway; `enable` exits 1 when a service asked for with `--with-sudo` or `--with-polkit` is missing or has no line irlume can wire next to, or when irlume's lines in one of those copies are left as they were (or not added) because that would move a numeric jump or cross a line you added, and `enable` and `disable` exit 1 when they keep a PAM file as it is because it has a line irlume does not read as PAM does, which they name ([DISABLE.md](DISABLE.md)); when only a numeric jump of yours in such a copy is in the way, such as `[success=1 default=ignore] pam_fprintd.so` right above the password substack, it says how `--adjust-jumps` would change that line, naming it by its number and quoting no line, so that each jump skips the same lines of yours and lands on the same line (the success of a `pam_fprintd.so` line: on irlume's `pam_permit.so` landing, here `success=2`), and `enable --adjust-jumps` writes it with irlume's lines; where a run takes irlume's lines out of such a copy (`disable`, or an `enable` on a login or lock screen its configuration no longer wants wired) and a numeric jump of yours counts them or lands on one of them, it leaves inactive lines in their places and prints what the same command with `--adjust-jumps` does instead: remove them, lowering a jump that counts them, or moving a landing off a line of irlume's it takes out to the first line after them; where irlume cannot show that the jumps keep their landings (a jump across an `include`, an `include` above irlume's lines whose stack has a jump that could land past its end or on the auth line irlume adds right after it, or a `substack` whose file irlume cannot read as PAM does), the flag keeps the file or the inactive lines, as without it; over the inactive lines a `disable` without the flag left, `enable` says to run `disable --adjust-jumps` and then `enable --adjust-jumps`, or why that disable would keep them too; `login status --json` uses the read-only public [machine API](MACHINE-API.md). On NixOS `enable` and `disable` refuse and `reconcile` does nothing: the module owns PAM ([NIXOS.md](NIXOS.md)) |
| `irlume logs [-f] [--since T]` | sometimes | the face-auth journal in one view (daemon, PAM, keyring); `-f` follows live, `--since "10 min ago"` widens the window |
| `irlume support-report [--output FILE.txt] [--since 10m] [--probe]` | only for `--probe` | create a mode-0600, no-replace, inspect-before-sharing report from structurally share-safe facts. The default is read-only and never opens a camera; `--probe` explicitly performs one bounded daemon-owned capture. `support-report --json [--since N] [--contract 1]` emits the same privacy-bounded object as the machine API (`support-report-json` capability) instead of writing a file; `--json` does not combine with `--output`/`--probe` |
| `sudo irlume trace [record] [--duration 60s] [--output FILE.jsonl]` | yes | record one root-authorized, non-persistent typed diagnostic stream (default 60s; cap 5m/50,000 events/16 MiB). One subscriber; no frames, embeddings, credentials, identities, or raw emitter payloads. A final file is published only after a clean terminal record |
| `irlume trace explain FILE.jsonl [--output FILE.txt]` | no | validate a complete trace offline and render its typed timeline grouped by daemon-generated operation ID; malformed, oversized, sequence-gapped, or truncated traces are refused |
| `irlume logs debug <on\|off>` | yes | legacy persistent journal tracing. Still compatible, but new investigations should use bounded `irlume trace` so the daemon is not restarted and tracing cannot be left enabled |
| `irlume fingerprint <status\|add\|verify\|reset\|enable\|disable> [--fingerprint-only]` | for wiring | fprintd companion; `enable` = unlock with face OR fingerprint (both), `--fingerprint-only` replaces face |
| `irlume bitwarden <status\|setup> [--apply]` | for setup | install Bitwarden's biometric-unlock polkit action, flavor-aware (flatpak/native install it; snap is snapd's job; ostree gets the layering steps); see docs/APP-INTEGRATION.md |
| `irlume selinux <status\|load>` | for load | SELinux module for the login greeter (Fedora) |
| `sudo irlume biopolicy <on\|off\|status>` | for on/off | opt-in operation-class enforcement for IR verification; off by default. Independently, RGB-only face is always limited to recognized live-session screen unlock: login, sudo, polkit and credential release refuse. See [support boundaries](PLATFORMS.md#v0140-behavior-and-support-boundaries) |
| `irlume ir-setup [--dry-run]` | yes | configure the IR emitter; rarely needed, and only ever run when you ask. Writes to the camera, so read the warning in SETUP.md. `--dry-run` lists the camera's extension units and writes nothing |
| `irlume set-cameras <rgb> <ir>` | yes | persist the RGB+IR camera pair, e.g. `/dev/video0 /dev/video2`; the TUI camera picker runs this for you |
| `irlume camera-tune [--rounds N] [--emit-record FILE] [--verify-record FILE]` | yes | qualify the daemon's exact RGB+IR pair, accepted stream contracts, USB connection, delivered rates, continuity, illumination provenance, and concurrent signal retention. The versioned record selects concurrent only for that exact context; missing or changed evidence stays sequential. A successful explicit tune also clears this daemon generation's runtime degradation breaker. `--emit-record FILE` writes the share-safe measurement evidence (not a camera profile; ADR-0023), `--verify-record FILE` checks a record against the machine |
| `irlume camera-mode` | no | ask the daemon which schedule is active for its exact open pair. Reports qualified concurrent, measured sequential and its reason, no authority, changed/unreadable context, an environment override, or generation-scoped runtime degradation and its cause. It also prints the exact requested/accepted stream and USB context used by v2. RGB-only hosts report `no_ir_pair` without trying to open IR. The CLI does not read legacy `capture_mode.*` entries from `cameras.conf` or open cameras itself |
| `irlume camera census [--json]` | no | classify every camera-like device on the machine (UVC RGB/IR pairs, metadata-only nodes, Y8-only sensors, dummies, MIPI pipelines and bridges, unreadable nodes, USB camera-class devices with no driver), printing the evidence each classification keyed on (#575). `--json` is the machine API document; the hardware-report template asks for it as an attachment |
| `irlume camera diagnostics --json` | no | machine-readable delivered-rate evidence for the configured pair: exact requested/accepted/delivered rationals per role, sequence gaps and drops, timestamp clock/source, RGB/IR skew, and the MS-XU illumination stream state (node present/absent, frames classified/lit, ambient observed). An under-rate stream is a measured `fail` object, never prose. See [MACHINE-API.md](MACHINE-API.md) |
| `irlume models list --json` | no | the one surviving models subcommand (ADR-0015): the machine model listing. All other models subcommands are removed and answer with a notice. Check installed weights with `irlume doctor` |
| `irlume update [--check]` | for install | update via the channel irlume was installed from (Copr/PPA: runs it; .deb/pkg/source: shows the steps); `--check` only reports |
| `irlume uninstall [--keep-data] [--yes]` | yes | un-wire PAM first (lockout-safe order), stop the daemon, sweep the stale socket, the `/etc/systemd/system` unit copies and enabled timer, the kernel-loaded AppArmor profile, and per-user XDG state; wipe enrolled data unless `--keep-data`, evict the persisted TPM storage root key after a fully completed wipe (kept with `--keep-data` or an incomplete wipe; a non-irlume key at the handle is never touched), name the Bitwarden polkit leave-behind if present, then print the package-removal command |

## Split camera authorizations

`irlume split --help` prints the full syntax without contacting the daemon.
These commands manage the authorization store described by ADR-0032; they
do not enable split-pair enrollment or authentication.

| Command | Sudo | What it does |
|---|---|---|
| `irlume split list` | for full facts | list saved authorizations and current role-classified candidate sides, including when the store is empty |
| `irlume split status` | yes | report store state, record count, referenced generation and selection resolution; a digest failure still names its generation |
| `irlume split add --guard JSON --rgb JSON --ir JSON` | yes | add or replace an authorization using the exact displayed publication and per-side guards |
| `irlume split remove 'PAIRKEY'` | yes | remove an authorization without requiring its cameras to remain connected |
| `irlume split select 'PAIRKEY' --guard JSON` | yes | select an authorized pair after checking its displayed incarnations and facts |
| `irlume split select --clear --guard JSON` | yes | clear the selection using the displayed guard |

Root listings include each saved record's canonical `key` for `select` and
`remove`; non-root listings omit it. Split listings use a bounded 1 MiB socket
reply envelope to accommodate JSON escaping of the 64 KiB generation store.

Start with `sudo irlume split list`. Its `candidates` entries carry `role`,
`guard` and `facts.Root`. Copy the RGB and IR guards, unchanged, into:

```json
{"supervisor_id":"<displayed supervisor>","revision":7,"rgb":{"instance_id":"<displayed RGB instance>","generation":1,"endpoint":"/dev/video0"},"ir":{"instance_id":"<displayed IR instance>","generation":2,"endpoint":"/dev/video1"}}
```

Pass each side's `facts.Root` object as `--rgb` or `--ir`:

```json
{"identity":"5986:2113:serial,with,commas","path":"/dev/video0","controller":"0000:00:14.0","domain":"usb2","ports":[8]}
```

Use the actual listing values, not the example IDs or revisions. Quote JSON
and canonical pair keys in the shell. JSON preserves commas, quotes and
Unicode in serials. Both `--name VALUE` and `--name=VALUE` work. A stale
listing refuses; obtain a fresh listing and confirm again rather than
silently refreshing a previously confirmed guard. Non-root listings contain
endpoint tokens and projections, not raw paths or binding identities.

The commands refuse on an older daemon; they never substitute `set-cameras`.
`split` does not expose the versioned machine API: `--json` and `--contract`
are rejected before sending a request.

## TUI access

Open **Irlume** from your desktop's application menu or run `irlume tui`. The desktop
entry uses your desktop's terminal launcher and starts as your account.
F3 chooses a section, F4 opens Current observations, F6 focuses page actions,
and Shift+L opens detailed session history. The observations panel shows each
source's age and availability; session history records earlier activity.
Administrator access remains attached to the individual action.

Press **F2** in the TUI to search additional CLI tasks, fill their options, and
review the account and effects before running them. See the [workflow and parity
reference](TUI.md), including multi-person profiles and appearance scans.

## Developer and benchmark tools

Hidden unless `IRLUME_DEV=1` is set, because they open the camera directly and
bypass the daemon. Not needed for normal use.

`capture`, `eval`, `irbench`, `genuine`, `calcapture`, `normprobe`,
`liveness`, `selftest align`, `padcapture`, `padreport`, `verify`,
`enrolldev`, `suncal`

Each prints its own usage line when run without arguments. `padcapture` /
`padreport` are the presentation-attack self-test pair documented in
[PAD_SELFTEST.md](PAD_SELFTEST.md); `suncal` is the outdoor/sunlight
calibration analyzer.

Two diagnostics are NOT dev-gated: `irlume selftest liveness` (goes through
the daemon; the TUI ships it as Diagnostics -> Test Infrared Camera) and the
`irlume detect` probe above.

## Where to go next

- First-time setup, step by step: [SETUP.md](SETUP.md)
- Versioned JSON for desktop integrations: [MACHINE-API.md](MACHINE-API.md)
- Reading scores, gate reasons, and PAM decisions: [DEBUGGING.md](DEBUGGING.md)
- NixOS module instead of imperative wiring: [NIXOS.md](NIXOS.md)

### Authorization before enrollment

`--camera-choice` is a low-level ordinary-pair socket option (ADR-0029 section 3).
Its JSON contains `rgb`, `ir` and `expected`, where `expected` is the unchanged
`CameraSelection` guard copied from one displayed `LiveStatus` candidate:

```json
{"rgb":"/dev/video0","ir":"/dev/video1","expected":{"supervisor_id":"11111111111111111111111111111111","candidate":{"instance_id":"22222222222222222222222222222222","generation":7,"endpoint_paths":["/dev/video0","/dev/video1"]}}}
```

Use actual displayed IDs, generation and endpoints, not these example values.
The daemon verifies current roles, ordinary class and external-camera policy
before probe, preflight or capture. A stale or wrong-role choice refuses; it
does not select another camera. Quote the JSON in the shell. Missing, repeated
or malformed values are usage errors before a request is sent.

For an existing enrollment, non-reset capture requires the same complete
primary binding. To use a different camera, explicitly add a camera group or
reset after authorization. The old commands without this option retain their
behavior. An older daemon reports that operation-scoped choice needs an upgrade;
the client does not retry a legacy enrollment or persist a camera pin. Guided
session choices and split enrollment remain separate work. This option does not
extend the public machine `--json` contract.

Adding or replacing trusted faces requires OS authorization for a non-root account owner. This covers `enroll`, `enroll --reset`, and `profiles add-scan`, including the guided TUI and direct socket clients. Each request needs its own authorization; root retains administrative access. A successful replacement preserves the existing template key and recovery setup, and failed capture preserves the old enrollment.

Removing a whole profile (`profiles delete --profile ...` without `--scan`) or
a recognizer's face data (`profiles forget-model`) also requires the
`org.irlume.enroll` approval, including the TUI and direct socket clients.
Removing the final profile also removes the added cameras' store
(`cameras/<user>.json`, ADR-0024) and retires the template key and recovery
passphrase.
Denied or cancelled approval leaves the enrollment and recovery files unchanged.
Deleting individual scans and renaming profiles/scans keep their existing behavior;
a profile's final scan cannot be deleted individually. Root retains administrative
access. These approval checks require the updated daemon; an older daemon does not
enforce them even when called by a newer client.

Setting, replacing or erasing a recovery passphrase (`recovery setup` and
`recovery forget`) also requires OS authorization for non-root users, including
TUI and direct socket requests. The dialog identifies the account and operation;
no recovery passphrase is sent to polkit. Root retains administrative access.
The separate `org.irlume.recovery-manage` action ships with the package. If the
action is missing, repair the Irlume policy installation; terminal users can
register a `pkttyagent` when no desktop agent is available. Administrator polkit
rules can override the shipped authentication requirement.

`recovery restore` still verifies the existing recovery passphrase and reseals
the template key without a new OS approval requirement. It does not reset retry
history or override other face-authentication checks. OS authorization for
recovery management does not attest which authentication factor was used.
Older clients can use the new daemon with an available authorization agent;
older daemons, including after a binary rollback, do not enforce this new gate.
Rollback leaves recovery envelopes and retry records intact.

Install polkit and run a desktop authentication agent. For terminal sessions, register `pkttyagent` for the requesting process/session before enrollment or profile/model removal. Missing authority or agent, denial, cancellation and expired approval refuse the operation. The dialog uses configured OS authentication, which may include an existing face or fingerprint. The shipped policy does not retain approvals; administrator policy overrides remain authoritative.

The daemon enforces this rule. Restart into the updated daemon after upgrading; a new client with an older running daemon does not provide this protection. Older clients can meet the new dialog but retain their shorter reply timeout.

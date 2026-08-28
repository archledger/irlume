# Command reference

Every irlume command on one page. `irlume help` prints the short version of
this list in the terminal; this page adds the flags and the sudo requirements.

Conventions that apply everywhere:

- Commands act on the current user by default. `--user U` overrides that
  (managing another account needs root).
- Commands that change system state (PAM wiring, SELinux, camera config,
  the daemon) need `sudo`; the tables below mark them. Everything else runs
  as your own user.
- `irlume tui` wraps most of these in a guided interface. If you forget a
  command, the TUI is the fallback: enrollment, profiles, wiring, keyring,
  recovery, and fingerprint are all reachable from it.

## Setup and status

| Command | What it does |
|---|---|
| `irlume tui` | guided setup + live dashboard; enroll and configure here |
| `irlume setup` | scripted onboarding: enroll, keyring, recovery, PAM wiring, each step prompted y/N |
| `irlume status` | health dashboard: daemon, enrollment, keyring, cameras; `status --json` uses the read-only public [machine API](MACHINE-API.md) |
| `irlume detect` | script-friendly probe; exit `0` = ready, `10` = partial, `20` = absent |
| `irlume doctor` | platform checks in one pass: TPM, Secure Boot, camera, models, polkit app prompts, login-keyring lock state + provider (ksecretd/kwalletd/gnome-keyring), the authselect/pam-auth-update regeneration guard, and install hygiene (leftover backup files next to the managed binaries, hand-installed builds overlaying the packaged ones); `doctor --json` uses the read-only public [machine API](MACHINE-API.md) |
| `irlume deps` | verify runtime dependencies (onnxruntime, models, TPM) |
| `irlume version` | print the installed version (`--version` / `-V` also work); `version --json` uses the public [machine API](MACHINE-API.md) |

## Enrollment and profiles

| Command | What it does |
|---|---|
| `irlume enroll [--name N] [--scans K] [--reset]` | capture a face profile; `--reset` starts the profile space over |
| `irlume profiles` (or `profiles list`) | list profiles and their scans; `profiles list --json` uses the read-only public [machine API](MACHINE-API.md) |
| `irlume profiles add-scan --profile P [--scans N]` | add scans to profile P: improves recognition in new conditions, and adds templates for a second recognizer without re-enrolling as a new person (scans belong to the recognizer the daemon has loaded) |
| `irlume profiles rename --profile P [--scan S] --name N` | rename a profile, or one scan inside it |
| `irlume profiles delete --profile P [--scan S]` | delete a profile, or one scan inside it |
| `irlume profiles forget-model <model>` | remove one recognizer's scans (and the calibrations fitted from them) from every profile of a user. `<model>` is `shipped` or an `embed:<sha256>` tag as `profiles list` prints it (used to clean scans left by the removed third-party lane, ADR-0015). A profile left with no scans is deleted with them |
| `irlume profiles eyes-open off` | one-release migration command: clear a stored legacy eyes-open blocker. It cannot be turned on |
| `irlume identify` | 1:N "who is this?"; as root it checks all users, otherwise scoped to you |

## Keyring, TPM, and recovery

| Command | What it does |
|---|---|
| `irlume keyring <arm\|status\|forget>` | TPM-sealed secret so a login also unlocks the wallet/keyring. What is sealed depends on the backend: the login password, the KDE wallet key, or a random token this re-keys a GNOME keyring to. `status` names which; `forget` re-keys a token back and takes `--force` to skip that |
| `irlume reseal` | re-bind the sealed secret to the current PCRs after a firmware or kernel update; prompts for the password, safe to re-run. A GNOME keyring token re-binds itself on the next password login, so this reports that and does nothing |
| `irlume recovery <status\|setup\|restore\|forget>` | recovery passphrase + profile encryption |
| `irlume diag` | Separate keyring-credential and face-template-key seal/PCR-drift diagnostics; run with `sudo` for full detail |

## System integration

| Command | Sudo | What it does |
|---|---|---|
| `irlume login <status\|enable\|disable\|reconcile> [--with-sudo] [--with-polkit] [--apply]` | yes | PAM wiring for the greeter and lock screen; `--with-sudo` adds face-`sudo`, `--with-polkit` adds app prompts (Bitwarden unlock, pkexec; see docs/APP-INTEGRATION.md); `reconcile` re-applies the wiring after a distro PAM regeneration (also run by the `irlume-reconcile.path` unit); without `--apply` it previews; `login status --json` uses the read-only public [machine API](MACHINE-API.md) |
| `irlume logs [-f] [--since T]` | sometimes | the face-auth journal in one view (daemon, PAM, keyring); `-f` follows live, `--since "10 min ago"` widens the window |
| `irlume support-report [--output FILE.txt] [--since 10m] [--probe]` | only for `--probe` | create a mode-0600, no-replace, inspect-before-sharing report from structurally share-safe facts. The default is read-only and never opens a camera; `--probe` explicitly performs one bounded daemon-owned capture |
| `sudo irlume trace [record] [--duration 60s] [--output FILE.jsonl]` | yes | record one root-authorized, non-persistent typed diagnostic stream (default 60s; cap 5m/50,000 events/16 MiB). One subscriber; no frames, embeddings, credentials, identities, or raw emitter payloads. A final file is published only after a clean terminal record |
| `irlume trace explain FILE.jsonl [--output FILE.txt]` | no | validate a complete trace offline and render its typed timeline grouped by daemon-generated operation ID; malformed, oversized, sequence-gapped, or truncated traces are refused |
| `irlume logs debug <on\|off>` | yes | legacy persistent journal tracing. Still compatible, but new investigations should use bounded `irlume trace` so the daemon is not restarted and tracing cannot be left enabled |
| `irlume fingerprint <status\|add\|verify\|reset\|enable\|disable> [--fingerprint-only]` | for wiring | fprintd companion; `enable` = unlock with face OR fingerprint (both), `--fingerprint-only` replaces face |
| `irlume bitwarden <status\|setup> [--apply]` | for setup | install Bitwarden's biometric-unlock polkit action, flavor-aware (flatpak/native install it; snap is snapd's job; ostree gets the layering steps); see docs/APP-INTEGRATION.md |
| `irlume selinux <status\|load>` | for load | SELinux module for the login greeter (Fedora) |
| `sudo irlume biopolicy <on\|off\|status>` | for on/off | the operation-class gate: when ENFORCING, a face match is accepted only for the operations its camera tier is trusted for (login and sudo require the Secure IR tier; screen unlock and app prompts stay allowed); off by default, and the password is always available either way |
| `sudo irlume credential-release-challenge [<service>] <on\|off\|status>` | for on/off | with a privileged service (`sudo`, `su`, `doas`, `polkit-1`), toggles an additional experimental head gesture (nod to approve, shake to decline). It defaults off and never replaces the mandatory hidden `yes` PAM confirmation; enabling warns about false rejects, while disabling needs no risk confirmation. Bare, it toggles the separate default-off gesture before releasing the login-keyring credential |
| `irlume ir-setup [--dry-run]` | yes | configure the IR emitter; rarely needed, and only ever run when you ask. Writes to the camera, so read the warning in SETUP.md. `--dry-run` lists the camera's extension units and writes nothing |
| `irlume set-cameras <rgb> <ir>` | yes | persist the RGB+IR camera pair, e.g. `/dev/video0 /dev/video2`; the TUI camera picker runs this for you |
| `irlume camera-tune [--rounds N]` | yes | qualify the daemon's exact RGB+IR pair, accepted stream contracts, USB connection, delivered rates, continuity, illumination provenance, and concurrent signal retention. The versioned record selects concurrent only for that exact context; missing or changed evidence stays sequential. A successful explicit tune also clears this daemon generation's runtime degradation breaker |
| `irlume camera-mode` | no | ask the daemon which schedule is active for its exact open pair. Reports qualified concurrent, measured sequential and its reason, no authority, changed/unreadable context, an environment override, or generation-scoped runtime degradation and its cause. It also prints the exact requested/accepted stream and USB context used by v2. RGB-only hosts report `no_ir_pair` without trying to open IR. The CLI does not read legacy `capture_mode.*` entries from `cameras.conf` or open cameras itself |
| `irlume camera census [--json]` | no | classify every camera-like device on the machine (UVC RGB/IR pairs, metadata-only nodes, Y8-only sensors, dummies, MIPI pipelines and bridges, unreadable nodes, USB camera-class devices with no driver), printing the evidence each classification keyed on (#575). `--json` is the machine API document; the hardware-report template asks for it as an attachment |
| `irlume models …` | — | removed (ADR-0015): third-party/bring-your-own model support is gone; irlume ships its full model set and the command answers with a notice. Check installed weights with `irlume doctor` |
| `irlume update [--check]` | for install | update via the channel irlume was installed from (Copr/PPA: runs it; .deb/pkg/source: shows the steps); `--check` only reports |
| `irlume uninstall [--keep-data] [--yes]` | yes | un-wire PAM first (lockout-safe order), stop the daemon, sweep the stale socket, the `/etc/systemd/system` unit copies and enabled timer, the kernel-loaded AppArmor profile, and per-user XDG state; wipe enrolled data unless `--keep-data`, then print the package-removal command |

## Developer and benchmark tools

Hidden unless `IRLUME_DEV=1` is set, because they open the camera directly and
bypass the daemon. Not needed for normal use.

`capture`, `eval`, `irbench`, `genuine`, `calcapture`, `normprobe`,
`liveness`, `selftest align`, `padcapture`, `padreport`, `verify`,
`enrolldev`, `suncal`, `gesturecap`

Each prints its own usage line when run without arguments. `padcapture` /
`padreport` are the presentation-attack self-test pair documented in
[PAD_SELFTEST.md](PAD_SELFTEST.md); `suncal` is the outdoor/sunlight
calibration analyzer.

`gesturecap` captures or replays head-pose evidence with the shipped classifier:

```console
IRLUME_DEV=1 irlume gesturecap capture --label nod --det models/face_detection_yunet_2023mar.onnx --model models/glintr100.onnx --out nod.jsonl
IRLUME_DEV=1 irlume gesturecap replay nod.jsonl
```

## Where to go next

- First-time setup, step by step: [SETUP.md](SETUP.md)
- Versioned JSON for desktop integrations: [MACHINE-API.md](MACHINE-API.md)
- Reading scores, gate reasons, and PAM decisions: [DEBUGGING.md](DEBUGGING.md)
- NixOS module instead of imperative wiring: [NIXOS.md](NIXOS.md)

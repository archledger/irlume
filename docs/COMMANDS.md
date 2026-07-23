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
| `irlume status` | health dashboard: daemon, enrollment, keyring, cameras |
| `irlume detect` | script-friendly probe; exit `0` = ready, `10` = partial, `20` = absent |
| `irlume doctor` | platform checks in one pass: TPM, Secure Boot, camera, models |
| `irlume deps` | verify runtime dependencies (onnxruntime, models, TPM) |
| `irlume version` | print the installed version (`--version` / `-V` also work) |

## Enrollment and profiles

| Command | What it does |
|---|---|
| `irlume enroll [--name N] [--scans K] [--reset]` | capture a face profile; `--reset` starts the profile space over |
| `irlume profiles` (or `profiles list`) | list profiles and their scans |
| `irlume profiles add-scan --profile P` | add a scan to profile P (improves recognition in new conditions) |
| `irlume profiles rename --profile P [--scan S] --name N` | rename a profile, or one scan inside it |
| `irlume profiles delete --profile P [--scan S]` | delete a profile, or one scan inside it |
| `irlume profiles eyes-open <on\|off>` | require eyes open to unlock |
| `irlume profiles challenge <on\|off>` | opt-in passive blink liveness |
| `irlume identify` | 1:N "who is this?"; as root it checks all users, otherwise scoped to you |

## Keyring, TPM, and recovery

| Command | What it does |
|---|---|
| `irlume keyring <arm\|status\|forget>` | TPM-sealed login password so a face login also unlocks the wallet/keyring |
| `irlume reseal` | re-bind the sealed password to the current PCRs after a firmware or kernel update; prompts for the password, safe to re-run |
| `irlume recovery <status\|setup\|restore\|forget>` | recovery passphrase + profile encryption |
| `irlume diag` | TPM seal + PCR-drift diagnostics; run with `sudo` for full detail |

## System integration

| Command | Sudo | What it does |
|---|---|---|
| `irlume login <status\|enable\|disable> [--with-sudo] [--with-polkit] [--apply]` | yes | PAM wiring for the greeter and lock screen; `--with-sudo` adds face-`sudo`, `--with-polkit` adds app prompts (Bitwarden unlock, pkexec — see docs/APP-INTEGRATION.md); without `--apply` it previews |
| `irlume logs [-f] [--since T]` | sometimes | the face-auth journal in one view (daemon, PAM, keyring); `-f` follows live, `--since "10 min ago"` widens the window |
| `irlume logs debug <on\|off>` | yes | per-stage pipeline tracing in the daemon (numbers only, never frames) |
| `irlume fingerprint <status\|add\|enable\|disable>` | for wiring | fprintd companion factor |
| `irlume selinux <status\|load>` | for load | SELinux module for the login greeter (Fedora) |
| `irlume ir-setup [--dry-run]` | yes | auto-configure the IR emitter; rarely needed, enroll runs it itself when IR frames come back dark |
| `irlume set-cameras <rgb> <ir>` | yes | persist the RGB+IR camera pair, e.g. `/dev/video0 /dev/video2`; the TUI camera picker runs this for you |
| `irlume models [list]` | no | show the opt-in third-party liveness models and their checksum state |
| `irlume models enable <name>` / `models disable` | yes | fetch and enable one (deny-only, checksum-pinned), or turn it off |
| `irlume update [--check]` | for install | update via the channel irlume was installed from (Copr/PPA: runs it; .deb/pkg/source: shows the steps); `--check` only reports |
| `irlume uninstall [--keep-data] [--yes]` | yes | un-wire PAM first (lockout-safe order), stop the daemon, wipe enrolled data unless `--keep-data`, then print the package-removal command |

## Developer and benchmark tools

Hidden unless `IRLUME_DEV=1` is set, because they open the camera directly and
bypass the daemon. Not needed for normal use.

`capture`, `eval`, `irbench`, `genuine`, `calcapture`, `normprobe`,
`liveness`, `meshprobe`, `selftest align`, `padcapture`, `padreport`,
`verify`, `enrolldev`, `suncal`

Each prints its own usage line when run without arguments. `padcapture` /
`padreport` are the presentation-attack self-test pair documented in
[PAD_SELFTEST.md](PAD_SELFTEST.md); `suncal` is the outdoor/sunlight
calibration analyzer.

## Where to go next

- First-time setup, step by step: [SETUP.md](SETUP.md)
- Reading scores, gate reasons, and PAM decisions: [DEBUGGING.md](DEBUGGING.md)
- NixOS module instead of imperative wiring: [NIXOS.md](NIXOS.md)

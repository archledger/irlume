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
| `irlume doctor` | platform checks in one pass: TPM, Secure Boot, camera, models, polkit app prompts, login-keyring lock state + provider (ksecretd/kwalletd/gnome-keyring), the authselect/pam-auth-update regeneration guard, and install hygiene (leftover backup files next to the managed binaries, hand-installed builds overlaying the packaged ones) |
| `irlume deps` | verify runtime dependencies (onnxruntime, models, TPM) |
| `irlume version` | print the installed version (`--version` / `-V` also work); `version --json` uses the public [machine API](MACHINE-API.md) |

## Enrollment and profiles

| Command | What it does |
|---|---|
| `irlume enroll [--name N] [--scans K] [--reset]` | capture a face profile; `--reset` starts the profile space over |
| `irlume enroll --events=jsonl [preview flags]` | public bounded enrollment event stream; see the [machine API](MACHINE-API.md) |
| `irlume auth test --events=jsonl [preview flags]` | live match/liveness test that never releases a credential or changes a profile |
| `irlume profiles` (or `profiles list`) | list profiles and their scans; `profiles list --json` uses the public [machine API](MACHINE-API.md) |
| `irlume profiles add-scan --profile P` | add a scan to profile P (improves recognition in new conditions) |
| `irlume profiles add-scan --profile-id ID --events=jsonl [preview flags]` | machine-facing improve-recognition stream targeting an opaque ID |
| `irlume profiles rename --profile P [--scan S] --name N` | rename a profile, or one scan inside it |
| `irlume profiles delete --profile P [--scan S]` | delete a profile, or one scan inside it |
| `irlume profiles eyes-open <on\|off>` | require eyes open to unlock |
| `irlume profiles challenge <on\|off>` | opt-in passive blink liveness |
| `sudo irlume calibrate-closure` | teach the eye-closure consent gesture for app prompts (captures eyes-open/closed EAR); the head nod is the default and needs no calibration |
| `irlume identify` | 1:N "who is this?"; as root it checks all users, otherwise scoped to you |

Desktop integrations use opaque IDs with `--profile-id` / `--scan-id` plus
`--json`; human commands continue to use display names.
Machine event streams optionally expose a preview only with the complete fixed
flag set: `--preview=ir-jpeg --preview-max-fps=8
--preview-max-size=640x480`. Without it, positioning events contain no image.

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
| `irlume login <status\|enable\|disable\|reconcile> [--with-sudo] [--with-polkit] [--apply]` | yes | human PAM wiring for the greeter and lock screen; `--with-sudo` adds face-`sudo`, `--with-polkit` adds app prompts (Bitwarden unlock, pkexec; see docs/APP-INTEGRATION.md); `reconcile` re-applies the wiring after a distro PAM regeneration (also run by the `irlume-reconcile.path` unit); without `--apply` it previews |
| `irlume login <enable\|disable\|verify\|rollback> … --json` | apply/rollback | fixed-scope machine transaction with plan lineage, post-apply verification, and exact rollback; see the [machine API](MACHINE-API.md) |
| `irlume logs [-f] [--since T]` | sometimes | the face-auth journal in one view (daemon, PAM, keyring); `-f` follows live, `--since "10 min ago"` widens the window |
| `irlume logs debug <on\|off>` | yes | per-stage pipeline tracing in the daemon (numbers only, never frames) |
| `irlume fingerprint <status\|add\|verify\|reset\|enable\|disable> [--fingerprint-only]` | for wiring | fprintd companion; `enable` = unlock with face OR fingerprint (both), `--fingerprint-only` replaces face |
| `irlume bitwarden <status\|setup> [--apply]` | for setup | install Bitwarden's biometric-unlock polkit action, flavor-aware (flatpak/native install it; snap is snapd's job; ostree gets the layering steps); see docs/APP-INTEGRATION.md |
| `irlume selinux <status\|load>` | for load | SELinux module for the login greeter (Fedora) |
| `sudo irlume biopolicy <on\|off\|status>` | for on/off | the operation-class gate: when ENFORCING, a face match is accepted only for the operations its camera tier is trusted for (login and sudo require the Secure IR tier; screen unlock and app prompts stay allowed); off by default, and the password is always available either way |
| `irlume ir-setup [--dry-run]` | yes | auto-configure the IR emitter; rarely needed, enroll runs it itself when IR frames come back dark |
| `irlume set-cameras <rgb> <ir>` | yes | persist the RGB+IR camera pair, e.g. `/dev/video0 /dev/video2`; the TUI camera picker runs this for you |
| `irlume camera-tune [--rounds N]` | yes | measure whether this camera keeps its brightness while both sensors stream, and store the resulting capture mode in `cameras.conf`; some modules starve their own RGB interface (measured: NexiGo HelloCam N930W keeps 56% of its RGB brightness), and this puts those on one-at-a-time capture |
| `irlume cameras list --json` | no | list reviewed camera pairs by opaque ID without exposing device nodes |
| `irlume cameras select --pair-id ID --apply --json` | yes | atomically persist and activate one currently discovered pair |
| `irlume cameras emitter-test --json` | no | typed, read-only emitter-control availability probe |
| `irlume cameras emitter-setup --apply --json` | yes | configure the emitter through a fixed machine operation |
| `irlume cameras tune --apply --json` | yes | measure and persist the capture mode with fixed bounds |
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
- Versioned JSON for desktop integrations: [MACHINE-API.md](MACHINE-API.md)
- Reading scores, gate reasons, and PAM decisions: [DEBUGGING.md](DEBUGGING.md)
- NixOS module instead of imperative wiring: [NIXOS.md](NIXOS.md)

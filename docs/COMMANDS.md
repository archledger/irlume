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
| `irlume profiles eyes-open <on\|off>` | require eyes open to unlock |
| `irlume profiles challenge <on\|off>` | opt-in passive blink liveness |
| `sudo irlume calibrate-closure [--rounds N] [--force]` | teach the eye-closure consent gesture for app prompts. Captures eyes-open/closed EAR over N rounds (default 3) and stores the median, because a single capture varies enough to leave the threshold sitting on top of your own closures; it then reports how many of your readings the result would actually accept. Replacing an existing calibration asks first, and `--force` is required to do it with no terminal. The head nod is the default and needs no calibration |
| `irlume identify` | 1:N "who is this?"; as root it checks all users, otherwise scoped to you |

## Keyring, TPM, and recovery

| Command | What it does |
|---|---|
| `irlume keyring <arm\|status\|forget>` | TPM-sealed secret so a login also unlocks the wallet/keyring. What is sealed depends on the backend: the login password, the KDE wallet key, or a random token this re-keys a GNOME keyring to. `status` names which; `forget` re-keys a token back and takes `--force` to skip that |
| `irlume reseal` | re-bind the sealed secret to the current PCRs after a firmware or kernel update; prompts for the password, safe to re-run. A GNOME keyring token re-binds itself on the next password login, so this reports that and does nothing |
| `irlume recovery <status\|setup\|restore\|forget>` | recovery passphrase + profile encryption |
| `irlume diag` | TPM seal + PCR-drift diagnostics; run with `sudo` for full detail |

## System integration

| Command | Sudo | What it does |
|---|---|---|
| `irlume login <status\|enable\|disable\|reconcile> [--with-sudo] [--with-polkit] [--apply]` | yes | PAM wiring for the greeter and lock screen; `--with-sudo` adds face-`sudo`, `--with-polkit` adds app prompts (Bitwarden unlock, pkexec; see docs/APP-INTEGRATION.md); `reconcile` re-applies the wiring after a distro PAM regeneration (also run by the `irlume-reconcile.path` unit); without `--apply` it previews; `login status --json` uses the read-only public [machine API](MACHINE-API.md) |
| `irlume logs [-f] [--since T]` | sometimes | the face-auth journal in one view (daemon, PAM, keyring); `-f` follows live, `--since "10 min ago"` widens the window |
| `irlume logs debug <on\|off>` | yes | per-stage pipeline tracing in the daemon (numbers only, never frames) |
| `irlume fingerprint <status\|add\|verify\|reset\|enable\|disable> [--fingerprint-only]` | for wiring | fprintd companion; `enable` = unlock with face OR fingerprint (both), `--fingerprint-only` replaces face |
| `irlume bitwarden <status\|setup> [--apply]` | for setup | install Bitwarden's biometric-unlock polkit action, flavor-aware (flatpak/native install it; snap is snapd's job; ostree gets the layering steps); see docs/APP-INTEGRATION.md |
| `irlume selinux <status\|load>` | for load | SELinux module for the login greeter (Fedora) |
| `sudo irlume biopolicy <on\|off\|status>` | for on/off | the operation-class gate: when ENFORCING, a face match is accepted only for the operations its camera tier is trusted for (login and sudo require the Secure IR tier; screen unlock and app prompts stay allowed); off by default, and the password is always available either way |
| `irlume ir-setup [--dry-run]` | yes | configure the IR emitter; rarely needed, and only ever run when you ask. Writes to the camera, so read the warning in SETUP.md. `--dry-run` lists the camera's extension units and writes nothing |
| `irlume set-cameras <rgb> <ir>` | yes | persist the RGB+IR camera pair, e.g. `/dev/video0 /dev/video2`; the TUI camera picker runs this for you |
| `irlume camera-tune [--rounds N]` | yes | measure whether this camera keeps its brightness while both sensors stream, and store the resulting capture mode in `cameras.conf`; some modules starve their own RGB interface (measured: NexiGo HelloCam N930W keeps 56% of its RGB brightness), and this puts those on one-at-a-time capture |
| `irlume models [list]` | no | show the opt-in third-party models (stage, tier, checksum state); `models list --json` is the [machine API](MACHINE-API.md) per-stage report |
| `irlume models enable <name>` / `models disable` | yes | fetch and enable one (deny-only, checksum-pinned), or turn it off |
| `irlume models add <name> <path>` | yes | enable a model whose licence means you obtain the file; verified against the pin irlume measured ([THIRD-PARTY-MODELS.md](THIRD-PARTY-MODELS.md)) |
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

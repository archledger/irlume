# The irlume System Settings module (KDE Plasma)

On KDE Plasma 6, irlume ships a System Settings module (KCM): search
"irlume" in System Settings, or run `kcmshell6 kcm_irlume` for a standalone
window. It appears under Personalization.

## What it shows

The module is a read-only dashboard. Every value on screen comes from the
same machine API that external integrations use (contract 1): the Overview
page renders `irlume status --json`, Diagnostics renders `irlume doctor
--json`, Cameras renders `irlume camera census --json`, and Login wiring
renders `irlume login status --json`. Pages whose capability the installed
engine does not advertise are hidden, never broken.

Each state is shown as an icon with words (OK, needs attention, problem,
not determined, or a neutral information mark for facts that are neither
good nor bad, such as a keyring unlock that is not armed), never by colour
alone, and screen readers get the same words.

- **Overview**: the daemon, enrollment, keyring unlock (with its sealing
  tier in words, as the TUI shows it), templates at rest, recovery passphrase, face sensors and
  fingerprint reader. Templates that are encrypted while their sealed key
  is missing read as a problem, with the way back (`irlume recovery
  restore` when a recovery passphrase is set, enrolling again when it is
  not). A daemon that is starting, not reachable, or not reachable from
  this account says so, and the face sensors row then says why the
  cameras were not checked.
- **Diagnostics**: one row per check, grouped by state with problems
  first (Failing, Warnings, Not determined, Passing, Informational) and a
  count on each group, under a one-line summary. Each check has a plain
  title that names what is checked; its id stays beside it for support
  and bug reports. The detail of a check that needs attention is shown in
  full; a passing or informational detail takes one line, with the full
  text on hover or when the row is selected with the keyboard. The checks
  that read root-only records say they need administrator rights (`sudo
  irlume doctor`) instead of showing the permission error, and do not by
  themselves prompt you to open irlume.
- **Cameras**: one entry per device, with its class and verdict in words,
  whether it is part of an RGB + IR pair (an RGB camera and an IR sensor
  on the same device), and the evidence on one line. Metadata interfaces
  and test devices are listed together on one line at the end. A closed
  privacy shutter is reported at the top of the page.
- **Login wiring**: the login manager, the SELinux module (reading it needs
  administrator rights on SELinux systems, so an ordinary account sees
  "not determined"), and the PAM surfaces present on this machine with
  their role and face mode in words. This machine's own login screen is
  marked, and flagged when face login is not wired on it.

A daemon that is down or a command that is refused renders as data, not
as a crash: a refused command is shown at the top of the page with the
documented meaning of its error code, and with Retry when the code is
retryable. The module holds no state of its own and polls nothing in the
background; Refresh (or the Refresh shortcut, usually F5) asks again.

## Making changes

The module deliberately does not edit anything. Every button that changes
state ("Enroll face", "Arm wallet unlock" or "Manage wallet unlock", "Set
recovery passphrase" or "Change recovery passphrase", "Choose cameras",
wiring changes) launches the irlume TUI in a terminal, deep-linked to the
right screen when the session provides `xdg-terminal-exec` (otherwise the
plain TUI launcher opens). Interactive flows, authorizations and the login
plan/apply/verify/rollback transaction stay in the TUI, where they are
reviewed and tested; the GUI is a view. A launch that fails is reported at
the top of the page.

Because the TUI is single-instance ([TUI.md](TUI.md)), clicking a launch
button twice does not pile up terminals: the running TUI switches to the
requested screen, and System Settings never waits for it.

## Packaging

- Fedora (Copr): the `irlume-kcm` subpackage.
- Arch (AUR): the `irlume-kcm` split package.
- PPA (Ubuntu 26.04): the `irlume-kcm` binary package (installs on
  resolute and resolute-based derivatives such as Linux Mint 23;
  verified in containers).
- NixOS: `services.irlume.kcm.enable` in the flake module (off by
  default pending a NixOS loading verification, nixpkgs#296999).
- The universal .deb does not carry the module (its Debian 12 base has
  no KF6). It is optional everywhere: the daemon, CLI and PAM module
  work without it.
- Building it needs Qt 6.5 and KDE Frameworks 6.2 or newer.

## Testing

`.github/workflows/kcm.yml` builds the module with `-DBUILD_TESTING=ON` in
Fedora and Arch containers and runs, besides `kcmshell6` and `qmllint`:

- `kcm_loadtest`: the plugin's metadata and factory, and the bridge
  against a contract-shaped stub CLI;
- `kcm_bridgetest`: the bridge's failure paths (a child killed by a
  signal, a timeout, a request superseded while it runs, a missing
  program) against fake programs;
- `kcm_pagetest`: every page, offscreen, for each fixture set in
  `kcm/tests/fixtures/` at 420 and 1530 pixels wide, failing on any QML
  warning, any text outside the page and any row or action out of place.

The fixture sets are synthetic documents owned by the module;
`schemas/fixtures/` is not edited by hand.

## Security posture

The module runs inside systemsettings as your own user. It execs exactly
one program (`irlume`, resolved to the packaged absolute path, which the
terminal launch passes on as well), renders JSON documents, and can start
the TUI. It never reads or writes enrollment data, never edits PAM, and
ships no privileged helper: the
[design doc](superpowers/specs/2026-09-18-kcm-plasma-settings-design.md)
records the rejected alternatives (including a KAuth helper).

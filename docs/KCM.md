# The irlume System Settings module (KDE Plasma)

On KDE Plasma 6, irlume ships a System Settings module (KCM): search
"irlume" in System Settings, or run `kcmshell6 kcm_irlume` for a standalone
window. It appears under Personalization.

## What it shows

The module is a read-only dashboard. Every value on screen comes from the
same machine API that external integrations use (contract 1): the Overview
page renders `irlume status --json`, Diagnostics renders `irlume doctor
--json` grouped by severity with the remediation text verbatim, Cameras
renders `irlume camera census --json`, and Login wiring renders
`irlume login status --json`. Pages whose capability the installed engine
does not advertise are hidden, never broken.

A daemon that is down or a command that is refused renders as data (the
typed refusal and its meaning), not as a crash: the module holds no state
of its own and polls nothing in the background.

## Making changes

The module deliberately does not edit anything. Every button that changes
state ("Enroll face", "Arm wallet unlock", "Set recovery passphrase",
"Choose cameras", wiring changes) launches the irlume TUI in a terminal,
deep-linked to the right screen when the session provides
`xdg-terminal-exec` (otherwise the plain TUI launcher opens). Interactive
flows, authorizations and the login plan/apply/verify/rollback transaction
stay in the TUI, where they are reviewed and tested; the GUI is a view.

Because the TUI is single-instance ([TUI.md](TUI.md)), clicking a launch
button twice does not pile up terminals: the running TUI switches to the
requested screen.

## Packaging

- Fedora (Copr): the `irlume-kcm` subpackage.
- Arch (AUR): the `irlume-kcm` split package.
- The universal .deb and NixOS do not carry the module yet (Debian 12 has
  no KF6; the NixOS module needs an in-module verification first). It is
  optional everywhere: the daemon, CLI and PAM module work without it.

## Security posture

The module runs inside systemsettings as your own user. It execs exactly
one program (`irlume`, resolved to the packaged absolute path), renders
JSON documents, and can start the TUI. It never reads or writes
enrollment data, never edits PAM, and ships no privileged helper: the
[design doc](superpowers/specs/2026-09-18-kcm-plasma-settings-design.md)
records the rejected alternatives (including a KAuth helper).

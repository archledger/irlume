# Item 5: COSMIC greeter + immutable-distro one-shot tests

Date: 2026-08-25
Agent: opencode
Survey item 5 of `2026-08-24-face-unlock-competitor-pain-survey.md`:
test the Pop!_OS COSMIC greeter (Howdy #1134 class: login broken and
cannot disable) and an immutable distro (Howdy #594 class: Silverblue)
before anyone files them.

## Method

Two disposable VMs on archhost (libvirt, UEFI/OVMF), scripted end to end:

- **pop-item5**: Pop!_OS 24.04 LTS (COSMIC, Epoch 1), ISO build
  `intel/20` (Oct 2025, sha256 `a0ef3842…`). Installed headless by running
  the live ISO's own `distinst` CLI against an nbd-attached qcow2
  (pre-partitioned with parted; `--use` for both partitions), then
  `console=ttyS0` added to the systemd-boot entry for serial access and
  sshd installed in the guest.
- **sb44-item5**: Fedora Silverblue 44.1.7, ISO sha256 `9ccec9b0…`
  (verified against the signed CHECKSUM). Kickstart over the libvirt
  NAT network (anaconda fetched it; note: archhost's ufw INPUT DROP
  policy must allow the ks port on virbr0 or anaconda hangs in
  dracut-initqueue with no diagnostic). `ostreesetup` needs
  `--url=file:///ostree/repo` (the repo lives inside install.img, which
  is the installer runtime root; `file:///run/install/repo` fails with
  `opendir(objects)` and omitting the directive silently produces a
  plain package-based Workstation, not Silverblue).

The Logitech BRIO 4K was passed into each guest as a libvirt USB hostdev.
qemu-xhci negotiates SuperSpeed: `lsusb -t` shows 5000M in the guest, the
strobe-capable link the fleet notes require.

## Findings

### 1. BLOCKER found and fixed: irlume 0.11.1 could not be installed on
any rpm-ostree system

`rpm-ostree install` of the shipped fc44 RPM aborts:

    error: Running %post for irlume: bwrap(/bin/sh): Child process exited with code 1
      mkdir: cannot create directory '/var/lib/irlume': Read-only file system
      /proc/self/fd/5: line 31: /var/lib/irlume/.reconcile-timer-armed: No such file or directory

rpm-ostree runs scriptlets in a bwrap sandbox with `/var` read-only, and
any scriptlet failure aborts the whole transaction (no deployment is
created). Root cause is subtler than the unguarded write: the timer-arm
marker was written with `: > marker`, and `:` is a POSIX special builtin,
so the redirection failure aborts the entire /bin/sh scriptlet. `|| :`
cannot catch it (verified in a local bwrap repro with tmpfs `/var`).
Fix: write the marker with `touch` (an external command, whose failure
`|| :` does catch) and guard the `mkdir`. See the spec change in this PR.
Verified: layering exit 0, deployment healthy after reboot.

The same `: > marker` pattern exists in packaging/arch/irlume.install and
packaging/debian/postinstall.sh, but their targets (pacman, dpkg) do not
sandbox `/var`, so they keep working; not changed.

### 2. Silverblue 44: everything else passes (with the fixed scriptlet)

- Layered install of irlume + irlume-selinux survives reboot into the new
  deployment; SELinux module loads (Enforcing).
- All units active (`irlumed.service/socket`, `irlume-reconcile.timer/path`);
  `/var/lib/irlume` and the setgid `/run/lock/irlume` are created at boot by
  tmpfiles.d exactly as on mutable Fedora.
- "IR emitter ready" in the daemon log: the #542 emitter path works on a
  USB3 virt redirect under ostree.
- `irlume login enable --apply` self-gates on "no camera" until
  `set-cameras` pins a pair (fail-closed, correct), then wires
  `/etc/pam.d/gdm-password` with a `.pre-irlume` backup (ostree `/etc`
  overlay is writable; wiring works).
- sudo surface, consent gate: password entry grants (RC 0) with zero
  camera requests in the daemon journal (the ADR-0011 single-field
  passthrough); an explicit `yes` on an unenrolled box denies pre-camera
  (no capture spin-up), fail-closed.
- `irlume login disable --apply` restores every PAM file from backup and
  removes the SELinux module cleanly; `rpm-ostree uninstall` removes both
  packages cleanly.

Face-grant (real enrollment + live capture) was not exercised in the VM:
it needs the user physically at the camera and we do not fake biometrics.
The mechanical surface above is the part the #594 class breaks.

### 3. Pop!_OS 24.04 COSMIC: passes

- The .deb installs clean; units active.
- irlume auto-detects the greeter: `login manager: cosmic-greeter` and
  wires `/etc/pam.d/cosmic-greeter` with a backup. This is the exact
  #1134 surface, natively supported.
- End to end: rebooted to the COSMIC greeter with the wired PAM stack,
  the greeter renders normally (no crash), and a password typed through
  `virsh send-key` logs into the desktop session (the pam_irlume hidden
  field received the password and passed it through).
- `irlume login disable --apply` restores cosmic-greeter from backup;
  `apt remove --purge irlume` removes everything (RC 0).

Known quirk seen again: `set-cameras` could not persist under Pop's
systemd 255 sandbox (`live only; Permission denied`), matching the
documented ProtectSystem behavior; writing cameras.conf directly and
restarting the daemon works.

## Disposition

- Spec fix ships in this PR; the release vehicle (0.11.1-2 respin or
  0.11.2) is a maintainer call.
- VMs retained on archhost at `/var/lib/libvirt/images/item5/` until the
  optional live-face greeter test or deletion (disk is tight: ~16G).

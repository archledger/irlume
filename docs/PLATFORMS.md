# Platform support

What irlume is validated on, how each platform installs it, and what has not
been tested yet. "Validated" below means someone ran it on that platform and
checked the result; nothing on this page is extrapolated. If you run irlume
anywhere not listed, an issue report with your distro, camera, and
`irlume doctor` output extends this page: https://github.com/archledger/irlume/issues

## Install lane per distro

| Distro | Lane | Notes |
|---|---|---|
| Fedora, current stable releases + rawhide | Copr `archledger/irlume` (`dnf copr enable` + `dnf install irlume`) | SELinux module ships as the `irlume-selinux` subpackage |
| Ubuntu, current LTS | PPA `ppa:archledger/irlume` | the PPA carries the current LTS only |
| Debian 12+, Ubuntu derivatives (Mint, Pop!\_OS, Zorin, elementary), older Ubuntu LTS | `.deb` from [Releases](https://github.com/archledger/irlume/releases) | needs glibc 2.35+; the package refuses anything older |
| Arch | AUR package [`irlume`](https://aur.archlinux.org/packages/irlume) | builds from the signed release tag; models come from the models-v1 release |
| NixOS | `nixosModules.irlume` from this flake | declarative daemon + PAM wiring, see [NIXOS.md](NIXOS.md) |
| anything else | from source | see [DEVELOPMENT.md](DEVELOPMENT.md); Rust 1.88+, onnxruntime 1.24+ |

Every lane is x86_64 only today (Copr chroots, PPA, `.deb`, and the AUR
`arch=` line all say so). No aarch64 build exists yet; the blocker is an
arm64 onnxruntime + rebuild validation, not anything in the code.

## Validated on real hardware

| Platform | Machine / camera | Tier | What was actually exercised |
|---|---|---|---|
| Fedora 44 KDE (Wayland) | ASUS Zenbook S 14, integrated IR module | IR/Secure | The reference install: greeter face login (Plasma Login Manager), lock screen, face-`sudo`, TPM-sealed keyring unlock, SELinux enforcing, enrollment/liveness calibration, multi-boot journal audits |
| Ubuntu 26.04 LTS GNOME | ThinkPad X13 Yoga G4, Chicony RGB camera + Synaptics fingerprint | Convenience | PPA install end to end, lock-screen face unlock, fingerprint companion, correct password-only refusals for login and sudo, AppArmor profile enforcing (soak-tested, zero denials) |
| Arch | desktop, no camera | none | package build, daemon + full CLI stack, PAM wiring dry-run, clean camera-less refusals |
| Debian 12 | container (no camera) | none | from-source build, `.deb` install, `irlume doctor` |
| external IR camera | NexiGo HelloCam N930W (USB) | IR/Secure | presentation-attack testing (photo, screen, replay denied), daemon-to-password fallback end to end |
| external IR camera | Logitech Brio 4K (046d:085e) | link-dependent, see below | sequential capture both links; emitter strobe and dark-room IR measured on USB3; RGB starvation measured on both links |

### Logitech Brio 4K: capability depends on the USB link

Measured 2026-08-07 (USB3 host, dark room) and 2026-08-06 (USB2 host, the
#187 session):

- **The IR emitter fires only on a USB3 link.** On USB3 it strobes on
  alternate frames from bare STREAMON after a cold re-enumeration, with no
  extension-unit write (dark-phase frame mean 0.6, lit-phase 126 to 224 in
  an ambient-IR-free room). On a USB2 link the same model never strobes,
  so secure-tier authentication there works only when the environment
  supplies infrared.
- **Held dual streams fail on BOTH links.** With the IR stream armed, RGB
  delivers zero frames and dies with QBUF EINVAL (USB2: `Failed to
  resubmit video URB`; USB3: immediate EINVAL, three of three probe
  rounds). Sequential capture works on both.
- The IR sensor answers 340x340 GREY at ~19 fps regardless of the
  requested size.

Verdict: on USB2, convenience tier or an external camera with a working
emitter (the NexiGo above). On USB3 the measured pieces (emitter, dark-room
IR, sequential capture) support Hello-class use, but full enrollment and
authentication on that link are not yet exercised; the verdict is only as
wide as those measurements.

The first cross-distro survey (build, daemon, PAM plan, tier detection on
Arch and Ubuntu) is written up in
[cross-distro/2026-07-01-arch-ubuntu-survey.md](cross-distro/2026-07-01-arch-ubuntu-survey.md).

One caveat for cameras not listed: recognition calibrates per enrollment, but
the liveness cue floors were tuned on the Zenbook and NexiGo modules
([DEBUGGING.md](DEBUGGING.md) covers reading the cue values if a different
module misbehaves).

## Login managers

All wiring is on-demand: leave the password empty and press Enter to trigger
the camera. `irlume login enable` detects the login manager and tailors the
PAM changes.

| Login manager | Status |
|---|---|
| Plasma Login Manager (plasmalogin) | validated live on hardware, daily-driven |
| KDE lock screen | validated live on hardware, daily-driven |
| GDM | wired; on-demand on GNOME 46+, face-first before that |
| SDDM | wired and exercised in the login-manager matrix |
| LightDM (gtk and slick greeters, X11) | wired and exercised in the login-manager matrix |
| greetd (tuigreet) | wired and exercised in the login-manager matrix |
| COSMIC greeter | wired and exercised in the login-manager matrix |
| ly (TUI) | wired and validated on a real `ly` install: detected, wired, password fallback confirmed. The greeter's own login was not driven, so the face-first wiring it gets is the conservative default rather than a measured choice |
| polkit-1 (app prompts: Bitwarden, pkexec) | validated live: Bitwarden flatpak biometric unlock approved by a head nod |

## Not tested yet, reports welcome

- openSUSE (Tumbleweed or Leap): no package; from-source should work, nobody
  has confirmed it.
- Fedora Atomic desktops (Silverblue, Kinoite): `rpm-ostree` layering of the
  Copr package is untested, and the PAM wiring assumes a writable `/etc/pam.d`.
- Ubuntu derivatives via the `.deb` (Mint, Pop!\_OS, Zorin, elementary):
  expected to behave like their Ubuntu base, unconfirmed on real installs.
- Arch derivatives (Manjaro, EndeavourOS) via the AUR package.
- NixOS on bare-metal IR hardware: the module's greeter and lock-screen matrix
  was validated on a NixOS VM with camera passthrough (see
  [NIXOS.md](NIXOS.md)); a face login on a physical NixOS machine has not been
  reported.
- Other IR cameras: any Windows Hello-capable module that exposes a V4L2 IR
  node should work; only the two above are confirmed.
- musl-based distros (Alpine): untested; the release binaries assume glibc.

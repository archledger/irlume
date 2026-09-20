# Platform support

Support baseline: **v0.14.0**, reviewed September 19, 2026. This page separates
implemented behavior, installation checks and attended authentication results.
Historical validation applies to its named build and environment, not every
later release. Inferred compatibility is labelled. If you run irlume
anywhere not listed, an issue report with your distro, camera, and
`irlume doctor` output extends this page: https://github.com/archledger/irlume/issues

## v0.14.0 behavior and support boundaries

| Surface | Shipped behavior | Qualification or limit |
|---|---|---|
| Login, lock, sudo and polkit | IR-backed face authentication on supported PAM surfaces; fingerprint is an fprintd companion | Per-desktop wiring and hardware evidence below. Face plus fingerprint means either factor, not required two-factor authentication |
| RGB-only cameras | Face may satisfy recognized live-session screen unlock | Login, elevation, polkit and secret release refuse, independently of the optional `biopolicy` setting |
| Start and consent | On-demand desktop empty Enter; privileged literal `yes` by default | Older/undetected GNOME and unknown greeters can use face-first; the owner can waive privileged confirmation; stale capture qualification can trigger delayed background measurement ([limits](LIMITATIONS.md)) |
| Password and cancellation | Face refusal returns to the separate password provider; daemon deadlines and disconnect checks bound admission | No universal simultaneous password lane or Esc/typing-to-cancel during a synchronous request. Frontend lifecycle and OS `pam_faillock` remain independent ([desktop contract](DESKTOP-AUTH.md)) |
| Stored enrollment | Primary and secondary embeddings use AES-256-GCM under the account template key on TPM hosts | v0.13.0 plaintext secondary stores migrate on the next authorized write, not install/read. No-TPM hosts and old plaintext backups remain plaintext ([storage](SECURITY_AT_REST.md)) |
| Multiple cameras | Enrolled groups with scoped scans, calibration and authorization | Exact enrolled pair required; no arbitrary RGB/IR mixing or promised automatic docking failover. Experimental IR-only is primary-only ([ADR-0024](adr/0024-multi-camera-enrollment.md)) |
| Login keyring and app vaults | TPM-backed GNOME/KDE keyring paths; measured Bitwarden polkit quick unlock | First vault unlock and keyring unlock are different operations. No direct KeePassXC/1Password qualification ([app integration](APP-INTEGRATION.md)) |
| KDE settings | Shipped KCM dashboard and deep-linked TUI actions | Native privileged controls are optional future work; NixOS KCM runtime loading remains unverified and default-off ([KCM](KCM.md)) |
| MIPI/IPU and other cameras | Census can identify unsupported pipelines | Detection is not a qualified capture/illumination backend. Usable UVC IR needs an accepted 8-bit grey stream and illumination evidence |
| Optional acceleration | CPU default; optional execution-provider builds | Compile success, including external NPU research, does not establish device execution, inference parity or end-to-end speedup |

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

## Release upgrade validation

Package builds and clean-install checks do not establish upgrade or rollback
behavior. Follow [Package upgrade and rollback validation](UPGRADE-VALIDATION.md)
for the disposable Debian/Ubuntu, Arch, and Fedora guest procedure, authentication
checks, recovery steps, and evidence limits. A passing package transaction does
not extend the hardware or login-manager qualification described below.

<a id="validated-on-real-hardware"></a>

## Recorded hardware and installation validation

The September 17 attended results and September 19 release checks are
summarized in the [dated validation record](validation/2026-09-19-support-baseline.md).
The generated [hardware matrix](HARDWARE.md) retains its older measurements;
those dates are not the ceiling of the newer attended evidence.

| Platform | Machine / camera | Tier | What was actually exercised |
|---|---|---|---|
| Fedora 44 KDE (Wayland) | ASUS Zenbook S 14, integrated IR module | IR/Secure | The reference install: greeter face login (Plasma Login Manager), lock screen, face-`sudo`, TPM-sealed keyring unlock, SELinux enforcing, enrollment/liveness calibration, multi-boot journal audits |
| Ubuntu 26.04 LTS GNOME | ThinkPad X13 Yoga G4, Chicony RGB camera + Synaptics fingerprint | Convenience | PPA install end to end, lock-screen face unlock, fingerprint companion, correct password-only refusals for login and sudo, AppArmor profile enforcing (soak-tested, zero denials) |
| Arch | desktop, BRIO and NexiGo | IR/Secure | September 17 pre-v0.13 dual-policy grants with default PAD, camera-group churn, hotplug and scoped attack controls; September 19 v0.14 package/state-preserving upgrade and installed KCM loadtest. These are separate campaigns |
| Debian 12 | container (no camera) | none | from-source build, `.deb` install, `irlume doctor` |
| external IR camera | NexiGo HelloCam N930W (`3443:c803`) | IR/Secure | presentation-attack testing (photo, screen, replay denied), daemon-to-password fallback end to end |
| external IR camera | Logitech Brio 4K (046d:085e) | link-dependent, see below | historical link/capture measurements plus September 17 attended sequential dual grants with default PAD and scoped print/phone refusals |

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

Those August link measurements remain scoped to their tested connections.
Later BRIO sequential dual-policy authentication with the shipped default-PAD
configuration succeeded in the September 17 pre-v0.13 workstream, including
scoped print/phone refusals and hotplug recovery. See the [newer record](validation/2026-09-19-support-baseline.md).
This does not establish USB2 dark-room support, every BRIO firmware/link, or a
fresh v0.14.0 attended qualification campaign.

### Buying an external camera: what the model name does not tell you

**The NexiGo N930W name does not identify one camera design.** The HelloCam
measured by this project is `3443:c803` and carries an IR sensor. A prior survey
identified `3443:930d` as an RGB-only 60fps N930W, but #449 reports another
`3443:930d` unit that exposes a 640x360 GREY IR stream and works with Windows
Hello. Do not infer the sensor or emitter capability from the box or USB ID
alone. Check the nodes with `irlume doctor`, and inspect an unrecognised emitter
with `sudo irlume ir-setup --dry-run` before allowing any write.

More generally, a camera advertised as "Windows Hello compatible" is not
evidence of anything irlume can use. Microsoft's own implementation guide
describes three arrangements: RGB-only, IR-only, and one camera carrying both.
Only the last, or a paired RGB and IR pair inside one physical device, gives a
secure tier. What to check before trusting a camera:

- It presents a node advertising a GREY or Y-family format, not only YUYV and
  MJPEG. `irlume doctor` reports what each node advertises.
- The node count tells you nothing. A simple RGB plus IR camera commonly shows
  four `/dev/video*` entries, two of them image nodes and two secondary, and
  more elaborate devices show more. Never select by number; irlume selects by
  advertised format and device topology, and so should you when reading `lsusb`
  output.
- The emitter is the part most likely to be missing. irlume discovers it
  through the Microsoft camera extension unit where present, and `irlume
  ir-setup` covers the rest, but a camera whose vendor exposes no control at all
  can still capture IR only when the room supplies infrared.

Two models turn up often in searches and are **not** recommendable on current
evidence: the Dell UltraSharp WB7022 and the Lenovo 510 / Performance FHD. Both
are documented by their vendors as Hello cameras and both plausibly work, but
neither has a public, reproducible Linux report pairing an IR stream with a
working emitter, and neither has been measured here. Absence of a report is not
a verdict against them; it is a reason not to spend money on this project's
say-so.

The first cross-distro survey (build, daemon, PAM plan, tier detection on
Arch and Ubuntu) is written up in
[cross-distro/2026-07-01-arch-ubuntu-survey.md](cross-distro/2026-07-01-arch-ubuntu-survey.md).

One caveat for cameras not listed: recognition calibrates per enrollment, but
the liveness cue floors were tuned on the Zenbook and NexiGo modules
([DEBUGGING.md](DEBUGGING.md) covers reading the cue values if a different
module misbehaves).

## Login managers

On-demand wiring uses an empty password and Enter to trigger the camera.
`irlume login enable` selects a recipe for the detected login manager; some
compatibility paths remain face-first. Check the planned PAM changes rather
than assuming every desktop has the same prompt or cancellation behavior.

| Login manager | Status |
|---|---|
| Plasma Login Manager (plasmalogin) | validated live on hardware, daily-driven |
| KDE lock screen | validated live on hardware, daily-driven |
| GDM | on-demand for detected GNOME 46+; measured on 50, inferred for 46–49. Older or undetected GNOME receives face-first wiring |
| SDDM | wired and exercised in the login-manager matrix |
| LightDM (gtk and slick greeters, X11) | wired and exercised in the login-manager matrix |
| greetd (tuigreet) | wired and exercised in the login-manager matrix |
| COSMIC greeter | wired and exercised in the login-manager matrix |
| ly (TUI) | wired and validated on a real `ly` install: detected, wired, password fallback confirmed. The greeter's own login was not driven, so the face-first wiring it gets is the conservative default rather than a measured choice |
| polkit-1 (app prompts: Bitwarden, pkexec) | validated live (pre-0.12.0 via the then-current head-nod approval; today's confirmation is the typed `yes` field): Bitwarden flatpak biometric unlock approved |

<a id="not-tested-yet-reports-welcome"></a>

## Limited qualification and untested configurations

- openSUSE (Tumbleweed or Leap): no package; from-source should work, nobody
  has confirmed it.
- Silverblue 44: [August 25 VM validation](research/2026-08-25-item5-cosmic-silverblue.md)
  covered layered installation, reboot, enforcing SELinux, writable `/etc/pam.d`
  wiring, password fallback, disable and removal. Live face grants were not
  exercised. Kinoite and current-release Atomic upgrade/rollback remain unqualified.
- Ubuntu derivatives: that same report covers Pop!_OS 24.04 COSMIC `.deb`
  installation, wired greeter password login, disable and removal, with a
  camera-config persistence quirk. Cinnamon/Mint has separate recorded wiring
  and live prompt validation. Neither is an all-derivative v0.14 qualification;
  Zorin and elementary remain unconfirmed.
- Arch derivatives (Manjaro, EndeavourOS) via the AUR package.
- NixOS on bare-metal IR hardware: the module's greeter and lock-screen matrix
  was validated on a NixOS VM with camera passthrough (see
  [NIXOS.md](NIXOS.md)); a face login on a physical NixOS machine has not been
  reported.
- Other IR cameras: an 8-bit grey format (`GREY`, `Y8`, `Y800`) is necessary,
  but does not prove emitter, capture or authentication support. A node
  that offers **only** `Y16`/`Y10`/`Y12`/`NV12`/`YUYV` is refused rather than
  untested: those formats name no sensor ceiling, so the IR exposure check
  cannot run, and irlume refuses instead of judging a frame it never read
  (#358). No such camera has been reported; every module in the record,
  including the two user-reported ones, offers grey.
- musl-based distros (Alpine): untested; the release binaries assume glibc.

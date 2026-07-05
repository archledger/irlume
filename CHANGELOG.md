# Changelog

All notable changes to irlume are documented here. This project adheres to
[Semantic Versioning](https://semver.org/).

## [0.1.2] — 2026-07-05

First-run smoothness release, driven by a screen-recorded fresh-install test
on Fedora: install → `irlume tui` → press `[e]` → enrolled → `[w]` → wired,
with no terminal detours.

### Fixed

- **Fresh installs work immediately**: the Fedora package now enables and
  starts `irlumed` at install (systemd preset + scriptlet), matching what the
  Arch and Debian packages already did. Previously the daemon shipped disabled
  and the first enrollment failed with a cryptic `os error 2`.
- **SELinux**: `dnf install irlume` now pulls the policy subpackage in by
  default (weak dependency), and both the subpackage scriptlet and
  `irlume login enable` restart the daemon after loading the module — the
  already-bound socket kept its pre-policy label, which silently blocked the
  confined greeter until the next reboot.
- `sudo irlume login disable --apply` now always unwires `/etc/pam.d/sudo`
  (the "undoes everything" promise was false unless `--with-sudo` was passed).
- Daemon-unreachable errors name the exact fix
  (`sudo systemctl enable --now irlumed`) instead of `os error 2`; the
  dry-run `login disable` no longer claims it removed the SELinux module.
- Security-audit hardening: enrollment saves are atomic (0600 temp + rename,
  no truncation on crash, no permissions window); the daemon zeroizes response
  buffers that may carry an unsealed credential; a cancelled sudo during the
  enroll fix no longer freezes the TUI; PAM-file restores keep admin edits
  made after wiring (strip-in-place unless the file is otherwise unchanged).

### Changed

- **TUI essential view**: the wizard shows only the setup path — Welcome →
  Enroll → Keyring → Recovery → Login wiring → Done. `[v]` reveals all tabs;
  Repair appears automatically when something actually fails.
- **Press `[e]` and it works**: enrolling with a stopped daemon now runs the
  sudo enable+start fix and resumes enrollment automatically.
- **`[w]` wires login from the TUI** (Done tab and Login-wiring tab); the Done
  dashboard gained a "login wiring" row and says "one step left" instead of a
  premature "All set".
- Enrollment guidance (glasses profile, appearance changes, sunlight) on the
  Profiles tab and in the README FAQ; THREAT_MODEL now states plainly that the
  fingerprint companion has no presentation-attack detection of its own.
- New `irlume version` subcommand, and `irlume update` now detects how irlume
  was installed (Copr, PPA, release asset, source) and updates through that
  same channel.

## [0.1.1] — 2026-07-04

Packaging-only patch release: makes the Fedora Copr pipeline work end-to-end.
No functional changes to the daemon, CLI, or PAM module.

### Fixed

- **Fedora/Copr builds now succeed** (validated live in Copr): Packit jobs
  request build-time networking (`enable_net`) so cargo can reach crates.io;
  `Cargo.lock` is now committed so `cargo build --locked` works from release
  tarballs; the spec gained the missing `clang-devel`, `kernel-headers`, and
  `pkgconf-pkg-config` BuildRequires (bindgen for V4L2, pkg-config for
  tss-esapi); and the SELinux policy module is compiled from its committed
  `.te` source during the build instead of expecting a pregenerated `.pp`.
- Fedora users can install from Copr: `dnf copr enable archledger/irlume &&
  dnf install irlume`.

### Notes

- Arch (`.pkg.tar.zst`) and Debian/Ubuntu (`.deb`) packages are functionally
  unchanged from v0.1.0; the v0.1.1 release ships freshly built assets.

## [0.1.0] — 2026-07-03

First public release. Local infrared face authentication for Linux —
clean-BOM, TPM-sealed, engineered to meet or beat Windows Hello. The password
is always the fallback: no lockout, ever.

### Added

- **Privilege-separated architecture** — a thin `pam_irlume.so` module and
  `irlume` CLI are untrusted clients of a privileged `irlumed` daemon (the only
  component that touches the camera, IR emitter, models, templates, or TPM),
  over a `SO_PEERCRED`-authenticated Unix socket.
- **Clean model bill-of-materials**, all permissive & GPLv3-compatible, bundled:
  YuNet (MIT) detection, AuraFace 512-D ArcFace (Apache-2.0) recognition,
  self-built algorithmic IR liveness, and opt-in passive blink liveness via
  MediaPipe FaceMesh (Apache-2.0) eye-aspect-ratio.
- **Encrypted at rest** — templates are 512-D embeddings only (never images),
  AES-256-GCM encrypted under a key the TPM seals to boot state. Disk-theft
  tested: sealed data is undecryptable on another machine.
- **Hardware tiers** — IR camera → Secure (login, `sudo`, lock screen, keyring
  unlock); RGB-only → Convenience (screen unlock only); optional fingerprint
  companion factor.
- **TPM-sealed keyring unlock** — a face login unseals the login password and
  hands it to gnome-keyring / KWallet, so the wallet opens with no prompt.
- **Method/tier/login-manager-aware PAM wiring** (`irlume login enable`) for
  GDM, SDDM, and Plasma `plasmalogin`; opt-in, never auto-wired on install.
- **Guided TUI** (`irlume tui`) for enrollment, configuration, live status, and
  a Repair tab that detects and fixes common issues.
- **Packaging for all three families** — Fedora RPM (Copr/Packit), Arch
  PKGBUILD, Debian/Ubuntu `.deb` (nfpm). onnxruntime is bundled on Fedora and
  Debian/Ubuntu; Arch uses the system package.

### Security

- ISO/IEC 30107-3 PAD self-test tooling (`padcapture` / `padreport`) with
  per-species APCER / BPCER / ACER and exact-binomial confidence intervals.
- SO_PEERCRED + operation-class biopolicy gate on credential release (opt-in, off by default);
  bounded request size and read/write timeouts on the daemon socket.

### Known limitations

- Passive blink liveness is a deterrent, not a guarantee: a determined
  life-size glossy print can still slip through occasionally, and it does not
  cover glasses-wearers — every miss falls safely to the password.
- RGB-only laptops get the Convenience tier by design (face never releases
  credentials).
- Not lab-certified: self-tested against ISO/IEC 30107-3, no paid iBeta pass.

[0.1.2]: https://github.com/archledger/irlume/releases/tag/v0.1.2
[0.1.1]: https://github.com/archledger/irlume/releases/tag/v0.1.1
[0.1.0]: https://github.com/archledger/irlume/releases/tag/v0.1.0

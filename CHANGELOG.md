# Changelog

All notable changes to irlume are documented here. This project adheres to
[Semantic Versioning](https://semver.org/).

## [Unreleased]

### Fixed

- **`irlume enroll` now works as the documented 0.2.0 upgrade remedy.** The
  0.2.0 notes tell upgraders to run `irlume enroll` to restore dark/dim login,
  but the anti-mixing guard refused it ("this face is already enrolled as ..."),
  because an upgrader's face still matches their old profile through the
  unchanged RGB path. Enrolling a face that already owns a profile whose IR
  templates are all unusable in the current embedding space now refreshes that
  profile instead of refusing: the captured scans are added (up to the 30-scan
  cap), the per-enrollment IR calibration is refitted from them, and dark/dim
  login matches again. A duplicate of a profile with working IR templates is
  still refused, as is a capture that matches two different profiles. Until
  this ships, the working paths on 0.2.0 are `irlume tui` (Profiles, improve)
  or `irlume enroll --reset`.

## [0.2.0] - 2026-07-15

> **⚠ Breaking — re-enroll needed for dark/dim login.** This release removes the
> IR adapter (see Removed). Face profiles enrolled under 0.1.x have IR templates
> in the old adapter's embedding space, which no longer matches. **Bright-light
> (RGB) face login keeps working**, and any mismatch falls back to your password
> as usual, but **dark/dim (IR) login stops until you re-enroll**: run
> `irlume enroll`. Nothing else is required and no data is lost.

### Added

- **Detection cascade: BlazeFace short-range rescue.** YuNet stays the primary
  detector; when it finds no face (measured on saturated outdoor-walking frames:
  76.9% detected), a BlazeFace short-range pass runs and FaceMesh refines its
  box into the 5 alignment points. The cascade detects 98.5% of those frames
  while never firing when YuNet succeeds, so easy detection is unchanged (LFW:
  0 rescues, identical accuracy). Both models are Apache-2.0.
- **FaceMesh upgraded to the 478-point FaceLandmarker mesh** (256px), converted
  from Google's Apache-2.0 `face_landmarker.task`. Measured 28% better eye
  accuracy on CBSR ground truth (NME 0.0378 → 0.0273). The loader auto-detects
  the input size and accepts either the 468 or 478 generation.
- **Per-enrollment IR calibration (ADR-0004).** A ridge-regularized linear map
  fitted on-device from each user's own consented scans, pulling IR embeddings
  toward their RGB space; it activates whenever no global adapter is loaded and
  ships no weights (no license surface). Replaces the research-only-trained
  `ir_adapter.onnx` (now removed, see below).
- **Presence grace window after the consent gesture.** After the blank-Enter
  gesture, capture retries while no usable face is in frame so walking up or
  settling still authenticates: ~15s for login/lock, ~5s for `sudo`/`su`
  (`IRLUME_GRACE_MS` overrides). Only presence-class failures retry — never a
  below-threshold match (FAR-neutral by construction).
- **IR-template embedding-space tagging** so a future adapter swap/removal fails
  loud ("re-enroll") instead of scoring across embedding spaces.

### Removed

- **`ir_adapter.onnx` dropped from the repo and every package (ADR-0004).** Both
  versions that ever shipped were trained on the CBSR NIR (OTCBVS dataset 07) and
  Oulu-CASIA NIR academic datasets, whose licenses cover research/education only;
  bundling them conflicted with the commercial freedom GPLv3 grants downstream, so
  the shipped stack is now MIT/Apache-2.0 only. The default IR path is raw AuraFace
  plus the per-enrollment calibration above, which the ADR's own measurements show
  is also the better default (the global adapter slightly *worsened* every unseen
  identity). The optional `--adapter` / `IRLUME_IR_ADAPTER` hook remains for a
  user-supplied clean-licensed adapter. **Upgrade note:** an enrollment made
  against the old adapter is tagged with its embedding space and must be
  re-enrolled after updating; the daemon refuses to match across spaces.

### Changed

- Enabled the cargo-deny license gate (`check licenses` in CI) with a curated
  permissive + GPL-compatible allowlist; no non-commercial or AGPL/SSPL license
  is permitted in the dependency tree.
- Dropped the unused `ndarray` dependency (the `ort` bridge only used the tuple
  tensor API), trimming the build; reduced per-match string allocation in the
  argmax path. No auth-decision, threshold, or model change.
- Added a Microsoft trademark disclaimer for the descriptive "Windows Hello"
  references.

## [0.1.5] - 2026-07-12

### Added

- **Tier 2 TPM sealing via systemd-pcrlock.** On a machine where the admin has
  run `systemd-pcrlock make-policy`, new seals bind to the pcrlock NV index
  (`TPM2_PolicyAuthorizeNV`). A firmware or Secure Boot update then needs one
  `make-policy` re-run instead of a re-arm, and the sealed password keeps
  releasing. Sealing tries Tier 1 (signed PCR policy), then Tier 2, then the
  literal PCR-7 seal, and round-trip-verifies each candidate before trusting
  it, so a policy that cannot unseal on the current boot never holds the
  secret. Existing envelopes are untouched until the next arm or reseal.
- `irlume status` and the TUI keyring panel now name the seal tier and warn
  when the bound PCRs have drifted since sealing. This uses a new daemon
  `KeyringInfo` request; against an older daemon both surfaces fall back to
  the previous armed yes/no display.
- `irlume diag` reports whether a pcrlock policy is provisioned and which NV
  index new seals would bind to.
- The daemon log names the exact remedy when a PCR drift locks face
  authentication (re-arm for a literal seal, `make-policy` for pcrlock).
- TPM fault-injection test hooks and ignored real-hardware tests covering
  pcrlock seal/unseal, drift, and the seal-tier ladder.

### Changed

- The `tss-esapi` dependency builds from the `irlume-patches` branch of our
  fork: tss-esapi 7.7.0 plus the `PolicyAuthorizeNV` wrapper (upstream merged
  it in 2024 but never shipped it in a 7.x release) and upstream PR #530's
  session-handle leak fix. `Cargo.lock` pins the exact commit.
- IR ambient subtraction (opt-in via `IRLUME_IR_AMBIENT_SUBTRACT=1`) reworked
  its gate against a real sunlight dataset. Under strong ambient IR the sensor
  saturates and a genuine strobe compresses to a gap of ~8-10, so the old
  fixed gap of 20 blocked subtraction in exactly the sunlit captures that
  needed it; the strobe threshold is now the sensor-noise floor (8). After
  subtracting, the result must retain enough mean signal (12) or the raw lit
  frame is kept, so a bright pedestal that collapses the subtracted frame can
  no longer hand a blank image downstream. On 33 genuine bursts this lifts the
  IR depth cue over its floor in 7 more cases with no regression to any that
  already passed. Still opt-in: enabling it by default needs flat-spoof
  captures under the same light and a re-enroll so the per-user floor matches.
  A new `IRLUME_DEV=1 irlume suncal <det> <dir>` tool scores such a dataset.

### Fixed

- TUI: the Activity-history scroll (PgUp/PgDn) now works during a running
  operation and mid-enrollment, and the Welcome screen's `[i]` identify key
  works in the default view; both were previously swallowed by the panel's
  key handling.
- A pcrlock policy that covers zero PCRs is refused at seal and unseal time;
  binding a secret to it would give no measured-boot protection.

## [0.1.4] - 2026-07-07

A distribution and self-update release: face authentication itself is
unchanged; this makes installing and updating irlume smooth on every distro.

### Changed

- **`irlume update` is fully adaptive.** It reports the version your package
  manager has installed, detects the exact channel it came from (Copr,
  PPA, the GitHub `.deb`, the pacman package, or a source build), matches the
  release asset for your CPU architecture, and only offers a download that
  exists: no more dead links or steering an Ubuntu derivative to a PPA
  that can't serve it.
- **Two Ubuntu lanes.** The PPA carries the current Ubuntu LTS (native,
  auto-updating); every derivative (Mint, Pop!_OS, Zorin, elementary) uses the
  universal `.deb` below: one binary that installs on Ubuntu 24.04 and newer.
- Declared minimum Rust is now 1.88 (the real floor, via the ONNX Runtime binding).

### Fixed

- Arch: `git lfs pull` fetches the model weights correctly under `makepkg`.
- PPA source builds pack a deterministic orig tarball.

### Downloads: which asset do I need?

Prefer your distro's repo (`dnf` / the PPA / the AUR-style package) so updates
arrive automatically; these assets are direct downloads for everyone else.

- **`irlume_0.1.4_amd64.deb`**: Debian and Ubuntu derivatives. Built on the
  oldest supported Ubuntu base, so this single file installs on Mint, Pop!_OS,
  Zorin, elementary, and any newer Ubuntu (`sudo apt install ./…`).
- **`irlume-0.1.4-1-x86_64.pkg.tar.zst`**: Arch Linux (`sudo pacman -U ./…`).
- **`irlume-0.1.4-1.fc44.x86_64.rpm`**: Fedora, the main package
  (`sudo dnf install ./…`). The [Copr](https://copr.fedorainfracloud.org/coprs/archledger/irlume)
  is the auto-updating Fedora channel and pulls the SELinux policy in for you.
- **`irlume-selinux-0.1.4-1.fc44.noarch.rpm`**: the SELinux policy companion for
  the Fedora RPM. Fedora enforces SELinux by default and the login greeter can't
  reach the daemon without this module. It's a *weak* dependency, so a local
  `dnf install ./main.rpm` won't pull it automatically; install it alongside the
  main RPM on an enforcing system. It's `noarch` because the policy is
  architecture-independent (that's also why it's a separate package, not baked
  into the `x86_64` RPM).

## [0.1.3] - 2026-07-07

Display-manager coverage, new diagnostics, security hardening, and a much
friendlier guided enrollment.

### Added

- **Every major login manager is now profiled** for consent-driven face auth:
  GDM (on-demand on GNOME ≥ 46, face-first below), SDDM, LightDM (gtk + slick),
  greetd, COSMIC's greeter, and KDE's Plasma Login Manager, each wired to the
  behaviour its greeter supports. Face is **on-demand** by default:
  leave the password empty and press Enter; typing a password never starts the
  camera.
- **`irlume logs`**: every face-auth journal line (daemon, PAM grantors, keyring
  modules) in one view, with `-f` / `--since`. **`irlume logs debug
  on|off`** toggles per-stage pipeline tracing (`IRLUME_LOG=debug`) for
  diagnosing a failed or slow login: capture timings, liveness cues vs
  thresholds, match scores. Numbers only; never frames, embeddings, or secrets.
- **Directional enrollment guidance**: the framing guide now tells you which way
  to turn ("Turn your head left") and tilt ("Lift your chin"), and **auto-
  calibrates the frontal pitch neutral per user/camera** so the coaching centres
  on wherever a level face reads on your hardware. Fresh enrollment now captures
  **5 scans** (was 3).
- A per-tab **hint bar** in the TUI so a first-time user always knows what a
  screen is for and which key to press. `docs/DEBUGGING.md` scrutineer's guide.

### Security

- **1:N `identify` and identity verification are peer-authenticated**: a
  non-root caller is scoped to its own account (root keeps the cross-user
  search), closing a similarity-score oracle on a world-connectable socket.
- **Journal deny lines are redacted** with tracing off: denied-attempt scores
  quantize to one decimal and cue measurements are stripped, so the system
  journal can't be used as a spoof-tuning oracle. Exact values still reach the
  session's own TUI/CLI for false-reject coaching.

### Fixed

- **Enrollment enforces frontal framing at capture, not just before the
  countdown**: drifting off-angle during the 3-2-1 re-frames instead of saving
  a bad-angle template.

## [0.1.2] - 2026-07-05

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
  `irlume login enable` restart the daemon after loading the module; the
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

- **TUI essential view**: the wizard shows only the setup path: Welcome →
  Enroll → Keyring → Recovery → Login wiring → Done. `[v]` reveals all tabs;
  Repair appears automatically when something fails.
- **Press `[e]` and it works**: enrolling with a stopped daemon now runs the
  sudo enable+start fix and resumes enrollment automatically.
- **`[w]` wires login from the TUI** (Done tab and Login-wiring tab); the Done
  dashboard gained a "login wiring" row and says "one step left" instead of a
  premature "All set".
- Enrollment guidance (glasses profile, appearance changes, sunlight) on the
  Profiles tab and in the README FAQ; THREAT_MODEL now states that the
  fingerprint companion has no presentation-attack detection of its own.
- New `irlume version` subcommand, and `irlume update` now detects how irlume
  was installed (Copr, PPA, release asset, source) and updates through that
  same channel.

## [0.1.1] - 2026-07-04

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

## [0.1.0] - 2026-07-03

First public release. Local infrared face authentication for Linux:
clean-BOM, TPM-sealed, engineered to meet or beat Windows Hello. The password
is always the fallback: no lockout, ever.

### Added

- **Privilege-separated architecture**: a thin `pam_irlume.so` module and
  `irlume` CLI are untrusted clients of a privileged `irlumed` daemon (the only
  component that touches the camera, IR emitter, models, templates, or TPM),
  over a `SO_PEERCRED`-authenticated Unix socket.
- **Clean model bill-of-materials**, all permissive & GPLv3-compatible, bundled:
  YuNet (MIT) detection, AuraFace 512-D ArcFace (Apache-2.0) recognition,
  self-built algorithmic IR liveness, and opt-in passive blink liveness via
  MediaPipe FaceMesh (Apache-2.0) eye-aspect-ratio.
- **Encrypted at rest**: templates are 512-D embeddings only (never images),
  AES-256-GCM encrypted under a key the TPM seals to boot state. Disk-theft
  tested: sealed data is undecryptable on another machine.
- **Hardware tiers**: IR camera → Secure (login, `sudo`, lock screen, keyring
  unlock); RGB-only → Convenience (screen unlock only); optional fingerprint
  companion factor.
- **TPM-sealed keyring unlock**: a face login unseals the login password and
  hands it to gnome-keyring / KWallet, so the wallet opens with no prompt.
- **Method/tier/login-manager-aware PAM wiring** (`irlume login enable`) for
  GDM, SDDM, and Plasma `plasmalogin`; opt-in, never auto-wired on install.
- **Guided TUI** (`irlume tui`) for enrollment, configuration, live status, and
  a Repair tab that detects and fixes common issues.
- **Packaging for all three families**: Fedora RPM (Copr/Packit), Arch
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
  cover glasses-wearers; every miss falls safely to the password.
- RGB-only laptops get the Convenience tier by design (face never releases
  credentials).
- Not lab-certified: self-tested against ISO/IEC 30107-3, no paid iBeta pass.

[0.1.4]: https://github.com/archledger/irlume/releases/tag/v0.1.4
[0.1.3]: https://github.com/archledger/irlume/releases/tag/v0.1.3
[0.1.2]: https://github.com/archledger/irlume/releases/tag/v0.1.2
[0.1.1]: https://github.com/archledger/irlume/releases/tag/v0.1.1
[0.1.0]: https://github.com/archledger/irlume/releases/tag/v0.1.0

# Changelog

All notable changes to irlume are documented here. This project adheres to
[Semantic Versioning](https://semver.org/).

## [Unreleased]

### Fixed

- **Tier-1 signed-PCR sealing works.** irlume's strongest TPM tier (a
  `PolicyAuthorize` over systemd's PCR-signing key, the one that survives kernel
  updates without a reseal) never actually engaged. It loaded systemd's public
  key under the Null hierarchy, so the TPM rejected the resulting
  `PolicyAuthorize` ticket with `TPM_RC_VALUE`, and every UKI / systemd-boot
  host silently fell back to Tier-2 (pcrlock). Loading the key under the Owner
  hierarchy fixes it (the key's Name, which the sealed policy commits to, is
  hierarchy-independent, so the policy is unchanged). Verified on a real
  systemd-boot host, including a Tier-1 seal that unseals after a reboot.

### Changed

- **Existing seals climb to the strongest available tier automatically, with no
  re-arm.** After the fix above a machine that was sealed under a weaker tier
  upgrades on its own: the keyring seal on the next login, and the template key
  on the next face match. The upgrade fires only when a strictly stronger tier
  is available and the ladder round-trip-verifies it, so a machine already at
  its best tier does nothing. New enrollments seal at Tier-1 directly.

## [0.4.0] - 2026-07-21

Two batches: preempting camera and UX failure classes mined from other Linux
face-auth projects' issue trackers with research-grounded auth-policy hardening,
and a whole-codebase, CLI/TUI, and auth-pipeline audit. The matching and
liveness changes were confirmed on the KDE lock screen (face grants in a bright
room and in the dark) before release.

### Added

- **RGB pixel-format negotiation.** Capture now negotiates `NV12` in addition to
  `YUYV`, so cameras that expose only `NV12` work instead of failing at capture.
  A camera that offers neither (MJPEG-only) gets a clear up-front error and an
  `irlume doctor` diagnosis, in place of a cryptic "expected YUYV". `doctor`
  reports RGB decodability using the same format list capture actually decodes.
- **`irlume doctor` recognizes Intel IPU6/IPU7 cameras.** These expose no direct
  V4L2 node, so a bare "no camera" was misleading; doctor now names the sensor
  and points at the libcamera software relay, covering both IPU6 and IPU7 across
  the dkms and in-kernel drivers with a PCI-ID fallback. It also states the
  accurate limitation that the IR sensor is not exposed on Linux at all.
- **`irlume doctor` warns when a user is enrolled but no greeter is wired.**
  `authselect` / `pam-auth-update` can regenerate the PAM stacks and drop
  irlume; doctor now surfaces that state instead of leaving a silently
  face-less login.
- **Consecutive-failure throttle.** After a run of failed face attempts (5 by
  default, `IRLUME_RATE_LIMIT`) the daemon stops firing the camera on the
  gesture for a cooldown (30s, `IRLUME_RATE_COOLDOWN_SECS`) and PAM falls
  straight to the password; a grant resets it, and an empty frame (nobody
  present) never counts. A rejected real presentation counts, including a caught
  spoof, so an attacker cannot cheaply grind presentation attacks against the
  gate. This is a throttle, not the NIST SP 800-63B-4 §3.2.3 hard
  biometric-disable tier: the password is always the fallback and there is no
  account lockout. Applied on both the login/sudo and keyring-unseal paths.
- **Informed opt-in for the anti-spoof blink challenge at enrollment.** Every
  mainstream authenticator (Face ID, Android, Windows Hello) ships passive
  presentation-attack detection rather than an active challenge, so the blink
  challenge stays off by default; the enroll flow now surfaces the choice
  instead of leaving it a hidden flag. The TUI Settings screen toggles it in
  place with `[c]`, alongside the existing `[enter]` eyes-open toggle.

### Changed

- **First capture warms up and retries.** A suspend/resume can leave `uvcvideo`
  re-initializing when the first frame is requested; capture now warms the
  stream and retries so a resume does not fail the login outright.
- **`irlumed.service` stops promptly and runs sandboxed.** `TimeoutStopSec=10s`
  caps the stop wait so a package-upgrade restart cannot stall (the 90s-hang
  class seen elsewhere), guarded by a SIGTERM regression test. The unit also
  gains `NoNewPrivileges`, `RestrictAddressFamilies=AF_UNIX AF_NETLINK`,
  `ProtectSystem=full`, the `ProtectKernel*`/`ProtectControlGroups` set, and a
  `CapabilityBoundingSet` scoped to `CAP_CHOWN`/`CAP_DAC_OVERRIDE`/`CAP_FOWNER`
  (the caps it needs to own enrolled files to the user). `ProtectHome`,
  `PrivateDevices`, and `MemoryDenyWriteExecute` are deliberately left off
  (per-user `$HOME` state, camera and TPM access, the ONNX runtime's JIT).
  Validated live: the daemon starts, loads models, binds the socket, and raises
  no SELinux denials under the restrictions.
- **`docs/THREAT_MODEL.md`** documents that the on-demand empty-Enter gesture
  already supplies the deliberate intent (FIDO User Presence) a passive
  face-auth tool otherwise lacks for `sudo`, so privilege elevation needs no
  extra challenge beyond the gesture and the default liveness gate.

### Security

- **A remote (SSH) session no longer fires the local camera.** The camera is
  physically at the machine, so on an SSH login or an `sudo` inside an SSH
  shell, whoever is in front of the camera (not the remote user) would satisfy
  the face factor. The PAM module now checks `PAM_RHOST` (and the `SSH_*`
  environment markers) up front and returns `PAM_IGNORE` for a remote
  transaction, so the password or another factor authenticates instead. Always
  on, independent of how the stack is wired.
- **Stage-2 fusion weighs the RGB modality by its real brightness.** The
  cross-spectrum path passed a hardcoded RGB face brightness of 0 into fusion's
  quality weight, so fusion always treated RGB as if the room were pitch-dark
  and collapsed the fused score toward IR regardless of actual light. That
  weakened the "an impostor must fool both modalities at once" bound in bright
  rooms. `assess_full` now measures the real RGB face luma (as the RGB-only
  path already did); the liveness gate is unchanged.
- **The dark (IR-only) path enforces the per-user calibrated depth floor.** The
  RGB path already required the live frame to clear the user's enrolled
  3D-structure floor; the dark path used only the lenient global ratio, so a
  curved warm spoof sitting between the two could be rejected in lit conditions
  yet granted in the dark. The same floor now applies on both paths.
- **The daemon self-test is gated to root.** `SelfTest` fires the camera and
  returns raw liveness measurements (IR brightness, depth, glint), a
  spoof-tuning oracle; it now refuses a non-root peer like the other
  camera-bearing requests, which matters on the permissive-socket fallback.
- **Sealed key and recovery files are created at mode 0600 atomically.** They
  were written and then `chmod`-ed, leaving a brief window where the file
  existed under the default umask. The payload is TPM-sealed or
  passphrase-wrapped, so the window was low-value, but the file is now opened
  with the mode set so it is never momentarily wider.

### Fixed

- **The pcrlock PCR parser rejects malformed hex instead of panicking.** The
  same class already fixed in the PCR-signature parser existed in `tpm::hex32`,
  which sliced two bytes at a time with no guard: an odd-length or non-ASCII
  (multi-byte) value in `pcrlock.json` panicked the root daemon. It now rejects
  odd-length and non-ASCII input up front, mirroring `pcrsig::from_hex`.
- **A non-finite detector score can no longer hide the real face.** A NaN
  detection score passed the `< threshold` test (false for NaN) and then ranked
  highest under `total_cmp`, so a single NaN cell would win the top-face pick
  and shadow the genuine face, forcing a false reject. Non-finite scores are
  now dropped at decode.
- **A truncated IR frame degrades to a safe deny instead of panicking.**
  `mean_in_bbox` indexed the frame assuming `len == width * height`; a short or
  mismatched buffer from the camera would panic. It now length-checks once and
  returns 0 (read as "too dark") on a short frame.
- **A wrong-dimension stored template can no longer crash the daemon.** The
  cosine matcher assumed both embeddings were the same length (only a
  debug-time assertion), so a template whose dimension differs from the live
  probe (a swapped recognizer model, which the daemon allows with a warning, or
  a truncated file) indexed out of bounds and panicked the root daemon into a
  restart loop. Mismatched lengths now score a definitive non-match, so the
  account falls back to re-enrollment instead. The IR path already filtered by
  dimension; this covers the RGB and identify paths.

## [0.3.0] - 2026-07-19

### Added

- **`irlume uninstall` (CLI and TUI).** Removes irlume the way it was
  installed, in a lockout-safe order: it un-wires PAM and stops the daemon
  first so a box is never stranded mid-auth, disarms the keyring, wipes
  `/var/lib/irlume` and `/etc/irlume`, then removes the package through
  whatever installed it (`dnf remove`, `apt-get purge`, `pacman -R`, or
  deleting the source-installed files) and clears the residual repo files and
  systemd drop-in that a plain package remove leaves behind. The TUI requires
  a typed-word confirmation before it proceeds.
- **NixOS module.** `nixosModules.irlume` (in the flake, backed by
  `nix/module.nix`) wires the daemon, PAM, and per-greeter login and lock
  configuration declaratively; `docs/NIXOS.md` documents it.
- **Merge-aware enrollment in the TUI.** Enrolling a face the system already
  knows now adds the new scans to that profile instead of creating a second
  one; a face maps to exactly one profile. This brings the 0.2.1 CLI behavior
  to the TUI (issue #15), with a confirmation prompt before the merge.
- **`irlume models`: opt-in third-party liveness models** (the runtime shape
  of the issue #4 `nonfree-pad` idea). The catalog lists externally-trained
  models with real weight licenses that fail the shipped-stack provenance bar;
  irlume never ships or mirrors them. `sudo irlume models enable flir` shows
  the license, the provenance status, and the measured numbers, requires the
  model name typed back plus a y/N, downloads once from the publisher's
  origin, verifies the pinned sha256, and restarts the daemon; `disable`
  deletes the weights and reverts to the shipped stack. The daemon wires an
  enabled model as a deny-only cue on the lit IR frame: it can turn a Live
  verdict into Spoof, never anything else (unit-tested invariant), and it
  refuses weights whose checksum stops matching. First entry: the MIT-licensed
  DAMO FLIR IR model, which closes the vinyl-print gap above. `irlume doctor`
  reports the enabled model.
- Third-party PAD candidate evaluation (issue #4 follow-through):
  `docs/pad-results/2026-07-17-third-party-pad-candidates.md` measures the two
  externally-trained liveness models that carry real weight licenses on real
  deployment hardware. The MIT-licensed DAMO FLIR IR model catches the
  vinyl-print species that defeats the algorithmic gate (122/123 frames across
  two cameras vs the gate's 98.6% APCER) with a clean genuine side; Intel's
  CelebA-Spoof-trained `anti-spoof-mn3` saturates at "spoof" for genuine users
  under indoor lighting and is not listed. Eval scripts and score summaries in
  `benchmarks/pad-candidates/`.
- `docs/STANDARDS.md`: maps the biometric standards that apply to a device
  login system (ISO/IEC 30107-3, 19795-1, 24745, the Windows Hello bar,
  Android's biometric classes) onto irlume's committed evidence, states what
  is not claimed under each (no certification, no Hello-bar FAR, no 3D-mask
  resistance), and points every number at the artifact and reproduction path
  behind it.
- `landmark_dump` example (issue #4): captures a raw IR strobe burst and
  writes, per frame, the PGM plus a CSV of all 478 FaceMesh landmark
  coordinates and the IR brightness (3x3 patch mean) at each; the input a
  landmark-anchored relief prototype needs without writing capture/detect/mesh
  glue. Coordinates print at full f32 precision so offline re-sampling from
  the CSV reproduces the tool's own brightness values exactly (verified: 8604
  landmarks across 18 live frames, worst delta 0.0044 from decimal printing).

### Changed

- **Ambient-flooded IR scenes get an actionable rejection.** When the scene's
  own infrared is strong enough to starve the anti-spoof depth and reflectance
  cues (measured threshold: ambient 170 on the 0-255 scale; above it, 0/129
  genuine samples passed in the 2026-07-16 field session), the denial now says
  "too much IR light behind you (open sky, sun, or bright lamps); turn away
  from the light or use your password" instead of "looks 2D, not a 3D face".
  Same fail-closed verdict, honest reason. The sensor cannot tell what the
  source is, so the message names examples rather than guessing. The measured
  ambient level also joins the liveness debug traces.
- The daemon startup notice about stale IR templates fires only when dark/dim
  login is actually broken (no usable current-space templates), not forever
  after a completed re-enroll.
- README documents the measured outdoor operating envelope; packaging comments
  record the verified distro onnxruntime versions (Fedora and Ubuntu are all
  below irlume's 1.24 floor, so the bundle stays).
- ARCHITECTURE.md documents the IR strobe capture and the opt-in ambient
  subtraction path with its gates (previously only in this changelog);
  ADR-0001 gains the acceptance bar for a future learned PAD model, including
  the model-inversion criterion raised in issue #4.
- Every operator-facing knob is now documented: SETUP.md gains a configuration
  reference (the four `/etc/irlume` + `/var/lib/irlume` config files, camera
  selection precedence, and the daemon environment variables from
  `IRLUME_MODELS_STRICT` through the TPM overrides), DEVELOPMENT.md lists the
  sandbox path overrides and the nine cargo example harnesses, and
  DEBUGGING.md covers the per-camera liveness tuning thresholds. `irlume
  set-cameras` appears in `irlume help` (it was the TUI picker's hidden
  backing command, but it is also the only scriptable way to persist a camera
  pair).

### Fixed

- **On Arch, the IR emitter self-heals at daemon startup, and the PAM
  include-layout wiring is corrected.** The daemon re-applies the IR emitter
  enable on startup so a suspend/resume or a fresh boot does not leave the
  emitter dark, and the PAM include layout is wired the way Arch's stack
  expects.
- **The PCR-signature parser rejects non-ASCII hex instead of panicking.** A
  multi-byte UTF-8 character in a hex field split a byte boundary and panicked
  the root daemon's parser; it now rejects non-ASCII input up front. Found by
  fuzzing the signature parser.
- **TUI micro-audit fixes.** A full pass over the TUI produced deliberate
  `[y]`/`[n]` confirmations (a stray key no longer counts as "yes"), correct
  rendering of the merge and delete prompts, a static two-row footer with all
  live messages moved to a scrollable Activity panel, and scroll-handling
  fixes for the enroll and operation views.
- **The universal `.deb` works on Debian 12 (and now Ubuntu 22.04).** It was
  built on Ubuntu 24.04 (glibc 2.39), so on Debian 12 (glibc 2.36) dpkg
  installed it and then every binary failed to start with "GLIBC_2.39 not
  found"; the package declared no libc floor, so nothing refused. The build
  now runs on a debian:12 base (binaries reference GLIBC_2.35 symbols at
  most), the package declares `libc6 (>= 2.35)` so older systems get a clean
  dpkg refusal instead of a broken install, and `build-deb.sh` asserts the
  declared floor covers what the binaries actually reference so a future base
  bump cannot reintroduce this silently. Found by container-testing the
  install matrix on Debian proper. The v0.2.1 release asset was rebuilt and
  replaced in place (same source, same tag; only the build base changed).
- **`install.sh` GPG verification can actually fire.** The script verified
  `SHA256SUMS.asc` against a keyserver fetch of the pinned key, but no `.asc`
  was published with releases and the key was not on keys.openpgp.org, so
  every install silently fell back to HTTPS + SHA256. Releases now ship
  `SHA256SUMS.asc`, and the installer carries the pinned public key inline
  (same trust anchor as the already-pinned fingerprint), importing it into a
  throwaway GNUPGHOME, with no keyserver dependency, and the user's keyring is
  never touched.
- **The Arch PKGBUILD builds on a clean system.** `clang` joins
  `makedepends`: the V4L2 bindings are generated by bindgen, which needs
  libclang at build time, so `makepkg` on a machine without clang failed in
  `v4l2-sys-mit`. Found by a container dry run of the AUR install; dev boxes
  had clang installed and never hit it. (AUR updated as pkgrel 2.)
- **Arch update and install paths point at the AUR.** `irlume update` on a
  pacman install and the one-step `install.sh` both still referenced a
  `.pkg.tar.zst` release asset that stopped shipping after 0.1.x, so each
  ended at a missing download. Both now use the AUR package (live since
  0.2.0): the installer runs `yay`/`paru` when present and prints the
  `makepkg` steps otherwise, and `irlume update` shows the helper and
  helper-less routes.

## [0.2.1] - 2026-07-16

### Fixed

- **`irlume enroll` merges into the matching profile instead of refusing.** A
  face can never own two profiles, so when a capture matches an existing
  profile the only thing the old refusal ("this face is already enrolled
  as ...") accomplished was forcing the same scans through `add-scan` by hand.
  Now the captured scans are added to the matching profile (up to the 30-scan
  cap; a full profile still refuses), the per-enrollment IR calibration is
  refitted, and the reply says what happened. A novel face still creates a new
  profile, and a capture that matches two different profiles is still refused.
  This also makes `irlume enroll` work as the documented 0.2.0 upgrade remedy:
  the anti-mixing guard used to refuse upgraders, whose faces still match
  their old profile through the unchanged RGB path, exactly when they needed
  fresh current-space scans to revive dark/dim login. On 0.2.0 itself, the
  working paths are `irlume tui` (Profiles, improve) or `irlume enroll --reset`.
- **Enroll captures only what fits.** A one-scan probe decides whether the
  face merges into an existing profile and sizes the session from the free
  slots: a profile with 5 slots left gets a 5-scan top-up instead of a 10-scan
  session that discards half, and a full profile (30 scans) is refused after
  one scan instead of ten. A new face still gets the normal 10.

## [0.2.0] - 2026-07-15

> **⚠ Breaking: re-enroll needed for dark/dim login.** This release removes the
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
  (`IRLUME_GRACE_MS` overrides). Only presence-class failures retry, never a
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

[0.4.0]: https://github.com/archledger/irlume/releases/tag/v0.4.0
[0.3.0]: https://github.com/archledger/irlume/releases/tag/v0.3.0
[0.2.1]: https://github.com/archledger/irlume/releases/tag/v0.2.1
[0.2.0]: https://github.com/archledger/irlume/releases/tag/v0.2.0
[0.1.5]: https://github.com/archledger/irlume/releases/tag/v0.1.5
[0.1.4]: https://github.com/archledger/irlume/releases/tag/v0.1.4
[0.1.3]: https://github.com/archledger/irlume/releases/tag/v0.1.3
[0.1.2]: https://github.com/archledger/irlume/releases/tag/v0.1.2
[0.1.1]: https://github.com/archledger/irlume/releases/tag/v0.1.1
[0.1.0]: https://github.com/archledger/irlume/releases/tag/v0.1.0

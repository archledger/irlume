%global tflite_ver v2.19.0
%global ort_ver 1.28.1

Name:           irlume
Version:        0.11.0
Release:        1%{?dist}
Summary:        Windows Hello-style face login for Linux

License:        GPL-3.0-or-later
URL:            https://github.com/archledger/irlume
# Packit fills VCS source from the signed tag.
Source0:        %{url}/archive/v%{version}/%{name}-%{version}.tar.gz
# Model weights: release assets on the version-independent models-v1 release,
# kept OUT of Git LFS so builds do not consume the account's LFS bandwidth
# quota. Packit/Copr fetch remote sources (net-on); verified by sha256 in %prep.
Source2:        %{url}/releases/download/models-v1/glintr100.onnx
Source3:        %{url}/releases/download/models-v1/face_detection_yunet_2023mar.onnx
Source4:        %{url}/releases/download/models-v1/face_landmark.onnx
Source5:        %{url}/releases/download/models-v1/blaze_face_short_range.onnx
Source7:        %{url}/releases/download/models-v1/face_landmarks_detector.tflite
Source8:        %{url}/releases/download/models-v1/liveness_vit.onnx
Source9:        %{url}/releases/download/models-v1/flir.onnx
# Bundled onnxruntime runtime (MIT). irlume needs the api-24 ABI (>=1.24);
# Fedora's own onnxruntime is below that in every release we build for
# (verified 2026-07-16: f43 1.20.1, f44 1.22.2; rawhide's 1.26 is the first
# to clear the floor), so we vendor the upstream Linux build. Revisit
# unbundling when the floor is met across our chroots. Packit/Copr fetch
# remote sources (net-on).
Source1:        https://github.com/microsoft/onnxruntime/releases/download/v%{ort_ver}/onnxruntime-linux-x64-%{ort_ver}.tgz
# Bundled TFLite C runtime (Apache-2.0), for native .tflite models (#295).
# Google publishes no prebuilt Linux C-API artifact at stable URLs, so irlume
# builds its own from the pinned tensorflow tag (scripts/build-tflite-runtime.sh)
# and publishes it on the tflite-runtime-* release; the daemon dlopens it from
# %%{_datadir}/%%{name}/tflite (the first path its resolver probes), so no env
# drop-in is needed. Update the digest together with tflite_ver.
Source6:        %{url}/releases/download/tflite-runtime-%{tflite_ver}/libtensorflowlite_c-%{tflite_ver}-linux-x64.tar.gz

BuildRequires:  cargo
BuildRequires:  rust
BuildRequires:  gcc
BuildRequires:  pam-devel
BuildRequires:  tpm2-tss-devel
BuildRequires:  systemd-devel
BuildRequires:  systemd-rpm-macros
# v4l2-sys-mit generates bindings at build time: bindgen dlopens libclang
# and parses the kernel's videodev2.h; tss-esapi locates tss2 via pkg-config.
BuildRequires:  clang-devel
BuildRequires:  kernel-headers
BuildRequires:  pkgconf-pkg-config
# Compiles packaging/selinux/irlume.te → irlume.pp in %%build.
BuildRequires:  selinux-policy-devel

# Runtime: onnxruntime is bundled (see Source1); the PAM stack + TPM + fprintd
# companion remain normal deps.
Requires:       pam
Requires:       tpm2-tss
Recommends:     fprintd
# Fedora enforces SELinux by default and the greeter can't reach the daemon
# without the policy module; pull the subpackage in by default (weak dep, so
# SELinux-disabled installs can still skip it).
Recommends:     %{name}-selinux = %{version}-%{release}
%{?systemd_requires}

%description
irlume authenticates you to Linux by your face with whatever camera the
machine has: an infrared (Windows Hello) camera enables the secure tier
(login, sudo, and TPM-sealed keyring unlock with algorithmic IR liveness)
while a regular RGB webcam enables convenient screen unlock, and a
fingerprint reader can join as a companion factor. A thin PAM module talks
to a privileged daemon that owns the camera and runs a clean-license model
stack. Gesture-gated requests use head nodding to approve and a head shake to
decline; passive PAD remains separate. Password is always the fallback; no
lockout.

%package selinux
Summary:        SELinux policy module for irlume
Requires:       %{name} = %{version}-%{release}
Requires(post): policycoreutils
BuildArch:      noarch
%description selinux
SELinux module letting the confined display-manager greeter reach the irlume
daemon socket. Only needed on SELinux-enforcing systems (Fedora default).

%prep
%autosetup -n %{name}-%{version}
# Verify the bundled onnxruntime (Source1) before unpacking: the .so runs in
# the privileged daemon, and Copr fetches remote sources without the Fedora
# lookaside's own integrity check. Update the digest together with ort_ver.
echo '2529aef968d0ad0603365054bc46ebefa7f0fe3bc12f28c5f729c99ddffe2a81  %{SOURCE1}' | sha256sum -c -
# Unpack the bundled onnxruntime (Source1) next to the source tree; installed
# below into %{_datadir}/%{name}/onnxruntime.
tar -xzf %{SOURCE1}
# Same verify-then-unpack for the bundled TFLite C runtime (Source6).
echo 'dd3abcdbc0f35a9466a682358955ac3826a9a81590cd6b8abcf98548e17bd311  %{SOURCE6}' | sha256sum -c -
tar -xzf %{SOURCE6}
# Verify the release-hosted model weights (Source2-5) the same way: they load in
# the privileged daemon, and Copr fetches remote sources without a lookaside
# checksum. Keep these in sync with models/SHA256SUMS.
echo 'a7933ea5330113b01c9b60351d8f4c33003f145d8470ac5f0e52ee2effe25c60  %{SOURCE2}' | sha256sum -c -
echo '8f2383e4dd3cfbb4553ea8718107fc0423210dc964f9f4280604804ed2552fa4  %{SOURCE3}' | sha256sum -c -
echo '821683be088447839638f79d64268bd501bdb72e5d9e262ec981c7e252956caf  %{SOURCE4}' | sha256sum -c -
echo 'c5453678015f6289c1d77bda88a8ba9c87574f01de1a05ba1909b9a7e08b237b  %{SOURCE5}' | sha256sum -c -
echo 'c7d54204ce0448474c7f3fa9af494787c0965cbdd6f20fc72867e43046bd43d5  %{SOURCE7}' | sha256sum -c -
echo 'c7f8a6f3054b11f9719f5e24d37ec227721608fff8b90373c6c3e7659864161c  %{SOURCE8}' | sha256sum -c -
echo 'df80cea7228b92562692e56aac965d35766c77399159798c552fb3c77b410c72  %{SOURCE9}' | sha256sum -c -

%build
cargo build --release --locked
# Compile the SELinux policy module from source (the .pp is a build artifact,
# not committed to git).
make -f %{_datadir}/selinux/devel/Makefile -C packaging/selinux irlume.pp

%install
install -Dm0755 target/release/irlumed %{buildroot}%{_bindir}/irlumed
install -Dm0755 target/release/irlume  %{buildroot}%{_bindir}/irlume
install -Dm0644 target/release/libpam_irlume.so %{buildroot}%{_libdir}/security/pam_irlume.so
# The KDE wallet handoff helper. libexec, not bindir: it is not a command a
# user runs, it takes a secret on stdin, and it is only meaningful inside a
# PAM transaction.
install -Dm0755 target/release/irlume-kwallet-init %{buildroot}%{_libexecdir}/%{name}/irlume-kwallet-init
install -Dm0755 target/release/irlume-gkr-unlock %{buildroot}%{_libexecdir}/%{name}/irlume-gkr-unlock
# Bundled models (release assets, verified in %prep) → /usr/share/irlume/models
install -Dm0644 %{SOURCE2} %{buildroot}%{_datadir}/%{name}/models/glintr100.onnx
install -Dm0644 %{SOURCE3} %{buildroot}%{_datadir}/%{name}/models/face_detection_yunet_2023mar.onnx
install -Dm0644 %{SOURCE4} %{buildroot}%{_datadir}/%{name}/models/face_landmark.onnx
install -Dm0644 %{SOURCE5} %{buildroot}%{_datadir}/%{name}/models/blaze_face_short_range.onnx
install -Dm0644 %{SOURCE7} %{buildroot}%{_datadir}/%{name}/models/face_landmarks_detector.tflite
install -Dm0644 %{SOURCE8} %{buildroot}%{_datadir}/%{name}/models/liveness_vit.onnx
install -Dm0644 %{SOURCE9} %{buildroot}%{_datadir}/%{name}/models/flir.onnx
install -Dm0644 packaging/systemd/irlumed.service %{buildroot}%{_unitdir}/irlumed.service
install -Dm0644 packaging/systemd/irlumed.socket %{buildroot}%{_unitdir}/irlumed.socket
# Self-heal wiring watcher: re-applies irlume's greeter PAM lines if a distro
# update strips them (no-op unless `login enable` was run and the lines went
# missing). Enabled by preset; harmless when login was never wired.
install -Dm0644 packaging/systemd/irlume-reconcile.path %{buildroot}%{_unitdir}/irlume-reconcile.path
install -Dm0644 packaging/systemd/irlume-reconcile.service %{buildroot}%{_unitdir}/irlume-reconcile.service
install -Dm0644 packaging/systemd/irlume-reconcile.timer %{buildroot}%{_unitdir}/irlume-reconcile.timer
# Bundled onnxruntime runtime + a drop-in pointing ORT_DYLIB_PATH at it (cp -a
# to preserve the .so version symlinks).
install -d %{buildroot}%{_datadir}/%{name}/onnxruntime/lib
cp -a onnxruntime-linux-x64-%{ort_ver}/lib/libonnxruntime.so* %{buildroot}%{_datadir}/%{name}/onnxruntime/lib/
# Bundled TFLite C runtime; the daemon's resolver probes this path first, so
# unlike onnxruntime it needs no environment drop-in.
install -d %{buildroot}%{_datadir}/%{name}/tflite
install -m0755 libtensorflowlite_c-%{tflite_ver}-linux-x64/lib/libtensorflowlite_c.so %{buildroot}%{_datadir}/%{name}/tflite/libtensorflowlite_c.so
install -m0644 libtensorflowlite_c-%{tflite_ver}-linux-x64/LICENSE.tensorflow %{buildroot}%{_datadir}/%{name}/tflite/LICENSE.tensorflow
install -m0644 libtensorflowlite_c-%{tflite_ver}-linux-x64/PROVENANCE %{buildroot}%{_datadir}/%{name}/tflite/PROVENANCE
# Not all of libtensorflowlite_c.so is Apache-2.0: it statically links Eigen
# (MPL-2.0), XNNPACK, ruy and others. Name them beside the library.
install -m0644 packaging/licenses/THIRD-PARTY-NOTICES.tflite %{buildroot}%{_datadir}/%{name}/tflite/THIRD-PARTY-NOTICES
install -Dm0644 packaging/fedora/10-ort.conf %{buildroot}%{_unitdir}/irlumed.service.d/10-ort.conf
install -Dm0644 packaging/selinux/irlume.pp %{buildroot}%{_datadir}/selinux/packages/irlume.pp
# Preset: the daemon is enabled on install (see %%post); it only serves a local
# socket and auth stays opt-in, so "installed" should mean "works".
install -Dm0644 packaging/fedora/90-irlume.preset %{buildroot}%{_presetdir}/90-irlume.preset
# The machine-API contract: the schema a consumer validates our JSON against,
# shipped with the engine that implements it so the two cannot be a version
# apart on a user's machine.
install -Dm0644 schemas/machine-api-v1.schema.json %{buildroot}%{_datadir}/%{name}/schemas/machine-api-v1.schema.json

%post
# %%systemd_post honours our shipped preset → enables irlumed + the PAM-wiring
# self-heal path unit on first install.
%systemd_post irlumed.socket irlumed.service irlume-reconcile.path irlume-reconcile.timer irlume-reconcile.service
# Also start it now so `irlume tui` works immediately after `dnf install`
# (no-op in chroots/containers where systemd isn't running).
if [ $1 -eq 1 ]; then
    systemctl start irlumed.service &>/dev/null || :
fi
# Start the PAM-file watcher now (else it only becomes active at the next boot),
# and run one reconcile: on an upgrade this adopts an already-wired install into
# the self-heal marker, and re-applies wiring a same-transaction strip removed.
# Both self-gate and no-op on a fresh/un-wired box.
systemctl start irlume-reconcile.path &>/dev/null || :
systemctl start irlume-reconcile.timer &>/dev/null || :
# The timer is NEW in 0.7.0 and %%systemd_post only applies presets on a FRESH
# install, so an upgrader would never get the backstop. Arm it once, recorded by
# a marker, leaving a later deliberate disable alone.
if [ ! -e /var/lib/irlume/.reconcile-timer-armed ]; then
    mkdir -p /var/lib/irlume
    systemctl enable --now irlume-reconcile.timer &>/dev/null || :
    : > /var/lib/irlume/.reconcile-timer-armed
fi
systemctl start irlume-reconcile.service &>/dev/null || :
# PAM wiring is opt-in (irlume login enable); never auto-wire auth on install.
# The pre-0.2.0 re-enroll notice lives in %%triggerpostun below, because $1 here
# counts installed packages and cannot tell which version is being replaced.

%preun
%systemd_preun irlumed.socket irlumed.service irlume-reconcile.path irlume-reconcile.timer irlume-reconcile.service

%postun
%systemd_postun_with_restart irlumed.service
%systemd_postun irlume-reconcile.path irlume-reconcile.timer irlume-reconcile.service

# 0.2.0 removed the IR adapter, so IR templates enrolled under 0.1.x no longer
# match; those users need `irlume enroll` for dark/dim login (RGB login and the
# password are unaffected). This has to be a trigger: in %%post, $1 is the count
# of installed packages, so `[ $1 -gt 1 ]` means "some upgrade" and never "an
# upgrade from before 0.2.0". Gated that way it printed on EVERY Fedora upgrade
# including 0.6.1 to 0.7.0, telling users an adapter had just been removed that
# had in fact been gone for five releases. The Arch scriptlet already compares
# the old version with vercmp and the PPA carries it in debian/NEWS; this makes
# Fedora agree with them.
%triggerpostun -- irlume < 0.2.0
echo "irlume: 0.2.0 removed the IR adapter. Because you upgraded from an older" >&2
echo "irlume: version, dark/dim face login needs a re-enroll: run 'irlume enroll'." >&2
echo "irlume: bright-light login keeps working; your password is unaffected." >&2

%post selinux
semodule -i %{_datadir}/selinux/packages/irlume.pp 2>/dev/null || :
# The daemon (started by the main package's %%post, same transaction) bound its
# socket before the policy existed; restart so the socket gets its label and
# the confined greeter can actually connect. The restorecon is the backstop:
# with rpm's SELinux plugin the policy commit can land after the restarted
# daemon's bind, leaving the socket var_run_t (observed live on fc44); the
# irlume.fc entry lets restorecon settle it regardless of timing.
systemctl try-restart irlumed.service &>/dev/null || :
restorecon /run/irlume.sock 2>/dev/null || :

%postun selinux
[ $1 -eq 0 ] && semodule -r irlume 2>/dev/null || :

%files
%license LICENSE
%doc README.md docs/SECURITY_AT_REST.md docs/MACHINE-API.md docs/INTEGRATION.md
%{_bindir}/irlumed
%{_bindir}/irlume
%{_libdir}/security/pam_irlume.so
%dir %{_libexecdir}/%{name}
%{_libexecdir}/%{name}/irlume-kwallet-init
%{_libexecdir}/%{name}/irlume-gkr-unlock
# Own the directories the globs populate (rpmlint: "directory not owned by a
# package"; also leaves them behind on erase otherwise).
%dir %{_datadir}/%{name}
%dir %{_datadir}/%{name}/models
%dir %{_datadir}/%{name}/onnxruntime
%dir %{_datadir}/%{name}/onnxruntime/lib
%dir %{_datadir}/%{name}/tflite
%{_datadir}/%{name}/tflite/*
%dir %{_datadir}/%{name}/schemas
%{_datadir}/%{name}/schemas/*.json
%{_datadir}/%{name}/models/*.onnx
%{_datadir}/%{name}/models/*.tflite
%{_datadir}/%{name}/onnxruntime/lib/*
%{_unitdir}/irlumed.service
%{_unitdir}/irlumed.socket
%{_unitdir}/irlumed.service.d/10-ort.conf
%{_unitdir}/irlume-reconcile.path
%{_unitdir}/irlume-reconcile.service
%{_unitdir}/irlume-reconcile.timer
%{_presetdir}/90-irlume.preset

%files selinux
%{_datadir}/selinux/packages/irlume.pp

%changelog
* Sun Aug 23 2026 archledger <archledger236@gmail.com> - 0.11.0-1
- SecureDark: scene gate + 0.635 dark threshold (ADR-0016)
- Capture-path: role-aware flush (-3.3s/auth), schedule-aware pairing (ADR-0014)
- IR emitter lock: clean installs keep IR auth under confinement
- AppArmor: template-key locks + media-controller reads
- TUI: Diagnostics fixes issues in-app; visible support report; exit chip
- install.sh: verified channel fallbacks for Copr/PPA outages
- uninstall: socket, units, AppArmor profile, user XDG state swept

* Wed Aug 12 2026 archledger <archledger236@gmail.com> - 0.10.0-1
- Per-service consent gestures with a head-shake decline; elevation and polkit prompts require a nod by default
- The keyring-release gesture default changed from ON to OFF; opt back in with irlume credential-release-challenge credential_release on
- The landmark mesh is now the published .tflite on a bundled TFLite runtime; a runtime that fails to load degrades to nod-only instead of stopping the daemon
- The polkit PAM stanza migrates to the abort=die control on upgrade so the shake decline works
- login enable refuses to act on an unestablished camera reading, closing a path that could unwire face auth from every greeter
- Camera fixes: session recovery keeps the emitter lit, scanning opens fewer nodes, capture verifies the negotiated format, backlight compensation is restored after sessions
- Repair and doctor report the TFLite runtime, a starting daemon, and per-service gesture state accurately
* Wed Aug 05 2026 archledger <archledger236@gmail.com> - 0.9.0-1
- A sandboxed run could delete live template keys and recovery envelopes, because those paths ignored IRLUME_STATE_DIR; all state paths now honor the override
- recovery setup accepted an empty passphrase when stdin was a pipe; the 12-character floor now applies to both paths
- The AppArmor profile blocked every Tier 2 TPM unseal by omitting /var/lib/systemd/pcrlock.json, so the keyring stopped opening at login
- The TUI and CLI reported "off"/"none" for state they could not read; an unanswered question now renders as unknown
- The TUI no longer opens camera nodes while the daemon streams them, which failed enrollment on strict UVC modules (#187)
- A profile can hold templates for more than one recognizer; profiles add-scan and profiles forget-model manage that state (#288)
- The recognition stage opens to measured third-party models, starting with buffalo_l (#276)
- Every catalog entry names its pipeline stage; detection and landmarks stay closed
- A native TFLite runtime ships at /usr/share/irlume/tflite/ behind a stage gate that stays closed
- Dark login was unreachable since 0.8.0 and works again (#284)
- Garbage landmark geometry abstains instead of scoring confident wrong numbers
- enroll --scans and camera-tune --rounds with a non-numeric value are usage errors, not a capture at the default count
- The CLI no longer opens video nodes while the daemon streams them, completing the #187 fix that #300 started in the TUI
- A scan budget an older daemon did not report reads as unknown rather than zero, which had silently under-enrolled during the upgrade window
- Packit could not build an SRPM at all since the TFLite runtime tag was published; .packit.yaml now filters to release tags
- CI validates the AppArmor profiles, which nothing checked before
* Tue Aug 04 2026 archledger <archledger236@gmail.com> - 0.8.1-1
- A printed photograph of an enrolled face passes the built-in liveness gate; the cue cannot be repaired by tuning it, and the mitigation is `irlume models enable flir` (advisory, #235)
- A blown infrared frame is refused rather than judged, so clipping no longer silences the PAD cue (#237)
- Burst selection prefers a lit frame that is not clipped, which is how ordinary captures reached that regime (#221)
- The sealed envelope no longer holds the login password: the KWallet key on KDE, a random re-keyed token on GNOME (#250)
- A fingerprint login after a reboot no longer meets a keyring prompt; systemd owns the socket and the per-boot sweep is gone (#244, #249)
- Keyring unseal latency drops from 10.88s to 2.71s on a discrete TPM; the policy digests are computed in software (#246, #248)
- A retryable TPM PCR-counter race no longer surfaces as a keyring prompt on a fast login
- irlume no longer names itself as the application holding its own camera, and enrolment stops opening one camera twice (#187)
- A status read can no longer make a login wait (#212)

* Sun Aug 02 2026 archledger <archledger236@gmail.com> - 0.8.0-1
- Emitter write honours the Windows exclusive-control model; consumer scan reports its blind spot (#169, #207)
- fingerprint enable and status print per-surface coverage; the fingerprint-only gate parses PAM rule fields (#155)
- Keyring hand-off check for KWallet and GNOME Keyring; openSUSE and renamed-substack wiring fixes
- gdm-fingerprint gains the keyring release pair so a fingerprint login opens the wallet
- camera-tune is reachable from the TUI with an upfront cost explanation (#170)
- mean_step consent discriminator recorded with the evidence, strobe-aware (#101)
- TUI: all machine probes moved off the UI thread; slow-TPM machines get a responsive TUI and a visible profile list
- pamwire split into submodules; origin_tests flake fixed structurally (#194)

* Thu Jul 30 2026 archledger <archledger236@gmail.com> - 0.7.2-1
- IRLUME_IR_EMITTER is checked against the camera's descriptor before any write
- Login transactions in the machine API: plan, apply, verify, rollback
- IR frames are classified by the camera's illumination flag, not by brightness

* Wed Jul 29 2026 archledger <archledger236@gmail.com> - 0.7.1-1
- Security: irlume no longer searches for an IR-emitter control by writing
  guessed values to UVC extension units. That search destroyed a reporter's
  camera (#159) and ran unattended: from 0.1.0 on enrolment, from 0.3.0 on every
  daemon start. Discovery now reads the camera's USB descriptor, addresses only
  Microsoft's documented camera-control unit and only selectors it advertises,
  builds the value from the camera's own answers, and runs only when asked.
- Configurations written by the old search are refused on upgrade.

* Tue Jul 28 2026 archledger <archledger236@gmail.com> - 0.7.0-1
- Camera arbitration: an authentication is no longer queued behind preview work
- Versioned read-only JSON machine API for desktop integrations
- Consent gesture: measured thresholds, discoverable prompts, diagnosable refusals
- Daemon hardening: per-uid refusal throttle and a wedged-capture watchdog
- ly display manager support
- Fix: the control socket is reachable again from a user-context PAM stack

* Fri Jul 24 2026 archledger <archledger236@gmail.com> - 0.6.1-1
- Update resilience: login self-heal survives an inactive watcher and a
  pre-marker upgrade; doctor warns on an unrecognized display manager; a pinned
  camera pair re-anchors by device identity after a udev renumber.
- Pre-release audit hardening (bitwarden setup, doctor install-hygiene, TUI
  Ctrl-C, recovery passphrase floor) and liveness fail-closed on a missing
  challenge model.
- Model weights are fetched from the models-v1 release (Source2-5), off Git LFS.

* Thu Jul 23 2026 archledger <archledger236@gmail.com> - 0.6.0-1
- Face-approve app prompts via polkit (Bitwarden biometric unlock, pkexec) with
  a deliberate consent gesture (head nod, or eye closure after calibrate-closure);
  fingerprint coexistence (face OR fingerprint); distro-update PAM self-heal
  (login reconcile + irlume-reconcile.path); doctor login-keyring probe.
- Security: pam_irlume ignores IRLUME_SOCKET in setuid contexts (local root fix).

* Tue Jul 21 2026 archledger <archledger236@gmail.com> - 0.5.0-1
- Field-hardening release: Tier-1 signed-PCR sealing fix with automatic
  tier upgrade, fingerprint robustness batch, IR format negotiation
  (Y16/NV12/YUYV), PAM panic firewall, hardware-validated in CI

* Tue Jul 21 2026 archledger <archledger236@gmail.com> - 0.4.0-1
- New: RGB pixel-format negotiation (NV12 alongside YUYV); MJPEG-only cameras
  get a clear error and an `irlume doctor` diagnosis instead of failing at
  capture. Doctor now recognizes Intel IPU6/IPU7 cameras and warns when a user
  is enrolled but no greeter is wired.
- New: consecutive-failure throttle (`IRLUME_RATE_LIMIT`,
  `IRLUME_RATE_COOLDOWN_SECS`) on the login/sudo and keyring paths, and an
  informed opt-in for the anti-spoof blink challenge at enrollment (default
  off), toggleable in the TUI Settings screen with `[c]`.
- Security: a remote (SSH) session no longer fires the local camera; stage-2
  fusion weighs RGB by real brightness again; the dark path enforces the
  per-user depth floor; sealed key/recovery files are created at mode 0600
  atomically. The daemon unit is sandboxed and stops within 10s.
- Fixed: malformed `pcrlock.json` hex, a non-finite detector score, and a
  truncated IR frame no longer panic the daemon.
* Sun Jul 19 2026 archledger <archledger236@gmail.com> - 0.3.0-1
- New: `irlume uninstall` (CLI and TUI) removes irlume the way it was installed,
  un-wiring PAM and stopping the daemon first so a box is never left locked out,
  then removing the package (dnf/apt/pacman/source) and cleaning residual repo
  and drop-in files. The TUI asks for a typed-word confirmation.
- New: opt-in third-party liveness models via `irlume models`, fetched from the
  publisher on the operator's machine, SHA-256 pinned, never shipped or warranted;
  wired deny-only. See ADR-0001 criterion 4 and docs/pad-results.
- New: NixOS module (`nixosModules.irlume`) with per-greeter PAM wiring.
- Merge-aware enrollment reaches the TUI: enrolling a face already known adds the
  scans to that profile instead of creating a duplicate; one face is one profile.
- Fixed: on Arch the IR emitter self-heals at daemon startup, and the PAM
  include-layout wiring is corrected.
- Fixed: the PCR-signature parser rejects non-ASCII hex instead of panicking
  (root-daemon hardening, found by fuzzing).
- A batch of TUI fixes from a full micro-audit: deliberate y/n confirmations,
  correct merge-prompt rendering, a static footer with a scrollable activity
  panel, and scroll-handling fixes.

* Thu Jul 16 2026 archledger <archledger236@gmail.com> - 0.2.1-1
- irlume enroll now merges into the profile the captured face already matches,
  adding the scans instead of refusing with "this face is already enrolled".
  This makes plain `irlume enroll` the working upgrade remedy the 0.2.0 notes
  promised for restoring dark/dim login.
- The enroll capture is sized to the matched profile's free scan slots: a
  profile with 5 slots left gets a 5-scan top-up instead of a 10-scan session
  that discards half, and a full profile is refused after one probe scan.

* Wed Jul 15 2026 archledger <archledger236@gmail.com> - 0.2.0-1
- BREAKING: re-enroll needed for dark/dim (IR) login. The IR adapter was
  removed (its training data was research-only), so IR templates enrolled under
  0.1.x no longer match. Bright-light (RGB) login keeps working and the password
  is unaffected; run `irlume enroll` to restore dark/dim login.
- Removed the research-only-trained ir_adapter.onnx; the default IR path is raw
  AuraFace plus per-enrollment on-device calibration (no bundled weights).
- Detection cascade: BlazeFace short-range rescue on a YuNet miss (saturated
  outdoor frames), FaceMesh upgraded to the 478-point FaceLandmarker mesh.
- Presence grace window after the consent gesture (15s login/lock, 5s sudo/su),
  retrying only presence-class failures.
- cargo-deny license gate enabled; dead ndarray dependency dropped.
* Sun Jul 12 2026 archledger <archledger236@gmail.com> - 0.1.5-1
- Tier 2 TPM sealing via systemd-pcrlock: on a pcrlock-provisioned machine new
  seals bind to the pcrlock NV index, so a firmware/Secure Boot update needs one
  `make-policy` re-run instead of a re-arm. Sealing tries signed, then pcrlock,
  then the literal PCR-7 policy, round-trip-verifying each; existing envelopes
  are untouched until the next arm/reseal.
- `status`, `diag`, and the TUI name the seal tier and warn on PCR drift.
- TUI fix: Activity history scroll (PgUp/PgDn) now works mid-operation and
  mid-enrollment; the Welcome [i] identify key works in the default view.
- tss-esapi builds from the archledger fork (7.7.0 + PolicyAuthorizeNV wrapper +
  upstream PR #530 session-leak fix), pinned to an exact commit.
- Opt-in IR ambient subtraction gate reworked against a real sunlight dataset.

* Tue Jul 07 2026 archledger <archledger236@gmail.com> - 0.1.4-1
- Distribution/maintenance release (face auth unchanged): `irlume update` now
  adapts to distro, install channel, and CPU arch, and reports the real
  installed package version; universal .deb for Ubuntu derivatives; Arch makepkg
  git-lfs fix; deterministic PPA orig; declared MSRV raised to Rust 1.88.

* Tue Jul 07 2026 archledger <archledger236@gmail.com> - 0.1.3-1
- Every major login manager profiled for on-demand face auth (GDM/SDDM/LightDM/
  greetd/COSMIC/Plasma Login); `irlume logs` + IRLUME_LOG=debug diagnostics.
- Directional, per-user auto-calibrated enrollment guidance; 5 scans; frontal
  framing enforced at capture. TUI hint bar.
- Security: peer-authenticated 1:N identify; redacted journal deny lines.

* Sun Jul 05 2026 archledger <archledger236@gmail.com> - 0.1.2-1
- First-run: daemon enabled+started at install (systemd preset + %%post);
  irlume-selinux pulled in by default (Recommends) and the daemon restarts
  after policy load so the greeter can reach the freshly labeled socket.
- TUI: essential-view wizard, enroll auto-starts a stopped daemon and
  resumes, [w] wires login from the Done tab, version subcommand.
- login disable --apply now always unwires /etc/pam.d/sudo.

* Sat Jul 04 2026 archledger <archledger236@gmail.com> - 0.1.1-1
- Copr pipeline fixes: enable_net for cargo, committed Cargo.lock,
  bindgen/pkg-config BuildRequires, SELinux policy built from source.

* Thu Jul 02 2026 archledger <archledger236@gmail.com> - 0.1.0-1
- Initial package: daemon + CLI + PAM module, bundled models, SELinux subpackage.

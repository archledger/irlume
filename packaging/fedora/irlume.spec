%global ort_ver 1.24.4

Name:           irlume
Version:        0.6.1
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
# Bundled onnxruntime runtime (MIT). irlume needs the api-24 ABI (>=1.24);
# Fedora's own onnxruntime is below that in every release we build for
# (verified 2026-07-16: f43 1.20.1, f44 1.22.2; rawhide's 1.26 is the first
# to clear the floor), so we vendor the upstream Linux build. Revisit
# unbundling when the floor is met across our chroots. Packit/Copr fetch
# remote sources (net-on).
Source1:        https://github.com/microsoft/onnxruntime/releases/download/v%{ort_ver}/onnxruntime-linux-x64-%{ort_ver}.tgz

BuildRequires:  cargo
BuildRequires:  rust
BuildRequires:  gcc
BuildRequires:  pam-devel
BuildRequires:  tpm2-tss-devel
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
stack (YuNet + AuraFace). Password is always the fallback; no lockout.

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
echo '3a211fbea252c1e66290658f1b735b772056149f28321e71c308942cdb54b747  %{SOURCE1}' | sha256sum -c -
# Unpack the bundled onnxruntime (Source1) next to the source tree; installed
# below into %{_datadir}/%{name}/onnxruntime.
tar -xzf %{SOURCE1}
# Verify the release-hosted model weights (Source2-5) the same way: they load in
# the privileged daemon, and Copr fetches remote sources without a lookaside
# checksum. Keep these in sync with models/SHA256SUMS.
echo 'a7933ea5330113b01c9b60351d8f4c33003f145d8470ac5f0e52ee2effe25c60  %{SOURCE2}' | sha256sum -c -
echo '8f2383e4dd3cfbb4553ea8718107fc0423210dc964f9f4280604804ed2552fa4  %{SOURCE3}' | sha256sum -c -
echo '821683be088447839638f79d64268bd501bdb72e5d9e262ec981c7e252956caf  %{SOURCE4}' | sha256sum -c -
echo 'c5453678015f6289c1d77bda88a8ba9c87574f01de1a05ba1909b9a7e08b237b  %{SOURCE5}' | sha256sum -c -

%build
cargo build --release --locked
# Compile the SELinux policy module from source (the .pp is a build artifact,
# not committed to git).
make -f %{_datadir}/selinux/devel/Makefile -C packaging/selinux irlume.pp

%install
install -Dm0755 target/release/irlumed %{buildroot}%{_bindir}/irlumed
install -Dm0755 target/release/irlume  %{buildroot}%{_bindir}/irlume
install -Dm0644 target/release/libpam_irlume.so %{buildroot}%{_libdir}/security/pam_irlume.so
# Bundled models (release assets, verified in %prep) → /usr/share/irlume/models
install -Dm0644 %{SOURCE2} %{buildroot}%{_datadir}/%{name}/models/glintr100.onnx
install -Dm0644 %{SOURCE3} %{buildroot}%{_datadir}/%{name}/models/face_detection_yunet_2023mar.onnx
install -Dm0644 %{SOURCE4} %{buildroot}%{_datadir}/%{name}/models/face_landmark.onnx
install -Dm0644 %{SOURCE5} %{buildroot}%{_datadir}/%{name}/models/blaze_face_short_range.onnx
install -Dm0644 packaging/systemd/irlumed.service %{buildroot}%{_unitdir}/irlumed.service
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
%systemd_post irlumed.service irlume-reconcile.path irlume-reconcile.timer irlume-reconcile.service
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
# Upgrade from a version that shipped the IR adapter (< 0.2.0): dark/dim IR
# login needs a re-enroll (RGB login keeps working). Bright-line the notice.
if [ $1 -gt 1 ]; then
    echo "irlume: this upgrade removed the IR adapter. If you enrolled before 0.2.0," >&2
    echo "irlume: dark/dim face login needs a re-enroll: run 'irlume enroll'." >&2
    echo "irlume: bright-light login keeps working; your password is unaffected." >&2
fi

%preun
%systemd_preun irlumed.service irlume-reconcile.path irlume-reconcile.timer irlume-reconcile.service

%postun
%systemd_postun_with_restart irlumed.service
%systemd_postun irlume-reconcile.path irlume-reconcile.timer irlume-reconcile.service

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
# Own the directories the globs populate (rpmlint: "directory not owned by a
# package"; also leaves them behind on erase otherwise).
%dir %{_datadir}/%{name}
%dir %{_datadir}/%{name}/models
%dir %{_datadir}/%{name}/onnxruntime
%dir %{_datadir}/%{name}/onnxruntime/lib
%dir %{_datadir}/%{name}/schemas
%{_datadir}/%{name}/schemas/*.json
%{_datadir}/%{name}/models/*.onnx
%{_datadir}/%{name}/onnxruntime/lib/*
%{_unitdir}/irlumed.service
%{_unitdir}/irlumed.service.d/10-ort.conf
%{_unitdir}/irlume-reconcile.path
%{_unitdir}/irlume-reconcile.service
%{_unitdir}/irlume-reconcile.timer
%{_presetdir}/90-irlume.preset

%files selinux
%{_datadir}/selinux/packages/irlume.pp

%changelog
* Thu Jul 24 2026 archledger <archledger236@gmail.com> - 0.6.1-1
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

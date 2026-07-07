%global ort_ver 1.24.4

Name:           irlume
Version:        0.1.3
Release:        1%{?dist}
Summary:        Windows Hello-style face login for Linux

License:        GPL-3.0-or-later
URL:            https://github.com/archledger/irlume
# Packit fills VCS source from the signed tag; models come via Git LFS.
Source0:        %{url}/archive/v%{version}/%{name}-%{version}.tar.gz
# Bundled onnxruntime runtime (MIT). Fedora ships 1.22 but irlume needs the
# api-24 ABI (>=1.24), so we vendor the upstream Linux build instead of
# depending on an external Copr. Packit/Copr fetch remote sources (net-on).
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
# without the policy module — pull the subpackage in by default (weak dep, so
# SELinux-disabled installs can still skip it).
Recommends:     %{name}-selinux = %{version}-%{release}
%{?systemd_requires}

%description
irlume authenticates you to Linux by your face with whatever camera the
machine has: an infrared (Windows Hello) camera enables the secure tier —
login, sudo, and TPM-sealed keyring unlock with algorithmic IR liveness —
while a regular RGB webcam enables convenient screen unlock, and a
fingerprint reader can join as a companion factor. A thin PAM module talks
to a privileged daemon that owns the camera and runs a clean-license model
stack (YuNet + AuraFace). Password is always the fallback — no lockout.

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
# Unpack the bundled onnxruntime (Source1) next to the source tree; installed
# below into %{_datadir}/%{name}/onnxruntime.
tar -xzf %{SOURCE1}

%build
cargo build --release --locked
# Compile the SELinux policy module from source (the .pp is a build artifact,
# not committed to git).
make -f %{_datadir}/selinux/devel/Makefile -C packaging/selinux irlume.pp

%install
install -Dm0755 target/release/irlumed %{buildroot}%{_bindir}/irlumed
install -Dm0755 target/release/irlume  %{buildroot}%{_bindir}/irlume
install -Dm0644 target/release/libpam_irlume.so %{buildroot}%{_libdir}/security/pam_irlume.so
# Bundled models (Git LFS) → /usr/share/irlume/models
for m in glintr100 face_detection_yunet_2023mar face_landmark ir_adapter; do
    install -Dm0644 models/$m.onnx %{buildroot}%{_datadir}/%{name}/models/$m.onnx
done
install -Dm0644 packaging/systemd/irlumed.service %{buildroot}%{_unitdir}/irlumed.service
# Bundled onnxruntime runtime + a drop-in pointing ORT_DYLIB_PATH at it (cp -a
# to preserve the .so version symlinks).
install -d %{buildroot}%{_datadir}/%{name}/onnxruntime/lib
cp -a onnxruntime-linux-x64-%{ort_ver}/lib/libonnxruntime.so* %{buildroot}%{_datadir}/%{name}/onnxruntime/lib/
install -Dm0644 packaging/fedora/10-ort.conf %{buildroot}%{_unitdir}/irlumed.service.d/10-ort.conf
install -Dm0644 packaging/selinux/irlume.pp %{buildroot}%{_datadir}/selinux/packages/irlume.pp
# Preset: the daemon is enabled on install (see %%post) — it only serves a local
# socket and auth stays opt-in, so "installed" should mean "works".
install -Dm0644 packaging/fedora/90-irlume.preset %{buildroot}%{_presetdir}/90-irlume.preset

%post
# %%systemd_post honours our shipped preset → enables irlumed on first install.
%systemd_post irlumed.service
# Also start it now so `irlume tui` works immediately after `dnf install`
# (no-op in chroots/containers where systemd isn't running).
if [ $1 -eq 1 ]; then
    systemctl start irlumed.service &>/dev/null || :
fi
# PAM wiring is opt-in (irlume login enable) — never auto-wire auth on install.

%preun
%systemd_preun irlumed.service

%postun
%systemd_postun_with_restart irlumed.service

%post selinux
semodule -i %{_datadir}/selinux/packages/irlume.pp 2>/dev/null || :
# The daemon (started by the main package's %%post, same transaction) bound its
# socket before the policy existed — restart so the socket gets its label and
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
%doc README.md docs/SECURITY_AT_REST.md
%{_bindir}/irlumed
%{_bindir}/irlume
%{_libdir}/security/pam_irlume.so
%{_datadir}/%{name}/models/*.onnx
%{_datadir}/%{name}/onnxruntime/lib/*
%{_unitdir}/irlumed.service
%{_unitdir}/irlumed.service.d/10-ort.conf
%{_presetdir}/90-irlume.preset

%files selinux
%{_datadir}/selinux/packages/irlume.pp

%changelog
* Mon Jul 07 2026 archledger <archledger236@gmail.com> - 0.1.3-1
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

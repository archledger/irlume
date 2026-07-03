%global ort_ver 1.24.4

Name:           irlume
Version:        0.1.0
Release:        1%{?dist}
Summary:        Local IR face authentication for Linux (clean-BOM, TPM-sealed)

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

# Runtime: onnxruntime is bundled (see Source1); the PAM stack + TPM + fprintd
# companion remain normal deps.
Requires:       pam
Requires:       tpm2-tss
Recommends:     fprintd
%{?systemd_requires}

%description
irlume authenticates you to Linux by your face using the infrared (Windows
Hello) camera: a thin PAM module talks to a privileged daemon that owns the
camera, runs a clean-license model stack (YuNet + AuraFace) with algorithmic IR
liveness, and TPM-seals the login credential so a face match can unlock the
keyring. Password is always the fallback — no lockout.

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
install -Dm0644 packaging/selinux/irlume.pp %{buildroot}%{_datadir}/selinux/packages/irlume.pp 2>/dev/null || :

%post
%systemd_post irlumed.service
# PAM wiring is opt-in (irlume login enable) — never auto-wire auth on install.

%preun
%systemd_preun irlumed.service

%postun
%systemd_postun_with_restart irlumed.service

%post selinux
semodule -i %{_datadir}/selinux/packages/irlume.pp 2>/dev/null || :

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

%files selinux
%{_datadir}/selinux/packages/irlume.pp

%changelog
* Thu Jul 02 2026 archledger <archledger236@gmail.com> - 0.1.0-1
- Initial package: daemon + CLI + PAM module, bundled models, SELinux subpackage.

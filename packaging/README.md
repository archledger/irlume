# Packaging irlume

Family-aware packaging (see `../docs/cross-distro/family-vs-capability.md`): the
concerns that differ here — PAM module directory, onnxruntime dependency, LSM
policy, package format — are genuine distro conventions, so each family gets its
own recipe. Everything the daemon does at *runtime* stays capability-detected.

## Shared install layout (FHS, all families)

| Artifact | Path |
|---|---|
| `irlumed`, `irlume` | `/usr/bin/` |
| `pam_irlume.so` | Fedora `/usr/lib64/security/` · Debian `/usr/lib/x86_64-linux-gnu/security/` · Arch `/usr/lib/security/` |
| models (LFS, bundled) | `/usr/share/irlume/models/*.onnx` |
| systemd unit | `/usr/lib/systemd/system/irlumed.service` (from `systemd/irlumed.service`) |
| LSM policy | Fedora SELinux module · Debian `apparmor/usr.local.bin.irlumed` (path-adjusted) · Arch none |

Models are bundled (Git LFS) — no fetch step. Packages that build from a git
checkout must `git lfs pull` first so the real weights (not pointers) are staged.

## Per-family

- **Fedora** — `fedora/irlume.spec` + `../.packit.yaml`: Copr builds from signed
  GitHub tags (the linhello pipeline). Requires `onnxruntime`; PAM to
  `/usr/lib64/security`; SELinux subpackage. Update path: `dnf upgrade` / Copr,
  driven by `irlume update`.
- **Arch** — `arch/PKGBUILD` for the AUR: builds from the release tag; depends on
  `onnxruntime`, `tpm2-tss`, `pam`; PAM to `/usr/lib/security`. Updates are the
  AUR helper's job; `irlume update` only checks + prints the command (never
  fights pacman).
- **Debian/Ubuntu** — `debian/` via nfpm or dpkg-buildpackage: **bundles
  onnxruntime** (the archive ships 1.22; irlume needs ≥1.24) or depends on a
  companion `-ort` package; ships the AppArmor profile; PAM to the multiarch
  dir. Update path: signed apt repo or a `.deb` from GitHub Releases via
  `irlume update`.

## onnxruntime ≥ 1.24 (the api-24 pin)

- Fedora: `onnxruntime` from the author's Copr (matches the pin).
- Arch: system `onnxruntime` is current (≥1.24) — plain dependency.
- Debian/Ubuntu: NOT in the archive at ≥1.24 → bundle under
  `/opt/irlume/onnxruntime` and point `ORT_DYLIB_PATH` via a unit override.

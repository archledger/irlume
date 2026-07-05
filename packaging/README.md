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
| LSM policy | Fedora SELinux module · Debian `apparmor/usr.bin.irlumed` (path-adjusted) · Arch none |

Models are bundled (Git LFS) — no fetch step. Packages that build from a git
checkout must `git lfs pull` first so the real weights (not pointers) are staged.

## Per-family

- **Fedora** — `fedora/irlume.spec` + `../.packit.yaml`: Packit builds in Copr
  from signed GitHub tags. Bundles onnxruntime 1.24.4 (Source1 →
  `/usr/share/irlume/onnxruntime` + `ORT_DYLIB_PATH` drop-in); PAM to
  `/usr/lib64/security`; SELinux subpackage. Update path: `dnf upgrade` / Copr,
  driven by `irlume update`.
- **Arch** — primary channel is a **prebuilt `.pkg.tar.zst` on GitHub Releases**
  (`arch/build-pkg.sh` produces it from the local build), installed with
  `sudo pacman -U`. AUR account registration is disabled upstream at the moment,
  so `arch/PKGBUILD` (builds from the release tag) is kept for source builds and
  will become the update path once AUR sign-ups reopen. Depends on `onnxruntime`
  (system pkg is current), `tpm2-tss`, `pam`; PAM to `/usr/lib/security`.
- **Ubuntu** — [`ppa:archledger/irlume`](https://launchpad.net/~archledger/+archive/ubuntu/irlume):
  source package built on Launchpad from a self-contained orig tarball
  (`ppa/debian/` + `scripts/build-ppa-source.sh` — vendored crates, bundled
  onnxruntime, real model weights; LP builders have no network). Update path:
  plain `apt upgrade`.
- **Debian** (and Ubuntu series the PPA doesn't cover) — `debian/` via nfpm or
  dpkg-buildpackage: **bundles onnxruntime** (the archive ships 1.22; irlume
  needs ≥1.24); ships the AppArmor profile; PAM to the multiarch dir. Update
  path: a `.deb` from GitHub Releases via `irlume update`.

## onnxruntime ≥ 1.24 (the api-24 pin)

- Fedora: bundled in the RPM (Source1 tarball → `/usr/share/irlume/onnxruntime`,
  `ORT_DYLIB_PATH` unit drop-in).
- Arch: system `onnxruntime` is current (≥1.24) — plain dependency.
- Debian/Ubuntu: NOT in the archive at ≥1.24 → bundle under
  `/opt/irlume/onnxruntime` and point `ORT_DYLIB_PATH` via a unit override.

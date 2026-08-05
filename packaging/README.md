# Packaging irlume

Family-aware packaging (see `../docs/cross-distro/family-vs-capability.md`): the
concerns that differ here (PAM module directory, onnxruntime dependency, LSM
policy, package format) are genuine distro conventions, so each family gets its
own recipe. Everything the daemon does at *runtime* stays capability-detected.

## Shared install layout (FHS, all families)

| Artifact | Path |
|---|---|
| `irlumed`, `irlume` | `/usr/bin/` |
| `pam_irlume.so` | Fedora `/usr/lib64/security/` · Debian `/usr/lib/x86_64-linux-gnu/security/` · Arch `/usr/lib/security/` |
| models (LFS, bundled) | `/usr/share/irlume/models/*.onnx` |
| systemd units | `/usr/lib/systemd/system/irlumed.service` + `irlume-reconcile.path`/`.service` (self-heal watcher; all families incl. PPA enable the `.path`) |
| LSM policy | Fedora SELinux module · Debian `apparmor/usr.bin.irlumed` (path-adjusted) · Arch none |

Models are hosted as release assets (the `models-v1` release), not Git LFS; each
lane fetches and sha256-verifies them at build time (`scripts/fetch-models.sh`,
or the Source URLs in the spec / PKGBUILD / flake). An installed package bundles
the weights, so a running system needs no download.

## Per-family

- **Fedora** (`fedora/irlume.spec` + `../.packit.yaml`): Packit builds in Copr
  from signed GitHub tags. Bundles onnxruntime 1.24.4 (Source1 →
  `/usr/share/irlume/onnxruntime` + `ORT_DYLIB_PATH` drop-in); PAM to
  `/usr/lib64/security`; SELinux subpackage. Update path: `dnf upgrade` / Copr,
  driven by `irlume update`.
- **Arch**: primary channel is the **AUR**
  ([aur.archlinux.org/packages/irlume](https://aur.archlinux.org/packages/irlume),
  builds the signed release tag); `arch/PKGBUILD` here is its source of truth
  and also serves local source builds (`makepkg -si`). Depends on `onnxruntime`
  (system pkg is current), `tpm2-tss`, `pam`; PAM to `/usr/lib/security`.
  Update path: `yay -Syu` / `paru -Syu`, driven by `irlume update`.
- **Ubuntu** ([`ppa:archledger/irlume`](https://launchpad.net/~archledger/+archive/ubuntu/irlume)):
  source package built on Launchpad from a self-contained orig tarball
  (`ppa/debian/` + `scripts/build-ppa-source.sh`: vendored crates, bundled
  onnxruntime, real model weights; LP builders have no network). Update path:
  plain `apt upgrade`. **The lane ends at "binary published", not at "upload
  accepted"**: `dput` reports only that Launchpad took the upload, and the
  build and binary publication after it are both silent. Finish with
  `python3 scripts/verify-ppa-publish.py`, which polls Launchpad and exits
  non-zero unless a binary is actually installable. 0.6.1 was accepted, failed
  to build, and left Ubuntu users on 0.6.0 for four days unnoticed; this is the
  only lane where a green upload and a broken package look the same from the
  maintainer's side.
- **Debian** (and Ubuntu series the PPA doesn't cover), `debian/` via nfpm or
  dpkg-buildpackage: **bundles onnxruntime** (the archive ships 1.22; irlume
  needs ≥1.24); ships the AppArmor profile; PAM to the multiarch dir. The
  universal `.deb` is built on debian:12 (`debian/build-deb-container.sh`) and
  declares `libc6 (>= 2.35)`, the measured floor of its binaries, so it covers
  Debian 12+ and Ubuntu 22.04+ and refuses cleanly on anything older. Update
  path: a `.deb` from GitHub Releases via `irlume update`.

## TFLite C runtime (native .tflite models, #295)

Google publishes no prebuilt Linux x86_64 C-API artifact at stable URLs, so
irlume builds `libtensorflowlite_c.so` from a pinned tensorflow tag
(`scripts/build-tflite-runtime.sh`, currently v2.19.0) and publishes the
tarball with signed checksums on the `tflite-runtime-<tag>` GitHub release.
The four FHS lanes (Fedora, Arch, Debian/nfpm, PPA) bundle it at
`/usr/share/irlume/tflite/`, the first path the daemon's resolver probes, so
unlike onnxruntime no environment drop-in is needed; a missing library is a
recoverable "runtime not installed" answer, never a startup failure. Nix is
the exception and is not yet wired: a flake user sets IRLUME_TFLITE_LIB.
Fedora: Source6 in the spec. Arch: an extra pinned source in the PKGBUILD
(no usable system package exists). Debian/nfpm and the PPA orig tarball:
fetched + sha256-checked by their build scripts, floors asserted against
the declared libc6/libstdc++ baseline. The artifact is BUILT on that floor
(scripts/build-tflite-runtime-container.sh, ubuntu:22.04) and the build
script refuses output whose symbol versions exceed it.

## onnxruntime ≥ 1.24 (the api-24 pin)

- Fedora: bundled in the RPM (Source1 tarball → `/usr/share/irlume/onnxruntime`,
  `ORT_DYLIB_PATH` unit drop-in).
- Arch: system `onnxruntime` is current (≥1.24), a plain dependency.
- Debian/Ubuntu: NOT in the archive at ≥1.24 → bundle under
  `/opt/irlume/onnxruntime` and point `ORT_DYLIB_PATH` via a unit override.

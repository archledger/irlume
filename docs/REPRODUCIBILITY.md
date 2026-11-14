# Build reproducibility

irlume's shipped binaries are not certified bit-for-bit reproducible: no
independent rebuild of a released `.deb`, RPM or PPA binary has been compared
against the published digests. What the project does maintain, and checks in
CI, is that the inputs of every lane the repository controls are pinned and
digest-verified (crates, model weights, bundled runtimes, container base
images), that cargo builds refuse to drift from the committed lockfile, and
that one artifact class, the PPA orig tarball, is packed deterministically.
The distribution lanes build with toolchains this repository does not pin;
the table below states that per lane. This page says exactly what that means
and what a third party can compare, and its scope is the decision of
[ADR-0040](adr/0040-reproducibility-scope.md).

To reproduce irlume's *behavior claims* (anti-spoof numbers, encryption at
rest), see [`VERIFY.md`](VERIFY.md). The release process that publishes the
digests below is [`RELEASING.md`](RELEASING.md).

## Pinned inputs

| Input | Pinned by |
|---|---|
| Rust crates | committed `Cargo.lock`; forks by `rev` in `Cargo.toml` |
| Rust compiler | 1.88.0, the MSRV (the lanes that build with it directly: the CI check job, `nix develop`, the universal `.deb` container; the nix package build uses the toolchain of the pinned nixpkgs/rust-overlay revisions) |
| Nix package set | `flake.lock` (nixpkgs, rust-overlay, flake-utils) |
| Model weights | per-file sha256, `models-v1` release assets |
| ONNX Runtime | 1.28.1 tarball sha256 (`scripts/fetch-ort.sh`) |
| TensorFlow Lite runtime | v2.19.0 asset sha256 (`build-ppa-source.sh`) |
| Container base images | digest-pinned `ubuntu:26.04`, `debian:12` (the PPA container route still installs its `cargo`/`rustc` from the Ubuntu archive at build time, which a digest does not pin) |

The model digests are recorded in `scripts/fetch-models.sh`,
`models/SHA256SUMS` and `nix/package.nix`, and the two bundled runtimes'
digests in the packaging scripts that fetch them (the Fedora spec repeats
both).

Every lane the repository builds itself pins cargo 1.88.0: `nix develop`
takes it from rust-overlay, which `flake.lock` pins; the CI `check` job
installs it with the `dtolnay/rust-toolchain` action pinned by commit SHA;
the universal `.deb` container installs it with rustup. The PPA, Fedora and
Arch lanes build with their distribution's toolchains, which this repository
does not pin: the PPA container route installs `cargo`/`rustc` from the
Ubuntu archive at build time (a mutable source a base-image digest does
not cover), and the Fedora and Arch toolchains come from their
distributions. Cargo builds run `--locked` or `--frozen`,
so they refuse to drift from the committed `Cargo.lock`, and cargo verifies
each fetched registry crate against the checksums recorded there.

The ONNX Runtime version and sha256 are written in several places (the PPA
and `.deb` scripts, the Fedora spec, the Nix files); CI's packaging parity
step (`scripts/check-packaging-parity.sh`) fails if any copy drifts. The
`.deb` lane also pins `nfpm` by version and verifies it against goreleaser's
published checksums before it packs anything.

## The PPA orig tarball is packed deterministically

`scripts/build-ppa-source.sh` packs the orig tarball with a fixed timestamp,
fixed ownership, sorted names and an undated gzip stream, so one upstream
version always yields the same orig tarball (Launchpad keeps a single orig
per version and rejects a second upload whose checksum differs). The
timestamp comes from the release tag's commit date:

```sh
SDE="${SOURCE_DATE_EPOCH:-$(git -C "$REPO" log -1 --format=%ct "v${VERSION}" 2>/dev/null || echo 1600000000)}"
tar --exclude="irlume-$VERSION/target" \
    --sort=name --mtime="@${SDE}" --owner=0 --group=0 --numeric-owner \
    --pax-option='exthdr.name=%d/PaxHeaders/%f,delete=atime,delete=ctime' \
    -cf - "irlume-$VERSION" | gzip -n > "irlume_${VERSION}.orig.tar.gz"
```

The nightly PPA lane (`scripts/ppa-nightly.py`) passes the same kind of value
(the built commit's commit date) as `SOURCE_DATE_EPOCH`, so nightly origs are
deterministic the same way.

What this gives you: re-running the same route from the same tag produces a
byte-identical orig tarball when the staged tree's file modes match. The
recipe fixes timestamps, ownership and order but not permission bits:
`fetch-models.sh` writes the weights with the writing umask's bits,
`rsync -a` preserves them and tar records them, so a umask difference
between runs changes the tarball. What it does not: the container route
(`packaging/ppa/build-ppa-container.sh`) and a native Ubuntu run do not
produce identical bytes (gzip and `cargo vendor` differ between
environments), so each release uploads from one route only.

## Nix builds

`nix build .#default` builds irlume in a sandbox with no network and no view
of host state (with Nix's default sandboxing enabled): every build input,
from the
nixpkgs revision through the pinned toolchain to the vendored crates
(`Cargo.lock` via `importCargoLock`, with
recorded hashes for the fork crates) and the model weights,
enters the sandbox as a fixed, content-addressed store path. Host impurities
such as the checkout location or locally installed libraries cannot reach the
build. The package build takes its toolchain from the pinned nixpkgs and
rust-overlay revisions; only `nix develop` additionally selects 1.88.0.
ONNX Runtime is deliberately NOT a build input of the default package
(`nix/package.nix` loads it at runtime, and the flake ships it as the
separate `onnxruntime-bin` output): a full rebuild-and-run comparison
builds `.#onnxruntime-bin` beside `.#default`, and the runtime's own
sha256 pin is what the table above records.

To compare two machines: run `nix build .#default --no-link --print-out-paths`
on the same commit in both. The printed store path is derived from the
derivation inputs, so equal paths mean the inputs matched. For the byte
comparison, hash the built output (`nix hash path <store-path>`) on each
machine and compare those digests.

## What is not claimed

- No published bit-for-bit rebuild comparison exists for any shipped
  artifact. Nothing on this page has been verified against the release
  `SHA256SUMS` by an independent rebuild.
- A plain cargo build does not prove byte-identical binaries across
  machines: the linker, the build-id and paths the compiler embeds can
  differ with the build environment. The pinned toolchain and lockfile are
  an input guarantee, not an output guarantee.
- PPA binaries are built by Launchpad on Ubuntu infrastructure; the Fedora
  and Arch lanes build with distribution toolchains this repo does not pin.
  Those binaries are authenticated by signature and digest, not by rebuild.
- The C++ System Settings module (`kcm/`, CMake) has no reproducibility
  mechanism documented here.

## Attempting a rebuild

1. **Release packages.** Download the release assets, `SHA256SUMS` and its
   detached `SHA256SUMS.asc`, then run
   `python3 scripts/verify-release-assets.py <asset-dir>` (it needs
   GnuPG, `dpkg-deb`, `tar` with zstd support, the separate `zstd`
   executable for the Arch assets, and `rpm` when an RPM
   asset is present) to check the signature and coverage. Check out the
   release tag you are comparing first: the next step builds the source
   tree that is currently checked out, so running it on another
   revision compares against a different artifact. Rebuild the
   universal `.deb` with
   `packaging/debian/build-deb-container.sh` (digest-pinned `debian:12`,
   rustup 1.88.0; the host needs podman or Docker, rootless is fine)
   and compare its sha256 against the release's `SHA256SUMS`
   line. A mismatch is a data point, not proof of tampering: this lane is
   not certified byte-reproducible, so report it rather than conclude from
   it.
2. **PPA orig tarball.** Build from a clean disposable checkout of tag
   `vX.Y.Z` (a fresh `git clone --depth 1 --branch vX.Y.Z`, or
   `git worktree add` on the tag): `build-ppa-source.sh` stages the
   working tree with `rsync -a`, which does not honor `.gitignore`, so
   ignored local files (downloaded weights, enrollment templates left by
   a test run) would be bundled into the orig. The container route does
   this by design already: it git-archives the tag to a clean tree. From
   that checkout, run `scripts/build-ppa-source.sh` (needs `rsync`,
   `cargo`, `dpkg-buildpackage` and `curl`). It writes
   `~/ppa-build/irlume_X.Y.Z.orig.tar.gz` and deletes and recreates that
   path on every run, so before rerunning, either copy the first tarball
   aside or record its `sha256sum`. Run the script again and compare the
   fresh tarball's digest against the recorded one; equal digests are the
   deterministic-packing check, subject to the permission-bits caveat
   above. Comparing the container route works the same way; compare like
   with like, since the two routes are not byte-identical to each other.
3. **Nix.** `nix build .#default --no-link --print-out-paths` and
   `nix hash path <store-path>`, as above, on two machines.
4. **Weights and runtime.** `bash scripts/fetch-models.sh` and
   `bash scripts/fetch-ort.sh 1.28.1` each verify their sha256 pins and
   refuse to proceed on a mismatch. This checks the inputs, not any binary.

## Where digests are published

- Every release carries `SHA256SUMS` and a detached `SHA256SUMS.asc`
  signature; the release key's fingerprint is
  `F35053398E3C80FE20891B82C10B8492BD7F30C6`, its public key
  `.github/release-signing-key.asc`. `scripts/verify-release-assets.py`
  checks the manifest's coverage and structure.
- The model weights' digests are in `models/SHA256SUMS` and match the
  `models-v1` release assets.
- Each crate SBOM and the release VEX document are themselves `SHA256SUMS`
  entries; see [`SBOM-INTEGRITY.md`](SBOM-INTEGRITY.md) and
  [`RELEASING.md`](RELEASING.md).

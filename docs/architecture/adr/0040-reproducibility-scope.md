# ADR-0040: Reproducibility scope

## Status

Accepted 2026-11-14. Ships with the guide it scopes
([REPRODUCIBILITY.md](../../security/REPRODUCIBILITY.md)). It records what the release
lanes already do; it amends and supersedes nothing.

## Context

Releases ship through several lanes (the universal `.deb` container, the
PPA source route, Fedora RPM, Arch and Nix), and each lane controls a
different set of its inputs. Shipped binaries are authenticated by
signature and digest, but no independent rebuild of a released binary has
been compared against the published digests, so a bit-for-bit claim would
be untested. At the same time, the inputs the repository does control are
pinned and verified, and one artifact class, the PPA orig tarball, is
packed deterministically. A claim worded as "every build starts from
pinned inputs" would still be false: the PPA, Fedora and Arch lanes build
with toolchains from their distributions, which this repository does not
pin. The scope of the claim therefore needs a decision, so the guide and
the badge texts state one thing, not two.

## Decision

### 1. What irlume claims

1. Every input of a lane the repository controls is pinned and
   digest-verified where CI can check it: crates by the committed
   `Cargo.lock`, model weights and the bundled ONNX Runtime and
   TensorFlow Lite runtimes by sha256, container base images by digest.
   Cargo builds run `--locked` or `--frozen` and refuse to drift from
   the lockfile.
2. The PPA orig tarball is packed deterministically from the release
   tag's commit date, so the same tag yields the same tarball on the
   same route when the staged tree's file modes match: the recipe fixes
   timestamps, ownership and order, not permission bits.
3. No lane is certified bit-for-bit reproducible and none is claimed to
   be. A mismatch on an independent rebuild is a data point to report,
   not evidence of tampering and not a release blocker.

### 2. What stays unpinned

The distribution lanes keep their distribution toolchains: the PPA
container route installs `cargo` and `rustc` from the Ubuntu archive
beyond its digest-pinned base image, and the Fedora and Arch lanes use
their distributions' toolchains. Pinning those, and publishing a
bit-for-bit rebuild comparison, are the follow-ups tracked in
[#1366](https://github.com/archledger/irlume/issues/1366), not promises
this decision makes.

## Consequences

- `docs/REPRODUCIBILITY.md` is the single place that states the scope
  per lane and how a third party compares each channel.
- Strengthening a lane to fully pinned inputs, or publishing a
  bit-for-bit comparison, extends the guide and cites this ADR; the
  scope above stays true, so it needs no amendment here.
- Weakening a pin, an unpinned fetch in a lane or a lockfile bypass, is
  a change to this decision and amends this ADR.

## Acceptance tests

- The packaging parity check (`scripts/check-packaging-parity.sh`)
  fails when a recorded digest copy drifts.
- Every cargo build or test invocation the repository's own lanes run
  uses `--locked` or `--frozen`.
- The nightly PPA lane packs its orig with a fixed `SOURCE_DATE_EPOCH`
  taken from the built commit's date, the same recipe as a release.

## Amendment 2026-11-14: the PPA container build is toolchain-pinned, and the orig comparison is published

Section 2's first example no longer applies: the PPA container route no
longer builds with the Ubuntu archive's Rust toolchain. It installs
rustup-pinned `RUST_VER` (1.88.0, the same pin as the universal `.deb`
lane) inside the digest-pinned base image; the archive's `cargo`/`rustc`
packages remain installed only because the source package's
Build-Depends names them, which Launchpad's own builders re-check on
their side. The Fedora and Arch lanes keep their distribution
toolchains, and PPA binaries are still built by Launchpad, as section 2
records.

Section 1.2's claim now has published evidence: for tag v0.16.0, two
runs of the container route on two different machines (podman 6.2.0
rootless and Docker 29.9.1 rootful, same image digest, same pinned
toolchain, same `SOURCE_DATE_EPOCH`) produced a byte-identical orig
tarball, sha256 `694fdb072fc6aaadcfebd27ce7b8e10b82c681d4eb854c78b9a86f600cb3199d`.
The guide carries the comparison table; released binaries remain outside
it (#1366).

## Amendment 2026-11-14: the installer is pinned, and the orig is clean

The earlier amendment today left two gaps a review of the change found. The
rustup installer was fetched from the unpinned `sh.rustup.rs` pipe, so
one lane input was not digest-verified as section 1.1 claims; both
container lanes now pin `rustup-init` by version
(`RUSTUP_VER=1.29.3`) and verify its published sha256 before it runs.
And without `--no-modify-path`, rustup wrote a `.profile` sourcing the
toolchain into `HOME` (=/work in the PPA container), which the staging
rsync shipped inside the orig tarball: the first published comparison
digest included that stray file. The comparison was re-run on both hosts
with the fixed lane; the table above carries the corrected digest.
`RUST_VER` is also passed through by both callers now, so the pin is
overridable as documented instead of only by editing the script.

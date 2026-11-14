# ADR-0040: Reproducibility scope

## Status

Accepted 2026-11-14. Ships with the guide it scopes
([REPRODUCIBILITY.md](../REPRODUCIBILITY.md)). It records what the release
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
   same route.
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

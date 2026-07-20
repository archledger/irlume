# Governance

irlume is a single-maintainer project. This page documents how it is run so
nobody has to guess.

## Decision making

The maintainer (archledger) decides what merges and what ships. Proposals,
bug reports, and design discussion happen in public on
[issues](https://github.com/archledger/irlume/issues) and
[discussions](https://github.com/archledger/irlume/discussions); anyone can
argue for a change there, and the maintainer reads them. There is no voting
body. If the project grows more maintainers, this file changes first.

## Roles

**Maintainer** (currently: archledger)
- reviews and merges pull requests
- cuts releases: signs the release tag and the checksum file (signing key
  fingerprint `F350 5339 8E3C 80FE 2089 1B82 C10B 8492 BD7F 30C6`, published
  in `scripts/install.sh`), and publishes the Copr, PPA, AUR, and GitHub
  release lanes
- handles security reports under the process and response times in
  [SECURITY.md](SECURITY.md)
- enforces the [code of conduct](CODE_OF_CONDUCT.md)

**Contributors**
- anyone; send pull requests under the requirements in
  [CONTRIBUTING.md](CONTRIBUTING.md) (DCO sign-off, tests, green CI)

**Security reporters**
- use the private channels in [SECURITY.md](SECURITY.md), not the public
  tracker

## Continuity

Everything needed to continue the project is public: the source, the model
weights (Git LFS in this repository), the packaging for every distribution
lane (`packaging/`), the release process (`scripts/`), and the documentation.
The license (GPL-3.0-or-later) permits anyone to fork and carry on. The only
things a successor cannot inherit are the maintainer's accounts and signing
key; a fork would publish its own key and channels, and the pinned-fingerprint
verification in the install script makes that change visible to users rather
than silent.

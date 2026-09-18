# Support Policy

irlume is pre-1.0, solo-maintained software. This page states plainly what
support a release receives; the security-reporting side lives in
[SECURITY.md](SECURITY.md) and the trust boundaries in
[docs/THREAT_MODEL.md](docs/THREAT_MODEL.md).

## Supported versions

| Version | Support |
|---|---|
| latest release | ✅ bug fixes and security fixes |
| `main` between releases | fixes land here first |
| any older pre-1.0 tag | ❌ no fixes; upgrade to the latest release |

There is no long-term-support branch: security fixes land on `main` and ship
in the next release. When a new version is published, the previous version
stops receiving security updates at that moment, and the release notes plus
[CHANGELOG.md](CHANGELOG.md) state what changed and how to upgrade.

## Kinds of support

- **Security fixes**: highest priority; see [SECURITY.md](SECURITY.md) for
  reporting. Fixed releases are cut from a clean advisory gate
  (`cargo-deny`), and known not-exploitable advisories are published in the
  release VEX document.
- **Bug fixes**: reported through the
  [issue tracker](https://github.com/archledger/irlume/issues); every
  confirmed defect fix carries a regression test before it merges.
- **Upgrade path**: packages upgrade in place (enrollment, keyring and
  recovery state are retained across upgrades; `irlume uninstall --keep-data`
  removes the software without the data). Rollback packages for one version
  are documented in each release's evidence.

## No professional support

There is no SLA, no dedicated support channel and no paid tier. If irlume
breaks your login, the password fallback always works - that is a design
invariant, not a best effort.

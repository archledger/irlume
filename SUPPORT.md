# Support Policy

irlume is pre-1.0, solo-maintained software. This page states plainly what
support a release receives; the security-reporting side lives in
[SECURITY.md](SECURITY.md) and the trust boundaries in
[docs/THREAT_MODEL.md](docs/THREAT_MODEL.md).

## Where to report a problem

```text
Security problem (a photo, video, mask or another person got in,
face sign-in worked without your face, or face data was exposed),
or not sure? Never post it publicly. Report it privately:
https://github.com/archledger/irlume/security/advisories/new
or the e-mail address in SECURITY.md.
Anything else: https://github.com/archledger/irlume/issues/new/choose
```

As links: [report privately][private] or [open an issue][issues].

[private]: https://github.com/archledger/irlume/security/advisories/new
[issues]: https://github.com/archledger/irlume/issues/new/choose

The maintainer never asks for:

- your password
- your recovery passphrase
- your keyring token
- template files
- photos of you

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

There is no SLA, no dedicated support channel and no paid tier.

On a supported PAM stack, when irlume declines face sign-in, it returns
control to the password provider. The
[login frontend](docs/DESKTOP-AUTH.md#frontend-boundary) controls when you can
enter a password, and the operating system's account policy still applies.
For example, `pam_faillock` can reject even a correct password while the
account is locked after repeated failed attempts.

# ADR-0037: A nightly channel built from main

## Status

Proposed 2026-10-17. Adds a release channel; changes no existing channel. The
maintainer chose the name "nightly" and, for the Ubuntu lane, nightly uploads
from minihost signed with the key Launchpad already has (2026-10-17). Depends
on [docs/RELEASING.md](../RELEASING.md), which keeps governing releases.

## Context

Every install lane today moves only with a signed release tag, after the
candidate checks in RELEASING.md:

| Lane | Built from |
|---|---|
| Copr `archledger/irlume` | Packit, `trigger: release` (`.packit.yaml`) |
| AUR `irlume` | `packaging/arch/PKGBUILD`, the signed tag (`#tag=v${pkgver}?signed`) |
| PPA `ppa:archledger/irlume` | `scripts/build-ppa-source.sh` on the tag tree |
| `.deb` and Arch package | GitHub release assets |
| Nix | the flake, which already follows `main` when unpinned |

The maintainer wants a channel that follows the latest commit on `main`, so
that a fix can be tried before the next release. `main` moves only through
squash-merged pull requests whose required checks passed, and SECURITY.md
already lists `main` as supported. What `main` does not have is the release work: the
install matrix, the upgrade and rollback transactions, hardware
qualification, SBOM, VEX and SLSA provenance.

The first name proposed, "edge", returns Microsoft Edge in searches, so the
maintainer chose "nightly".

### What irlume's tools assume today

The CLI knows one channel per distribution family, and a second one would be
misread (`crates/irlume-cli/src/commands.rs`, `uninstall.rs`,
`support_report.rs`):

- `is_copr_repo` accepts only `copr:...:archledger:irlume`, so a package from
  `archledger/irlume-nightly` reads as a local RPM, and `irlume update` then
  tells the user to enable the release Copr.
- The PPA test is a substring match on `ppa.launchpadcontent.net/archledger/
  irlume`, which `.../archledger/irlume-nightly` also matches: the nightly
  PPA reads as the release PPA, and uninstall removes the release PPA.
- `pacman -Qq irlume` succeeds for a package that provides `irlume` (pacman's
  `-Q` falls back to `alpm_find_satisfier` when no installed package has the
  name, `src/pacman/query.c`; on minihost's pacman 7.1.0 `pacman -Qq sh`
  prints `bash`), but its output, the actual package name, is discarded;
  uninstall's `pacman -Rns irlume` then fails, since `-R` does not resolve
  provides.
- `version_gt` keeps the leading all-digit fields of each dot-separated part,
  so `0.15.0^...` and `0.15.0+git...` parse as `0.15`, and `version_base`
  keeps a caret version whole.
- `irlume update` gates on the latest GitHub release, which a nightly build is
  always at or past, so it would never update a nightly install.

### What Launchpad allows

The release PPA's 0.15.0 upload is a 649 MB orig tarball (vendored crates,
ONNX Runtime, the models; Launchpad builders have no network) and builds a
582 MB package, about 1.23 GB per upload. A PPA has 8 GiB by default.
Launchpad removes a file once every publication that references it is
scheduled for deletion, and its cleanup runs every six hours (Launchpad
manual, "Delete packages from PPAs"). On the release PPA, each superseded
upload from 0.11.1 to 0.14.0 was removed from disk 1 to 1.5 days after the
next one was published (`getPublishedSources`, `date_superseded` and
`date_removed`). Launchpad also refuses an upload whose version is not higher
than the published one.

## Decision

### 1. One channel, named nightly, on three lanes

| Lane | Channel | Built | Version |
|---|---|---|---|
| Fedora | Copr `archledger/irlume-nightly` | by Packit on every push to `main` | the spec's `Version`, Packit's default Release suffix |
| Arch | AUR `irlume-git` and `irlume-kcm-git` | by the user's AUR helper from `main` at install time | `<tag>.r<commits>.g<hash>` |
| Ubuntu | PPA `ppa:archledger/irlume-nightly` | on minihost, at most once a day, when `main` moved | `<tag>+git<commits>.g<hash>-0ppa1~<series>1` |

The `.deb` and Arch packages on GitHub stay release-only, and Nix needs
nothing new. The AUR names follow the AUR's own rule for packages built from
a version control repository (the `-git` suffix), not the channel name.

### 2. Versions sort after the release they follow

Each nightly version sorts above the release of the same version and below
the next one, so with both lanes enabled the package manager installs the
newer build. Right after a release that can be the release itself, for up to
a day on the PPA, until the nightly built from its tag (the same code)
publishes and moves past it; then the machine is on the nightly lane again.
The channel's documentation therefore tells nightly users to enable the
nightly lane alone, which carries a build at least as new as the latest
release within a day of it when the nightly of the release's tag builds;
while that build fails, the nightly lane stays on the snapshot before the
release until a retry or the next commit on `main` succeeds, which the
uploader logs and the PPA page shows:

- **Copr.** Packit's commit builds keep the spec's `Version` and append its
  default suffix to the Release, `{original_release_number}.{current_time}.
  {sanitized_current_branch}{git_desc_suffix}` (Packit, "release_suffix"):
  `0.15.0-1.<time>.main.<n>.g<hash>` sorts above `0.15.0-1`, and the time
  keeps successive builds increasing. From the release-preparation commit,
  which bumps `Version` before the tag (RELEASING.md step 1), a nightly
  carries the next release's `Version` and sorts above that release too; it
  is the same code, so a nightly user simply stays on nightly.
- **AUR.** `pkgver()` is `git describe --long --tags --match 'v[0-9]*'`
  reformatted, as the Packit config matches release tags: `0.15.0.r139.
  g3c162b83`. `vercmp` puts it above `0.15.0-1` and below `0.15.1-1`, and the
  commit count keeps it increasing.
- **PPA.** The same `describe` gives `0.15.0+git139.g3c162b83-0ppa1~resolute1`:
  `+git` sorts above the release's `0.15.0-0ppa1~resolute1`, and the commit
  count keeps each upload higher than the last, which Launchpad requires.
  The `+git` form also names a nightly package on a machine whose installed
  version the PPA has since removed (section 4).

The AUR and PPA versions start from the last tag, not from `Cargo.toml`, so
the release-preparation bump does not move a nightly above the release it
precedes. `irlume version` keeps printing the crate version; the channel and
the package version are reported by `irlume doctor` (section 4). Between the
release-preparation bump and its tag, the crate version is ahead of the AUR
and PPA package versions by design, so the "the running binary is not the
packaged one" note `irlume update` prints for an overlaid build compares
nothing on a nightly lane.

### 3. Each lane's build

- **Copr.** `.packit.yaml` gains a `copr_build` job with `trigger: commit`,
  `branch: main`, `owner: archledger`, `project: irlume-nightly`,
  `identifier: nightly`, `enable_net: true` and the release job's targets.
  The spec is unchanged: Packit builds the SRPM from the checked-out commit,
  as the pull request job already does, and the other sources are pinned by
  SHA-256 as for a release.
- **AUR.** `packaging/arch-git/PKGBUILD` keeps `packaging/arch/PKGBUILD`'s
  dependencies, sources, checksums and package functions, with `pkgbase=
  irlume-git`, `pkgname=(irlume-git irlume-kcm-git)`, `provides` and
  `conflicts` for `irlume` and `irlume-kcm`, `git` in `makedepends`, and
  `git+https://github.com/archledger/irlume.git#branch=main` as its source.
  It does not add `?signed`: commits on `main` are GitHub's squash merges,
  signed by GitHub's web-flow key rather than the release key in
  `validpgpkeys`, so the source is fetched over HTTPS without a signature
  check. `scripts/arch-git-pkgbuild.py` generates it from the release
  recipe, and CI fails when the committed copy is stale.
  The generator also writes the recipe's `.SRCINFO`, the metadata AUR
  helpers and the AUR's RPC read for the split packages, dependencies,
  `provides` and `conflicts`, with `makepkg --printsrcinfo` in a pinned Arch
  container, and CI checks it too.
  An AUR helper builds from the AUR's own copy of the recipe, which only the
  maintainer's AUR key can update, so a change to `packaging/arch-git/`
  reaches users once the maintainer pushes it, as each release's AUR update
  does today. A scheduled workflow compares the AUR's `PKGBUILD`,
  `.SRCINFO` and `irlume.install` with `main`'s and fails when one differs, which `ci-alert.yml` turns into a
  `ci-alert` issue as for any failing scheduled workflow, so a recipe change
  on `main` is not left unpublished unseen.
- **PPA.** `scripts/ppa-nightly.py` runs from a user timer on minihost, which
  already runs user timers with lingering enabled. It updates a dedicated
  clone and derives the nightly version from `main` (section 2), so a release
  tag on an already uploaded commit is a new input too. It builds the source
  package from a `git archive` of that commit with the script and
  digest-pinned Ubuntu image a release uses (`packaging/ppa/container-build.sh`,
  which `packaging/ppa/build-ppa-container.sh` runs too), given the version,
  signs it with the key Launchpad has (fingerprint F350 5339 8E3C 80FE 2089
  1B82 C10B 8492 BD7F 30C6) through gpg-agent, uploads it with dput, and then
  waits for `scripts/verify-ppa-publish.py` (with `PPA_NAME=irlume-nightly`)
  to see the binary published. dput's success means only that the files
  reached Launchpad, which accepts or rejects the upload afterwards
  (Launchpad manual, "Package upload errors"), and Launchpad never accepts a
  version twice in a PPA, also after a deletion. So the script records each
  step's state, read from Launchpad's API:
  - the derived version it last saw published, kept apart from the PPA
    revision it was published under: when today's derived version equals
    it, there is nothing to do, also after a retry published it as
    `-0ppa2`;
  - a version it uploaded: accepted once its source publication appears in
    the PPA (pending or published), and from then on only verified again,
    never uploaded again; an upload whose source publication has not
    appeared a day later was rejected;
  - a version whose build failed, or whose upload was rejected: while the
    derived version is unchanged, the next run uploads the same commit with
    the next PPA revision (`-0ppa2`, then `-0ppa3`), as a release's failed
    build does (`verify-ppa-publish.py`'s own advice);
  - a new derived version (`main` moved, or a release tag landed): the
    older version's record is dropped, whether it was pending, accepted and
    still building, or failed, and the new version is uploaded at `-0ppa1`,
    so a build Launchpad keeps pending never holds the channel on an old
    commit, and a fix on `main` is never held up by retries of the commit it
    fixed.
  A failure before the upload (the build, the signature) records nothing,
  so the next night starts over. Once dput has run, its version is recorded
  as uploaded whether dput succeeded or not, since a connection lost after
  the last byte leaves dput failing while Launchpad accepts the upload; the
  source publication then decides, as for any upload. Every failure is
  logged to the user journal. At most one upload a day keeps two or three uploads, 2.5 to
  3.7 GB, on disk at once, inside the 8 GiB quota (Context).
  The key is stored on minihost without a passphrase (gpg-agent's `keyinfo`
  reports it unprotected), as it already signs that host's commits
  unattended, so the timer needs no cached passphrase; if the key gains one,
  signing fails and the night's upload is skipped and logged.
  The script holds the key's use, so it does not run code it fetched: it is
  installed from a reviewed checkout, not run from the clone it updates, and
  code from `main` (the build scripts, `cargo vendor`, the model fetch) runs
  only inside the build container, which is not given the key. Signing and
  the upload run in containers of their own with fixed commands on the
  built files, the signing one reaching the key only through gpg-agent's
  extra socket, made for "signing data on a remote machine without exposing
  the private keys" (GnuPG manual, `--extra-socket`).

### 4. irlume's tools know the channel

- `install-origin` (doctor, the TUI, support reports) names the nightly lanes
  apart from the release lanes: "Fedora Copr nightly (archledger/
  irlume-nightly)", "Launchpad PPA nightly (ppa:archledger/irlume-nightly)",
  "AUR irlume-git (nightly)", with the installed package version. The Copr
  lane is told by the package's `from_repo`; the PPA lane by the origin
  `apt-cache policy` lists for the installed version, matched as a whole path
  segment, so neither PPA is mistaken for the other, and, when the PPA has
  since removed that version (a machine that missed several nightlies sees
  it only at `/var/lib/dpkg/status`), by its `+git` version while the nightly
  PPA is configured; the AUR lane by the name `pacman -Qq irlume` prints. The support report gains the channel values
  `fedora_copr_nightly`, `ubuntu_ppa_nightly` and `arch_git`.
- `irlume update` on a nightly lane upgrades through that lane every time,
  since GitHub releases are not its gate: `dnf upgrade --refresh irlume` from
  the nightly Copr, `apt-get install --only-upgrade irlume` after an update
  from the nightly PPA, and, as for the AUR release package, the commands to
  run (an AUR helper does not run as root): `yay -Syu --devel` or rebuilding
  `irlume-git`.
- Version comparisons read the snapshot forms: the caret, `+git` and
  `.r<n>.g<hash>` suffixes end the numeric part, so `0.15.0^...`,
  `0.15.0+git...` and `0.15.0.r139.g...` compare as `0.15.0` against a
  release tag.
- `irlume uninstall` removes the packages that are installed under their own
  names: the one that provides `irlume` (`irlume` or `irlume-git`) and the
  one that provides `irlume-kcm`, whichever it is, so the release KCM beside
  `irlume-git` (its unversioned `depends=('irlume')` lets that pair form) is
  removed with it, in one transaction; and the channel they came from: the
  nightly Copr repository or the nightly PPA, never the release one in their
  place.

### 5. What the channel promises

Nothing beyond `main`: each build is a commit that passed the required checks,
and none has had the release candidate checks. The channel's documentation
says so, and that:

- a nightly build can break face login or its PAM wiring on a given machine;
  the password always works, as it does with any irlume build;
- Copr and Launchpad sign their repositories with their own keys, the AUR
  build fetches `main` over HTTPS without a signature check, and nightly
  builds carry no SBOM, VEX or SLSA provenance ([VERIFY.md](../VERIFY.md)
  covers release assets only);
- leaving the channel returns to the release: `dnf copr disable
  archledger/irlume-nightly`, `dnf copr enable archledger/irlume` (a machine
  installed from the nightly Copr alone has no release repository enabled,
  and `distro-sync` picks from enabled repositories only), then
  `dnf distro-sync --skip-unavailable irlume irlume-selinux irlume-kcm`:
  each subpackage requires the exact `irlume` version, and dnf downgrades
  only the packages a `distro-sync` names, so the installed ones (the
  default install has `irlume-selinux`, a Recommends) move in the same
  transaction, and `--skip-unavailable` lets the command name one that is
  not installed; removing the
  nightly PPA, adding the release PPA (a machine installed from the nightly
  PPA alone has none), then installing the release PPA's version with
  `--allow-downgrades`, with `irlume-kcm` in the same command when it is
  installed, since it depends on the exact `irlume` version; installing
  `irlume` from the AUR, which replaces
  `irlume-git`, in the same transaction as `irlume-kcm` when
  `irlume-kcm-git` is installed (`yay -S irlume irlume-kcm`), since each
  release package replaces only its own nightly counterpart.

### 6. Owner setup, once

These need the maintainer's accounts, and are done once:

1. Copr: create `archledger/irlume-nightly` with the same chroots as
   `archledger/irlume`, network enabled for builds, and
   `github.com/archledger/irlume` under "Packit allowed forge projects"; then
   approve Packit's builder request at its first build (or run
   `copr-cli edit-permissions --builder packit irlume-nightly`).
2. Launchpad: create the PPA `irlume-nightly` under `~archledger`.
3. AUR: publish `irlume-git` from `packaging/arch-git/` with the maintainer's
   AUR key (`irlume-kcm-git` is its split package).
4. minihost: enable the user timer (`systemctl --user enable --now
   irlume-ppa-nightly.timer`).

## Consequences

- Fedora users get a build of every merge, once Copr has built it; Arch users
  get `main` whenever they rebuild `irlume-git`; Ubuntu users get `main` at
  most a day late, once Launchpad has built it.
- On a night `main` moved, minihost builds the source package in a container
  and uploads about 650 MB; Launchpad builds the 582 MB package.
- The AUR copy of the `irlume-git` recipe is updated by hand, with an alert
  when it falls behind `main`'s.
- The CLI gains three install origins and their update and uninstall paths;
  the support report gains three channel values.
- RELEASING.md is unchanged: releases still come only from signed tags, and
  the nightly lanes never replace a release lane's packages.

## Phasing

1. This ADR.
2. The CLI's channel awareness (section 4), before any nightly package
   exists, so the first nightly install is read correctly.
3. The Packit job, the `irlume-git` recipe, the PPA nightly script and its
   timer, and the documentation (sections 1, 3 and 5).
4. The owner setup (section 6), then a first build on each lane.

## Acceptance tests

- With a fake `dnf repoquery` answering `copr:copr.fedorainfracloud.org:
  archledger:irlume-nightly`, `install-origin` names the nightly Copr and
  `irlume update` runs `dnf upgrade --refresh irlume`; with `...:irlume`, the
  release Copr as before.
- With a fake `apt-cache policy` listing only the nightly PPA for the
  installed version, `install-origin` names the nightly PPA; with only the
  release PPA, the release PPA; uninstall removes only the PPA named. A
  nightly version listed only at `/var/lib/dpkg/status`, beside a newer
  candidate from the nightly PPA and the release PPA's version, still reads
  as the nightly PPA.
- Leaving the nightly PPA adds the release PPA before the downgrade, so a
  machine that had only the nightly PPA returns to the release, and names
  `irlume-kcm` in the downgrade command beside `irlume`.
- Leaving the nightly Copr enables the release Copr before `distro-sync`, so
  a machine that had only the nightly Copr returns to the release, and
  names `irlume-selinux` and `irlume-kcm` beside `irlume`, so the default
  install (with `irlume-selinux`) and one with `irlume-kcm` both downgrade
  in one transaction, and one without them still runs.
- With a fake `pacman -Qq irlume` printing `irlume-git`, `install-origin`
  names the AUR nightly package and uninstall removes `irlume-git` and, when
  installed, `irlume-kcm-git`, or the release `irlume-kcm` beside it.
- On a nightly lane `irlume update` prints no "running binary" note, also
  when the crate version is `0.16.0` and the package version
  `0.15.0+git150.g...` (the release-preparation commit before its tag).
- `version_gt` and `version_base` read `0.15.0^20261017git3c162b8`,
  `0.15.0+git139.g3c162b83-0ppa1~resolute1` and `0.15.0.r139.g3c162b83-1` as
  `0.15.0`: not newer than the v0.15.0 tag, and older than v0.15.1. With a
  nonzero patch field, `0.15.1+git3.g...`, `0.15.1^...` and `0.15.1.r3.g...`
  read as `0.15.1`: not older than the v0.15.1 tag, newer than v0.15.0, older
  than v0.15.2.
- The `irlume-git` recipe builds in a clean Arch container, its package
  provides `irlume`, and the parity script checks it.
- `scripts/ppa-nightly.py`, with Launchpad, dput and the container build
  faked:
  - uploads nothing when the derived version is the one last published;
  - uploads when a release tag lands on the already published commit
    (`0.15.0+git139...` becomes `0.16.0+git0...`);
  - after an accepted upload whose publication it has not seen, verifies
    again and does not upload;
  - after a retry published as `-0ppa2`, does nothing while `main` is
    unchanged;
  - after an upload whose source publication never appears (rejected), and
    after a failed build, uploads the same commit with the next PPA
    revision;
  - after a failed build, and after an accepted upload still building,
    followed by a move of `main`, uploads the new version at `-0ppa1` and
    drops the older one;
  - records nothing when the build or the signature fails;
  - after a dput failure whose upload Launchpad accepted, verifies it
    instead of uploading it again.
- The scheduled AUR drift check reports a `PKGBUILD`, `.SRCINFO` or
  `irlume.install` that differs from `main`'s `packaging/arch-git/`, also a
  stale `.SRCINFO` beside a current `PKGBUILD`, and passes when all match.

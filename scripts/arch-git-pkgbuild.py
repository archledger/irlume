#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright the irlume contributors.
"""Generate packaging/arch-git/ from packaging/arch/ (ADR-0037 section 3).

The AUR's irlume-git (with its split irlume-kcm-git) builds the nightly
channel from main. It keeps the release recipe's dependencies, sources,
checksums and package functions, so it is generated from that recipe rather
than kept by hand:

  python3 scripts/arch-git-pkgbuild.py           # write packaging/arch-git/
  python3 scripts/arch-git-pkgbuild.py --check   # exit 1 when it is stale

It also writes the recipe's .SRCINFO, the metadata AUR helpers and the AUR's
RPC read, with `makepkg --printsrcinfo` in a pinned Arch container (docker or
podman; makepkg refuses to run as root, so as a user, without network).

Each change is made at a named anchor of the release PKGBUILD, and a missing
anchor is an error, so a change to the release recipe never leaves the -git
recipe silently different.
"""

from __future__ import annotations

import argparse
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
RELEASE = ROOT / "packaging" / "arch"
NIGHTLY = ROOT / "packaging" / "arch-git"

# The Arch image makepkg runs in, pinned so .SRCINFO does not change with it.
ARCH_IMAGE = (
    "docker.io/library/archlinux:latest"
    "@sha256:3c64b538588416593f69a1aebd2f2ec0f2541b29159f32556fa7def2167147a0"
)

HEADER = """\
# Generated from packaging/arch/PKGBUILD by scripts/arch-git-pkgbuild.py:
# edit that recipe, then run the script (CI checks this file is current).
# The nightly channel (docs/adr/0037-nightly-channel.md): builds main.
"""

PKGVER = '''\
# The last release tag, the commits since it and the commit, as the Arch VCS
# package guidelines spell it: v0.15.0-139-g3c162b83 -> 0.15.0.r139.g3c162b83,
# which vercmp puts after 0.15.0 and before 0.15.1 (ADR-0037 section 2).
pkgver() {
    cd "$srcdir/irlume"
    git describe --long --tags --match 'v[0-9]*' | sed 's/^v//;s/\\([^-]*-g\\)/r\\1/;s/-/./g'
}

'''

# (anchor in the release recipe, replacement), applied in order.
EDITS: list[tuple[str, str]] = [
    (
        "pkgname=(irlume irlume-kcm)\n",
        "pkgbase=irlume-git\npkgname=(irlume-git irlume-kcm-git)\n",
    ),
    (
        "pkgdesc=\"Face authentication for Linux: IR cameras, consent-gated, "
        "photo-spoofing resistant, TPM-sealed, password always works\"\n",
        "pkgdesc=\"Face authentication for Linux: IR cameras, consent-gated, "
        "photo-spoofing resistant, TPM-sealed, password always works "
        "(nightly: builds main)\"\n",
    ),
    (
        "makedepends=('rust' 'cargo' 'gcc' 'clang' 'cmake'",
        "makedepends=('git' 'rust' 'cargo' 'gcc' 'clang' 'cmake'",
    ),
    (
        "# The code comes from the release tag, and makepkg checks the tag's signature\n"
        "# against validpgpkeys (the key scripts/install.sh pins) before it builds;\n"
        "# import it first: `gpg --recv-keys F35053398E3C80FE20891B82C10B8492BD7F30C6`.\n",
        "# The code comes from main over HTTPS. It is not signature-checked: commits\n"
        "# on main are GitHub's squash merges, signed by GitHub's web-flow key, not\n"
        "# by the release key the release recipe checks tags with (ADR-0037).\n",
    ),
    (
        'source=("git+https://github.com/archledger/irlume.git#tag=v${pkgver}?signed"\n',
        'source=("irlume::git+https://github.com/archledger/irlume.git#branch=main"\n',
    ),
    (
        "validpgpkeys=('F35053398E3C80FE20891B82C10B8492BD7F30C6') # archledger, signs the release tags\n",
        "",
    ),
    ("\n\nprepare() {", "\n\n" + PKGVER + "prepare() {"),
    (
        "package_irlume() {\n",
        "package_irlume-git() {\n"
        "    provides=(\"irlume=${pkgver}\")\n"
        "    conflicts=('irlume')\n",
    ),
    (
        "package_irlume-kcm() {\n"
        "    pkgdesc=\"Plasma System Settings module for irlume: read-only status, health and launch actions\"\n"
        "    depends=('irlume' 'qt6-declarative' 'kcmutils' 'kio' 'kirigami')\n",
        "package_irlume-kcm-git() {\n"
        "    pkgdesc=\"Plasma System Settings module for irlume: read-only status, health and launch actions (nightly: builds main)\"\n"
        "    depends=(\"irlume-git=${pkgver}\" 'qt6-declarative' 'kcmutils' 'kio' 'kirigami')\n"
        "    provides=(\"irlume-kcm=${pkgver}\")\n"
        "    conflicts=('irlume-kcm')\n",
    ),
]


def generate(release_pkgbuild: str) -> str:
    """The irlume-git PKGBUILD for `release_pkgbuild`'s text."""
    text = release_pkgbuild
    for anchor, replacement in EDITS:
        count = text.count(anchor)
        if count != 1:
            raise SystemExit(
                f"arch-git-pkgbuild: the release PKGBUILD has {count} copies of an anchor "
                f"(expected 1); update scripts/arch-git-pkgbuild.py:\n{anchor}"
            )
        text = text.replace(anchor, replacement)
    maintainer, _, rest = text.partition("\n")
    if not maintainer.startswith("# Maintainer:"):
        raise SystemExit("arch-git-pkgbuild: the release PKGBUILD must start with its Maintainer line")
    return f"{maintainer}\n{HEADER}{rest}"


def srcinfo(pkgbuild: str, install: str) -> str:
    """`makepkg --printsrcinfo` for the recipe, in the pinned Arch container."""
    engine = shutil.which("docker") or shutil.which("podman")
    if engine is None:
        raise SystemExit("arch-git-pkgbuild: .SRCINFO needs docker or podman to run makepkg in Arch")
    with tempfile.TemporaryDirectory() as recipe:
        Path(recipe, "PKGBUILD").write_text(pkgbuild)
        Path(recipe, "irlume.install").write_text(install)
        result = subprocess.run(
            [
                engine, "run", "--rm", "--network=none", "-v", f"{recipe}:/recipe:ro", ARCH_IMAGE,
                "bash", "-euc",
                "useradd -m builder && cp -r /recipe /home/builder/recipe"
                " && chown -R builder /home/builder/recipe"
                " && su builder -c 'cd /home/builder/recipe && makepkg --printsrcinfo'",
            ],
            check=False,
            capture_output=True,
            text=True,
        )
    if result.returncode != 0:
        raise SystemExit(f"arch-git-pkgbuild: makepkg --printsrcinfo failed:\n{result.stderr}")
    return result.stdout


def outputs() -> dict[Path, str]:
    """Every file under packaging/arch-git/ and its expected content."""
    pkgbuild = generate((RELEASE / "PKGBUILD").read_text())
    # The same install hooks: the packages install the same files.
    install = (RELEASE / "irlume.install").read_text()
    return {
        NIGHTLY / "PKGBUILD": pkgbuild,
        NIGHTLY / "irlume.install": install,
        NIGHTLY / ".SRCINFO": srcinfo(pkgbuild, install),
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--check", action="store_true", help="exit 1 when packaging/arch-git/ is stale")
    args = parser.parse_args()
    stale = []
    for path, content in outputs().items():
        current = path.read_text() if path.exists() else None
        if current == content:
            continue
        if args.check:
            stale.append(path.relative_to(ROOT))
        else:
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(content)
            print(f"wrote {path.relative_to(ROOT)}")
    if stale:
        for path in stale:
            print(f"arch-git-pkgbuild: {path} is stale; run python3 scripts/arch-git-pkgbuild.py", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())

#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright the irlume contributors.
"""Does the AUR's irlume-git match main's recipe? (ADR-0037 section 3)

An AUR helper builds irlume-git from the AUR's own copy of the recipe, which
only the maintainer's AUR key can update. This compares that copy with
packaging/arch-git/ and exits 1 when they differ, or when the AUR does not
serve the package, so a recipe change on main is not left unpublished
unseen. It runs daily (.github/workflows/aur-recipe.yml), where ci-alert.yml
turns a failure into a ci-alert issue.

  python3 scripts/check-aur-recipe.py
"""

from __future__ import annotations

import sys
import urllib.error
import urllib.request
from pathlib import Path
from typing import Callable

ROOT = Path(__file__).resolve().parent.parent
PACKAGE = "irlume-git"
# .SRCINFO too: AUR helpers and the AUR's RPC read the split packages,
# dependencies, provides and conflicts from it, not from the PKGBUILD.
FILES = ("PKGBUILD", ".SRCINFO", "irlume.install")
# cgit's plain view of the AUR repository's default branch.
URL = "https://aur.archlinux.org/cgit/aur.git/plain/{name}?h={package}"


def fetch(url: str) -> str | None:
    """The file at `url`, or None when the AUR does not serve it."""
    request = urllib.request.Request(url, headers={"User-Agent": "irlume-aur-recipe-check"})
    try:
        with urllib.request.urlopen(request, timeout=30) as response:
            return response.read().decode()
    except urllib.error.HTTPError as error:
        if error.code == 404:
            return None
        raise


def drift(local: Callable[[str], str], remote: Callable[[str], str | None]) -> list[str]:
    """Each way the AUR's copy differs from main's, as a sentence."""
    problems = []
    for name in FILES:
        published = remote(name)
        if published is None:
            problems.append(f"the AUR does not serve {PACKAGE}'s {name}: publish packaging/arch-git/")
        elif published != local(name):
            problems.append(
                f"the AUR's {PACKAGE} {name} differs from main's packaging/arch-git/{name}: "
                "push it with the maintainer's AUR key (ADR-0037 section 3)"
            )
    return problems


def main() -> int:
    problems = drift(
        lambda name: (ROOT / "packaging" / "arch-git" / name).read_text(),
        lambda name: fetch(URL.format(name=name, package=PACKAGE)),
    )
    for problem in problems:
        print(f"check-aur-recipe: {problem}", file=sys.stderr)
    if not problems:
        print(f"check-aur-recipe: the AUR's {PACKAGE} matches main's recipe")
    return 1 if problems else 0


if __name__ == "__main__":
    sys.exit(main())

#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright the irlume contributors.
"""The irlume-git recipe keeps the release recipe's build (ADR-0037 section 3).

Checks what scripts/arch-git-pkgbuild.py must keep true of its output: the
nightly names, provides and conflicts, main as the source with no signature
check, a pkgver() from the last release tag, and package functions identical
to the release recipe's apart from those lines.
"""

from __future__ import annotations

import importlib.util
import re
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
SPEC = importlib.util.spec_from_file_location("arch_git_pkgbuild", ROOT / "scripts" / "arch-git-pkgbuild.py")
GENERATOR = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(GENERATOR)

RELEASE = (ROOT / "packaging" / "arch" / "PKGBUILD").read_text()
NIGHTLY = GENERATOR.generate(RELEASE)


def function(text: str, name: str) -> str:
    """The body of shell function `name` in a PKGBUILD."""
    match = re.search(rf"^{re.escape(name)}\(\) {{\n(.*?)^}}\n", text, re.S | re.M)
    if not match:
        raise AssertionError(f"no function {name}")
    return match.group(1)


class ArchGitRecipe(unittest.TestCase):
    def test_names_provides_and_conflicts(self) -> None:
        self.assertIn("pkgbase=irlume-git\n", NIGHTLY)
        self.assertIn("pkgname=(irlume-git irlume-kcm-git)\n", NIGHTLY)
        main = function(NIGHTLY, "package_irlume-git")
        self.assertIn('provides=("irlume=${pkgver}")', main)
        self.assertIn("conflicts=('irlume')", main)
        kcm = function(NIGHTLY, "package_irlume-kcm-git")
        self.assertIn('provides=("irlume-kcm=${pkgver}")', kcm)
        self.assertIn("conflicts=('irlume-kcm')", kcm)
        self.assertIn('"irlume-git=${pkgver}"', kcm)

    def test_main_over_https_without_a_signature_check(self) -> None:
        self.assertIn('"irlume::git+https://github.com/archledger/irlume.git#branch=main"', NIGHTLY)
        self.assertNotIn("?signed", NIGHTLY)
        self.assertNotIn("validpgpkeys", NIGHTLY)
        self.assertIn("'git'", NIGHTLY.split("makedepends=", 1)[1].split("\n", 1)[0])

    def test_pkgver_follows_the_last_release_tag(self) -> None:
        body = function(NIGHTLY, "pkgver")
        self.assertIn("git describe --long --tags --match 'v[0-9]*'", body)
        sed = re.search(r"sed '([^']*)'", body).group(1)
        # The sed program applied to a describe line, as POSIX sed would.
        version = "v0.15.0-139-g3c162b83"
        for command in sed.split(";"):
            _, pattern, replacement, flags = command.split("/")
            pattern = pattern.replace("\\(", "(").replace("\\)", ")")
            replacement = replacement.replace("\\1", r"\1")
            version = re.sub(pattern, replacement, version, count=0 if "g" in flags else 1)
        self.assertEqual(version, "0.15.0.r139.g3c162b83")

    def test_the_build_is_the_release_recipes(self) -> None:
        for name in ("prepare", "build"):
            self.assertEqual(function(NIGHTLY, name), function(RELEASE, name), name)
        added = {
            '    provides=("irlume=${pkgver}")\n',
            "    conflicts=('irlume')\n",
        }
        main = "".join(l for l in function(NIGHTLY, "package_irlume-git").splitlines(True) if l not in added)
        self.assertEqual(main, function(RELEASE, "package_irlume"))
        for marker in ("sha256sums=(", "depends=('onnxruntime'", "backup=("):
            self.assertEqual(
                NIGHTLY.split(marker, 1)[1].split(")", 1)[0],
                RELEASE.split(marker, 1)[1].split(")", 1)[0],
                marker,
            )

    def test_only_the_main_package_carries_the_install_hooks(self) -> None:
        # Set before the package functions, install= gave the KCM package
        # irlume's pre_remove, so removing only the KCM stopped irlumed;
        # backup= and optdepends= name what only irlume ships or uses.
        for text, main, kcm in (
            (RELEASE, "package_irlume", "package_irlume-kcm"),
            (NIGHTLY, "package_irlume-git", "package_irlume-kcm-git"),
        ):
            header = text.split("\nprepare() {", 1)[0]
            for name in ("install=", "backup=", "optdepends="):
                self.assertNotIn("\n" + name, header, name)
                self.assertNotIn(name, function(text, kcm), name)
            self.assertIn("    install=irlume.install\n", function(text, main))

    def test_the_committed_srcinfo_describes_the_split_packages(self) -> None:
        # Its exact content is checked by `arch-git-pkgbuild.py --check`,
        # which runs makepkg; here, what AUR helpers read from it.
        info = (ROOT / "packaging" / "arch-git" / ".SRCINFO").read_text()
        self.assertIn("pkgbase = irlume-git\n", info)
        for line in (
            "pkgname = irlume-git\n",
            "\tconflicts = irlume\n",
            "pkgname = irlume-kcm-git\n",
            "\tconflicts = irlume-kcm\n",
        ):
            self.assertIn(line, info)
        self.assertIn("\tsource = irlume::git+https://github.com/archledger/irlume.git#branch=main\n", info)
        main, kcm = info.split("pkgname = irlume-git\n", 1)[1].split("pkgname = irlume-kcm-git\n", 1)
        self.assertIn("\tinstall = irlume.install\n", main)
        self.assertNotIn("install =", kcm)
        self.assertNotIn("install =", info.split("pkgname = ", 1)[0])

    def test_a_missing_anchor_is_an_error(self) -> None:
        with self.assertRaises(SystemExit):
            GENERATOR.generate(RELEASE.replace("package_irlume() {", "package_irlume () {"))


if __name__ == "__main__":
    sys.exit(0 if unittest.main(exit=False).result.wasSuccessful() else 1)

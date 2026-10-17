#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright the irlume contributors.
"""The AUR drift check reports a difference and passes a match (ADR-0037)."""

from __future__ import annotations

import importlib.util
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
SPEC = importlib.util.spec_from_file_location("check_aur_recipe", ROOT / "scripts" / "check-aur-recipe.py")
CHECK = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(CHECK)

LOCAL = {
    "PKGBUILD": "pkgbase=irlume-git\n",
    ".SRCINFO": "pkgbase = irlume-git\n",
    "irlume.install": "post_install() { :; }\n",
}


class AurDrift(unittest.TestCase):
    def test_a_match_passes(self) -> None:
        self.assertEqual(CHECK.drift(LOCAL.get, LOCAL.get), [])

    def test_a_difference_is_reported(self) -> None:
        remote = dict(LOCAL, PKGBUILD="pkgbase=irlume-git\npkgrel=2\n")
        problems = CHECK.drift(LOCAL.get, remote.get)
        self.assertEqual(len(problems), 1)
        self.assertIn("PKGBUILD differs", problems[0])

    def test_a_stale_srcinfo_beside_a_current_pkgbuild_is_reported(self) -> None:
        remote = dict(LOCAL, **{".SRCINFO": "pkgbase = irlume-git\npkgname = irlume-git\n"})
        problems = CHECK.drift(LOCAL.get, remote.get)
        self.assertEqual(len(problems), 1)
        self.assertIn(".SRCINFO differs", problems[0])

    def test_an_unpublished_package_is_reported(self) -> None:
        problems = CHECK.drift(LOCAL.get, lambda name: None)
        self.assertEqual(len(problems), 3)
        self.assertTrue(all("does not serve" in p for p in problems))

    def test_the_files_compared_are_the_generated_ones(self) -> None:
        for name in CHECK.FILES:
            self.assertTrue((ROOT / "packaging" / "arch-git" / name).is_file(), name)


if __name__ == "__main__":
    sys.exit(0 if unittest.main(exit=False).result.wasSuccessful() else 1)

#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright the irlume contributors.
"""The nightly PPA's decisions (ADR-0037 section 3 and its acceptance tests).

Launchpad, the clone and the containers are not touched: decide() takes the
state, the derived version and a status function, and the state transitions
are pure.
"""

from __future__ import annotations

import importlib.util
import os
import re
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parent.parent
SPEC = importlib.util.spec_from_file_location("ppa_nightly", ROOT / "scripts" / "ppa-nightly.py")
N = importlib.util.module_from_spec(SPEC)
# Dataclasses look their module up in sys.modules while it loads.
sys.modules[SPEC.name] = N
SPEC.loader.exec_module(N)

V = "0.15.0+git139.g3c162b83"
NOW = 1_800_000_000.0


def lp(answers: dict[str, str]):
    """A Launchpad status function: absent unless named."""
    return lambda debver: answers.get(debver, "absent")


class Versions(unittest.TestCase):
    def test_describe_becomes_the_nightly_version(self) -> None:
        self.assertEqual(N.nightly_version("v0.15.0-139-g3c162b83"), V)
        # A release tag on the commit itself: commit count 0, above the release.
        self.assertEqual(N.nightly_version("v0.16.0-0-g3c162b83\n"), "0.16.0+git0.g3c162b83")
        for bad in ("0.15.0-139-g3c1", "v0.15.0", "tflite-runtime-v2.19.0-3-gabc", "v0.15.0-x-gabc"):
            with self.assertRaises(ValueError, msg=bad):
                N.nightly_version(bad)

    def test_debian_version(self) -> None:
        self.assertEqual(N.debian_version(V, 1), f"{V}-0ppa1~resolute1")
        self.assertEqual(N.debian_version(V, 3, "questing"), f"{V}-0ppa3~questing1")


class Decide(unittest.TestCase):
    def test_nothing_when_the_version_is_published(self) -> None:
        action = N.decide({"published": V}, V, NOW, lp({}))
        self.assertIsInstance(action, N.Nothing)

    def test_a_new_version_uploads_its_first_revision(self) -> None:
        self.assertEqual(N.decide({}, V, NOW, lp({})), N.Upload(V, 1, "main moved"))
        moved = N.decide({"published": "0.15.0+git138.gaaaa"}, V, NOW, lp({}))
        self.assertEqual((moved.upstream, moved.pparev), (V, 1))

    def test_a_release_tag_on_the_published_commit_is_a_new_input(self) -> None:
        tagged = N.nightly_version("v0.16.0-0-g3c162b83")
        action = N.decide({"published": V}, tagged, NOW, lp({}))
        self.assertEqual((action.upstream, action.pparev), (tagged, 1))

    def test_an_accepted_upload_is_verified_again_never_uploaded_again(self) -> None:
        pending = {"pending": {"upstream": V, "pparev": 1, "uploaded_at": NOW - 3600}}
        debver = N.debian_version(V, 1)
        self.assertIsInstance(N.decide(pending, V, NOW, lp({debver: "pending"})), N.Wait)
        self.assertEqual(N.decide(pending, V, NOW, lp({debver: "ok"})), N.Published(V))

    def test_a_failed_dput_that_launchpad_accepted_is_verified_not_uploaded_again(self) -> None:
        # After dput, failed or not, the run records the version as uploaded.
        state = N.after_upload({}, N.Upload(V, 1, "main moved"), NOW)
        debver = N.debian_version(V, 1)
        self.assertIsInstance(N.decide(state, V, NOW + 600, lp({debver: "pending"})), N.Wait)
        self.assertEqual(N.decide(state, V, NOW + 600, lp({debver: "ok"})), N.Published(V))
        # Never accepted: a day later, the next revision.
        later = N.decide(state, V, NOW + N.REJECTED_AFTER + 1, lp({}))
        self.assertEqual((later.upstream, later.pparev), (V, 2))

    def test_a_retry_published_as_ppa2_makes_an_unchanged_main_a_no_op(self) -> None:
        pending = {"pending": {"upstream": V, "pparev": 2, "uploaded_at": NOW}}
        published = N.decide(pending, V, NOW, lp({N.debian_version(V, 2): "ok"}))
        state = N.after_publish(pending, published.upstream)
        # The derived version, not a revision, is what is recorded.
        self.assertEqual(state, {"published": V})
        self.assertIsInstance(N.decide(state, V, NOW + 86400, lp({})), N.Nothing)

    def test_a_rejected_upload_retries_with_the_next_revision(self) -> None:
        recent = {"pending": {"upstream": V, "pparev": 1, "uploaded_at": NOW - 3600}}
        self.assertIsInstance(N.decide(recent, V, NOW, lp({})), N.Wait)
        old = {"pending": {"upstream": V, "pparev": 1, "uploaded_at": NOW - N.REJECTED_AFTER - 1}}
        action = N.decide(old, V, NOW, lp({}))
        self.assertEqual((action.upstream, action.pparev), (V, 2))
        self.assertIn("rejected", action.reason)

    def test_a_failed_build_retries_with_the_next_revision(self) -> None:
        pending = {"pending": {"upstream": V, "pparev": 2, "uploaded_at": NOW - 3600}}
        action = N.decide(pending, V, NOW, lp({N.debian_version(V, 2): "failed"}))
        self.assertEqual((action.upstream, action.pparev), (V, 3))
        failed = {"failed": {"upstream": V, "pparev": 3}}
        self.assertEqual(N.decide(failed, V, NOW, lp({})).pparev, 4)

    def test_main_moving_drops_a_failed_or_pending_version(self) -> None:
        new = "0.15.0+git140.gbbbb"
        for state in (
            {"failed": {"upstream": V, "pparev": 3}},
            {"pending": {"upstream": V, "pparev": 1, "uploaded_at": NOW}},
        ):
            action = N.decide(state, new, NOW, lp({}))
            self.assertEqual((action.upstream, action.pparev), (new, 1), state)

    def test_retries_stop_at_the_cap_until_main_moves(self) -> None:
        failed = {"failed": {"upstream": V, "pparev": N.MAX_PPAREV}}
        self.assertIsInstance(N.decide(failed, V, NOW, lp({})), N.Wait)
        self.assertIsInstance(N.decide(failed, "0.15.0+git140.gbbbb", NOW, lp({})), N.Upload)


class States(unittest.TestCase):
    def test_transitions(self) -> None:
        upload = N.Upload(V, 2, "x")
        state = N.after_upload({"published": "old", "failed": {"upstream": V, "pparev": 1}}, upload, NOW)
        self.assertEqual(state, {"published": "old", "pending": {"upstream": V, "pparev": 2, "uploaded_at": NOW}})
        self.assertEqual(
            N.after_failure(state, V, 2), {"published": "old", "failed": {"upstream": V, "pparev": 2}}
        )
        self.assertEqual(N.after_publish(state, V), {"published": V})

    def test_the_state_round_trips_and_starts_empty(self) -> None:
        with tempfile.TemporaryDirectory() as d:
            path = Path(d) / "deep" / "ppa.json"
            self.assertEqual(N.load_state(path), {})
            N.save_state(path, {"published": V})
            self.assertEqual(N.load_state(path), {"published": V})


class Agreement(unittest.TestCase):
    def test_the_build_image_is_the_releases(self) -> None:
        release = (ROOT / "packaging" / "ppa" / "build-ppa-container.sh").read_text()
        base = re.search(r'BASE="\$\{BASE:-([^}]+)\}"', release).group(1)
        self.assertEqual(N.BASE, base)

    def test_files_are_handed_back_under_docker_only(self) -> None:
        # As build-ppa-container.sh: rootless podman's root is this user.
        for path, expected in (
            ("/usr/bin/docker", f"{os.getuid()}:{os.getgid()}"),
            ("/usr/bin/podman", None),
        ):
            with mock.patch.object(N, "engine", return_value=path):
                self.assertEqual(N.owner(), expected, path)

    def test_the_build_runs_the_release_containers_script(self) -> None:
        release = (ROOT / "packaging" / "ppa" / "build-ppa-container.sh").read_text()
        self.assertIn("bash /work/packaging/ppa/container-build.sh", release)
        self.assertIn('"bash", "/work/packaging/ppa/container-build.sh"', (ROOT / "scripts" / "ppa-nightly.py").read_text())


if __name__ == "__main__":
    sys.exit(0 if unittest.main(exit=False).result.wasSuccessful() else 1)

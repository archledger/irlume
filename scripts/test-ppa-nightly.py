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
import stat
import subprocess
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
        # As build-ppa-container.sh: rootless podman's root is this user. The
        # runtime says what it is: podman-docker's `docker` runs podman.
        for path, version, expected in (
            ("/usr/bin/docker", "Docker version 29.9.1, build dfc520dcc2", f"{os.getuid()}:{os.getgid()}"),
            ("/usr/bin/podman", "podman version 5.4.2", None),
            ("/usr/bin/docker", "podman version 5.4.2", None),
        ):
            with mock.patch.object(N, "engine", return_value=path), \
                    mock.patch.object(N, "run", return_value=mock.Mock(stdout=version + "\n")):
                self.assertEqual(N.owner(), expected, (path, version))

    def test_rootless_docker_gets_no_hand_back_either(self) -> None:
        # Its root is this user too; docker info names the mode.
        def answers(rootless: bool):
            def run(cmd, **kwargs):
                if "--version" in cmd:
                    return mock.Mock(stdout="Docker version 29.9.1, build dfc520dcc2\n")
                options = '["name=seccomp,profile=builtin","name=rootless","name=cgroupns"]'
                return mock.Mock(stdout=options if rootless else '["name=seccomp,profile=builtin"]')
            return run
        for rootless, expected in ((True, None), (False, f"{os.getuid()}:{os.getgid()}")):
            with mock.patch.object(N, "engine", return_value="/usr/bin/docker"), \
                    mock.patch.object(N, "run", side_effect=answers(rootless)):
                self.assertEqual(N.owner(), expected, rootless)
        release = (ROOT / "packaging" / "ppa" / "build-ppa-container.sh").read_text()
        self.assertIn("info --format '{{json .SecurityOptions}}'", release)
        self.assertIn("*rootless*) ;;", release)

    def test_the_build_root_is_outside_the_tree(self) -> None:
        # An older tag's build-ppa-source.sh lacks the in-tree exclusion and
        # would copy a build root inside /work into itself.
        build = (ROOT / "packaging" / "ppa" / "container-build.sh").read_text()
        self.assertIn("export BUILDROOT=/out\n", build)
        self.assertNotIn("/work/ppa-build", build)
        release = (ROOT / "packaging" / "ppa" / "build-ppa-container.sh").read_text()
        self.assertIn('-v "$BUILD:/out:z"', release)
        self.assertNotIn("$WORK/ppa-build", release)
        self.assertIn('"-v", f"{built}:/out:z"', (ROOT / "scripts" / "ppa-nightly.py").read_text())

    def test_the_release_wrapper_asks_the_runtime_too(self) -> None:
        release = (ROOT / "packaging" / "ppa" / "build-ppa-container.sh").read_text()
        self.assertIn('case "$("$ENGINE" --version 2>/dev/null)" in', release)
        self.assertNotIn('case "$(basename "$ENGINE")"', release)

    def test_the_build_runs_the_release_containers_script(self) -> None:
        release = (ROOT / "packaging" / "ppa" / "build-ppa-container.sh").read_text()
        # A release runs its checkout's copy, which tags older than the
        # script lack; the nightly runs the copy in the tree it builds.
        self.assertIn('cp "$REPO/packaging/ppa/container-build.sh" "$HELPER/"', release)
        self.assertIn("bash /helper/container-build.sh", release)
        self.assertIn('"bash", "/work/packaging/ppa/container-build.sh"', (ROOT / "scripts" / "ppa-nightly.py").read_text())


def git_env(home: str) -> dict[str, str]:
    """git without the user's or the system's configuration (signing, hooks)."""
    return {
        "GIT_CONFIG_GLOBAL": os.devnull, "GIT_CONFIG_SYSTEM": os.devnull, "HOME": home,
        "GIT_AUTHOR_NAME": "t", "GIT_AUTHOR_EMAIL": "t@example.invalid",
        "GIT_COMMITTER_NAME": "t", "GIT_COMMITTER_EMAIL": "t@example.invalid",
    }


class Clone(unittest.TestCase):
    def test_tags_from_another_repository_never_outlive_its_fetch(self) -> None:
        # A dry run of a fork with a newer tag on official main's commit must
        # not leave that tag for the next real run's git describe.
        with tempfile.TemporaryDirectory() as d, mock.patch.dict(os.environ, git_env(d)):
            git = lambda *args: subprocess.run(["git", *args], check=True, capture_output=True)
            official, fork, clone = (Path(d) / n for n in ("official", "fork", "clone"))
            git("init", "--quiet", "-b", "main", str(official))
            git("-C", str(official), "commit", "--quiet", "--allow-empty", "-m", "one")
            git("-C", str(official), "tag", "v0.15.0")
            git("-C", str(official), "commit", "--quiet", "--allow-empty", "-m", "two")
            # Shallow, as a dry run's local checkout can be.
            git("clone", "--quiet", "--depth", "2", f"file://{official}", str(fork))
            git("-C", str(fork), "tag", "-a", "-m", "not ours", "v999.0.0", "HEAD")
            _, describe, _ = N.update_clone(clone, str(fork), "main")
            self.assertTrue(describe.startswith("v999.0.0-0-g"), describe)
            commit, describe, when = N.update_clone(clone, str(official), "main")
            self.assertTrue(describe.startswith("v0.15.0-1-g"), describe)
            self.assertEqual(N.nightly_version(describe).split("+")[0], "0.15.0")
            self.assertEqual(len(commit), 40)
            self.assertGreater(when, 0)

    def test_a_failed_fetch_is_tried_again(self) -> None:
        # At boot the catch-up run can start before the network is up.
        calls = {"fetch": 0}

        def run(cmd, **kwargs):
            if "fetch" in cmd:
                calls["fetch"] += 1
                if calls["fetch"] < 3:
                    raise subprocess.CalledProcessError(128, cmd)
                return mock.Mock(stdout="")
            answers = {"rev-parse": "c" * 40, "describe": "v0.15.0-139-g3c162b83", "log": "1700000000"}
            return mock.Mock(stdout=next(v for k, v in answers.items() if k in cmd) + "\n")

        with tempfile.TemporaryDirectory() as d, mock.patch.object(N, "run", side_effect=run), \
                mock.patch.object(N.time, "sleep") as sleep, mock.patch.object(N, "log"):
            (Path(d) / ".git").mkdir()
            commit, describe, when = N.update_clone(Path(d))
        self.assertEqual((calls["fetch"], sleep.call_count), (3, 2))
        self.assertEqual(describe, "v0.15.0-139-g3c162b83")
        # And it gives up after FETCH_TRIES.
        calls["fetch"] = -100
        with tempfile.TemporaryDirectory() as d, mock.patch.object(N, "run", side_effect=run), \
                mock.patch.object(N.time, "sleep") as sleep, mock.patch.object(N, "log"):
            (Path(d) / ".git").mkdir()
            with self.assertRaises(subprocess.CalledProcessError):
                N.update_clone(Path(d))
        self.assertEqual(sleep.call_count, N.FETCH_TRIES - 1)

    def test_a_dry_run_of_another_repository_gets_its_own_clone(self) -> None:
        self.assertNotEqual(N.DRY_RUN_CLONE, N.DEFAULT_CLONE)
        self.assertEqual(N.DRY_RUN_CLONE.parent, N.DEFAULT_CLONE.parent)


class Collect(unittest.TestCase):
    DEBVER = N.debian_version(V, 1)

    def built(self, root: Path) -> Path:
        built = root / "tree" / "ppa-build"
        built.mkdir(parents=True)
        for name in N.artifacts(V, self.DEBVER):
            (built / name).write_text(name)
        return built

    def test_the_upload_moves_out_of_the_build_tree(self) -> None:
        with tempfile.TemporaryDirectory() as d:
            built = self.built(Path(d))
            old = os.umask(0o022)
            try:
                changes = N.collect(built, Path(d) / "out", V, self.DEBVER)
            finally:
                os.umask(old)
            # A signed upload is for this user alone, whatever the umask.
            self.assertEqual(stat.S_IMODE(changes.parent.stat().st_mode), 0o700)
            self.assertEqual(changes, Path(d) / "out" / f"irlume_{self.DEBVER}_source.changes")
            self.assertEqual(sorted(p.name for p in changes.parent.iterdir()), sorted(N.artifacts(V, self.DEBVER)))
            self.assertEqual(list(built.iterdir()), [])

    def test_a_symlink_from_the_build_is_refused(self) -> None:
        # The build container ran main's code; a link it left could aim a
        # later host write at the installed uploader or anything else.
        with tempfile.TemporaryDirectory() as d:
            victim = Path(d) / "victim"
            victim.write_text("keep")
            built = self.built(Path(d))
            dsc = built / f"irlume_{self.DEBVER}.dsc"
            dsc.unlink()
            dsc.symlink_to(victim)
            with self.assertRaises(RuntimeError):
                N.collect(built, Path(d) / "out", V, self.DEBVER)
            self.assertEqual(victim.read_text(), "keep")
        with tempfile.TemporaryDirectory() as d:
            elsewhere = Path(d) / "elsewhere"
            elsewhere.mkdir()
            (Path(d) / "tree").mkdir()
            (Path(d) / "tree" / "ppa-build").symlink_to(elsewhere)
            with self.assertRaises(RuntimeError):
                N.collect(Path(d) / "tree" / "ppa-build", Path(d) / "out", V, self.DEBVER)

    def test_the_key_is_exported_beside_the_build_never_into_it(self) -> None:
        source = (ROOT / "scripts" / "ppa-nightly.py").read_text()
        self.assertIn('export_key(args.work / "key")', source)
        self.assertNotIn("changes.parent / \"signing-key.asc\"", source)


class DryRun(unittest.TestCase):
    def run_main(self, state: dict) -> tuple[dict, list[str]]:
        """main() with --no-upload over `state`: the state file afterwards, and
        which of build, sign and upload ran."""
        ran: list[str] = []
        with tempfile.TemporaryDirectory() as d:
            path = Path(d) / "ppa.json"
            N.save_state(path, state)
            changes = Path(d) / "out" / "x_source.changes"
            argv = ["ppa-nightly.py", "--no-upload", "--state", str(path), "--clone", d, "--work", d]
            with mock.patch.object(sys, "argv", argv), \
                    mock.patch.object(N, "LOCK", Path(d) / "lock"), \
                    mock.patch.object(N, "update_clone", return_value=("c" * 40, "v0.15.0-139-g3c162b83", 1)), \
                    mock.patch.object(N, "launchpad", return_value=lp({N.debian_version(V, 1): "pending"})), \
                    mock.patch.object(N, "build", side_effect=lambda *a: ran.append("build") or changes), \
                    mock.patch.object(N, "export_key", return_value=Path(d)), \
                    mock.patch.object(N, "sign", side_effect=lambda *a: ran.append("sign")), \
                    mock.patch.object(N, "upload", side_effect=lambda *a: ran.append("upload")):
                self.assertEqual(N.main(), 0)
            return N.load_state(path), ran

    def test_a_dry_run_builds_and_signs_whatever_the_state_says(self) -> None:
        # Caught up, pending or empty: the check still builds, never uploads,
        # and records nothing.
        for state in (
            {"published": V},
            {"pending": {"upstream": V, "pparev": 1, "uploaded_at": NOW}},
            {},
        ):
            after, ran = self.run_main(state)
            self.assertEqual(ran, ["build", "sign"], state)
            self.assertEqual(after, state)

    def test_a_dry_run_builds_when_launchpad_cannot_be_read(self) -> None:
        # A pending record makes the timer's decision ask Launchpad; the
        # verifier exits when it cannot, and the dry run builds anyway.
        def unreachable(debver: str) -> str:
            raise SystemExit(2)
        state = {"pending": {"upstream": V, "pparev": 1, "uploaded_at": NOW}}
        with mock.patch.object(N, "log") as log:
            action = N.dry_run(state, V, unreachable)
        self.assertEqual((action.upstream, action.pparev), (V, 1))
        self.assertIn("could not be read", log.call_args.args[0])

    def test_one_run_at_a_time(self) -> None:
        # A dry run beside the timer would delete its work directory.
        with tempfile.TemporaryDirectory() as d:
            lock = Path(d) / "state" / "lock"
            first = N.hold_lock(lock)
            self.assertIsNotNone(first)
            self.assertIsNone(N.hold_lock(lock))
            with mock.patch.object(N, "LOCK", lock), \
                    mock.patch.object(sys, "argv", ["ppa-nightly.py", "--no-upload"]), \
                    mock.patch.object(N, "update_clone") as clone:
                self.assertEqual(N.main(), 1)
                clone.assert_not_called()
            first.close()
            again = N.hold_lock(lock)
            self.assertIsNotNone(again)
            again.close()

    def test_what_the_timer_would_do_is_a_sentence(self) -> None:
        self.assertEqual(N.what(N.Upload(V, 2, "its build failed at -0ppa1")),
                         f"upload {V}-0ppa2~resolute1 (its build failed at -0ppa1)")
        self.assertEqual(N.what(N.Published(V)), f"record {V} as published")
        self.assertEqual(N.what(N.Nothing("x")), "x")


class Uploaded(unittest.TestCase):
    def test_the_signed_changes_is_deleted_after_the_upload(self) -> None:
        # Never used again, and it is what an upload to another PPA needs.
        for push in (lambda *a: None, mock.Mock(side_effect=subprocess.CalledProcessError(1, ["dput"]))):
            with tempfile.TemporaryDirectory() as d:
                state = Path(d) / "ppa.json"
                changes = Path(d) / "out" / "x_source.changes"
                changes.parent.mkdir()
                changes.write_text("signed")
                argv = ["ppa-nightly.py", "--state", str(state), "--clone", d, "--work", d]
                with mock.patch.object(sys, "argv", argv), \
                        mock.patch.object(N, "LOCK", Path(d) / "lock"), \
                        mock.patch.object(N, "POLL_FOR", 0), \
                        mock.patch.object(N, "update_clone", return_value=("c" * 40, "v0.15.0-139-g3c162b83", 1)), \
                        mock.patch.object(N, "launchpad", return_value=lp({})), \
                        mock.patch.object(N, "build", return_value=changes), \
                        mock.patch.object(N, "export_key", return_value=Path(d)), \
                        mock.patch.object(N, "sign"), \
                        mock.patch.object(N, "upload", side_effect=push):
                    N.main()
                self.assertFalse(changes.exists())
                self.assertEqual(N.load_state(state)["pending"]["upstream"], V)


class Mounts(unittest.TestCase):
    def argv(self, call) -> list[str]:
        calls: list[list[str]] = []

        def fake(cmd, **kwargs):
            calls.append(cmd)
            return mock.Mock(stdout="/run/user/1000/gnupg/S.gpg-agent.extra" if "gpgconf" in cmd else b"")

        with mock.patch.object(N, "run", side_effect=fake), \
                mock.patch.object(N, "engine", return_value="/usr/bin/podman"), \
                mock.patch.object(N, "owner", return_value=None):
            call()
        return next(c for c in calls if c[1:2] == ["run"])

    def test_an_selinux_host_lets_the_containers_read_their_mounts(self) -> None:
        # Podman changes no label by default; the release wrapper uses :z.
        out, key = Path("/w/out"), Path("/w/key")
        changes = out / "irlume_1_source.changes"
        upload = self.argv(lambda: N.upload(changes, key))
        self.assertIn(f"{out}:/pkg:z", upload)
        self.assertIn(f"{key}:/key:ro,z", upload)
        # Signing disables label separation instead: :z would relabel the
        # user's own gpg-agent socket.
        sign = self.argv(lambda: N.sign(changes, key))
        self.assertIn("label=disable", sign)
        self.assertIn("/run/user/1000/gnupg/S.gpg-agent.extra:/gnupg/S.gpg-agent", sign)
        self.assertIn('f"{tree}:/work:z"', (ROOT / "scripts" / "ppa-nightly.py").read_text())


class Upload(unittest.TestCase):
    ACTION = N.Upload(V, 2, "its build failed at -0ppa1")

    def test_a_failure_before_dput_records_nothing(self) -> None:
        def push() -> None:
            raise N.NotUploaded("the upload container failed before dput (exit 87)")
        recorded, uploaded, message = N.attempt_upload({"published": "x"}, self.ACTION, NOW, push)
        self.assertIsNone(recorded)
        self.assertFalse(uploaded)
        self.assertIn("nothing recorded", message)

    def test_once_dput_ran_the_upload_is_pending_whatever_dput_said(self) -> None:
        def fails() -> None:
            raise subprocess.CalledProcessError(1, ["dput"])
        for push, ok in ((fails, False), (lambda: None, True)):
            recorded, uploaded, _ = N.attempt_upload({"published": "x"}, self.ACTION, NOW, push)
            self.assertEqual(recorded["pending"], {"upstream": V, "pparev": 2, "uploaded_at": NOW})
            self.assertEqual(uploaded, ok)

    def test_the_upload_container_tells_setup_from_dput(self) -> None:
        changes = Path("/x/irlume_1_source.changes")
        for code, raised in ((N.BEFORE_DPUT, N.NotUploaded), (125, N.NotUploaded), (1, subprocess.CalledProcessError)):
            failure = subprocess.CalledProcessError(code, ["docker"])
            with mock.patch.object(N, "engine", return_value="/usr/bin/docker"), \
                    mock.patch.object(N, "run", side_effect=failure):
                with self.assertRaises(raised, msg=str(code)) as caught:
                    N.upload(changes, Path("/k"))
                if raised is subprocess.CalledProcessError:
                    self.assertNotIsInstance(caught.exception, N.NotUploaded)


if __name__ == "__main__":
    sys.exit(0 if unittest.main(exit=False).result.wasSuccessful() else 1)

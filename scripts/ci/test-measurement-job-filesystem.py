#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright the irlume contributors.
"""Synthetic filesystem identities; no device nodes, services or namespaces."""

import copy
import importlib.util
import os
import socket
import stat
import tempfile
import time
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest import mock

HERE = Path(__file__).resolve().parent
# sun_path holds 108 bytes, so directories that will hold a bound AF_UNIX
# socket use this short base instead of TMPDIR, which may be long.
SOCKET_BASE = "/tmp"


def load(name, filename):
    spec = importlib.util.spec_from_file_location(name, HERE / filename)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


fs = load("filesystem", "measurement-job-filesystem.py")
fixtures = load("filesystem_fixtures", "test-measurement-job-root.py")


class FilesystemTests(unittest.TestCase):
    def test_descriptor_tree_does_not_follow_links_and_rechecks_names(self):
        reader = fs.startup.ProcCollector(time.monotonic_ns() + 5_000_000_000)
        with (
            reader._open(self.base, directory=True, path_only=True) as fd,
            fs.RootTree(reader, fd) as tree,
        ):
            self.assertIsNone(tree.node("/missing"))
            self.assertEqual(tree.node("/dev/fd")["target"], "/proc/self/fd")
            tree.node("/run/irlume/base.raw")
            target = self.path("/run/irlume/base.raw")
            target.rename(target.with_name("old.raw"))
            target.write_bytes(b"replacement")
            with self.assertRaises(ValueError):
                tree.recheck()
        self.assertEqual(reader.owned, {})

    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(dir=SOCKET_BASE)
        self.addCleanup(self.temporary.cleanup)
        self.base = Path(self.temporary.name)
        self.plan, _ = fixtures.selection()
        self.plan["uid"] = os.getuid()
        self.plan["gid"] = os.getgid()
        self.devices = {}
        self.paths = {
            "attempt": "/run/irlume/attempt",
            "base": "/run/irlume/base.raw",
            "payload": "/run/irlume/payload.raw",
            "manifest": "/run/irlume/runtime-manifest.json",
        }
        for path in (
            "/dev",
            "/proc",
            "/sys/fs",
            "/run/host",
            "/tmp",
        ):
            self.path(path).mkdir(parents=True, exist_ok=True)
        for name, path in self.paths.items():
            target = self.path(path)
            if name == "attempt":
                target.mkdir(parents=True, mode=0o700)
            else:
                target.write_bytes(b"immutable\n")
                target.chmod(0o400)
            info = target.stat()
            self.plan[name]["device"], self.plan[name]["inode"] = (
                info.st_dev,
                info.st_ino,
            )
        for name, device in fs.DEVICES.items():
            target = self.path("/dev/" + name)
            target.touch()
            self.devices[target.stat().st_ino] = os.makedev(*device)
        for name, target in fs.DEV_LINKS.items():
            self.path("/dev/" + name).symlink_to(target)
        for path in (*fs.root.DENIED, *fs.root.KERNEL_DENIED, *fixtures.HOST_COVERS):
            target = self.path(path)
            if path == "/dev/ptmx":
                target.symlink_to("pts/ptmx")
            elif path in fs.root.KERNEL_DENIED:
                target.touch()
                target.chmod(0)
            else:
                target.parent.mkdir(parents=True, exist_ok=True)
                target.mkdir(mode=0)
        info = self.base.stat()
        self.plan["root"]["device"], self.plan["root"]["inode"] = (
            info.st_dev,
            info.st_ino,
        )

    def path(self, absolute):
        return self.base / absolute.lstrip("/")

    def collect(
        self,
        plan=None,
        process_root=None,
        opened=None,
        process_mountinfo=b"fixture\n",
        process_stdio=None,
        root_changed=False,
        configure=None,
        cancel_at=None,
        acquired=None,
        after=None,
    ):
        collector = fs.FilesystemCollector(time.monotonic_ns() + 5_000_000_000)
        self.last_collector = collector
        real_open, real_stat, real_metadata = os.open, os.stat, fs.metadata
        real_read = collector._read
        with collector._open(f"/proc/{os.getpid()}", directory=True) as fd:
            namespaces = collector._namespaces(fd)
        process = {
            "root": {key: self.plan["root"][key] for key in ("device", "inode")},
            "mountinfo": process_mountinfo,
            "namespaces": namespaces,
            "stdio": collector._stdio(),
            "fds": (0, 1, 2),
        }
        if process_root is not None:
            process["root"] = process_root
        if process_stdio is not None:
            process["stdio"] = process_stdio

        def open_root(path, flags, *args, **kwargs):
            if opened is not None:
                opened.append((path, flags))
            if path == cancel_at:
                raise KeyboardInterrupt
            if path == "/" and flags & os.O_PATH:
                path = self.base
            fd = real_open(path, flags, *args, **kwargs)
            if acquired is not None:
                acquired.append(fd)
            return fd

        def stat_root(path, *args, **kwargs):
            info = real_stat(self.base if path == "/" else path, *args, **kwargs)
            if path == "/" and root_changed:
                fields = {
                    name: getattr(info, name)
                    for name in (
                        "st_dev",
                        "st_ino",
                        "st_mode",
                        "st_uid",
                        "st_gid",
                        "st_nlink",
                        "st_size",
                        "st_mtime_ns",
                        "st_ctime_ns",
                        "st_rdev",
                    )
                }
                fields["st_ino"] += 1
                return SimpleNamespace(**fields)
            return info

        def device_metadata(info):
            result = real_metadata(info)
            if info.st_ino in self.devices:
                result["mode"] = stat.S_IFCHR | 0o666
                result["rdev"] = self.devices[info.st_ino]
            return result

        def read(proc, name, limit):
            return b"fixture\n" if name == "mountinfo" else real_read(proc, name, limit)

        def proc_snapshot():
            if configure is not None:
                configure(collector)
            return process

        with (
            mock.patch.object(
                fs.startup.ProcCollector, "collect", side_effect=proc_snapshot
            ),
            mock.patch.object(fs.os, "open", side_effect=open_root),
            mock.patch.object(fs.os, "stat", side_effect=stat_root),
            mock.patch.object(fs, "metadata", side_effect=device_metadata),
            mock.patch.object(collector, "_read", side_effect=read),
        ):
            result = collector.collect(plan or self.plan)
            if after is not None:
                result = after(collector, result)
        self.assertEqual(collector.owned, {})
        return result

    def test_fixed_root_identities_and_special_nodes_are_collected_without_data_io(
        self,
    ):
        row = self.collect()
        self.assertEqual(
            row["nodes"][self.paths["base"]]["inode"], self.plan["base"]["inode"]
        )
        self.assertEqual(row["nodes"]["/dev/null"]["rdev"], os.makedev(1, 3))
        self.assertEqual(row["nodes"]["/dev/ptmx"]["target"], "pts/ptmx")
        self.assertEqual(row["entries"]["/tmp"], ())
        self.assertNotIn("accepted", row)

    def test_wrong_selected_root_or_input_refuses(self):
        for key in ("root", "base", "payload", "manifest", "attempt"):
            plan = copy.deepcopy(self.plan)
            plan[key]["inode"] += 2**32
            with self.subTest(key=key), self.assertRaises(ValueError):
                self.collect(plan)

    def test_user_runtime_directory_refuses(self):
        row = self.collect()
        self.assertIsNone(row["nodes"]["/run/user"])
        self.assertNotIn("user", row["entries"]["/run"])
        user = self.path("/run/user")
        user.mkdir()
        with self.assertRaisesRegex(
            ValueError, "^unexpected filesystem directory entry$"
        ):
            self.collect()
        user.rmdir()
        endpoint = socket.socket(socket.AF_UNIX)
        try:
            endpoint.bind(str(user))
        finally:
            endpoint.close()
        with self.assertRaisesRegex(
            ValueError, "^unexpected filesystem directory entry$"
        ):
            self.collect()
        user.unlink()
        # A witness whose inventory omits the node is refused on the node itself.
        nodes = copy.deepcopy(row["nodes"])
        nodes["/run/user"] = dict(nodes["/run"])
        with self.assertRaisesRegex(
            ValueError, "^user runtime directory in rooted view$"
        ):
            fs.check_roles(self.plan, nodes, row["entries"])

    def test_writable_wrong_type_and_symlinked_inputs_refuse(self):
        target = self.path(self.paths["base"])
        target.chmod(0o600)
        with self.assertRaises(ValueError):
            self.collect()
        target.unlink()
        target.symlink_to("payload.raw")
        with self.assertRaises(ValueError):
            self.collect()

    def test_ancestor_symlink_and_unknown_directory_entries_refuse(self):
        self.path("/dev/kvm").touch()
        with self.assertRaises(ValueError):
            self.collect()
        self.path("/dev/kvm").unlink()
        inputs = self.path("/run/irlume")
        inputs.rename(inputs.with_name("moved"))
        inputs.symlink_to("moved", target_is_directory=True)
        with self.assertRaises((ValueError, OSError)):
            self.collect()

    def test_private_dev_number_links_are_exact_and_optional(self):
        self.collect()
        links = self.path("/dev/char")
        links.mkdir()
        for number, name in fs.CHAR_LINKS.items():
            (links / number).symlink_to("../" + name)
        self.collect()
        cases = (
            ("extra number", lambda: (links / "1:1").symlink_to("../mem")),
            (
                "wrong target",
                lambda: (
                    (links / "1:3").unlink(),
                    (links / "1:3").symlink_to("../zero"),
                ),
            ),
            ("not a link", lambda: ((links / "1:9").unlink(), (links / "1:9").touch())),
            ("block directory", lambda: self.path("/dev/block").mkdir()),
        )
        for label, change in cases:
            change()
            with self.subTest(label), self.assertRaises(ValueError):
                self.collect()
            for extra in (links / "1:1", self.path("/dev/block")):
                if extra.is_dir():
                    extra.rmdir()
                elif extra.is_symlink():
                    extra.unlink()
            for number, name in fs.CHAR_LINKS.items():
                link = links / number
                if link.is_symlink() and link.readlink() == Path("../" + name):
                    continue
                link.unlink(missing_ok=True)
                link.symlink_to("../" + name)
        self.collect()

    def test_wrong_device_number_and_symlink_target_refuse(self):
        inode = self.path("/dev/null").stat().st_ino
        self.devices[inode] = os.makedev(1, 5)
        with self.assertRaises(ValueError):
            self.collect()
        self.devices[inode] = os.makedev(1, 3)
        target = self.path("/dev/fd")
        target.unlink()
        target.symlink_to("/etc")
        with self.assertRaises(ValueError):
            self.collect()

    def test_process_root_must_agree_even_with_correct_selected_root(self):
        with self.assertRaises(ValueError):
            self.collect(
                process_root={
                    "device": self.plan["root"]["device"],
                    "inode": self.plan["root"]["inode"] + 1,
                }
            )

    def test_real_unrooted_process_cannot_pass_as_selected_fixture_root(self):
        collector = fs.FilesystemCollector(time.monotonic_ns() + 5_000_000_000)
        with self.assertRaisesRegex(ValueError, "filesystem root does not match"):
            collector.collect(self.plan)
        self.assertEqual(collector.owned, {})
        with self.assertRaisesRegex(ValueError, "single-use"):
            collector.collect(self.plan)

    def test_special_endpoints_are_never_opened_for_data(self):
        opened = []
        self.collect(opened=opened)
        targets = set(fs.DEVICES) | {
            "base.raw",
            "payload.raw",
            "runtime-manifest.json",
            "ptmx",
        }
        endpoints = [(path, flags) for path, flags in opened if path in targets]
        self.assertEqual(len(endpoints), len(targets))
        self.assertTrue(all(flags & os.O_PATH for _, flags in endpoints))

    def test_attempt_mode_and_input_hardlink_are_checked(self):
        attempt = self.path(fs.root.ATTEMPT)
        attempt.chmod(0o755)
        with self.assertRaises(ValueError):
            self.collect()
        attempt.chmod(0o700)
        extra = self.path("/hardlink")
        extra.hardlink_to(self.path(self.paths["base"]))
        with self.assertRaises(ValueError):
            self.collect()
        extra.unlink()
        self.collect()

    def test_directory_entry_limit_and_optional_os_release_topology(self):
        stage = self.path(fs.root.OS_RELEASE_STAGE)
        stage.mkdir()
        (stage / "os-release").write_bytes(b"ID=synthetic\n")
        self.path("/run/host/os-release").symlink_to(".os-release-stage/os-release")
        self.collect()
        (stage / "extra").touch()
        with self.assertRaises(ValueError):
            self.collect()
        (stage / "extra").unlink()
        for number in range(129):
            self.path(f"/tmp/entry-{number}").touch()
        with self.assertRaises(ValueError):
            self.collect()

    def test_inaccessible_denial_and_mode_zero_socket_fallback_are_recorded(self):
        target = self.path("/proc/kcore")
        target.unlink()
        endpoint = socket.socket(socket.AF_UNIX)
        try:
            endpoint.bind(str(target))
        finally:
            endpoint.close()
        target.chmod(0)
        row = self.collect()
        self.assertEqual(row["nodes"]["/proc/kcore"]["mode"], stat.S_IFSOCK)
        self.path("/dev/shm").chmod(0o700)
        with self.assertRaises(ValueError):
            self.collect()

    def test_original_name_is_checked_even_when_retained_descriptor_is_unchanged(self):
        reader = fs.startup.ProcCollector(time.monotonic_ns() + 5_000_000_000)
        with (
            reader._open(self.base, directory=True, path_only=True) as fd,
            fs.RootTree(reader, fd) as tree,
        ):
            tree.node("/run/irlume/base.raw")
            real_stat = os.stat

            def changed(path, *args, **kwargs):
                info = real_stat(path, *args, **kwargs)
                if path == "base.raw":
                    fields = {
                        name: getattr(info, name)
                        for name in (
                            "st_dev",
                            "st_ino",
                            "st_mode",
                            "st_uid",
                            "st_gid",
                            "st_nlink",
                            "st_size",
                            "st_mtime_ns",
                            "st_ctime_ns",
                            "st_rdev",
                        )
                    }
                    fields["st_ino"] += 1
                    return SimpleNamespace(**fields)
                return info

            with (
                mock.patch.object(fs.os, "stat", side_effect=changed),
                self.assertRaises(ValueError),
            ):
                tree.recheck()

    def test_kernel_view_nodes_are_observed_and_must_be_inaccessible(self):
        row = self.collect()
        for path in fs.root.KERNEL_HIDDEN:
            expected = None if path not in fixtures.HOST_COVERS else 0o40000
            node = row["nodes"][path]
            self.assertEqual(None if node is None else node["mode"], expected)
        target = self.path("/sys/kernel/debug")
        target.chmod(0o555)
        try:
            with self.assertRaisesRegex(ValueError, "filesystem denial is accessible"):
                self.collect()
        finally:
            target.chmod(0)

    def test_denial_host_alias_and_ptmx_ancestor_type_refuse(self):
        plan = copy.deepcopy(self.plan)
        info = self.path("/dev/shm").stat()
        plan["host_api"]["/dev/shm"] = {"device": info.st_dev, "inode": info.st_ino}
        with self.assertRaises(ValueError):
            self.collect(plan)
        pts = self.path("/dev/pts")
        pts.rmdir()
        pts.touch()
        pts.chmod(0)
        with self.assertRaises(ValueError):
            self.collect()

    def test_os_release_target_and_file_execute_bits_are_rejected(self):
        stage = self.path(fs.root.OS_RELEASE_STAGE)
        stage.mkdir()
        release = stage / "os-release"
        release.write_bytes(b"ID=synthetic\n")
        link = self.path("/run/host/os-release")
        link.symlink_to("/etc/os-release")
        with self.assertRaises(ValueError):
            self.collect()
        link.unlink()
        link.symlink_to(".os-release-stage/os-release")
        release.chmod(0o755)
        with self.assertRaises(ValueError):
            self.collect()

    def test_scan_entry_cap_is_independent_of_later_role_policy(self):
        for number in range(129):
            self.path(f"/tmp/entry-{number}").touch()
        reader = fs.startup.ProcCollector(time.monotonic_ns() + 5_000_000_000)
        with (
            reader._open(self.base, directory=True, path_only=True) as fd,
            fs.RootTree(reader, fd) as tree,
            self.assertRaises(ValueError),
        ):
            tree.entries("/tmp")
        self.assertEqual(reader.owned, {})

    def test_role_validation_crosschecks_inventory_against_node_facts(self):
        row = self.collect()
        entries = copy.deepcopy(row["entries"])
        entries["/run/irlume"] = tuple(
            name for name in entries["/run/irlume"] if name != "base.raw"
        )
        with self.assertRaises(ValueError):
            fs.check_roles(self.plan, row["nodes"], entries)
        entries = copy.deepcopy(row["entries"])
        entries["/run"] = None
        with self.assertRaises(ValueError):
            fs.check_roles(self.plan, row["nodes"], entries)

    def test_final_root_mount_and_stdio_changes_refuse(self):
        for changes in (
            {"root_changed": True},
            {"process_mountinfo": b"different\n"},
            {"process_stdio": ()},
        ):
            with self.subTest(changes=changes), self.assertRaises(ValueError):
                self.collect(**changes)

    def test_recheck_binds_historical_identity_and_current_handle_independently(self):
        for replace_name in (False, True):
            reader = fs.startup.ProcCollector(time.monotonic_ns() + 5_000_000_000)
            with (
                reader._open(self.base, directory=True, path_only=True) as fd,
                fs.RootTree(reader, fd) as tree,
            ):
                path = "/run/irlume/base.raw"
                tree.node(path)
                target = tree.handles[path]
                real_stat, real_fstat = os.stat, os.fstat

                def replacement(info):
                    fields = {
                        name: getattr(info, name)
                        for name in (
                            "st_dev",
                            "st_ino",
                            "st_mode",
                            "st_uid",
                            "st_gid",
                            "st_nlink",
                            "st_size",
                            "st_mtime_ns",
                            "st_ctime_ns",
                            "st_rdev",
                        )
                    }
                    fields["st_ino"] += 1
                    return SimpleNamespace(**fields)

                def stat_name(
                    name,
                    *args,
                    selected=replace_name,
                    original=real_stat,
                    replace=replacement,
                    **kwargs,
                ):
                    info = original(name, *args, **kwargs)
                    return replace(info) if selected and name == "base.raw" else info

                def stat_fd(
                    number, selected=target, original=real_fstat, replace=replacement
                ):
                    info = original(number)
                    return replace(info) if number == selected else info

                with (
                    self.subTest(replace_name=replace_name),
                    mock.patch.object(fs.os, "stat", side_effect=stat_name),
                    mock.patch.object(fs.os, "fstat", side_effect=stat_fd),
                    self.assertRaises(ValueError),
                ):
                    tree.recheck()

    def test_filesystem_phase_cannot_restart_consumed_proc_budget(self):
        for expired in (False, True):
            opened = []

            def consume(collector, expired=expired):
                if expired:
                    collector.deadline = time.monotonic_ns() - 1
                else:
                    collector.operations = fs.startup.MAX_OPERATIONS

            with (
                self.subTest(expired=expired),
                self.assertRaises(TimeoutError if expired else ValueError),
            ):
                self.collect(configure=consume, opened=opened)
            self.assertEqual(opened, [])
            self.assertEqual(self.last_collector.owned, {})

    def test_cancellation_during_cached_traversal_closes_every_acquired_fd(self):
        acquired = []
        with self.assertRaises(KeyboardInterrupt):
            self.collect(cancel_at="base.raw", acquired=acquired)
        self.assertTrue(acquired)
        self.assertEqual(self.last_collector.owned, {})
        for fd in set(acquired):
            with self.subTest(fd=fd), self.assertRaises(OSError):
                os.fstat(fd)
        os.fstat(0)

    def test_final_observation_reuses_selection_and_preserves_both_timestamps(self):
        def finish(collector, first):
            # Either change refuses unless the original selection is reused.
            self.plan["uid"] += 1
            self.plan["base"]["inode"] += 1
            final = collector.reobserve()
            self.assertIsNone(final["nodes"]["/run/user"])
            self.assertEqual(final["started_ns"], first["started_ns"])
            self.assertGreater(final["finished_ns"], first["finished_ns"])
            self.assertIsNot(final["nodes"], first["nodes"])
            with self.assertRaises(ValueError):
                collector.reobserve()
            return final

        self.collect(after=finish)

    def test_final_observation_catches_new_excluded_directory_content(self):
        def finish(collector, first):
            self.path("/tmp/unexpected").touch()
            with self.assertRaises(ValueError):
                collector.reobserve()
            self.assertEqual(collector.owned, {})
            return first

        self.collect(after=finish)

    def test_final_observation_cannot_reset_an_expired_deadline(self):
        def finish(collector, first):
            collector.deadline = time.monotonic_ns() - 1
            with self.assertRaises(TimeoutError):
                collector.reobserve()
            self.assertEqual(collector.owned, {})
            with self.assertRaises(ValueError):
                collector.reobserve()
            return first

        self.collect(after=finish)


if __name__ == "__main__":
    unittest.main()

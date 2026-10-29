#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright the irlume contributors.
"""Startup composition contracts; no service, namespace or VM is created."""

import contextlib
import copy
import importlib.machinery
import importlib.util
import os
import stat
import tempfile
import time
import types
import unittest
from pathlib import Path
from unittest import mock

HERE = Path(__file__).resolve().parent
SPEC = importlib.util.spec_from_file_location(
    "startup_check", HERE / "measurement-job-startup-check.py"
)
startup = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(startup)


def load(name, filename):
    spec = importlib.util.spec_from_file_location(name, HERE / filename)
    result = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(result)
    return result


filesystem = load("startup_check_filesystem", "measurement-job-filesystem.py")
root_tests = load("startup_check_root_tests", "test-measurement-job-root.py")
# G's /proc/self/maps once the runtime's python3 has loaded every measurement
# module: 10703 bytes in 93 lines, three page reads. Same shape, synthetic text.
G_MAPS = b"".join(
    (b"%012x-%012x r-xp 00000000 00:2e %d " % (i << 12, (i + 1) << 12, i)).ljust(
        114, b"x"
    )
    + b"\n"
    for i in range(93)
)


def module(name):
    result = types.ModuleType(name)
    result.__loader__ = importlib.machinery.SourceFileLoader(
        name, "/opt/irlume/" + name + ".py"
    )
    result.__spec__ = importlib.machinery.ModuleSpec(
        name, result.__loader__, origin=result.__loader__.path
    )
    return result


def root_stat(info=None):
    real = os.stat
    result = info or types.SimpleNamespace(st_dev=1, st_ino=2)

    def observe(path, *args, **kwargs):
        return result if path == "/" else real(path, *args, **kwargs)

    return observe


class ModuleIdentityTests(unittest.TestCase):
    def test_reassigned_reference_is_detected_when_both_targets_stay_reachable(self):
        main, first, second = module("main"), module("first"), module("second")
        main.a, main.b, main.c = first, first, second
        table = {"main": main}
        before = startup.module_snapshot((main,), table, lambda: None)
        main.b = second
        after = startup.module_snapshot((main,), table, lambda: None)
        self.assertFalse(startup.same_modules(before, after))

    def test_registry_preserves_strong_identity_beyond_equal_metadata(self):
        main, child = module("main"), module("child")
        main.child = child
        table = {"main": main}
        first = startup.module_snapshot((main,), table, lambda: None)
        self.assertTrue(
            startup.same_modules(
                first, startup.module_snapshot((main,), table, lambda: None)
            )
        )
        main.child = module("child")
        self.assertFalse(
            startup.same_modules(
                first, startup.module_snapshot((main,), table, lambda: None)
            )
        )
        main.child = child
        child.__spec__ = importlib.machinery.ModuleSpec(
            "child", child.__loader__, origin=child.__loader__.path
        )
        self.assertFalse(
            startup.same_modules(
                first, startup.module_snapshot((main,), table, lambda: None)
            )
        )

    def test_global_table_replacement_and_loader_replacement_are_detected(self):
        main = module("main")
        table = {"main": main}
        first = startup.module_snapshot((main,), table, lambda: None)
        self.assertFalse(
            startup.same_modules(
                first, startup.module_snapshot((main,), dict(table), lambda: None)
            )
        )
        main.__loader__ = importlib.machinery.SourceFileLoader(
            "main", main.__loader__.path
        )
        main.__spec__.loader = main.__loader__
        self.assertFalse(
            startup.same_modules(
                first, startup.module_snapshot((main,), table, lambda: None)
            )
        )

    def test_local_module_and_loader_caps_fail_closed(self):
        main = module("main")
        for index in range(17):
            local = module(f"local_{index}")
            local.SourceLoader = type(
                f"Loader{index}", (importlib.machinery.SourceFileLoader,), {}
            )
            setattr(main, f"local_{index}", local)
        with self.assertRaises(ValueError):
            startup.module_snapshot((main,), {"main": main}, lambda: None)

    def test_module_reference_edges_have_their_own_bound(self):
        main, left, right, target = (
            module(name) for name in ("main", "left", "right", "target")
        )
        main.left, main.right = left, right
        for index in range(2100):
            setattr(left, f"edge_{index}", target)
            setattr(right, f"edge_{index}", target)
        with self.assertRaises(ValueError):
            startup.module_snapshot(
                (main,), {"main": main, "target": target}, lambda: None
            )

    def test_registry_does_not_invoke_module_getattr(self):
        main = module("main")
        main.__getattr__ = lambda name: self.fail("module getter invoked")
        value = startup.module_snapshot((main,), {"main": main}, lambda: None)
        self.assertEqual(value.locals, ())


class CompositionTests(unittest.TestCase):
    def setUp(self):
        patcher = mock.patch.object(startup.os, "stat", side_effect=root_stat())
        patcher.start()
        self.addCleanup(patcher.stop)

    def setup_dependencies(self, fail=None):
        self.events = []
        self.deadlines = []
        self.plan_observations = []
        self.runtime_args = []
        directory = tempfile.TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        self.tree_file = Path(directory.name) / "runtime.py"
        self.tree_file.write_bytes(b"original\n")
        clock = [100]
        events = self.events
        self.initial = {
            "proc": {"fds": (0, 1, 2), "stdio": (), "namespaces": {}},
            "started_ns": 10,
            "finished_ns": 20,
            "status_after": b"status",
        }
        self.final = {**self.initial, "status_after": b"status", "finished_ns": 40}
        if fail == "final-status":
            self.final["status_after"] = b"bad"
        test = self

        class Reader:
            deadline = 500
            started = 10

            def __init__(self, deadline):
                self.deadline = min(deadline, 500)

            def _after(self):
                if clock[0] >= self.deadline:
                    raise TimeoutError("injected deadline expiry")
                return clock[0]

            def collect(self, plan):
                events.append("filesystem-initial")
                return test.initial

            def reobserve(self):
                events.append("filesystem-final")
                if fail == "filesystem-final":
                    raise ValueError("injected final filesystem failure")
                return test.final

            @contextlib.contextmanager
            def _open(self, *args, **kwargs):
                yield 9

            def _read(self, fd, name, limit):
                if fail == "status" and name == "status":
                    return b"bad"
                return b"status" if name == "status" else b"maps"

            def _namespaces(self, fd):
                return {"bad": 1} if fail == "namespaces" else {}

            def _inventory(self):
                return (0, 1, 2)

            def _stdio(self):
                return ()

            def _call(self, fn, *args, **kwargs):
                return fn(*args, **kwargs)

        class Tree:
            def __init__(self):
                self.manifest = {"selected": True}

            def __enter__(self):
                events.append("tree-open")
                return self

            def __exit__(self, *args):
                events.append("tree-close")
                if fail == "tree-close":
                    raise OSError("injected close failure")
                if fail == "expire-close":
                    clock[0] = 500

            def file_facts(self):
                events.append("tree-facts")
                return {"selected": True}

            def check(self):
                events.append("tree-check")
                if test.tree_file.read_bytes() != b"original\n":
                    raise ValueError("verified runtime file changed")

        preflight, tree, state, python = (
            module(name) for name in ("preflight", "tree", "state", "python")
        )
        preflight.filesystem = types.SimpleNamespace(
            FilesystemCollector=Reader,
            startup=types.SimpleNamespace(
                LIMITS={"status": 65536, "maps": 1024**2, "mountinfo": 1024**2}
            ),
        )

        def check_status(status, *args):
            events.append("status-check")
            if status == b"bad":
                raise ValueError("bad status")

        preflight.root = types.SimpleNamespace(
            check_status=check_status,
            check_plan=lambda value: None,
            parse_mountinfo=lambda data: {"view of": data},
        )

        def core_witness(plan, fs, deadline, now):
            test.deadlines.append(deadline)
            test.plan_observations.append(copy.deepcopy(plan))
            return {
                "namespaces": {},
                "root": {"device": 1, "inode": 2},
                "mountinfo": b"mountinfo %d" % len(test.plan_observations),
            }

        preflight.core_witness = core_witness

        def open_tree(*args, **kwargs):
            test.deadlines.append(kwargs["deadline"])
            return Tree()

        tree.RootedRuntimeSnapshot = types.SimpleNamespace(open=open_tree)

        def validate(*args):
            events.append("runtime-check")
            test.runtime_args.append(args)
            if fail == "runtime":
                raise ValueError("injected runtime failure")

        state.check_runtime_state = validate

        python_calls = [0]

        def collect_python(deadline, **kwargs):
            test.deadlines.append(deadline)
            python_calls[0] += 1
            return {"stable": not (fail == "python-metadata" and python_calls[0] == 2)}

        python.collect_python_state = collect_python
        return startup.Dependencies(preflight, tree, state, python)

    def test_pipeline_closes_tree_before_final_filesystem_and_returns_no_authority(
        self,
    ):
        deps = self.setup_dependencies()
        main = module("main")
        table = {"main": main}
        with mock.patch.object(startup.os, "stat", side_effect=root_stat()):
            result = startup.collect_startup(
                {"uid": 1000, "gid": 1000, "manifest": {"sha256": "a" * 64}},
                b"manifest",
                deps,
                (main,),
                1000,
                _module_table=lambda: table,
            )
        self.assertLess(
            self.events.index("tree-close"), self.events.index("filesystem-final")
        )
        self.assertIs(result["initial_filesystem"], self.initial)
        self.assertIs(result["filesystem"], self.final)
        self.assertNotIn("native_authorized", result)
        self.assertTrue(self.deadlines)
        self.assertEqual(set(self.deadlines), {500})

    def test_both_runtime_checks_use_the_first_core_mount_view(self):
        deps = self.setup_dependencies()
        main = module("main")
        table = {"main": main}
        with mock.patch.object(startup.os, "stat", side_effect=root_stat()):
            startup.collect_startup(
                {"uid": 1000, "gid": 1000, "manifest": {"sha256": "a" * 64}},
                b"manifest",
                deps,
                (main,),
                1000,
                _module_table=lambda: table,
            )
        # The mount table the first core witness checked; the final view
        # refuses any change to it.
        self.assertEqual(
            [args[4:] for args in self.runtime_args],
            [({"view of": b"mountinfo 1"},)] * 2,
        )

    def test_runtime_failure_closes_tree_without_final_filesystem_acceptance(self):
        deps = self.setup_dependencies(fail="runtime")
        main = module("main")
        table = {"main": main}
        with self.assertRaises(ValueError):
            startup.collect_startup(
                {"uid": 1000, "gid": 1000, "manifest": {"sha256": "a" * 64}},
                b"manifest",
                deps,
                (main,),
                1000,
                _module_table=lambda: table,
            )
        self.assertIn("tree-close", self.events)
        self.assertNotIn("filesystem-final", self.events)

    def test_final_filesystem_failure_cannot_produce_a_successful_result(self):
        deps = self.setup_dependencies(fail="filesystem-final")
        main = module("main")
        table = {"main": main}
        with self.assertRaises(ValueError):
            startup.collect_startup(
                {"uid": 1000, "gid": 1000, "manifest": {"sha256": "a" * 64}},
                b"manifest",
                deps,
                (main,),
                1000,
                _module_table=lambda: table,
            )
        self.assertIn("tree-close", self.events)

    def test_tree_close_failure_prevents_final_acceptance(self):
        deps = self.setup_dependencies(fail="tree-close")
        main = module("main")
        table = {"main": main}
        with self.assertRaises(OSError):
            startup.collect_startup(
                {"uid": 1000, "gid": 1000, "manifest": {"sha256": "a" * 64}},
                b"manifest",
                deps,
                (main,),
                1000,
                _module_table=lambda: table,
            )
        self.assertNotIn("filesystem-final", self.events)

    def test_same_metadata_local_module_replacement_between_phases_refuses(self):
        deps = self.setup_dependencies()
        main, child = module("main"), module("child")
        main.child = child
        table = {"main": main}

        def replace(*args):
            main.child = module("child")

        deps.runtime_state.check_runtime_state = replace
        with self.assertRaisesRegex(ValueError, "module identities"):
            startup.collect_startup(
                {"uid": 1000, "gid": 1000, "manifest": {"sha256": "a" * 64}},
                b"manifest",
                deps,
                (main,),
                1000,
                _module_table=lambda: table,
            )
        self.assertIn("tree-close", self.events)

    def test_same_metadata_loader_replacement_during_final_observation_refuses(self):
        deps = self.setup_dependencies()
        main, child = module("main"), module("child")
        main.child = child
        table = {"main": main}
        calls = [0]

        def replace(*args, **kwargs):
            calls[0] += 1
            if calls[0] == 2:
                child.__loader__ = importlib.machinery.SourceFileLoader(
                    "child", child.__loader__.path
                )
                child.__spec__.loader = child.__loader__
            return {"stable": True}

        deps.python_state.collect_python_state = replace
        with self.assertRaisesRegex(ValueError, "Python state"):
            startup.collect_startup(
                {"uid": 1000, "gid": 1000, "manifest": {"sha256": "a" * 64}},
                b"manifest",
                deps,
                (main,),
                1000,
                _module_table=lambda: table,
            )

    def test_final_root_and_descriptor_mismatch_refuse(self):
        for root_changed in (False, True):
            deps = self.setup_dependencies()
            if not root_changed:
                deps.preflight.filesystem.FilesystemCollector._stdio = lambda self: (
                    "changed",
                )
            main = module("main")
            table = {"main": main}
            info = types.SimpleNamespace(st_dev=1, st_ino=3 if root_changed else 2)
            with (
                mock.patch.object(startup.os, "stat", side_effect=root_stat(info)),
                self.subTest(root_changed=root_changed),
                self.assertRaises(ValueError),
            ):
                startup.collect_startup(
                    {"uid": 1000, "gid": 1000, "manifest": {"sha256": "a" * 64}},
                    b"manifest",
                    deps,
                    (main,),
                    1000,
                    _module_table=lambda table=table: table,
                )

    def test_second_python_observation_cannot_outlive_tree_integrity_check(self):
        deps = self.setup_dependencies()
        main = module("main")
        table = {"main": main}
        calls = [0]

        def mutate(*args, **kwargs):
            calls[0] += 1
            if calls[0] == 2:
                self.tree_file.write_bytes(b"changed\n")
            return {"stable": True}

        deps.python_state.collect_python_state = mutate
        with (
            mock.patch.object(
                startup.os,
                "stat",
                side_effect=root_stat(),
            ),
            self.assertRaises(ValueError),
        ):
            startup.collect_startup(
                {"uid": 1000, "gid": 1000, "manifest": {"sha256": "a" * 64}},
                b"manifest",
                deps,
                (main,),
                1000,
                _module_table=lambda: table,
            )

    def test_mutating_caller_selection_does_not_relabel_verified_evidence(self):
        deps = self.setup_dependencies()
        main = module("main")
        table = {"main": main}
        plan = {"uid": 1000, "gid": 1000, "manifest": {"sha256": "a" * 64}}

        def mutate(*args):
            plan["manifest"]["sha256"] = "b" * 64
            plan["uid"] = 99

        deps.runtime_state.check_runtime_state = mutate
        with mock.patch.object(startup.os, "stat", side_effect=root_stat()):
            result = startup.collect_startup(
                plan, b"manifest", deps, (main,), 1000, _module_table=lambda: table
            )
        self.assertEqual(result["runtime_manifest_sha256"], "a" * 64)
        self.assertEqual(
            [(row["uid"], row["manifest"]["sha256"]) for row in self.plan_observations],
            [(1000, "a" * 64)] * 2,
        )

    def test_expiry_after_tree_cleanup_cannot_return_a_result(self):
        deps = self.setup_dependencies(fail="expire-close")
        main = module("main")
        table = {"main": main}
        with self.assertRaises(TimeoutError):
            startup.collect_startup(
                {"uid": 1000, "gid": 1000, "manifest": {"sha256": "a" * 64}},
                b"manifest",
                deps,
                (main,),
                1000,
                _module_table=lambda: table,
            )
        self.assertIn("tree-close", self.events)

    def test_changed_python_metadata_status_or_namespaces_refuse(self):
        for failure in ("python-metadata", "status", "final-status", "namespaces"):
            deps = self.setup_dependencies(fail=failure)
            main = module("main")
            table = {"main": main}
            with (
                mock.patch.object(
                    startup.os,
                    "stat",
                    side_effect=root_stat(),
                ),
                self.subTest(failure=failure),
                self.assertRaises(ValueError),
            ):
                startup.collect_startup(
                    {"uid": 1000, "gid": 1000, "manifest": {"sha256": "a" * 64}},
                    b"manifest",
                    deps,
                    (main,),
                    1000,
                    _module_table=lambda table=table: table,
                )
            self.assertIn("tree-close", self.events)


class NativeBudgetTests(unittest.TestCase):
    """Run the real reader through collect_startup over G's native views.

    The root is what G observed on both hosts (V1 probe): a private /dev with
    its /dev/char links and /dev/core, every kernel view but smackfs under a
    cover, selinux only on the laptop, no /run/credentials. Each read of a
    /proc file returns whole lines up to one page, as a seq_file read does.
    The other startup dependencies are inert.
    """

    def view(self, selinux):
        directory = tempfile.TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        base = Path(directory.name)
        self.root, self.proc = base / "root", base / "proc"

        def path(absolute):
            return self.root / absolute.lstrip("/")

        for name in ("/dev/char", "/proc", "/run/irlume", "/run/host", "/tmp"):
            path(name).mkdir(parents=True)
        self.devices = {}
        for name, numbers in filesystem.DEVICES.items():
            path("/dev/" + name).touch()
            self.devices[path("/dev/" + name).stat().st_ino] = os.makedev(*numbers)
        for name, target in filesystem.DEV_LINKS.items():
            path("/dev/" + name).symlink_to(target)
        for number, name in filesystem.CHAR_LINKS.items():
            path("/dev/char/" + number).symlink_to("../" + name)
        covers = ["/dev/pts", "/dev/shm", "/dev/mqueue", "/dev/hugepages"]
        covers += root_tests.HOST_COVERS
        if selinux:
            covers.append("/sys/fs/selinux")
        for name in covers:
            path(name).parent.mkdir(parents=True, exist_ok=True)
            path(name).mkdir(mode=0)
        path("/dev/ptmx").touch(mode=0)
        stage = path(filesystem.root.OS_RELEASE_STAGE)
        stage.mkdir()
        (stage / "os-release").write_bytes(b"ID=fedora\n")
        path("/run/host/os-release").symlink_to(".os-release-stage/os-release")
        plan, _ = root_tests.selection()
        plan["uid"], plan["gid"] = os.getuid(), os.getgid()
        for key, name in (
            ("attempt", filesystem.root.ATTEMPT),
            ("base", "/run/irlume/base.raw"),
            ("payload", "/run/irlume/payload.raw"),
            ("manifest", "/run/irlume/runtime-manifest.json"),
        ):
            if key == "attempt":
                path(name).mkdir(mode=0o700)
            else:
                path(name).write_bytes(b"immutable\n")
                path(name).chmod(0o400)
            info = path(name).stat()
            plan[key]["device"], plan[key]["inode"] = info.st_dev, info.st_ino
        info = self.root.stat()
        plan["root"]["device"], plan["root"]["inode"] = info.st_dev, info.st_ino
        (self.proc / "ns").mkdir(parents=True)
        for name in filesystem.startup.NAMESPACES:
            (self.proc / "ns" / name).touch()
        return plan

    def observe(self, mountinfo, selinux):
        """Return the operations collect_startup spent on one native view."""
        plan = self.view(selinux)
        files = {
            "mountinfo": mountinfo,
            "maps": G_MAPS,
            "status": root_tests.witness(plan)["status"],
            "uid_map": b"      1000       1000          1\n",
            "gid_map": b"      1000       1000          1\n",
        }
        for name, data in files.items():
            (self.proc / name).write_bytes(data)
        real_open, real_stat, real_read = os.open, os.stat, os.read
        real_metadata, pid, pages = filesystem.metadata, os.getpid(), set()

        def open_view(path, flags, *args, **kwargs):
            path = {"/": self.root, f"/proc/{pid}": self.proc}.get(path, path)
            fd = real_open(path, flags, *args, **kwargs)
            if kwargs.get("dir_fd") is not None and path in files:
                pages.add(fd)
            else:
                pages.discard(fd)
            return fd

        def stat_view(path, *args, **kwargs):
            return real_stat(self.root if path == "/" else path, *args, **kwargs)

        def read_page(fd, size):
            data = real_read(fd, size)
            if fd not in pages:
                return data
            page = b""
            for line in data.splitlines(keepends=True):
                if page and len(page) + len(line) > 4096:
                    break
                page += line
            os.lseek(fd, len(page) - len(data), os.SEEK_CUR)
            return page

        def device_metadata(info):
            result = real_metadata(info)
            if info.st_ino in self.devices:
                result.update(mode=stat.S_IFCHR | 0o666, rdev=self.devices[info.st_ino])
            return result

        readers = []

        class Reader(filesystem.FilesystemCollector):
            def __init__(self, deadline):
                super().__init__(deadline)
                readers.append(self)

        @contextlib.contextmanager
        def runtime_tree(*args, **kwargs):
            yield types.SimpleNamespace(
                manifest={}, file_facts=dict, check=lambda: None
            )

        preflight, tree, state, python = (
            module(name) for name in ("preflight", "tree", "state", "python")
        )
        preflight.filesystem = types.SimpleNamespace(
            FilesystemCollector=Reader, startup=filesystem.startup
        )
        preflight.root = types.SimpleNamespace(
            check_plan=lambda plan: None,
            check_status=lambda *args: None,
            parse_mountinfo=filesystem.root.parse_mountinfo,
        )
        preflight.core_witness = lambda plan, snapshot, deadline, now: {
            key: snapshot["proc"][key] for key in ("namespaces", "root", "mountinfo")
        }
        tree.RootedRuntimeSnapshot = types.SimpleNamespace(open=runtime_tree)
        state.check_runtime_state = lambda *args: None
        python.collect_python_state = lambda deadline, **kwargs: {}
        main = module("main")
        table = {"main": main}
        with (
            mock.patch.object(os, "open", side_effect=open_view),
            mock.patch.object(os, "stat", side_effect=stat_view),
            mock.patch.object(os, "read", side_effect=read_page),
            mock.patch.object(filesystem, "metadata", side_effect=device_metadata),
        ):
            try:
                startup.collect_startup(
                    plan,
                    b"manifest",
                    startup.Dependencies(preflight, tree, state, python),
                    (main,),
                    time.monotonic_ns() + 5_000_000_000,
                    _module_table=lambda: table,
                )
            finally:
                self.assertEqual(len(readers), 1)
                self.assertEqual(readers[0].owned, {})
        return readers[0].operations

    def test_native_views_fit_the_operation_budget(self):
        for label, mountinfo, selinux, spent in (
            ("laptop", root_tests.R5_TRACING, True, 1104),
            ("archhost", root_tests.R5_ARCHHOST, False, 1096),
        ):
            with self.subTest(label=label):
                # The measured counts the budget comment cites; the cap stays
                # within half again the larger one.
                self.assertEqual(self.observe(mountinfo, selinux), spent)
                self.assertLess(spent, filesystem.startup.MAX_OPERATIONS)
                self.assertLessEqual(filesystem.startup.MAX_OPERATIONS, 1104 * 3 // 2)

    def test_operation_budget_is_a_hard_cap_at_the_native_count(self):
        budget = filesystem.startup
        with mock.patch.object(budget, "MAX_OPERATIONS", 1104):
            self.assertEqual(self.observe(root_tests.R5_TRACING, True), 1104)
        with (
            mock.patch.object(budget, "MAX_OPERATIONS", 1103),
            self.assertRaisesRegex(ValueError, "^startup observation operation cap$"),
        ):
            self.observe(root_tests.R5_TRACING, True)


if __name__ == "__main__":
    unittest.main()

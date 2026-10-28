#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright the irlume contributors.
"""Startup composition contracts; no service, namespace or VM is created."""

import contextlib
import importlib.machinery
import importlib.util
import os
import tempfile
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
        self.bus_observations = []
        directory = tempfile.TemporaryDirectory(dir="/tmp/opencode")
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

            def collect(self, plan, bus):
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
            identity=lambda value: None,
        )

        def core_witness(plan, bus, fs, deadline, now):
            test.deadlines.append(deadline)
            test.bus_observations.append(dict(bus))
            return {"namespaces": {}, "root": {"device": 1, "inode": 2}}

        preflight.core_witness = core_witness

        def open_tree(*args, **kwargs):
            test.deadlines.append(kwargs["deadline"])
            return Tree()

        tree.RootedRuntimeSnapshot = types.SimpleNamespace(open=open_tree)

        def validate(*args):
            events.append("runtime-check")
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
                {},
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

    def test_runtime_failure_closes_tree_without_final_filesystem_acceptance(self):
        deps = self.setup_dependencies(fail="runtime")
        main = module("main")
        table = {"main": main}
        with self.assertRaises(ValueError):
            startup.collect_startup(
                {"uid": 1000, "gid": 1000, "manifest": {"sha256": "a" * 64}},
                {},
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
                {},
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
                {},
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
                {},
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
                {},
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
                    {},
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
                {},
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
        bus = {"device": 1, "inode": 2}

        def mutate(*args):
            plan["manifest"]["sha256"] = "b" * 64
            bus["inode"] = 99

        deps.runtime_state.check_runtime_state = mutate
        with mock.patch.object(startup.os, "stat", side_effect=root_stat()):
            result = startup.collect_startup(
                plan, bus, b"manifest", deps, (main,), 1000, _module_table=lambda: table
            )
        self.assertEqual(result["runtime_manifest_sha256"], "a" * 64)
        self.assertEqual([row["inode"] for row in self.bus_observations], [2, 2])

    def test_expiry_after_tree_cleanup_cannot_return_a_result(self):
        deps = self.setup_dependencies(fail="expire-close")
        main = module("main")
        table = {"main": main}
        with self.assertRaises(TimeoutError):
            startup.collect_startup(
                {"uid": 1000, "gid": 1000, "manifest": {"sha256": "a" * 64}},
                {},
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
                    {},
                    b"manifest",
                    deps,
                    (main,),
                    1000,
                    _module_table=lambda table=table: table,
                )
            self.assertIn("tree-close", self.events)


if __name__ == "__main__":
    unittest.main()

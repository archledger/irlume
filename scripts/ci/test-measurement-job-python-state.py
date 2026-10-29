#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright the irlume contributors.
"""Synthetic interpreter metadata; no selected code or provider is executed."""

import importlib.machinery
import importlib.util
import json
import subprocess
import sys
import tempfile
import time
import types
import unittest
from pathlib import Path

HERE = Path(__file__).resolve().parent
SPEC = importlib.util.spec_from_file_location(
    "python_state", HERE / "measurement-job-python-state.py"
)
collector = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(collector)


def source_module(name, path, loader_type=importlib.machinery.SourceFileLoader):
    module = types.ModuleType(name)
    loader = loader_type(name, path)
    module.__loader__ = loader
    module.__file__ = path
    module.__cached__ = None
    module.__spec__ = importlib.machinery.ModuleSpec(name, loader, origin=path)
    return module


def interpreter():
    result = types.ModuleType("synthetic_sys")
    main = source_module("__main__", "/opt/irlume/entry.py")
    main.__spec__ = None
    builtin = types.ModuleType("sys")
    builtin.__loader__ = importlib.machinery.BuiltinImporter
    builtin.__spec__ = importlib.machinery.ModuleSpec(
        "sys", builtin.__loader__, origin="built-in"
    )
    result.modules = {"__main__": main, "sys": builtin}
    result.implementation = types.SimpleNamespace(name="cpython")
    result.version_info = (3, 14, 8, "final", 0)
    result.executable = "/usr/bin/python3"
    result.flags = types.SimpleNamespace(
        isolated=1,
        no_site=1,
        dont_write_bytecode=1,
        ignore_environment=1,
        safe_path=True,
    )
    result.pycache_prefix = "/dev/null"
    result.path = ["/usr/lib/python3.14"]
    result._jit = types.ModuleType("jit")
    result._jit.is_available = lambda: True
    result._jit.is_enabled = lambda: False
    return result


class PythonStateTests(unittest.TestCase):
    def test_real_isolated_interpreter_metadata_collection(self):
        code = f"""import importlib.util,json,time
s=importlib.util.spec_from_file_location("python_state",{str(HERE / "measurement-job-python-state.py")!r})
m=importlib.util.module_from_spec(s);s.loader.exec_module(m)
r=m.collect_python_state(time.monotonic_ns()+5000000000,local_modules=(("python_state",m),))
print(json.dumps({{"modules":len(r["modules"]),"flags":r["flags"],"jit_enabled":r["jit_enabled"]}}))
"""
        with tempfile.TemporaryDirectory() as directory:
            script = Path(directory) / "probe.py"
            script.write_text(code)
            result = subprocess.run(
                [
                    sys.executable,
                    "-I",
                    "-S",
                    "-B",
                    "-X",
                    "pycache_prefix=/dev/null",
                    str(script),
                ],
                env={"LC_ALL": "C", "PATH": "/usr/bin:/bin"},
                capture_output=True,
                timeout=10,
                check=False,
            )
        self.assertEqual(result.returncode, 0, result.stderr[:2048])
        row = json.loads(result.stdout)
        self.assertGreater(row["modules"], 10)
        self.assertIs(row["jit_enabled"], False)
        self.assertEqual(row["flags"]["isolated"], 1)

    def collect(self, sys=None, env=None, **kwargs):
        return collector.collect_python_state(
            time.monotonic_ns() + 5_000_000_000,
            _sys=sys or interpreter(),
            _environ={"LC_ALL": "C", "PATH": "/usr/bin:/bin"} if env is None else env,
            **kwargs,
        )

    def test_exact_metadata_and_specless_main_are_collected_without_hooks(self):
        sys = interpreter()
        sys.modules["sys"].__getattr__ = lambda name: self.fail("module hook invoked")
        row = self.collect(sys)
        self.assertEqual(row["version"], (3, 14, 8))
        self.assertEqual(row["modules"][0]["origin"], "/opt/irlume/entry.py")
        self.assertIs(row["jit_available"], True)
        self.assertIs(row["jit_enabled"], False)
        self.assertNotIn("accepted", row)

    def test_unknown_environment_keys_are_rejected_without_reading_values(self):
        class SecretEnvironment(dict):
            def __getitem__(self, key):
                raise AssertionError("environment value was read")

        with self.assertRaisesRegex(ValueError, "environment"):
            self.collect(
                env=SecretEnvironment(TOKEN="synthetic-private-value", PATH="/bin")
            )

    def test_wrong_loader_instance_metadata_and_unknown_subclass_refuse(self):
        sys = interpreter()
        sys.modules["__main__"].__loader__.path = "/wrong/path.py"
        with self.assertRaises(ValueError):
            self.collect(sys)

        class CustomLoader(importlib.machinery.SourceFileLoader):
            pass

        sys = interpreter()
        sys.modules["extra"] = source_module(
            "extra", "/opt/irlume/extra.py", CustomLoader
        )
        with self.assertRaises(ValueError):
            self.collect(sys)
        self.assertEqual(
            len(self.collect(sys, source_loader_types=(CustomLoader,))["modules"]), 3
        )

    def test_same_name_module_replacement_during_collection_refuses(self):
        sys = interpreter()

        def replace():
            sys.modules["sys"] = types.ModuleType("replacement")
            return False

        sys._jit.is_enabled = replace
        with self.assertRaises(ValueError):
            self.collect(sys)

    def test_loader_disagreement_and_incomplete_import_refuse(self):
        for incomplete in (False, True):
            sys = interpreter()
            module = source_module("extra", "/opt/irlume/extra.py")
            sys.modules["extra"] = module
            if incomplete:
                module.__spec__._initializing = True
            else:
                module.__loader__ = importlib.machinery.SourceFileLoader(
                    "extra", module.__file__
                )
            with self.subTest(incomplete=incomplete), self.assertRaises(ValueError):
                self.collect(sys)

    def test_jit_failure_nonboolean_and_late_result_refuse(self):
        for value in (None, 0, "false"):
            sys = interpreter()
            sys._jit.is_enabled = lambda value=value: value
            with self.subTest(value=value), self.assertRaises(ValueError):
                self.collect(sys)
        sys = interpreter()
        clock = [1]

        def late():
            clock[0] = 100
            return False

        sys._jit.is_enabled = late
        with self.assertRaises(TimeoutError):
            collector.collect_python_state(
                100,
                _sys=sys,
                _environ={"LC_ALL": "C", "PATH": "/usr/bin:/bin"},
                _clock=lambda: clock[0],
            )

    def test_metadata_objects_are_rejected_without_equality_hooks(self):
        class Trap:
            def __eq__(self, other):
                raise AssertionError("metadata equality hook invoked")

        sys = interpreter()
        module = source_module("package", "/opt/irlume/package/__init__.py")
        module.__spec__.submodule_search_locations = [Trap()]
        module.__path__ = [Trap()]
        sys.modules["package"] = module
        with self.assertRaises(ValueError):
            self.collect(sys)
        sys = interpreter()
        sys.modules["__main__"].__loader__.path = Trap()
        with self.assertRaises(ValueError):
            self.collect(sys)

    def test_invalid_registry_name_refuses(self):
        sys = interpreter()
        with self.assertRaises(ValueError):
            self.collect(sys, local_modules=(([], types.ModuleType("bad")),))

    def test_module_text_cap_applies_before_return(self):
        sys = interpreter()
        for index in range(300):
            module = source_module(f"extra_{index}", "/opt/irlume/extra.py")
            module.__cached__ = "/dev/null/" + "a" * 4080
            sys.modules[f"extra_{index}"] = module
        with self.assertRaises(ValueError):
            self.collect(sys)

    def test_environment_values_are_checked_before_return(self):
        for env in (
            {"LC_ALL": "en_US.UTF-8", "PATH": "/usr/bin:/bin"},
            {"LC_ALL": "C", "PATH": "/tmp"},
        ):
            with self.subTest(env=env), self.assertRaises(ValueError):
                self.collect(env=env)

    def test_registry_caps_and_invalid_loader_classes_refuse(self):
        sys = interpreter()
        for index in range(4096):
            sys.modules[f"builtin_{index}"] = sys.modules["sys"]
        with self.assertRaises(ValueError):
            self.collect(sys)
        sys = interpreter()
        with self.assertRaises(ValueError):
            self.collect(sys, source_loader_types=(str,))
        local = tuple((f"local_{index}", sys.modules["sys"]) for index in range(129))
        with self.assertRaises(ValueError):
            self.collect(sys, local_modules=local)

    def test_module_spec_type_and_plain_package_path_agreement_are_checked(self):
        class OtherSpec(importlib.machinery.ModuleSpec):
            pass

        sys = interpreter()
        module = source_module("extra", "/opt/irlume/extra.py")
        module.__spec__ = OtherSpec("extra", module.__loader__, origin=module.__file__)
        sys.modules["extra"] = module
        with self.assertRaises(ValueError):
            self.collect(sys)
        module.__spec__ = importlib.machinery.ModuleSpec(
            "extra", module.__loader__, origin=module.__file__
        )
        module.__spec__.submodule_search_locations = ["/opt/irlume/good"]
        module.__path__ = ["/opt/irlume/bad"]
        with self.assertRaises(ValueError):
            self.collect(sys)

    def test_unregistered_loader_metaclass_equality_is_never_invoked(self):
        for spoof in (False, True):
            calls = []

            class LoaderMeta(type):
                def __eq__(cls, other, calls=calls, spoof=spoof):
                    calls.append(other)
                    if spoof:
                        return True
                    raise AssertionError("metaclass equality invoked")

            class UnknownLoader(metaclass=LoaderMeta):
                def __init__(self):
                    self.name = "__main__"
                    self.path = "/opt/irlume/entry.py"

            sys = interpreter()
            sys.modules["__main__"].__loader__ = UnknownLoader()
            with self.subTest(spoof=spoof):
                with self.assertRaises(ValueError):
                    self.collect(sys)
                self.assertEqual(calls, [])

    def test_sys_path_is_bounded_before_iteration(self):
        class Paths:
            def __iter__(self):
                raise AssertionError("custom sys.path iterator invoked")

        for paths in (Paths(), ["/a"] * 5, ["/" + "a" * 4096], [object()]):
            sys = interpreter()
            sys.path = paths
            with (
                self.subTest(paths_type=type(paths).__name__),
                self.assertRaises(ValueError),
            ):
                self.collect(sys)

    def test_opaque_interpreter_metadata_is_not_invoked(self):
        class Opaque:
            def __iter__(self):
                raise AssertionError("metadata iterator invoked")

            def __getattr__(self, name):
                raise AssertionError("metadata getter invoked")

        for field in ("version_info", "flags", "implementation"):
            sys = interpreter()
            setattr(sys, field, Opaque())
            with self.subTest(field=field), self.assertRaises(ValueError):
                self.collect(sys)


if __name__ == "__main__":
    unittest.main()

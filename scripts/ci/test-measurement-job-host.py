#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright the irlume contributors.
"""H's startup self-check: synthetic facts, then runs through the tree loader.

HostRuntimeTests copy a prepared runtime (IRLUME_HOST_RUNTIME: root/ and
inputs/manifest.json) into a private throwaway tree with the current sources
and a launcher built from them. Without it they refuse; no host fallback.
"""

import copy
import errno
import fcntl
import hashlib
import importlib
import importlib.util
import json
import mmap
import os
import py_compile
import re
import shutil
import stat
import subprocess
import sys
import tempfile
import time
import types
import unittest
from builtins import BaseExceptionGroup
from pathlib import Path
from unittest import mock

HERE = Path(__file__).resolve().parent


def load(name, filename):
    spec = importlib.util.spec_from_file_location(name, HERE / filename)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


host = load("host_entry", "measurement-job-host.py")
state = load("host_runtime_state", "measurement-job-runtime-state.py")
root = load("host_root", "measurement-job-root.py")
witness = load("host_witness", "measurement-job-startup-witness.py")
state_tests = load("host_state_fixtures", "test-measurement-job-runtime-state.py")
owner = load("host_owner", "measurement-job-rooted-host.py")
inputs_module = load("host_inputs", "measurement-job-rooted-host-inputs.py")
startup_check = load("host_startup_check", "measurement-job-startup-check.py")
proc = load("host_proc", "measurement-job-startup.py")
closure = root.closure
DEPS = host.Dependencies(state, root, witness)
ENVIRONMENT = {"LC_ALL": "C", "PATH": "/usr/bin:/bin"}
FLAGS = ["-I", "-S", "-B", "-X", "pycache_prefix=/dev/null"]
LOADER = "lib64/ld-linux-x86-64.so.2"
TREE = "/home/u/.cache/run/root"
REQUEST = "/home/u/.cache/run/attempt/host-request.json"
MANIFEST = "/home/u/.cache/run/inputs/manifest.json"
MOUNTINFO = b"2 1 0:1 / / rw - ext4 /dev/root rw\n"
STATUS = (
    b"Name:\tld-linux-x86-64\nPid:\t4242\nPPid:\t4000\n"
    b"Uid:\t1000\t1000\t1000\t1000\nGid:\t1000\t1000\t1000\t1000\nThreads:\t1\n"
    b"CapInh:\t0000000000000000\nCapPrm:\t0000000000000000\n"
    b"CapEff:\t0000000000000000\nCapBnd:\t000001ffffffffff\n"
    b"CapAmb:\t0000000000000000\n"
)
STDIO = tuple((fd, (1, 3 + fd, stat.S_IFCHR | 0o620, 0x8801), 2) for fd in range(3))


def deadline():
    return time.monotonic_ns() + 60_000_000_000


def sha(data):
    return hashlib.sha256(data).hexdigest()


def synthetic_manifest():
    """A selected runtime with H's entry, launcher, loader, jeepney and sources."""
    image = state_tests.fixtures.fixtures.image
    files = {
        "usr/bin/python3": image(interpreter=closure.elf.INTERPRETER),
        "opt/irlume/launcher": image(dynamic=False, kind=2),
        LOADER: image(),
        "usr/lib64/python3.14/os.py": b"# os\n",
        "opt/irlume/vendor/jeepney/__init__.py": b"__version__ = '0.9.0'\n",
        host.ENTRY: b"# host entry\n",
    }
    for name in host.SOURCES:
        files["opt/irlume/" + name] = b"# " + name.encode() + b"\n"
    value = state_tests.fixtures.profile()
    value["python"]["entry"] = "opt/irlume/measurement-job-guardian-native.py"
    # The selected runtime's order: stdlib, lib-dynload, vendor.
    value["python"]["roots"] = [
        "usr/lib64/python3.14",
        "usr/lib64/python3.14/lib-dynload",
        "opt/irlume/vendor",
    ]
    value["bootstrap"] = "opt/irlume/launcher"
    folders = {
        str(parent)
        for path in files
        for parent in Path(path).parents
        if str(parent) != "."
    }
    folders.add("usr/lib64/python3.14/lib-dynload")
    members = [{"path": d, "kind": "directory", "mode": 0o500} for d in folders]
    members += [
        {
            "path": name,
            "kind": "file",
            "mode": 0o500 if data.startswith(b"\x7fELF") else 0o400,
            "size": len(data),
            "sha256": sha(data),
        }
        for name, data in files.items()
    ]
    value["members"] = sorted(members, key=lambda row: row["path"])
    data = closure.canonical(value)
    return value, data, sha(data)


def request_bytes(tree=TREE, manifest_sha256=None, **changes):
    value = {
        "scope": host.REQUEST_SCOPE,
        "mode": "self-check",
        "runtime": tree,
        "manifest": MANIFEST,
        "manifest_sha256": manifest_sha256 or synthetic_manifest()[2],
    }
    value.update(changes)
    return closure.canonical(value)


def specification(**changes):
    """An inert startup selection as a startup-only request names it."""
    value = {
        "run_id": "run-01",
        "boot_input_sha256": "a" * 64,
        "build_sha256": "b" * 64,
        "input_manifest_sha256": "c" * 64,
        "mode": "boot-only",
        "cases": ["supervisor-only"],
        "first_epoch": 1,
        "qemu": "/usr/bin/qemu-system-x86_64",
        "base": "/home/u/.cache/run/inputs/base",
        "payload": "/home/u/.cache/run/inputs/payload",
        "overlay": "/home/u/.local/state/irlume-job-runner/attempt-run-01/overlay.qcow2",
        "cpus": [0, 1],
    }
    value.update(changes)
    return value


def startup_request(tree=TREE, manifest_sha256=None, **changes):
    value = {
        "scope": host.REQUEST_SCOPE,
        "mode": "startup-only",
        "runtime": tree,
        "manifest": MANIFEST,
        "manifest_sha256": manifest_sha256 or synthetic_manifest()[2],
        "specification": specification(),
        "base_sha256": "d" * 64,
        "payload_sha256": "e" * 64,
    }
    value.update(changes)
    return closure.canonical(value)


def resolve_request(tree=TREE, manifest_sha256=None, **changes):
    value = {
        "scope": host.REQUEST_SCOPE,
        "mode": "resolve-failed-startup",
        "runtime": tree,
        "manifest": MANIFEST,
        "manifest_sha256": manifest_sha256 or synthetic_manifest()[2],
        "run_id": "run-01",
        "commit": False,
    }
    value.update(changes)
    return closure.canonical(value)


def synthetic():
    """A valid observation of H as the launcher starts it, and its checker's pages."""
    manifest, data, digest = synthetic_manifest()
    files = {
        TREE + "/" + row["path"]: {
            "device": os.makedev(0, 1),
            "inode": 100 + number,
            "mode": stat.S_IFREG | row["mode"],
            "size": row["size"],
            "sha256": row["sha256"],
        }
        for number, row in enumerate(manifest["members"])
        if row["kind"] == "file"
    }
    jeepney = TREE + "/opt/irlume/vendor/jeepney"
    python = {
        "implementation": "cpython",
        "version": (3, 14, 8),
        "executable": TREE + "/usr/bin/python3",
        "flags": {
            "isolated": 1,
            "no_site": 1,
            "dont_write_bytecode": 1,
            "ignore_environment": 1,
            "safe_path": True,
        },
        "pycache_prefix": "/dev/null",
        "environment": dict(ENVIRONMENT),
        "sys_path": tuple(TREE + "/" + path for path in manifest["python"]["roots"]),
        "jit_available": False,
        "jit_enabled": False,
        "modules": (
            {
                "name": "__main__",
                "kind": "source",
                "origin": TREE + "/" + host.ENTRY,
                "package_paths": (),
                "cached": None,
            },
            {
                "name": "jeepney",
                "kind": "source",
                "origin": jeepney + "/__init__.py",
                "package_paths": (jeepney,),
                "cached": "/dev/null" + jeepney + "/__init__.cpython-314.pyc",
            },
            {
                "name": "sys",
                "kind": "builtin",
                "origin": "built-in",
                "package_paths": (),
                "cached": None,
            },
        ),
    }
    maps = b""
    for number, path in enumerate(("usr/bin/python3", LOADER), start=1):
        maps += (
            f"{number * 4096:016x}-{(number + 1) * 4096:016x} r-xp 00000000 00:01 "
            f"{files[TREE + '/' + path]['inode']} {TREE}/{path}\n"
        ).encode()
    maps += b"0000000000004000-0000000000005000 rw-p 00000000 00:00 0 [heap]\n"
    maps += b"0000000000006000-0000000000008000 r-xp 00000000 00:00 0 [vdso]\n"
    pages = state_tests.page_digests(files)
    request = request_bytes(manifest_sha256=digest)
    entry = TREE + "/" + host.ENTRY
    loader = files[TREE + "/" + LOADER]
    observation = {
        "pid": 4242,
        "uid": 1000,
        "gid": 1000,
        "orig_argv": (
            TREE + "/usr/bin/python3",
            *FLAGS,
            entry,
            "--request",
            REQUEST,
            sha(request),
        ),
        "argv": (entry, "--request", REQUEST, sha(request)),
        "file": entry,
        "prefixes": (TREE + "/usr",) * 4,
        "initial_path": (
            TREE + "/usr/lib64/python314.zip",
            TREE + "/usr/lib64/python3.14",
            TREE + "/usr/lib64/python3.14/lib-dynload",
        ),
        "environment": dict(ENVIRONMENT),
        "exe": {
            "path": TREE + "/" + LOADER,
            "device": loader["device"],
            "inode": loader["inode"],
        },
        "preload": False,
        "descriptors": {"initial": (0, 1, 2), "final": (0, 1, 2)},
        "stdio": {"initial": STDIO, "final": STDIO},
        "request_data": request,
        "hooks": {"excepthook": True, "meta_path": True, "path_hooks": True},
        "jeepney": {"version": "0.9.0", "origin": jeepney + "/__init__.py"},
        "sources": tuple(
            sorted(
                (
                    TREE + "/opt/irlume/" + name,
                    files[TREE + "/opt/irlume/" + name]["sha256"],
                )
                for name in host.SOURCES
            )
        ),
        "mountinfo": MOUNTINFO,
        "namespaces": {
            "pid": 1,
            "user": 2,
            "mnt": 3,
            "net": 4,
            "cgroup": 5,
        },
        "status": STATUS,
        "files": files,
        "python": python,
        "maps": maps,
        "mapped": state_tests.mapped_rows(maps, pages),
        "started_ns": 1,
        "finished_ns": 2,
    }
    return observation, data, digest, pages


def accepted(test, function, *args, **keywords):
    """A refusal of valid facts is an assertion failure, not an error."""
    try:
        return function(*args, **keywords)
    except ValueError as error:
        test.fail(f"refused: {error}")


def validate(observation, data=None, digest=None, pages=None, tree=TREE):
    _, default_data, default_digest, default_pages = synthetic()
    return host.validate(
        observation,
        tree,
        default_data if data is None else data,
        default_digest if digest is None else digest,
        default_pages if pages is None else pages,
        DEPS,
    )


class HostRootTests(unittest.TestCase):
    def test_tree_root_is_the_tree_python_without_usr_bin_python3(self):
        self.assertEqual(
            accepted(self, host.tree_root, TREE + "/usr/bin/python3"), TREE
        )
        for executable in (
            "/usr/bin/python3",
            "usr/bin/python3",
            TREE + "/usr/bin/python3.14",
            TREE + "/usr/local/bin/python3",
            TREE + "//usr/bin/python3",
            "/home/u/../root/usr/bin/python3",
            "/home/./root/usr/bin/python3",
            "//root/usr/bin/python3",
            "/root\n/usr/bin/python3",
            "/ré/usr/bin/python3",
            None,
        ):
            with (
                self.subTest(executable=executable),
                self.assertRaisesRegex(ValueError, "^host runtime root$"),
            ):
                host.tree_root(executable)


class HostRequestTests(unittest.TestCase):
    def test_request_is_canonical_exact_and_bound_to_the_tree_and_digest(self):
        data = request_bytes()
        value = accepted(self, host.decode_request, data, sha(data), TREE, root)
        self.assertEqual(value["runtime"], TREE)
        self.assertEqual(value["manifest"], MANIFEST)

    def test_request_refusals(self):
        data = request_bytes()
        cases = [
            (data, "0" * 64, "host request digest"),
            (data, sha(data).upper(), "host request digest"),
            (
                request_bytes(scope="contained-job-host-request-v2"),
                None,
                "host request scope or mode",
            ),
            # A startup-only request without its selection.
            (request_bytes(mode="startup-only"), None, "invalid fields"),
            (request_bytes(mode="other"), None, "host request scope or mode"),
            (request_bytes(mode=["self-check"]), None, "host request scope or mode"),
            (
                request_bytes(tree="/home/u/.cache/other/root"),
                None,
                "host request runtime",
            ),
            (request_bytes(tree=TREE + "x"), None, "host request runtime"),
            (request_bytes(tree=TREE + "/"), None, "host request runtime"),
            (
                request_bytes(manifest="relative/manifest.json"),
                None,
                "host request manifest",
            ),
            (
                request_bytes(manifest="/a/../manifest.json"),
                None,
                "host request manifest",
            ),
            (request_bytes(manifest_sha256="A" * 64), None, "host request manifest"),
            (request_bytes(manifest_sha256=1), None, "host request manifest"),
            (request_bytes(extra=1), None, "invalid fields"),
            (data.replace(b",", b", ", 1), None, "host request encoding"),
            (b"", None, "host request size"),
            (b" " * (host.REQUEST_LIMIT + 1), None, "host request size"),
        ]
        for data_, digest, reason in cases:
            with (
                self.subTest(reason=reason, data=data_[:80]),
                self.assertRaisesRegex(ValueError, "^" + reason + "$"),
            ):
                host.decode_request(data_, digest or sha(data_), TREE, root)

    def test_startup_only_request_names_one_inert_selection(self):
        data = startup_request()
        value = accepted(self, host.decode_request, data, sha(data), TREE, root)
        self.assertEqual(value["mode"], "startup-only")
        spec = accepted(self, host.specification, value, root)
        self.assertEqual(
            spec,
            root.guardian.Specification(
                **dict(specification(), cases=("supervisor-only",), cpus=(0, 1))
            ),
        )
        cases = [
            (startup_request(specification=None), "host request specification"),
            (
                startup_request(specification=specification(extra=1)),
                "host request specification",
            ),
            (
                startup_request(
                    specification={**specification(), "cases": "supervisor-only"}
                ),
                "host request specification",
            ),
            (
                startup_request(
                    specification={
                        **specification(),
                        "cases": {"supervisor-only": 0},
                    }
                ),
                "host request specification",
            ),
            (
                startup_request(
                    specification=specification(
                        mode="runtime-candidate", cases=["normal"]
                    )
                ),
                "host request specification",
            ),
            (
                startup_request(
                    specification=specification(cases=["supervisor-only", "normal"])
                ),
                "host request specification",
            ),
            (
                startup_request(
                    specification=specification(
                        qemu="/usr/local/bin/qemu-system-x86_64"
                    )
                ),
                "host request specification",
            ),
            (
                startup_request(specification=specification(base="inputs/base")),
                "host request specification",
            ),
            (
                startup_request(specification=specification(cpus=[0, 0])),
                "host request specification",
            ),
            (
                startup_request(specification=specification(cpus=[[0], 1])),
                "host request specification",
            ),
            (
                startup_request(specification=specification(run_id="Run 01")),
                "host request specification",
            ),
            (startup_request(base_sha256="D" * 64), "host request input digest"),
            (startup_request(payload_sha256=1), "host request input digest"),
            (startup_request(extra=1), "invalid fields"),
            (startup_request(tree=TREE + "x"), "host request runtime"),
        ]
        for data_, reason in cases:
            with (
                self.subTest(reason=reason, data=data_[-120:]),
                self.assertRaisesRegex(ValueError, "^" + reason + "$"),
            ):
                host.decode_request(data_, sha(data_), TREE, root)

    def test_resolution_request_names_one_run_and_a_commit_flag(self):
        # The owner's witness check repeats the entry's field set.
        self.assertEqual(
            owner.RESOLVER_REQUEST_FIELDS,
            set(host.REQUEST_FIELDS["resolve-failed-startup"]),
        )
        for commit in (False, True):
            data = resolve_request(commit=commit)
            value = accepted(self, host.decode_request, data, sha(data), TREE, root)
            self.assertEqual(
                (value["mode"], value["run_id"]),
                ("resolve-failed-startup", "run-01"),
            )
            self.assertIs(value["commit"], commit)
        full = json.loads(resolve_request())

        def without(name):
            return closure.canonical({k: v for k, v in full.items() if k != name})

        cases = [
            (resolve_request(invocation_id="d" * 32), "invalid fields"),
            (resolve_request(gate="/home/u/.cache/gate"), "invalid fields"),
            (without("commit"), "invalid fields"),
            (without("run_id"), "invalid fields"),
            (without("manifest"), "invalid fields"),
            (resolve_request(commit=1), "host request commit flag"),
            (resolve_request(commit=0), "host request commit flag"),
            (resolve_request(commit="true"), "host request commit flag"),
            (resolve_request(commit=None), "host request commit flag"),
            (resolve_request(run_id=""), "host request run ID"),
            (resolve_request(run_id="Run-01"), "host request run ID"),
            (resolve_request(run_id="-run"), "host request run ID"),
            (resolve_request(run_id="r" * 65), "host request run ID"),
            (resolve_request(run_id="run/01"), "host request run ID"),
            (resolve_request(run_id=1), "host request run ID"),
            (resolve_request(run_id=None), "host request run ID"),
            (resolve_request(tree=TREE + "x"), "host request runtime"),
            (resolve_request(manifest_sha256="A" * 64), "host request manifest"),
            (
                resolve_request().replace(b",", b", ", 1),
                "host request encoding",
            ),
        ]
        for data, reason in cases:
            with (
                self.subTest(reason=reason, data=data[-90:]),
                self.assertRaisesRegex(ValueError, "^" + reason + "$"),
            ):
                host.decode_request(data, sha(data), TREE, root)
        # The longest run ID the resolver takes.
        data = resolve_request(run_id="r" * 64)
        accepted(self, host.decode_request, data, sha(data), TREE, root)

    def test_request_and_witness_formats_are_the_ones_h_binds(self):
        self.assertEqual(host.REQUEST_SCOPE, owner.HOST_REQUEST_SCOPE)
        self.assertEqual(host.SCOPE, owner.HOST_WITNESS_SCOPE)
        self.assertEqual(host.WITNESS_LIMIT, owner.HOST_WITNESS_LIMIT)
        value = json.loads(startup_request())
        spec = root.guardian.Specification(
            **dict(value["specification"], cases=("supervisor-only",), cpus=(0, 1))
        )
        selection = inputs_module.Selection(
            spec,
            value["runtime"],
            value["manifest"],
            value["manifest_sha256"],
            value["base_sha256"],
            value["payload_sha256"],
        )
        self.assertEqual(
            closure.canonical(owner.host_request(selection)), startup_request()
        )

    def test_private_read_is_bounded_no_follow_and_owner_only(self):
        inputs = closure.inputs
        with tempfile.TemporaryDirectory() as directory:
            folder = Path(directory).resolve()
            path = folder / "host-request.json"
            path.write_bytes(b"{}")
            path.chmod(0o400)
            self.assertEqual(host.read_private(inputs, str(path), 2, deadline()), b"{}")
            with self.assertRaisesRegex(ValueError, "^host input mode, owner or size$"):
                host.read_private(inputs, str(path), 1, deadline())
            path.chmod(0o600)
            with self.assertRaisesRegex(ValueError, "^host input mode, owner or size$"):
                host.read_private(inputs, str(path), 2, deadline())
            path.chmod(0o400)
            link = folder / "link.json"
            link.symlink_to(path.name)
            with self.assertRaises(OSError):
                host.read_private(inputs, str(link), 2, deadline())
            other = folder / "linked.json"
            os.link(path, other)
            with self.assertRaisesRegex(ValueError, "^host input mode, owner or size$"):
                host.read_private(inputs, str(path), 2, deadline())
            other.unlink()
            folder.chmod(0o770)
            try:
                with self.assertRaises(ValueError):
                    host.read_private(inputs, str(path), 2, deadline())
            finally:
                folder.chmod(0o700)
            with self.assertRaises(ValueError):
                host.read_private(inputs, "relative/host-request.json", 2, deadline())


class HostLoaderTests(unittest.TestCase):
    def test_native_is_compiled_from_the_digested_bytes_not_a_stale_cache(self):
        probe = """import importlib.machinery,importlib.util,sys
mode,tree,entry=sys.argv[1:4]
if mode=="control":
    path=tree+"/opt/irlume/measurement-job-guardian-native.py"
    loader=importlib.machinery.SourceFileLoader("stale_control",path)
    spec=importlib.util.spec_from_loader("stale_control",loader)
    loader.exec_module(importlib.util.module_from_spec(spec))
else:
    spec=importlib.util.spec_from_file_location("host_probe",entry)
    host=importlib.util.module_from_spec(spec)
    spec.loader.exec_module(host)
    print(host.load_native(tree).__source_sha256__)
"""
        with tempfile.TemporaryDirectory() as directory:
            tree = Path(directory).resolve()
            folder = tree / "opt/irlume"
            folder.mkdir(parents=True)
            for path in HERE.glob("measurement-job*.py"):
                shutil.copyfile(path, folder / path.name)
            target = folder / "measurement-job-guardian-native.py"
            original = target.read_bytes()
            poison = b'raise RuntimeError("stale native bytecode executed")\n'
            target.write_bytes(poison + b"#" * (len(original) - len(poison)))
            stamp = target.stat().st_mtime_ns
            cache = f"{target.stem}.{sys.implementation.cache_tag}.pyc"
            py_compile.compile(
                str(target), cfile=str(folder / "__pycache__" / cache), doraise=True
            )
            target.write_bytes(original)
            os.utime(target, ns=(stamp, stamp))
            results = {}
            for mode in ("control", "host"):
                results[mode] = subprocess.run(
                    [
                        sys.executable,
                        "-I",
                        "-B",
                        "-c",
                        probe,
                        mode,
                        str(tree),
                        str(HERE / "measurement-job-host.py"),
                    ],
                    capture_output=True,
                    text=True,
                    timeout=30,
                    check=False,
                )
        # The poison is live for a cache-reading load, so the entry's load
        # proves it compiled the bytes it digested.
        self.assertNotEqual(results["control"].returncode, 0)
        self.assertIn("stale native bytecode executed", results["control"].stderr)
        self.assertEqual(results["host"].returncode, 0, results["host"].stderr)
        self.assertEqual(results["host"].stdout.strip(), sha(original))

    def test_preload_file_presence_is_observed_without_following_it(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "ld.so.preload"
            self.assertIs(host.preload_present(str(path)), False)
            path.symlink_to("missing")
            self.assertIs(host.preload_present(str(path)), True)
            path.unlink()
            path.write_bytes(b"")
            self.assertIs(host.preload_present(str(path)), True)


HOOKS = """import importlib.util,json,sys
case,entry=sys.argv[1:3]
spec=importlib.util.spec_from_file_location("host_probe",entry)
host=importlib.util.module_from_spec(spec)
spec.loader.exec_module(host)
class Finder:
    @classmethod
    def find_spec(cls,*args):
        return None
def hook(path):
    raise ImportError(path)
if case=="extra-finder":
    sys.meta_path.append(Finder)
elif case=="replaced-finder":
    sys.meta_path[2]=Finder
elif case=="excepthook":
    sys.excepthook=lambda *args:None
elif case=="replaced-path-hook":
    sys.path_hooks[1]=hook
elif case=="extra-path-hook":
    sys.path_hooks.insert(0,hook)
print(json.dumps(host.import_hooks(),sort_keys=True))
"""


class HostHookTests(unittest.TestCase):
    def test_collector_reports_each_changed_import_hook(self):
        # A fresh interpreter with H's isolation flags, one change per case.
        keys = ("excepthook", "meta_path", "path_hooks")
        cases = (
            ("none", None),
            ("extra-finder", "meta_path"),
            ("replaced-finder", "meta_path"),
            ("excepthook", "excepthook"),
            ("replaced-path-hook", "path_hooks"),
            ("extra-path-hook", "path_hooks"),
        )
        for case, changed in cases:
            with self.subTest(case=case):
                result = subprocess.run(
                    [
                        sys.executable,
                        "-I",
                        "-S",
                        "-B",
                        "-c",
                        HOOKS,
                        case,
                        str(HERE / "measurement-job-host.py"),
                    ],
                    capture_output=True,
                    text=True,
                    timeout=30,
                    check=False,
                )
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertEqual(
                    json.loads(result.stdout), {key: key != changed for key in keys}
                )


class HostProcessCheckTests(unittest.TestCase):
    """The recheck HostOwner runs: the witness's module table and file mappings."""

    def baseline(self):
        roots = (host, state, root)
        reader = proc.ProcCollector(deadline())
        modules = startup_check.module_snapshot(roots, sys.modules, reader._after)
        with reader._open(f"/proc/{os.getpid()}", directory=True) as fd:
            maps = reader._read(fd, "maps", proc.LIMITS["maps"])
        return host.process_check(roots, modules, maps, startup_check, proc)

    def test_an_unchanged_process_passes_every_recheck(self):
        check = self.baseline()
        self.assertIs(type(check), types.FunctionType)
        for _ in range(3):
            accepted(self, check, deadline())

    def test_an_import_or_a_rebound_module_refuses(self):
        with mock.patch.dict(sys.modules):
            sys.modules.pop("colorsys", None)
            check = self.baseline()
            importlib.import_module("colorsys")
            with self.assertRaisesRegex(
                ValueError, "^host modules changed after the self-check$"
            ):
                check(deadline())
        check = self.baseline()
        with (
            mock.patch.object(host, "re", copy),
            self.assertRaisesRegex(
                ValueError, "^host modules changed after the self-check$"
            ),
        ):
            check(deadline())
        accepted(self, check, deadline())

    def test_a_new_file_mapping_refuses_until_it_is_gone(self):
        check = self.baseline()
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / "mapped.bin"
            path.write_bytes(b"\0" * mmap.PAGESIZE)
            with (
                path.open("rb") as file,
                mmap.mmap(file.fileno(), 0, prot=mmap.PROT_READ),
                self.assertRaisesRegex(
                    ValueError, "^host file mappings changed after the self-check$"
                ),
            ):
                check(deadline())
        accepted(self, check, deadline())

    def test_a_removed_file_mapping_refuses(self):
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / "mapped.bin"
            path.write_bytes(b"\0" * mmap.PAGESIZE)
            with path.open("rb") as file:
                view = mmap.mmap(file.fileno(), 0, prot=mmap.PROT_READ)
            check = self.baseline()
            view.close()
            with self.assertRaisesRegex(
                ValueError, "^host file mappings changed after the self-check$"
            ):
                check(deadline())

    def test_a_mapping_with_a_non_ascii_path_refuses_with_the_fixed_reason(self):
        check = self.baseline()
        with tempfile.TemporaryDirectory() as folder:
            name = os.path.join(os.fsencode(folder), b"mapped-\xc3\xa9.bin")
            fd = os.open(name, os.O_RDWR | os.O_CREAT | os.O_EXCL, 0o600)
            try:
                os.write(fd, b"\0" * mmap.PAGESIZE)
                view = mmap.mmap(fd, 0, prot=mmap.PROT_READ)
            finally:
                os.close(fd)
            try:
                with self.assertRaisesRegex(
                    ValueError, "^host file mappings changed after the self-check$"
                ):
                    check(deadline())
            finally:
                view.close()
        accepted(self, check, deadline())

    def test_file_rows_are_the_file_backed_lines_as_printed(self):
        maps = (
            b"00400000-00401000 r-xp 00000000 00:01 7 /t/lib64/libc.so.6\n"
            b"00401000-00402000 rw-p 00000000 00:00 0 [heap]\n"
            b"00402000-00403000 rw-p 00000000 00:00 0\n"
            b"00403000-00404000 r-xp 00000000 00:00 0 [vdso]\n"
            b"00404000-00405000 r--p 00000000 00:05 9 /memfd:x (deleted)\n"
        )
        self.assertEqual(
            host.file_rows(maps),
            frozenset(
                {
                    "00400000-00401000 r-xp 00000000 00:01 7 /t/lib64/libc.so.6",
                    "00404000-00405000 r--p 00000000 00:05 9 /memfd:x (deleted)",
                }
            ),
        )
        with self.assertRaises(ValueError):
            host.file_rows(b"00400000-00401000 r-xp 00000000 00:01 7 /\xff\n")


class HostReasonTests(unittest.TestCase):
    def test_a_check_keeps_its_message_and_a_kernel_error_only_its_errno(self):
        receipt = OSError("short rooted host receipt")
        cases = (
            (ValueError("host descriptors"), "host descriptors"),
            (
                TimeoutError("rooted host operation deadline"),
                "rooted host operation deadline",
            ),
            # Raised by a check with a message and no errno.
            (
                FileExistsError("prior rooted ownership unresolved"),
                "prior rooted ownership unresolved",
            ),
            (receipt, "short rooted host receipt"),
            (
                BaseExceptionGroup("cleanup", [receipt, ValueError("x")]),
                "short rooted host receipt",
            ),
            # From the kernel: never its path.
            (
                FileNotFoundError(errno.ENOENT, "No such file", "/home/u/x"),
                "OSError ENOENT",
            ),
            (OSError(), "OSError unknown"),
            (KeyError("/home/u/x"), "KeyError"),
        )
        for error, expected in cases:
            with self.subTest(expected):
                self.assertEqual(host.reason(error), expected)


class HostResolveTests(unittest.TestCase):
    """The entry's resolve mode in process.

    Each test's runtime is a namespace whose only gate and manager are mocks,
    so nothing here can reach AdmissionGate.for_current_user, which creates
    and locks the real admission directory.
    """

    def setUp(self):
        self.production = mock.Mock(side_effect=ValueError("production gate"))
        self.manager = mock.Mock(side_effect=AssertionError("production manager"))
        service = types.SimpleNamespace(
            AdmissionGate=types.SimpleNamespace(for_current_user=self.production),
            SystemdBus=self.manager,
        )
        self.runtime = types.SimpleNamespace(
            native=types.SimpleNamespace(service=service),
            preflight=types.SimpleNamespace(root=root),
        )

    def checked(self, request, check=None):
        """A passed self-check of this process for request's bytes."""
        wire = {
            "scope": host.SCOPE,
            "runtime": TREE,
            "request_sha256": sha(request),
            "manifest_sha256": json.loads(request)["manifest_sha256"],
            "observation": {
                "pid": os.getpid(),
                "request_data": {"$bytes": request.hex()},
            },
            "accepted": False,
            "native_authorized": False,
            "full_contract_proven": False,
        }

        def unchanged(deadline):
            pass

        return host.Checked(
            TREE,
            json.loads(request),
            closure.canonical(wire),
            check or unchanged,
            self.runtime,
            inputs_module,
            owner,
            None,
        )

    def test_resolve_refuses_without_a_resolve_self_check(self):
        gate = mock.Mock(side_effect=AssertionError("admission"))
        for label, checked in (
            ("startup-only", self.checked(startup_request())),
            ("self-check", self.checked(request_bytes())),
            ("tuple", tuple(self.checked(resolve_request()))),
            ("none", None),
        ):
            with self.subTest(label):
                # A lookup or type error past the gate, or an acceptance, is a
                # failure, not an error.
                try:
                    host.resolve_failed(checked, gate_factory=gate)
                except ValueError as error:
                    self.assertEqual(
                        str(error), "host resolve without a resolve self-check"
                    )
                except (KeyError, TypeError, AttributeError) as error:
                    self.fail(f"not a refusal: {error!r}")
                else:
                    self.fail("accepted")
        gate.assert_not_called()
        self.production.assert_not_called()

    def test_resolve_admits_only_through_the_production_gate(self):
        # main()'s call: no factories, so no request field can name the gate.
        real = owner.resolve_failed_startup
        for commit in (False, True):
            checked = self.checked(resolve_request(commit=commit))
            self.production.reset_mock()
            resolver = mock.Mock(side_effect=real)
            with (
                self.subTest(commit=commit),
                mock.patch.object(owner, "resolve_failed_startup", resolver),
                self.assertRaisesRegex(ValueError, "^production gate$"),
            ):
                host.resolve_failed(checked)
            self.production.assert_called_once()
            resolver.assert_called_once()
            args, keywords = resolver.call_args
            self.assertEqual(args, ("run-01", self.runtime))
            self.assertEqual(set(keywords), {"witness", "commit"})
            self.assertIs(keywords["commit"], commit)
            self.assertEqual(
                keywords["witness"], owner.HostWitness(checked.witness, checked.check)
            )
            self.assertIs(type(keywords["witness"]), owner.HostWitness)
        self.manager.assert_not_called()

    def test_main_writes_only_the_canonical_resolution_result(self):
        record = b'{"outcome":"lost-owner-resolved"}'
        for commit, state in ((False, "present"), (True, "absent")):
            checked = self.checked(resolve_request(commit=commit))
            result = owner.Resolution(record, sha(record), commit, state)
            resolver = mock.Mock(return_value=result)
            startup = mock.Mock(side_effect=AssertionError("startup"))
            with tempfile.TemporaryFile() as output, self.subTest(commit=commit):
                sys.stdout.flush()
                saved = os.dup(1)
                try:
                    os.dup2(output.fileno(), 1)
                    with (
                        mock.patch.object(host, "run", return_value=checked),
                        mock.patch.object(host, "startup_only", startup),
                        mock.patch.object(owner, "resolve_failed_startup", resolver),
                    ):
                        code = host.main()
                finally:
                    os.dup2(saved, 1)
                    os.close(saved)
                output.seek(0)
                data = output.read()
                self.assertEqual(code, 0)
                self.assertEqual(
                    data,
                    closure.canonical(
                        {
                            "scope": "contained-job-host-resolution-result-v1",
                            "run_id": "run-01",
                            "committed": commit,
                            "admission_state": state,
                            "record": {"$bytes": record.hex()},
                            "record_sha256": sha(record),
                            "witness": {"$bytes": checked.witness.hex()},
                            "witness_sha256": sha(checked.witness),
                            "accepted": False,
                            "native_authorized": False,
                            "full_contract_proven": False,
                        }
                    ),
                )
                startup.assert_not_called()
                resolver.assert_called_once()
                # No factories: production admission and manager.
                self.assertEqual(set(resolver.call_args.kwargs), {"witness", "commit"})
                self.assertIs(resolver.call_args.kwargs["commit"], commit)


def mount_line(number, parent, device, point, kind="ext4"):
    return f"{number} {parent} {device} / {point} rw - {kind} src rw\n".encode()


class HostMountTests(unittest.TestCase):
    def test_chain_is_the_path_walk_from_slash_to_the_tree(self):
        data = mount_line(2, 1, "0:1", "/") + mount_line(3, 2, "0:2", "/home")
        data += mount_line(4, 3, "0:3", "/home/u/.cache")
        data += mount_line(5, 2, "0:4", "/mnt/share", "autofs")
        data += mount_line(6, 5, "0:5", "/mnt/share", "cifs")
        data += mount_line(7, 2, "0:6", "/home2")
        data += mount_line(8, 4, "0:7", TREE + "x")
        # A string prefix of the tree path that is not one of its directories.
        data += mount_line(9, 2, "0:8", "/home/u/.ca")
        chain = accepted(self, host.mount_chain, root, data, TREE)
        self.assertEqual(list(chain), ["/", "/home", "/home/u/.cache"])
        self.assertEqual(state.mount_device(chain, TREE + "/usr/bin/python3"), (0, 3))
        single = accepted(
            self, host.mount_chain, root, mount_line(2, 1, "0:1", "/"), TREE
        )
        self.assertEqual(list(single), ["/"])

    def test_mounts_in_the_tree_stacks_and_hidden_rows_on_the_chain_refuse(self):
        base = mount_line(2, 1, "0:1", "/") + mount_line(3, 2, "0:2", "/home")
        for extra, reason in (
            # <T> staged as its own mount (bind, tmpfs, subvolume) refuses.
            (mount_line(4, 3, "0:3", TREE), "host mount at the runtime root"),
            (mount_line(4, 3, "0:3", TREE + "/usr"), "host mount inside the runtime"),
            (
                mount_line(4, 3, "0:3", "/home"),
                "host stacked mount on the runtime path",
            ),
            (
                mount_line(4, 2, "0:3", "/home/u"),
                "host mount chain is not one path walk",
            ),
            (mount_line(4, 1, "0:3", "/"), "host stacked mount on the runtime path"),
        ):
            with (
                self.subTest(extra=extra),
                self.assertRaisesRegex(ValueError, "^" + reason + "$"),
            ):
                # /home/u below /home but parented on /: hidden under /home.
                host.mount_chain(root, base + extra, TREE)
        with self.assertRaisesRegex(ValueError, "^host mount chain root$"):
            host.mount_chain(root, mount_line(3, 2, "0:2", "/home"), TREE)
        with self.assertRaises(ValueError):
            host.mount_chain(root, b"2 1 0:1 / / rw - ext4 src rw", TREE)


class HostStatusTests(unittest.TestCase):
    def test_status_is_single_threaded_unprivileged_and_this_process(self):
        self.assertIsNone(
            accepted(self, host.check_status, root, STATUS, 4242, 1000, 1000)
        )
        # A session's inheritable set grants nothing without an exec.
        inheritable = STATUS.replace(
            b"CapInh:\t0000000000000000", b"CapInh:\t0000000800000000"
        )
        self.assertIsNone(
            accepted(self, host.check_status, root, inheritable, 4242, 1000, 1000)
        )
        for data in (
            STATUS.replace(b"Threads:\t1", b"Threads:\t2"),
            STATUS.replace(b"CapEff:\t0000000000000000", b"CapEff:\t0000000000000001"),
            STATUS.replace(b"CapPrm:\t0000000000000000", b"CapPrm:\t0000000000000001"),
            STATUS.replace(b"CapAmb:\t0000000000000000", b"CapAmb:\t0000000000000400"),
            STATUS.replace(
                b"Uid:\t1000\t1000\t1000\t1000", b"Uid:\t1000\t0\t1000\t1000"
            ),
            STATUS.replace(b"Pid:\t4242", b"Pid:\t4243"),
        ):
            with (
                self.subTest(data=data),
                self.assertRaisesRegex(ValueError, "^host process status$"),
            ):
                host.check_status(root, data, 4242, 1000, 1000)
        root_status = STATUS.replace(b"\t1000", b"\t0")
        with self.assertRaisesRegex(ValueError, "^host process status$"):
            host.check_status(root, root_status, 4242, 0, 0)


class HostValidateTests(unittest.TestCase):
    """Each check refuses one perturbed fact of an otherwise valid observation."""

    def refuses(self, reason, change):
        observation, data, digest, pages = synthetic()
        change(observation)
        with self.assertRaisesRegex(ValueError, "^" + re.escape(reason) + "$"):
            host.validate(observation, TREE, data, digest, pages, DEPS)

    def test_synthetic_observation_is_accepted_without_authority(self):
        observation, data, digest, pages = synthetic()
        manifest = accepted(
            self, host.validate, observation, TREE, data, digest, pages, DEPS
        )
        self.assertEqual(manifest["bootstrap"], "opt/irlume/launcher")

    def test_environment_arguments_and_entry_are_exact(self):
        cases = {
            "host environment": [
                lambda o: o["environment"].update(LD_PRELOAD="/usr/lib64/libz.so.1"),
                lambda o: o["environment"].update(IRLUME_EXTRA="1"),
                lambda o: o["environment"].update(PATH="/usr/local/bin:/usr/bin:/bin"),
                lambda o: o["environment"].pop("LC_ALL"),
            ],
            "host interpreter arguments": [
                lambda o: o.update(
                    orig_argv=tuple(a for a in o["orig_argv"] if a != "-S")
                ),
                lambda o: o.update(
                    orig_argv=o["orig_argv"][:1] + ("-O",) + o["orig_argv"][1:]
                ),
                lambda o: o.update(
                    orig_argv=("/usr/bin/python3",) + o["orig_argv"][1:]
                ),
            ],
            "host entry arguments": [
                lambda o: o.update(argv=o["argv"] + ("extra",)),
                lambda o: o.update(
                    file=TREE + "/opt/irlume/measurement-job-guardian-native.py"
                ),
                lambda o: o.update(
                    argv=("/opt/irlume/measurement-job-host.py",) + o["argv"][1:]
                ),
                # orig_argv matches, so only the argv[1] check refuses.
                lambda o: o.update(
                    argv=o["argv"][:1] + ("--other",) + o["argv"][2:],
                    orig_argv=o["orig_argv"][:-3] + ("--other",) + o["orig_argv"][-2:],
                ),
            ],
            "host interpreter prefix": [
                lambda o: o.update(prefixes=("/usr",) + o["prefixes"][1:]),
                lambda o: o.update(prefixes=o["prefixes"][:3] + (TREE + "x/usr",)),
                # Inside the tree but not getpath's <T>/usr.
                lambda o: o.update(prefixes=(TREE + "/opt",) * 4),
                lambda o: o.update(prefixes=o["prefixes"][:3] + (TREE + "/usr/lib64",)),
                lambda o: o.update(prefixes=o["prefixes"][:3]),
            ],
            "host initial search path": [
                # Subsets of the selection that are not getpath's exact triple.
                lambda o: o.update(initial_path=o["initial_path"][:2]),
                lambda o: o.update(initial_path=o["initial_path"][1:]),
                lambda o: o.update(initial_path=o["initial_path"][::-1]),
                lambda o: o.update(initial_path=(TREE + "/opt/irlume/vendor",)),
                lambda o: o.update(
                    initial_path=o["initial_path"] + ("/usr/lib64/python3.14",)
                ),
                lambda o: o.update(initial_path=(TREE + "x/usr/lib64/python3.14",)),
                lambda o: o.update(initial_path=(TREE + "/opt/irlume",)),
                lambda o: o.update(initial_path=(TREE + "/opt/irlume/launcher.zip",)),
                lambda o: o.update(initial_path=(TREE + "/usr/lib64/python313.zip",)),
                lambda o: o.update(initial_path=o["initial_path"] * 2),
                lambda o: o.update(initial_path=()),
            ],
        }
        for reason, changes in cases.items():
            for number, change in enumerate(changes):
                with self.subTest(reason=reason, case=number):
                    self.refuses(reason, change)

    def test_process_executable_preload_descriptors_and_status(self):
        cases = {
            "host process executable": [
                lambda o: o["exe"].update(path=TREE + "/usr/bin/python3"),
                lambda o: o["exe"].update(path="/usr/lib64/ld-linux-x86-64.so.2"),
                lambda o: o["exe"].update(inode=o["exe"]["inode"] + 1),
                lambda o: o["exe"].update(device=o["exe"]["device"] + 1),
            ],
            "host loader preload file": [lambda o: o.update(preload=True)],
            "host descriptors": [
                lambda o: o["descriptors"].update(initial=(0, 1, 2, 5)),
                lambda o: o["descriptors"].update(final=(0, 1, 2, 9)),
                lambda o: o["stdio"].update(final=STDIO[:2] + ((2, (1, 9, 0, 0), 2),)),
            ],
            "host process status": [
                lambda o: o.update(
                    status=STATUS.replace(b"Threads:\t1", b"Threads:\t3")
                ),
                lambda o: o.update(pid=4243),
            ],
        }
        for reason, changes in cases.items():
            for number, change in enumerate(changes):
                with self.subTest(reason=reason, case=number):
                    self.refuses(reason, change)

    def test_request_binds_the_tree_and_the_selected_manifest(self):
        other = request_bytes(tree="/home/u/.cache/other/root")
        stale = request_bytes(manifest_sha256="0" * 64)
        cases = (
            ("host request digest", lambda o: o.update(request_data=other)),
            (
                "host request runtime",
                lambda o: o.update(
                    request_data=other,
                    argv=o["argv"][:3] + (sha(other),),
                    orig_argv=o["orig_argv"][:-1] + (sha(other),),
                ),
            ),
            (
                "host request manifest digest",
                lambda o: o.update(
                    request_data=stale,
                    argv=o["argv"][:3] + (sha(stale),),
                    orig_argv=o["orig_argv"][:-1] + (sha(stale),),
                ),
            ),
        )
        for reason, change in cases:
            with self.subTest(reason=reason):
                self.refuses(reason, change)

    def test_a_startup_only_request_is_bound_like_a_self_check(self):
        def using(request):
            def change(o):
                o.update(
                    request_data=request,
                    argv=o["argv"][:3] + (sha(request),),
                    orig_argv=o["orig_argv"][:-1] + (sha(request),),
                )

            return change

        observation, data, digest, pages = synthetic()
        using(startup_request(manifest_sha256=digest))(observation)
        accepted(self, host.validate, observation, TREE, data, digest, pages, DEPS)
        active = specification(mode="runtime-candidate", cases=["normal"])
        self.refuses(
            "host request specification",
            using(
                startup_request(manifest_sha256=synthetic()[2], specification=active)
            ),
        )

    def test_mount_view_maps_and_mapped_bytes(self):
        libc = b"0000000000009000-000000000000a000 r-xp 00000000 00:01 9 /usr/lib64/libc.so.6\n"
        cases = (
            (
                "host mount inside the runtime",
                lambda o: o.update(
                    mountinfo=MOUNTINFO + mount_line(3, 2, "0:2", TREE + "/opt")
                ),
            ),
            (
                "runtime unlisted mapped file",
                lambda o: o.update(
                    maps=o["maps"].replace(
                        b"0000000000004000-", libc + b"0000000000004000-"
                    )
                ),
            ),
            (
                "runtime writable or shared executable map",
                lambda o: o.update(maps=o["maps"].replace(b"r-xp", b"rwxp", 1)),
            ),
            (
                "runtime mapped file identity",
                lambda o: o.update(maps=o["maps"].replace(b" 00:01 ", b" 00:02 ", 1)),
            ),
            (
                "runtime mapped bytes differ",
                lambda o: o.update(
                    mapped=(dict(o["mapped"][0], sha256="0" * 64),) + o["mapped"][1:]
                ),
            ),
        )
        for reason, change in cases:
            with self.subTest(reason=reason):
                self.refuses(reason, change)

    def test_python_state_is_the_selected_runtime_and_entry(self):
        def module(o, name, **change):
            o["python"]["modules"] = tuple(
                dict(row, **change) if row["name"] == name else row
                for row in o["python"]["modules"]
            )

        cases = (
            ("runtime Python flag", lambda o: o["python"]["flags"].update(no_site=0)),
            (
                "runtime Python environment or search path",
                lambda o: o["python"].update(pycache_prefix=None),
            ),
            (
                "runtime Python environment or search path",
                lambda o: o["python"].update(sys_path=o["python"]["sys_path"][:1]),
            ),
            (
                "runtime Python environment or search path",
                lambda o: o["python"].update(
                    sys_path=("/usr/lib64/python3.14",) + o["python"]["sys_path"][1:]
                ),
            ),
            (
                "runtime main entry",
                lambda o: module(
                    o,
                    "__main__",
                    origin=TREE + "/opt/irlume/measurement-job-guardian-native.py",
                ),
            ),
            (
                "runtime module is not a selected file",
                lambda o: module(
                    o,
                    "jeepney",
                    origin="/usr/lib/python3.14/site-packages/jeepney/__init__.py",
                ),
            ),
        )
        for reason, change in cases:
            with self.subTest(reason=reason):
                self.refuses(reason, change)

    def test_sources_jeepney_and_import_hooks(self):
        cases = (
            (
                "host source digest",
                lambda o: o.update(
                    sources=((o["sources"][0][0], "0" * 64),) + o["sources"][1:]
                ),
            ),
            (
                "host source digest",
                lambda o: o.update(
                    sources=(("/opt/irlume/x.py", "0" * 64),) + o["sources"]
                ),
            ),
            (
                "host source digest",
                lambda o: o.update(sources=o["sources"] + (o["sources"][0],)),
            ),
            ("host sources missing", lambda o: o.update(sources=o["sources"][1:])),
            ("host jeepney", lambda o: o["jeepney"].update(version="0.8.0")),
            (
                "host jeepney",
                lambda o: o["jeepney"].update(
                    origin="/usr/lib/python3.14/site-packages/jeepney/__init__.py"
                ),
            ),
            ("host import hooks", lambda o: o["hooks"].update(excepthook=False)),
            ("host import hooks", lambda o: o["hooks"].update(meta_path=False)),
            ("host import hooks", lambda o: o["hooks"].update(path_hooks=False)),
        )
        for reason, change in cases:
            with self.subTest(reason=reason):
                self.refuses(reason, change)

    def test_bootstrap_and_manifest_digest_are_the_checker_own(self):
        observation, data, digest, pages = synthetic()
        with self.assertRaises(ValueError):
            host.validate(observation, TREE, data, "0" * 64, pages, DEPS)
        value = json.loads(data)
        value["bootstrap"] = "usr/bin/python3"
        other = closure.canonical(value)
        request = request_bytes(manifest_sha256=sha(other))
        observation.update(
            request_data=request,
            argv=observation["argv"][:3] + (sha(request),),
            orig_argv=observation["orig_argv"][:-1] + (sha(request),),
        )
        with self.assertRaisesRegex(ValueError, "^host runtime bootstrap$"):
            host.validate(observation, TREE, other, sha(other), pages, DEPS)
        # The checker's tree, not the observation's, decides every path.
        observation, data, digest, pages = synthetic()
        with self.assertRaises(ValueError):
            host.validate(observation, TREE + "x", data, digest, pages, DEPS)

    def test_witness_is_canonical_bounded_and_carries_no_authority(self):
        observation, data, digest, pages = synthetic()
        encoded = host.encode(observation, TREE, digest, DEPS, deadline())
        self.assertLessEqual(len(encoded), host.WITNESS_LIMIT)
        wire = json.loads(encoded)
        self.assertEqual(wire["scope"], host.SCOPE)
        self.assertEqual(wire["runtime"], TREE)
        self.assertEqual(wire["request_sha256"], observation["argv"][3])
        self.assertEqual(wire["manifest_sha256"], digest)
        for name in ("accepted", "native_authorized", "full_contract_proven"):
            self.assertIs(wire[name], False)
        decoded = host.decode(encoded, DEPS, deadline())
        self.assertTrue(witness.typed_equal(decoded["observation"], observation))
        accepted(
            self, host.validate, decoded["observation"], TREE, data, digest, pages, DEPS
        )
        for change in (
            lambda w: w.update(accepted=True),
            lambda w: w.update(native_authorized=True),
            lambda w: w.update(scope="contained-job-startup-witness-v2"),
            lambda w: w.update(extra=1),
        ):
            bad = json.loads(encoded)
            change(bad)
            with self.assertRaises(ValueError):
                host.decode(closure.canonical(bad), DEPS, deadline())
        with self.assertRaises(ValueError):
            host.decode(encoded + b" ", DEPS, deadline())


ROOT_FIELDS = ("scope", "platform", "python", "native", "environment", "bootstrap")
REPLACED = re.compile(r"opt/irlume/measurement-job[^/]*\.py")
QEMU = "usr/bin/qemu-system-x86_64"
# Appended to python-state in one copy: each collector call leaves a
# descriptor open.
LEAK = b"""

_collect_python_state = collect_python_state


def collect_python_state(*args, **keywords):
    os.open("/dev/null", os.O_RDONLY | os.O_CLOEXEC)
    return _collect_python_state(*args, **keywords)
"""


# The entry's call into HostOwner. A diagnostic runtime replaces this line to
# name a scratch admission directory, never a request field; these tests
# replace it the same way and refuse the manager, so no unit is created. Run
# h2-import also imports a module after the self-check.
STARTUP_LINE = (
    "        selection, support, witness=witness, bus_bridge=checked.bridge, "
    "**factories\n"
)
STARTUP_TEST = (
    "        selection, support, witness=witness, bus_bridge=checked.bridge, "
    "gate_factory=lambda deadline: test_gate({gates!r}, checked, deadline), "
    "bus_factory=refuse_manager\n"
)
STARTUP_HELPERS = """

def test_gate(gates, checked, deadline):
    run_id = checked.request["specification"]["run_id"]
    if run_id == "h2-import":
        importlib.import_module("colorsys")
    service = checked.runtime.native.service
    return service.AdmissionGate(gates + "/" + run_id, deadline)


def refuse_manager(*args, **keywords):
    raise ValueError("test manager refused")
"""
MAIN = '\n\nif __name__ == "__main__":\n'
# Slice H4: the entry's call into the resolver, replaced the same way. The test
# manager is read-only and knows no unit, the scans are fixed: real scans could
# flake on a busy host, and no unit is ever created. The last part of a run ID
# names its gate, so a later run can use the gate an earlier one left. Every
# real-kernel resolve run goes through this tree: an unpatched entry would reach
# AdmissionGate.for_current_user, which creates and locks the real directory.
RESOLVE_LINE = "        **factories,\n"
RESOLVE_TEST = (
    "        gate_factory=lambda deadline: test_gate({gates!r}, checked, deadline),\n"
    "        bus_factory=lambda uid, deadline: AbsentManager(),\n"
    "        process_scan=no_process,\n"
    "        cgroup_scan=lambda unit, uid: [],\n"
)
RESOLVE_HELPERS = """

def test_gate(gates, checked, deadline):
    request = checked.request
    run_id = request["run_id"] if "run_id" in request else request["specification"]["run_id"]
    service = checked.runtime.native.service
    return service.AdmissionGate(gates + "/" + run_id.rpartition("-")[2], deadline)


def refuse_manager(*args, **keywords):
    raise ValueError("test manager refused")


class AbsentManager:
    def call(self, path, interface, method, signature, args, deadline):
        if method == "GetUnit":
            raise RuntimeError("user-bus error: org.freedesktop.systemd1.NoSuchUnit")
        raise RuntimeError("test manager call")

    def close(self):
        pass


def no_process(targets, unit, before):
    return {"processes": 1, "same_uid": 1, "unreadable_before_owner": 0, "matches": []}
"""
# DIAGNOSTIC BUILD ONLY, as the native round's kill patch: H kills itself right
# after its anchor when the run ID selects that point, so a real SIGKILL leaves
# the state; other run IDs pass the same bytes.
KILL_ANCHORS = {
    "after-intent": '        self.write("host-intent", intent, deadline)\n',
    "after-claim": "        self.gate.claim(self.spec.run_id, intent, deadline)\n",
}
KILL_LINE = (
    '        if self.spec.run_id.startswith("r5-h4-{point}-"): '
    "os.kill(os.getpid(), 9)  # DIAGNOSTIC BUILD ONLY\n"
)
OWNER_ENTRY = "opt/irlume/measurement-job-rooted-host.py"


def remove(path):
    """Remove a throwaway tree whose directories are read-only."""
    if not os.path.lexists(path):
        return
    for folder, names, _ in os.walk(path):
        os.chmod(folder, 0o700)
        for name in names:
            child = os.path.join(folder, name)
            if not os.path.islink(child):
                os.chmod(child, 0o700)
    shutil.rmtree(path)


class HostRuntimeTests(unittest.TestCase):
    """The entry runs through the tree loader in host namespaces."""

    @classmethod
    def setUpClass(cls):
        if os.uname().sysname != "Linux" or os.uname().machine != "x86_64":
            raise RuntimeError("host runtime tests require Linux x86-64")
        source = os.environ.get("IRLUME_HOST_RUNTIME")
        if not source:
            raise RuntimeError(
                "IRLUME_HOST_RUNTIME must name a prepared runtime (root/ and "
                "inputs/manifest.json); no host fallback"
            )
        cls.rustup = shutil.which("rustup")
        if cls.rustup is None:
            raise RuntimeError("pinned Rust is required; no host fallback")
        cls.work = Path(
            tempfile.mkdtemp(prefix="irlume-host-", dir=os.environ.get("TMPDIR"))
        ).resolve()
        cls.addClassCleanup(remove, cls.work)
        requested = os.environ.get("IRLUME_HOST_EVIDENCE")
        if requested:
            cls.evidence = Path(requested)
            cls.evidence.mkdir(mode=0o700)
        else:
            cls.evidence = Path(
                tempfile.mkdtemp(
                    prefix="irlume-host-evidence-", dir=os.environ.get("TMPDIR")
                )
            )
            print("Host evidence retained at", cls.evidence)
        source = Path(source)
        pinned = (source / "inputs/manifest.json").read_bytes()
        # The source tree must be the runtime its manifest pins.
        with closure.RuntimeSnapshot.open(
            source / "root", pinned, sha(pinned), deadline=deadline()
        ) as snapshot:
            snapshot.check()
        cls.build_launcher()
        cls.prepare_tree(source / "root", json.loads(pinned))
        cls.write_request()

    @classmethod
    def build_launcher(cls):
        build = cls.work / "build"
        build.mkdir(mode=0o700)
        rust = build / "launcher.rs"
        rust.write_bytes((HERE / "measurement-job-launcher.rs").read_bytes())
        command = [
            cls.rustup,
            "run",
            "1.88.0",
            "rustc",
            "--edition=2021",
            "--crate-name",
            "host_launcher",
            "--target",
            "x86_64-unknown-linux-musl",
            "-Ctarget-feature=+crt-static",
            "-Crelocation-model=static",
            "-Clink-arg=-no-pie",
            "-Cpanic=abort",
            "-Copt-level=s",
            "-Ccodegen-units=1",
            "-Dwarnings",
            str(rust),
            "-o",
            str(build / "launcher"),
        ]
        result = subprocess.run(
            command,
            capture_output=True,
            text=True,
            timeout=300,
            check=False,
            env={
                "HOME": str(Path.home()),
                "PATH": "/usr/bin:/bin",
                "LC_ALL": "C",
                "TMPDIR": str(build),
            },
            cwd=str(build),
        )
        if result.returncode:
            raise RuntimeError(result.stderr)
        metadata = closure.elf.inspect((build / "launcher").read_bytes())
        if metadata["type"] != 2 or metadata["dynamic"] or metadata["interpreter"]:
            raise RuntimeError("test launcher is not static ET_EXEC")
        cls.launcher_bytes = (build / "launcher").read_bytes()

    @classmethod
    def prepare_tree(cls, source, pinned):
        """Copy the pinned tree with this checkout's modules and launcher."""
        cls.source, cls.pinned = source, pinned
        tree, cls.manifest, cls.manifest_data, cls.manifest_sha256 = cls.copy_tree(
            "root", "inputs"
        )
        cls.tree = str(tree)
        cls.launcher = cls.tree + "/opt/irlume/launcher"
        cls.loader = cls.tree + "/" + LOADER
        cls.python = cls.tree + "/usr/bin/python3"
        cls.entry = cls.tree + "/" + host.ENTRY
        with closure.RuntimeSnapshot.open(
            cls.tree, cls.manifest_data, cls.manifest_sha256, deadline=deadline()
        ) as snapshot:
            cls.pages = host.page_digests(snapshot, cls.tree)
            cls.files = host.file_facts(snapshot, cls.tree)

    @classmethod
    def copy_tree(cls, name, inputs_name, replaced=None, qemu=False):
        """A re-pinned copy of the source tree at work/name, without the QEMU
        member unless qemu (a startup configuration selects it), with this
        checkout's modules and launcher; replaced maps a member path to the
        bytes it gets instead."""
        tree = cls.work / name
        tree.mkdir(mode=0o700)
        added = {
            "opt/irlume/" + path.name: path.read_bytes()
            for path in sorted(HERE.glob("measurement-job*.py"))
        }
        added["opt/irlume/launcher"] = cls.launcher_bytes
        added.update(replaced or {})
        modes = {}
        for row in cls.pinned["members"]:
            path = row["path"]
            if (path == QEMU and not qemu) or path in added or REPLACED.fullmatch(path):
                continue
            target = tree / path
            if row["kind"] == "directory":
                target.mkdir(mode=0o700)
                modes[target] = 0o500
            else:
                target.write_bytes((cls.source / path).read_bytes())
                target.chmod(row["mode"])
        for path, data in added.items():
            target = tree / path
            target.write_bytes(data)
            target.chmod(0o500 if path == "opt/irlume/launcher" else 0o400)
        for folder in sorted(modes, key=lambda p: len(p.parts), reverse=True):
            folder.chmod(0o500)
        tree.chmod(0o500)
        profile = {field: cls.pinned[field] for field in ROOT_FIELDS}
        manifest_data, manifest_sha256 = closure.prepare_manifest(
            tree, profile, deadline=deadline()
        )
        inputs = cls.work / inputs_name
        inputs.mkdir(mode=0o700)
        manifest = inputs / "manifest.json"
        manifest.write_bytes(manifest_data)
        manifest.chmod(0o400)
        return tree, manifest, manifest_data, manifest_sha256

    @classmethod
    def write_request(cls, name="attempt", **changes):
        folder = cls.work / name
        folder.mkdir(mode=0o700)
        value = {
            "scope": host.REQUEST_SCOPE,
            "mode": "self-check",
            "runtime": cls.tree,
            "manifest": str(cls.manifest),
            "manifest_sha256": cls.manifest_sha256,
        }
        value.update(changes)
        data = closure.canonical(value)
        path = folder / "host-request.json"
        path.write_bytes(data)
        path.chmod(0o400)
        if name == "attempt":
            cls.request, cls.request_sha256 = str(path), sha(data)
        return str(path), sha(data)

    def run_command(self, label, command, environment, *, pass_fds=(), executable=None):
        result = subprocess.run(
            command,
            capture_output=True,
            timeout=120,
            check=False,
            env=environment,
            cwd="/",
            pass_fds=pass_fds,
            executable=executable,
        )
        record = {
            "argv": command,
            "executable": executable,
            "environment": sorted(environment),
            "pass_fds": list(pass_fds),
            "returncode": result.returncode,
            "stdout_bytes": len(result.stdout),
            "stdout_sha256": sha(result.stdout),
            "stderr": result.stderr.decode("ascii", "replace"),
        }
        (self.evidence / (label + ".json")).write_text(
            json.dumps(record, indent=2) + "\n"
        )
        return result

    def through_loader(self, *, tree=None, libraries=None, request=None, digest=None):
        tree = tree or self.tree
        argv = [tree + "/" + LOADER, "--inhibit-cache"]
        argv += ["--library-path", libraries or tree + "/lib64"]
        return argv + [
            tree + "/usr/bin/python3",
            *FLAGS,
            tree + "/" + host.ENTRY,
            "--request",
            request or self.request,
            digest or self.request_sha256,
        ]

    def refused(self, result, reason):
        self.assertEqual(result.returncode, 77, result.stderr)
        self.assertEqual(result.stdout, b"")
        lines = result.stderr.decode("ascii", "replace").splitlines()
        self.assertTrue(lines, "no refusal reason")
        self.assertEqual(lines[-1], "measurement-job-host: " + reason)

    def decoded(self, result):
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stderr, b"")
        self.assertLessEqual(len(result.stdout), host.WITNESS_LIMIT)
        return host.decode(result.stdout, DEPS, deadline())

    def test_launcher_starts_the_self_check_despite_a_poisoned_caller(self):
        poison = {
            **ENVIRONMENT,
            "LD_PRELOAD": "/untrusted.so",
            "LD_AUDIT": "/audit.so",
            "LD_LIBRARY_PATH": "/untrusted",
            "GLIBC_TUNABLES": "untrusted.marker=1",
            "PYTHONPATH": "/untrusted",
            "IRLUME_POISON": "must-not-survive",
        }
        inherited = os.open("/dev/null", os.O_RDONLY)
        try:
            os.dup2(inherited, 9, inheritable=True)
            result = self.run_command(
                "launcher-positive",
                [self.launcher, "--host", self.request, self.request_sha256],
                poison,
                pass_fds=(9,),
            )
        finally:
            os.close(9)
            os.close(inherited)
        (self.evidence / "witness.json").write_bytes(result.stdout)
        wire = self.decoded(result)
        self.assertEqual(wire["scope"], host.SCOPE)
        for name in ("accepted", "native_authorized", "full_contract_proven"):
            self.assertIs(wire[name], False)
        observation = wire["observation"]
        accepted(
            self,
            host.validate,
            observation,
            self.tree,
            self.manifest_data,
            self.manifest_sha256,
            self.pages,
            DEPS,
        )
        self.assertEqual(observation["environment"], ENVIRONMENT)
        self.assertEqual(
            observation["descriptors"], {"initial": (0, 1, 2), "final": (0, 1, 2)}
        )
        self.assertEqual(observation["exe"]["path"], self.loader)
        self.assertEqual(
            observation["jeepney"],
            {
                "version": "0.9.0",
                "origin": self.tree + "/opt/irlume/vendor/jeepney/__init__.py",
            },
        )
        self.assertEqual(observation["files"], self.files)
        mapped = set()
        for line in observation["maps"].decode().splitlines():
            fields = line.split(None, 5)
            if len(fields) == 6 and fields[4] != "0":
                mapped.add(fields[5])
        self.assertTrue(mapped)
        self.assertTrue(
            all(path.startswith(self.tree + "/") for path in mapped), mapped
        )
        self.assertIn(self.loader, mapped)
        self.assertIn(self.tree + "/lib64/libc.so.6", mapped)
        origins = {path for path, _ in observation["sources"]}
        self.assertLessEqual(
            {self.tree + "/opt/irlume/" + name for name in host.SOURCES}, origins
        )
        modules = {row["name"]: row for row in observation["python"]["modules"]}
        self.assertEqual(modules["__main__"]["origin"], self.entry)
        self.assertIn("jeepney.io.blocking", modules)

    def test_real_witness_refuses_tampered_bytes_sources_and_host_mappings(self):
        result = self.run_command(
            "loader-positive", self.through_loader(), dict(ENVIRONMENT)
        )
        original = self.decoded(result)["observation"]
        cases = (
            (
                "runtime mapped bytes differ",
                lambda o: o.update(
                    mapped=(dict(o["mapped"][0], sha256="0" * 64),) + o["mapped"][1:]
                ),
            ),
            (
                "host source digest",
                lambda o: o.update(
                    sources=((o["sources"][0][0], "0" * 64),) + o["sources"][1:]
                ),
            ),
            (
                "runtime unlisted mapped file",
                lambda o: o.update(
                    maps=o["maps"].replace(
                        self.loader.encode(), b"/usr/lib64/ld-linux-x86-64.so.2"
                    )
                ),
            ),
        )
        for reason, change in cases:
            observation = copy.deepcopy(original)
            change(observation)
            with (
                self.subTest(reason=reason),
                self.assertRaisesRegex(ValueError, "^" + reason + "$"),
            ):
                host.validate(
                    observation,
                    self.tree,
                    self.manifest_data,
                    self.manifest_sha256,
                    self.pages,
                    DEPS,
                )

    def test_ambient_or_partial_launch_shapes_refuse_with_their_reason(self):
        python = shutil.which("python3")
        self.assertIsNotNone(python)
        python = str(Path(python).resolve())
        preload = next(
            path
            for path in ("/usr/lib64/libz.so.1", self.tree + "/lib64/libz.so.1")
            if os.path.exists(path)
        )
        # sys.executable and the prefixes keep the link (getpath does not
        # resolve it), so only the realpath gate, before any input or module
        # load, tells this tree from the one it names.
        linked = self.work / "linked-root"
        linked.symlink_to(self.tree)
        # A byte-identical copy of a tree library outside the tree is mapped
        # by its own path, which no member names. Unlike the host's libraries
        # it loads on any host.
        foreign = self.work / "foreign"
        foreign.mkdir(mode=0o700)
        shutil.copyfile(self.tree + "/lib64/libc.so.6", foreign / "libc.so.6")
        cases = (
            (
                "linked-tree",
                self.through_loader(tree=str(linked)),
                ENVIRONMENT,
                "host runtime root",
            ),
            (
                "host-python",
                [
                    python,
                    *FLAGS,
                    self.entry,
                    "--request",
                    self.request,
                    self.request_sha256,
                ],
                ENVIRONMENT,
                "host runtime root",
            ),
            (
                "host-python-ib",
                [
                    python,
                    "-I",
                    "-B",
                    self.entry,
                    "--request",
                    self.request,
                    self.request_sha256,
                ],
                ENVIRONMENT,
                "host runtime root",
            ),
            (
                "loader-foreign-library",
                self.through_loader(libraries=f"{foreign}:{self.tree}/lib64"),
                ENVIRONMENT,
                "runtime unlisted mapped file",
            ),
            (
                "loader-ld-preload",
                self.through_loader(),
                {**ENVIRONMENT, "LD_PRELOAD": preload},
                "host environment",
            ),
            (
                "loader-extra-variable",
                self.through_loader(),
                {**ENVIRONMENT, "IRLUME_EXTRA": "1"},
                "host environment",
            ),
        )
        for label, command, environment, reason in cases:
            with self.subTest(case=label):
                self.refused(
                    self.run_command(label, command, dict(environment)), reason
                )
        # These start the tree's python with the host's loader or libraries,
        # which may not start it at all (no such loader, another glibc, no
        # libpython3.14 in the host's default directories). A start that fails
        # must fail the same way without H. Run directly, the host's loader is
        # refused first. Through the tree's loader, the prefix the host's
        # libpython computes decides whether the prefix gate or the maps check
        # refuses.
        hosted = (
            ("direct-exec", [self.python], lambda prefix: "host process executable"),
            (
                "loader-without-library-path",
                [self.loader, "--inhibit-cache", self.python],
                lambda prefix: (
                    "runtime unlisted mapped file"
                    if prefix == self.tree + "/usr"
                    else "host interpreter prefix"
                ),
            ),
        )
        for label, start, expected in hosted:
            with self.subTest(case=label):
                probe = [*start, "-I", "-S", "-c", "import sys; print(sys.prefix)"]
                command = [
                    *start,
                    *FLAGS,
                    self.entry,
                    "--request",
                    self.request,
                    self.request_sha256,
                ]
                try:
                    probed = self.run_command(
                        label + "-probe", probe, dict(ENVIRONMENT)
                    )
                except OSError as error:
                    with self.assertRaises(OSError) as raised:
                        self.run_command(label, command, dict(ENVIRONMENT))
                    self.assertEqual(raised.exception.errno, error.errno)
                    continue
                result = self.run_command(label, command, dict(ENVIRONMENT))
                if probed.returncode == 0:
                    prefix = probed.stdout.decode("ascii", "replace").strip()
                    self.refused(result, expected(prefix))
                else:
                    self.assertEqual(result.returncode, probed.returncode)
                    self.assertEqual(result.stdout, b"")
                    self.assertNotIn(b"measurement-job-host:", result.stderr)
        inherited = os.open("/dev/null", os.O_RDONLY)
        try:
            os.dup2(inherited, 5, inheritable=True)
            result = self.run_command(
                "loader-inherited-fd",
                self.through_loader(),
                dict(ENVIRONMENT),
                pass_fds=(5,),
            )
        finally:
            os.close(5)
            os.close(inherited)
        self.refused(result, "host descriptors")

    def test_launcher_refuses_a_foreign_request_or_a_launcher_outside_the_tree(self):
        result = self.run_command(
            "launcher-wrong-digest",
            [self.launcher, "--host", self.request, "0" * 64],
            dict(ENVIRONMENT),
        )
        self.refused(result, "host request digest")
        path, digest = self.write_request(
            "other-runtime", runtime=str(self.work / "elsewhere")
        )
        result = self.run_command(
            "launcher-other-runtime",
            [self.launcher, "--host", path, digest],
            dict(ENVIRONMENT),
        )
        self.refused(result, "host request runtime")
        # A root taken from the wrong components of <work>/outside/opt/x/launcher
        # would be <work>/outside: a stub loader there turns that into a start,
        # not an exec failure that also exits 77.
        outside = self.work / "outside"
        stub = outside / LOADER
        stub.parent.mkdir(mode=0o700, parents=True)
        stub.write_bytes(b"#!/bin/sh\necho started\n")
        stub.chmod(0o500)
        result = self.run_command(
            "outside-stub-control", [str(stub)], dict(ENVIRONMENT)
        )
        self.assertEqual((result.returncode, result.stdout), (0, b"started\n"))
        copy_ = outside / "opt/x/launcher"
        copy_.parent.mkdir(mode=0o700, parents=True)
        copy_.write_bytes(self.launcher_bytes)
        copy_.chmod(0o500)
        result = self.run_command(
            "launcher-outside-tree",
            [str(copy_), "--host", self.request, self.request_sha256],
            dict(ENVIRONMENT),
        )
        self.assertEqual(result.returncode, 77)
        self.assertEqual((result.stdout, result.stderr), (b"", b""))

    def test_launcher_takes_its_tree_from_the_executable_link_not_argv0(self):
        # argv[0] names a launcher in another directory; /proc/self/exe still
        # selects this tree, so the self-check runs from it.
        result = self.run_command(
            "launcher-argv0-elsewhere",
            [
                str(self.work / "argv0-elsewhere/opt/irlume/launcher"),
                "--host",
                self.request,
                self.request_sha256,
            ],
            dict(ENVIRONMENT),
            executable=self.launcher,
        )
        observation = self.decoded(result)["observation"]
        self.assertEqual(observation["exe"]["path"], self.loader)
        accepted(
            self,
            host.validate,
            observation,
            self.tree,
            self.manifest_data,
            self.manifest_sha256,
            self.pages,
            DEPS,
        )

    def test_the_executable_is_checked_before_the_library_dependent_prefixes(self):
        # Another loader may map a libpython that computes other prefixes
        # (Arch: platlibdir lib); the refusal still names the executable.
        # This process's own executable is not the tree loader.
        argv = (self.entry, "--request", self.request, self.request_sha256)
        initial = {
            "path": (),
            "environment": dict(ENVIRONMENT),
            "orig_argv": (self.python, *FLAGS, *argv),
            "argv": argv,
            "file": self.entry,
            "executable": self.python,
            "prefixes": ("/usr",) * 4,
        }
        folder = os.getcwd()
        try:
            with self.assertRaisesRegex(ValueError, "^host process executable$"):
                host.run(initial)
        finally:
            os.chdir(folder)

    def test_a_descriptor_left_open_during_the_passes_refuses(self):
        # python-state's collector runs only between the two inventories; in
        # this re-pinned copy it leaves one descriptor open per call, so the
        # initial inventory is clean and only the final one can refuse.
        name = "opt/irlume/measurement-job-python-state.py"
        leaky = (HERE / Path(name).name).read_bytes() + LEAK
        tree, manifest, _, manifest_sha256 = self.copy_tree(
            "leaky-root", "leaky-inputs", {name: leaky}
        )
        self.addCleanup(remove, tree)
        path, digest = self.write_request(
            "leaky-attempt",
            runtime=str(tree),
            manifest=str(manifest),
            manifest_sha256=manifest_sha256,
        )
        result = self.run_command(
            "loader-leaked-fd",
            self.through_loader(tree=str(tree), request=path, digest=digest),
            dict(ENVIRONMENT),
        )
        self.refused(result, "host descriptors")

    @classmethod
    def startup_tree(cls):
        """A re-pinned copy whose entry admits to scratch gates and refuses
        the manager, with the QEMU member a startup configuration selects."""
        if getattr(cls, "h2", None) is None:
            # Short whatever TMPDIR is: control.sock must fit sun_path.
            gates = tempfile.mkdtemp(prefix="irlume-h2-", dir="/tmp")
            cls.addClassCleanup(remove, gates)
            source = (HERE / Path(host.ENTRY).name).read_text()
            if source.count(STARTUP_LINE) != 1 or source.count(MAIN) != 1:
                raise RuntimeError("the entry's HostOwner call changed")
            patched = source.replace(
                STARTUP_LINE, STARTUP_TEST.format(gates=gates)
            ).replace(MAIN, STARTUP_HELPERS + MAIN)
            tree, manifest, data, digest = cls.copy_tree(
                "h2-root", "h2-inputs", {host.ENTRY: patched.encode()}, qemu=True
            )
            with closure.RuntimeSnapshot.open(
                str(tree), data, digest, deadline=deadline()
            ) as snapshot:
                pages = host.page_digests(snapshot, str(tree))
            cls.h2 = types.SimpleNamespace(
                gates=Path(gates),
                tree=str(tree),
                manifest=manifest,
                data=data,
                sha256=digest,
                pages=pages,
            )
        return cls.h2

    @classmethod
    def kill_tree(cls):
        """A re-pinned copy with the startup tree's refusing manager, whose owner
        kills itself at KILL_ANCHORS and whose resolver uses a scratch gate and
        a fake read-only manager."""
        if getattr(cls, "h4", None) is None:
            # Short whatever TMPDIR is: control.sock must fit sun_path.
            gates = tempfile.mkdtemp(prefix="irlume-h4-", dir="/tmp")
            cls.addClassCleanup(remove, gates)
            source = (HERE / Path(host.ENTRY).name).read_text()
            if (
                source.count(STARTUP_LINE) != 1
                or source.count(RESOLVE_LINE) != 1
                or source.count(MAIN) != 1
            ):
                raise RuntimeError("the entry's HostOwner or resolver call changed")
            entry = (
                source.replace(STARTUP_LINE, STARTUP_TEST.format(gates=gates))
                .replace(RESOLVE_LINE, RESOLVE_TEST.format(gates=gates))
                .replace(MAIN, RESOLVE_HELPERS + MAIN)
            )
            killing = (HERE / Path(OWNER_ENTRY).name).read_text()
            for point, anchor in KILL_ANCHORS.items():
                if killing.count(anchor) != 1:
                    raise RuntimeError("the owner's kill anchor changed: " + point)
                killing = killing.replace(
                    anchor, anchor + KILL_LINE.format(point=point)
                )
            tree, manifest, data, digest = cls.copy_tree(
                "h4-root",
                "h4-inputs",
                {host.ENTRY: entry.encode(), OWNER_ENTRY: killing.encode()},
                qemu=True,
            )
            with closure.RuntimeSnapshot.open(
                str(tree), data, digest, deadline=deadline()
            ) as snapshot:
                pages = host.page_digests(snapshot, str(tree))
            cls.h4 = types.SimpleNamespace(
                gates=Path(gates),
                tree=str(tree),
                manifest=manifest,
                data=data,
                sha256=digest,
                pages=pages,
            )
        return cls.h4

    def startup_request(self, run_id, built=None, gate_name=None):
        """A startup-only request for run_id's own scratch gate and inputs,
        on the startup tree or built, in the gate gate_name if it is shared."""
        h2 = built or self.startup_tree()
        gate = h2.gates / (gate_name or run_id)
        gate.mkdir(mode=0o700, exist_ok=gate_name is not None)
        folder = self.work / ("h2-inputs-" + run_id)
        folder.mkdir(mode=0o700)
        inputs = {}
        for name in ("base", "payload"):
            data = f"inert {name} {run_id}\n".encode()
            (folder / name).write_bytes(data)
            (folder / name).chmod(0o400)
            inputs[name] = str(folder / name), sha(data)
        selection = {
            "run_id": run_id,
            "boot_input_sha256": inputs["base"][1],
            "build_sha256": "b" * 64,
            "input_manifest_sha256": h2.sha256,
            "mode": "boot-only",
            "cases": ["supervisor-only"],
            "first_epoch": 1,
            "qemu": "/usr/bin/qemu-system-x86_64",
            "base": inputs["base"][0],
            "payload": inputs["payload"][0],
            "overlay": f"{gate}/attempt-{run_id}/overlay.qcow2",
            "cpus": [0, 1],
        }
        path, digest = self.write_request(
            "h2-request-" + run_id,
            mode="startup-only",
            runtime=h2.tree,
            manifest=str(h2.manifest),
            manifest_sha256=h2.sha256,
            specification=selection,
            base_sha256=inputs["base"][1],
            payload_sha256=inputs["payload"][1],
        )
        return gate, path, digest

    def test_startup_only_runs_the_owner_from_the_tree_with_its_witness_bound(self):
        h2 = self.startup_tree()
        gate, path, digest = self.startup_request("h2-tree-run")
        poison = {**ENVIRONMENT, "LD_PRELOAD": "/untrusted.so", "PYTHONPATH": "/x"}
        inherited = os.open("/dev/null", os.O_RDONLY)
        try:
            os.dup2(inherited, 9, inheritable=True)
            result = self.run_command(
                "startup-only-scratch-gate",
                [h2.tree + "/opt/irlume/launcher", "--host", path, digest],
                poison,
                pass_fds=(9,),
            )
        finally:
            os.close(9)
            os.close(inherited)
        # H was admitted, wrote and bound its witness, passed the prestart
        # recheck and only then reached the (refusing) manager.
        self.refused(result, "test manager refused")
        attempt = gate / "attempt-h2-tree-run"
        self.assertEqual(
            sorted(os.listdir(attempt)),
            [
                "control.sock",
                "guardian-config.json",
                "host-intent.json",
                "host-witness.json",
            ],
        )
        witness = attempt / "host-witness.json"
        info = witness.lstat()
        self.assertEqual(
            (stat.S_IMODE(info.st_mode), info.st_nlink, info.st_uid),
            (0o400, 1, os.getuid()),
        )
        data = witness.read_bytes()
        self.assertLessEqual(len(data), host.WITNESS_LIMIT)
        wire = accepted(self, host.decode, data, DEPS, deadline())
        self.assertEqual((wire["runtime"], wire["request_sha256"]), (h2.tree, digest))
        observation = wire["observation"]
        accepted(
            self,
            host.validate,
            observation,
            h2.tree,
            h2.data,
            h2.sha256,
            h2.pages,
            DEPS,
        )
        intent_data = (attempt / "host-intent.json").read_bytes()
        intent = json.loads(intent_data)
        self.assertEqual(intent.get("scope"), "contained-job-rooted-host-intent-v2")
        self.assertEqual(intent.get("host_witness_sha256"), sha(data))
        claim = json.loads((gate / "active.json").read_bytes())
        self.assertEqual(bytes.fromhex(claim["intent_hex"]), intent_data)
        failure = json.loads((gate / "failed-h2-tree-run.json").read_bytes())
        self.assertEqual(
            (failure["reason"], failure["creation_attempted"], failure["created"]),
            ("ValueError", False, False),
        )
        # Neither R4's coordinator nor what it imports ran in this process.
        modules = observation["python"]["modules"]
        names = {row["name"] for row in modules}
        self.assertFalse(
            names & {"tomllib", "shutil", "zlib", "_bz2", "_lzma", "_zstd"}, names
        )
        self.assertFalse(
            [
                row["origin"]
                for row in modules
                if str(row["origin"]).endswith(
                    ("/measurement-job-guardian-host.py", "/measurement-job.py")
                )
            ]
        )
        self.assertIn("jeepney.io.blocking", names)
        record = {
            "witness_sha256": sha(data),
            "witness_bytes": len(data),
            "intent": intent,
            "failure": failure,
        }
        (self.evidence / "startup-only-scratch-gate-attempt.json").write_text(
            json.dumps(record, indent=2, sort_keys=True) + "\n"
        )

    def test_an_import_after_the_self_check_refuses_before_the_manager(self):
        h2 = self.startup_tree()
        gate, path, digest = self.startup_request("h2-import")
        result = self.run_command(
            "startup-only-import-after-self-check",
            self.through_loader(tree=h2.tree, request=path, digest=digest),
            dict(ENVIRONMENT),
        )
        # The gate factory imported a module; the recheck before the claim
        # refused, so no blocker or failure record was written and the
        # manager was never asked for anything.
        self.refused(result, "host modules changed after the self-check")
        self.assertEqual(
            sorted(os.listdir(gate)), ["admission.lock", "attempt-h2-import"]
        )
        self.assertEqual(
            sorted(os.listdir(gate / "attempt-h2-import")),
            [
                "control.sock",
                "guardian-config.json",
                "host-intent.json",
                "host-witness.json",
            ],
        )

    def test_a_failed_self_check_never_reaches_admission(self):
        h2 = self.startup_tree()
        gate, path, digest = self.startup_request("h2-unchecked")
        inherited = os.open("/dev/null", os.O_RDONLY)
        try:
            os.dup2(inherited, 5, inheritable=True)
            result = self.run_command(
                "startup-only-inherited-fd",
                self.through_loader(tree=h2.tree, request=path, digest=digest),
                dict(ENVIRONMENT),
                pass_fds=(5,),
            )
        finally:
            os.close(5)
            os.close(inherited)
        self.refused(result, "host descriptors")
        result = self.run_command(
            "startup-only-wrong-digest",
            [h2.tree + "/opt/irlume/launcher", "--host", path, "0" * 64],
            dict(ENVIRONMENT),
        )
        self.refused(result, "host request digest")
        self.assertEqual(os.listdir(gate), [])

    def resolve_file(self, label, run_id, commit):
        """A resolve request for the kill tree, the only tree it may run on."""
        h4 = self.kill_tree()
        return self.write_request(
            "h4-resolve-" + label,
            mode="resolve-failed-startup",
            runtime=h4.tree,
            manifest=str(h4.manifest),
            manifest_sha256=h4.sha256,
            run_id=run_id,
            commit=commit,
        )

    def resolve_tree(self, label, run_id, commit):
        """The resolve mode through the kill tree's launcher."""
        path, digest = self.resolve_file(label, run_id, commit)
        return self.run_command(
            "h4-" + label,
            [self.kill_tree().tree + "/opt/irlume/launcher", "--host", path, digest],
            dict(ENVIRONMENT),
        )

    def killed(self, label, run_id, gate_name):
        """H started through the launcher, killed by its own kill line."""
        h4 = self.kill_tree()
        gate, path, digest = self.startup_request(run_id, h4, gate_name)
        poison = {**ENVIRONMENT, "LD_PRELOAD": "/untrusted.so", "PYTHONPATH": "/x"}
        inherited = os.open("/dev/null", os.O_RDONLY)
        try:
            os.dup2(inherited, 9, inheritable=True)
            result = self.run_command(
                "h4-" + label,
                [h4.tree + "/opt/irlume/launcher", "--host", path, digest],
                poison,
                pass_fds=(9,),
            )
        finally:
            os.close(9)
            os.close(inherited)
        self.assertEqual(result.returncode, -9, result.stderr)
        self.assertEqual((result.stdout, result.stderr), (b"", b""))
        return gate

    def gate_state(self, gate):
        rows = {}
        for path in sorted(gate.rglob("*")):
            info = path.lstat()
            data = path.read_bytes() if stat.S_ISREG(info.st_mode) else b""
            rows[str(path.relative_to(gate))] = (info.st_ino, info.st_mode, sha(data))
        return rows

    def test_an_owner_killed_before_the_claim_leaves_no_blocker(self):
        run_id = "r5-h4-after-intent-g1"
        gate = self.killed("killed-before-claim", run_id, "g1")
        self.assertEqual(
            sorted(os.listdir(gate)), ["admission.lock", "attempt-" + run_id]
        )
        self.assertEqual(
            sorted(os.listdir(gate / ("attempt-" + run_id))),
            [
                "control.sock",
                "guardian-config.json",
                "host-intent.json",
                "host-witness.json",
            ],
        )
        before = self.gate_state(gate)
        result = self.resolve_tree("before-claim-resolve", run_id, True)
        self.refused(result, "resolver found no blocker")
        self.assertEqual(self.gate_state(gate), before)

    def test_an_owner_killed_after_the_claim_is_resolved_through_the_launcher(self):
        h4 = self.kill_tree()
        run_id = "r5-h4-after-claim-g2"
        gate = self.killed("killed-after-claim", run_id, "g2")
        self.assertEqual(
            sorted(os.listdir(gate)),
            ["active.json", "admission.lock", "attempt-" + run_id],
        )
        attempt = gate / ("attempt-" + run_id)
        self.assertEqual(
            sorted(os.listdir(attempt)),
            [
                "control.sock",
                "guardian-config.json",
                "host-intent.json",
                "host-witness.json",
            ],
        )
        config = json.loads((attempt / "guardian-config.json").read_bytes())
        end = config["origin_ns"] + 10_000_000_000
        self.assertEqual(
            config["startup_deadline_ns"], config["origin_ns"] + 5_000_000_000
        )
        before = self.gate_state(gate)
        early = self.resolve_tree("after-claim-early", run_id, True)
        # An early run that finished after the window would prove nothing.
        self.assertLess(time.monotonic_ns(), end, "host too slow for the early run")
        self.refused(early, "resolver startup window still open")
        self.assertEqual(self.gate_state(gate), before)
        # The window really passes once, here.
        time.sleep(max(0, end - time.monotonic_ns()) / 1_000_000_000)
        dry = self.resolve_tree("after-claim-dry", run_id, False)
        self.assertEqual(dry.returncode, 0, dry.stderr)
        self.assertEqual(self.gate_state(gate), before)
        result = self.resolve_tree("after-claim-commit", run_id, True)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stderr, b"")
        value = json.loads(result.stdout)
        self.assertEqual(closure.canonical(value), result.stdout)
        self.assertEqual(
            set(value),
            {
                "scope",
                "run_id",
                "committed",
                "admission_state",
                "record",
                "record_sha256",
                "witness",
                "witness_sha256",
                "accepted",
                "native_authorized",
                "full_contract_proven",
            },
        )
        self.assertEqual(value["scope"], "contained-job-host-resolution-result-v1")
        self.assertEqual(
            (value["run_id"], value["committed"], value["admission_state"]),
            (run_id, True, "absent"),
        )
        for flag in ("accepted", "native_authorized", "full_contract_proven"):
            self.assertIs(value[flag], False)
        record_data = bytes.fromhex(value["record"]["$bytes"])
        witness_data = bytes.fromhex(value["witness"]["$bytes"])
        self.assertEqual(value["record_sha256"], sha(record_data))
        self.assertEqual(value["witness_sha256"], sha(witness_data))
        wire = accepted(self, host.decode, witness_data, DEPS, deadline())
        accepted(
            self,
            host.validate,
            wire["observation"],
            h4.tree,
            h4.data,
            h4.sha256,
            h4.pages,
            DEPS,
        )
        request = json.loads(wire["observation"]["request_data"])
        self.assertEqual(
            (request["mode"], request["run_id"], request["commit"]),
            ("resolve-failed-startup", run_id, True),
        )
        record = json.loads(record_data)
        self.assertEqual(
            record["scope"], "contained-job-rooted-failed-attempt-resolution-v2"
        )
        self.assertEqual(record["outcome"], "lost-owner-resolved")
        self.assertEqual(record["unit_state"], "absent")
        self.assertEqual(
            record["invocation"], {"id": None, "source": None, "manager_path": None}
        )
        self.assertEqual((record["service"], record["failure_record"]), (None, None))
        self.assertEqual(record["client"]["state"], "absent")
        name = f"resolver-witness-{run_id}-{sha(witness_data)[:16]}.json"
        self.assertEqual(
            record["resolver_witness"],
            {"name": name, "sha256": sha(witness_data), "size": len(witness_data)},
        )
        self.assertEqual(
            sorted(os.listdir(gate)),
            sorted(
                [
                    "admission.lock",
                    "attempt-" + run_id,
                    "resolved-" + run_id + ".json",
                    name,
                ]
            ),
        )
        self.assertEqual(
            (gate / ("resolved-" + run_id + ".json")).read_bytes(), record_data
        )
        self.assertEqual((gate / name).read_bytes(), witness_data)
        self.assertEqual(stat.S_IMODE((gate / name).lstat().st_mode), 0o600)
        again = self.resolve_tree("after-claim-again", run_id, True)
        self.refused(again, "resolver found no blocker")
        # The next admission proceeds to its (refusing) manager, on the same bytes.
        following = "r5-h4-none-g2"
        _, path, digest = self.startup_request(following, h4, "g2")
        next_run = self.run_command(
            "h4-after-claim-next",
            [h4.tree + "/opt/irlume/launcher", "--host", path, digest],
            dict(ENVIRONMENT),
        )
        self.refused(next_run, "test manager refused")
        self.assertIn("active.json", os.listdir(gate))
        (self.evidence / "h4-after-claim-resolution.json").write_text(
            json.dumps(
                {
                    "witness_bytes": len(witness_data),
                    "stdout_bytes": len(result.stdout),
                    "record": record,
                },
                indent=2,
                sort_keys=True,
            )
            + "\n"
        )

    def test_a_failed_self_check_never_reaches_the_resolver(self):
        h4 = self.kill_tree()
        run_id = "r5-h4-unchecked-g3"
        gate = h4.gates / "g3"
        gate.mkdir(mode=0o700)
        path, digest = self.resolve_file("unchecked", run_id, True)
        inherited = os.open("/dev/null", os.O_RDONLY)
        try:
            os.dup2(inherited, 5, inheritable=True)
            result = self.run_command(
                "h4-resolve-inherited-fd",
                self.through_loader(tree=h4.tree, request=path, digest=digest),
                dict(ENVIRONMENT),
                pass_fds=(5,),
            )
        finally:
            os.close(5)
            os.close(inherited)
        self.refused(result, "host descriptors")
        result = self.run_command(
            "h4-resolve-wrong-digest",
            [h4.tree + "/opt/irlume/launcher", "--host", path, "0" * 64],
            dict(ENVIRONMENT),
        )
        self.refused(result, "host request digest")
        self.assertEqual(os.listdir(gate), [])

    def test_a_held_gate_refuses_the_resolver(self):
        run_id = "r5-h4-held-g4"
        gate = self.kill_tree().gates / "g4"
        gate.mkdir(mode=0o700)
        lock = os.open(gate / "admission.lock", os.O_RDWR | os.O_CREAT, 0o600)
        self.addCleanup(os.close, lock)
        fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        before = self.gate_state(gate)
        result = self.resolve_tree("resolve-held-gate", run_id, True)
        self.refused(result, "OSError EAGAIN")
        self.assertEqual(self.gate_state(gate), before)

    def test_tree_loader_with_the_exact_environment_passes_without_the_launcher(self):
        # The control for the refusals above: the checks, not the launcher, decide.
        wire = self.decoded(
            self.run_command("loader-control", self.through_loader(), dict(ENVIRONMENT))
        )
        self.assertEqual(wire["runtime"], self.tree)


if __name__ == "__main__":
    unittest.main()

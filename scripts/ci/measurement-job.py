#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright the irlume contributors.
"""Private contained-job input/receipt support, not a runtime or admission API.

Expected identities come from the caller's separately reviewed inputs, never
from a profile or guest claim. The explicit Task3 build lane compiles separate
native products without executing them. All runtime entry points stay inactive.
"""

import contextlib
import hashlib
import importlib.util
import json
import os
import re
import selectors
import shutil
import signal
import stat
import subprocess
import sys
import time
from pathlib import Path, PurePosixPath
from typing import NamedTuple

import tomllib

SCOPE = "contained-job-lifetime-v1"
PROFILE_LIMIT = 64 * 1024
EVIDENCE_LIMIT = 32 * 1024 * 1024
ROLES = ("base", "payload", "guest_entry", "validator", "qemu", "qemu_img", "recovery")
LIMITS = {
    "vcpus": 2,
    "memory_mib": 2048,
    "batch_cases": 6,
    "guest_seconds": 150,
    "host_seconds": 300,
    "stop_seconds": 5,
    "recovery_seconds": 60,
    "serial_bytes": 8 * 1024 * 1024,
    "evidence_bytes": EVIDENCE_LIMIT,
    "scratch_bytes": 16 * 1024**3,
}
OUTCOMES = {"fixture_complete", "aborted_clean", "unsupported", "cleanup_incomplete"}


class Expected(NamedTuple):
    """Out-of-band pins and exact batch, not a self-authenticating JSON object.

    boot_id is the selected boot-input identity, not a guest's /proc boot UUID.
    Matching it corroborates selection; it cannot authenticate a boot chain.
    """

    run_id: str
    boot_id: str
    epoch: int
    cases: tuple
    inputs: tuple


def identifier(value):
    if (
        type(value) is not str
        or re.fullmatch(r"[a-z0-9][a-z0-9-]{0,63}", value) is None
    ):
        raise ValueError("invalid identity")


def safe_path(value):
    if (
        type(value) is not str
        or len(value) > 4096
        or not value.startswith("/")
        or value == "/"
        or "//" in value
        or any(
            part in ("", ".", "..") or re.fullmatch(r"[A-Za-z0-9_.-]+", part) is None
            for part in value.split("/")[1:]
        )
    ):
        raise ValueError("unsafe path")
    return PurePosixPath(value)


def integer(value, low, high):
    if type(value) is not int or not low <= value <= high:
        raise ValueError("invalid integer")


def fields(row, names):
    if type(row) is not dict or set(row) != set(names):
        raise ValueError("invalid fields")


def strict_json(data, limit):
    if type(data) is not bytes or not 0 < len(data) <= limit:
        raise ValueError("invalid JSON size")

    def pairs(items):
        result = {}
        for key, value in items:
            if key in result:
                raise ValueError("duplicate JSON key")
            result[key] = value
        return result

    def number(text):
        if len(text) > 20:
            raise ValueError("oversized integer")
        return int(text)

    def constant(_):
        raise ValueError("nonfinite number")

    try:
        return json.loads(
            data.decode("utf-8"),
            object_pairs_hook=pairs,
            parse_int=number,
            parse_constant=constant,
        )
    except (UnicodeError, RecursionError) as error:
        raise ValueError("invalid JSON") from error


def check_expected(want):
    if type(want) is not Expected:
        raise ValueError("separate expectations required")
    identifier(want.run_id)
    identifier(want.boot_id)
    integer(want.epoch, 1, 2**64 - 1)
    if (
        type(want.cases) is not tuple
        or not 1 <= len(want.cases) <= LIMITS["batch_cases"]
    ):
        raise ValueError("invalid batch")
    seen = set()
    for case in want.cases:
        if type(case) is not tuple or len(case) != 2:
            raise ValueError("invalid case")
        name, outcome = case
        identifier(name)
        if name in seen or type(outcome) is not str or outcome not in OUTCOMES:
            raise ValueError("invalid case outcome")
        seen.add(name)
    if type(want.inputs) is not tuple or len(want.inputs) != len(ROLES):
        raise ValueError("missing input pins")
    roles, paths = set(), set()
    for item in want.inputs:
        if type(item) is not tuple or len(item) != 3:
            raise ValueError("invalid pin")
        role, path, digest = item
        safe_path(path)
        if (
            type(role) is not str
            or role not in ROLES
            or role in roles
            or path in paths
            or type(digest) is not str
            or re.fullmatch(r"[0-9a-f]{64}", digest) is None
        ):
            raise ValueError("invalid pin")
        roles.add(role)
        paths.add(path)


def parse_profile(data, want):
    check_expected(want)
    row = strict_json(data, PROFILE_LIMIT)
    fields(
        row,
        (
            "scope",
            "run_id",
            "boot_id",
            "epoch",
            "cases",
            "inputs",
            "host_loss",
            "limits",
        ),
    )
    integer(row["epoch"], 1, 2**64 - 1)
    if (
        row["scope"] != SCOPE
        or row["run_id"] != want.run_id
        or row["boot_id"] != want.boot_id
        or row["epoch"] != want.epoch
        or row["cases"] != [list(case) for case in want.cases]
    ):
        raise ValueError("profile identity mismatch")
    fields(row["inputs"], ROLES)
    for role, path, digest in want.inputs:
        item = row["inputs"][role]
        fields(item, ("path", "sha256"))
        if item != {"path": path, "sha256": digest}:
            raise ValueError("profile pin mismatch")
    fields(row["limits"], LIMITS)
    for key, value in LIMITS.items():
        if type(row["limits"][key]) is not int or row["limits"][key] != value:
            raise ValueError("unreviewed bound")
    fields(row["host_loss"], ("owner", "mechanism"))
    identifier(row["host_loss"]["owner"])
    if row["host_loss"]["mechanism"] not in ("external-watchdog", "recovery-owner"):
        raise ValueError("host loss handling required")
    return row


def validate_evidence(data, want):
    """Validate model records only. Even a match is never a runtime acceptance."""
    check_expected(want)
    row = strict_json(data, EVIDENCE_LIMIT)
    fields(
        row,
        (
            "scope",
            "mode",
            "run_id",
            "boot_id",
            "epoch",
            "hashes",
            "cases",
            "native_authorized",
            "full_contract_proven",
            "complete",
            "expected_cases",
        ),
    )
    integer(row["epoch"], 1, 2**64 - 1)
    integer(row["expected_cases"], 1, LIMITS["batch_cases"])
    if (
        row["scope"] != SCOPE
        or row["mode"] != "model"
        or row["run_id"] != want.run_id
        or row["boot_id"] != want.boot_id
        or row["epoch"] != want.epoch
        or row["hashes"] != {role: digest for role, _, digest in want.inputs}
        or row["complete"] is not True
        or row["native_authorized"] is not False
        or row["full_contract_proven"] is not False
        or row["expected_cases"] != len(want.cases)
        or type(row["cases"]) is not list
        or len(row["cases"]) != len(want.cases)
    ):
        raise ValueError("incomplete or mismatched evidence")
    for case, (name, outcome) in zip(row["cases"], want.cases, strict=True):
        fields(
            case,
            (
                "id",
                "epoch",
                "outcome",
                "reason",
                "cleanup",
                "total_j_empty",
                "fully_reaped",
                "consumers",
                "leases_released",
                "custody_retained",
            ),
        )
        integer(case["epoch"], 1, 2**64 - 1)
        integer(case["consumers"], 0, 2**32 - 1)
        if (
            case["id"] != name
            or case["epoch"] != want.epoch
            or case["outcome"] != outcome
        ):
            raise ValueError("case identity mismatch")
        for flag in (
            "total_j_empty",
            "fully_reaped",
            "leases_released",
            "custody_retained",
        ):
            if type(case[flag]) is not bool:
                raise ValueError("invalid cleanup flag")
        reason = case["reason"]
        reasons = {"supervisor_lost", "expired", "operation_failed", "unsupported"}
        if reason is not None and (type(reason) is not str or reason not in reasons):
            raise ValueError("invalid reason")
        if (
            (outcome == "fixture_complete" and reason is not None)
            or (outcome == "unsupported" and reason != "unsupported")
            or (outcome == "aborted_clean" and reason not in reasons - {"unsupported"})
        ):
            raise ValueError("conflicting outcome/reason")
        if outcome == "cleanup_incomplete":
            if (
                case["cleanup"] != "incomplete"
                or case["leases_released"]
                or not case["custody_retained"]
            ):
                raise ValueError("incomplete cleanup lost custody")
        elif (
            case["cleanup"] != "complete"
            or not case["total_j_empty"]
            or not case["fully_reaped"]
            or case["consumers"] != 0
            or not case["leases_released"]
            or case["custody_retained"]
        ):
            raise ValueError("missing total cleanup")
    return {
        "model_matched": True,
        "accepted": False,
        "native_authorized": False,
        "full_contract_proven": False,
    }


def open_directory(path):
    """Walk without following symlinks. Sticky root-owned /tmp is an ancestor only."""
    parts = safe_path(str(path)).parts
    fd = os.open("/", os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC)
    try:
        for part in parts[1:]:
            child = os.open(
                part,
                os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC,
                dir_fd=fd,
            )
            previous = fd
            fd = child
            # close() can release a descriptor and still raise. Guard the new
            # child first; never retry the old number after a close failure.
            os.close(previous)
            info = os.fstat(fd)
            sticky_root = info.st_uid == 0 and bool(info.st_mode & stat.S_ISVTX)
            if info.st_uid not in (0, os.getuid()) or (
                info.st_mode & 0o022 and not sticky_root
            ):
                raise ValueError("untrusted directory ancestry")
        return fd
    except BaseException:
        os.close(fd)
        raise


class OwnedOutput:
    """Fresh output only, retained by descriptor; never delete or overwrite evidence.

    Receipt writes sync their file and this directory. Creation does not sync
    the parent, so survival of the new directory name across power loss is not
    claimed. Failed creation/validation leaves partial artifacts in place.
    """

    def __init__(self, fd):
        self.fd = fd

    @classmethod
    def create(cls, path):
        path = safe_path(str(path))
        parent = open_directory(str(path.parent))
        fd = None
        try:
            try:
                info = os.fstat(parent)
                if info.st_uid != os.getuid() or info.st_mode & 0o022:
                    raise ValueError("output parent must be privately owned")
                os.mkdir(path.name, 0o700, dir_fd=parent)
                fd = os.open(
                    path.name,
                    os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC,
                    dir_fd=parent,
                )
                info = os.fstat(fd)
                if info.st_uid != os.getuid() or info.st_mode & 0o077:
                    raise ValueError("unsafe fresh output")
            finally:
                os.close(parent)
            return cls(fd)
        except BaseException:
            if fd is not None:
                os.close(fd)
            raise

    def save(self, label, row):
        data = (json.dumps(row, sort_keys=True, allow_nan=False) + "\n").encode()
        self._write(label, data, PROFILE_LIMIT)

    def save_blob(self, label, data):
        self._write(label, data, EVIDENCE_LIMIT)

    def _write(self, label, data, limit):
        identifier(label)
        if type(data) is not bytes or len(data) > limit:
            raise ValueError("oversized receipt/evidence")
        fd = os.open(
            label + ".json",
            os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC,
            0o600,
            dir_fd=self.fd,
        )
        try:
            view = memoryview(data)
            while view:
                count = os.write(fd, view)
                if count <= 0:
                    raise OSError("short receipt write")
                view = view[count:]
            os.fsync(fd)
            os.fsync(self.fd)
        finally:
            os.close(fd)

    def close(self):
        os.close(self.fd)


def observe_input(path, *, limit, deadline):
    """Read-only, descriptor-bound digest with finite size and elapsed-time checks.

    Regular-file kernel I/O can still stall in the kernel; Task2 does not claim
    an independent I/O watchdog. Real execution remains unavailable.
    """
    path = safe_path(path)
    parent = open_directory(str(path.parent))
    fd = None
    try:
        try:
            fd = os.open(
                path.name,
                os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC,
                dir_fd=parent,
            )
        finally:
            os.close(parent)
        before = os.fstat(fd)
        if (
            not stat.S_ISREG(before.st_mode)
            or before.st_uid not in (0, os.getuid())
            or before.st_mode & 0o6022
            or not 0 < before.st_size <= limit
        ):
            raise ValueError("unsafe input file")
        digest, count = hashlib.sha256(), 0
        while True:
            if time.monotonic() >= deadline:
                raise TimeoutError("input observation deadline")
            data = os.read(fd, min(1024 * 1024, limit + 1 - count))
            if not data:
                break
            count += len(data)
            if count > limit:
                raise ValueError("oversized input")
            digest.update(data)
        after = os.fstat(fd)
        identity = lambda info: (
            info.st_dev,
            info.st_ino,
            info.st_size,
            info.st_mtime_ns,
            info.st_ctime_ns,
        )
        if identity(before) != identity(after) or count != before.st_size:
            raise ValueError("input changed during observation")
        return digest.hexdigest()
    finally:
        if fd is not None:
            os.close(fd)


def build_bytes(path, limit=64 * 1024 * 1024):
    """Bound trusted source/tool/artifact reads; no hard kernel-I/O deadline."""
    with Path(path).open("rb") as source:
        info = os.fstat(source.fileno())
        if not stat.S_ISREG(info.st_mode) or not 0 < info.st_size <= limit:
            raise ValueError("invalid build input size/type")
        data = source.read(limit + 1)
        if len(data) != info.st_size or len(data) > limit:
            raise ValueError("changed or oversized build input")
        return data


class FrozenPins:
    """Immutable input identities, with a reader seam for memory-only tests."""

    def __init__(self, paths, *, reader=None):
        self.reader = reader or build_bytes
        self.hashes = {
            str(path): hashlib.sha256(self.reader(str(path))).hexdigest()
            for path in paths
        }

    def add(self, path):
        path = str(path)
        if path in self.hashes:
            raise ValueError("cannot overwrite a frozen pin")
        self.hashes[path] = hashlib.sha256(self.reader(path)).hexdigest()

    def check(self):
        for path, expected in self.hashes.items():
            if hashlib.sha256(self.reader(path)).hexdigest() != expected:
                raise RuntimeError("changed build input: " + path)


def check_suite(expected, actual, *, success, skipped, expected_failures=0):
    """Reject missing, duplicated, skipped or unsuccessful selected tests."""
    if (
        success is not True
        or skipped != 0
        or expected_failures != 0
        or not expected
        or len(set(expected)) != len(expected)
        or len(actual) != len(expected)
        or set(actual) != set(expected)
    ):
        raise RuntimeError("incomplete selected test inventory")


def directory_inventory(path):
    directory = Path(path)
    if not directory.is_dir() or directory.is_symlink():
        raise RuntimeError("invalid dependency directory")
    files = sorted(directory.rglob("*"))
    if len(files) > 4096:
        raise RuntimeError("dependency inventory too large")
    inventory = {}
    for file in files:
        if file.is_symlink():
            raise RuntimeError("symlink in dependency inventory")
        if file.is_dir():
            inventory[str(file.relative_to(directory))] = "directory"
        else:
            inventory[str(file.relative_to(directory))] = hashlib.sha256(
                build_bytes(file)
            ).hexdigest()
    return inventory


class FrozenDirectories:
    """Freeze contents and membership, including transitive rustc search inputs."""

    def __init__(self, paths, *, inventory=directory_inventory):
        self.inventory = inventory
        self.hashes = {str(path): dict(inventory(path)) for path in paths}

    def check(self):
        for path, expected in self.hashes.items():
            if self.inventory(path) != expected:
                raise RuntimeError("changed dependency directory: " + path)


def optional_config(path):
    try:
        info = Path(path).lstat()
    except FileNotFoundError:
        return None
    if not stat.S_ISREG(info.st_mode) or info.st_size > PROFILE_LIMIT:
        raise RuntimeError("unsupported Cargo configuration file")
    with Path(path).open("rb") as source:
        data = source.read(PROFILE_LIMIT + 1)
    if len(data) != info.st_size:
        raise RuntimeError("changed Cargo configuration read")
    return data


class CargoConfigurations:
    """Pin Cargo 1.88's ancestor/home config paths, including absence facts.

    This narrow lane accepts only empty/comment-only configurations. Rejecting
    nonempty files avoids merges, config includes, env injection and wrappers
    without changing the user's configuration. Both legacy and .toml names are
    frozen, even when Cargo would give the legacy spelling precedence.
    """

    def __init__(self, root, environment, *, reader=optional_config):
        root = Path(root)
        cargo_home = environment.get("CARGO_HOME")
        if cargo_home is None:
            cargo_home = str(Path(environment["HOME"]) / ".cargo")
        home = Path(cargo_home)
        if not home.is_absolute():
            home = root / home
        directories = [path / ".cargo" for path in (root, *root.parents)] + [home]
        paths = dict.fromkeys(
            str(path / name)
            for path in directories
            for name in ("config", "config.toml")
        )
        self.reader = reader
        self.hashes = {}
        for path in paths:
            data = reader(path)
            if data is not None and tomllib.loads(data.decode("utf-8")):
                raise RuntimeError(
                    "nonempty Cargo configuration is unsupported: " + path
                )
            self.hashes[path] = (
                None if data is None else hashlib.sha256(data).hexdigest()
            )

    def check(self):
        for path, expected in self.hashes.items():
            data = self.reader(path)
            actual = None if data is None else hashlib.sha256(data).hexdigest()
            if actual != expected:
                raise RuntimeError("changed Cargo configuration: " + path)


EXPECTED_CONTROLS = {
    "active_compile_negative": ("active-control",),
    "active_lint_negative": (
        "missing_errors_doc",
        "missing_panics_doc",
        "undocumented_unsafe_blocks",
    ),
}


def check_controls(controls):
    if type(controls) is not dict or set(controls) != set(EXPECTED_CONTROLS):
        raise RuntimeError("missing compiler controls")
    for name, expected in EXPECTED_CONTROLS.items():
        row = controls[name]
        if (
            type(row.get("status")) is not int
            or row["status"] == 0
            or row.get("expected") != list(expected)
        ):
            raise RuntimeError("invalid compiler control diagnostics/status")


def check_legacy_refusal(status, stderr, source):
    """Require the pinned compiler to reject both fresh-clock entry imports."""
    if (
        type(status) is not int
        or status == 0
        or type(stderr) is not str
        or len(stderr) > PROFILE_LIMIT
    ):
        raise RuntimeError("legacy entry control did not fail as expected")
    try:
        records = [
            strict_json(line.encode(), PROFILE_LIMIT)
            for line in stderr.splitlines()
            if line.strip()
        ]
    except (ValueError, UnicodeError) as error:
        raise RuntimeError("invalid legacy control diagnostics") from error
    if any(type(row) is not dict for row in records):
        raise RuntimeError("invalid legacy control diagnostics")
    errors = [
        row
        for row in records
        if row.get("level") == "error" and row.get("code") is not None
    ]
    if len(errors) != 1:
        raise RuntimeError("legacy control failed for another reason")
    error = errors[0]
    spans = error.get("spans")
    if (
        type(error.get("code")) is not dict
        or error["code"].get("code") != "E0432"
        or error.get("message")
        != "unresolved imports `kernel::run`, `kernel::run_case`"
        or type(spans) is not list
        or any(type(span) is not dict for span in spans)
    ):
        raise RuntimeError("legacy control did not reject both entry points")
    primary = [span for span in spans if span.get("is_primary") is True]
    if not primary or any(span.get("file_name") != str(source) for span in primary):
        raise RuntimeError("legacy control diagnostic source mismatch")


def check_bounds_codegen(ir):
    """Require compiled sentinel operations; no runtime property is inferred."""
    for pattern in (
        r"\bcall\b[^\n]*@memfd_create\(",
        r"\bcall\b[^\n]*@fcntl\(",
        r"irlume-job-custody-v1",
    ):
        if re.search(pattern, ir) is None:
            raise RuntimeError("missing bounds codegen evidence: " + pattern)


def check_child_codegen(ir):
    """Require emitted child-protocol operations; this does not execute them."""
    for pattern in (
        r"\bcall\b[^\n]*@recvmsg\(",
        r"\bcall\b[^\n]*@sendmsg\(",
        r"\bcall\b[^\n]*@setsid\(",
        r"\bcall\b[^\n]*@syscall\(i64 noundef 424,",
        r"store i64 4096,",
        r"memory\.events\.local",
    ):
        if re.search(pattern, ir) is None:
            raise RuntimeError("missing child codegen evidence: " + pattern)


def check_native_codegen(ir, dependencies, required_sources):
    """Require emitted bodies/calls, not just source names or declarations."""
    root = re.search(
        r"^define[^\n]*task3_native_root[^\n]*\{\n(.*?)^\}",
        ir,
        re.MULTILINE | re.DOTALL,
    )
    if root is None or re.search(r"\bcall\b[^\n]*3sys3run", root[1]) is None:
        raise RuntimeError("missing concrete native root body")
    for pattern in (
        r"\bcall\b[^\n]*@syscall\(i64 noundef 435,[^\n]*i64 noundef 88\)",
        r"\bcall\b[^\n]*@clock_gettime\(i32 noundef 7,",
        r"\bcall\b[^\n]*@waitid\(",
        r"store i64 8589938688,",
        r"cgroup\.kill",
    ):
        if re.search(pattern, ir) is None:
            raise RuntimeError("missing native codegen evidence: " + pattern)
    for path in required_sources:
        if str(path) not in dependencies:
            raise RuntimeError("native dep-info missing: " + str(path))


class ExecutionAllowlist:
    """Only an exact pure-test or inactive-entry product may execute."""

    def __init__(self):
        self.products = {}

    def add(self, path, kind, digest):
        path = str(path)
        if kind not in ("pure", "inactive") or path in self.products:
            raise ValueError("non-executable or duplicate build product")
        self.products[str(path)] = (kind, digest)

    def check(self, path, digest):
        if str(path) not in self.products or self.products[str(path)][1] != digest:
            raise ValueError("product is not approved for execution")


COMPILER_OWNERS = {}
# All throwables cross owned-process finalization. They are recorded here and
# re-raised below, including cancellation and unexpected BaseException types.
FINALIZATION_FAILURES = (BaseException,)


class BuildCancelled(RuntimeError):
    """Deferred parent cancellation; the owned compiler is finalized first."""


@contextlib.contextmanager
def deferred_compiler_signals(errors):
    """Defer Python handlers, not OS signal masks inherited by the compiler."""
    pending = []
    previous = {}
    try:
        try:
            for number in (signal.SIGINT, signal.SIGTERM):
                previous[number] = signal.getsignal(number)
                signal.signal(number, lambda number, frame: pending.append(number))
        except FINALIZATION_FAILURES as error:
            errors.append(error)
        yield pending
    finally:
        for number, handler in previous.items():
            try:
                signal.signal(number, handler)
            except FINALIZATION_FAILURES as error:
                # Finish every restore and the caller's receipts/owner removal.
                errors.append(error)


def create_owned_compiler(owner, command, **options):
    """Adopt before CPython's fallible initializer, not after Popen returns.

    The POSIX 3.11-3.14 source stores public returncode after its internal
    exec-failure wait. An incomplete initializer without a published pid is
    still unknown. Other runtimes need a reviewed constructor contract and
    are refused before allocation.
    """
    if (
        sys.implementation.name != "cpython"
        or os.name != "posix"
        or not (3, 11) <= sys.version_info[:2] <= (3, 14)
    ):
        raise RuntimeError("unsupported compiler process constructor")
    process = subprocess.Popen.__new__(subprocess.Popen)
    owner.process = process
    owner.construction = "initializing"
    owner.no_child = False
    subprocess.Popen.__init__(process, command, **options)
    owner.construction = "returned"


class CompilerCommand:
    """One owned compiler/session, kept unreaped until its group is stopped.

    Fatal interpreter loss and kernel-stalled I/O remain outside this in-process
    owner. Deferred INT/TERM spans Popen construction, collection and teardown.
    No preexec hook or child signal-mask modification is used.
    """

    def __init__(self, label, deadline, emit, *, limit=8 * 1024 * 1024):
        self.label, self.deadline, self.emit, self.limit = label, deadline, emit, limit
        self.process = None
        self.stdout, self.stderr = bytearray(), bytearray()
        self.reaped = False
        self.group_stopped = False
        self.construction = "not-started"
        self.no_child = True
        self.constructor_reaped = False

    def _stop_and_reap(self):
        pid = getattr(self.process, "pid", None)
        status = getattr(self.process, "returncode", None)
        if type(pid) is not int or pid <= 0:
            raise RuntimeError("compiler construction identity unknown")
        if (
            self.construction == "initializing"
            and type(status) is int
            and status != sys.maxsize
        ):
            # CPython already consumed the exec-failed child. Its PID can now
            # belong to someone else: never signal or wait on that number.
            self.reaped = self.constructor_reaped = True
            return status
        if status is not None:
            raise RuntimeError("compiler construction reap state unknown")
        # WNOWAIT retains the leader's PID/session until the group is stopped.
        observed = os.waitid(os.P_PID, pid, os.WEXITED | os.WNOHANG | os.WNOWAIT)
        if observed is not None and (
            observed.si_pid != pid
            or observed.si_code not in (os.CLD_EXITED, os.CLD_KILLED, os.CLD_DUMPED)
        ):
            raise RuntimeError("compiler identity unknown at cleanup")
        try:
            os.killpg(pid, signal.SIGKILL)
        except ProcessLookupError as error:
            if self.construction == "initializing":
                # The child may not have reached setsid yet. Keep the leader
                # unreaped; its later group must not escape our ownership.
                raise RuntimeError("compiler process group not established") from error
        self.group_stopped = True
        remaining = self.deadline - time.monotonic()
        if remaining <= 0:
            raise TimeoutError("compiler cleanup deadline")
        status = self.process.wait(timeout=min(5, remaining))
        self.reaped = True
        return status

    def run(self, command, environment, *, cwd=None):
        if self.label in COMPILER_OWNERS:
            raise RuntimeError("duplicate compiler owner")
        COMPILER_OWNERS[self.label] = (
            self  # Exists even across interrupted construction.
        )
        first, secondary, status = None, [], None
        selector = None
        started = time.monotonic()
        command_end = min(self.deadline - 5, started + 180)
        with deferred_compiler_signals(secondary) as pending:
            try:
                if secondary:
                    raise secondary.pop(0)
                if started >= command_end:
                    raise TimeoutError("compiler aggregate deadline")
                create_owned_compiler(
                    self,
                    command,
                    stdin=subprocess.DEVNULL,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    env=environment,
                    close_fds=True,
                    start_new_session=True,
                    cwd=cwd,
                )
                selector = selectors.DefaultSelector()
                streams = {}
                for stream, destination in (
                    (self.process.stdout, self.stdout),
                    (self.process.stderr, self.stderr),
                ):
                    descriptor = stream.fileno()
                    streams[descriptor] = destination
                    os.set_blocking(descriptor, False)
                    selector.register(descriptor, selectors.EVENT_READ)
                terminal = False
                while streams or not terminal:
                    if pending:
                        raise BuildCancelled("compiler cancellation")
                    now = time.monotonic()
                    if now >= command_end:
                        raise TimeoutError("compiler command deadline")
                    observed = os.waitid(
                        os.P_PID, self.process.pid, os.WEXITED | os.WNOHANG | os.WNOWAIT
                    )
                    if observed is not None:
                        if (
                            observed.si_pid != self.process.pid
                            or observed.si_code
                            not in (os.CLD_EXITED, os.CLD_KILLED, os.CLD_DUMPED)
                        ):
                            raise RuntimeError("invalid compiler terminal observation")
                        terminal = True
                    for key, _ in selector.select(min(0.05, command_end - now)):
                        try:
                            data = os.read(key.fd, 65536)
                        except (BlockingIOError, InterruptedError):
                            continue
                        if not data:
                            selector.unregister(key.fd)
                            streams.pop(key.fd)
                        else:
                            remaining = self.limit - len(self.stdout) - len(self.stderr)
                            streams[key.fd].extend(data[: max(0, remaining)])
                            if len(data) > remaining:
                                raise RuntimeError("compiler output cap")
                    if time.monotonic() >= command_end:
                        raise TimeoutError("late compiler completion")
            except FINALIZATION_FAILURES as error:
                first = error
            finally:
                if selector is not None:
                    try:
                        selector.close()
                    except FINALIZATION_FAILURES as error:
                        secondary.append(error)
                if self.process is not None:
                    try:
                        status = self._stop_and_reap()
                        if time.monotonic() >= self.deadline:
                            raise TimeoutError("compiler cleanup deadline after reap")
                    except FINALIZATION_FAILURES as error:
                        secondary.append(error)
                    if self.reaped or self.no_child:
                        for stream in (
                            getattr(self.process, "stdout", None),
                            getattr(self.process, "stderr", None),
                        ):
                            if stream is None:
                                continue
                            try:
                                stream.close()
                            except FINALIZATION_FAILURES as error:
                                secondary.append(error)
                if pending and first is None:
                    first = BuildCancelled("compiler cancellation")
        if self.reaped or self.no_child:
            COMPILER_OWNERS.pop(self.label)
        record = {
            "argv": command,
            "started": started,
            "deadline": command_end,
            "aggregate_deadline": self.deadline,
            "returncode": status,
            "reaped": self.reaped,
            "no_child": self.no_child,
            "construction": self.construction,
            "constructor_reaped": self.constructor_reaped,
            "pid": getattr(self.process, "pid", None),
            "group_stopped_before_reap": self.group_stopped,
            "owner_retained": self.label in COMPILER_OWNERS,
            "first": None if first is None else f"{type(first).__name__}: {first}",
            "secondary": [f"{type(error).__name__}: {error}" for error in secondary],
        }
        try:
            self.emit(self.label, record, bytes(self.stdout), bytes(self.stderr))
        except FINALIZATION_FAILURES as error:
            secondary.append(error)
        if first is not None:
            for error in secondary:
                first.add_note(f"secondary: {type(error).__name__}: {error}")
            raise first
        if secondary:
            for error in secondary[1:]:
                secondary[0].add_note(f"secondary: {type(error).__name__}: {error}")
            raise secondary[0]
        return subprocess.CompletedProcess(
            command,
            status,
            self.stdout.decode("utf-8", "backslashreplace"),
            self.stderr.decode("utf-8", "backslashreplace"),
        )


RUST_TESTS = (
    "kernel::tests::r2a_clock_regression_after_birth_retains_custody",
    "kernel::tests::r2a_reservation_requires_exact_finite_origin_budget",
    "kernel::tests::r2a_delayed_entry_does_not_restart_phase_or_total_caps",
    "kernel::tests::r2a_invalid_reservation_refuses_before_any_os_effect",
    "kernel::tests::r2a_pre_origin_and_expired_start_refuse_before_acquisition",
    "kernel::tests::r2a_clean_completion_retains_original_finalization_deadline",
    "kernel::tests::r2a_quarantine_and_late_native_return_cannot_refresh_budget",
    "kernel::tests::b01_complete_requires_cutover_and_returns_owned_sentinel",
    "kernel::tests::b02_withheld_predicates_retain_sentinel_and_leases",
    "kernel::tests::b03_native_cadence_stalls_reach_deadline_before_operation_cap",
    "kernel::tests::b04_bounds_case_inventory_is_exact_and_unique",
    "kernel::tests::b05_valid_result_cannot_replace_terminal_worker_or_complete_record",
    "kernel::tests::b06_near_startup_limit_and_stopped_clock_preserve_both_bounds",
    "kernel::tests::b07_sentinel_survives_each_initialization_and_final_guard_failure",
    "kernel::tests::b08_unreached_fault_or_unrelated_error_cannot_pass_negative_case",
    "kernel::tests::b09_supervisor_loss_before_cutover_never_commits_success",
    "kernel::tests::b10_channel_budget_refusal_retains_delivered_descriptors",
    "kernel::tests::b11_withholding_case_rejects_combined_sentinel_failure",
    "kernel::tests::b12_replay_requires_a_well_formed_completion_frame",
    "kernel::tests::b13_late_result_retains_exact_frame_and_postcheck_time",
    "kernel::tests::b20_complete",
    "kernel::tests::b21_supervisor_stall",
    "kernel::tests::b22_worker_stall",
    "kernel::tests::b23_extension_flood",
    "kernel::tests::b24_output_flood",
    "kernel::tests::b25_replay",
    "kernel::tests::b26_late_read",
    "kernel::tests::b27_pre_cutover_loss",
    "kernel::tests::b28_withheld_wait",
    "kernel::tests::b29_withheld_population",
    "kernel::tests::b30_withheld_consumer",
    "kernel::tests::b31_withheld_sentinel",
    "kernel::bounds::tests::output_exhaustion_is_sticky_and_checked",
    "kernel::bounds::tests::sentinel_is_fixed_public_data_bound_to_epoch",
    "kernel::bounds::tests::sentinel_requires_all_seals_exact_data_size_and_nonexec_regular_mode",
    "kernel::tests::c19_membership_requires_complete_exact_unordered_unique_live_set",
    "kernel::tests::c20_pidfd_record_matches_one_visible_namespace_and_owned_pid",
    "kernel::tests::c21_each_loss_cut_requires_its_actual_witness_and_complete_reaping",
    "kernel::tests::c22_unreached_cut_or_oom_cannot_be_credited_as_injection",
    "kernel::tests::c23_delivered_handle_survives_postcheck_failure_and_is_closed_once",
    "kernel::tests::c24_partial_positive_send_transfers_rights_only_once",
    "kernel::tests::c25_oom_evidence_must_be_complete_unique_and_numeric",
    "kernel::tests::c26_double_fork_and_zombie_require_every_adopted_wait",
    "kernel::tests::c27_rejected_and_fragmented_rights_preserve_exact_handle_ownership",
    "kernel::tests::c28_leaf_only_cleanup_and_unverified_placement_cannot_complete",
    "kernel::tests::c29_natural_or_wrong_signal_exit_is_not_an_effective_cut",
    "kernel::tests::c30_born_identity_is_epoch_bound_and_disjoint",
    "kernel::tests::c31_oom_before_injection_stops_signaling_not_only_case_acceptance",
    "kernel::tests::c32_delivery_cut_precedes_all_registration_validation",
    "kernel::tests::c33_complete_birth_is_owned_before_final_fragment_postcheck",
    "kernel::tests::c34_leaf_local_ooms_cannot_hide_behind_zero_parent_counter",
    "kernel::tests::c35_before_birth",
    "kernel::tests::c36_before_delivery",
    "kernel::tests::c37_before_registration",
    "kernel::tests::c38_before_placement",
    "kernel::tests::c39_before_readback",
    "kernel::tests::c40_after_readback",
    "kernel::tests::c04_initialization_refusal_releases_only_unstarted_owner",
    "kernel::tests::c04_initialization_refusal_cannot_release_acquired_or_used_owner",
    "kernel::tests::c06_late_pidfd_close_keeps_custody_and_terminal_facts",
    "kernel::tests::c06_release_rechecks_clock_after_successful_close_postcheck",
    "kernel::tests::c06_expired_dispose_keeps_unconsumed_pidfd",
    "kernel::tests::c08_consumed_direct_terminal_survives_failed_postcheck",
    "kernel::tests::c12_consumed_adopted_terminal_survives_failed_postcheck",
    "kernel::tests::c08_early_terminal_peek_prevents_success_and_still_reaps",
    "kernel::tests::c13_sparse_child_close_plan_includes_zero_and_excludes_peer",
    "kernel::tests::c01_exact_birth_request",
    "kernel::tests::c02_positive_order_and_single_release",
    "kernel::tests::c03_setup_refusals_have_no_fallback",
    "kernel::tests::c04_every_acquisition_failure_retains_custody",
    "kernel::tests::c05_failed_dirty_slot_and_successful_child_ownership",
    "kernel::tests::c06_independent_cleanup_and_quarantine_owner",
    "kernel::tests::c07_population_is_complete_bounded_and_unique",
    "kernel::tests::c08_pending_observation_is_not_a_consuming_wait",
    "kernel::tests::c09_wait_uses_owned_handle_not_reported_pid",
    "kernel::tests::c10_absolute_checked_caps_and_equality",
    "kernel::tests::c11_partial_record_and_eof_have_distinct_results",
    "kernel::tests::c12_one_cleanup_path_drains_adopted_after_direct",
    "kernel::tests::c13_transfer_closes_exact_owned_descriptors",
    "kernel::tests::c14_first_error_survives_successful_cleanup_and_secondary_error",
    "lifecycle::tests::c01_both_reservations_precede_create",
    "lifecycle::tests::c02_complete_result_and_terminal_worker_precede_cutover",
    "lifecycle::tests::c03_clean_completion_releases_each_lease_once",
    "lifecycle::tests::c04_cleanup_requires_all_three_independent_predicates",
    "lifecycle::tests::c05_cleanup_evidence_cannot_be_accumulated_across_incomplete_observations",
    "lifecycle::tests::c06_pre_cutover_supervisor_loss_aborts_even_with_complete_inputs",
    "lifecycle::tests::c07_planned_supervisor_stop_after_cutover_is_not_an_abort",
    "lifecycle::tests::c08_abort_reason_stays_distinct_from_cleanup_status",
    "lifecycle::tests::c09_cleanup_expiry_quarantines_and_late_evidence_cannot_release",
    "lifecycle::tests::c10_wrong_epoch_events_never_change_any_lifecycle_state",
    "lifecycle::tests::c11_duplicate_transitions_never_get_second_credit",
    "lifecycle::tests::c12_out_of_order_evidence_never_advances_a_job",
    "lifecycle::tests::c13_partial_reservation_failure_releases_only_held_leases_after_cleanup",
    "lifecycle::tests::c14_failure_after_cutover_still_prevents_success",
    "lifecycle::tests::c15_cleaned_evidence_is_terminal_before_explicit_release",
)


class BuildSession:
    """Owned receipts and aggregate limits around the unchanged Build recipes.

    Only build_task3 constructs this class. Native products are never registered
    as executable. Regular filesystem I/O remains subject to kernel stalls.
    """

    def __init__(self, output):
        self.path = Path(output)
        self.root = Path(__file__).resolve().parents[2]
        self.example = (
            self.root / "crates/irlume-common/examples/measurement_job_fixture.rs"
        )
        self.output = None
        self.pins = None
        self.sequence = 0
        self.output_bytes = 0
        self.allowed = ExecutionAllowlist()
        self.records = []
        self.flags_check = lambda: None
        self.dependency_inputs = None
        self.config_inputs = None

    def start(self):
        self.output = OwnedOutput.create(str(self.path))
        self.deadline = time.monotonic() + 900
        self.output.save(
            "started",
            {
                "mode": "build-only",
                "accepted": False,
                "native_authorized": False,
                "full_contract_proven": False,
                "deadline": self.deadline,
            },
        )
        directory = self.example.with_suffix("")
        kernel, native = directory / "kernel.rs", directory / "sys.rs"
        driver = (
            "// SPDX-License-Identifier: GPL-3.0-or-later\n"
            "// Copyright the irlume contributors.\n"
            f"#[path = {json.dumps(str(kernel))}] pub mod kernel;\n"
            f"#[path = {json.dumps(str(native))}] pub mod sys;\n"
            "/// Codegen-only root, never executed.\n"
            "///\n/// # Safety\n/// Requires every sys::run boot and retention precondition.\n"
            "#[inline(never)]\n"
            "pub unsafe fn task3_native_root(input: sys::Input) -> "
            "kernel::Completion<std::os::fd::OwnedFd> {\n"
            "    // SAFETY: the caller explicitly assumes sys::run preconditions.\n"
            "    unsafe { sys::run(input) }\n}\n"
        )
        self.driver = self.generated("native-driver.rs", driver.encode())
        self.legacy_control = self.generated(
            "legacy-entry-control.rs",
            (
                f"#[path = {json.dumps(str(kernel))}] pub mod kernel;\n"
                "pub use kernel::{run, run_case};\n"
            ).encode(),
        )
        self.control_sys = self.generated(
            "control-sys.rs",
            native.read_bytes() + b'\ncompile_error!("job-sys-active-control");\n',
        )
        self.control = self.generated(
            "control-driver.rs",
            driver.replace(str(native), str(self.control_sys)).encode(),
        )
        sources = sorted((self.root / "crates/irlume-common/examples").rglob("*.rs"))
        sources += [
            self.root / name
            for name in (
                "Cargo.toml",
                "Cargo.lock",
                "crates/irlume-common/Cargo.toml",
                "scripts/ci/measurement-job.py",
                "scripts/ci/test-measurement-job.py",
                "scripts/ci/measurement-job-vm.py",
                "scripts/ci/test-measurement-job-vm.py",
                "scripts/ci/measurement-job-guest.sh",
                "scripts/ci/measurement-fixture-bootstrap.py",
                "scripts/ci/test-measurement-fixture-bootstrap.py",
                "scripts/test-measurement-fixture-bootstrap.sh",
                "scripts/ci/isolated-cli.py",
                "scripts/ci/isolated-cli-probe.c",
            )
        ]
        sources += [self.driver, self.control_sys, self.control, self.legacy_control]
        self.rustup, self.cargo = shutil.which("rustup"), shutil.which("cargo")
        if not self.rustup or not self.cargo:
            raise RuntimeError(
                "installed Rust tools required; no installation fallback"
            )
        sources += [
            Path(self.rustup),
            Path(self.cargo),
            Path(self.rustup).resolve(),
            Path(self.cargo).resolve(),
        ]
        self.pins = FrozenPins(sources)
        self.environment = {
            key: os.environ[key]
            for key in ("PATH", "HOME", "RUSTUP_HOME", "CARGO_HOME")
            if key in os.environ
        }
        self.environment.update(
            CARGO_BUILD_JOBS="4",
            CARGO_PROFILE_RELEASE_DEBUG="0",
            CARGO_PROFILE_RELEASE_OPT_LEVEL="z",
        )
        self.config_inputs = CargoConfigurations(self.root, self.environment)
        self.tool_paths = {}
        for tool in ("rustc", "clippy-driver", "rustdoc", "cargo"):
            found = self.command(
                "locate-" + tool, [self.rustup, "which", "--toolchain", "1.88.0", tool]
            ).stdout.strip()
            safe_path(found)
            resolved = str(Path(found).resolve(strict=True))
            if resolved not in self.pins.hashes:
                self.pins.add(resolved)
            self.tool_paths[tool] = resolved
        self.output.save(
            "input-pins",
            {
                "hashes": self.pins.hashes,
                "tools": self.tool_paths,
                "target": "x86_64-unknown-linux-musl",
                "rust": "1.88.0",
                "cargo_configs": self.config_inputs.hashes,
            },
        )

    def generated(self, name, data):
        if len(data) > PROFILE_LIMIT or "/" in name:
            raise ValueError("invalid generated input")
        raw = os.open(
            name,
            os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC,
            0o600,
            dir_fd=self.output.fd,
        )
        try:
            view = memoryview(data)
            while view:
                if time.monotonic() >= self.deadline:
                    raise TimeoutError("generated input deadline")
                count = os.write(raw, view)
                if count <= 0:
                    raise OSError("generated input short write")
                view = view[count:]
        finally:
            os.close(raw)
        return self.path / name

    def check(self):
        if time.monotonic() >= self.deadline:
            raise TimeoutError("aggregate build deadline")
        self.flags_check()
        self.pins.check()
        if self.dependency_inputs is not None:
            self.dependency_inputs.check()
        if self.config_inputs is not None:
            self.config_inputs.check()
        if time.monotonic() >= self.deadline:
            raise TimeoutError("aggregate deadline after input checks")

    def emitted(self, label, record, stdout, stderr):
        self.output_bytes += len(stdout) + len(stderr)
        if self.output_bytes > EVIDENCE_LIMIT:
            raise RuntimeError("aggregate compiler output cap")
        self.output.save(label, record)
        self.output.save_blob(label + "-stdout", stdout)
        self.output.save_blob(label + "-stderr", stderr)
        self.records.append(record)

    def direct_command(self, command):
        if command[:3] == [self.rustup, "run", "1.88.0"] and len(command) >= 4:
            tool = command[3]
            if tool in ("rustc", "clippy-driver", "rustdoc"):
                return [self.tool_paths[tool], *command[4:]]
        if command[:2] == [self.cargo, "+1.88.0"]:
            return [self.tool_paths["cargo"], *command[2:]]
        if (
            len(command) == 5
            and command[:4] == [self.rustup, "which", "--toolchain", "1.88.0"]
            and command[4] in ("rustc", "clippy-driver", "rustdoc", "cargo")
        ):
            return command
        raise ValueError("unapproved build executable or command prefix")

    def command(self, description, command, *, env=None, failure=False, safe=False):
        self.check()
        if safe:
            self.allowed.check(
                command[0], hashlib.sha256(build_bytes(command[0])).hexdigest()
            )
        else:
            command = self.direct_command(command)
        self.sequence += 1
        label = f"command-{self.sequence:03}"
        effective = dict(env or self.environment)
        for key in ("PATH", "HOME", "CARGO_HOME", "RUSTUP_HOME"):
            if effective.get(key) != self.environment.get(key):
                raise RuntimeError("changed build environment: " + key)
        if command[0] == self.tool_paths.get("cargo"):
            if "--config" in command or any(
                arg.startswith("--config=") for arg in command
            ):
                raise RuntimeError("additional Cargo configuration is unsupported")
            effective.update(
                RUSTC=self.tool_paths["rustc"],
                RUSTDOC=self.tool_paths["rustdoc"],
                RUSTC_WRAPPER="",
                RUSTC_WORKSPACE_WRAPPER="",
                CARGO_BUILD_JOBS="4",
            )
        identity = json.dumps(
            {"argv": command, "env": effective}, sort_keys=True
        ).encode()
        self.output.save(
            label + "-input",
            {
                "description": description,
                "argv": command,
                "environment": effective,
                "sha256": hashlib.sha256(identity).hexdigest(),
            },
        )
        result = CompilerCommand(label, self.deadline, self.emitted).run(
            command, effective, cwd=str(self.root)
        )
        self.check()
        if (result.returncode == 0) == failure:
            raise RuntimeError("unexpected compiler/test status: " + description)
        return result

    def compile_native(self, builder):
        self.output.save(
            "dependency-pins",
            {
                "artifacts": builder.artifacts,
                "search_directories": self.dependency_inputs.hashes,
            },
        )
        bootstrap = builder.bootstrap
        flags = [*bootstrap.FLAGS, *builder.search]
        output = self.path / "native.rlib"
        llvm = self.path / "native.ll"
        dependencies = self.path / "native.d"
        args = [str(self.driver), *flags, "--crate-type=rlib"]
        self.command(
            "native-clippy",
            [
                self.rustup,
                "run",
                "1.88.0",
                "clippy-driver",
                *args,
                *bootstrap.LINTS,
                "--emit=metadata",
                "-o",
                str(self.path / "native.rmeta"),
            ],
        )
        self.command(
            "native-codegen",
            [
                self.rustup,
                "run",
                "1.88.0",
                "rustc",
                *args,
                f"--emit=link={output},llvm-ir={llvm},dep-info={dependencies}",
            ],
        )
        self.command(
            "native-doc",
            [
                self.rustup,
                "run",
                "1.88.0",
                "rustdoc",
                *args,
                "--document-private-items",
                "--out-dir",
                str(self.path / "native-doc"),
            ],
        )
        ir = build_bytes(llvm).decode()
        dep = build_bytes(dependencies).decode()
        # The native artifact never enters the execution allowlist.
        check_native_codegen(
            ir,
            dep,
            (
                self.driver,
                self.example.with_suffix("") / "kernel.rs",
                self.example.with_suffix("") / "sys.rs",
                self.example.with_suffix("") / "bounds.rs",
            ),
        )
        check_child_codegen(ir)
        check_bounds_codegen(ir)
        control = self.command(
            "native-active-control",
            [
                self.rustup,
                "run",
                "1.88.0",
                "rustc",
                str(self.control),
                *flags,
                "--crate-type=rlib",
                "--emit=metadata",
                "-o",
                str(self.path / "control.rmeta"),
            ],
            failure=True,
        )
        if "job-sys-active-control" not in control.stderr:
            raise RuntimeError("native negative control failed for wrong reason")
        legacy = self.command(
            "legacy-entry-control",
            [
                self.rustup,
                "run",
                "1.88.0",
                "rustc",
                str(self.legacy_control),
                *flags,
                "--crate-type=rlib",
                "--emit=metadata",
                "--error-format=json",
                "-o",
                str(self.path / "legacy-control.rmeta"),
            ],
            failure=True,
        )
        check_legacy_refusal(legacy.returncode, legacy.stderr, self.legacy_control)
        self.output.save(
            "native-products",
            {
                "class": "non-executed-rlib-and-codegen",
                "executed": False,
                "final_elf_link_tested": False,
                "artifacts": {
                    str(path): hashlib.sha256(build_bytes(path)).hexdigest()
                    for path in (output, llvm, dependencies)
                },
            },
        )

    def run_safe(self, product, kind):
        path = str(product)
        self.allowed.add(path, kind, hashlib.sha256(build_bytes(product)).hexdigest())
        arguments = [path] if kind == "inactive" else [path, "--nocapture"]
        # Exit 77 is expected only for an explicitly pinned inactive entry.
        result = self.command(kind, arguments, safe=True, failure=kind == "inactive")
        if kind == "inactive":
            if (result.returncode, result.stdout, result.stderr) != (77, "", ""):
                raise RuntimeError("inactive entry did not refuse")
            hostile = self.command(
                "inactive-arguments",
                [path, "--kernel", "--execute"],
                env=dict(self.environment, IRLUME_JOB_RUN="1"),
                safe=True,
                failure=True,
            )
            if (hostile.returncode, hostile.stdout, hostile.stderr) != (77, "", ""):
                raise RuntimeError("inactive entry accepted arguments/environment")
        else:
            names = tuple(
                re.findall(r"^test (\S+) \.\.\. ok$", result.stdout, re.MULTILINE)
            )
            check_suite(
                RUST_TESTS,
                names,
                success=result.returncode == 0,
                skipped=0 if "0 ignored" in result.stdout else 1,
            )

    def finish(self, builder):
        self.check()
        check_controls(builder.record.get("controls"))
        if COMPILER_OWNERS:
            raise RuntimeError("compiler owner still outstanding")
        self.output.save(
            "finished",
            {
                "mode": "build-only",
                "complete": True,
                "native_authorized": False,
                "full_contract_proven": False,
                "commands": len(self.records),
                "controls": builder.record.get("controls"),
                "flags": list(builder.bootstrap.FLAGS),
                "lints": list(builder.bootstrap.LINTS),
                "pins": self.pins.hashes,
                "search_directories": self.dependency_inputs.hashes,
                "cargo_configs": self.config_inputs.hashes,
            },
        )
        if time.monotonic() >= self.deadline:
            raise TimeoutError("aggregate build deadline after receipt")

    def failed(self, error):
        if self.output is not None:
            self.output.save(
                "failed",
                {
                    "complete": False,
                    "error": f"{type(error).__name__}: {error}"[:2000],
                    "native_authorized": False,
                    "retained_compiler_owners": list(COMPILER_OWNERS),
                },
            )

    def close(self):
        output, self.output = self.output, None
        if output is not None:
            output.close()  # A close error is never retried on a reused fd.


def make_builder(context):
    path = context.root / "scripts/ci/measurement-fixture-bootstrap.py"
    spec = importlib.util.spec_from_file_location("job_private_build", path)
    bootstrap = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(bootstrap)
    expected_flags, expected_lints = tuple(bootstrap.FLAGS), tuple(bootstrap.LINTS)

    def check_flags():
        if (
            tuple(bootstrap.FLAGS) != expected_flags
            or tuple(bootstrap.LINTS) != expected_lints
        ):
            raise RuntimeError("changed effective build flags/lints")

    context.flags_check = check_flags

    class JobBuild(bootstrap.Build):
        def command(self, label, command, *, env=None, failure=False):
            return context.command(label, command, env=env, failure=failure)

        def check_inputs(self):
            super().check_inputs()
            context.check()

    # The command override exists before the superclass constructor starts any
    # compiler. Existing negative-control snippets and polarity are unchanged.
    builder = JobBuild(context.path / "transaction")
    builder.bootstrap = bootstrap
    for artifact in builder.artifacts.values():
        if (
            hashlib.sha256(build_bytes(artifact["path"])).hexdigest()
            != artifact["sha256"]
        ):
            raise RuntimeError("dependency changed before adoption")
        context.pins.add(artifact["path"])
    context.dependency_inputs = FrozenDirectories(
        flag.removeprefix("-Ldependency=")
        for flag in builder.search
        if flag.startswith("-Ldependency=")
    )
    return builder


def build_task3(output, *, _context=None, _factory=None):
    """Explicit build-only entry. Import/default tests never call this function."""
    context = (_context or BuildSession)(output)
    try:
        context.start()
        builder = (_factory or make_builder)(context)
        builder.negative_controls()
        context.compile_native(builder)
        for name, test, evidence in [("pure", True, True), ("inactive", False, False)]:
            product = builder.compile(
                name, context.example, test=test, evidence=evidence, document=True
            )
            context.run_safe(product, "pure" if test else "inactive")
        builder.check_inputs()
        context.finish(builder)
    except BaseException as error:
        try:
            context.failed(error)
        except FINALIZATION_FAILURES as secondary:
            error.add_note(f"receipt failure: {type(secondary).__name__}: {secondary}")
        try:
            context.close()
        except FINALIZATION_FAILURES as secondary:
            error.add_note(
                f"output close failure: {type(secondary).__name__}: {secondary}"
            )
        raise
    else:
        context.close()
        # The output is consumed; an overrun must not retry receipt I/O or close.
        if time.monotonic() >= context.deadline:
            raise TimeoutError("aggregate build deadline after close")

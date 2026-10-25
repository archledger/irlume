#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright the irlume contributors.
"""Explicit read-only namespace observation contexts, never launch admission."""
import importlib.util
import json
import os
import subprocess
from pathlib import Path

SPEC = importlib.util.spec_from_file_location(
    "namespace_bootstrap", Path(__file__).with_name("measurement-fixture-bootstrap.py"))
bootstrap = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(bootstrap)


def command(executable, mode, *, fake_proc=None):
    """Select one fixed test context, without falling back between contexts."""
    if mode == "host":
        return [str(executable)]
    prefix = ["/usr/bin/unshare", "--user", "--map-root-user"]
    if mode == "user":
        return prefix + ["--", str(executable)]
    if mode == "user-pid":
        return prefix + ["--pid", "--fork", "--", str(executable)]
    if mode == "fake-proc" and fake_proc is not None:
        return ["/usr/bin/bwrap", "--unshare-all", "--as-pid-1", "--die-with-parent",
                "--clearenv", "--uid", "0", "--gid", "0", "--cap-drop", "ALL",
                "--tmpfs", "/", "--ro-bind", str(executable), "/probe",
                "--ro-bind", str(fake_proc), "/proc", "--chdir", "/", "--", "/probe"]
    raise ValueError("unknown namespace context")


def run(executable, mode, *, timeout=5, fake_proc=None):
    """Run only a trusted static test binary in the explicitly chosen context.

    Host mode is intentional: the positive asks about the existing non-root
    task's namespace. It is never a recovery path for failed isolation.
    """
    if os.getuid() == 0 or os.getuid() != os.geteuid() or os.getgid() != os.getegid():
        raise RuntimeError("non-root, non-setid test controller required")
    executable, identity = bootstrap.owned_static(executable)
    selected = command(executable, mode, fake_proc=fake_proc)
    process = subprocess.Popen(selected, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                               stderr=subprocess.PIPE, env={}, close_fds=True,
                               start_new_session=True)
    result = bootstrap._collect(process, timeout=timeout)
    return dict(result, command=selected, fixture_sha256=identity, host_pid=process.pid)


def parse_result(result):
    """Validate fixed-shape evidence without promoting errors to observations."""
    if result["timed_out"] or not result["eof"] or result["stderr"]:
        raise ValueError("incomplete namespace probe")
    if len(result["stdout"]) > 1024:
        raise ValueError("oversized namespace result")
    try:
        row = json.loads(result["stdout"])
    except (ValueError, UnicodeError) as error:
        raise ValueError("invalid namespace JSON") from error
    if not isinstance(row, dict) or set(row) != {"initial", "namespace_id", "errno", "pid", "uid"}:
        raise ValueError("invalid namespace fields")
    for name, upper in [("namespace_id", 2**64), ("errno", 4096), ("pid", 2**31), ("uid", 2**32 - 1)]:
        if type(row[name]) is not int or not 0 <= row[name] < upper:
            raise ValueError("invalid namespace field type or bound")
    if row["pid"] == 0:
        raise ValueError("invalid task id")
    if row["initial"] is None:
        if result["status"] != 77 or row["namespace_id"] != 0:
            raise ValueError("invalid namespace error")
    elif type(row["initial"]) is bool:
        if result["status"] != 0 or row["errno"] != 0:
            raise ValueError("invalid namespace observation")
        if row["initial"]:
            if row["namespace_id"] != 4:
                raise ValueError("invalid initial witness")
        elif row["namespace_id"] != 0 and not 8 < row["namespace_id"] < 2**64 - 1:
            raise ValueError("invalid absent witness")
    else:
        raise ValueError("invalid observation type")
    return row

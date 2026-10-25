#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright the irlume contributors.
"""CPU-only mount-lifetime experiment, never native-loading admission."""
import importlib.util
import json
import os
import select
import shutil
import subprocess
import time
from pathlib import Path

SPEC = importlib.util.spec_from_file_location(
    "generation_bootstrap", Path(__file__).with_name("measurement-fixture-bootstrap.py"))
bootstrap = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(bootstrap)


def namespace_command(bwrap, executable):
    """Build a private empty-root command; never weaken unavailable isolation."""
    return [str(bwrap), "--unshare-all", "--as-pid-1", "--die-with-parent",
            "--clearenv", "--uid", "0", "--gid", "0", "--cap-drop", "ALL",
            "--cap-add", "CAP_SYS_ADMIN", "--cap-add", "CAP_SYS_CHROOT",
            "--cap-add", "CAP_SETPCAP", "--tmpfs", "/", "--proc", "/proc",
            "--dir", "/dev", "--dev-bind", "/dev/null", "/dev/null",
            "--ro-bind", str(executable), "/fixture", "--chdir", "/",
            "--", "/fixture"]


def validate_report(report, case):
    """Require the complete final fixed-fixture result, not a readiness marker."""
    expected = {"case": case, "publisher_terminated": True, "published": "b",
                "consumer_a": "retained", "consumer_b": "retained", "handles_closed": True}
    if case not in ("positive", "publisher-crash", "cancel", "fail-file",
                    "fail-clone", "fail-move", "fail-after-move"):
        raise ValueError("unknown fixture case")
    if case == "cancel":
        expected.update(consumer_a="cancelled", consumer_b="cancelled")
    if case.startswith("fail-"):
        expected.update(published="b" if case == "fail-after-move" else "a",
                        consumer_b="not-started")
    if not isinstance(report, dict) or report.keys() != expected.keys():
        raise ValueError("incomplete generation result")
    if any(type(report[key]) is not type(value) or report[key] != value
           for key, value in expected.items()):
        raise ValueError("generation result mismatch")


def validate_output(stdout, case):
    """Require ordered completion, including actual publisher death before reads."""
    if len(stdout) > 4096:
        raise ValueError("oversized generation output")
    try:
        rows = [json.loads(line) for line in stdout.decode("ascii").splitlines()]
    except (ValueError, UnicodeError) as error:
        raise ValueError("invalid generation output") from error
    if not rows:
        raise ValueError("missing generation output")
    validate_report(rows[-1], case)
    published = "a" if case in ("fail-file", "fail-clone", "fail-move") else "b"
    expected = [{"event": "a_ready"},
                {"event": "published", "selected": published, "b_started": not case.startswith("fail-")},
                {"event": "publisher_reaped", "status": 9 if case == "publisher-crash" else 0}]
    if case != "cancel":
        expected.append({"event": "late_release"})
    # JSON booleans are not integer status codes, despite Python equality.
    if json.dumps(rows[:-1], sort_keys=True) != json.dumps(expected, sort_keys=True):
        raise ValueError("generation phase mismatch")


def run_fixture(executable, *, timeout=20):
    """Execute only an owned static fixture inside the required empty root."""
    executable, identity = bootstrap.owned_static(executable)
    bwrap = shutil.which("bwrap")
    if not bwrap or os.getuid() == 0 or os.getuid() != os.geteuid() or os.getgid() != os.getegid():
        raise RuntimeError("unprivileged controller and bubblewrap required; no host fallback")
    command = namespace_command(bwrap, executable)
    process = subprocess.Popen(command, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                               stderr=subprocess.PIPE, env={}, close_fds=True, start_new_session=True)
    streams = [process.stdout, process.stderr]
    collected = {stream: bytearray() for stream in streams}
    timed_out = False
    try:
        bootstrap._OWNED[process.pid] = process
        for stream in streams:
            os.set_blocking(stream.fileno(), False)
        pending = list(streams)
        deadline = time.monotonic() + timeout
        while pending:
            if time.monotonic() >= deadline:
                timed_out = True
                break
            ready, _, _ = select.select(pending, [], [], min(0.05, max(0, deadline - time.monotonic())))
            for stream in ready:
                data = os.read(stream.fileno(), 4096)
                if not data:
                    pending.remove(stream)
                else:
                    collected[stream].extend(data)
                    if len(collected[stream]) > 4096:
                        raise RuntimeError("generation output limit")
        if not timed_out:
            try:
                process.wait(timeout=max(0.001, deadline - time.monotonic()))
            except subprocess.TimeoutExpired:
                timed_out = True
    finally:
        bootstrap._finish(process)
    return {"status": process.returncode, "timed_out": timed_out, "eof": not pending,
            "stdout": bytes(collected[process.stdout]), "stderr": bytes(collected[process.stderr]),
            "fixture_sha256": identity, "command": command}

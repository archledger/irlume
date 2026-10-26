#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright the irlume contributors.
"""Bounded, model-only disposable-controller preparation.

There is intentionally no real process/recovery backend in Task2. The current
Rust entry always exits 77 and no qualified M/E boot payload exists. Matching
input hashes, JSON flags, KVM access or a model result cannot enable execution.
The private _model seam below is for in-memory test doubles, not an authority
boundary or an invitation to plug in a runtime executor.
"""

import importlib.util
import json
import os
import sys
import time
from builtins import BaseExceptionGroup
from pathlib import Path

SPEC = importlib.util.spec_from_file_location(
    "job_support", Path(__file__).with_name("measurement-job.py")
)
job = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(job)
_OWNED = {}
OPERATIONAL_FAILURES = (OSError, ValueError, TypeError, RuntimeError)
# All throwables cross mandatory finalization. Only known operational failures
# may return; cancellations and unexpected exceptions are retained for rethrow.
DEFERRED_ERRORS = (BaseException,)


def observe_host(output, want):
    """Read-only availability hints. None constitutes runtime qualification."""
    parent = job.safe_path(output).parent
    space = os.statvfs(str(parent))
    tools = [
        path
        for role, path, _ in want.inputs
        if role in ("qemu", "qemu_img", "recovery")
    ]
    return {
        "uid": os.getuid(),
        "euid": os.geteuid(),
        "gid": os.getgid(),
        "egid": os.getegid(),
        "kvm": os.access("/dev/kvm", os.R_OK | os.W_OK),
        "tools": all(os.access(path, os.X_OK) for path in tools),
        "scratch_free": space.f_bavail * space.f_frsize,
    }


def check_host(host):
    job.fields(host, ("uid", "euid", "gid", "egid", "kvm", "tools", "scratch_free"))
    for name in ("uid", "euid", "gid", "egid"):
        job.integer(host[name], 0, 2**32 - 2)
    job.integer(host["scratch_free"], 0, 2**64 - 1)
    if (
        host["uid"] == 0
        or host["uid"] != host["euid"]
        or host["gid"] != host["egid"]
        or host["kvm"] is not True
        or host["tools"] is not True
        or host["scratch_free"] < job.LIMITS["scratch_bytes"]
    ):
        raise ValueError("unqualified host availability")


def check_inputs(want, deadline):
    for role, path, expected in want.inputs:
        if time.monotonic() >= deadline:
            raise TimeoutError("input observation deadline")
        limit = job.LIMITS["scratch_bytes"] if role == "base" else 64 * 1024 * 1024
        if job.observe_input(path, limit=limit, deadline=deadline) != expected:
            raise ValueError("observed hash differs from trusted expectation")


def commands(want, output):
    """Fixed argv model. No arbitrary flags, environment, shares or host devices.

    The base is explicitly raw (no implicit backing chain); payload is raw and
    read-only. Only a fresh private overlay is writable. These argv are tested
    preparation, not a qualified boot profile and are never executed here.
    """
    job.check_expected(want)
    output = job.safe_path(output)
    paths = {role: path for role, path, _ in want.inputs}
    overlay = str(output / "overlay.qcow2")
    prepare = [
        paths["qemu_img"],
        "create",
        "-f",
        "qcow2",
        "-F",
        "raw",
        "-b",
        paths["base"],
        overlay,
    ]
    disk = {
        "driver": "qcow2",
        "node-name": "job-disk",
        "file": {"driver": "file", "filename": overlay},
        "backing": {
            "driver": "raw",
            "read-only": True,
            "file": {"driver": "file", "filename": paths["base"]},
        },
    }
    payload = {
        "driver": "raw",
        "node-name": "job-payload",
        "read-only": True,
        "file": {"driver": "file", "filename": paths["payload"], "read-only": True},
    }
    launch = [
        paths["qemu"],
        "-no-user-config",
        "-nodefaults",
        "-accel",
        "kvm",
        "-smp",
        "2",
        "-m",
        "2048",
        "-display",
        "none",
        "-monitor",
        "none",
        "-nic",
        "none",
        "-no-reboot",
        "-serial",
        "file:" + str(output / "serial.log"),
        "-blockdev",
        json.dumps(disk, separators=(",", ":")),
        "-device",
        "virtio-blk-pci,drive=job-disk",
        "-blockdev",
        json.dumps(payload, separators=(",", ":")),
        "-device",
        "virtio-blk-pci,drive=job-payload",
    ]
    return prepare, launch


def run(profile_data, want, output, *, _model=None):
    """Keep started/terminal receipts even on failure; never enable real runtime.

    Test doubles own their exact process handle. wait() must reap that handle;
    kill() must target it alone, not a PID looked up later or a name/group scan.
    They must enforce the supplied output/time bounds. No real implementation
    of that contract is supplied. Failed reap keeps the handle in _OWNED and
    forbids recovery, because a disk still being written is not final evidence.
    Invalid Expected data is refused before any output allocation or write.
    """
    job.check_expected(want)
    root = job.OwnedOutput.create(output)  # No writes at all if ownership is unsafe.
    row = {
        "scope": job.SCOPE,
        "mode": "model" if _model is not None else "unavailable",
        "run_id": want.run_id,
        "boot_id": want.boot_id,
        "epoch": want.epoch,
        "cases": [list(case) for case in want.cases],
        "inputs": {
            role: {"path": path, "sha256": digest} for role, path, digest in want.inputs
        },
        "limits": dict(job.LIMITS),
        "status": "started",
        "reason": None,
        "accepted": False,
        "model_matched": False,
        "native_authorized": False,
        "full_contract_proven": False,
        "qemu_started": False,
        "qemu_reaped": False,
        "leftover": False,
        "cleanup": "not-started",
        "stop_error": False,
        "failures": [],
    }
    process = None
    first_error = None
    pending = []

    def record_failure(stage, error, *, must_raise=False):
        nonlocal first_error
        if first_error is None:
            first_error = error
        cancellation = isinstance(error, (KeyboardInterrupt, SystemExit))
        operational = isinstance(error, OPERATIONAL_FAILURES)
        if row["reason"] is None:
            row["reason"] = stage
        row["model_matched"] = False
        kind = (
            "interrupted"
            if cancellation
            else "operational"
            if operational
            else "unexpected"
        )
        # Replace rather than mutate the list retained in a started snapshot.
        row["failures"] = [*row["failures"], {"stage": stage, "kind": kind}]
        if must_raise or not operational:
            pending.append(error)

    stage = "started-receipt"
    try:
        root.save("started", row)
        stage = "profile-preflight"
        job.parse_profile(profile_data, want)
        stage = "host-preflight"
        check_host(observe_host(output, want))
        stage = "input-preflight"
        observation_deadline = time.monotonic() + job.LIMITS["recovery_seconds"]
        check_inputs(want, observation_deadline)
        stage = "runtime-unavailable"
        if _model is None or _model.model_only is not True:
            raise ValueError("qualified M/E payload and execution profile unavailable")
        prepare, launch = commands(want, output)
        stage = "prepare"
        prepare_deadline = time.monotonic() + 60
        prepared = _model.prepare(prepare, timeout=60, output_limit=job.PROFILE_LIMIT)
        if time.monotonic() >= prepare_deadline:
            raise TimeoutError("overlay preparation deadline")
        job.fields(prepared, ("status", "output_bytes", "overlay_bytes"))
        job.integer(prepared["status"], 0, 255)
        job.integer(prepared["output_bytes"], 0, job.PROFILE_LIMIT)
        job.integer(prepared["overlay_bytes"], 1, job.LIMITS["scratch_bytes"])
        if prepared["status"] != 0:
            raise ValueError("overlay preparation failed")
        stage = "input-preflight"
        check_inputs(want, observation_deadline)
        stage = "spawn"
        deadline = time.monotonic() + job.LIMITS["host_seconds"]
        process = _model.spawn(
            launch, deadline=deadline, output_limit=job.LIMITS["serial_bytes"]
        )
        _OWNED[id(process)] = process
        row["qemu_started"] = True
        stage = "wait"
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise TimeoutError("host deadline")
        status = process.wait(timeout=remaining)
        job.integer(status, -255, 255)
        row.update(qemu_reaped=True, qemu_status=status)
        del _OWNED[id(process)]
        if time.monotonic() >= deadline:
            raise TimeoutError("late completion")
        stage = "qemu-exit"
        if status != 0:
            raise ValueError("early exit or signal")
    except DEFERRED_ERRORS as error:
        if isinstance(error, (KeyboardInterrupt, SystemExit)):
            row["reason"] = "interrupted"
        record_failure(stage, error)
    try:
        if process is not None and not row["qemu_reaped"]:
            stop_deadline = time.monotonic() + job.LIMITS["stop_seconds"]
            try:
                process.kill()
            except DEFERRED_ERRORS as error:
                row["stop_error"] = True
                record_failure("stop-kill", error)
            try:
                remaining = stop_deadline - time.monotonic()
                if remaining <= 0:
                    raise TimeoutError("stop deadline")
                status = process.wait(timeout=remaining)
                job.integer(status, -255, 255)
                row.update(qemu_reaped=True, qemu_status=status)
                del _OWNED[id(process)]
                if time.monotonic() >= stop_deadline:
                    raise TimeoutError("late stop completion")
            except DEFERRED_ERRORS as error:
                row["stop_error"] = True
                row["leftover"] = not row["qemu_reaped"]
                record_failure("stop-wait", error)
        if process is not None:
            row["cleanup"] = "reaped" if row["qemu_reaped"] else "incomplete"
        # Recovered bytes are corroborating model evidence, not authenticated
        # guest truth. Keep malformed bytes too, but never recover a live disk.
        if process is not None and row["qemu_reaped"]:
            recovery_stage = "serial-limit"
            try:
                recovery_deadline = time.monotonic() + job.LIMITS["recovery_seconds"]
                job.integer(_model.serial_size(), 0, job.LIMITS["serial_bytes"])
                recovery_stage = "recovery"
                remaining = recovery_deadline - time.monotonic()
                if remaining <= 0:
                    raise TimeoutError("recovery deadline before recovery")
                data = _model.recover(
                    str(job.safe_path(output) / "overlay.qcow2"),
                    read_only=True,
                    timeout=remaining,
                    limit=job.EVIDENCE_LIMIT,
                )
                if type(data) is not bytes or len(data) > job.EVIDENCE_LIMIT:
                    raise ValueError("invalid recovered bytes")
                root.save_blob("recovered", data)
                if time.monotonic() >= recovery_deadline:
                    raise TimeoutError("recovery deadline")
                recovery_stage = "input-postflight"
                check_inputs(want, recovery_deadline)
                recovery_stage = "evidence"
                result = job.validate_evidence(data, want)
                if time.monotonic() >= recovery_deadline:
                    raise TimeoutError("validation deadline")
                if row["reason"] is None and not row["stop_error"]:
                    row.update(result)
            except DEFERRED_ERRORS as error:
                record_failure(recovery_stage, error)
            # Never replace an earlier process failure with recovered success.
    except DEFERRED_ERRORS as error:
        # Even an unexpected failure outside a callback cannot skip the receipt
        # and close attempts. Callback failures above still permit exact wait.
        record_failure("cleanup", error)
    finally:
        row["status"] = "model-complete" if row["model_matched"] else "failed"
        try:
            root.save("finished", row)
        except DEFERRED_ERRORS as error:
            record_failure("finished-receipt", error, must_raise=True)
        finally:
            try:
                root.close()
            except DEFERRED_ERRORS as error:
                record_failure("output-close", error, must_raise=True)
    if pending:
        error = (
            pending[0]
            if len(pending) == 1
            else BaseExceptionGroup("controller finalization failures", pending)
        )
        if error is first_error:
            raise error
        raise error from first_error
    return row


if __name__ == "__main__":
    sys.stderr.write("measurement-job: Task2 only; qualified M/E runtime unavailable\n")
    raise SystemExit(77)

#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright the irlume contributors.
"""Canonical startup evidence only; no process provenance or execution authority."""

import hashlib
import re
import time
import types
from typing import NamedTuple

LIMIT = 1024**2
MAX_NODES = 65536
MAX_DEPTH = 32


class Dependencies(NamedTuple):
    preflight: types.ModuleType
    runtime_state: types.ModuleType


class Clock:
    def __init__(self, deadline, clock):
        self.deadline, self.clock, self.previous = deadline, clock, 0

    def check(self):
        now = self.clock()
        if type(now) is not int or now < self.previous or not 0 < now < self.deadline:
            raise TimeoutError("startup witness deadline")
        self.previous = now
        return now


class Budget:
    def __init__(self, clock):
        self.clock, self.nodes, self.bytes = clock, 0, 0

    def use(self, depth, size=8):
        self.clock.check()
        self.nodes += 1
        self.bytes += size
        if depth > MAX_DEPTH or self.nodes > MAX_NODES or self.bytes > LIMIT:
            raise ValueError("startup witness encoding budget")


def text(value):
    if (
        type(value) is not str
        or len(value) > 4096
        or any(not 32 <= ord(c) <= 126 for c in value)
    ):
        raise ValueError("startup witness text")
    return value


def transform(value, budget, *, decode=False, depth=0):
    """Private lossless tags; charge allocation before creating encoded buffers."""
    budget.use(depth)
    kind = type(value)
    if value is None or kind is bool:
        return value
    if kind is int:
        if not -(2**63) <= value <= 2**64 - 1:
            raise ValueError("startup witness integer")
        return value
    if kind is str:
        text(value)
        budget.use(depth, len(value) * 2 + 2)
        return value
    if kind is bytes and not decode:
        budget.use(depth, len(value) * 2 + 20)
        return {"$bytes": value.hex()}
    if kind is tuple and not decode:
        if len(value) > MAX_NODES:
            raise ValueError("startup witness tuple cap")
        return {"$tuple": [transform(item, budget, depth=depth + 1) for item in value]}
    if kind is list:
        if len(value) > MAX_NODES:
            raise ValueError("startup witness list cap")
        return [
            transform(item, budget, decode=decode, depth=depth + 1) for item in value
        ]
    if kind is not dict or len(value) > MAX_NODES:
        raise ValueError("startup witness value type or dictionary cap")
    if decode and set(value) == {"$bytes"}:
        encoded = value["$bytes"]
        if type(encoded) is not str or len(encoded) % 2:
            raise ValueError("startup witness byte encoding")
        budget.use(depth, len(encoded) + 20)
        if re.fullmatch("[0-9a-f]*", encoded) is None:
            raise ValueError("startup witness byte encoding")
        return bytes.fromhex(encoded)
    if decode and set(value) == {"$tuple"}:
        items = value["$tuple"]
        if type(items) is not list or len(items) > MAX_NODES:
            raise ValueError("startup witness tuple encoding")
        return tuple(
            transform(item, budget, decode=True, depth=depth + 1) for item in items
        )
    result = {}
    for key, item in value.items():
        text(key)
        if key.startswith("$"):
            raise ValueError("startup witness reserved tag")
        budget.use(depth, len(key) * 2 + 4)
        result[key] = transform(item, budget, decode=decode, depth=depth + 1)
    return result


def typed_equal(left, right):
    if type(left) is not type(right):
        return False
    if type(left) is dict:
        return left.keys() == right.keys() and all(
            typed_equal(left[key], right[key]) for key in left
        )
    if type(left) in (list, tuple):
        return len(left) == len(right) and all(
            typed_equal(a, b) for a, b in zip(left, right)
        )
    return left == right


def check_binding(binding, dependencies):
    runtime = dependencies.preflight.runtime
    runtime._fields(
        binding,
        (
            "run_id",
            "transaction_sha256",
            "invocation_id",
            "guardian_pid",
            "guardian_starttime",
            "startup_deadline_ns",
        ),
    )
    runtime._identifier(binding["run_id"])
    for name, size in (("transaction_sha256", 64), ("invocation_id", 32)):
        if (
            type(binding[name]) is not str
            or re.fullmatch(f"[0-9a-f]{{{size}}}", binding[name]) is None
            or binding[name] == "0" * size
        ):
            raise ValueError("startup witness binding digest")
    runtime._integer(binding["guardian_pid"], 2, 2**31 - 1)
    runtime._integer(binding["guardian_starttime"], 1, runtime.U64_MAX)
    runtime._integer(binding["startup_deadline_ns"], 1, runtime.U64_MAX)
    return dict(binding)


def validate(observation, plan, manifest_data, binding, dependencies, timer):
    preflight = dependencies.preflight
    runtime = preflight.runtime
    manifest = preflight.root.check_selection(plan, manifest_data)
    if binding["run_id"] != plan["run_id"]:
        raise ValueError("startup witness run binding")
    runtime._fields(
        observation,
        (
            "initial_filesystem",
            "filesystem",
            "core",
            "runtime_manifest_sha256",
            "files",
            "python",
            "maps",
            "status",
            "started_ns",
            "finished_ns",
        ),
    )
    runtime._integer(observation["started_ns"], 1, timer.check())
    timer.deadline = min(timer.deadline, observation["started_ns"] + 5_000_000_000)
    now = timer.check()
    runtime._integer(observation["finished_ns"], observation["started_ns"], now)
    first, last = observation["initial_filesystem"], observation["filesystem"]
    preflight.core_witness(plan, first, timer.deadline, timer.check())
    final_core = preflight.core_witness(plan, last, timer.deadline, timer.check())
    if (
        first["started_ns"] != observation["started_ns"]
        or last["started_ns"] != observation["started_ns"]
        or not first["finished_ns"] <= last["finished_ns"] <= observation["finished_ns"]
    ):
        raise ValueError("startup witness phase ordering")
    if not typed_equal(first["proc"], last["proc"]) or not typed_equal(
        final_core, observation["core"]
    ):
        raise ValueError("startup witness inconsistent process or core")
    if (
        type(observation["status"]) is not bytes
        or observation["status"] != last["status_after"]
    ):
        raise ValueError("startup witness final status")
    if observation["runtime_manifest_sha256"] != plan["manifest"]["sha256"]:
        raise ValueError("startup witness manifest digest")
    dependencies.runtime_state.check_runtime_state(
        manifest,
        observation["files"],
        observation["python"],
        observation["maps"],
        preflight.root.parse_mountinfo(final_core["mountinfo"]),
    )
    timer.check()


def context(dependencies, binding, clock):
    if type(dependencies) is not Dependencies or any(
        type(module) is not types.ModuleType for module in dependencies
    ):
        raise ValueError("startup witness dependencies")
    selected = check_binding(binding, dependencies)
    timer = Clock(selected["startup_deadline_ns"], clock)
    timer.check()
    return selected, timer


def encode(
    observation,
    plan,
    manifest_data,
    binding,
    dependencies,
    *,
    clock=time.monotonic_ns,
):
    binding, timer = context(dependencies, binding, clock)
    packed = transform(observation, Budget(timer))
    frozen = transform(packed, Budget(timer), decode=True)
    validate(frozen, plan, manifest_data, binding, dependencies, timer)
    wire = {
        "scope": "contained-job-startup-witness-v1",
        "binding": binding,
        "observation": packed,
        "native_authorized": False,
        "full_contract_proven": False,
    }
    data = dependencies.preflight.root.closure.canonical(wire)
    if len(data) > LIMIT:
        raise ValueError("startup witness encoded size")
    digest = hashlib.sha256(data).hexdigest()
    timer.check()
    return data, digest


def decode(
    data,
    expected_digest,
    plan,
    manifest_data,
    binding,
    dependencies,
    *,
    clock=time.monotonic_ns,
):
    binding, timer = context(dependencies, binding, clock)
    if (
        type(data) is not bytes
        or not 0 < len(data) <= LIMIT
        or type(expected_digest) is not str
        or re.fullmatch("[0-9a-f]{64}", expected_digest) is None
    ):
        raise ValueError("startup witness bytes or digest")
    if hashlib.sha256(data).hexdigest() != expected_digest:
        raise ValueError("startup witness digest mismatch")
    runtime = dependencies.preflight.runtime
    wire = runtime._json(data)
    runtime._fields(
        wire,
        (
            "scope",
            "binding",
            "observation",
            "native_authorized",
            "full_contract_proven",
        ),
    )
    if (
        wire["scope"] != "contained-job-startup-witness-v1"
        or wire["native_authorized"] is not False
        or wire["full_contract_proven"] is not False
    ):
        raise ValueError("startup witness scope or authority")
    if (
        not typed_equal(wire["binding"], binding)
        or dependencies.preflight.root.closure.canonical(wire) != data
    ):
        raise ValueError("startup witness binding or canonical encoding")
    frozen = transform(wire["observation"], Budget(timer), decode=True)
    validate(frozen, plan, manifest_data, binding, dependencies, timer)
    timer.check()
    return frozen


if __name__ == "__main__":
    raise SystemExit(77)

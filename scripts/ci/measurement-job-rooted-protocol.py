#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright the irlume contributors.
"""Startup-only configuration/wire schema. No execution or transport is started."""

import hashlib
import re
import types
from pathlib import PurePosixPath
from typing import NamedTuple

CONFIG_LIMIT = 32 * 1024
CONFIG_SCOPE = "contained-job-rooted-startup-config-v1"


class Dependencies(NamedTuple):
    root: types.ModuleType
    artifact: types.ModuleType


class Configuration(NamedTuple):
    data: bytes
    sha256: str


def dependencies(value):
    if type(value) is not Dependencies or any(
        type(module) is not types.ModuleType for module in value
    ):
        raise ValueError("rooted protocol dependencies")
    return value.root, value.root.runtime, value.root.guardian


def validate_header(value, deps):
    root, runtime, guardian = dependencies(deps)
    runtime._fields(
        value,
        (
            "scope",
            "mode",
            "host_spec",
            "root_plan",
            "client",
            "origin_ns",
            "startup_deadline_ns",
            "bus_identity",
        ),
    )
    if (
        type(value["scope"]) is not str
        or type(value["mode"]) is not str
        or value["scope"] != CONFIG_SCOPE
        or value["mode"] != "startup-only"
    ):
        raise ValueError("rooted startup config scope or mode")
    runtime._fields(value["host_spec"], guardian.Specification._fields)
    selection = value["host_spec"]
    if type(selection["mode"]) is not str:
        raise ValueError("rooted startup specification mode type")
    if type(selection["cpus"]) is not list or type(selection["cases"]) is not list:
        raise ValueError("rooted startup specification arrays")
    spec = guardian.Specification(
        **dict(
            selection, cpus=tuple(selection["cpus"]), cases=tuple(selection["cases"])
        )
    )
    guardian.validate_spec(spec)
    plan = value["root_plan"]
    root.check_plan(plan)
    if spec.mode != "boot-only" or spec.cases != ("supervisor-only",):
        raise ValueError("rooted startup must be inert")
    if (
        spec.run_id != plan["run_id"]
        or spec.base != plan["base"]["path"]
        or spec.payload != plan["payload"]["path"]
        or spec.overlay != plan["attempt"]["path"] + "/overlay.qcow2"
        or spec.qemu != "/usr/bin/qemu-system-x86_64"
    ):
        raise ValueError("rooted startup host path coordinates")
    client = value["client"]
    runtime._fields(client, ("pid", "uid", "gid", "starttime"))
    runtime._integer(client["pid"], 2, 2**31 - 1)
    runtime._integer(client["uid"], plan["uid"], plan["uid"])
    runtime._integer(client["gid"], plan["gid"], plan["gid"])
    runtime._integer(client["starttime"], 1, runtime.U64_MAX)
    runtime._integer(value["origin_ns"], 1, runtime.U64_MAX - guardian.STOP_NS)
    runtime._integer(
        value["startup_deadline_ns"],
        value["origin_ns"] + guardian.STOP_NS,
        value["origin_ns"] + guardian.STOP_NS,
    )
    root.identity(value["bus_identity"])
    return spec


def validate_config(value, manifest_data, deps):
    spec = validate_header(value, deps)
    manifest = deps.root.check_selection(value["root_plan"], manifest_data)
    if not any(
        row["path"] == "usr/bin/qemu-system-x86_64"
        and row["kind"] == "file"
        and row["mode"] == 0o500
        and row["size"] > 0
        for row in manifest["members"]
    ):
        raise ValueError("rooted startup selected QEMU member")
    return spec


def make_config(spec, plan, client, bus_identity, origin, manifest_data, deps):
    root, runtime, guardian = dependencies(deps)
    if type(spec) is not guardian.Specification or type(spec.mode) is not str:
        raise ValueError("rooted startup specification mode type")
    guardian.validate_spec(spec)
    runtime._integer(origin, 1, runtime.U64_MAX - guardian.STOP_NS)
    value = {
        "scope": CONFIG_SCOPE,
        "mode": "startup-only",
        "host_spec": guardian.launch_request(spec)["payload"],
        "root_plan": plan,
        "client": client,
        "origin_ns": origin,
        "startup_deadline_ns": origin + guardian.STOP_NS,
        "bus_identity": bus_identity,
    }
    validate_config(value, manifest_data, deps)
    data = root.closure.canonical(value)
    if len(data) > CONFIG_LIMIT:
        raise ValueError("rooted startup configuration byte cap")
    return Configuration(data, hashlib.sha256(data).hexdigest())


def decode_header(data, expected, deps):
    root, runtime, _ = dependencies(deps)
    if (
        type(data) is not bytes
        or not 0 < len(data) <= CONFIG_LIMIT
        or type(expected) is not str
        or re.fullmatch("[0-9a-f]{64}", expected) is None
        or hashlib.sha256(data).hexdigest() != expected
    ):
        raise ValueError("rooted startup configuration bytes or digest")
    value = runtime._json(data)
    validate_header(value, deps)
    if root.closure.canonical(value) != data:
        raise ValueError("rooted startup configuration encoding")
    return value


def decode_config(data, expected, manifest_data, deps):
    value = decode_header(data, expected, deps)
    validate_config(value, manifest_data, deps)
    return value


def context(config, service, reference, manifest_data, deps):
    if type(config) is not Configuration:
        raise ValueError("rooted startup configuration owner")
    value = decode_config(config.data, config.sha256, manifest_data, deps)
    _, runtime, guardian = dependencies(deps)
    spec = validate_config(value, manifest_data, deps)
    if (
        type(service) is not guardian.ServiceIdentity
        or type(service.unit) is not str
        or service.unit != guardian.unit_name(spec)
    ):
        raise ValueError("rooted startup service identity")
    runtime._integer(service.pid, 2, 2**31 - 1)
    runtime._integer(service.deadline_ns, value["startup_deadline_ns"], runtime.U64_MAX)
    if (
        type(service.invocation_id) is not str
        or re.fullmatch("[0-9a-f]{32}", service.invocation_id) is None
        or service.invocation_id == "0" * 32
    ):
        raise ValueError("rooted startup invocation")
    group = service.cgroup
    uid = value["root_plan"]["uid"]
    if (
        type(group) is not str
        or len(group) > 4096
        or any(not 32 <= ord(c) <= 126 for c in group)
        or not group.startswith(f"/user.slice/user-{uid}.slice/user@{uid}.service/")
        or not group.endswith("/" + service.unit)
        or str(PurePosixPath(group)) != group
        or ".." in PurePosixPath(group).parts
    ):
        raise ValueError("rooted startup cgroup")
    deps.artifact.check_metadata(reference)
    if reference["uid"] != uid or reference["gid"] != value["root_plan"]["gid"]:
        raise ValueError("rooted startup artifact owner")
    return value, guardian


def launch(config, manifest_data, deps):
    if type(config) is not Configuration:
        raise ValueError("rooted startup configuration owner")
    value = decode_config(config.data, config.sha256, manifest_data, deps)
    return deps.root.guardian.encode(
        {
            "kind": "launch",
            "payload": {
                "scope": "rooted-startup-launch-v1",
                "run_id": value["root_plan"]["run_id"],
                "config_sha256": config.sha256,
            },
        }
    )


def check_launch(frame, config, manifest_data, deps):
    guardian = deps.root.guardian
    if guardian.encode(guardian.decode(frame)) != launch(config, manifest_data, deps):
        raise ValueError("rooted startup LAUNCH mismatch")


def ready(config, service, reference, manifest_data, deps):
    _, guardian = context(config, service, reference, manifest_data, deps)
    return guardian.encode(
        {
            "kind": "ready",
            "payload": {
                "scope": "rooted-startup-ready-v1",
                "config_sha256": config.sha256,
                "service": service._asdict(),
                "startup": reference,
            },
        }
    )


def check_ready(frame, config, service, manifest_data, deps):
    root, runtime, guardian = dependencies(deps)
    row = guardian.decode(frame)
    if row["kind"] != "ready":
        raise ValueError("rooted startup expected READY")
    runtime._fields(row["payload"], ("scope", "config_sha256", "service", "startup"))
    reference = row["payload"]["startup"]
    if guardian.encode(row) != ready(config, service, reference, manifest_data, deps):
        raise ValueError("rooted startup READY mismatch")
    return runtime._json(root.closure.canonical(reference))


def bound_message(kind, config, service, reference, manifest_data, deps):
    _, guardian = context(config, service, reference, manifest_data, deps)
    payload = {
        "scope": f"rooted-startup-{kind}-v1",
        "config_sha256": config.sha256,
        "invocation_id": service.invocation_id,
        "startup_sha256": reference["sha256"],
    }
    if kind == "done":
        payload.update(
            outcome="startup-only-complete",
            accepted=False,
            native_authorized=False,
            full_contract_proven=False,
        )
    elif kind != "commit":
        raise ValueError("rooted startup message kind")
    return guardian.encode({"kind": kind, "payload": payload})


def commit(config, service, reference, manifest_data, deps):
    return bound_message("commit", config, service, reference, manifest_data, deps)


def done(config, service, reference, manifest_data, deps):
    return bound_message("done", config, service, reference, manifest_data, deps)


def check_commit(frame, config, service, reference, manifest_data, deps):
    guardian = deps.root.guardian
    if guardian.encode(guardian.decode(frame)) != commit(
        config, service, reference, manifest_data, deps
    ):
        raise ValueError("rooted startup COMMIT mismatch")


def check_done(frame, config, service, reference, manifest_data, deps):
    guardian = deps.root.guardian
    if guardian.encode(guardian.decode(frame)) != done(
        config, service, reference, manifest_data, deps
    ):
        raise ValueError("rooted startup DONE mismatch")


if __name__ == "__main__":
    raise SystemExit(77)

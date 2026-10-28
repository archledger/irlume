#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright the irlume contributors.
"""Typed rooted-service calls through an already-owned, bounded bus transport."""

import re
import types
from typing import NamedTuple


class Dependencies(NamedTuple):
    protocol: types.ModuleType
    protocol_deps: object
    transport: types.ModuleType


class RootedBus:
    """Borrow the bus. Creation failures retain intent; this object never closes it."""

    def __init__(self, bus, support):
        if (
            type(support) is not Dependencies
            or type(support.protocol) is not types.ModuleType
            or type(support.transport) is not types.ModuleType
        ):
            raise ValueError("rooted bus dependencies")
        self.root, _, _ = support.protocol.dependencies(support.protocol_deps)
        self.bus, self.support = bus, support
        self.creation_attempted = False
        self.start_reply = None
        self.partial = {}

    def config(self, config, manifest):
        protocol = self.support.protocol
        if type(config) is not protocol.Configuration:
            raise ValueError("rooted bus configuration")
        value = protocol.decode_config(
            config.data, config.sha256, manifest, self.support.protocol_deps
        )
        return value, protocol.validate_config(
            value, manifest, self.support.protocol_deps
        )

    def start(self, config, manifest, deadline):
        if self.creation_attempted:
            raise ValueError("rooted unit creation already attempted")
        self.root.runtime._integer(deadline, 1, self.root.runtime.U64_MAX)
        self.bus.remaining(deadline)
        value, spec = self.config(config, manifest)
        deadline = min(deadline, value["startup_deadline_ns"])
        self.bus.remaining(deadline)
        plan = value["root_plan"]
        self.root.service_properties(spec, plan, manifest)
        transport = self.support.transport
        base = self.root.guardian.service_properties(spec)
        kinds = {**transport.PROPERTY_TYPES, "AddRef": "b"}
        entries = [
            (name, self.bus.variant(kinds[name], item)) for name, item in base.items()
        ]
        entries.extend(self.root.wire_properties(plan))
        argv = self.root.entry_argv(plan, config.sha256)
        entries.append(
            ("ExecStart", self.bus.variant("commands", ((argv[0], argv, False),)))
        )
        for name, item in (
            ("WorkingDirectory", "/"),
            ("StandardInput", "null"),
            ("StandardOutput", "null"),
            ("StandardError", "null"),
        ):
            entries.append((name, self.bus.variant("s", item)))
        if len({name for name, _ in entries}) != len(entries):
            raise ValueError("duplicate rooted service property")
        self.bus.remaining(deadline)
        self.creation_attempted = True
        self.start_reply = self.bus.call(
            transport.MANAGER_PATH,
            transport.MANAGER,
            "StartTransientUnit",
            "ssa(sv)a(sa(sv))",
            (self.root.guardian.unit_name(spec), "fail", entries, []),
            deadline,
        )
        self.bus.remaining(deadline)
        if (
            type(self.start_reply) is not str
            or re.fullmatch(
                r"/org/freedesktop/systemd1/job/[1-9][0-9]{0,19}", self.start_reply
            )
            is None
        ):
            raise ValueError("rooted service creation reply")
        return self.start_reply

    def get_all(self, path, interface, label, deadline):
        self.bus.remaining(deadline)
        row = self.bus.call(
            path,
            "org.freedesktop.DBus.Properties",
            "GetAll",
            "s",
            (interface,),
            deadline,
        )
        if type(row) is not dict or len(row) > 4096:
            raise ValueError("rooted bus property dictionary")
        self.partial[label] = dict(row)
        self.bus.remaining(deadline)
        return row

    def normalize(self, row, kinds, deadline):
        result = {}
        for name, kind in kinds.items():
            self.bus.remaining(deadline)
            if name not in row:
                raise ValueError("missing rooted bus property: " + name)
            result[name] = self.bus.normal(row[name], kind)
        if "InvocationID" in result:
            result["InvocationID"] = bytes(result["InvocationID"]).hex()
        return result

    def observe(self, config, manifest, deadline):
        self.partial = {}
        self.root.runtime._integer(deadline, 1, self.root.runtime.U64_MAX)
        self.bus.remaining(deadline)
        value, spec = self.config(config, manifest)
        deadline = min(deadline, value["startup_deadline_ns"])
        self.bus.remaining(deadline)
        transport = self.support.transport
        path = self.bus.call(
            transport.MANAGER_PATH,
            transport.MANAGER,
            "GetUnit",
            "s",
            (self.root.guardian.unit_name(spec),),
            deadline,
        )
        self.partial["unit_path"] = path
        self.bus.remaining(deadline)
        if (
            type(path) is not str
            or re.fullmatch(r"/org/freedesktop/systemd1/unit/[A-Za-z0-9_]{1,255}", path)
            is None
        ):
            raise ValueError("rooted service unit path")
        before = self.get_all(
            path, transport.BUS_NAME + ".Unit", "unit_before", deadline
        )
        first = self.normalize(before, transport.UNIT_TYPES, deadline)
        service = self.get_all(
            path, transport.BUS_NAME + ".Service", "service", deadline
        )
        base = self.normalize(service, transport.PROPERTY_TYPES, deadline)
        kinds = {
            **self.root.PROPERTY_TYPES,
            "PrivateUsers": "b",
            "ProtectControlGroupsEx": "s",
        }
        roots = {}
        for name, kind in kinds.items():
            self.bus.remaining(deadline)
            if name not in service:
                raise ValueError("missing rooted bus property: " + name)
            roots[name] = (kind, self.root.normal_variant(service[name], kind))
        self.partial["root"] = roots
        after = self.get_all(path, transport.BUS_NAME + ".Unit", "unit_after", deadline)
        last = self.normalize(after, transport.UNIT_TYPES, deadline)
        if first != last:
            raise ValueError("rooted service changed during observation")
        self.root.check_properties(roots, value["root_plan"])
        self.bus.remaining(deadline)
        return {"service": {**first, **base}, "root": roots}


if __name__ == "__main__":
    raise SystemExit(77)

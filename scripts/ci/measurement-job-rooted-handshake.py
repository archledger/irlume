#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright the irlume contributors.
"""One-shot startup-only H/G controllers. No child or VM execution path exists."""

import types
from builtins import BaseExceptionGroup
from typing import NamedTuple

CLEANUP_FAILURES = (BaseException,)


class Dependencies(NamedTuple):
    protocol: types.ModuleType
    protocol_deps: object
    witness: types.ModuleType
    witness_deps: object
    artifact: types.ModuleType


class _Controller:
    host = False

    def __init__(self, config, manifest, support, effects):
        if type(support) is not Dependencies or any(
            type(module) is not types.ModuleType
            for module in (support.protocol, support.witness, support.artifact)
        ):
            raise ValueError("startup controller dependencies")
        if type(config) is not support.protocol.Configuration:
            raise ValueError("startup controller configuration")
        self.value = support.protocol.decode_config(
            config.data, config.sha256, manifest, support.protocol_deps
        )
        self.config, self.manifest, self.support, self.io = (
            config,
            manifest,
            support,
            effects,
        )
        self.root = support.protocol_deps.root
        self.spec = support.protocol.validate_config(
            self.value, manifest, support.protocol_deps
        )
        self.deadline = self.value["startup_deadline_ns"]
        self.previous = self.value["origin_ns"]
        self.used = self.control_attempted = self.prepare_attempted = False
        self.identity = self.reference = None
        self.state = "new"

    def check(self):
        now = self.io.now()
        self.root.runtime._integer(now, self.previous, self.root.runtime.U64_MAX)
        if now >= self.deadline:
            raise TimeoutError("rooted startup controller deadline")
        self.previous = now
        return now

    def call(self, function, *args, **kwargs):
        self.check()
        result = function(*args, **kwargs)
        self.check()
        return result

    def binding(self, starttime):
        if (
            type(self.identity) is not self.root.guardian.ServiceIdentity
            or type(self.identity.unit) is not str
            or self.identity.unit != self.root.guardian.unit_name(self.spec)
        ):
            raise ValueError("startup controller service identity")
        return self.support.witness.check_binding(
            {
                "run_id": self.spec.run_id,
                "transaction_sha256": self.config.sha256,
                "invocation_id": self.identity.invocation_id,
                "guardian_pid": self.identity.pid,
                "guardian_starttime": starttime,
                "startup_deadline_ns": self.deadline,
            },
            self.support.witness_deps,
        )

    def directory_identity(self):
        plan = self.value["root_plan"]["attempt"]
        return plan["device"], plan["inode"]

    def close_control(self):
        if self.control_attempted:
            self.control_attempted = False
            self.io.close_control()

    def record(self):
        return {
            "scope": "contained-job-rooted-startup-result-v1",
            "role": "H" if self.host else "G",
            "config_sha256": self.config.sha256,
            "startup_sha256": self.reference["sha256"],
            "service": self.identity._asdict(),
            "outcome": "startup-only-complete",
            "accepted": False,
            "native_authorized": False,
            "full_contract_proven": False,
        }

    def run(self):
        if self.used:
            raise ValueError("startup controller is one-shot")
        self.used = True
        errors = []
        result = None
        try:
            self.check()
            result = self.execute()
        except CLEANUP_FAILURES as error:
            errors.append(error)
        try:
            self.close_control()
        except CLEANUP_FAILURES as error:
            errors.append(error)
        if not errors:
            try:
                self.check()
            except CLEANUP_FAILURES as error:
                errors.append(error)
        if errors and self.host and self.prepare_attempted:
            cleanup_end = min(
                self.deadline + self.root.guardian.STOP_NS, self.root.runtime.U64_MAX
            )
            try:
                self.io.abort(
                    self.config, self.identity, type(errors[0]).__name__, cleanup_end
                )
            except CLEANUP_FAILURES as error:
                errors.append(error)
        if errors:
            self.state = "failed"
            if len(errors) == 1:
                raise errors[0]
            raise BaseExceptionGroup("startup controller failure and cleanup", errors)
        self.state = "complete"
        return result


class Guardian(_Controller):
    """Effects collect/preflight without retained attempt FDs or child creation.

    G holds no manager connection. Its service identity is H's, from LAUNCH,
    bound to G's own kernel view by the cgroup ID that comes with it, before
    the witness is written or READY sent.
    """

    def execute(self):
        support, protocol = self.support, self.support.protocol
        # The observation and the page digests of G's own runtime tree.
        snapshot = self.call(self.io.collect, self.config, self.manifest, self.deadline)
        self.state = "collected"
        # Kernel-local checks only; the effects keep the view for bind_service.
        self.call(self.io.preflight, self.config, self.manifest, self.deadline)
        self.root.runtime._integer(
            snapshot.observation["started_ns"], self.value["origin_ns"], self.check()
        )
        directory = self.io.open_attempt(self.config, self.deadline)
        if type(directory) is not int or directory < 3:
            raise ValueError("startup attempt descriptor")
        with support.artifact.owned(directory):
            self.check()
            # Nothing crosses the control socket before the attempt is proven.
            support.artifact.check_directory(directory, self.directory_identity())
            self.control_attempted = True
            self.call(self.io.connect, self.config, self.deadline)
            frame = self.call(self.io.receive, self.deadline)
            self.identity, cgroup_id = protocol.check_launch(
                frame, self.config, self.manifest, support.protocol_deps
            )
            starttime = self.call(
                self.io.bind_service,
                self.config,
                self.manifest,
                self.identity,
                cgroup_id,
                self.deadline,
            )
            binding = self.binding(starttime)
            # Still inside the witness window that starts at the snapshot.
            data, digest = self.call(
                support.witness.encode,
                snapshot.observation,
                self.value["root_plan"],
                self.manifest,
                binding,
                support.witness_deps,
                pages=snapshot.pages,
                clock=self.io.now,
            )
            self.check()
            self.reference = self.call(
                support.artifact.write_closed,
                directory,
                self.directory_identity(),
                data,
                digest,
                self.deadline,
                clock=self.io.now,
            )
            self.state = "published"
            self.call(
                self.io.send,
                protocol.ready(
                    self.config,
                    self.identity,
                    self.reference,
                    self.manifest,
                    support.protocol_deps,
                ),
                self.deadline,
            )
            self.state = "ready"
            frame = self.call(self.io.receive, self.deadline)
            protocol.check_commit(
                frame,
                self.config,
                self.identity,
                self.reference,
                self.manifest,
                support.protocol_deps,
            )
            self.call(self.io.require_idle, self.deadline)
            self.state = "committed"
        self.check()
        self.call(
            self.io.send,
            protocol.done(
                self.config,
                self.identity,
                self.reference,
                self.manifest,
                support.protocol_deps,
            ),
            self.deadline,
        )
        return self.record()


class Host(_Controller):
    """Caller retains admission/attempt ownership; this controller never releases it.

    pages are the page digests of H's own prepared runtime; H checks G's
    mapped rows with them, never with anything G sends.
    """

    host = True

    def __init__(self, config, manifest, support, effects, terminal_check, *, pages):
        super().__init__(config, manifest, support, effects)
        if type(terminal_check) is not types.FunctionType:
            raise ValueError("startup terminal checker")
        if type(pages) is not types.MappingProxyType:
            raise ValueError("startup controller runtime pages")
        self.terminal_check = terminal_check
        self.pages = pages

    def execute(self):
        support, protocol = self.support, self.support.protocol
        self.prepare_attempted = True
        self.call(self.io.prepare, self.config, self.manifest, self.deadline)
        self.identity = self.call(self.io.start, self.config, self.deadline)
        starttime = self.call(self.io.process_start, self.identity, self.deadline)
        cgroup_id = self.call(self.io.cgroup_id, self.identity, self.deadline)
        binding = self.binding(starttime)
        self.control_attempted = True
        self.call(self.io.connect, self.identity, self.deadline)
        self.call(
            self.io.send,
            protocol.launch(
                self.config,
                self.identity,
                cgroup_id,
                self.manifest,
                support.protocol_deps,
            ),
            self.deadline,
        )
        frame = self.call(self.io.receive, self.deadline)
        self.reference = protocol.check_ready(
            frame, self.config, self.identity, self.manifest, support.protocol_deps
        )
        self.state = "ready"
        directory = self.call(self.io.attempt_fd, self.deadline)
        data = self.call(
            support.artifact.read_closed,
            directory,
            self.directory_identity(),
            self.reference,
            self.deadline,
            clock=self.io.now,
        )
        observation = self.call(
            support.witness.decode,
            data,
            self.reference["sha256"],
            self.value["root_plan"],
            self.manifest,
            binding,
            support.witness_deps,
            pages=self.pages,
            clock=self.io.now,
        )
        self.root.runtime._integer(
            observation["started_ns"], self.value["origin_ns"], self.check()
        )
        self.call(self.io.recheck, self.identity, starttime, self.deadline)
        self.state = "verified"
        self.call(
            self.io.send,
            protocol.commit(
                self.config,
                self.identity,
                self.reference,
                self.manifest,
                support.protocol_deps,
            ),
            self.deadline,
        )
        frame = self.call(self.io.receive, self.deadline)
        protocol.check_done(
            frame,
            self.config,
            self.identity,
            self.reference,
            self.manifest,
            support.protocol_deps,
        )
        self.call(self.io.expect_eof, self.deadline)
        self.close_control()
        self.check()
        terminal = self.call(self.io.wait_terminal, self.identity, self.deadline)
        self.terminal_check(
            terminal,
            self.identity,
            self.identity.deadline_ns - self.root.guardian.HOST_NS,
            self.check(),
        )
        self.check()
        record = self.record()
        self.call(self.io.finish, self.root.closure.canonical(record), self.deadline)
        return record


if __name__ == "__main__":
    raise SystemExit(77)

#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright the irlume contributors.
"""Inert H/G controller ordering with real synthetic codec/file validation."""

import copy
import hashlib
import importlib.util
import json
import os
import tempfile
import unittest
from builtins import BaseExceptionGroup
from pathlib import Path
from types import MappingProxyType
from typing import NamedTuple
from unittest import mock

HERE = Path(__file__).resolve().parent


def load(name, filename):
    spec = importlib.util.spec_from_file_location(name, HERE / filename)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


controller = load("rooted_handshake", "measurement-job-rooted-handshake.py")
proof_tests = load("handshake_proof", "test-measurement-job-startup-witness.py")
protocol = load("handshake_protocol", "measurement-job-rooted-protocol.py")
artifact = load("handshake_artifact", "measurement-job-witness-file.py")
host = load("handshake_host", "measurement-job-guardian-host.py")


class Collected(NamedTuple):
    """collect_startup's result: the observation and G's own page digests."""

    observation: dict
    pages: object


class Effects:
    def __init__(self, fixture, role, messages=()):
        self.f = fixture
        self.role = role
        self.messages = list(messages)
        self.sent, self.calls = [], []
        self.time = 1_006_000
        self.fd = None
        self.fail = None
        self.late = None
        self.opened = []
        self.limit = protocol.decode_config(
            fixture.config.data,
            fixture.config.sha256,
            fixture.manifest,
            fixture.protocol_deps,
        )["startup_deadline_ns"]
        fixture.addCleanup(self.close_borrowed)

    def close_borrowed(self):
        if self.fd is not None:
            fd, self.fd = self.fd, None
            os.close(fd)

    def now(self):
        return self.time

    def mark(self, name):
        self.calls.append(name)
        if self.late == name:
            self.time = self.limit
        if self.fail == name or type(self.fail) is set and name in self.fail:
            raise ValueError("injected " + name)

    def collect(self, config, manifest, deadline):
        self.mark("collect")
        return Collected(copy.deepcopy(self.f.observation), self.f.pages)

    def preflight(self, config, manifest, deadline):
        self.mark("preflight")
        return "local-view"

    def bind_service(self, config, manifest, identity, cgroup_id, deadline):
        self.mark("bind-service")
        self.bound = identity, cgroup_id
        return 123

    def open_attempt(self, config, deadline):
        self.mark("open-attempt")
        fd = os.open(self.f.path, os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC)
        self.opened.append(fd)
        if self.late == "open-attempt":
            self.time = deadline
        return fd

    def prepare(self, config, manifest, deadline):
        self.mark("prepare")
        self.fd = os.open(self.f.path, os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC)

    def start(self, config, deadline):
        self.mark("start")
        return self.f.service

    def process_start(self, identity, deadline):
        self.mark("process-start")
        return 123

    def cgroup_id(self, identity, deadline):
        self.mark("cgroup-id")
        self.cgroup_identity = identity
        return self.f.cgroup_id

    def attempt_fd(self, deadline):
        self.mark("attempt-fd")
        return self.fd

    def connect(self, identity, deadline):
        self.mark("connect")

    def receive(self, deadline):
        self.mark("receive")
        if self.messages:
            return self.messages.pop(0)
        if not self.sent:
            return protocol.launch(
                self.f.config,
                self.f.service,
                self.f.cgroup_id,
                self.f.manifest,
                self.f.protocol_deps,
            )
        ready = self.f.guardian.decode(self.sent[0])["payload"]["startup"]
        return protocol.commit(
            self.f.config, self.f.service, ready, self.f.manifest, self.f.protocol_deps
        )

    def send(self, data, deadline):
        self.mark("send-" + self.f.guardian.decode(data)["kind"])
        self.sent.append(data)

    def require_idle(self, deadline):
        self.mark("idle")

    def recheck(self, identity, starttime, deadline):
        self.mark("recheck")

    def expect_eof(self, deadline):
        self.mark("eof")

    def close_control(self):
        self.mark("close-control")

    def wait_terminal(self, identity, deadline):
        self.mark("wait-terminal")
        self.time = 1_008_000
        return {
            "processes": (),
            "unit": {
                "Id": identity.unit,
                "InvocationID": identity.invocation_id,
                "MainPID": 0,
                "ActiveState": "inactive",
                "SubState": "dead",
                "Result": "success",
                "ExecMainCode": 1,
                "ExecMainStatus": 0,
                "ExecMainStartTimestampMonotonic": 1001,
                "ExecMainExitTimestampMonotonic": 1007,
            },
        }

    def finish(self, data, deadline):
        self.mark("finish")
        self.result = json.loads(data)

    def release(self, deadline):
        self.mark("release")
        os.close(self.fd)
        self.fd = None

    def abort(self, config, identity, reason, deadline):
        self.mark("abort")
        if self.fd is not None:
            os.close(self.fd)
            self.fd = None

    def spawn(self, *args):
        raise AssertionError("startup-only controller must not spawn")


class HandshakeTests(unittest.TestCase):
    def setUp(self):
        fixture = proof_tests.WitnessTests(
            "test_lossless_canonical_round_trip_without_authority"
        )
        self.addCleanup(fixture.doCleanups)
        fixture.setUp()
        self.plan = fixture.plan
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.path = Path(temporary.name)
        info = self.path.stat()
        self.plan["attempt"].update(
            path=str(self.path), device=info.st_dev, inode=info.st_ino
        )
        self.observation = fixture.observation
        # One prepared runtime: G's tree and H's inputs hash the same bytes.
        self.pages = fixture.pages
        for fs in (
            self.observation["initial_filesystem"],
            self.observation["filesystem"],
        ):
            node = fs["nodes"]["/run/irlume/attempt"]
            node.update(
                device=info.st_dev,
                inode=info.st_ino,
                mode=info.st_mode,
                uid=info.st_uid,
                gid=info.st_gid,
                size=info.st_size,
                links=info.st_nlink,
                mtime_ns=info.st_mtime_ns,
                ctime_ns=info.st_ctime_ns,
            )
            fs["started_ns"] += 1_000_900
            fs["finished_ns"] += 1_000_900
            fs["proc"]["started_ns"] += 1_000_900
            fs["proc"]["finished_ns"] += 1_000_900
        self.observation["started_ns"] += 1_000_900
        self.observation["finished_ns"] += 1_000_900
        self.protocol_deps = protocol.Dependencies(
            fixture.deps.preflight.root, artifact
        )
        self.guardian = self.protocol_deps.root.guardian
        manifest = self.protocol_deps.root.runtime._json(fixture.manifest)
        row = dict(
            next(
                row for row in manifest["members"] if row["path"] == "usr/bin/python3"
            ),
            path="usr/bin/qemu-system-x86_64",
        )
        manifest["members"].append(row)
        manifest["members"].sort(key=lambda row: row["path"])
        self.manifest = self.protocol_deps.root.closure.canonical(manifest)
        self.plan["manifest"]["sha256"] = hashlib.sha256(self.manifest).hexdigest()
        self.observation["runtime_manifest_sha256"] = self.plan["manifest"]["sha256"]
        self.observation["files"]["/usr/bin/qemu-system-x86_64"] = dict(
            self.observation["files"]["/usr/bin/python3"], inode=999
        )
        self.observation["core"] = fixture.deps.preflight.core_witness(
            self.plan,
            self.observation["filesystem"],
            5_001_000_000,
            1_006_000,
        )
        sample = (
            proof_tests.preflight_tests.fixtures.fixtures.guardian_tests.specification()
        )
        spec = self.guardian.Specification(**sample._asdict())._replace(
            base=self.plan["base"]["path"],
            payload=self.plan["payload"]["path"],
            overlay=str(self.path / "overlay.qcow2"),
        )
        client = {
            "pid": 4000,
            "uid": self.plan["uid"],
            "gid": self.plan["gid"],
            "starttime": 321,
        }
        self.config = protocol.make_config(
            spec,
            self.plan,
            client,
            1_000_000,
            self.manifest,
            self.protocol_deps,
        )
        self.service = self.guardian.ServiceIdentity(
            self.guardian.unit_name(spec),
            "d" * 32,
            4242,
            f"/user.slice/user-{self.plan['uid']}.slice/user@{self.plan['uid']}.service/app.slice/"
            + self.guardian.unit_name(spec),
            self.guardian.HOST_NS + 1_001_000,
        )
        self.cgroup_id = 286458
        self.support = controller.Dependencies(
            protocol, self.protocol_deps, proof_tests.codec, fixture.deps, artifact
        )

    def guardian_run(self, fail=None):
        effects = Effects(self, "G")
        effects.fail = fail
        runner = controller.Guardian(self.config, self.manifest, self.support, effects)
        return runner, effects

    def test_successful_guardian_never_spawns_and_closes_before_done(self):
        runner, effects = self.guardian_run()
        self.assertEqual(effects.calls, [])
        result = runner.run()
        self.assertEqual(result["outcome"], "startup-only-complete")
        self.assertFalse(result["accepted"])
        self.assertLess(
            effects.calls.index("collect"), effects.calls.index("open-attempt")
        )
        self.assertEqual(
            [self.guardian.decode(frame)["kind"] for frame in effects.sent],
            ["ready", "done"],
        )
        with self.assertRaises(ValueError):
            runner.run()

    def recorded_guardian_run(self, fail=None):
        """Run G, recording the witness write among its effects."""
        runner, effects = self.guardian_run(fail)
        write = artifact.write_closed

        def recorded(*args, **kwargs):
            effects.calls.append("write-closed")
            return write(*args, **kwargs)

        with mock.patch.object(artifact, "write_closed", side_effect=recorded):
            runner.run()
        return runner, effects

    def test_guardian_receives_launch_before_publishing(self):
        runner, effects = self.recorded_guardian_run()
        self.assertEqual(
            effects.calls,
            [
                "collect",
                "preflight",
                "open-attempt",
                "connect",
                "receive",
                "bind-service",
                "write-closed",
                "send-ready",
                "receive",
                "idle",
                "send-done",
                "close-control",
            ],
        )
        # G's identity is H's LAUNCH identity, checked locally by bind_service
        # with the cgroup ID that came with it.
        self.assertEqual(effects.bound, (self.service, self.cgroup_id))
        self.assertEqual(runner.identity, self.service)
        ready = self.guardian.decode(effects.sent[0])["payload"]
        self.assertEqual(ready["service"], self.service._asdict())

    def test_guardian_refuses_launch_service_before_publishing(self):
        for fail in ("bind-service", "receive"):
            runner, effects = self.guardian_run()
            effects.fail = fail
            write = artifact.write_closed
            with (
                self.subTest(fail=fail),
                mock.patch.object(
                    artifact,
                    "write_closed",
                    side_effect=AssertionError("published before binding"),
                ),
                self.assertRaisesRegex(ValueError, "injected " + fail),
            ):
                runner.run()
            self.assertIs(artifact.write_closed, write)
            self.assertEqual(effects.sent, [])
            self.assertFalse((self.path / artifact.NAME).exists())
            self.assertIn("close-control", effects.calls)
        # A LAUNCH for another unit never reaches the local binding.
        runner, effects = self.guardian_run()
        other = self.service._replace(unit="irlume-job-guardian-other.service")
        frame = self.guardian.decode(
            protocol.launch(
                self.config,
                self.service,
                self.cgroup_id,
                self.manifest,
                self.protocol_deps,
            )
        )
        frame["payload"]["service"] = other._asdict()
        effects.messages = [self.guardian.encode(frame)]
        with self.assertRaisesRegex(ValueError, "rooted startup service identity"):
            runner.run()
        self.assertNotIn("bind-service", effects.calls)
        self.assertEqual(effects.sent, [])
        self.assertFalse((self.path / artifact.NAME).exists())

    def test_host_sends_launch_with_exactly_its_identity(self):
        guardian, g_effects = self.guardian_run()
        guardian.run()
        effects = Effects(self, "H", g_effects.sent)
        runner = controller.Host(
            self.config,
            self.manifest,
            self.support,
            effects,
            host.verify_service_terminal,
            pages=self.pages,
        )
        runner.run()
        self.assertEqual(
            effects.calls[:5],
            ["prepare", "start", "process-start", "cgroup-id", "connect"],
        )
        self.assertLess(
            effects.calls.index("connect"), effects.calls.index("send-launch")
        )
        # H asks for the cgroup ID of exactly the identity it started.
        self.assertIs(effects.cgroup_identity, self.service)
        self.assertEqual(
            effects.sent[0],
            protocol.launch(
                self.config,
                self.service,
                self.cgroup_id,
                self.manifest,
                self.protocol_deps,
            ),
        )
        payload = self.guardian.decode(effects.sent[0])["payload"]
        self.assertEqual(payload["service"], self.service._asdict())
        self.assertEqual(payload["cgroup_id"], self.cgroup_id)
        effects.release(runner.deadline)

    def test_guardian_encodes_with_its_own_collected_pages(self):
        runner, _ = self.guardian_run()
        with mock.patch.object(
            proof_tests.codec, "encode", wraps=proof_tests.codec.encode
        ) as encode:
            runner.run()
        encode.assert_called_once()
        self.assertIs(encode.call_args.kwargs["pages"], self.pages)
        self.assertEqual(encode.call_args.args[0], self.observation)

    def test_host_decodes_with_its_own_pages_and_refuses_other_bytes(self):
        guardian, g_effects = self.guardian_run()
        guardian.run()
        effects = Effects(self, "H", g_effects.sent)
        pages = MappingProxyType(dict(self.pages))
        runner = controller.Host(
            self.config,
            self.manifest,
            self.support,
            effects,
            host.verify_service_terminal,
            pages=pages,
        )
        with mock.patch.object(
            proof_tests.codec, "decode", wraps=proof_tests.codec.decode
        ) as decode:
            runner.run()
        self.assertIs(decode.call_args.kwargs["pages"], pages)
        effects.release(runner.deadline)
        # H's runtime holds other bytes for a page G has mapped.
        python3 = "/usr/bin/python3"
        other = MappingProxyType(
            {
                **self.pages,
                python3: (b"\0" * 32, *self.pages[python3][1:]),
            }
        )
        effects = Effects(self, "H", g_effects.sent)
        runner = controller.Host(
            self.config,
            self.manifest,
            self.support,
            effects,
            host.verify_service_terminal,
            pages=other,
        )
        with self.assertRaisesRegex(ValueError, "^runtime mapped bytes differ$"):
            runner.run()
        self.assertNotIn("send-commit", effects.calls)
        self.assertIn("abort", effects.calls)

    def test_host_requires_read_only_runtime_pages(self):
        for pages in (dict(self.pages), None, ()):
            with (
                self.subTest(pages=type(pages).__name__),
                self.assertRaisesRegex(
                    ValueError, "^startup controller runtime pages$"
                ),
            ):
                controller.Host(
                    self.config,
                    self.manifest,
                    self.support,
                    Effects(self, "H"),
                    host.verify_service_terminal,
                    pages=pages,
                )
        with self.assertRaises(TypeError):
            controller.Host(
                self.config,
                self.manifest,
                self.support,
                Effects(self, "H"),
                host.verify_service_terminal,
            )

    def test_host_sends_no_launch_without_a_cgroup_id(self):
        guardian, g_effects = self.guardian_run()
        guardian.run()
        for value in (0, None, True, 2**64):
            effects = Effects(self, "H", g_effects.sent)
            effects.cgroup_id = lambda identity, deadline, value=value: value
            runner = controller.Host(
                self.config,
                self.manifest,
                self.support,
                effects,
                host.verify_service_terminal,
                pages=self.pages,
            )
            with self.subTest(value=value), self.assertRaises(ValueError):
                runner.run()
            self.assertEqual(effects.sent, [])
            self.assertIn("abort", effects.calls)

    def test_host_validates_real_closed_witness_before_commit_and_release(self):
        guardian, g_effects = self.guardian_run()
        guardian.run()
        effects = Effects(self, "H", g_effects.sent)
        runner = controller.Host(
            self.config,
            self.manifest,
            self.support,
            effects,
            host.verify_service_terminal,
            pages=self.pages,
        )
        result = runner.run()
        self.assertFalse(result["native_authorized"])
        self.assertLess(
            effects.calls.index("recheck"), effects.calls.index("send-commit")
        )
        self.assertLess(
            effects.calls.index("wait-terminal"), effects.calls.index("finish")
        )
        self.assertNotIn("release", effects.calls)
        self.assertIsNotNone(effects.fd)
        effects.release(runner.deadline)

    def test_collection_failure_never_opens_attempt_or_connects(self):
        runner, effects = self.guardian_run(fail="collect")
        with self.assertRaises(ValueError):
            runner.run()
        self.assertNotIn("open-attempt", effects.calls)
        self.assertNotIn("connect", effects.calls)

    def test_late_directory_acquisition_is_closed_before_timeout_returns(self):
        runner, effects = self.guardian_run()
        effects.late = "open-attempt"
        before = set(os.listdir("/proc/self/fd"))
        try:
            with self.assertRaises(TimeoutError):
                runner.run()
            self.assertEqual(set(os.listdir("/proc/self/fd")), before)
        finally:
            for fd in effects.opened:
                try:
                    os.close(fd)
                except OSError:
                    pass

    def test_modified_artifact_blocks_host_commit_and_retains_cleanup_intent(self):
        guardian, g_effects = self.guardian_run()
        guardian.run()
        path = self.path / artifact.NAME
        path.chmod(0o600)
        path.write_bytes(b"corrupt")
        path.chmod(0o400)
        effects = Effects(self, "H", g_effects.sent)
        runner = controller.Host(
            self.config,
            self.manifest,
            self.support,
            effects,
            host.verify_service_terminal,
            pages=self.pages,
        )
        with self.assertRaises(ValueError):
            runner.run()
        self.assertNotIn("send-commit", effects.calls)
        self.assertNotIn("finish", effects.calls)
        self.assertNotIn("release", effects.calls)
        self.assertIn("abort", effects.calls)

    def test_host_recheck_failure_blocks_commit(self):
        guardian, g_effects = self.guardian_run()
        guardian.run()
        effects = Effects(self, "H", g_effects.sent)
        effects.fail = "recheck"
        runner = controller.Host(
            self.config,
            self.manifest,
            self.support,
            effects,
            host.verify_service_terminal,
            pages=self.pages,
        )
        with self.assertRaises(ValueError):
            runner.run()
        self.assertNotIn("send-commit", effects.calls)
        self.assertIn("close-control", effects.calls)
        self.assertIn("abort", effects.calls)

    def test_wrong_commit_is_never_treated_as_startup_completion(self):
        runner, effects = self.guardian_run()
        original_receive = effects.receive

        def receive(deadline):
            frame = original_receive(deadline)
            row = self.guardian.decode(frame)
            if row["kind"] == "commit":
                row["payload"]["startup_sha256"] = "f" * 64
                return self.guardian.encode(row)
            return frame

        effects.receive = receive
        with self.assertRaises(ValueError):
            runner.run()
        self.assertNotIn("send-done", effects.calls)
        self.assertEqual(effects.calls.count("open-attempt"), 1)
        self.assertIn("close-control", effects.calls)

    def test_guardian_closes_attempt_before_done(self):
        runner, effects = self.guardian_run()
        send = effects.send

        def check_closed(data, deadline):
            if self.guardian.decode(data)["kind"] == "done":
                with self.assertRaises(OSError):
                    os.fstat(effects.opened[-1])
            send(data, deadline)

        effects.send = check_closed
        runner.run()

    def test_changed_host_process_identity_rejects_the_witness(self):
        guardian, g_effects = self.guardian_run()
        guardian.run()
        effects = Effects(self, "H", g_effects.sent)
        effects.process_start = lambda identity, deadline: 124
        runner = controller.Host(
            self.config,
            self.manifest,
            self.support,
            effects,
            host.verify_service_terminal,
            pages=self.pages,
        )
        with self.assertRaises(ValueError):
            runner.run()
        self.assertNotIn("send-commit", effects.calls)
        self.assertIn("abort", effects.calls)

    def test_terminal_mismatch_prevents_finish_or_release(self):
        guardian, g_effects = self.guardian_run()
        guardian.run()
        effects = Effects(self, "H", g_effects.sent)
        wait = effects.wait_terminal

        def mismatch(identity, deadline):
            proof = wait(identity, deadline)
            proof["processes"] = (9999,)
            return proof

        effects.wait_terminal = mismatch
        runner = controller.Host(
            self.config,
            self.manifest,
            self.support,
            effects,
            host.verify_service_terminal,
            pages=self.pages,
        )
        with self.assertRaises(ValueError):
            runner.run()
        self.assertNotIn("finish", effects.calls)
        self.assertNotIn("release", effects.calls)
        self.assertIn("abort", effects.calls)

    def test_prepare_failure_retains_host_cleanup_intent(self):
        effects = Effects(self, "H")
        effects.fail = "prepare"
        runner = controller.Host(
            self.config,
            self.manifest,
            self.support,
            effects,
            host.verify_service_terminal,
            pages=self.pages,
        )
        with self.assertRaises(ValueError):
            runner.run()
        self.assertEqual(effects.calls, ["prepare", "abort"])
        with self.assertRaises(ValueError):
            runner.run()

    def test_primary_and_control_close_errors_are_retained(self):
        runner, effects = self.guardian_run()
        effects.fail = {"receive", "close-control"}
        before = set(os.listdir("/proc/self/fd"))
        with self.assertRaises(BaseExceptionGroup) as caught:
            runner.run()
        self.assertEqual(len(caught.exception.exceptions), 2)
        self.assertEqual(set(os.listdir("/proc/self/fd")), before)
        self.assertEqual(effects.calls.count("open-attempt"), 1)

    def test_cancellation_before_collection_does_not_acquire_outputs(self):
        runner, effects = self.guardian_run()

        def cancelled(*args):
            raise KeyboardInterrupt("cancelled")

        effects.collect = cancelled
        with self.assertRaises(KeyboardInterrupt):
            runner.run()
        self.assertEqual(effects.calls, [])

    def test_late_host_recheck_cannot_send_commit(self):
        guardian, g_effects = self.guardian_run()
        guardian.run()
        effects = Effects(self, "H", g_effects.sent)
        effects.late = "recheck"
        runner = controller.Host(
            self.config,
            self.manifest,
            self.support,
            effects,
            host.verify_service_terminal,
            pages=self.pages,
        )
        with self.assertRaises(TimeoutError):
            runner.run()
        self.assertNotIn("send-commit", effects.calls)
        self.assertIn("abort", effects.calls)

    def test_wrong_attempt_identity_is_rejected_before_write_or_connect(self):
        wrong = tempfile.TemporaryDirectory()
        self.addCleanup(wrong.cleanup)
        runner, effects = self.guardian_run()
        effects.open_attempt = lambda config, deadline: os.open(
            wrong.name, os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC
        )
        before = set(os.listdir("/proc/self/fd"))
        with self.assertRaises(ValueError):
            runner.run()
        self.assertEqual(set(os.listdir("/proc/self/fd")), before)
        self.assertFalse((Path(wrong.name) / artifact.NAME).exists())
        self.assertNotIn("connect", effects.calls)

    def test_failed_controller_cannot_retry_any_effect(self):
        runner, effects = self.guardian_run(fail="collect")
        with self.assertRaises(ValueError):
            runner.run()
        calls = list(effects.calls)
        with self.assertRaises(ValueError):
            runner.run()
        self.assertEqual(effects.calls, calls)

    def test_late_control_close_prevents_returning_success(self):
        runner, effects = self.guardian_run()
        effects.late = "close-control"
        with self.assertRaises(TimeoutError):
            runner.run()
        self.assertEqual(runner.state, "failed")
        self.assertIn("close-control", effects.calls)

    def test_host_refuses_a_correctly_bound_witness_from_before_its_origin(self):
        config = protocol.decode_config(
            self.config.data, self.config.sha256, self.manifest, self.protocol_deps
        )
        observation = copy.deepcopy(self.observation)
        started = config["origin_ns"] - 1
        observation["started_ns"] = started
        for view in (observation["initial_filesystem"], observation["filesystem"]):
            view["started_ns"] = started
            view["proc"]["started_ns"] = started
        deadline = config["startup_deadline_ns"]
        observation["core"] = self.support.witness_deps.preflight.core_witness(
            self.plan, observation["filesystem"], deadline, 1_006_000
        )
        binding = {
            "run_id": self.plan["run_id"],
            "transaction_sha256": self.config.sha256,
            "invocation_id": self.service.invocation_id,
            "guardian_pid": self.service.pid,
            "guardian_starttime": 123,
            "startup_deadline_ns": deadline,
        }
        data, digest = self.support.witness.encode(
            observation,
            self.plan,
            self.manifest,
            binding,
            self.support.witness_deps,
            pages=self.pages,
            clock=lambda: 1_006_000,
        )
        fd = os.open(self.path, os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC)
        try:
            metadata = artifact.write_closed(
                fd,
                (self.plan["attempt"]["device"], self.plan["attempt"]["inode"]),
                data,
                digest,
                deadline,
                clock=lambda: 1_006_000,
            )
        finally:
            os.close(fd)
        frames = [
            protocol.ready(
                self.config, self.service, metadata, self.manifest, self.protocol_deps
            ),
            protocol.done(
                self.config, self.service, metadata, self.manifest, self.protocol_deps
            ),
        ]
        effects = Effects(self, "H", frames)
        runner = controller.Host(
            self.config,
            self.manifest,
            self.support,
            effects,
            host.verify_service_terminal,
            pages=self.pages,
        )
        with self.assertRaises(ValueError):
            runner.run()
        self.assertNotIn("send-commit", effects.calls)
        self.assertIn("abort", effects.calls)
        self.assertNotIn("release", effects.calls)


if __name__ == "__main__":
    unittest.main()

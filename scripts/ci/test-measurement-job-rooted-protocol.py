#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright the irlume contributors.
"""Inert rooted configuration and wire contracts; never start a service or VM."""

import copy
import hashlib
import importlib.util
import os
import unittest
from pathlib import Path
from unittest import mock

HERE = Path(__file__).resolve().parent


def load(name, filename):
    spec = importlib.util.spec_from_file_location(name, HERE / filename)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


protocol = load("rooted_protocol", "measurement-job-rooted-protocol.py")
root_tests = load("protocol_root_tests", "test-measurement-job-root.py")
artifact = load("protocol_artifact", "measurement-job-witness-file.py")


class ProtocolTests(unittest.TestCase):
    def setUp(self):
        self.root = root_tests.root
        self.deps = protocol.Dependencies(self.root, artifact)
        self.plan, manifest = root_tests.selection()
        self.plan["uid"], self.plan["gid"] = os.getuid(), os.getgid()
        value = self.root.runtime._json(manifest)
        member = dict(
            next(row for row in value["members"] if row["path"] == "usr/bin/python3")
        )
        member["path"] = "usr/bin/qemu-system-x86_64"
        value["members"].append(member)
        value["members"].sort(key=lambda row: row["path"])
        self.manifest = self.root.closure.canonical(value)
        self.plan["manifest"]["sha256"] = hashlib.sha256(self.manifest).hexdigest()
        sample = root_tests.guardian_tests.specification(
            base=self.plan["base"]["path"],
            payload=self.plan["payload"]["path"],
            overlay=self.plan["attempt"]["path"] + "/overlay.qcow2",
        )
        self.spec = self.root.guardian.Specification(**sample._asdict())
        self.client = {
            "pid": 4000,
            "uid": self.plan["uid"],
            "gid": self.plan["gid"],
            "starttime": 100,
        }
        self.config = protocol.make_config(
            self.spec,
            self.plan,
            self.client,
            1_000_000,
            self.manifest,
            self.deps,
        )
        self.service = self.root.guardian.ServiceIdentity(
            self.root.guardian.unit_name(self.spec),
            "d" * 32,
            4200,
            f"/user.slice/user-{self.plan['uid']}.slice/user@{self.plan['uid']}.service/app.slice/"
            + self.root.guardian.unit_name(self.spec),
            301_000_000_000,
        )
        self.reference = {
            "device": 1,
            "inode": 2,
            "mode": 0o100400,
            "uid": os.getuid(),
            "gid": os.getgid(),
            "links": 1,
            "size": 100,
            "mtime_ns": 0,
            "ctime_ns": 0,
            "sha256": "e" * 64,
        }

    def test_canonical_config_preserves_host_coordinates_and_is_detached(self):
        value = protocol.decode_config(
            self.config.data, self.config.sha256, self.manifest, self.deps
        )
        self.plan["base"]["path"] = "/changed"
        self.client["pid"] = 9999
        self.assertEqual(value["host_spec"]["base"], "/private/base.raw")
        self.assertEqual(value["client"]["pid"], 4000)
        self.assertEqual(value["mode"], "startup-only")

    def test_config_mismatch_or_late_version_does_not_fall_back(self):
        original = protocol.decode_config(
            self.config.data, self.config.sha256, self.manifest, self.deps
        )
        for change in ("scope", "base", "client", "deadline", "extra"):
            value = copy.deepcopy(original)
            if change == "scope":
                value["scope"] = "contained-job-guardian-config-v1"
            elif change == "base":
                value["host_spec"]["base"] = "/run/irlume/base.raw"
            elif change == "client":
                value["client"]["uid"] += 1
            elif change == "deadline":
                value["startup_deadline_ns"] += 1
            else:
                value["extra"] = True
            data = self.root.closure.canonical(value)
            with self.subTest(change=change), self.assertRaises(ValueError):
                protocol.decode_config(
                    data, hashlib.sha256(data).hexdigest(), self.manifest, self.deps
                )

    def test_ready_commit_done_bind_same_config_service_and_artifact(self):
        request = protocol.launch(self.config, self.service, self.manifest, self.deps)
        self.assertEqual(
            protocol.check_launch(request, self.config, self.manifest, self.deps),
            self.service,
        )
        ready = protocol.ready(
            self.config, self.service, self.reference, self.manifest, self.deps
        )
        self.assertEqual(
            protocol.check_ready(
                ready, self.config, self.service, self.manifest, self.deps
            ),
            self.reference,
        )
        for make, check in (
            (protocol.commit, protocol.check_commit),
            (protocol.done, protocol.check_done),
        ):
            data = make(
                self.config, self.service, self.reference, self.manifest, self.deps
            )
            self.assertIsNone(
                check(
                    data,
                    self.config,
                    self.service,
                    self.reference,
                    self.manifest,
                    self.deps,
                )
            )
            changed = dict(self.reference, sha256="f" * 64)
            with self.assertRaises(ValueError):
                check(
                    data, self.config, self.service, changed, self.manifest, self.deps
                )
        done = self.root.guardian.decode(
            protocol.done(
                self.config, self.service, self.reference, self.manifest, self.deps
            )
        )
        self.assertEqual(done["payload"]["outcome"], "startup-only-complete")
        self.assertIs(done["payload"]["accepted"], False)

    def test_reject_config_size_digest_and_legacy_ready(self):
        with self.assertRaises(ValueError):
            protocol.decode_config(
                b" " * (protocol.CONFIG_LIMIT + 1), "a" * 64, self.manifest, self.deps
            )
        with self.assertRaises(ValueError):
            protocol.decode_config(self.config.data, "f" * 64, self.manifest, self.deps)
        legacy = self.root.guardian.encode(
            {
                "kind": "ready",
                "payload": {
                    "transaction_sha256": self.config.sha256,
                    "service": self.service._asdict(),
                },
            }
        )
        with self.assertRaises(ValueError):
            protocol.check_ready(
                legacy, self.config, self.service, self.manifest, self.deps
            )

    def test_configuration_v2_fields_are_exact(self):
        original = protocol.decode_config(
            self.config.data, self.config.sha256, self.manifest, self.deps
        )
        self.assertEqual(original["scope"], "contained-job-rooted-startup-config-v2")
        self.assertEqual(
            set(original),
            {
                "scope",
                "mode",
                "host_spec",
                "root_plan",
                "client",
                "origin_ns",
                "startup_deadline_ns",
            },
        )
        for field, value in (
            ("mode", "boot"),
            ("client", dict(self.client, starttime=False)),
            # The v1 schema carried the user-bus identity for G to check.
            ("bus_identity", {"device": 1, "inode": 900}),
            ("scope", "contained-job-rooted-startup-config-v1"),
        ):
            bad = dict(original, **{field: value})
            data = self.root.closure.canonical(bad)
            with self.subTest(field=field), self.assertRaises(ValueError):
                protocol.decode_header(
                    data, hashlib.sha256(data).hexdigest(), self.deps
                )
        v1 = dict(
            original,
            scope="contained-job-rooted-startup-config-v1",
            bus_identity={"device": 1, "inode": 900},
        )
        data = self.root.closure.canonical(v1)
        with self.assertRaisesRegex(ValueError, "invalid fields"):
            protocol.decode_header(data, hashlib.sha256(data).hexdigest(), self.deps)

    def test_launch_carries_checked_service_identity(self):
        frame = protocol.launch(self.config, self.service, self.manifest, self.deps)
        row = self.root.guardian.decode(frame)
        self.assertEqual(
            row["payload"],
            {
                "scope": "rooted-startup-launch-v2",
                "run_id": self.plan["run_id"],
                "config_sha256": self.config.sha256,
                "service": self.service._asdict(),
            },
        )
        identity = protocol.check_launch(frame, self.config, self.manifest, self.deps)
        self.assertIs(type(identity), self.root.guardian.ServiceIdentity)
        self.assertEqual(identity, self.service)
        uid = self.plan["uid"]
        manager = f"/user.slice/user-{uid}.slice/user@{uid}.service"
        startup = protocol.decode_config(
            self.config.data, self.config.sha256, self.manifest, self.deps
        )["startup_deadline_ns"]
        wrong = {
            "unit": {"unit": "irlume-job-guardian-other.service"},
            "zero invocation": {"invocation_id": "0" * 32},
            "short invocation": {"invocation_id": "d" * 31},
            "outside manager": {"cgroup": "/system.slice/" + self.service.unit},
            "other manager": {
                "cgroup": f"/user.slice/user-{uid + 1}.slice/user@{uid + 1}.service/"
                + self.service.unit
            },
            "not the unit": {"cgroup": manager + "/app.slice/other.service"},
            "dotted cgroup": {"cgroup": manager + "/app.slice/../" + self.service.unit},
            "early deadline": {"deadline_ns": startup - 1},
            "pid": {"pid": 1},
            "pid type": {"pid": True},
        }
        for label, changes in wrong.items():
            service = self.service._replace(**changes)
            with self.subTest(label=label), self.assertRaises(ValueError):
                protocol.launch(self.config, service, self.manifest, self.deps)
            bad = copy.deepcopy(row)
            bad["payload"]["service"].update(changes)
            with self.subTest(label=label), self.assertRaises(ValueError):
                protocol.check_launch(
                    self.root.guardian.encode(bad),
                    self.config,
                    self.manifest,
                    self.deps,
                )
        edits = {
            "extra field": lambda r: r["payload"]["service"].update(extra=1),
            "missing field": lambda r: r["payload"]["service"].pop("cgroup"),
            "extra payload": lambda r: r["payload"].update(extra=1),
            "missing service": lambda r: r["payload"].pop("service"),
            "v1 scope": lambda r: r["payload"].update(scope="rooted-startup-launch-v1"),
            "v1 payload": lambda r: (
                r["payload"].update(scope="rooted-startup-launch-v1"),
                r["payload"].pop("service"),
            ),
            "other run": lambda r: r["payload"].update(run_id="run-02"),
            "other config": lambda r: r["payload"].update(config_sha256="f" * 64),
            "not launch": lambda r: r.update(kind="ready"),
        }
        for label, edit in edits.items():
            bad = copy.deepcopy(row)
            edit(bad)
            with self.subTest(label=label), self.assertRaises(ValueError):
                protocol.check_launch(
                    self.root.guardian.encode(bad),
                    self.config,
                    self.manifest,
                    self.deps,
                )
        with self.assertRaises(ValueError):
            protocol.launch(
                self.config, self.service._asdict(), self.manifest, self.deps
            )

    def test_config_limit_and_canonical_form_apply_to_both_directions(self):
        with (
            mock.patch.object(protocol, "CONFIG_LIMIT", len(self.config.data) - 1),
            self.assertRaises(ValueError),
        ):
            protocol.make_config(
                self.spec,
                self.plan,
                self.client,
                1_000_000,
                self.manifest,
                self.deps,
            )
        data = b" " + self.config.data
        with self.assertRaises(ValueError):
            protocol.decode_config(
                data, hashlib.sha256(data).hexdigest(), self.manifest, self.deps
            )
        with self.assertRaises(ValueError):
            protocol.make_config(
                self.spec,
                self.plan,
                self.client,
                True,
                self.manifest,
                self.deps,
            )

    def test_ready_service_and_invocation_mismatch_refuse(self):
        data = protocol.ready(
            self.config, self.service, self.reference, self.manifest, self.deps
        )
        for changes in ({"pid": self.service.pid + 1}, {"invocation_id": "f" * 32}):
            other = self.service._replace(**changes)
            with self.subTest(changes=changes), self.assertRaises(ValueError):
                protocol.check_ready(data, self.config, other, self.manifest, self.deps)
        for changes in (
            {"invocation_id": "0" * 32},
            {"pid": True},
            {"cgroup": "/wrong"},
            {"deadline_ns": 1},
        ):
            with self.subTest(changes=changes), self.assertRaises(ValueError):
                protocol.ready(
                    self.config,
                    self.service._replace(**changes),
                    self.reference,
                    self.manifest,
                    self.deps,
                )

    def test_missing_qemu_member_and_misplaced_overlay_refuse(self):
        with self.assertRaises(ValueError):
            protocol.make_config(
                self.spec._replace(overlay="/elsewhere/overlay.qcow2"),
                self.plan,
                self.client,
                1_000_000,
                self.manifest,
                self.deps,
            )
        value = self.root.runtime._json(self.manifest)
        value["members"] = [
            row
            for row in value["members"]
            if row["path"] != "usr/bin/qemu-system-x86_64"
        ]
        data = self.root.closure.canonical(value)
        self.plan["manifest"]["sha256"] = hashlib.sha256(data).hexdigest()
        with self.assertRaises(ValueError):
            protocol.make_config(
                self.spec, self.plan, self.client, 1_000_000, data, self.deps
            )

    def test_commit_and_done_reject_replayed_version_and_true_authority(self):
        for make, check in (
            (protocol.commit, protocol.check_commit),
            (protocol.done, protocol.check_done),
        ):
            frame = make(
                self.config, self.service, self.reference, self.manifest, self.deps
            )
            row = self.root.guardian.decode(frame)
            row["payload"]["scope"] = "legacy"
            with self.assertRaises(ValueError):
                check(
                    self.root.guardian.encode(row),
                    self.config,
                    self.service,
                    self.reference,
                    self.manifest,
                    self.deps,
                )
        frame = protocol.done(
            self.config, self.service, self.reference, self.manifest, self.deps
        )
        row = self.root.guardian.decode(frame)
        row["payload"]["accepted"] = True
        with self.assertRaises(ValueError):
            protocol.check_done(
                self.root.guardian.encode(row),
                self.config,
                self.service,
                self.reference,
                self.manifest,
                self.deps,
            )

    def test_valid_vm_candidate_spec_is_not_an_inert_startup_config(self):
        spec = self.spec._replace(mode="runtime-candidate", cases=("bounds-complete",))
        self.root.guardian.validate_spec(spec)
        with self.assertRaises(ValueError):
            protocol.make_config(
                spec,
                self.plan,
                self.client,
                1_000_000,
                self.manifest,
                self.deps,
            )

    def test_launch_digest_and_artifact_owner_are_independent_bindings(self):
        row = self.root.guardian.decode(
            protocol.launch(self.config, self.service, self.manifest, self.deps)
        )
        row["payload"]["config_sha256"] = "f" * 64
        with self.assertRaises(ValueError):
            protocol.check_launch(
                self.root.guardian.encode(row), self.config, self.manifest, self.deps
            )
        reference = dict(self.reference, gid=os.getgid() + 1)
        with self.assertRaises(ValueError):
            protocol.ready(
                self.config, self.service, reference, self.manifest, self.deps
            )

    def test_factory_refuses_a_comparison_spoofing_mode_before_callbacks(self):
        calls = []

        class Alias(str):
            def __eq__(self, other):
                calls.append("eq")
                return True

            def __ne__(self, other):
                calls.append("ne")
                return False

            __hash__ = str.__hash__

        spec = self.spec._replace(mode=Alias("runtime-candidate"))
        with self.assertRaises(ValueError):
            protocol.make_config(
                spec,
                self.plan,
                self.client,
                1_000_000,
                self.manifest,
                self.deps,
            )
        self.assertEqual(calls, [])

    def test_literal_discriminants_reject_subclasses_without_comparing(self):
        calls = []

        class Trap(str):
            def __eq__(self, other):
                calls.append("eq")
                raise AssertionError("untrusted equality called")

            def __ne__(self, other):
                calls.append("ne")
                raise AssertionError("untrusted inequality called")

        for key in ("scope", "mode", "host-mode"):
            value = protocol.decode_config(
                self.config.data, self.config.sha256, self.manifest, self.deps
            )
            if key == "host-mode":
                value["host_spec"]["mode"] = Trap("boot-only")
            else:
                value[key] = Trap(value[key])
            with self.subTest(key=key), self.assertRaises(ValueError):
                protocol.validate_config(value, self.manifest, self.deps)
        with self.assertRaises(ValueError):
            protocol.ready(
                self.config,
                self.service._replace(unit=Trap(self.service.unit)),
                self.reference,
                self.manifest,
                self.deps,
            )
        self.assertEqual(calls, [])

    def test_each_accepted_factory_result_decodes_to_identical_canonical_bytes(self):
        for origin in (1, 1_000_000, 2**63):
            config = protocol.make_config(
                self.spec,
                self.plan,
                self.client,
                origin,
                self.manifest,
                self.deps,
            )
            value = protocol.decode_config(
                config.data, config.sha256, self.manifest, self.deps
            )
            self.assertEqual(config.data, self.root.closure.canonical(value))
            self.assertEqual(value["host_spec"]["mode"], "boot-only")
            self.assertEqual(
                value["startup_deadline_ns"], origin + self.root.guardian.STOP_NS
            )

    def test_header_validation_is_manifest_independent_but_not_full_admission(self):
        value = protocol.decode_header(self.config.data, self.config.sha256, self.deps)
        self.assertEqual(value["mode"], "startup-only")
        value["root_plan"]["manifest"]["sha256"] = "f" * 64
        data = self.root.closure.canonical(value)
        digest = hashlib.sha256(data).hexdigest()
        self.assertEqual(protocol.decode_header(data, digest, self.deps), value)
        with self.assertRaises(ValueError):
            protocol.decode_config(data, digest, self.manifest, self.deps)


if __name__ == "__main__":
    unittest.main()
